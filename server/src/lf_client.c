#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <malloc.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <limits.h>

#include "famfs_error.h"
#include "famfs_env.h"
#include "log.h"
#include "lf_client.h"


/* Parse LFS_COMMAND and start FAM emulation servers on nodes marked in map */
int lfs_emulate_fams(char * const cmdline, int rank, int size, char *map,
    LFS_CTX_t **lfs_ctx_pp)
{
    LFS_CTX_t *lfs_ctx_p = NULL;
    N_PARAMS_t *params;
    LFS_SHM_t *lfs_shm;
    pthread_mutexattr_t pattr;
    pthread_condattr_t cattr;
    pid_t cpid;
    char *argv[LFS_MAXARGS];
    int argc, verbose;
    int rc = -1; /* OOM error */

    lfs_ctx_p = (LFS_CTX_t *) calloc(1, sizeof(LFS_CTX_t));
    if (lfs_ctx_p == NULL)
	return rc;

    argc = str2argv(cmdline, argv, LFS_MAXARGS);
    verbose = (rank == 0);
    if ((rc = arg_parser(argc, argv, verbose, -1, &params))) {
        err("Error parsing command arguments");
        if (verbose)
            ion_usage(argv[0]);
        goto _exit;
    }
    lfs_ctx_p->lf_params = params;

    /* Having the real FAM? */
    if (params->fam_map)
        goto _exit;

    /*
     * FAM emulator
     */

    /* Initialize shared data */
    lfs_shm = (LFS_SHM_t *) mmap(NULL, sizeof(LFS_SHM_t),
            PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (lfs_shm == NULL) {
        rc = -1;
        goto _exit;
    }
    lfs_shm->quit_lfs = 0;
    lfs_shm->lfs_ready = 0;
    pthread_mutexattr_init(&pattr);
    pthread_mutexattr_setpshared(&pattr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&lfs_shm->lock, &pattr);
    pthread_condattr_init(&cattr);
    pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
    pthread_cond_init(&lfs_shm->cond_ready, &cattr);
    pthread_cond_init(&lfs_shm->cond_quit, &cattr);
    lfs_ctx_p->lfs_shm = lfs_shm;

    /* On each node: fork FAM emulation server */
    cpid = fork();
    if (cpid < 0) {
        rc = -errno;
        err("fork failed: %m");
        goto _exit;
    } else if (cpid == 0) {
        LF_SRV_t   **lf_servers;
        int lfs_size, *lfs_ranks;
        int i, srv_cnt;

        lfs_ranks = (int *) calloc(size, sizeof(int));
        if (lfs_ranks == NULL)
            goto _child_exit;
        lfs_size = 0;
        bool start_lfs = false;
        for (i = 0; i < size; i++) {
            if (!map[i])
                continue;
            lfs_ranks[lfs_size++] = i;
            if (i == rank)
                start_lfs = true;
        }
        /* On each node in map[] */
        if (start_lfs) {

            /* Initialize libfabric target */
            rc = lf_servers_init(&lf_servers, params, 0);
            if (rc)
                err("Can't start FAM emulation target on %s rc:%d",
                    params->nodelist[params->node_id], rc);
        }

_child_exit:
        /* It's Ok for parent process to proceed with MPI communication */
        pthread_mutex_lock(&lfs_shm->lock);
        lfs_shm->lfs_ready = rc? -1 : 1;
        pthread_mutex_unlock(&lfs_shm->lock);
        pthread_cond_signal(&lfs_shm->cond_ready);

        /* Sleep if libfabric was initialized successfully */
        if (rc == 0) {
            pthread_mutex_lock(&lfs_shm->lock);
            while (lfs_shm->quit_lfs == 0)
                pthread_cond_wait(&lfs_shm->cond_quit, &lfs_shm->lock);
            pthread_mutex_unlock(&lfs_shm->lock);
        }
        pthread_cond_destroy(&lfs_shm->cond_quit);
        munmap(lfs_shm, sizeof(LFS_SHM_t));

        /* Close fabric and exit */
        srv_cnt = params->node_servers;
        for (i = 0; i < srv_cnt; i++)
            lf_srv_free(lf_servers[i]);
        free(lf_servers);
        free_lf_params(&params);
        free(lfs_ctx_p);

        exit(0);
    }

    /* Parent thread should wait */
    pthread_mutex_lock(&lfs_shm->lock);
    while (lfs_shm->lfs_ready == 0)
            pthread_cond_wait(&lfs_shm->cond_ready, &lfs_shm->lock);
    pthread_mutex_unlock(&lfs_shm->lock);
    if (lfs_shm->lfs_ready != 1) {
        LOG(LOG_ERR, "Failed to start FAM emulator process!");
        rc = -1;
    }

    /* Way to go with MPI */
    MPI_Barrier(MPI_COMM_WORLD);

    if (lfs_ctx_p->lf_params->verbose && lfs_shm->lfs_ready == 1)
        LOG(LOG_INFO, "FAM module emulator is ready");

    pthread_cond_destroy(&lfs_shm->cond_ready);
    lfs_ctx_p->child_pid = cpid;

_exit:
    if (rc) {
        free_lfs_ctx(&lfs_ctx_p);
    } else
        *lfs_ctx_pp = lfs_ctx_p;
    return rc;
}

void free_lfs_ctx(LFS_CTX_t **lfs_ctx_pp) {
    LFS_CTX_t *lfs_ctx_p = *lfs_ctx_pp;
    LFS_SHM_t *lfs_shm = lfs_ctx_p->lfs_shm;
    N_PARAMS_t *params = lfs_ctx_p->lf_params;

    if (lfs_shm) {
        /* Signal FAM emulator to quit */
        if (lfs_ctx_p->child_pid) {
            pthread_mutex_lock(&lfs_shm->lock);
            lfs_shm->quit_lfs = 1;
            pthread_mutex_unlock(&lfs_shm->lock);
            pthread_cond_signal(&lfs_shm->cond_quit);
        }
        munmap(lfs_ctx_p->lfs_shm, sizeof(LFS_SHM_t));
    }

    free_lf_params(&params);
    free(lfs_ctx_p);
    *lfs_ctx_pp = NULL;
}

