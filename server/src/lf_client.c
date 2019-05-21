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
#include "unifycr_metadata.h"


/* Parse LFS_COMMAND and start FAM emulation servers on nodes in hostlist */
int lfs_emulate_fams(char * const cmdline, int rank, int size,
    LFS_CTX_t **lfs_ctx_pp)
{
    LFS_CTX_t *lfs_ctx_p = NULL;
    N_PARAMS_t *params;
    LFS_SHM_t *lfs_shm;
    pthread_mutexattr_t pattr;
    pthread_condattr_t cattr;
    pid_t cpid;
    size_t shm_size, len;
    char *argv[LFS_MAXARGS];
    int argc, verbose, srv_cnt, is_srv, zero_srv_rank, cnt;
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
    srv_cnt = params->node_servers;
    shm_size = sizeof(LFS_SHM_t) + srv_cnt*sizeof(LFS_EXCG_t);
    lfs_shm = (LFS_SHM_t *) mmap(NULL, shm_size,
            PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (lfs_shm == NULL) {
        rc = -1;
        goto _exit;
    }
    lfs_shm->node_servers = srv_cnt;
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
        int i, part;

        /* On each node in nodelist */
        i = find_my_node(params->nodelist, params->node_cnt, NULL);
        if (i >= 0) {

            /* Initialize libfabric target on node 'i' */
            rc = lf_servers_init(&lf_servers, params, i, 0);
            if (rc) {
                err("Can't start FAM emulation target on %s rc:%d",
                    params->nodelist[params->node_id], rc);
            } else if (!params->lf_mr_flags.scalable) {
                /* For each partition */
                for (part = 0; part < srv_cnt; part++) {
                    int lf_client_idx = to_lf_client_id(i, srv_cnt, part);

                    if (params->lf_mr_flags.prov_key)
                        lfs_shm->rmk[part].prov_key = params->mr_prov_keys[lf_client_idx];
                    if (params->lf_mr_flags.virt_addr)
                        lfs_shm->rmk[part].virt_addr = params->mr_virt_addrs[lf_client_idx];
                }
            }
        }

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
        munmap(lfs_shm, shm_size);

        /* Close fabric and exit */
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
    if (rc || !(params->lf_mr_flags.prov_key || params->lf_mr_flags.virt_addr))
        goto _exit;

    /*
     * LF remote key/address exchange
     */

    /* Create MPI communicator for LF servers */
    is_srv = (params->node_id < 0)? 0 : 1;
    zero_srv_rank = mpi_split_world(&params->mpi_comm, is_srv, 1, rank, size);
    if (!is_srv || zero_srv_rank < 0 ||
        !(params->lf_mr_flags.prov_key || params->lf_mr_flags.virt_addr))
        goto _exit;

    /* Exchange the keys within servers */
    len = srv_cnt * sizeof(uint64_t);
    if (params->lf_mr_flags.prov_key &&
        ((rc = MPI_Allgather(MPI_IN_PLACE, len, MPI_BYTE,
                             params->mr_prov_keys, len, MPI_BYTE,
                             params->mpi_comm)))) {
        LOG(LOG_ERR, "LF PROV_KEYS MPI_Allgather failed:%d", rc);
        goto _close_comm;
    }
    if (params->lf_mr_flags.virt_addr &&
        ((rc = MPI_Allgather(MPI_IN_PLACE, len, MPI_BYTE,
                             params->mr_virt_addrs, len, MPI_BYTE,
                             params->mpi_comm)))) {
        LOG(LOG_ERR, "LF VIRT_ADDRS MPI_Allgather failed:%d", rc);
        //goto _close_comm;
    }
_close_comm:
    MPI_Comm_free(&params->mpi_comm);

    /* Broadcast the keys to all [clients] */
    cnt = params->fam_cnt * srv_cnt;
    if (params->lf_mr_flags.prov_key &&
        ((rc = mpi_broadcast_arr64(params->mr_prov_keys, cnt, zero_srv_rank)))) {
        LOG(LOG_ERR, "LF PROV_KEYS MPI broadcast failed:%d", rc);
        goto _exit;
    }
    if (params->lf_mr_flags.virt_addr &&
        ((rc = mpi_broadcast_arr64(params->mr_virt_addrs, cnt, zero_srv_rank)))) {
        LOG(LOG_ERR, "LF VIRT_ADDRS MPI broadcast failed:%d", rc);
        //goto _exit;
    }

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
        munmap(lfs_ctx_p->lfs_shm,
               sizeof(LFS_SHM_t) + lfs_shm->node_servers*sizeof(LFS_EXCG_t));
    }

    free_lf_params(&params);
    free(lfs_ctx_p);
    *lfs_ctx_pp = NULL;
}

int meta_register_fam(LFS_CTX_t *lfs_ctx)
{
    N_PARAMS_t *params = lfs_ctx->lf_params;
    fam_attr_val_t *fam_attr;
    LFS_EXCG_t *rmk, *attr;
    unsigned int fam_id, part_cnt, i;
    int rc;

    /* Do nothing on LF client */
    if (params->node_id < 0)
        return 0;

    /* NOTE: FAM emulation only; limited to 31 bits */
    fam_id = (unsigned int) params->node_id;
    part_cnt = params->node_servers;
    fam_attr = (fam_attr_val_t *)malloc(fam_attr_val_sz(part_cnt));
    fam_attr->part_cnt = part_cnt;
    attr = fam_attr->part_attr;
    rmk = lfs_ctx->lfs_shm->rmk;
    for (i = 0; i < part_cnt; i++, rmk++, attr++)
        memcpy(attr, rmk, sizeof(LFS_EXCG_t));

    rc = meta_famattr_put(fam_id, fam_attr);
    free(fam_attr);
    return rc;
}

