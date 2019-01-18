#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <malloc.h>
#include <signal.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <limits.h>

#include "famfs_error.h"
#include "famfs_env.h"
#include "lf_client.h"


/* FAM emulator process quit signal */
static volatile sig_atomic_t quit_lfs = 0;
static void syn_sig(int sig) { quit_lfs = 1; }
static void quit_sim(LFS_CTX_t *lfs_ctx_p) { kill(lfs_ctx_p->child_pid, SIGQUIT); } 

/* Parse LFS_COMMAND and start FAM emulation servers on nodes marked in map */
int lfs_emulate_fams(char * const cmdline, int rank, int size, char *map,
    LFS_CTX_t **lfs_ctx_pp)
{
    LFS_CTX_t *lfs_ctx_p = NULL;
    MPI_Comm world_comm, lfs_comm;
    MPI_Group group_all, lfs_group;
    N_PARAMS_t *params;
    pid_t cpid;
    char *argv[LFS_MAXARGS];
    int i, argc, verbose;
    int lfs_size, *lfs_ranks;
    int rc = 1; /* OOM error */

    lfs_ctx_p = (LFS_CTX_t *) calloc(1, sizeof(LFS_CTX_t));
    if (lfs_ctx_p == NULL)
	return rc;

    argc = str2argv(cmdline, argv, LFS_MAXARGS);
    verbose = (rank == 0);
    if ((rc = arg_parser(argc, argv, verbose, -1, &params))) {
        err("Error parsing command arguments");
        if (verbose)
            ion_usage(argv[0]);
        free(lfs_ctx_p);
        return rc;
    }
    lfs_ctx_p->lf_params = params;
    lfs_ctx_p->quit_fn = &quit_sim;

    if (params->fam_map) {
        rc = 0;
        goto _exit; /* Having the real FAM(s) */
    }

    /*
     * Create MPI group communicator for the LF servers
     */
    rc = MPI_Comm_dup(MPI_COMM_WORLD, &world_comm);
    if (rc != MPI_SUCCESS) {
        err("MPI_Comm_dup failed:%d", rc);
        goto _exit;
    }
    rc = MPI_Comm_group(world_comm, &group_all);
    if (rc != MPI_SUCCESS) {
        err("MPI_Comm_group failed:%d", rc);
        goto _exit;
    }

    lfs_ranks = (int *) calloc(size, sizeof(int));
    if (lfs_ranks == NULL)
        goto _exit;
    lfs_size = 0;
    bool start_lfs = false;
    for (i = 0; i < size; i++) {
        if (!map[i])
            continue;
        lfs_ranks[lfs_size++] = i;
        if (i == rank)
            start_lfs = true;
    }
    if (!start_lfs) {
        rc = 0;
        goto _exit;
    }

    rc = MPI_Group_incl(group_all, lfs_size, lfs_ranks, &lfs_group);
    free(lfs_ranks);
    if (rc != MPI_SUCCESS) {
        err("MPI_Comm_incl failed:%d", rc);
        goto _exit;
    }
    rc = MPI_Comm_create(world_comm, lfs_group, &lfs_comm);
    if (rc != MPI_SUCCESS || lfs_comm == MPI_COMM_NULL) {
        err("MPI_Comm_create failed:%d lfs_size:%d",
            rc, lfs_size);
        rc = -1;
        goto _exit;
    }

    /* Fork FAM emulation servers */
    cpid = fork();
    if (cpid < 0) {
        rc = -errno;
        err("fork failed: %m");
        goto _exit;
    } else if (cpid == 0) {
        LF_SRV_t   **lf_servers;
        sigset_t mask, oldmask, block_mask;
        struct sigaction quit_action;
        int srv_cnt = params->node_servers;

        ON_ERROR( lf_servers_init(&lf_servers, params, lfs_comm),
                  "Can't start FAM emulation target on %s",
                  params->nodelist[params->node_id]);

        /* Sleep */
        sigemptyset(&mask);
        sigaddset(&mask, SIGUSR1);
        sigaddset(&mask, SIGQUIT);

        sigfillset(&block_mask);
        quit_action.sa_handler = syn_sig;
        quit_action.sa_mask = block_mask;
        quit_action.sa_flags = 0;
        sigaction(SIGUSR1, &quit_action, NULL);
        sigaction(SIGQUIT, &quit_action, NULL);

        sigprocmask(SIG_BLOCK, &mask, &oldmask);
        while(!quit_lfs)
            sigsuspend(&oldmask);
        sigprocmask(SIG_UNBLOCK, &mask, NULL);

        /* Close fabric and exit */
        for (i = 0; i < srv_cnt; i++)
            lf_srv_free(lf_servers[i]);
        free(lf_servers);
        free_lf_params(&params);
        free(lfs_ctx_p);
        exit(0);
    }
    lfs_ctx_p->child_pid = cpid;

_exit:
    if (rc) {
        free_lf_params(&params);
        free(lfs_ctx_p);
    } else
        *lfs_ctx_pp = lfs_ctx_p;
    return rc;
}

void free_lfs_ctx(LFS_CTX_t **lfs_ctx_pp) {
    LFS_CTX_t *lfs_ctx_p = *lfs_ctx_pp;
    N_PARAMS_t *params = lfs_ctx_p->lf_params;

    if (lfs_ctx_p->child_pid)
        lfs_ctx_p->quit_fn(lfs_ctx_p);

    free_lf_params(&params);
    free(lfs_ctx_p);
    *lfs_ctx_pp = NULL;
}

