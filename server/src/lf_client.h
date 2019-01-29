/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef LF_CLIENT_H
#define LF_CLIENT_H

#include <stddef.h>
#include <pthread.h>

#include "famfs_lf_connect.h"


typedef struct lfs_shm_ {
	int		lfs_ready;	/* 1: tell parent that server is ready */
	int		quit_lfs;	/* 1: tell child to quit */
	pthread_mutex_t	lock;		/* shared mutex */
	pthread_cond_t	cond_ready;	/* parent waits for LF server */
	pthread_cond_t	cond_quit;	/* child waits to quit */
} LFS_SHM_t;

typedef struct lfs_ctx_ {
	N_PARAMS_t	*lf_params;	/* LF clients */
	/* FAM emulation only */
	pid_t		child_pid;	/* pid of child process or zero */
        struct lfs_shm_	*lfs_shm;	/* shared data */
} LFS_CTX_t;


int lfs_emulate_fams(char * const cmdline, int rank, int size, char *map,
    LFS_CTX_t **lfs_ctx_pp);
void free_lfs_ctx(LFS_CTX_t **lfs_ctx_p);

#endif /* LF_CLIENT_H */

