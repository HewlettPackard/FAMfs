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
#include "famfs_global.h"


typedef struct lfs_shm_ {
	int		lfs_ready;	/* 1: tell parent that server is ready */
	int		quit_lfs;	/* 1: tell child to quit */
	pthread_mutex_t	lock_ready;	/* shared mutex for ready condition */
	pthread_cond_t	cond_ready;	/* parent waits for LF server */
	pthread_mutex_t	lock_quit;	/* shared mutex for quit condition */
	pthread_cond_t	cond_quit;	/* child waits to quit */
	unsigned int	node_servers;	/* number of LF parti */
	/* Array of 'node_servers' size: */
	struct lfs_excg_ rmk[];		/* LF remote memory keys */
} LFS_SHM_t;

typedef struct lfs_ctx_ {
	N_PARAMS_t	*lf_params;	/* LF clients */
	/* FAM emulation only */
	pid_t		child_pid;	/* pid of child process or zero */
        struct lfs_shm_	*lfs_shm;	/* shared data */
} LFS_CTX_t;


int lfs_emulate_fams(int rank, int size, LFS_CTX_t **lfs_ctx_pp);
int meta_register_fam(LFS_CTX_t *lfs_ctx);
void free_lfs_ctx(LFS_CTX_t **lfs_ctx_p);

#endif /* LF_CLIENT_H */

