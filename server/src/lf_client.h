/*
 * (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor
 *   Boston, MA 02110-1301, USA.
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef LF_CLIENT_H
#define LF_CLIENT_H

#include <stddef.h>
#include <pthread.h>

#include "f_lf_connect.h"
#include "f_global.h"
#include "f_pool.h"


typedef struct lfs_shm_ {
	size_t		shm_size;	/* this structure's size */
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
	F_POOL_t	*pool;		/* famfs pool structure, reference */
	/* FAM emulation only */
	pid_t		child_pid;	/* pid of child process or zero */
        struct lfs_shm_	*lfs_shm;	/* shared data */
} LFS_CTX_t;

int create_lfs_ctx(LFS_CTX_t **lfs_ctx_p);
int lfs_emulate_fams(int rank, int size, LFS_CTX_t *lfs_ctx);
int meta_register_fam(LFS_CTX_t *lfs_ctx);
void free_lfs_ctx(LFS_CTX_t **lfs_ctx_p);

#endif /* LF_CLIENT_H */

