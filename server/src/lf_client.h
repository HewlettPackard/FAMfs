/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef LF_CLIENT_H
#define LF_CLIENT_H

#include <stddef.h>

#include "famfs_lf_connect.h"

struct lfs_ctx_;
typedef void (*quit_fn_t)(struct lfs_ctx_ *ctx);

typedef struct lfs_ctx_ {
	N_PARAMS_t	*lf_params;	/* LF clients */
	/* FAM emulation only */
	pid_t		child_pid;	/* pid of child process or zero */
	quit_fn_t	quit_fn;	/* function that signals the emulator to quit */
} LFS_CTX_t;


int lfs_emulate_fams(char * const cmdline, int rank, int size, char *map,
    LFS_CTX_t **lfs_ctx_pp);
void free_lfs_ctx(LFS_CTX_t **lfs_ctx_p);

#endif /* LF_CLIENT_H */

