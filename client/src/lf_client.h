/*
 * Copyright (c) 2017-2020, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef LF_CLIENT_H
#define LF_CLIENT_H

#include <stddef.h>

#include "famfs_lf_connect.h"
#include "famfs_stripe.h"
#include "famfs_stats.h"
#include "f_pool.h"


typedef struct lfs_ctx_ {
	F_POOL_t	*pool;		/* famfs pool structure, reference */
//	N_STRIPE_t	*fam_stripe;	/* FAM stripe attributes */
	struct famsim_stats *famsim_stats_fi_wr; /* Carbion stats: fi_write */
} LFS_CTX_t;


int lfs_connect(int rank, size_t rank_size, LFS_CTX_t **lfs_ctx_pp);
void free_lfc_ctx(LFS_CTX_t **lfs_ctx_p);

#endif /* LF_CLIENT_H */

