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

#include "f_lf_connect.h"
#include "f_stripe.h"
#include "f_stats.h"
#include "f_pool.h"


typedef struct lfs_ctx_ {
	F_POOL_t	*pool;		/* famfs pool structure, reference */
//	N_STRIPE_t	*fam_stripe;	/* FAM stripe attributes */
	struct famsim_stats *famsim_stats_fi_wr; /* Carbion stats: fi_write */
} LFS_CTX_t;

int lfs_connect(LFS_CTX_t **lfs_ctx_pp);
void free_lfc_ctx(LFS_CTX_t **lfs_ctx_p);

#endif /* LF_CLIENT_H */

