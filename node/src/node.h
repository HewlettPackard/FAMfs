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

#ifndef NODE_H
#define NODE_H

#include "f_stripe.h"
#include "lf_connect.h"
#include "ec_perf.h"


/* Performance statistics */
typedef struct perf_stat_ {
	struct ec_perf		ec_bw;		/* ISA lib encoding time&data counters */
	struct ec_perf		rc_bw;		/* ISA lib decoding time&data counters */
	struct ec_perf		lw_bw;		/* data transfer from local buffer to FAM */
	struct ec_perf		lr_bw;		/* data transfer to local buffer from FAM */
} PERF_STAT_t;

typedef struct w_private_ {
	struct n_params_	*params;	/* reference to struct n_params_ */
	struct b_stripes_	bunch;		/* bunch of stripes belongs to the same extent */
	struct perf_stat_	perf_stat;	/* per thread data transfer/encode/decode statistic */
	int			thr_id;		/* worker's thread id */
	/* Arrays of pointers to chunk and libfabric client for this stripe */
	struct n_chunk_		**chunks;
	struct lf_cl_		**lf_clients;	/* array of references */
} W_PRIVATE_t;

#endif
