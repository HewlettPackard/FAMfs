/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef NODE_H
#define NODE_H

#include "famfs_stripe.h"
#include "famfs_lf_connect.h"
#include "ec_perf.h"


/* Performance statistics */
typedef struct perf_stat_ {
	struct ec_perf		ec_bw;		/* ISA lib encoding time&data counters */
	struct ec_perf		rc_bw;		/* ISA lib decoding time&data counters */
	struct ec_perf		lw_bw;		/* data transfer from local buffer to FAM */
	struct ec_perf		lr_bw;		/* data transfer to local buffer from FAM */
} PERF_STAT_t;

typedef struct lf_srv_ {
	struct n_params_	*params;	/* reference to struct n_params_ */
	LF_CL_t			*lf_client;	/* open libfabric objects to be closed/freed */
	void			*virt_addr;	/* mapped memory buffer */
	size_t			length;		/* FAM address range (length, bytes) */
	int			thread_id;	/* worker's thread id */
} LF_SRV_t;

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
