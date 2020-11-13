/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef LF_TEST_H
#define LF_TEST_H

#include "f_stripe.h"
#include "lf_connect.h"
#include "ec_perf.h"


typedef enum lf_role_ {
        LF_ROLE_UNDEF = 0,
	LF_ROLE_SRV,
	LF_ROLE_CLT,
} LF_ROLE_t;

/* Performance statistics */
typedef struct perf_stat_ {
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

#endif /* LF_TEST_H */
