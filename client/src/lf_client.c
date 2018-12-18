#include <unistd.h>
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

#include "famfs_env.h"
#include "lf_client.h"
#include "fam_stripe.h"
//#include "unifycr-internal.h"


static int alloc_lf_clients(int argc, char **argv, int rank, N_PARAMS_t **params_p)
{
    N_PARAMS_t *params;
    LF_CL_t **lf_all_clients;
    char **stripe_buf = NULL;
    int i, part, verbose;
    int nchunks, fam_cnt, srv_cnt, psize, rc;

    verbose = (rank == 0);
    if ((rc = arg_parser(argc, argv, verbose, LFS_MAXCLIENTS, params_p))) {
	if (verbose)
	    ion_usage(argv[0]);
	return rc;
    }
    params = *params_p;
    ASSERT(params);
    params->w_thread_cnt = 1;

    rc = lf_clients_init(params);
    if (rc == 0)
	*params_p = params;
    return rc;
}

int lfs_connect(char *param_str, int rank, size_t rank_size, LFS_CTX_t **lfs_ctx_pp)
{
    N_PARAMS_t *lfs_params;
    N_STRIPE_t *stripe = NULL;
    LFS_CTX_t *lfs_ctx_p;
    N_CHUNK_t *chunk, *chunks = NULL;
    char *argv[LFS_MAXARGS];
    int i, nchunks, argc;
    int rc = 1; /* OOM error */

    lfs_ctx_p = (LFS_CTX_t *)malloc(sizeof(LFS_CTX_t));
    if (lfs_ctx_p == NULL)
	return rc;

    argc = str2argv(param_str, argv, LFS_MAXARGS);
    if ((rc = alloc_lf_clients(argc, argv, rank, &lfs_params)))
	return rc;

    stripe = (N_STRIPE_t *)malloc(sizeof(N_STRIPE_t));
    if (stripe == NULL)
	goto _free;

    nchunks = lfs_params->nchunks;
#if 0
    /* stripe buffer for libfabric I/O */
    posix_memalign((void **)&stripe->lf_buffer, getpagesize(),
		   lfs_params->chunk_sz * nchunks);
    if (stripe->lf_buffer == NULL)
	goto _free;
#endif
    /* array of chunks */
    chunks = (N_CHUNK_t *)malloc(nchunks * sizeof(N_CHUNK_t));
    if (chunks == NULL)
	goto _free;

    chunk = chunks;
    for (i = 0; i < nchunks; i++, chunk++) {
	chunk->r_event = 0;
	chunk->w_event = 0;
    }
    stripe->p	= lfs_params->parities;
    stripe->d	= lfs_params->nchunks - lfs_params->parities;
    stripe->extent_stipes	= lfs_params->extent_sz / lfs_params->chunk_sz;
    stripe->srv_extents		= lfs_params->srv_extents;
    stripe->part_count		= lfs_params->node_servers;
    stripe->part_mreg		= lfs_params->part_mreg;
    /* TODO: Allocate stripes to clients. Now the clients must me evenly distributed. */
    //stripe->node_id		= my_srv_rank * local_rank_cnt + local_rank_idx;
    //stripe->node_size		= my_srv_size * local_rank_cnt;
    stripe->node_id		= rank;
    stripe->node_size		= rank_size;

    stripe->chunks = chunks;
    /* initial mapping */
    get_fam_chunk(0, stripe, NULL);

    lfs_ctx_p->lfs_params = lfs_params;
    lfs_ctx_p->fam_stripe = stripe;
    *lfs_ctx_pp = lfs_ctx_p;
    return 0;

_free:
    free(chunks);
    //free(stripe->lf_buffer);
    free(stripe);
    free_lf_params(&lfs_params);
    free(lfs_ctx_p);
    return rc;
}

void free_lfs_ctx(LFS_CTX_t **lfs_ctx_pp) {
    LFS_CTX_t *lfs_ctx_p = *lfs_ctx_pp;

    free_fam_stripe(lfs_ctx_p->fam_stripe);
    free_lf_params(&lfs_ctx_p->lfs_params);
    free(lfs_ctx_p);
    *lfs_ctx_pp = NULL;
}

