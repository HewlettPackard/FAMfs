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
#include "famfs_global.h"
#include "lf_client.h"
#include "fam_stripe.h"
#include "unifycr-internal.h" /* DEBUG() macro */


static int get_lf_meta(N_PARAMS_t *params)
{
    fam_attr_val_t *fam_meta = NULL;
    int fam_cnt, srv_cnt;
    int i, part, lf_client_idx;
    int rc = 0;

    if (params->lf_mr_flags.scalable ||
        (params->mr_prov_keys == NULL && params->mr_virt_addrs == NULL))
        return UNIFYCR_SUCCESS;

    fam_cnt = params->fam_cnt;
    srv_cnt = params->node_servers;
    for (i = 0; i < fam_cnt; i++) {
        rc = get_global_fam_meta(i, &fam_meta);
        if (rc != UNIFYCR_SUCCESS) {
            err("Get LF meta error:%d id:%d", rc, i);
            return -1;
        }
        for (part = 0; part < srv_cnt && fam_meta; part++) {
            lf_client_idx = to_lf_client_id(i, srv_cnt, part);
            params->mr_prov_keys[lf_client_idx] = fam_meta->part_attr[part].prov_key;
            params->mr_virt_addrs[lf_client_idx] = fam_meta->part_attr[part].virt_addr;
            DEBUG("get_lf_meta id:%d(p%d) prov_key:%lu virt_addr:%lu\n",
              i, part,
              params->mr_prov_keys[lf_client_idx],
              params->mr_virt_addrs[lf_client_idx]);
        }
        free(fam_meta);
    }
    return rc;
}

static int alloc_lf_clients(int argc, char **argv, int rank, N_PARAMS_t **params_p)
{
    N_PARAMS_t *params;
    int nchunks, verbose, rc;

    verbose = (rank == 0);
    if ((rc = arg_parser(argc, argv, verbose, 1, params_p))) {
	if (verbose)
	    ion_usage(argv[0]);
	return rc;
    }
    params = *params_p;
    ASSERT(params);
    params->w_thread_cnt = 1;

    if ((rc = get_lf_meta(params))) {
	DEBUG("rank:%d failed to get LF metadata from the delegator on mount, error:%d",
	      dbg_rank, rc);
	return rc;
    }

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
    struct famsim_stats *stats_fi_wr;
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

    stats_fi_wr = famsim_stats_create(famsim_ctx, FAMSIM_STATS_FI_WR);
    if (stats_fi_wr)
	famsim_ctx->fam_cnt = lfs_params->fam_cnt;

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
    lfs_ctx_p->famsim_stats_fi_wr = stats_fi_wr;
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

void free_lfc_ctx(LFS_CTX_t **lfs_ctx_pp) {
    LFS_CTX_t *lfs_ctx_p = *lfs_ctx_pp;

    famsim_stats_stop(lfs_ctx_p->famsim_stats_fi_wr, 1);

    free_fam_stripe(lfs_ctx_p->fam_stripe);
    free_lf_params(&lfs_ctx_p->lfs_params);
    free(lfs_ctx_p);
    *lfs_ctx_pp = NULL;
}

