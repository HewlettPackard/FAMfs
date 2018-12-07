#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <malloc.h>
#include <signal.h>
#include <sys/mman.h>
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
    nchunks = params->nchunks;
    fam_cnt = params->fam_cnt;
    srv_cnt = params->node_servers;

    /* Pre-allocate LF client stripe buffer */
    stripe_buf = (char **)malloc(params->w_thread_cnt * sizeof(void*));
    ASSERT(stripe_buf);
    psize = getpagesize();
    for (i = 0; i < params->w_thread_cnt; i++) {
	/* Stripe I/O buffer */
	ON_ERROR(posix_memalign((void **)&stripe_buf[i], psize,
				params->chunk_sz * nchunks),
		"stripe buffer memory alloc failed");
	if (params->lf_mr_flags.allocated)
	    mlock(stripe_buf[i], params->chunk_sz * nchunks);
    }
    params->stripe_buf = stripe_buf;

    /* Allocate one LF_CL_t structure per FAM partition */
    lf_all_clients = (LF_CL_t **)malloc(fam_cnt * srv_cnt * sizeof(void*));
    ASSERT(lf_all_clients);
    params->lf_clients = lf_all_clients;
    /* Setup fabric for each node */
    for (i = 0; i < fam_cnt; i++) {
	for (part = 0; part < srv_cnt; part++) {
	    LF_CL_t *cl;
	    int lf_client_idx = to_lf_client_id(i, srv_cnt, part);

	    cl = (LF_CL_t *) malloc(sizeof(LF_CL_t));
	    ASSERT(cl);
	    cl->node_id = i;
	    cl->fam_id = fam_id_by_index(params->fam_map, i);
	    cl->partition = (unsigned int)part;
#if 0 /* TODO: Exchange prov_keys & virt_addr */
	    if (params->lf_mr_flags.prov_key)
		cl->mr_key = params->mr_prov_keys[lf_client_idx];
	    /* FI_MR_VIRT_ADDR? */
	    if (params->lf_mr_flags.virt_addr) {
		if (params->part_mreg == 0)
		    cl->dst_virt_addr = (uint64_t) fam_buf;
		else
		    cl->dst_virt_addr = (uint64_t) params->mr_virt_addrs[lf_client_idx];
	    }
#else
	    cl->mr_key = 0;
	    cl->dst_virt_addr = 0;
#endif
	    if (!params->fam_map || (i == 0 && part == 0)) {
		/* Join the fabric and domain */
		cl->fabric = NULL;
	    } else {
		LF_CL_t *fab = lf_all_clients[0];
		cl->fabric = fab->fabric;
		cl->domain = fab->domain;
		cl->av = fab->av;
	    }

	    /* Create tx contexts */
	    ON_ERROR( lf_client_init(cl, params),
		     "Error in libfabric client init");

	    lf_all_clients[lf_client_idx] = cl;
	    if (params->verbose)
		printf("%d %s:%5d CL attached to FAM node %d(p%d) mr_key:%lu\n",
			rank, params->nodelist[params->node_id], cl->service, i, part, cl->mr_key);
	}
    }
    if (verbose) {
	printf("LF initiator scalable:%d local:%d basic:%d (prov_key:%d virt_addr:%d allocated:%d)\n",
		params->lf_mr_flags.scalable, params->lf_mr_flags.local, params->lf_mr_flags.basic,
		params->lf_mr_flags.prov_key, params->lf_mr_flags.virt_addr, params->lf_mr_flags.allocated);
    }

    if (params->set_affinity && verbose) {
	printf("Set CQ and worker affinity: ");
		printf("%d ", lf_all_clients[0]->cq_affinity[0]);
	printf("\n");
    }

    *params_p = params;
    return 0;
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

