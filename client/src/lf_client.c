#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include "famfs_env.h"
#include "famfs_global.h"
#include "lf_client.h"
#include "fam_stripe.h"
#include "unifycr-internal.h" /* DEBUG() macro */
#include "famfs_maps.h"
#include "f_pool.h"
#include "f_layout.h"


static int get_lf_meta(F_POOL_t *pool)
{
    LF_INFO_t *lf_info = pool->lf_info;
    F_POOL_DEV_t *pdev;
    fam_attr_val_t *fam_meta = NULL;
    int fam_cnt, i;
    int rc = 0;

    if (lf_info->mrreg.scalable ||
        (!lf_info->mrreg.prov_key && !lf_info->mrreg.virt_addr))
        return UNIFYCR_SUCCESS;

    for_each_pool_dev(pool, pdev) {
	FAM_DEV_t *fdev = &pdev->dev->f;

	rc = get_global_fam_meta((int)_i, &fam_meta);
	if (rc != UNIFYCR_SUCCESS) {
	    err("Get LF meta error:%d id:%u", rc, _i);
	    return -1;
	}

	fdev->pkey = fam_meta->part_attr[0].prov_key;
	fdev->virt_addr = fam_meta->part_attr[0].virt_addr;
	DEBUG("get_lf_meta id:%d prov_key:%lu virt_addr:%lu\n",
		i, fdev->pkey, fdev->virt_addr);

        free(fam_meta);
    }
    return rc;
}

int lfs_connect(int rank, size_t rank_size, LFS_CTX_t **lfs_ctx_pp)
{
    F_POOL_t *pool;
    F_POOL_INFO_t *info;
    LF_INFO_t *lf_info;
    N_STRIPE_t *stripe = NULL;
    LFS_CTX_t *lfs_ctx_p;
    F_LAYOUT_INFO_t *lo_info;
    N_CHUNK_t *chunk, *chunks = NULL;
    struct famsim_stats *stats_fi_wr;
    int i, nchunks;
    int rc = 1; /* OOM error */

    lfs_ctx_p = (LFS_CTX_t *)malloc(sizeof(LFS_CTX_t));
    if (lfs_ctx_p == NULL)
	return rc;

    pool = f_get_pool();
    assert( pool );
    info = &pool->info;
    lf_info = pool->lf_info;

    if ((rc = get_lf_meta(pool))) {
	DEBUG("rank:%d failed to get LF metadata from the delegator on mount, error:%d",
	      dbg_rank, rc);
	return rc;
    }

    if ((rc = lf_clients_init(pool))) {
	DEBUG("rank:%d failed to initialize libfabric device(s) on mount, error:%d",
	      dbg_rank, rc);
	return rc;
    }

    stripe = (N_STRIPE_t *)malloc(sizeof(N_STRIPE_t));
    if (stripe == NULL)
	goto _free;

    stats_fi_wr = famsim_stats_create(famsim_ctx, FAMSIM_STATS_FI_WR);
    if (stats_fi_wr)
	famsim_ctx->fam_cnt = info->dev_count;

    /* default layout */
    lo_info = f_get_layout_info(0);
    assert( lo_info );

    nchunks = lo_info->chunks;
    /* array of chunks */
    chunks = (N_CHUNK_t *)malloc(nchunks * sizeof(N_CHUNK_t));
    if (chunks == NULL)
	goto _free;

    chunk = chunks;
    for (i = 0; i < nchunks; i++, chunk++) {
	chunk->r_event = 0;
	chunk->w_event = 0;
    }
    stripe->p	= lo_info->chunks - lo_info->data_chunks;
    stripe->d	= lo_info->data_chunks;
    stripe->chunk_sz		= lo_info->chunk_sz;
    stripe->extent_stipes	= info->extent_sz / lo_info->chunk_sz;
    stripe->srv_extents		= info->size_def / info->extent_sz;
    /* TODO: Allocate stripes to clients. Now the clients must me evenly distributed. */
    //stripe->node_id		= my_srv_rank * local_rank_cnt + local_rank_idx;
    //stripe->node_size		= my_srv_size * local_rank_cnt;
    stripe->node_id		= rank;
    stripe->node_size		= rank_size;

    /* Find the lowest media id */
    for (unsigned int j = 0; j <= pool->info.pdev_max_idx; j++) {
	uint16_t pdi;
	F_POOL_DEV_t *pdev;

	pdi = pool->info.pdi_by_media[j];
	if (pdi == F_PDI_NONE)
	    continue;
	pdev = &pool->devlist[pdi];
	stripe->media_id_0 = pdev->pool_index;
	break;
    }

    stripe->chunks = chunks;
    /* initial mapping */
    get_fam_chunk(0, stripe, NULL);

    lfs_ctx_p->pool = pool;
    lfs_ctx_p->fam_stripe = stripe;
    lfs_ctx_p->famsim_stats_fi_wr = stats_fi_wr;
    *lfs_ctx_pp = lfs_ctx_p;
    return 0;

_free:
    free(chunks);
    free(stripe);
    lf_clients_free(pool);
    free(lfs_ctx_p);
    return rc;
}

void free_lfc_ctx(LFS_CTX_t **lfs_ctx_pp) {
    LFS_CTX_t *lfs_ctx_p = *lfs_ctx_pp;

    famsim_stats_stop(lfs_ctx_p->famsim_stats_fi_wr, 1);

    free_fam_stripe(lfs_ctx_p->fam_stripe);
    lf_clients_free(lfs_ctx_p->pool);
    free(lfs_ctx_p);
    *lfs_ctx_pp = NULL;
}

