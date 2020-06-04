#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include "famfs_env.h"
#include "famfs_error.h"
#include "famfs_global.h"
#include "famfs_maps.h"
#include "f_pool.h"
#include "f_layout.h"
#include "f_map.h"
#include "f_helper.h"

#include "lf_client.h"
#include "fam_stripe.h"
#include "unifycr-internal.h" /* DEBUG() macro; UNIFYCR_SUCCESS */
#include "famfs.h"


static int get_lf_meta(F_POOL_t *pool)
{
    LF_INFO_t *lf_info = pool->lf_info;
    F_POOL_DEV_t *pdev;
    fam_attr_val_t *fam_meta = NULL;
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
	      _i, fdev->pkey, fdev->virt_addr);

        free(fam_meta);
    }
    return rc;
}

static void exit_lo_maps(F_POOL_t *pool)
{
    struct list_head *l;

    list_for_each_prev(l, &pool->layouts) {
	F_LAYOUT_t *lo;

	lo = container_of(l, struct f_layout_, list);
	if (lo->slabmap)
	    f_map_exit(lo->slabmap);
	if (lo->file_ids)
	    f_map_exit(lo->file_ids);
    }
}

static int load_slab_maps(F_POOL_t *pool)
{
    struct list_head *l;
    int rc = 0;

    assert( pool->info.layouts_count ); /* check configuration! */

    /* Load Slab map for each layout */
    list_for_each_prev(l, &pool->layouts) {
	F_LAYOUT_t *lo;
	F_LAYOUT_INFO_t *info;
	F_MAP_t *sm, *file_ids;
	int sm_entry_sz;
	int r = 0;

	lo = container_of(l, struct f_layout_, list);
	info = &lo->info;

        printf("  %uD+%uP chunk:%u, stripes:%u per slab, total %u slab(s)\n",
	    info->data_chunks, (info->chunks - info->data_chunks),
	    info->chunk_sz, info->slab_stripes, info->slab_count);
	printf("  This layout has %u device(s), including %u missing.\n",
	    info->devnum, info->misdevnum);

	/* Init map struct */
	sm_entry_sz = F_SLABMAP_ENTRY_SZ(info->chunks);
	sm = f_map_init(F_MAPTYPE_STRUCTURED, sm_entry_sz, F_SLABMAP_BOSL_SZ, 0);
	if (sm == NULL) {
	    r = -ENOMEM;
	    goto _cont;
	}

	/* Set partitioned global map */
	f_map_init_prt(sm, pool->ionode_count, 0, 0, 1);

	/* This map was attached to persistent KV store in Helper process */
	sm->reg_id = info->conf_id; /* layout id */
	//sm->id = LO_TO_SM_ID(sm->reg_id); /* map id */

	/* Attach to the shared (RO) registered map in SHMEM */
	r = f_map_shm_attach(sm, F_MAPMEM_SHARED_RD);
	if (r) {
	    f_map_exit(sm);
	    goto _cont;
	}
	lo->slabmap = sm;

	/* Array of open file IDs */
	file_ids = f_map_init(F_MAPTYPE_BITMAP, 1, 0, 0);
	if (file_ids == NULL) {
	    f_map_exit(sm);
	    r = -ENOMEM;
	    goto _cont;
	}
	lo->file_ids = file_ids;

#if 0
	F_POOLDEV_INDEX_t *pdi;
	pdi = lo->devlist;
	for (u = 0; u < lo->devlist_sz; u++, pdi++) {
	    if (pdi->pool_index == F_PDI_NONE)
		continue;
	    printf("  dev#%u media id:%u [%u,%u] ext size/used/failed:%u/%u/%u\n",
		u, pdi->pool_index, pdi->idx_ag, pdi->idx_dev,
		((F_POOL_DEV_t (*)[p->ag_devs]) p->devlist)
			[pdi->idx_ag][pdi->idx_dev].extent_count,
		pdi->sha->extents_used, pdi->sha->failed_extents);
	}
#endif
_cont:
	if (r) {
	    err("Layout id:%u moniker:%s - cannot open slab map:%d\n",
		info->conf_id, info->name, r);
	    rc = rc?:r;
	}
    }
    return rc;
}

int lfs_connect(LFS_CTX_t **lfs_ctx_pp)
{
    F_POOL_t *pool;
    F_POOL_INFO_t *info;
    LFS_CTX_t *lfs_ctx_p;
    struct famsim_stats *stats_fi_wr;
    int rc = 1; /* OOM error */

    lfs_ctx_p = (LFS_CTX_t *)malloc(sizeof(LFS_CTX_t));
    if (lfs_ctx_p == NULL)
	return rc;

    pool = f_get_pool();
    assert( pool );
    info = &pool->info;

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

    stats_fi_wr = famsim_stats_create(famsim_ctx, FAMSIM_STATS_FI_WR);
    if (stats_fi_wr)
	famsim_ctx->fam_cnt = info->dev_count;

    if ((rc = f_ah_attach())) {
	DEBUG("rank:%d failed to attach to helper, error:%d",
	      dbg_rank, rc);
	goto _free;
    }

    rcu_register_thread();

    if ((rc = load_slab_maps(pool))) {
	DEBUG("rank:%d failed to load slab map(s), error:%d",
	      dbg_rank, rc);
	goto _free;
    }

#if 0
    /* default layout */
    F_LAYOUT_t *lo = f_get_layout(0);
    assert( lo );

    rc = f_map_fam_stripe(lo, &lo->fam_stripe, 0);
    if (rc == -ENOMEM)
	goto _free;
#endif

    lfs_ctx_p->pool = pool;
    lfs_ctx_p->famsim_stats_fi_wr = stats_fi_wr;
    *lfs_ctx_pp = lfs_ctx_p;
    return 0;

_free:
    free_lfc_ctx(&lfs_ctx_p);
    return rc;
}

void free_lfc_ctx(LFS_CTX_t **lfs_ctx_pp) {
    LFS_CTX_t *lfs_ctx_p = *lfs_ctx_pp;
    F_POOL_t *pool = lfs_ctx_p->pool;
    F_LAYOUT_t *lo;

    famsim_stats_stop(lfs_ctx_p->famsim_stats_fi_wr, 1);

    list_for_each_entry(lo, &pool->layouts, list) {
	free_fam_stripe(lo->fam_stripe);
    }

    exit_lo_maps(pool);
    rcu_unregister_thread();

    f_ah_detach();

    lf_clients_free(pool); /* called free_fam_stripe() */
    free(lfs_ctx_p);
    *lfs_ctx_pp = NULL;
}

