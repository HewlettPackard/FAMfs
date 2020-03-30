/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Yann Livis
 */
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "unifycr_debug.h"
#include "unifycr_const.h"
#include "famfs_env.h"
#include "famfs_error.h"
#include "famfs_maps.h"
#include "famfs_bitmap.h"
#include "f_map.h"
#include "f_pool.h"
#include "f_layout.h"
#include "f_allocator.h"
#include "f_layout_ctl.h"

/*
 * Mark slab extent failed
 *
 ^  Params
 *	lo	FAMfs layout to mrk extent in
 *	sme	pointer to the slab map entry fo that slab
 ^	slab	slab to fail extent in
 *	n	extent # to fail
 *
 *  Returns
 *	>	no update, extent already marked failed
 *	1	partial update, only the extent record
 *	2	both the slab entry and the extent record have been updated
 */
static inline int mark_extent_fail(F_LAYOUT_t *lo, F_SLABMAP_ENTRY_t *sme, f_slab_t slab, unsigned n)
{
	F_LO_PART_t *lp = lo->lp;
	F_SLAB_ENTRY_t se, old_se;
	F_EXTENT_ENTRY_t ext, old_ext;
	volatile F_SLAB_ENTRY_t *sep = &sme->slab_rec;
	volatile F_EXTENT_ENTRY_t *extp = &sme->extent_rec[n];
	bool failed = false;
	int failed_chunks = 0;
	int retries = 0, retries_max = 5;

	old_ext._v64 = __atomic_load_8(&sme->extent_rec[n], __ATOMIC_SEQ_CST);
	if (old_ext.failed) return 0; // Already set
	do {
		ext = old_ext;
		ext.failed = 1;
		ext.checksum = 0;
		ext.checksum = f_crc4_fast((char*)&ext, sizeof(ext));
		if (likely(__atomic_compare_exchange_8(extp, &old_ext, ext._v64,
			0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)))
			break;
	} while (++retries < retries_max);
	ASSERT(retries < retries_max);

	if (slab_in_sync(lp, slab)) {
		clear_slab_in_sync(lp, slab);
		lp->sync_count--;
	}

	/* Count # of failed chunks to determine if the slab is degraded or failed */
	for (n = 0; n < lo->info.chunks; n++) {
		if (sme->extent_rec[n].failed)
			failed_chunks++;
	}
	failed = failed_chunks > (lo->info.chunks - lo->info.data_chunks);
		
	retries = 0;
	old_se._v128 = __atomic_load_16(&sme->slab_rec, __ATOMIC_SEQ_CST);
	if ((old_se.failed && failed) || (old_se.degraded && !failed)) return 1; // Already set
	do {
		se = old_se;
		se.failed = failed;
		se.degraded = !failed;
		se.checksum = 0;
		se.checksum = f_crc4_sm_fast(&se);
		if (likely(__atomic_compare_exchange_16(sep, &old_se, se._v128,
			0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)))
			break;
	} while (++retries < retries_max);
	ASSERT(retries < retries_max);

	if (se.failed) 
		atomic_inc(&lp->failed_slabs);
	else
		atomic_inc(&lp->degraded_slabs);

	return 2;
}

/*
 * Fail an extent for a specific device
 */
static int fail_slab_extent(F_LAYOUT_t *lo, f_slab_t slab, int pool_index)
{
	F_LO_PART_t *lp = lo->lp;
	F_POOL_t *pool = lo->pool;
	F_SLABMAP_ENTRY_t *sme;
	F_POOL_DEV_t *pdev = f_find_pdev_by_media_id(pool, pool_index);
	int n, rc = 0;

	ASSERT(pdev && pdev->sha);
	ASSERT(slab < lp->slab_count);
	pthread_rwlock_wrlock(&lp->lock);
	sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lo->slabmap, slab);
	if (!sme) {
		LOG(LOG_ERR, "%s[%d]: error getting SM entry %u", lo->info.name, lp->part_num, slab);
		rc = -EINVAL; goto _ret;
	}	

	/* Skip unmapped sheets */
	if (!sme->slab_rec.mapped) {
		LOG(LOG_DBG, "%s[%d]: slab %u s not mapped, skipping", lo->info.name, lp->part_num, slab);
		rc = -ENOENT; goto _ret;
	}

	/* Find the right chunk */
	for (n = 0; n < lo->info.chunks; n++) {
		if (sme->extent_rec[n].media_id == pool_index)
			break;
	}

	if (n == lo->info.chunks) {
		LOG(LOG_DBG, "%s[%d]: dev %d not in slab %u, skipping", 
			lo->info.name, lp->part_num, pool_index, slab);
		rc = -ENOENT; goto _ret;
	}

	if (mark_extent_fail(lo, sme, slab, n) > 0) {
		/* Update failed extents count */
		off_t sha_off = (void *)pdev->sha - pool->pds_lfa->global;
		off_t off = sha_off + offsetof(F_PDEV_SHA_t, failed_extents);
		if (f_lfa_giafl(pool->pds_lfa->global_abd, off)) {
			LOG(LOG_WARN, "%s[%d]: error updating device %d failed exts",
				lo->info.name, lp->part_num, pool_index);		
		}
		f_map_mark_dirty(lo->slabmap, slab);
	}
_ret:
	pthread_rwlock_unlock(&lp->lock);
	return rc;
}

/*
 * Fail all extents for a specific device
 */
static int fail_slab_extents(F_LAYOUT_t *lo, int pool_index)
{
	F_LO_PART_t *lp = lo->lp;
	F_ITER_t *sm_it;
	int rc = 0, updated = 0;
	
	sm_it = f_map_get_iter(lo->slabmap, F_NO_CONDITION, 0);
	for_each_iter(sm_it) {
		f_slab_t slab = sm_it->entry;

		rc = fail_slab_extent(lo, slab, pool_index);
		if (rc) {
			if (rc != -ENOENT) {
				LOG(LOG_ERR, "%s[%d]: error marking extent in slab %d failed",
					lo->info.name, lp->part_num, rc);
			} else rc = 0;
			continue;
		}
		updated++;
	}

	LOG(LOG_DBG, "%s[%d]: marked extents failed for %d out of %d slabs",
		lo->info.name, lp->part_num, updated, lo->lp->slab_count);

	/* Wake up the allocator thread */
	if (updated) {
		atomic_inc(&lp->slabmap_version);
		pthread_cond_signal(&lp->a_thread_cond);
	}

	return rc;
}
/*
 * Mark pool device failed and update the slabmap wherever that device us used
 */
int f_fail_pdev(F_LAYOUT_t *lo, int pool_index)
{
	F_LO_PART_t *lp = lo->lp;
	F_POOLDEV_INDEX_t *pdi = f_find_pdi_by_media_id(lo, pool_index);
	int rc;

	LOG(LOG_DBG2, "%s[%d]: marking slab extents failed", lo->info.name, lp->part_num);

	if (!pdi) {
		LOG(LOG_ERR, "%s[%d]:  pool device %d lookup failed",
			lo->info.name, lp->part_num, pool_index);
		return -EINVAL;
	}

	rc = fail_slab_extents(lo, pool_index);
	if (rc) LOG(LOG_ERR, "%s[%d]: error %d marking slab extents failed",
			lo->info.name, lp->part_num, rc);

	return rc;
}


