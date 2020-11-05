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

/* Virtual map iterator function, filters unmapped slabs */ 
static int sm_is_slab_mapped(void *arg, const F_PU_VAL_t *entry)
{
	const F_SLAB_ENTRY_t *se = &entry->se;
	return (se->mapped);
}

static F_COND_t sm_slab_mapped = {
	.vf_get = &sm_is_slab_mapped,
};

/*
 * Mark slab extent failed
 *
 *  Params
 *	lo	FAMfs layout pointer
 *	sme	pointer to the slab map entry for that slab
 *	n	extent # to fail
 *
 *  Returns
 *	0	no update, extent already marked failed
 *	1	partial update, only the extent record
 *	2	both the slab entry and the extent record have been updated
 */
static inline int mark_extent_fail(F_LAYOUT_t *lo, F_SLABMAP_ENTRY_t *sme, unsigned n)
{
	F_LO_PART_t *lp = lo->lp;
	F_SLAB_ENTRY_t se, old_se;
	F_EXTENT_ENTRY_t ext, old_ext;
	f_slab_t slab = f_map_prt_to_local(lp->slabmap, stripe_to_slab(lo, sme->slab_rec.stripe_0));
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
 *
 *  Params
 *	lo		FAMfs layout pointer
 *	slab		slab # to fail an extent in
 *	pool_index	device index to fail
 *
 *  Returns
 *	0		success
 *	<0		error
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
	sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lp->slabmap, slab);
	if (!sme) {
		LOG(LOG_ERR, "%s[%d]: error getting SM entry %u", lo->info.name, lp->part_num, slab);
		rc = -EINVAL; goto _ret;
	}	

	/* Skip unmapped slabs */
	if (!sme->slab_rec.mapped) {
		LOG(LOG_DBG, "%s[%d]: slab %u not mapped, skipping", lo->info.name, lp->part_num, slab);
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

	if (mark_extent_fail(lo, sme, n) > 0) {
		/* Update failed extents count */
		off_t sha_off = (void *)pdev->sha - pool->pds_lfa->global;
		off_t off = sha_off + offsetof(F_PDEV_SHA_t, failed_extents);
		if (f_lfa_giafl(pool->pds_lfa->global_abd, off)) {
			LOG(LOG_WARN, "%s[%d]: error updating device %d failed exts",
				lo->info.name, lp->part_num, pool_index);		
		}
		LOG(LOG_DBG, "%s[%d]: marked ext %d (dev %d %s) in slab %u failed, count:%lu", 
			lo->info.name, lp->part_num, n, pool_index, 
			DevFailed(pdev->sha) ? "F" : "", slab, pdev->sha->failed_extents);
		f_map_mark_dirty(lp->slabmap, slab);
	}
_ret:
	pthread_rwlock_unlock(&lp->lock);
	return rc;
}

/*
 * Fail all extents for a specific device
 *
 *  Params
 *	lo		FAMfs layout pointer
 *	pool_index	device index to fail
 *
 *  Returns
 *	0		success
 *	<0		error
 */
static int fail_slab_extents(F_LAYOUT_t *lo, int pool_index)
{
	F_LO_PART_t *lp = lo->lp;
	F_ITER_t *sm_it;
	int rc = 0, updated = 0;
	
	sm_it = f_map_get_iter(lp->slabmap, sm_slab_mapped, 0);
	for_each_iter(sm_it) {
		f_slab_t slab = sm_it->entry;

		rc = fail_slab_extent(lo, slab, pool_index);
		if (rc) {
			if (rc != -ENOENT) {
				LOG(LOG_ERR, "%s[%d]: error %d marking extent in slab %u failed",
					lo->info.name, lp->part_num, rc, slab);
			} else rc = 0;
			continue;
		}
		updated++;
	}

	LOG(LOG_DBG, "%s[%d]: marked extents failed for %d out of %d slabs",
		lo->info.name, lp->part_num, updated, lo->lp->slab_count);

	/* Wake up the allocator thread */
	if (updated) {
		if (log_print_level > 0)
			f_print_sm(dbg_stream, lp->slabmap, lo->info.chunks, lo->info.slab_stripes);
		rc = f_map_flush(lp->slabmap);
		if (rc) LOG(LOG_ERR, "%s[%d]: error %d flushing slab map", 
			lo->info.name, lp->part_num, rc);
		atomic_inc(&lp->slabmap_version);
		pthread_cond_signal(&lp->a_thread_cond);
	}

	return rc;
}

/*
 * Mark pool device failed and update the slabmap wherever that device us used
 *
 *  Params
 *	lo		FAMfs layout pointer
 *	pool_index	device index to fail
 *
 *  Returns
 *	0		success
 *	<0		error
 */
int f_fail_pdev(F_LAYOUT_t *lo, int pool_index)
{
	F_LO_PART_t *lp = lo->lp;
	F_POOLDEV_INDEX_t *pdi = f_find_pdi_by_media_id(lo, pool_index);
	int rc;

	LOG(LOG_DBG2, "%s[%d]: marking slab extents failed", lo->info.name, lp->part_num);

	if (!pdi) {
		LOG(LOG_ERR, "%s[%d]: pool device %d lookup failed",
			lo->info.name, lp->part_num, pool_index);
		return -EINVAL;
	}

	rc = fail_slab_extents(lo, pool_index);
	if (rc) LOG(LOG_ERR, "%s[%d]: error %d marking slab extents failed",
			lo->info.name, lp->part_num, rc);

	return rc;
}

/*
 * Replace slab extent
 *
 ^  Params
 *	lo	FAMfs layout
 *	ext	new extent record pointer
 *	sme	pointer to the slab map entry fo that slab
 *	n	extent # to replace
 *
 *  Returns
 *	0	no update, extent already replaced
 *	1	partial update, only the extent record updated
 *	2	both the slab entry and the extent record have been updated
 */
static inline int replace_extent(F_LAYOUT_t *lo, F_EXTENT_ENTRY_t *pext,
	F_SLABMAP_ENTRY_t *sme, unsigned n)
{
	F_LO_PART_t *lp = lo->lp;
	F_SLAB_ENTRY_t se, old_se;
	f_slab_t slab = f_map_prt_to_local(lp->slabmap, stripe_to_slab(lo, sme->slab_rec.stripe_0));
	F_EXTENT_ENTRY_t old_ext;
	volatile F_SLAB_ENTRY_t *sep = &sme->slab_rec;
	volatile F_EXTENT_ENTRY_t *extp = &sme->extent_rec[n];
	bool failed = false;
	int failed_chunks = 0;
	int retries = 0, retries_max = 5;

	old_ext._v64 = __atomic_load_8(&sme->extent_rec[n], __ATOMIC_SEQ_CST);
	if (old_ext._v64 == pext->_v64) return 0;
	do {
		pext->failed = 1;
		pext->checksum = 0;
		pext->checksum = f_crc4_fast((char*)pext, sizeof(*pext));
		if (likely(__atomic_compare_exchange_8(extp, &old_ext, pext->_v64,
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
 * Allocate device extent to replace a failed extent in a slab. Least utilized device is used 
 * to allocate the replacement extent.
 * Used by the slab extent replace function.
 *
 *  Params
 *	lo		FAMfs layout partition pointer
 *	pext		extent record pointer (to update)
 *	sme		slab map entry pointer
 *
 *  Returns
 *	>=0		success, returns allocated extent #
 *	<0		error
 */
static int alloc_extent_by_util(F_LO_PART_t *lp, F_EXTENT_ENTRY_t *pext, F_SLABMAP_ENTRY_t *sme)
{
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	f_slab_t slab = f_map_prt_to_local(lp->slabmap, stripe_to_slab(lo, sme->slab_rec.stripe_0));
	F_POOLDEV_INDEX_t *sorted_devlist = NULL;
	unsigned devnum = pool->pool_ags * pool->ag_devs;
	int i, rc = -ENOSPC;

	sorted_devlist = calloc(pool->pool_ags, sizeof(F_POOLDEV_INDEX_t));
	if (!sorted_devlist) {
		LOG(LOG_ERR, "%s[%d]: error allocating device list array", lo->info.name, lp->part_num);
		return 0;
	}

	pthread_rwlock_wrlock(&pool->lock);

	/* Make sure the next allocator thread sees an updated list */ 
	rc = lp->dmx->gen_devlist_for_replace(lp->dmx, sorted_devlist, &devnum, sme);
	if (rc) {
		LOG(LOG_ERR, "%s[%d]: slab %u: error %d in gen_devlist",
			lo->info.name, lp->part_num, slab, rc);
		return 0;
	}

	for (i = 0; i < devnum; i++) {
		F_POOLDEV_INDEX_t *pdi = &sorted_devlist[i];		
		ASSERT(pdi->pool_index != F_PDI_NONE);

		if (ag_used_in_slab(lo, sme, pdi->pool_index))
			continue;

		/* Try to allocate a device extent */
		pext->media_id = pdi->pool_index;
		rc = f_alloc_dev_extent(lp, pext);
		if (rc < 0) {
			LOG(LOG_WARN, "%s[%d]: allocation failed on device %d rc=%d", 
				lo->info.name, lp->part_num, pdi->pool_index, rc);
			continue;
		}

		LOG(LOG_DBG, "%s[%d]: allocated extent %d from device %d",
			lo->info.name, lp->part_num, rc, pdi->pool_index);
		goto _ret;
	}

	LOG(LOG_ERR, "%s[%d]: no devices found for allocation", lo->info.name, lp->part_num);
	rc = -ENOSPC;

_ret:
	pthread_rwlock_unlock(&pool->lock);
	free(sorted_devlist);

	return rc;
}

/* 
 * Allocate device extent to replace a failed extent in a slab by an extent from a specific device.
 * Used by the slab extent replace function.
 *
 *  Params
 *	lo		FAMfs layout partition pointer
 *	pext		extent record pointer (to update)
 *	pool_index	if not F_PDI_NONE, allocate new extent from that device
 *
 *  Returns
 *	>=0		success, returns allocated extent #
 *	<0		error
 */
static int alloc_extent_by_idx(F_LO_PART_t *lp, F_EXTENT_ENTRY_t *pext, int pool_index)
{
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	int rc = -ENOSPC;

	pthread_rwlock_wrlock(&pool->lock);

	/* Try to allocate a device extent */
	pext->media_id = pool_index;
	rc = f_alloc_dev_extent(lp, pext);
	if (rc < 0) {
		LOG(LOG_ERR, "%s[%d]: allocation failed on device %d, rc=%d", 
			lo->info.name, lp->part_num, pool_index, rc);
	} else {

		LOG(LOG_DBG, "%s[%d]: allocated extent %d from device %d",
			lo->info.name, lp->part_num, rc, pool_index);
	}

	pthread_rwlock_unlock(&pool->lock);

	return rc;
}

/* 
 * Allocate device extent to replace a failed extent in a slab.
 * If pool_index provided allocate the extent from that device, otherwise 
 * use the utilization based allocation.
 * Used by the slab extent replace function.
 *
 *  Params
 *	lo		FAMfs layout partition pointer
 *	pext		extent record pointer (to update)
 *	sme		slab map entry pointer
 *	pool_index	if not F_PDI_NONE, allocate new extent from that device
 *
 *  Returns
 *	>=0		success, returns allocated extent #
 *	<0		error
 */
static int alloc_extent2replace(F_LO_PART_t *lp, F_EXTENT_ENTRY_t *pext, 
	F_SLABMAP_ENTRY_t *sme, int pool_index)
{
	F_LAYOUT_t *lo = lp->layout;
	int extent;

	if (pool_index != F_PDI_NONE && ag_used_in_slab(lo, sme, pool_index)) return -EINVAL;

	extent = (pool_index != F_PDI_NONE) ? alloc_extent_by_idx(lp, pext, pool_index) :
		alloc_extent_by_util(lp, pext, sme);

	if (extent >= 0) {
		/* Fill in the extent */
		pext->extent = extent;
		pext->mapped = 1;
		pext->failed = 1;
		pext->checksum = 0;
		pext->checksum = f_crc4_fast((char*)pext, sizeof(*pext));
	} else {
		memset(pext, 0, sizeof(F_EXTENT_ENTRY_t));
	}

	return extent;
}

/*
 * Do extents replacement:
 *	- allocate a replacement extent from the pool or the src_idx device
 *	- update the slab map entry with the new extent info
 *	- release the old extent and update counters  
 *  Params
 *	lo		FAMfs layout pointer
 *	sme		slab map entry pointer
 *	n		extent # to replace
 *	src_idx		if not F_PDI_NONE, allocate new extent from the src_idx device
 *
 *  Returns
 *	0		success
 *	<0		error
 */
static int do_replace_extent(F_LAYOUT_t *lo, f_slab_t slab, F_SLABMAP_ENTRY_t *sme, 
	int n, int src_idx)
{
	F_LO_PART_t *lp = lo->lp;
	F_POOL_t *pool = lo->pool;
	F_EXTENT_ENTRY_t ext, old_ext = sme->extent_rec[n];
	int rc;

	LOG(LOG_DBG2, "%s[%d]: replacing extent @%d", lo->info.name, lp->part_num, n);
	memset(&ext, 0, sizeof(F_EXTENT_ENTRY_t));
	rc = alloc_extent2replace(lp, &ext, sme, src_idx);
	if (rc < 0) {
		LOG(LOG_ERR, "%s[%d]: failed to allocate replacement extent @%d",
			lo->info.name, lp->part_num, n);
		return rc;
	}

	/*
	 * Update the slab map extents. Mark the replaced extent
	 * failed so it will be picked up by recovery
	 */
	if (!replace_extent(lo, &ext, sme, n)) {
		LOG(LOG_WARN, "%s[%d]: extent @%d already replaced",
			lo->info.name, lp->part_num, n);
		return -ESRCH;

	}
	/* Update failed extents count */
	F_POOL_DEV_t *pdev = f_find_pdev_by_media_id(pool, ext.media_id);
	off_t sha_off = (void *)pdev->sha - pool->pds_lfa->global;
	off_t off = sha_off + offsetof(F_PDEV_SHA_t, failed_extents);
	if (f_lfa_giafl(pool->pds_lfa->global_abd, off)) {
		LOG(LOG_WARN, "%s[%d]: error updating device %d failed exts",
			lo->info.name, lp->part_num, ext.media_id);		
	}

	/* Release the original device extent */
	if (old_ext.mapped)
		f_release_dev_extent(lp, &old_ext);

	LOG(LOG_DBG, "%s[%d]: replaced ext %d (dev %d %s) in slab %u, count:%lu", 
		lo->info.name, lp->part_num, n, ext.media_id,
		DevFailed(pdev->sha) ? "F" : "", slab, pdev->sha->failed_extents);
	return 0;
}

/*
 * Replace all or specified failed extents in the slab by available pool extents or by 
 * the extents from the source device if given
 *
 *  Params
 *	lo		FAMfs layout pointer
 *	slab		slab # for replacement
 *	tgt_idx		replace all extents from that device
 *	src_idx		by extents from src_idx device
 *
 *  Returns
 *	0		success
 *	<0		error
 */
static int replace_slab_extent(F_LAYOUT_t *lo, f_slab_t slab, int tgt_idx, int src_idx)
{
	F_LO_PART_t *lp = lo->lp;
	F_SLABMAP_ENTRY_t *sme;
	int n, replaced = 0, rc = 0;

	ASSERT(slab < lp->slab_count);

	pthread_rwlock_wrlock(&lp->lock);
	sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lp->slabmap, slab);
	if (!sme) {
		LOG(LOG_ERR, "%s[%d]: error getting SM entry %u", lo->info.name, lp->part_num, slab);
		rc = -EINVAL; goto _ret;
	}	

	/* Skip unmapped slabs */
	if (!sme->slab_rec.mapped) {
		LOG(LOG_DBG, "%s[%d]: slab %u not mapped, skipping", lo->info.name, lp->part_num, slab);
		rc = -ENOENT; goto _ret;
	}

	/* Skip failed slabs */
	if (sme->slab_rec.failed) {
		LOG(LOG_DBG, "%s[%d]: slab %u is failed, skipping", lo->info.name, lp->part_num, slab);
		rc = -ENOENT; goto _ret;
	}

	/* Skip not degraded slabs */
	if (!sme->slab_rec.degraded) {
		LOG(LOG_DBG, "%s[%d]: slab %u is not degraded, skipping", 
			lo->info.name, lp->part_num, slab);
		rc = -ENOENT; goto _ret;
	}

	/* Find a failed extent */
	for (n = 0; n < lo->info.chunks; n++) {
		if (sme->extent_rec[n].media_id == tgt_idx || (tgt_idx == F_PDI_NONE && sme->extent_rec[n].failed)) {
			rc = do_replace_extent(lo, slab, sme, n, src_idx);
			if (!rc) replaced++;
		}
		/* If we are only replacing the tgt_idx extents, we are done here */
		if (sme->extent_rec[n].media_id == tgt_idx) break;
	}

	if (n == lo->info.chunks && !replaced) {
		LOG(LOG_DBG, "%s[%d]: no failed extents in slab %u, skipping", 
			lo->info.name, lp->part_num, slab);
		rc = -ENOENT; goto _ret;
	}

	LOG(LOG_DBG, "%s[%d]: replaced %d extents in slab %u", 
		lo->info.name, lp->part_num, replaced, slab); 
	f_map_mark_dirty(lp->slabmap, slab);
_ret:
	pthread_rwlock_unlock(&lp->lock);
	return rc;
}

/*
 * Replace failed extents by available pool extents unless src_idx is passed
 *
 *  Params
 *	lo		FAMfs layout pointer
 *	tgt_idx		replace all extents from that device
 *	src_idx		by extents from src_idx device
 *
 *  Returns
 *	0		success
 *	<0		error
 */
static int replace_slab_extents(F_LAYOUT_t *lo, int tgt_idx, int src_idx)
{
	F_LO_PART_t *lp = lo->lp;
	F_ITER_t *sm_it;
	int rc = 0, updated = 0;
	
	sm_it = f_map_get_iter(lp->slabmap, sm_slab_mapped, 0);
	for_each_iter(sm_it) {
		f_slab_t slab = sm_it->entry;

		/* Skip unused slabs, the allocator will release them */
		if (!slab_used(lp, slab_to_stripe0(lo, slab))) {
			LOG(LOG_DBG, "%s[%d]: slab %u not used in_sync:%d", 
				lo->info.name, lp->part_num, slab, slab_in_sync(lp, slab));
			continue;
		}

		rc = replace_slab_extent(lo, slab, tgt_idx, src_idx);
		if (rc) {
			if (rc != -ENOENT) {
				LOG(LOG_ERR, "%s[%d]: error %d replacing extent in slab %u",
					lo->info.name, lp->part_num, rc, slab);
			} else rc = 0;
			continue;
		}
		updated++;
	}

	LOG(LOG_DBG, "%s[%d]: replaced extents for %d out of %d slabs",
		lo->info.name, lp->part_num, updated, lp->slab_count);

	/* Flush slabmap and wake up the allocator thread */
	if (updated) {
		if (log_print_level > 0)
			f_print_sm(dbg_stream, lp->slabmap, lo->info.chunks, lo->info.slab_stripes);
		rc = f_map_flush(lp->slabmap);
		if (rc) LOG(LOG_ERR, "%s[%d]: error %d flushing slab map", 
			lo->info.name, lp->part_num, rc);
		atomic_inc(&lp->slabmap_version);
		pthread_cond_signal(&lp->a_thread_cond);
	}

	return rc;
}

/*
 * Replace pool device extent:
 * 1) no parameters: all failed extents replaced from the pool
 * 2) only tgt_idx passsed: replace all extents from that device
 *	by the available pool extents
 * 3) both src_idx and tgt_idx passed: replace all extents from tgt_idx
 *	by the extents from src_idx device
 *
 *  Params
 *	lo		FAMfs layout pointer
 *	tgt_idx		replace all extents from that device
 *	src_idx		by extents from src_idx device
 *
 *  Returns
 *	0		success
 *	<0		error
 */
int f_replace(F_LAYOUT_t *lo, int tgt_idx, int src_idx)
{
	F_LO_PART_t *lp = lo->lp;
	int rc;

	LOG(LOG_DBG2, "%s[%d]: replacing slab extents from dev %d%s by extents from dev %d%s", 
		lo->info.name, lp->part_num, tgt_idx, tgt_idx == F_PDI_NONE ? "(all failed)" : "", 
		src_idx, tgt_idx == F_PDI_NONE ? "(all in pool)" : "");

	/* Validate parmeters */
	if (tgt_idx != F_PDI_NONE) {
		/* Replace all extents for a specific device */
		F_POOLDEV_INDEX_t *tgt_pdi = f_find_pdi_by_media_id(lo, tgt_idx);
		F_POOLDEV_INDEX_t *src_pdi;
		
		if (!tgt_pdi) {
			LOG(LOG_ERR, "%s[%d]: invalid target device %d",
				lo->info.name, lp->part_num, tgt_idx);
			return -EINVAL;
		}

		/* Replace all extents for a target device only by extents from a source device */
		if (src_idx != F_PDI_NONE) {
			/* Source device index passed in the command */
			src_pdi = f_find_pdi_by_media_id(lo, src_idx);
			if (!src_pdi) {
				LOG(LOG_ERR, "%s[%d]: invalid source device %d",
					lo->info.name, lp->part_num, src_idx);
				return -EINVAL;
			}
		}
	}

	rc = replace_slab_extents(lo, tgt_idx, src_idx);
	if (rc) LOG(LOG_ERR, "%s[%d]: error %d replacing slab extents tgt/src: %d/%d",
		lo->info.name, lp->part_num, rc, tgt_idx, src_idx);

	return rc;
}

/*
 * Set IO-node ranks in the pool ionodes array.
 *
 *  Params
 *	pool		FAMfs pool pointer
 *
 *  Returns
 *	0		success
 *	<0		error
 */
int f_set_ionode_ranks(F_POOL_t *pool)
{
    int *idxbuf, io_idx = pool->mynode.ionode_idx;
    int rank, cnt, rc, i, n, hcnt, hidx = 0;

    ASSERT(pool->mynode.ionode_idx < pool->ionode_count);

    rc = MPI_Comm_rank(pool->helper_comm, &rank);
    if (rc != MPI_SUCCESS) return rc;

    rc = MPI_Comm_size(pool->helper_comm, &cnt);
    if (rc != MPI_SUCCESS) return rc;

    idxbuf = alloca(cnt*sizeof(io_idx));
    if (!idxbuf) return -ENOMEM;
    memset(idxbuf, 0, cnt*sizeof(io_idx));

    /*
     * Synchronize all allocator and helper threads across all nodes and 
     * exchange IO-node ranks
     */ 
    idxbuf[rank] = NodeIsIOnode(&pool->mynode) ? io_idx : -1;
    rc = MPI_Allgather(MPI_IN_PLACE, sizeof(io_idx), MPI_BYTE, idxbuf, 
            sizeof(io_idx), MPI_BYTE, pool->helper_comm);
    if (rc != MPI_SUCCESS) return rc;

    for (i = 0, n = 0, hcnt = 0; i < cnt; i++) {
        if (idxbuf[i] != -1) {
            uint16_t idx = idxbuf[i];
            F_IONODE_INFO_t *ioi;
            ASSERT(idx < pool->ionode_count);
            pool->ionodes[idx].rank = i;
            ioi = &pool->ionodes[idx];
            if (!rank) printf("IO-node %s: idx %d rank %d\n", ioi->hostname, idx, ioi->rank);
            n++;
        } else {
            // this rank is CN's helper, is it me?
            if (rank == i)
                hidx = hcnt;
            hcnt++;
        }
    }
    pool->mynode.my_ion = pool->ionodes[hidx%pool->ionode_count].rank;
    return n == pool->ionode_count ? 0 : -EINVAL;
}

/*
 * Mark slab recovering
 *
 *  Params
 *	lo	FAMfs layout pointer
 *	sme	pointer to the slab map entry for that slab
 *
 *  Returns
 *	0	no update, already marked recovering
 *	1	slab entry have been updated
 */
static inline int mark_slab_recovering(F_LAYOUT_t *lo, volatile F_SLABMAP_ENTRY_t *sme)
{
	F_LO_PART_t *lp = lo->lp;
	F_SLAB_ENTRY_t se, old_se;
	f_slab_t slab = f_map_prt_to_local(lp->slabmap, stripe_to_slab(lo, sme->slab_rec.stripe_0));
	volatile F_SLAB_ENTRY_t *sep = &sme->slab_rec;
	int retries = 0, retries_max = 5;

	ASSERT(!slab_in_sync(lp, slab));

	old_se._v128 = __atomic_load_16(&sme->slab_rec, __ATOMIC_SEQ_CST);
	ASSERT(old_se.mapped && old_se.degraded && !old_se.failed);
	if (old_se.recovery) return 0; // Already set
	do {
		se = old_se;
		se.recovery = 1;
		se.recovered = 0;
		se.checksum = 0;
		se.checksum = f_crc4_sm_fast(&se);
		if (likely(__atomic_compare_exchange_16(sep, &old_se, se._v128,
			0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)))
			break;
	} while (++retries < retries_max);
	ASSERT(retries < retries_max);

	return 1;
}

/*
 * Mark slab recovering
 *
 *  Params
 *	lo		FAMfs layout pointer
 *	slab		slab # to mark
 *
 *  Returns
 *	0		success
 *	<0		error
 */
int f_mark_slab_recovering(F_LAYOUT_t *lo, f_slab_t slab)
{
	F_LO_PART_t *lp = lo->lp;
	volatile F_SLABMAP_ENTRY_t *sme;

	ASSERT(slab < lp->slab_count);
	sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lp->slabmap, slab);
	if (!sme) {
		LOG(LOG_ERR, "%s[%d]: error getting SM entry %u", lo->info.name, lp->part_num, slab);
		return -EINVAL;
	}	

	/* Skip unmapped slabs */
	if (!sme->slab_rec.mapped) {
		LOG(LOG_DBG, "%s[%d]: slab %u not mapped, skipping", lo->info.name, lp->part_num, slab);
		return -ENOENT;
	}

	if (mark_slab_recovering(lo, sme) > 0) {
		LOG(LOG_DBG, "%s[%d]: marked slab %u recovering", lo->info.name, lp->part_num, slab);
		f_map_mark_dirty(lp->slabmap, slab);
	}

	f_map_mark_dirty(lp->slabmap, slab);
	return 0;
}

/*
 * Clear slab recovering, resets slab recovery state
 *
 *  Params
 *	lo	FAMfs layout pointer
 *	sme	pointer to the slab map entry for that slab
 *
 *  Returns
 *	0	no update, already cleared
 *	1	slab entry have been updated
 */
static inline int clear_slab_recovering(F_LAYOUT_t *lo, volatile F_SLABMAP_ENTRY_t *sme)
{
	F_LO_PART_t *lp = lo->lp;
	F_SLAB_ENTRY_t se, old_se;
	f_slab_t slab = f_map_prt_to_local(lp->slabmap, stripe_to_slab(lo, sme->slab_rec.stripe_0));
	volatile F_SLAB_ENTRY_t *sep = &sme->slab_rec;
	int retries = 0, retries_max = 5;

	ASSERT(!slab_in_sync(lp, slab));

	old_se._v128 = __atomic_load_16(&sme->slab_rec, __ATOMIC_SEQ_CST);
	ASSERT(old_se.mapped && old_se.degraded && !old_se.failed);
	if (!old_se.recovery) return 0; // Already cleared
	do {
		se = old_se;
		se.rc = 0;
		se.checksum = 0;
		se.checksum = f_crc4_sm_fast(&se);
		if (likely(__atomic_compare_exchange_16(sep, &old_se, se._v128,
			0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)))
			break;
	} while (++retries < retries_max);
	ASSERT(retries < retries_max);

	return 1;
}

/*
 * Clear slab recovering, resets slab recovery state
 *
 *  Params
 *	lo		FAMfs layout pointer
 *	slab		slab # to clear
 *
 *  Returns
 *	0		success
 *	<0		error
 */
int f_clear_slab_recovering(F_LAYOUT_t *lo, f_slab_t slab)
{
	F_LO_PART_t *lp = lo->lp;
	volatile F_SLABMAP_ENTRY_t *sme;

	ASSERT(slab < lp->slab_count);
	sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lp->slabmap, slab);
	if (!sme) {
		LOG(LOG_ERR, "%s[%d]: error getting SM entry %u", lo->info.name, lp->part_num, slab);
		return -EINVAL;
	}	

	/* Skip unmapped slabs */
	if (!sme->slab_rec.mapped) {
		LOG(LOG_DBG, "%s[%d]: slab %u not mapped, skipping", lo->info.name, lp->part_num, slab);
		return -ENOENT;
	}

	if (clear_slab_recovering(lo, sme) > 0) {
		LOG(LOG_DBG, "%s[%d]: marked slab %u recovering", lo->info.name, lp->part_num, slab);
		f_map_mark_dirty(lp->slabmap, slab);
	}

	f_map_mark_dirty(lp->slabmap, slab);
	return 0;
}

/*
 * Mark slab recovered, i.e. clear recovery and degraded flags and reset failed extents
 *
 *  Params
 *	lo	FAMfs layout pointer
 *	sme	pointer to the slab map entry for that slab
 *
 *  Returns
 *	0	no update, extents and the slab entry already cleared
 *	1	partial update, only the slab record
 *	>1	the slab entry and the extent records have been updated
 */
static inline int mark_slab_recovered(F_LAYOUT_t *lo, volatile F_SLABMAP_ENTRY_t *sme)
{
	F_LO_PART_t *lp = lo->lp;
	F_SLAB_ENTRY_t se, old_se;
	F_EXTENT_ENTRY_t ext, old_ext;
	f_slab_t slab = f_map_prt_to_local(lp->slabmap, stripe_to_slab(lo, sme->slab_rec.stripe_0));
	volatile F_SLAB_ENTRY_t *sep = &sme->slab_rec;
	int retries = 0, retries_max = 5;
	int n, rc = 0;

	for (n = 0; n < lo->info.chunks; n++) {
		if (sme->extent_rec[n].failed) {
			volatile F_EXTENT_ENTRY_t *extp = &sme->extent_rec[n];
			old_ext._v64 = __atomic_load_8(&sme->extent_rec[n], __ATOMIC_SEQ_CST);
			do {
				ext = old_ext;
				ext.failed = 0;
				ext.checksum = 0;
				ext.checksum = f_crc4_fast((char*)&ext, sizeof(ext));
				if (likely(__atomic_compare_exchange_8(extp, &old_ext, ext._v64,
					0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)))
					break;
			} while (++retries < retries_max);
			ASSERT(retries < retries_max);
			rc++;
		}
	}

	retries = 0;
	old_se._v128 = __atomic_load_16(&sme->slab_rec, __ATOMIC_SEQ_CST);
	do {
		se = old_se;
		se.rc = 0;
		se.degraded = 0;
		se.checksum = 0;
		se.checksum = f_crc4_sm_fast(&se);
		if (likely(__atomic_compare_exchange_16(sep, &old_se, se._v128,
			0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)))
			break;
	} while (++retries < retries_max);
	ASSERT(retries < retries_max);
	rc++;

	if (!slab_in_sync(lp, slab)) {
		set_slab_in_sync(lp, slab);
		lp->sync_count++;
		atomic_dec(&lp->degraded_slabs);
	}

	return rc;
}

/*
 * Mark slab recovered, i.e. clear recovery and degraded flags and reset failed extents
 *
 *  Params
 *	lo		FAMfs layout pointer
 *	slab		slab # to mark
 *
 *  Returns
 *	0		success
 *	<0		error
 */
int f_mark_slab_recovered(F_LAYOUT_t *lo, f_slab_t slab)
{
	F_LO_PART_t *lp = lo->lp;
	volatile F_SLABMAP_ENTRY_t *sme;

	ASSERT(slab < lp->slab_count);
	sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lp->slabmap, slab);
	if (!sme) {
		LOG(LOG_ERR, "%s[%d]: error getting SM entry %u", lo->info.name, lp->part_num, slab);
		return -EINVAL;
	}	

	/* Skip unmapped slabs */
	if (!sme->slab_rec.mapped) {
		LOG(LOG_DBG, "%s[%d]: slab %u not mapped, skipping", lo->info.name, lp->part_num, slab);
		return -EINVAL;
	}

	if (sme->slab_rec.failed || !sme->slab_rec.degraded) {
		LOG(LOG_DBG, "%s[%d]: slab %u failed or not degraded, skipping", 
			lo->info.name, lp->part_num, slab);
		return -EINVAL;
	}

	if (!sme->slab_rec.recovery) {
		LOG(LOG_DBG, "%s[%d]: slab %u not recovering, skipping", 
			lo->info.name, lp->part_num, slab);
		return -EINVAL;
	}

	if (mark_slab_recovered(lo, sme) > 0) {
		LOG(LOG_DBG, "%s[%d]: marked slab %u recovered", lo->info.name, lp->part_num, slab);
		f_map_mark_dirty(lp->slabmap, slab);
		if (log_print_level > 0)
			f_print_sm(dbg_stream, lp->slabmap, lo->info.chunks, lo->info.slab_stripes);
	}

	f_map_mark_dirty(lp->slabmap, slab);

	return 0;
}

/*
 * Check if the stripe belongs to a heathy slab, i.e. not degraded or failed
 *
 *  Params
 *	lo		FAMfs layout pointer
 *	s		stripe to check
 *
 *  Returns
 *	true		healthy slab
 *	false		not mapped or failed or degraded
 */
bool f_stripe_slab_healthy(F_LAYOUT_t *lo, f_stripe_t s)
{
	F_LO_PART_t *lp = lo->lp;
	f_slab_t slab = stripe_to_slab(lo, s);
	volatile F_SLABMAP_ENTRY_t *sme;

	ASSERT(slab < lp->slab_count);
	sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lp->slabmap, slab);
	if (!sme) {
		LOG(LOG_ERR, "%s[%d]: error getting SM entry %u", lo->info.name, lp->part_num, slab);
		return false;
	}	

	return (sme->slab_rec.mapped && !sme->slab_rec.failed && !sme->slab_rec.degraded);
}
