/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Yann Livis
 */

#ifndef F_LAYOUT_CTL_H
#define F_LAYOUT_CTL_H

#include "famfs_bitmap.h"

/*
 * Mark pool device failed and update the slabmap wherever that device us used
 ^
 ^  Params
 *	lo		layout to fail device in
 *	pool_index	pool index to fail
 ^
 ^  Returns
 *      0               success
 *      <>0             error
 */
int f_fail_pdev(F_LAYOUT_t *lo, int pool_index);

/*
 * Replace pool device extent:
 * 1) no parameters: all failed extents replaced from the pool
 * 2) only tgt_idx passsed: replace all extents from that device
 *	by the available pool extents
 * 3) both src_idx and tgt_idx passed: replace all extents from tgt_idx
 *	by the extents from src_idx device
 ^
 ^  Params
 *	lo		layout pointer
 *	tgt_idx		replace all extents from that device
 *	src_idx		by extents from src_idx device
 ^
 ^  Returns
 *      0               success
 *      <>0             error
 */
int f_replace(F_LAYOUT_t *lo, int tgt_idx, int src_idx);

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
int f_set_ionode_ranks(F_POOL_t *pool);

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
int f_mark_slab_recovering(F_LAYOUT_t *lo, f_slab_t slab);

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
int f_clear_slab_recovering(F_LAYOUT_t *lo, f_slab_t slab);

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
int f_mark_slab_recovered(F_LAYOUT_t *lo, f_slab_t slab);

/*
 * Check if the stripe belongs to a heathy slab, i.e. mapped and not degraded or failed
 *
 *  Params
 *	lo		FAMfs layout pointer
 *	s		stripe to check
 *
 *  Returns
 *	true		healthy slab
 *	false		not mapped or failed or degraded
 */
bool f_stripe_slab_healthy(F_LAYOUT_t *lo, f_stripe_t s);

/* 
 * Slab allocation bitmap manipulation routines 
 */
static inline void set_slab_bit(F_LO_PART_t *lp, f_slab_t slab, unsigned long *bmap)
{
	ASSERT(slab < lp->slab_count);
	set_bit(slab, bmap);
}

static inline void clear_slab_bit(F_LO_PART_t *lp, f_slab_t slab, unsigned long *bmap)
{
	ASSERT(slab < lp->slab_count);
	clear_bit(slab, bmap);
}

static inline bool slab_bit_set(F_LO_PART_t *lp, f_slab_t slab, unsigned long *bmap)
{
	ASSERT(slab < lp->slab_count);
	return test_bit(slab, bmap);
}

static inline void set_slab_allocated(F_LO_PART_t *lp, f_slab_t slab)
{
	atomic_inc(&lp->allocated_slabs);
	return set_slab_bit(lp, slab, lp->slab_bmap);
}

static inline void clear_slab_allocated(F_LO_PART_t *lp, f_slab_t slab)
{
	atomic_dec(&lp->allocated_slabs);
	return clear_slab_bit(lp, slab, lp->slab_bmap);
}

static inline int slab_allocated(F_LO_PART_t *lp, f_slab_t slab)
{
	return slab_bit_set(lp, slab, lp->slab_bmap);
}

static inline int slabs_allocated(F_LO_PART_t *lp)
{
	return bitmap_weight(lp->slab_bmap, lp->slab_count);
}

static inline int max_slab_allocated(F_LO_PART_t *lp)
{
	return find_last_bit(lp->slab_bmap, lp->slab_count);
}

static inline bool all_slabs_allocated(F_LO_PART_t *lp)
{
	F_LAYOUT_t *lo = lp->layout;
	return (slabs_allocated(lp) == lp->slab_count || LayoutNoSpace(lo));
}

static inline void set_slab_in_sync(F_LO_PART_t *lp, f_slab_t slab)
{
	return set_slab_bit(lp, slab, lp->sync_bmap);
}

static inline void clear_slab_in_sync(F_LO_PART_t *lp, f_slab_t slab)
{
	return clear_slab_bit(lp, slab, lp->sync_bmap);
}

static inline int slab_in_sync(F_LO_PART_t *lp, f_slab_t slab)
{
	return slab_bit_set(lp, slab, lp->sync_bmap);
}

static inline f_slab_t stripe_to_slab(F_LAYOUT_t *lo, f_stripe_t stripe)
{
	return (stripe / lo->info.slab_stripes);
}

static inline f_stripe_t slab_to_stripe0(F_LAYOUT_t *lo, f_slab_t slab)
{
	return (slab * lo->info.slab_stripes);
}

static inline void inc_slab_used(F_LO_PART_t *lp, f_stripe_t stripe)
{
	f_slab_t slab = stripe_to_slab(lp->layout, stripe);
	ASSERT(slab < lp->slab_count);
	ASSERT(++(lp->slab_usage[slab].used) <= lp->layout->info.slab_stripes);
	atomic_inc(&lp->allocated_stripes);
}

static inline void dec_slab_used(F_LO_PART_t *lp, f_stripe_t stripe)
{
	f_slab_t slab = stripe_to_slab(lp->layout, stripe);
	ASSERT(slab < lp->slab_count);
	lp->slab_usage[slab].used--;
	atomic_dec(&lp->allocated_stripes);
}

static inline int slab_used(F_LO_PART_t *lp, f_stripe_t stripe)
{
	f_slab_t slab = stripe_to_slab(lp->layout, stripe);
	ASSERT(slab < lp->slab_count);
	return lp->slab_usage[slab].used;
}

static inline void reset_slab_usage(F_LO_PART_t *lp, f_slab_t slab)
{
	ASSERT(slab < lp->slab_count);
	lp->slab_usage[slab].used = 0;	
}

static inline bool slab_full(F_LO_PART_t *lp, f_stripe_t stripe)
{
	return (slab_used(lp, stripe) == lp->layout->info.slab_stripes);
}

static inline bool ag_used_in_slab(F_LAYOUT_t *lo, F_SLABMAP_ENTRY_t *sme, int pool_index)
{
	F_LO_PART_t *lp = lo->lp;
	F_POOLDEV_INDEX_t *pdi0 = f_find_pdi_by_media_id(lo, pool_index);
	int n;

	for (n = 0; n < lo->info.chunks; n++) {
		F_POOLDEV_INDEX_t *pdi = f_find_pdi_by_media_id(lo, sme->extent_rec[n].media_id);
		if (sme->extent_rec[n].failed) continue; // skip failed extents
		if (pdi->idx_ag == pdi0->idx_ag) {
			LOG(LOG_DBG, "%s[%d]: device %d AG(%d) used by extent %d",
				lo->info.name, lp->part_num, pool_index, pdi->idx_ag, n);
			return true;
		}
	}
	return false;
}

static inline struct f_stripe_set *ss_alloc(size_t size)
{
	struct f_stripe_set *ss = calloc(1, sizeof(struct f_stripe_set));
	if (!ss) return NULL;
	ss->stripes = calloc(size, sizeof(f_stripe_t));
	if (!ss->stripes) return NULL;
	return ss;
}

static inline void ss_free(struct f_stripe_set *ss)
{
	if (ss && ss->stripes) free(ss->stripes);
	if (ss) free(ss);
}

static inline bool lo_has_parity(F_LAYOUT_t *lo) {
    return (lo->info.data_chunks < lo->info.chunks);
}

#endif
