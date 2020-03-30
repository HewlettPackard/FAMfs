/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Yann Livis
 */

#ifndef F_LAYOUT_CTL_H
#define F_LAYOUT_CTL_H

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

#endif
