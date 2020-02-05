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


static void *f_allocator_thread(void *ctx);

int start_allocator_thread(F_LAYOUT_t *lo)
{
	F_LO_PART_t *lp = lo->lp;
	int e_sz, rc = 0;

	pthread_mutex_init(&lp->lock_ready, NULL);
	pthread_cond_init(&lp->cond_ready, NULL);

	/* Initialize layout maps */
	e_sz = sizeof(F_SLAB_ENTRY_t) + lo->info.chunks*sizeof(F_EXTENT_ENTRY_t);
	lo->slabmap  = f_map_init(F_MAPTYPE_STRUCTURED, e_sz, 0, 0);
	lo->claimvec = f_map_init(F_MAPTYPE_BITMAP, 2, 0, 0);
	if (!lo->slabmap || !lo->claimvec) return EINVAL;

	rc = pthread_create(&lp->thread, NULL, f_allocator_thread, lo);
	if (!rc) {
		/* Wait for the allocator thread to initialize and load maps */
		pthread_mutex_lock(&lp->lock_ready);
		while (lp->ready == 0)
			pthread_cond_wait(&lp->cond_ready, &lp->lock_ready);
		pthread_mutex_unlock(&lp->lock_ready);
		rc = (lp->ready == 1) ? 0 : -1;
	}

	return rc;
}

int stop_allocator_thread(F_LAYOUT_t *lo)
{
	F_LO_PART_t *lp = lo->lp;
	void *res;
	int rc = 0;

	SetLayoutQuit(lo);
	pthread_cond_signal(&lp->a_thread_cond);
	rc = pthread_join(lp->thread, &res);
	if (rc)
		LOG(LOG_ERR, "%s[%d]: error %d in pthread_join", lo->info.name, lo->lp->part_num, rc);

	pthread_cond_destroy(&lp->cond_ready);
	pthread_mutex_destroy(&lp->lock_ready);

	return lp->thread_res;
}

int f_start_allocator_threads(void)
{
	F_POOL_t *pool = f_get_pool();
	F_LAYOUT_t *lo;
	int rc = 0;

	if (pool) {
		struct list_head *l, *tmp;
		list_for_each_safe(l, tmp, &pool->layouts) {
			lo = container_of(l, struct f_layout_, list);
			rc = start_allocator_thread(lo);
			if (rc) {
				LOG(LOG_ERR, "%s[%d]: error %s starting allocator", 
					lo->info.name, lo->lp->part_num, strerror(rc));
			}
		}
	}
	return rc;
}

int f_stop_allocator_threads(void)
{
	F_POOL_t *pool = f_get_pool();
	F_LAYOUT_t *lo;
	int rc = 0;

	if (pool) {
		struct list_head *l, *tmp;
		list_for_each_safe(l, tmp, &pool->layouts) {
			lo = container_of(l, struct f_layout_, list);
			rc = stop_allocator_thread(lo);
			if (rc) {
				LOG(LOG_ERR, "%s[%d]: error %s stopping allocator", 
					lo->info.name, lo->lp->part_num, strerror(rc));
			}
		}
	}
	return rc;
}

/* 
 * Slab allocation bitmap manipulation routines 
 */
static inline void set_slab_bit(F_LO_PART_t *lp, f_slab_t slab, unsigned long *bmap)
{
}

static inline void clear_slab_bit(F_LO_PART_t *lp, f_slab_t slab, unsigned long *bmap)
{
}

static inline bool slab_bit_set(F_LO_PART_t *lp, f_slab_t slab, unsigned long *bmap)
{
	return false;
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

#if 0
static inline int max_slab_allocated(F_LO_PART_t *lp)
{
	return find_last_bit(lp->slab_bmap, lp->slab_count);
}
#endif

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

static inline bool slab_full(F_LO_PART_t *lp, f_stripe_t stripe)
{
	return (slab_used(lp, stripe) == lp->layout->info.slab_stripes);
}

static inline bool all_slabs_full(F_LO_PART_t *lp)
{
	int n = lp->slab_count;
	
	while (n--) {
		f_stripe_t s0 = slab_to_stripe0(lp->layout, n);
		if (!slab_allocated(lp, n))
			return false;
		if (!slab_full(lp, s0))
			return false;
	}
	return true;
}

static inline bool all_allocated_slabs_full(F_LO_PART_t *lp)
{
	int n = lp->slab_count;
	
	while (n--) {
		f_stripe_t s0 = slab_to_stripe0(lp->layout, n);
		if (!slab_allocated(lp, n))
			continue;
		if (!slab_full(lp, s0))
			return false;
	}
	return true;
}

/* Map load callback function data */
struct cb_data {
	F_LO_PART_t 	*lp;
	int		err;
};

/*
 * Slab map load callback function. Called on each slab map PU load
 */
static void slabmap_load_cb(uint64_t e, void *arg, const F_PU_VAL_t *pu)
{
	struct cb_data *data = (struct cb_data *) arg;
	F_LO_PART_t *lp = data->lp;;
	F_LAYOUT_t *lo = lp->layout;
	F_SLABMAP_ENTRY_t *sme;
	f_slab_t slab = e;
	unsigned int pu_entries = 1U << lo->slabmap->geometry.pu_factor;
	unsigned int e_sz = lo->slabmap->geometry.entry_sz;
	unsigned int i;

	for(i = 0; i < pu_entries; i++, slab++) {
		f_stripe_t s0 = slab_to_stripe0(lo, slab);;
		unsigned int n;

		sme = (F_SLABMAP_ENTRY_t *)&pu->se;
		if (!sme) {
			LOG(LOG_ERR, "%s[%d]: error on SM entry %u", lo->info.name, lp->part_num, slab);
			data->err++;
		}
	
		/* Check slab map entry CRC */
		if (f_crc4_sm_chk(&sme->slab_rec)) {
			LOG(LOG_ERR, "%s[%d]: slab %u CRC error", lo->info.name, lp->part_num, slab);
			data->err++;
		}

		if (sme->slab_rec.mapped) {
			set_slab_allocated(lp, slab);
		} else { /* Unmapped slabs are considered in sync */
			set_slab_in_sync(lp, slab);
			lp->sync_count++;
			continue;
		} 
		
		if (sme->slab_rec.stripe_0 != s0) {
			LOG(LOG_ERR, "%s[%d]: slab %u s0 mismatch", lo->info.name, lp->part_num, slab);
			data->err++;
		}
	
		if (!sme->slab_rec.failed && !sme->slab_rec.degraded) {
			set_slab_in_sync(lp, slab);
			lp->sync_count++;
		} else if (sme->slab_rec.degraded) {
			atomic_inc(&lp->degraded_slabs);
		}  else if (sme->slab_rec.failed) {
			atomic_inc(&lp->failed_slabs);	
		}

		/* Process this slab map entry */
		for (n = 0;  n < lo->info.chunks; n++) {
			F_POOL_DEV_t *pdev = f_find_pdev(sme->extent_rec[n].media_id);	
			
			if (!pdev) {
				LOG(LOG_ERR, "%s[%d]: slab %u ext %u invalid dev idx %u", 
					lo->info.name, lp->part_num, slab, n, sme->extent_rec[n].media_id);
				data->err++;
			}

			if (f_crc4_fast_chk(&sme->extent_rec[n], sizeof(F_EXTENT_ENTRY_t))) {
				LOG(LOG_ERR, "%s[%d]: slab %u ext %u CRC err", lo->info.name, lp->part_num, slab, n);
				data->err++;
			}

			if (DevMissing(pdev->sha)) {
				LOG(LOG_INFO, "%s[%d]: missing dev in slab %u ext %u", 
					lo->info.name, lp->part_num, slab, n); 
				atomic_inc(&lp->missing_dev_slabs);
			}

			/* All chunk extents have to be mapped */
			if (!sme->extent_rec[n].mapped) {
				LOG(LOG_ERR, "%s[%d]: slab %u ext %u not mapped", 
					lo->info.name, lp->part_num, slab, n);
				data->err++;
			}
				
			/* Populate device extent map */
		}

		LOG(LOG_DBG, "%s[%d]: slab %u loaded: %d errors", lo->info.name, lp->part_num, slab, data->err++);
		pu = (F_PU_VAL_t *) ((char*)pu + e_sz);
	}

}

/*
 * Claim vector load callback function. Called on each slab map PU load
 */
static void claimvec_load_cb(uint64_t e, void *arg, const F_PU_VAL_t *pu)
{
	struct cb_data *data = (struct cb_data *) arg;
	F_LO_PART_t *lp = data->lp;;
	F_LAYOUT_t *lo = lp->layout;
	f_stripe_t s = e;
	unsigned int pu_entries = 1U << lo->claimvec->geometry.pu_factor;
	unsigned int e_sz = lo->claimvec->geometry.entry_sz;
	unsigned int i;

	if (bbitmap_empty((unsigned long *)pu, e_sz*pu_entries)) return;

	for(i = 0; i < pu_entries; i++, s++) {
		if (test_bbit_patterns(i, CV_ALLOCATED_P | CV_LAMINATED_P, (unsigned long *)pu)) {
			F_SLABMAP_ENTRY_t *sme;
			f_slab_t slab = stripe_to_slab(lo, s);

			/* Verify that the slab is mapped */
			sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lo->slabmap, slab);
			if (!sme->slab_rec.mapped) {
				LOG(LOG_ERR, "%s[%d]: slab %u (s %lu) not mapped", 
					lo->info.name, lp->part_num, slab, s);
				data->err++;
			} else {
				inc_slab_used(lp, s);
			}
		} else if (test_bbit(i, CVE_PREALLOC, (unsigned long *)pu)) {
			LOG(LOG_DBG, "%s[%d]: clearing preallocated stipe %lu", lo->info.name, lp->part_num, s);
			set_bbit(i, CVE_FREE, (unsigned long *)pu);
		}
		LOG(LOG_DBG, "%s[%d]: stripe %lu loaded: %d errors", lo->info.name, lp->part_num, s, data->err++);
	}
}

/*
 * Load and process this partition of the slab map and the claim vector 
 *
 * Slab Map
 *
 * [F_SLAB_ENTRY_t 0][F_EXTENT_ENTRY_t 0][F_EXTENT_ENTRY_t 1]...[F_EXTENT_ENTRY_t N] [F_SLAB_ENTRY_t 1]...
 */
static int read_maps(F_LO_PART_t *lp)
{
	F_LAYOUT_t *lo = lp->layout;
	F_ITER_t *sm_iter;
	F_SLABMAP_ENTRY_t *sme;
	struct cb_data cbdata;
	int rc;

	ASSERT(lo->slabmap && lo->claimvec);

	LOG(LOG_DBG, "%s[%d]: loading slabmap", lo->info.name, lp->part_num);
	rc = f_map_init_prt(lo->slabmap, lo->part_count, lp->part_num, 0, 0);
	if (rc) {
		LOG(LOG_ERR, "%s[%d]: error %d initializing SM", lo->info.name, lp->part_num, rc);
		return rc;
	}

	rc = f_map_register(lo->slabmap, lo->info.conf_id);
	if (rc || f_map_is_ro(lo->slabmap)) {
		LOG(LOG_ERR, "%s[%d]: error %d registering SM", lo->info.name, lp->part_num, rc);
		return rc;
	}

	cbdata.err = 0;
	rc = f_map_load_cb(lo->slabmap, slabmap_load_cb, (void *)&cbdata);
	if (rc || cbdata.err) {
		LOG(LOG_ERR, "%s[%d]: error %d loading SM, %d load errors", 
			lo->info.name, lp->part_num, rc, cbdata.err);
		return rc ? rc : cbdata.err;
	}

	LOG(LOG_DBG, "%s[%d]: loading claim vector", lo->info.name, lp->part_num);
	rc = f_map_init_prt(lo->claimvec, lo->part_count, lp->part_num, 0, 0);
	if (rc) {
		LOG(LOG_ERR, "%s[%d]: error %d initializing CV", lo->info.name, lp->part_num, rc);
		return rc;
	}

	rc = f_map_register(lo->claimvec, lo->info.conf_id);
	if (rc || f_map_is_ro(lo->claimvec)) {
		LOG(LOG_ERR, "%s[%d]: error %d registering CV", lo->info.name, lp->part_num, rc);
		return rc;
	}

	cbdata.err = 0;
	rc = f_map_load_cb(lo->claimvec, claimvec_load_cb, (void *)&cbdata);
	if (rc || cbdata.err) {
		LOG(LOG_ERR, "%s[%d]: error %d loading CV, %d load errors", 
			lo->info.name, lp->part_num, rc, cbdata.err);
		return rc ? rc : cbdata.err;
	}

	/* Scan this slab map partition and set the devices extents bitmaps, etc. */
	LOG(LOG_DBG, "%s[%d]: scanning slabmap", lo->info.name, lp->part_num);
	sm_iter = f_map_new_iter(lo->slabmap, F_NO_CONDITION, 0);
	sm_iter = f_map_seek_iter(sm_iter, 0);
	assert(sm_iter);
	for_each_iter(sm_iter) {
		unsigned int e = sm_iter->entry;
		f_stripe_t s0 = slab_to_stripe0(lo, e);;
		int n;

		rc = EINVAL;
		sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lo->slabmap, sm_iter->entry);
		if (!sme) {
			LOG(LOG_ERR, "%s[%d]: error on SM entry %u", lo->info.name, lp->part_num, e);
			goto _ret;
		}
	
		/* Check slab map entry CRC */
		if (f_crc4_sm_chk(&sme->slab_rec)) {
			LOG(LOG_ERR, "%s[%d]: slab %u CRC error", lo->info.name, lp->part_num, e);
			goto _ret;
		}

		if (sme->slab_rec.mapped) {
			set_slab_allocated(lp, e);
		} else { /* Unmapped slabs are considered in sync */
			set_slab_in_sync(lp, e);
			lp->sync_count++;
			continue;
		} 
		
		if (sme->slab_rec.stripe_0 != s0) {
			LOG(LOG_ERR, "%s[%d]: slab %u s0 mismatch", lo->info.name, lp->part_num, e);
			goto _ret;
		}
	
		if (!sme->slab_rec.failed && !sme->slab_rec.degraded) {
			set_slab_in_sync(lp, e);
			lp->sync_count++;
		} else if (sme->slab_rec.degraded) {
			atomic_inc(&lp->degraded_slabs);
		}  else if (sme->slab_rec.failed) {
			atomic_inc(&lp->failed_slabs);	
		}

		/* Process this slab map entry */
		for (n = 0;  n < lo->info.chunks; n++) {
			F_POOL_DEV_t *pdev = f_find_pdev(sme->extent_rec[n].media_id);	
			
			if (!pdev) {
				LOG(LOG_ERR, "%s[%d]: slab %u ext %u invalid dev idx %u", 
					lo->info.name, lp->part_num, e, n, sme->extent_rec[n].media_id);
				goto _ret;
			}

			if (f_crc4_fast_chk(&sme->extent_rec[n], sizeof(F_EXTENT_ENTRY_t))) {
				LOG(LOG_ERR, "%s[%d]: slab %u ext %u CRC err", lo->info.name, lp->part_num, e, n);
				goto _ret;
			}

			if (DevMissing(pdev->sha)) {
				LOG(LOG_INFO, "%s[%d]: missing dev in slab %u ext %u", 
					lo->info.name, lp->part_num, e, n); 
				atomic_inc(&lp->missing_dev_slabs);
			}

			/* All chunk extents have to be mapped */
			if (!sme->extent_rec[n].mapped) {
				LOG(LOG_ERR, "%s[%d]: slab %u ext %u not mapped", lo->info.name, lp->part_num, e, n);
				goto _ret;
			}
				
			/* Populate device extent map */
		}
	}

	return 0;

_ret:
	if (sm_iter ) {f_map_free_iter(sm_iter); sm_iter = NULL;}
	return rc;
}
	
static void flush_maps(F_LO_PART_t *lp)
{
}

static int alloc_new_slab(F_LO_PART_t *lp, f_slab_t *slab)
{
	return 0;
}

/*
 * Determine layout partition out of space condition 
 */
static bool out_of_space(F_LO_PART_t *lp)
{
	F_LAYOUT_t *lo = lp->layout;
	int slab_count = (LayoutNoSpace(lo)) ? atomic_read(&lp->allocated_slabs) : lp->slab_count;

	if (atomic_read(&lp->prealloced_stripes)) 
		return false;

	slab_count -= atomic_read(&lp->degraded_slabs); /* we don't use degraded slabs */
	if (atomic_read(&lp->allocated_stripes) >= slab_count * lo->info.slab_stripes)
		return true; 

	return false;
}

/* 
 * Check if there is enough extents available to allocate a slab
 */
static bool can_allocate_slab(F_LO_PART_t *lp)
{
	return true;
}

/*
 * Go through all allocated slabs until we pre-allocate enough stripes
 * to satisfy the request.
 */
static int prealloc_stripes(F_LO_PART_t *lp, int count)
{
	return 0;
}

/*
 * Release count of strides from the pre-allocated tree, all if the count is 0.
 * Called from the stripe allocator with layout lock taken.
 */
static int release_alloc_stripes(F_LO_PART_t *lp, int count)
{
	return 0;
}

/*
 * Go through the pre-allocated stripes list and purge all stripes
 * from degraded (not in sync) slabs
 */
static int purge_alloc_stripes(F_LO_PART_t *lp)
{
	return 0;
}

/* Gauge the layout I/O pressure */
static inline int layout_pressure(F_LAYOUT_t *lo)
{
	int n = 0;
	// TODO: implement layout_pressure() estimator
	return n;
}

/*
 * Process entries on the stripe release queue.
 */
static int process_releaseq(F_LO_PART_t *lp)
{
	return 0;
}

/*
 * Release degraded slabs taking them out of allocation.
 */
static int process_degraded_slabs(F_LO_PART_t *lp)
{
	return 0;
}

/*
 * Release the layout partition structure.
 */
static inline void layout_partition_free(F_LO_PART_t *lp)
{
	rcu_unregister_thread();
	pthread_mutex_destroy(&lp->a_thread_lock);
	pthread_cond_destroy(&lp->a_thread_cond);
	if (lp->slab_usage) free(lp->slab_usage);
	if (lp->slab_bmap) free(lp->slab_bmap);
	if (lp->sync_bmap) free(lp->sync_bmap);
	if (lp->cv_bmap) free(lp->cv_bmap);
}

/*
 * Initialize the layout partition structure.
*/
static inline int layout_partition_init(F_LO_PART_t *lp)
{
	F_POOL_t *pool = f_get_pool();
	F_LAYOUT_t *lo = lp->layout;
	int chunk_size_factor   = F_CHUNK_SIZE_MAX / lo->info.chunk_sz;
	size_t slab_usage_size, cv_bmap_size;

	rcu_register_thread();
	pthread_mutex_init(&lp->a_thread_lock, NULL);
	pthread_cond_init(&lp->a_thread_cond, NULL);
	atomic_set(&lp->allocated_slabs, 0);
	atomic_set(&lp->degraded_slabs, 0);
	atomic_set(&lp->missing_dev_slabs, 0);
	atomic_set(&lp->failed_slabs, 0);
	atomic_set(&lp->prealloced_stripes, 0);
	atomic_set(&lp->allocated_stripes, 0);
	atomic_set(&lp->bucket_count, 0);
	atomic_set(&lp->bucket_count_max, 0);

	lp->lwm_stripes		= F_LWM_ALLOC_STRIPES * chunk_size_factor;
	lp->hwm_stripes		= F_HWM_ALLOC_STRIPES * chunk_size_factor;
	lp->max_alloc_stripes	= F_MAX_ALLOC_STRIPES * chunk_size_factor;
	lp->sync_count		= 0;
	lp->min_alloc_slabs	= max(F_MIN_ALLOC_SLABS, pool->pool_ags / lo->info.chunks);
	lp->slab_count		= DIV_CEIL(lo->info.slab_count, lo->part_count); //FIXME: calc & set lo->slab_count
	lp->stripe_count	= lp->slab_count * lo->info.slab_stripes;

	lp->bmap_size		= DIV_CEIL(lp->slab_count, BITS_PER_LONG) * sizeof(*lp->slab_bmap) *2;
	slab_usage_size		= sizeof(*lp->slab_usage) * lp->slab_count;

	lp->slab_usage = calloc(1, slab_usage_size);
	if (!lp->slab_usage) goto _err;
	lp->slab_bmap = calloc(1, lp->bmap_size);
	if (!lp->slab_bmap) goto _err;
	lp->sync_bmap = calloc(1, lp->bmap_size);
	if (!lp->sync_bmap) goto _err;
	cv_bmap_size = DIV_CEIL(lp->stripe_count, BITS_PER_LONG) * sizeof(*lp->cv_bmap);
	lp->cv_bmap = calloc(1, cv_bmap_size);
	if (!lp->slab_bmap) goto _err;

	return 0;

_err:
	layout_partition_free(lp);
	return ENOMEM;
}

/*
 * Stripe allocator maintains a pre-allocated stripe list per layout
 *
 * Size of the list is maintained to be within the low water/high water mark limits.
 * If it goes below the low water mark, an additional slab is allocated.
 * If the size exceeds the high water mark, release the extra stripes, preferably from
 * the least used slab so it could be dellocated as well.
 *
 * If the alloc_stripes_count is below the low water mark:
 *	find a free slab for that layout,
 *	get the slab map entry for that slab
 *	fill the F_SLAB_ENTRY_t record
 *	sort the layout devices by their utilization
 *	(we allocate chunks across allocation groups)
 *	iterate through the sorted layout device list:
 *		check device status, 
 *		find the next free extent,
 *		fill the F_EXTENT_t record for that device
 *	Update the pre-allocated stripe counter,
 *	increment the claim vector refcounters for each stripe in the new slab,
 *	and flush the updated claim vector and the slab map entries.
 *
 * If the alloc_stripes_count exceeds the high water mark:
 *	release extra stripes
 *	find pre-allocated slabs with no stripes used
 *	if found update and flush the slab map entries
 *	to mark that slab as unused.
 *
 *	Called with layout partition lock held
 */
int f_stripe_allocator(F_LO_PART_t *lp)
{
	F_LAYOUT_t *lo = lp->layout;
	f_slab_t slab;
	int allocated = 0;
	int n, i, alloc_count, rel_count, rc = 0;
	loglevel alloc_err_lvl = !LayoutNoSpace(lo) ? LOG_ERR : LOG_DBG;
	int stripes_threshold = F_LWM_ALLOC_STRIPES / 2;

	/* Flush slab map if requested */
	if (LPSMFlush(lp)) {
		rc = f_map_flush(lo->slabmap);
		if (rc) {
			LOG(LOG_ERR, "%s[%d]: error %s flushing slabmap", 
				lo->info.name, lp->part_num, strerror(rc));
		} else {
			atomic_inc(&lp->slabmap_version);
			ClearLPSMFlush(lp);
		}
	}

	/* Process stripes to be released */
	rc = process_releaseq(lp);
	if (rc) {
		LOG(LOG_WARN, "%s[%d]: error %s processing preallocated stripes release", 
				lo->info.name, lp->part_num, strerror(rc));
	}

	/* Drop preallocated stripes from degraded slabs */
	rc = purge_alloc_stripes(lp);
	if (rc) {
		LOG(LOG_WARN, "%s[%d]: error %s purging pre-allocated stripes", 
				lo->info.name, lp->part_num, strerror(rc));
	}

	/* Check and release degraded and not used slabs if any */
	rc = process_degraded_slabs(lp);
	if (rc) {
		LOG(LOG_WARN, "%s[%d]: error %s processing degraded slabs", 
				lo->info.name, lp->part_num, strerror(rc));
	}

	/* Preallocate min # of slabs to cover all devices */
	for (i = slabs_allocated(lp); i < lp->min_alloc_slabs && i < lp->slab_count; i++) {
		LOG(LOG_DBG, "%s[%d]: %d slab(s) allocated, adding a new slab",
			lo->info.name, lp->part_num, slabs_allocated(lp)); 
		rc = alloc_new_slab(lp, &slab);
		if (rc) {
			LOG(alloc_err_lvl, "%s[%d]: error %d allocating a new slab",
				lo->info.name, lp->part_num, rc);
			goto _ret; 
		}
	}
		
	/* Preallocation queue maintenance */
	ASSERT(lp->lwm_stripes && lp->hwm_stripes);
	pthread_spin_lock(&lp->alloc_lock);
	if (lp->increase_prealloc) {
		if (lp->lwm_stripes < lp->max_alloc_stripes) {
			int pressure_ratio = layout_pressure(lo) + 1;
			int inc = pressure_ratio * F_LWM_ALLOC_STRIPES / 2;
			lp->lwm_stripes += inc;
			lp->hwm_stripes += inc;
			 LOG(LOG_INFO, "%s[%d]: increasing allocation limits to %lu/%lu (pressure %d)",
				lo->info.name, lp->part_num, lp->lwm_stripes, lp->hwm_stripes, pressure_ratio); 
		}
		lp->increase_prealloc = 0;
	}
	alloc_count = lp->lwm_stripes - atomic_read(&lp->prealloced_stripes);
	rel_count = atomic_read(&lp->prealloced_stripes) - lp->hwm_stripes;
	pthread_spin_unlock(&lp->alloc_lock);

	/* don't bother with small change... */
	if (alloc_count < stripes_threshold && rel_count < stripes_threshold) {
		rc = 0;
		goto _ret;
	}
			
	/* Below the low water mark, preallocate more stripes */
	if (alloc_count >= stripes_threshold) {

		/* Preallocate needed # of stripes across min # of slabs */
		n = prealloc_stripes(lp, alloc_count);
		alloc_count -= n;
		allocated += n;

		/* Allocate a new slab if we couldn't allocate from existing */
		while (alloc_count > 0 && can_allocate_slab(lp)) {	
			LOG(LOG_DBG, "%s[%d]: need %d stripe(s) after allocating %d from existing slabs, "
				" adding a new slab", lo->info.name, lp->part_num, alloc_count, n);
			lp->alloc_error = rc = alloc_new_slab(lp, &slab);
			if (rc) {
				LOG(alloc_err_lvl, "%s[%d]: error %d allocating a new slab",
					lo->info.name, lp->part_num, rc);
				goto _ret; 
			}
			/*
			 *  Added a new slab, now try to preallocate the rest of the stripes across min # of slabs
			 */
			n = prealloc_stripes(lp, alloc_count);
			alloc_count -= n;
			allocated += n;
		}

		if (n < alloc_count)
			LOG(LOG_DBG, "%s[%d]: low on space, allocated %d stripes of %d",
				lo->info.name, lp->part_num, n, alloc_count);

		if (!LayoutSpcErrLogged(lo) && !allocated) {
			 LOG(LOG_WARN, "%s[%d]: low on space, no stripes allocated (needed %d)",
				lo->info.name, lp->part_num, alloc_count);

			/* Out of space, stop logging */
			SetLayoutSpcErrLogged(lo);
		}

		/* Reset the SpcErrLogged flag if the allocation was successfull */
		if (n == alloc_count)
			ClearLayoutSpcErrLogged(lo);

		if (!allocated && !out_of_space(lp)) {
			rc = ENOMEM;
			goto _ret;
		}

	/* Above the high water mark, release extra stripes */
	} else if (rel_count >= stripes_threshold) {
		LOG(LOG_DBG, "%s[%d]: releasing %d preallocated stripes", lo->info.name, lp->part_num, rel_count);
		rc = release_alloc_stripes(lp, rel_count);
		if (rc) {
			LOG(LOG_WARN, "%s[%d]: error %d releasing %d pre-allocated stripes",
				lo->info.name, lp->part_num, rc, rel_count);
		}
	}

_ret:
	return rc;
}

/*
 * Layout allocator thread
 */
static void *f_allocator_thread(void *ctx)
{
	F_POOL_t *pool = f_get_pool();
	F_LAYOUT_t *lo = (F_LAYOUT_t *)ctx;
	F_LO_PART_t *lp = lo->lp;
	int *rcbuf;
	int thr_cnt, thr_rank, i;
	int rc = 0;

	ASSERT(pool && lo && lp);

	ON_ERROR((MPI_Comm_rank(pool->ionode_comm, &thr_rank)), "MPI_Comm_rank");
	ON_ERROR((MPI_Comm_size(pool->ionode_comm, &thr_cnt)), "MPI_Comm_size");
	rcbuf = alloca(thr_cnt*sizeof(rc));

	ASSERT(rcbuf);
	memset(rcbuf, 0, thr_cnt*sizeof(rc));

	lp->part_num = thr_rank;
	lo->part_count = thr_cnt;
	
	LOG(LOG_INFO, "%s[%d]: starting allocator on %s", lo->info.name, lp->part_num, pool->mynode.hostname);

	rc = layout_partition_init(lp);

	/* Load and process this partition of the slab map and the claim vector */
	if (!rc) rc = read_maps(lp);

	/*
	 * Synchronize all allocator threads across all IO-nodes and make sure 
	 * all slab map partitions were successfully loaded
	 */ 
	MPI_Barrier(pool->ionode_comm);

	rcbuf[thr_rank] = rc;
	ON_ERROR(MPI_Allgather(MPI_IN_PLACE, 1, MPI_INT, rcbuf, 1, MPI_INT, pool->ionode_comm), "MPI_Allgather");

	for (i = 0; i < thr_cnt; i++) {
		/* Bring down all allocators if any of them failed */
		if (rcbuf[i] !=0) {
			if (!thr_rank) LOG(LOG_ERR, "%s[%d]: error %d loading slab map part %d", 
				lo->info.name, lp->part_num, rcbuf[i], i);
			SetLayoutThreadFailed(lo);
			rc = -1;
		}
	}
	
	/* All is well, signal the parent thread */
	if (!rc) {
		pthread_mutex_lock(&lp->lock_ready);
		lp->ready = 1;
		SetLayoutActive(lo);
		pthread_mutex_unlock(&lp->lock_ready);
		pthread_cond_signal(&lp->cond_ready);
	}

	SetLayoutQuit(lo);
	while (!LayoutQuit(lo) && !rc) {
		struct timespec to, wait;
		
		 /* ms to timespec */
		wait.tv_sec = lo->thread_run_intl / 1000;
		wait.tv_nsec = (lo->thread_run_intl % 1000U) * 1000000U;

		clock_gettime(CLOCK_REALTIME, &to);
		timespecadd(&to, &wait);

		pthread_mutex_lock(&lp->a_thread_lock);
		rc = pthread_cond_timedwait(&lp->a_thread_cond, &lp->a_thread_lock, &to);
		pthread_mutex_unlock(&lp->a_thread_lock);
		rc = (rc == ETIMEDOUT) ? 0 : rc;

		if (LayoutQuit(lo)) break;

		/* We start allocation only after all layout partitions are loaded */ 
		 if (LayoutActive(lo)) {
			bool report_alloc_errors = !LayoutNoSpace(lo);

			/* Run stripe allocator */
			LOG(LOG_DBG, "%s[%d]: allocator run @%lu", lo->info.name, lp->part_num, to.tv_sec);
			pthread_rwlock_wrlock(&lp->lock);
			rc = f_stripe_allocator(lp);
			if (rc) {
				if (!LayoutSpcErrLogged(lo) && report_alloc_errors)
					LOG(LOG_ERR, "%s[%d]: error %d in stripe allocator",
						lo->info.name, lp->part_num, rc);
				rc = 0; /* clear the error */
			}
			pthread_rwlock_unlock(&lp->lock);
		}
	}

	ASSERT(!release_alloc_stripes(lp, 0));
	flush_maps(lp);
	layout_partition_free(lp);

	LOG(LOG_INFO, "%s[%d]: allocator exiting on %s rc=%d", 
		lo->info.name, lp->part_num, pool->mynode.hostname, rc);

	if (LayoutThreadFailed(lo)) {
		pthread_mutex_lock(&lp->lock_ready);
		lp->ready = -1;
		pthread_mutex_unlock(&lp->lock_ready);
		pthread_cond_signal(&lp->cond_ready);
	}

	lp->thread_res = rc;
	return (void *)&lp->thread_res;
}
