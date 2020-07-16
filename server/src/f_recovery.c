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
#include "f_layout_ctl.h"
#include "f_recovery.h"


/* Virtual map iterator function, filters degraded slabs */
static int sm_is_slab_degraded(void *arg, const F_PU_VAL_t *entry)
{
	const F_SLAB_ENTRY_t *se = &entry->se;
	return (se->mapped && se->degraded);
}

static F_COND_t sm_slab_degraded = {
	.vf_get = &sm_is_slab_degraded,
};

static int recover_slab(F_LO_PART_t *lp, f_slab_t slab, unsigned long *bmap)
{
	F_LAYOUT_t *lo = lp->layout;
	F_RECOVERY_t *rec = (F_RECOVERY_t *)lp->rctx;
	f_stripe_t s0 = slab_to_stripe0(lo, slab);
	int batch_size = 16; //FIXME, adjust for chunk size
	struct f_stripe_set *ss = calloc(1, sizeof(struct f_stripe_set));
	int i, n, rc = 0;

	if (!ss) return -ENOMEM;
	ss->stripes = calloc(batch_size, sizeof(f_stripe_t));
	if (ss->stripes) return -ENOMEM;
	memset(ss->stripes, 0, ss->count * sizeof(f_stripe_t));
	ss->count = 0;

	LOG(LOG_INFO, "%s[%d]: recovering slab %u", lo->info.name, lp->part_num, slab);
	rc = f_mark_slab_recovering(lo, slab);
	if (rc) { free(ss->stripes); free(ss); return rc; }

	for (n = 0, i = 0; i < lo->info.slab_stripes; i++) {
		f_stripe_t s = s0 + i;
		void *p = f_map_get_p(lp->claimvec, s);

		if (!test_bbit(BBIT_NR_IN_LONG(s), CVE_LAMINATED, (unsigned long *)p)) {
			LOG(LOG_DBG, "%s[%d]: stripe %lu not laminated, skipping", lo->info.name, lp->part_num, s);
			continue;
		}

		ss->stripes[n] = s;
		ss->count = n;

		if (++n < batch_size) continue;

		n = 0;

		/* Stop recovery if layout is exitiing */
		if  (!LayoutActive(lo) || LayoutQuit(lo) || !LayoutRecover(lo)) break;

		//submit the stripe set here
		atomic_inc(&rec->in_progress);

		/* Allocate the next stripe set */
	 	ss = calloc(1, sizeof(struct f_stripe_set));
		if (!ss) return -ENOMEM;
		ss->stripes = calloc(batch_size, sizeof(f_stripe_t));
		if (ss->stripes) return -ENOMEM;
		memset(ss->stripes, 0, ss->count * sizeof(f_stripe_t));
		ss->count = 0;
	}

	/* Submit remaining strpes if any */
	if (n) {
		//submit the stripe set here
		atomic_inc(&rec->in_progress);
	}

	/* Wait for the slab recovery completon */
	pthread_mutex_lock(&rec->r_done_lock);
	while (atomic_read(&rec->in_progress)) {
		/* Stop recovery if layout is exitiing */
		if  (!LayoutActive(lo) || LayoutQuit(lo) || !LayoutRecover(lo)) break;
		pthread_cond_wait(&rec->r_batch_done, &rec->r_done_lock);
		atomic_dec(&rec->in_progress);
	}
	pthread_mutex_unlock(&rec->r_done_lock);

	if (!atomic_read(&rec->in_progress)) {
		rc = f_mark_slab_recovered(lo, slab);
		rec->done_slabs++;

		LOG(LOG_INFO, "%s[%d]: slab %u recovered, done: %lu of %lu, errors: %lu, skipped: %lu", 
			lo->info.name, lp->part_num, slab, rec->done_slabs, rec->slabs2recover,
			rec->error_slabs, rec->skipped_slabs);
	} else

		LOG(LOG_WARN, "%s[%d]: slab %u recovery interrupted, done: %lu of %lu, errors: %lu, skipped: %lu", 
			lo->info.name, lp->part_num, slab, rec->done_slabs, rec->slabs2recover,
			rec->error_slabs, rec->skipped_slabs);
	return rc;
}

static int get_chunks_to_recover(F_LO_PART_t *lp, f_slab_t slab, unsigned long *bmap)
{
	F_LAYOUT_t *lo = lp->layout;
	F_RECOVERY_t *rec = (F_RECOVERY_t *)lp->rctx;
	F_SLABMAP_ENTRY_t *sme;
	int n;

	if (slab_in_sync(lp, slab)) {
		LOG(LOG_DBG, "%s[%d]: slab %u is in sync", lo->info.name, lp->part_num, slab);
		return -ESRCH;
	}

	sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lp->slabmap, slab);
	if (!sme) {
		LOG(LOG_ERR, "%s[%d]: error getting SM entry %u", lo->info.name, lp->part_num, slab);
		return -EINVAL;
	}

	/* Skip unmapped slabs */
	if (!sme->slab_rec.mapped) {
		LOG(LOG_WARN, "%s[%d]: slab %u not mapped, skipping", lo->info.name, lp->part_num, slab);
		return -ESRCH;
	}

	/* Skip failed slabs */
	if (sme->slab_rec.failed) {
		LOG(LOG_ERR, "%s[%d]: slab %u is failed, skipping", lo->info.name, lp->part_num, slab);
		rec->error_slabs++;
		return -EINVAL;
	}

	/* Skip not degraded slabs */
	if (!sme->slab_rec.degraded) {
		LOG(LOG_WARN, "%s[%d]: slab %u is not degraded, skipping", lo->info.name, lp->part_num, slab);
		rec->skipped_slabs++;
		return -ESRCH;
	}

	/* Find failed chunks */
	bitmap_zero(bmap, lo->info.chunks);
	for (n = 0; n < lo->info.chunks; n++) {
		if (sme->extent_rec[n].failed) {
			set_bit(n, bmap);
		}
	}

	if (bitmap_empty(bmap, lo->info.chunks)) {
		rec->skipped_slabs++;
		LOG(LOG_WARN, "%s[%d]: slab %u has no failed extents, skipping", lo->info.name, lp->part_num, slab);
		return -ESRCH;
	}
		
	return 0;	
}

static int do_recovery(F_LO_PART_t *lp)
{
	F_LAYOUT_t *lo = lp->layout;
	F_RECOVERY_t *rec = (F_RECOVERY_t *)lp->rctx;
	F_ITER_t *sm_it;
	int rc = 0;

	LOG(LOG_DBG2, "%s[%d]: recovering %d slabs", lo->info.name, lp->part_num, atomic_read(&lp->degraded_slabs));
	sm_it = f_map_get_iter(lp->slabmap, sm_slab_degraded, 0);
	for_each_iter(sm_it) {
		f_slab_t slab = sm_it->entry;

		/* Stop recovery if layout is exitiing */
		if  (!LayoutActive(lo) || LayoutQuit(lo) || !LayoutRecover(lo)) break;

		if (!slab_used(lp, slab_to_stripe0(lo, slab))) {
			LOG(LOG_DBG, "%s[%d]: slab %u not used", lo->info.name, lp->part_num, slab);
			rec->skipped_slabs++;
			continue;
		}
		rc = get_chunks_to_recover(lp, slab, rec->failed_bmap);
		if (rc == -ESRCH) continue; 
		if (rc) {
			LOG(LOG_ERR, "%s[%d]: slab %u lookup error %d", lo->info.name, lp->part_num, slab, rc);
			break;
		} 

		rc = recover_slab(lp, slab, rec->failed_bmap);
		if (rc) {
			LOG(LOG_ERR, "%s[%d]: slab %u recovry error %d", lo->info.name, lp->part_num, slab, rc);
			break;
		}

	}
	LOG(LOG_INFO, "%s[%d]: recovered: %lu of %lu, errors: %lu, skipped: %lu", 
		lo->info.name, lp->part_num, rec->done_slabs, rec->slabs2recover,
		rec->error_slabs, rec->skipped_slabs);
	return rc;
}

/*
 * Release the layout recovery context structure.
 */
static inline void free_rec_ctx(F_LO_PART_t *lp)
{
	F_RECOVERY_t *rec = (F_RECOVERY_t *)lp->rctx;

	if (!rec) return;
	rcu_unregister_thread();
	pthread_mutex_destroy(&rec->r_done_lock);
	pthread_cond_destroy(&rec->r_batch_done);
	if (rec->failed_bmap) free(rec->failed_bmap);
	free(rec);
	lp->rctx = NULL;
}

/*
 * Allocate and initialize the layout recovery context structure.
*/
static inline int alloc_rec_ctx(F_LO_PART_t *lp)
{
	F_RECOVERY_t *rec = NULL;
	F_LAYOUT_t *lo = lp->layout;
	int bmap_size = max(sizeof(long), BITS_TO_BYTES(lo->info.chunks));
	int rc = -ENOMEM;

	
	rec = calloc(1, sizeof(F_RECOVERY_t));
	if (!rec) goto _err;
	lp->rctx = rec;
	rec->failed_bmap = calloc(1, bmap_size);
	if (!rec->failed_bmap) goto _err;
	if (pthread_mutex_init(&rec->r_done_lock, NULL)) goto _err;
	if (pthread_cond_init(&rec->r_batch_done, NULL)) goto _err;

	rcu_register_thread();
	atomic_set(&rec->in_progress, 0);
	rec->slabs2recover = atomic_read(&lp->degraded_slabs);

	LOG(LOG_DBG, "%s[%d]: recovery iniatialized", lo->info.name, lp->part_num);
	return 0;

_err:
	free_rec_ctx(lp);
	return rc;
}

/*
 * Layout recovery thread
 */
static void *f_recovery_thread(void *ctx)
{
	F_LAYOUT_t *lo = (F_LAYOUT_t *)ctx;
	F_POOL_t *pool = lo->pool;
	F_LO_PART_t *lp = lo->lp;
	int rc = 0;

	ASSERT(pool && lo && lp);

	LOG(LOG_INFO, "%s[%d]: starting recovery on %s", lo->info.name, lp->part_num, pool->mynode.hostname);

	/* Wait for the allocator thread to initialize  */
	pthread_mutex_lock(&lp->r_thread_lock);
	while (lp->ready == 0)
		pthread_cond_wait(&lp->r_thread_cond, &lp->r_thread_lock);
	pthread_mutex_unlock(&lp->r_thread_lock);

	if (likely(LayoutActive(lo))) {
		rc = alloc_rec_ctx(lp);

		printf("%s[%d]: recovery thread is ready\n", lo->info.name, lp->part_num);

		rc = do_recovery(lp);
	}

	if (f_map_flush(lp->slabmap)) 
		LOG(LOG_ERR, "%s[%d]: error flushing slab map", lo->info.name, lp->part_num);

	LOG(LOG_INFO, "%s[%d]: recovery thread exiting on %s rc=%d",
		lo->info.name, lp->part_num, pool->mynode.hostname, rc);

	free_rec_ctx(lp);

	lp->r_thread_res = rc;
	return (void *)&lp->r_thread_res;
}

int f_start_recovery_thread(F_LAYOUT_t *lo)
{
	F_LO_PART_t *lp = lo->lp;
	int rc = 0;

	rc = pthread_mutex_init(&lp->r_thread_lock, NULL);
	if (!rc) rc = pthread_cond_init(&lp->r_thread_cond, NULL);

	if (!rc) {
		SetLayoutRecover(lo);
		rc = pthread_create(&lp->r_thread, NULL, f_recovery_thread, lo);
	}
	return rc;
}

int f_stop_recovery_thread(F_LAYOUT_t *lo)
{
	F_LO_PART_t *lp = lo->lp;
	void *res;
	int rc = 0;

	ClearLayoutRecover(lo);
	pthread_cond_signal(&lp->r_thread_cond);
	rc = pthread_join(lp->r_thread, &res);
	if (rc)
		LOG(LOG_ERR, "%s[%d]: recovery: error %d in pthread_join", lo->info.name, lo->lp->part_num, rc);

	pthread_mutex_destroy(&lp->r_thread_lock);
	pthread_cond_destroy(&lp->r_thread_cond);

	return lp->r_thread_res;
}

