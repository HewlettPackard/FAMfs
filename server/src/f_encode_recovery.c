/*
 * Copyright (c) 2020, HPE
 *
 * Written by: Oleg Neverovitch, Yann Livis
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
#include "f_wpool.h"
#include "famfs_lf_connect.h"
#include "f_layout_ctl.h"
#include "f_encode_recovery.h"
#include "f_allocator.h"


int f_recover_stripes(F_WTYPE_t cmd, void *arg, int thread_id)
{
	struct ec_worker_data *ecw_data = (struct ec_worker_data *)arg;
	F_LO_PART_t *lp = ecw_data->lp;
	F_LAYOUT_t *lo = lp->layout;
	struct f_stripe_set *ss = &ecw_data->ss;
	int i, rc = 0;

	ASSERT(cmd == F_WT_DECODE);
	for (i = 0; i < ss->count; i++) {
		f_stripe_t s = ss->stripes[i];

		LOG(LOG_DBG3, "%s[%d]-w%d: recovering stripe %lu (%d of %d)", 
			lo->info.name, lp->part_num, thread_id, s, i, ecw_data->ss.count);
		usleep(500);

		if (rc ) return -EAGAIN;
	}

	if (ss->stripes) free(ss->stripes);
	if (ecw_data) free(ecw_data);
	return 0;
}

int f_encode_stripes(F_WTYPE_t cmd, void *arg, int thread_id)
{
	struct ec_worker_data *ecw_data = (struct ec_worker_data *)arg;
	F_LO_PART_t *lp = ecw_data->lp;
	F_LAYOUT_t *lo = lp->layout;
	struct f_stripe_set *ss = &ecw_data->ss;
	int i, rc = 0;

	ASSERT(cmd == F_WT_ENCODE);
	for (i = 0; i < ss->count; i++) {
		f_stripe_t s = ss->stripes[i];

		LOG(LOG_DBG3, "%s[%d]-w%d: encoding stripe %lu (%d of %d)", 
			lo->info.name, lp->part_num, thread_id, s, i, ecw_data->ss.count);
		usleep(500);

		if (rc ) return -EAGAIN;

		f_laminate_stripe(lp->layout, s);
	}
	
	/* Mark the claim vector to be flushed */
	SetLPCVFlush(lp);

	if (ss->stripes) free(ss->stripes);
	if (ecw_data) free(ecw_data);
	return 0;
}

int f_verify_stripes(F_WTYPE_t cmd, void *arg, int thread_id)
{
	ASSERT(cmd == F_WT_VERIFY);
	return 0;
}

struct ss_data {
	unsigned long		devmap[F_DEVMAP_SIZE];
	struct f_stripe_set 	ss;
};

/* Encode batch completed callback */
int encode_batch_done_cb(F_EDR_t *rq, void *ctx)
{
	F_EDR_WD_t *wdata = &rq->wdata;
	F_LO_PART_t *lp;
	F_LAYOUT_t *lo;

	ASSERT(wdata);
	lp = wdata->lp;
	lo = lp->layout;

	LOG(LOG_DBG, "%s[%d]: encode rq completed with status %d", lo->info.name, lp->part_num, rq->status);

//	ss_free(wdata->ss);
	return 0;
}

/*
 * Submit a set of committed stripes for EC encoding.i Called from f_commit_stripe().
 * All stripe #s n the set are expected to be global and to belong to the local allocator partition.
 * Returns 0 or error
 */
int f_submit_encode_stripes(F_LAYOUT_t *lo, struct f_stripe_set *ss)
{
	F_LO_PART_t *lp = lo->lp;
	F_POOL_t *pool = lo->pool;
	struct ss_data *buckets;
	F_ITER_t *sm_it;
	int batch_size = DIV_CEIL(ss->count, lp->w_thread_cnt);	// use all worker threads
	int n = 0, i = 0, j = 0, rc = 0;

	ASSERT(lp);

	/* 
	 * Split the stripe set by the slab buckets devmaps 
	 * to enable potential request merge 
	 */
	buckets = calloc(lp->slab_count, sizeof(struct ss_data));
	ASSERT(buckets);
	sm_it = f_map_get_iter(lp->slabmap, F_NO_CONDITION, 0); // TODO: use sm_slab_mapped cond
	for_each_iter(sm_it) {
		f_slab_t slab = sm_it->entry;
		unsigned long devmap[F_DEVMAP_SIZE];
		struct ss_data *ssd = NULL;

		if (slab >= lp->slab_count) break;
		if (!slab_allocated(lp, slab)) continue;

		rc = f_get_slab_devmap(lp, slab, devmap);
		ASSERT(!rc && !bitmap_empty(devmap, pool->info.pdev_max_idx+1));
		
		for (i = 0; i < lp->slab_count; i++) {
			ssd = &buckets[i];
			if (bitmap_empty(ssd->devmap, pool->info.pdev_max_idx+1) || 
				bitmap_equal(ssd->devmap, devmap, pool->info.pdev_max_idx+1))
					break;
		}
		ASSERT(ssd);
		
		if (bitmap_empty(ssd->devmap, pool->info.pdev_max_idx+1)) {
			bitmap_copy(ssd->devmap, devmap, pool->info.pdev_max_idx+1);
			ssd->ss.count = 0;
			ssd->ss.stripes = NULL; /* defer allocation untill we find a matching stripe */
			n = i + 1;
		}
	}
	f_map_free_iter(sm_it);

	buckets = realloc(buckets, sizeof(struct ss_data) * n);
	ASSERT(buckets);

	for (i = 0; i < ss->count; i++) {
		struct ss_data *ssd = NULL;
		f_stripe_t stripe;
//		struct ec_worker_data *ecw_data;
		struct f_stripe_set *bss;
		f_slab_t slab;
		unsigned long devmap[F_DEVMAP_SIZE];

		/* Remap global stripe # to local */
		ASSERT(f_map_prt_my_global(lp->claimvec, ss->stripes[i]));
		stripe = f_map_prt_to_local(lp->claimvec, ss->stripes[i]);

		/* Get this stripe's bitmap to find the right bucket */
		slab = stripe_to_slab(lo, stripe);
		rc = f_get_slab_devmap(lp, slab, devmap);
		ASSERT(!rc && !bitmap_empty(devmap, pool->info.pdev_max_idx+1));

		/* Find the matching bucket in the buckets array */
		for (j = 0; j < n; j++) {
			ssd = &buckets[j];
			ASSERT(!bitmap_empty(ssd->devmap, pool->info.pdev_max_idx+1));
			if (bitmap_equal(ssd->devmap, devmap, pool->info.pdev_max_idx+1))
				break; 
		}
		ASSERT(j < n && ssd);
		if (!ssd->ss.stripes) ssd->ss.stripes = calloc(batch_size, sizeof(f_stripe_t));
		ssd->ss.stripes[ssd->ss.count++] = stripe;
		if (ssd->ss.count < batch_size) continue;

		/* Exceeded the batch size, submit what we have so far */
/*		ecw_data = calloc(1, sizeof(struct ec_worker_data));
		ASSERT(ecw_data);
		ecw_data->lp = lp;
		ecw_data->ss.count = ssd->ss.count;
		ecw_data->ss.stripes = calloc(batch_size, sizeof(f_stripe_t));
		memcpy(ecw_data->ss.stripes, ssd->ss.stripes, ssd->ss.count * sizeof(f_stripe_t));
*/
		bss = ss_alloc(batch_size);
		ASSERT(bss);
		bss->count = ssd->ss.count;
		memcpy(bss->stripes, ssd->ss.stripes, ssd->ss.count * sizeof(f_stripe_t));		

		LOG(LOG_DBG2, "%s[%d]: submitting %d stripes for EC encoding (bucket 0x%lx)", 
			lo->info.name, lp->part_num, bss->count, *(ssd->devmap));

//		rc += f_wpool_add_work(lp->wpool, F_WT_ENCODE, F_WP_NORMAL, ecw_data);
		rc = f_edr_sumbit(lo, bss, NULL, encode_batch_done_cb, NULL);
		if (rc) {
			LOG(LOG_ERR, "%s[%d]: failed to submit stripe set for encode, rc=%d",
				lo->info.name, lp->part_num, rc);
			ss_free(bss);
			break;
		}

		/* Reset the busket's stripe set */
		memset(ssd->ss.stripes, 0, ssd->ss.count * sizeof(f_stripe_t));
		ssd->ss.count = 0;
	}

	/* Now submit the rest of stripe sets for encoding */
	for (j = 0; j < n; j++) {
		struct ss_data *ssd = &buckets[j];
		struct f_stripe_set *bss;

		/* Skip empty buckets */
		if (!ssd->ss.count) continue;

		bss = ss_alloc(batch_size);
		ASSERT(bss);
		bss->count = ssd->ss.count;
		memcpy(bss->stripes, ssd->ss.stripes, ssd->ss.count * sizeof(f_stripe_t));		

		LOG(LOG_DBG2, "%s[%d]: submitting %d stripes for EC encoding (bucket 0x%lx", 
			lo->info.name, lp->part_num, bss->count, *(ssd->devmap));

		rc = f_edr_sumbit(lo, bss, NULL, encode_batch_done_cb, NULL);
		if (rc) {
			LOG(LOG_ERR, "%s[%d]: failed to submit stripe set for encode, rc=%d",
				lo->info.name, lp->part_num, rc);
			ss_free(bss);
			break;
		}

	}
	
/*
	rc = f_wpool_wait_queue_jobs_done(lp->wpool, F_WP_NORMAL, 500);
	if (rc) LOG(LOG_DBG2, "%s[%d]: error %d in f_wpool_wait_queue_jobs", 
		lo->info.name, lp->part_num, rc);
*/
	return rc;
}

/*
 * Submnit Encode/Decode/Recover(/Verify) Request
 *
 * Parmas
 *      lo              layout pointer
 *      ss              stripe set to encode/recover
 *      fvec            failed chunks bitmap, if == 0: encode parities according to layout
 *                          if == <all 1s>: verify stripes
 *      done_cb         callaback function to call when state becomes DONE (or NULL if not needed)A
 *
 *  Returns
 *      0               success
 *      <>0             error              
*/      
int f_edr_sumbit(F_LAYOUT_t *lo, struct f_stripe_set *ss, uint64_t *fvec, F_EDR_CB_t done_cb, void *ctx) {
    return 0;
}
