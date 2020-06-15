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
#include "f_wpool.h"
#include "famfs_lf_connect.h"
#include "f_layout_ctl.h"
#include "f_encode_recovery.h"
#include "f_allocator.h"


static void *f_allocator_thread(void *ctx);

static f_wfunc_ wp_farray[F_WP_NR] = 
{
	f_recover_stripes,
	f_encode_stripes,
	f_verify_stripes
};

/*
 * Destroy pool devices shared structs array LFA
 */
static void destroy_pds_lfa(F_POOL_t *pool)
{
	if (pool->pds_lfa->global_abd) f_lfa_detach(pool->pds_lfa->global_abd, 0);
	if (pool->pds_lfa->local_abd) f_lfa_deregister(pool->pds_lfa->local_abd, 0);
	if (pool->pds_lfa->lfa) f_lfa_destroy(pool->pds_lfa->lfa);
	if (pool->pds_lfa->local) free(pool->pds_lfa->local);
	if (pool->pds_lfa->global) free(pool->pds_lfa->global);
	if (pool->pds_lfa) free(pool->pds_lfa);
}

/*
 * Create LFA for the shared part of pool devices (F_PDEV_SHA_t) 
 */
static int create_pds_lfa(F_POOL_t *pool)
{
	F_IONODE_INFO_t *my_ionode, *ioi;
	F_LFA_SLIST_t *ionode_lst;
	F_PDEV_SHA_t *g_sha;
	char lfa_port[6] = { 0 };
	int bmap_size = max(sizeof(long), BITS_TO_BYTES(pool->info.max_extents)); // size extent map by the max dev size
	int i, si, rc = -ENOMEM;

	ASSERT(pool->mynode.ionode_idx < pool->ionode_count);

	ionode_lst = alloca(sizeof(F_LFA_SLIST_t)*pool->ionode_count);
	if (!ionode_lst) return -ENOMEM;

	my_ionode = &pool->ionodes[pool->mynode.ionode_idx];
	pool->pds_lfa = (F_LFA_ATTR_t *) calloc(1, sizeof(F_LFA_ATTR_t));
	if (!pool->pds_lfa) return -ENOMEM;

	pool->pds_lfa->local_size =  (sizeof(F_PDEV_SHA_t) + bmap_size) * my_ionode->fam_devs;
	if (posix_memalign((void**)&pool->pds_lfa->local, 4096, pool->pds_lfa->local_size)) {
		LOG(LOG_ERR, "error allocating global pds");
		goto _ret;
	}
	memset(pool->pds_lfa->local, 0, pool->pds_lfa->local_size);

	pool->pds_lfa->global_size = (sizeof(F_PDEV_SHA_t) + bmap_size) * pool->pool_devs;
	if (posix_memalign((void**)&pool->pds_lfa->global, 4096, pool->pds_lfa->global_size)) {
		LOG(LOG_ERR, "error allocating global pds");
		goto _ret;
	}		
	memset(pool->pds_lfa->global, 0, pool->pds_lfa->global_size);

	ioi = pool->ionodes;
	for (i = 0, si = 0; i < pool->ionode_count; i++, ioi++) {
		int j;		
		for (j = 0; j < ioi->fam_devs; j++) {
			F_POOL_DEV_t *pdev;
			for_each_pool_dev(pool, pdev) {
				if (pdev->ionode_idx == i && pdev->idx_in_ion == j) {
					F_PDEV_SHA_t *sha = pdev->sha;
					g_sha = pool->pds_lfa->global + 
						si * (sizeof(F_PDEV_SHA_t) + bmap_size);
					LOG(LOG_DBG2, "pdev @%d:%d sha %p failed:%d", 
						i, j, g_sha, DevFailed(sha));
					memcpy(g_sha, sha, sizeof(F_PDEV_SHA_t));
					pdev->sha = g_sha;
					free(sha);
					si++;
					break;
				}
			}
		}
	}

	sprintf(lfa_port, "%5d", pool->info.lfa_port);
	pool->pds_lfa->lfa = f_lfa_mydom(pool->mynode.domain->fi, pool->mynode.hostname, lfa_port);
	if (!pool->pds_lfa->lfa) {
		LOG(LOG_ERR, "error opening domain for pds LFA");
		goto _ret;
	}		

//	rc = f_lfa_create(pool->mynode.domain->domain, pool->mynode.domain->av, 
//		pool->mynode.domain->fi, &pool->pds_lfa->lfa);
	rc = f_lfa_create(NULL, NULL, NULL, &pool->pds_lfa->lfa);
	if (rc) {
		LOG(LOG_ERR, "error %d creating pds LFA", rc);
		goto _ret;
	}		

	rc = f_lfa_register(pool->pds_lfa->lfa, F_LFA_PDS_KEY, pool->pds_lfa->local_size, 
		(void **)&pool->pds_lfa->local, &pool->pds_lfa->local_abd);
	if (rc) {
		LOG(LOG_ERR, "error %d registering pds LFA", rc);
		goto _ret;
	}		

	for (i = 0, ioi = pool->ionodes; i < pool->ionode_count; i++, ioi++) {
		char *sbuf = calloc(1, 32);
		if (!sbuf) { rc = -ENOMEM; goto _ret; }
		ionode_lst[i].name = strdup(ioi->hostname);
		ionode_lst[i].service = strdup(lfa_port);
		ionode_lst[i].bsz = ioi->fam_devs*(sizeof(F_PDEV_SHA_t) + bmap_size);
		LOG(LOG_DBG2, "added server/port: %s/%s/%lu", 
			ionode_lst[i].name, ionode_lst[i].service, ionode_lst[i].bsz); 
	}

	rc = f_lfa_attach(pool->pds_lfa->lfa, F_LFA_PDS_KEY, ionode_lst, i, 
		pool->pds_lfa->global_size, (void **)&pool->pds_lfa->global, &pool->pds_lfa->global_abd);
	if (rc) {
		LOG(LOG_ERR, "error %d attaching pds LFA", rc);
		goto _ret;
	}		

	LOG(LOG_DBG, "alocated/initialized LFA global: %p/%lu local: %p/%lu", 
		pool->pds_lfa->global, pool->pds_lfa->global_size, pool->pds_lfa->local, pool->pds_lfa->local_size);

	return 0;
_ret:
	destroy_pds_lfa(pool);
	return rc;
}


int start_allocator_thread(F_LAYOUT_t *lo)
{
	F_LO_PART_t *lp = lo->lp;
	int rc = 0;

	pthread_mutex_init(&lp->lock_ready, NULL);
	pthread_cond_init(&lp->cond_ready, NULL);

	lo->slab_alloc_type = F_BY_UTIL;
	lo->thread_run_intl = 1000;
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

static inline f_slab_t stripe_to_slab(F_LAYOUT_t *lo, f_stripe_t stripe);
static inline void test_get_stripe()
{
	F_POOL_t *pool = f_get_pool();
	F_LAYOUT_t *lo;
	struct list_head *l, *tmp;
	int rc = 0;

	list_for_each_safe(l, tmp, &pool->layouts) {
		struct f_stripe_set ss;
		int i;

		lo = container_of(l, struct f_layout_, list);

		memset(&ss, 0, sizeof(ss));
		ss.count = 4096;
		ss.stripes = alloca(sizeof(f_stripe_t) * ss.count);
		memset(ss.stripes, 0, sizeof(f_stripe_t) * ss.count);
/*
		while (atomic_read(&lo->lp->prealloced_stripes) < ss.count) { 
			printf("%d\n", atomic_read(&lo->lp->prealloced_stripes)); 
			sleep(1); 
		}
*/
		rc = f_get_stripe(lo, F_STRIPE_INVALID, &ss);
		if (rc < 0) {
			LOG(LOG_ERR, "%s[%d]: error %d in f_get_stripe", lo->info.name, lo->lp->part_num, rc);
			return;
		} else {
			LOG(LOG_DBG, "%s[%d]: allocated %d stripes", lo->info.name, lo->lp->part_num, rc);
		}
		printf("ss: %u", ss.count);
		for (i = 0; i < ss.count; i++) {
			f_slab_t slab = stripe_to_slab(lo, ss.stripes[i]);
			printf(" %u:%lu", slab, ss.stripes[i]);
		}
		printf("\n");

		rc = f_put_stripe(lo, &ss);
		if (rc)
			LOG(LOG_ERR, "%s[%d]: error %d in f_get_stripe", lo->info.name, lo->lp->part_num, rc);
	}
}

int f_start_allocator_threads(void)
{
	F_POOL_t *pool = f_get_pool();
	F_LAYOUT_t *lo;
	int rc = 0;

	ASSERT(pool);

	rc = f_set_ionode_ranks(pool);
	if (rc) {
		LOG(LOG_ERR, "error %s in f_set_ionode_ranks", strerror(-rc));
		return rc;
	}

	rc = create_pds_lfa(pool);
	if (rc) {
		destroy_pds_lfa(pool);
		return rc;
	}

	sleep(1);
	/* Init local slabmap and claim vector (f_map_init, f_map_register) in all layouts */
	rc = f_prepare_layouts_maps(pool, false);
	if (rc) {
	    LOG(LOG_ERR, "error %d in prepare_layouts_maps", rc);
	    return rc;
	}

	list_for_each_entry(lo, &pool->layouts, list) {
		rc = start_allocator_thread(lo);
		if (rc) {
			LOG(LOG_ERR, "%s[%d]: error %s starting allocator", 
				lo->info.name, lo->lp->part_num, strerror(-rc));
		}
	}

//	test_get_stripe();

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
					lo->info.name, lo->lp->part_num, strerror(-rc));
			}
		}
	}
	destroy_pds_lfa(pool);
	return rc;
}

/*
 * Initialize layout's maps
 */
int f_prepare_layouts_maps(F_POOL_t *pool, int global)
{
    F_LAYOUT_t *lo;
    int part, msg_partid;
    int e_sz, rc = 0;

    part = NodeIsIOnode(&pool->mynode) ? pool->mynode.ionode_idx : 0;

    list_for_each_entry(lo, &pool->layouts, list) {
	msg_partid = global? lo->part_count:lo->lp->part_num;

	/* slabmap */
	e_sz = F_SLABMAP_ENTRY_SZ(lo->info.chunks);
	lo->slabmap = f_map_init(F_MAPTYPE_STRUCTURED, e_sz, F_SLABMAP_BOSL_SZ, 0);
	if (!lo->slabmap) {
	    rc = -ENOMEM;
	    goto _err;
	}

	rc = f_map_init_prt(lo->slabmap, lo->part_count, part, 0, global);
	if (rc) {
	    LOG(LOG_ERR, "%s[%d]: error %d initializing %sslabmap",
		lo->info.name, msg_partid, rc, global?"global ":"");
	    goto _err;
	}

	rc = f_map_register(lo->slabmap, lo->info.conf_id);
	if (rc) {
	    LOG(LOG_ERR, "%s[%d]: error %d registering %sslabmap",
		lo->info.name, msg_partid, rc, global?"global ":"");
	    goto _err;
	}

	/* claim vector */
	lo->claimvec  = f_map_init(F_MAPTYPE_BITMAP, 2, 0, 0);
	if (!lo->claimvec) {
	    rc = -ENOMEM;
	    goto _err;
	}

	/*
	 * Reset the claim vector interleave to one slab worth of stripes.
	 * This is neccessary in order to align slab map and claim vector partition.
	 */
	if (lo->info.cv_intl_factor < lo->claimvec->geometry.intl_factor) {
	    rc = -EINVAL;
	    goto _err;
	}
	lo->claimvec->geometry.intl_factor = lo->info.cv_intl_factor;

	rc = f_map_init_prt(lo->claimvec, lo->part_count, part, 0, 1);
	if (rc) {
	    LOG(LOG_ERR, "%s[%d]: error %d initializing %sclaim vector",
		lo->info.name, msg_partid, rc, global?"global ":"");
	    goto _err;
	}

	rc = f_map_register(lo->claimvec, lo->info.conf_id);
	if (rc) {
	    LOG(LOG_ERR, "%s[%d]: error %d registering %sclaim vector",
		lo->info.name, msg_partid, rc, global?"global ":"");
	    goto _err;
	}
    }
    return rc;

_err:
    /* TODO: Call MPI_Abort(index->rs_comm); */
    return rc;
}

/*
 * Slab allocation helper routines
 */
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

static f_slab_t find_free_slab(F_LO_PART_t *lp)
{
	f_slab_t s;
	for (s = 0; s < lp->slab_count; s++) {
		if (slab_allocated(lp, s))
			continue;
		if (!lp->slab_usage[s].used)
			break;
	}
	return s;
}

int f_get_slab_devmap(F_LO_PART_t *lp, f_slab_t slab, unsigned long *devmap)
{
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	F_SLABMAP_ENTRY_t *sme;
	int n;

	ASSERT(F_DEVMAP_SIZE >= BITS_TO_LONGS(pool->info.pdev_max_idx+1));
	bitmap_zero(devmap, pool->info.pdev_max_idx+1);

	/* Get the slab map entry */
	sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lp->slabmap, slab);
	if (!sme) {
		LOG(LOG_ERR, "%s[%d]: error on SM entry %u", lo->info.name, lp->part_num, slab);
		return -EINVAL;
	}

	/* Sanity check */
	if (!sme->slab_rec.mapped) {
		LOG(LOG_ERR, "%s[%d]: slab %u s not mapped", lo->info.name, lp->part_num, slab);
		return -ENOENT;
	}

	/* Construct the slab device map */
	for (n = 0; n < lo->info.chunks; n++) {
		unsigned int di = sme->extent_rec[n].media_id;
		unsigned long bit = 1L << (di % BITS_PER_LONG);
		devmap[di / BITS_PER_LONG] |= bit;
	}

	return 0;
}

static int get_slab_agmap(F_LO_PART_t *lp, F_SLABMAP_ENTRY_t *sme, unsigned long *agmap)
{
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	f_slab_t slab = f_map_prt_to_local(lp->slabmap, stripe_to_slab(lo, sme->slab_rec.stripe_0));
	int n;

	bitmap_zero(agmap, pool->pool_ags);

	/* Sanity check */
	if (!sme->slab_rec.mapped) {
		LOG(LOG_ERR, "%s[%d]: slab %u s not mapped", lo->info.name, lp->part_num, slab);
		return -ENOENT;
	}

	/* Construct the slab AG map skipping AGs that were used to allocate failed extents */
	for (n = 0; n < lo->info.chunks; n++) {
		if (!sme->extent_rec[n].failed) {
			F_POOLDEV_INDEX_t *pdi = f_find_pdi_by_media_id(lo, sme->extent_rec[n].media_id);
			unsigned long bit = 1L << (pdi->idx_ag % BITS_PER_LONG);
			agmap[pdi->idx_ag / BITS_PER_LONG] |= bit;
		}
	}

	return 0;
}

static inline struct f_stripe_entry *alloc_stripe_entry(F_LO_PART_t *lp)
{
        struct f_stripe_entry *se;
	F_LAYOUT_t *lo = lp->layout;

        se = (struct f_stripe_entry *)calloc(1, sizeof(struct f_stripe_entry));
	if (!se) {
		LOG(LOG_ERR, "%s[%d]:  error allocating stripe entry", lo->info.name, lp->part_num);
		return ERR_PTR(-ENOMEM);
	}
	INIT_LIST_HEAD(&se->list);
	se->lp = lp;

	atomic_inc(lp->stats + FL_SE_ALLOC);
	return se;
}

static inline void free_stripe_entry(struct f_stripe_entry *se)
{
	F_LO_PART_t *lp = se->lp;

	ASSERT(lp);
	ASSERT(list_empty(&se->list));

	atomic_inc(lp->stats + FL_SE_FREE);
	free(se);
}


/* Pre-allocation buckets management functions */
static inline struct f_stripe_bucket *alloc_stripe_bucket(F_LO_PART_t *lp)
{
        struct f_stripe_bucket *sb;
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;

        sb = calloc(1, sizeof(struct f_stripe_bucket));
	if (!sb) {
		LOG(LOG_ERR, "%s[%d]:  error allocating stripe bucket", lo->info.name, lp->part_num);
		return ERR_PTR(-ENOMEM);
	}
	INIT_LIST_HEAD(&sb->list);
	INIT_LIST_HEAD(&sb->head);
	bitmap_zero(sb->devmap, pool->info.pdev_max_idx+1);
	atomic_set(&sb->count, 0);
	sb->lp = lp;

	atomic_inc(lp->stats + FL_SB_ALLOC);
	return sb;
}

static inline void free_stripe_bucket(struct f_stripe_bucket *sb)
{
	F_LO_PART_t *lp = sb->lp;

	ASSERT(lp);
	ASSERT(list_empty(&sb->list));

	atomic_inc(lp->stats + FL_SB_FREE);
	free(sb);
}

/* Return number of currently used buckets */
static inline int stripe_buckets_used(F_LO_PART_t *lp)
{
	return atomic_read(&lp->bucket_count);
}

static struct f_stripe_bucket *nth_bucket(F_LO_PART_t *lp, int n)
{
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	struct f_stripe_bucket *sb;
	int i = 0;

	list_for_each_entry(sb, &lp->alloc_buckets, list) {

		ASSERT(!bitmap_empty(sb->devmap, pool->info.pdev_max_idx+1));

		if (i == n)
			return sb;
		i++;
	}
	return NULL;
}


static struct f_stripe_bucket *find_stripe_bucket(F_LO_PART_t *lp, unsigned long *devmap)
{
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	struct f_stripe_bucket *sb;
	int i = 0;

	list_for_each_entry(sb, &lp->alloc_buckets, list) {

		ASSERT(!bitmap_empty(sb->devmap, pool->info.pdev_max_idx+1));

		/* match them against the devmap */
		if (bitmap_equal(sb->devmap, devmap, pool->info.pdev_max_idx+1)) {
			LOG(LOG_DBG3, "%s[%d]: found bucket %d", lo->info.name, lp->part_num, i);
			return sb;
		}
		i++;
	}
	return NULL;
}

static struct f_stripe_bucket *add_stripe_bucket(F_LO_PART_t *lp, unsigned long *devmap)
{
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	struct f_stripe_bucket *sb;

	sb = alloc_stripe_bucket(lp);
	if (IS_ERR(sb))
		return sb;
	bitmap_copy(sb->devmap, devmap, pool->info.pdev_max_idx+1);
	list_add_tail(&sb->list, &lp->alloc_buckets);
	atomic_inc(&lp->bucket_count);

	if (atomic_read(&lp->bucket_count_max) < atomic_read(&lp->bucket_count))
		atomic_set(&lp->bucket_count_max, atomic_read(&lp->bucket_count));

	LOG(LOG_DBG2, "%s[%d]: added alloc bucket, count: %d", 
		lo->info.name, lp->part_num, atomic_read(&lp->bucket_count));
	return sb;
}

static inline struct f_stripe_bucket *get_stripe_bucket(F_LO_PART_t *lp, unsigned long *devmap)
{
	struct f_stripe_bucket *sb = find_stripe_bucket(lp, devmap);
	return (sb) ? sb : add_stripe_bucket(lp, devmap);
}

static inline struct f_stripe_entry *find_sync_stripe(F_LO_PART_t *lp, struct f_stripe_bucket *sb)
{
	struct f_stripe_entry *se = NULL, *next;

	if (!sb || list_empty(&sb->head)) {
		return NULL;
	}
	list_for_each_entry_safe(se, next, &sb->head, list) {
		ASSERT(se->slab < lp->slab_count);
		if (slab_in_sync(lp, se->slab)) {
			return se;
		}
	}
	return NULL;
}

static struct f_stripe_entry *find_stripe(F_LO_PART_t *lp, f_stripe_t stripe)
{
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	struct f_stripe_bucket *sb;
	struct f_stripe_entry *se = NULL, *next;
	unsigned long devmap[F_DEVMAP_SIZE];
	f_slab_t slab = stripe_to_slab(lo, stripe);
	int rc;

	rc = f_get_slab_devmap(lp, slab, devmap);
	ASSERT(!rc);
	ASSERT(!bitmap_empty(devmap, pool->info.pdev_max_idx+1));

	pthread_spin_lock(&lp->alloc_lock);
	sb = find_stripe_bucket(lp, devmap);

	if (!sb || list_empty(&sb->head)) {
		pthread_spin_unlock(&lp->alloc_lock);
		return NULL;
	}
	list_for_each_entry_safe(se, next, &sb->head, list) {
		if (se->stripe == stripe) {
			ASSERT(se->slab == slab);
			pthread_spin_unlock(&lp->alloc_lock);
			return se;
		}
	}
	pthread_spin_unlock(&lp->alloc_lock);
	return NULL;
}

/* Map load callback function data */
struct cb_data {
	F_LO_PART_t 	*lp;
	int		loaded;
	int		err;
	size_t		dsize;
	void		*data;
};

/*
 * Apply this layout partition extent map and counters accumulated while 
 * loading slab map to the global area
 */
static inline int apply_counters_to_devices(F_LO_PART_t *lp, struct cb_data *cbdata)
{
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	int bmap_size = max(sizeof(long), BITS_TO_BYTES(pool->info.max_extents)); 
	int sha_size = sizeof(F_PDEV_SHA_t) + bmap_size;
	int dev0 =  pool->info.pdev_max_idx + 1 - pool->pool_devs;
	int i, n, rc, r = 0;

	for (i = 0; i <= pool->info.pdev_max_idx; i++) {
		F_POOL_DEV_t *pdev = f_find_pdev_by_media_id(pool, i+dev0);
		F_POOLDEV_INDEX_t *pdi = f_find_pdi_by_media_id(lo, i+dev0);
		F_PDEV_SHA_t *p_sha = (F_PDEV_SHA_t *) (cbdata->data + sha_size*i);
		off_t off, sha_off;
		int used;

		if (!pdev) continue;

		LOG(LOG_DBG, "%s[%d]: dev %d: used/failed exts: %lu/%u/%lu extmap: 0x%lx",
			lo->info.name, lp->part_num, i+dev0, p_sha->extents_used, 
			pdi->prt_extents_used, p_sha->failed_extents, p_sha->extent_bmap[0]);

		ASSERT(pdev->sha);
		sha_off = (void *)pdev->sha - pool->pds_lfa->global;
		ASSERT(sha_off < pool->pds_lfa->global_size);

		used = bitmap_weight(p_sha->extent_bmap, bmap_size*BITS_PER_BYTE);
		ASSERT(used == p_sha->extents_used);

		if (p_sha->extent_bmap) {
			for (n = 0; n < BITS_TO_LONGS(bmap_size); n++) {
				off = sha_off + offsetof(F_PDEV_SHA_t, extent_bmap) + n*sizeof(long);
				rc = f_lfa_gborfl(pool->pds_lfa->global_abd, off, *(p_sha->extent_bmap + n));
				if (rc) {
					LOG(LOG_WARN, "%s[%d]: error %d updating device %d extent map", 
						lo->info.name, lp->part_num, rc, i);
					r = rc;
				}
			}
		}
		if (p_sha->extents_used) {
			off = sha_off + offsetof(F_PDEV_SHA_t, extents_used);
			rc = f_lfa_gaafl(pool->pds_lfa->global_abd, off, p_sha->extents_used);
			if (rc) {
				LOG(LOG_WARN, "%s[%d]: error %d updating device %d usage", 
					lo->info.name, lp->part_num, rc, i);
				r = rc;
			}
		}
		if (p_sha->failed_extents) {
			off = sha_off + offsetof(F_PDEV_SHA_t, failed_extents);
			rc = f_lfa_gaafl(pool->pds_lfa->global_abd, off, p_sha->failed_extents);
			if (rc) {
				LOG(LOG_WARN, "%s[%d]: error %d updating device %d failed extents", 
					lo->info.name, lp->part_num, rc, i);
				r = rc;
			}
		}
	}
	return r;
}

/*
 * Slab map load callback function. Called on each slab map PU load
 */
static void slabmap_load_cb(uint64_t e, void *arg, const F_PU_VAL_t *pu)
{
	struct cb_data *data = (struct cb_data *) arg;
	F_LO_PART_t *lp = data->lp;
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	F_SLABMAP_ENTRY_t *sme;
	f_slab_t slab = e;
	int bmap_size =max(sizeof(long), BITS_TO_BYTES(pool->info.max_extents)); 
	unsigned int pu_entries = 1U << lp->slabmap->geometry.pu_factor;
	unsigned int e_sz = lp->slabmap->geometry.entry_sz;
	int dev0 =  pool->info.pdev_max_idx + 1 - pool->pool_devs;
	unsigned int i;

	for(i = 0; i < pu_entries; i++, slab++) {
		f_stripe_t s0 = slab_to_stripe0(lo, f_map_prt_to_global(lp->slabmap, slab));
		unsigned int n;

		sme = (F_SLABMAP_ENTRY_t *)&pu->se;
		if (!sme) {
			LOG(LOG_ERR, "%s[%d]: error on SM entry %u", lo->info.name, lp->part_num, slab);
			data->err++;
		}
	
		if (sme->slab_rec.mapped) {
			/* Check slab map entry CRC */
			if (f_crc4_sm_chk(&sme->slab_rec)) {
				LOG(LOG_ERR, "%s[%d]: slab %u CRC error", lo->info.name, lp->part_num, slab);
				data->err++;
			}
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
			unsigned int dev_id = sme->extent_rec[n].media_id;
			F_POOL_DEV_t *pdev = f_find_pdev_by_media_id(pool, dev_id);
			F_POOLDEV_INDEX_t *pdi = f_find_pdi_by_media_id(lo, dev_id);
			F_PDEV_SHA_t *p_sha;	
			int sha_size = sizeof(F_PDEV_SHA_t) + bmap_size;
			
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
				continue;
			}
				
			/* Populate device extent map (temporary per layout/partition version) */
			p_sha = (F_PDEV_SHA_t *) (data->data + sha_size*(dev_id-dev0));
			set_bit(sme->extent_rec[n].extent, p_sha->extent_bmap);

			p_sha->extents_used++;
			pdi->prt_extents_used++;

			if (sme->extent_rec[n].failed) {
				p_sha->failed_extents++;
				LOG(LOG_DBG2, "%s[%d]: slab %u ext %u failed", 
					lo->info.name, lp->part_num, slab, n);
			}
		}

		data->loaded++;

		LOG(LOG_DBG, "%s[%d]: slab %u loaded: %d errors", lo->info.name, lp->part_num, slab, data->err);
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
	unsigned int pu_entries = 1U << lp->claimvec->geometry.pu_factor;
	unsigned int e_sz = lp->claimvec->geometry.entry_sz;
	unsigned int i;

	if (bbitmap_empty((unsigned long *)pu, e_sz*pu_entries)) return;

	for(i = 0; i < pu_entries; i++, s++) {
		if (test_bbit_patterns(i, CV_ALLOCATED_P | CV_LAMINATED_P, (unsigned long *)pu)) {
			F_SLABMAP_ENTRY_t *sme;
			f_slab_t slab = stripe_to_slab(lo, s);

			/* Verify that the slab is mapped */
			sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lp->slabmap, slab);
			if (!sme->slab_rec.mapped) {
				LOG(LOG_ERR, "%s[%d]: slab %u (s %lu) not mapped", 
					lo->info.name, lp->part_num, slab, s);
				data->err++;
			} else {
				inc_slab_used(lp, s);
			}
		} else if (test_bbit(i, CVE_PREALLOC, (unsigned long *)pu)) {
			LOG(LOG_DBG3, "%s[%d]: clearing preallocated stipe %lu", lo->info.name, lp->part_num, s);
			set_bbit(i, CVE_FREE, (unsigned long *)pu);
			f_map_mark_dirty(lp->claimvec, s);
		}
		LOG(LOG_DBG3, "%s[%d]: stripe %lu loaded: %d errors", lo->info.name, lp->part_num, s, data->err);
		data->loaded++;
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
	F_POOL_t *pool = lo->pool;
	struct cb_data cbdata;
	int rc;

	ASSERT(lp->slabmap && lp->claimvec);

	LOG(LOG_DBG, "%s[%d]: loading slabmap", lo->info.name, lp->part_num);

	cbdata.lp = lp;
	cbdata.err = 0;
	cbdata.loaded = 0;
	cbdata.dsize = pool->pds_lfa->global_size;
	cbdata.data = calloc(1, cbdata.dsize);
	if (!cbdata.data) {
		LOG(LOG_ERR, "%s[%d]: error allocating data area", lo->info.name, lp->part_num);
		return  -ENOMEM;
	}

	rc = f_map_load_cb(lp->slabmap, slabmap_load_cb, (void *)&cbdata);
	if (rc || cbdata.err) {
		LOG(LOG_ERR, "%s[%d]: error %d loading SM, %d load errors",
			lo->info.name, lp->part_num, rc, cbdata.err);
		f_print_sm(dbg_stream, lp->slabmap, lo->info.chunks, lo->info.slab_stripes);
		return rc ? rc : cbdata.err;
	}

	if (cbdata.loaded) {
		rc = apply_counters_to_devices(lp, &cbdata);
		if (rc) {
			LOG(LOG_ERR, "%s[%d]: error %d propagating counters to global map", 
				lo->info.name, lp->part_num, rc);
			return rc;
		}
	}

	LOG(LOG_DBG, "%s[%d]: %u slabs loaded: %d errors", lo->info.name, lp->part_num, cbdata.loaded, cbdata.err);
	free(cbdata.data);
	cbdata.dsize = 0;

	if (log_print_level > 0)
		f_print_sm(dbg_stream, lp->slabmap, lo->info.chunks, lo->info.slab_stripes);

	LOG(LOG_DBG, "%s[%d]: loading claim vector", lo->info.name, lp->part_num);
	if (f_map_is_ro(lp->claimvec)) {
		LOG(LOG_ERR, "%s[%d]: error %d registering CV", lo->info.name, lp->part_num, rc);
		return rc;
	}

	cbdata.err = 0;
	cbdata.loaded = 0;

	rc = f_map_load_cb(lp->claimvec, claimvec_load_cb, (void *)&cbdata);
	if (rc || cbdata.err) {
		LOG(LOG_ERR, "%s[%d]: error %d loading CV, %d load errors",
			lo->info.name, lp->part_num, rc, cbdata.err);
		return rc ? rc : cbdata.err;
	}

	LOG(LOG_DBG, "%s[%d]: %u stripes loaded: %d errors",
		lo->info.name, lp->part_num, cbdata.loaded, cbdata.err);

	if (log_print_level > 0)
		f_print_cv(dbg_stream, lp->claimvec);

	if (cbdata.loaded) {
		rc = f_map_flush(lp->claimvec);
		if (rc) {
			LOG(LOG_ERR, "%s[%d]: error %d flushing claim vector", lo->info.name, lp->part_num, rc);
			return rc;
		}
	}
	return rc;
}

static void flush_maps(F_LO_PART_t *lp)
{
	F_LAYOUT_t *lo = lp->layout;
	int rc;
	LOG(LOG_DBG2, "%s[%d]: flushing maps", lo->info.name, lp->part_num);
	rc = f_map_flush(lp->slabmap);
	if (rc) LOG(LOG_ERR, "%s[%d]: error %d flushing slab map", lo->info.name, lp->part_num, rc);
	rc = f_map_flush(lp->claimvec);
	if (rc) LOG(LOG_ERR, "%s[%d]: error %d flushing claim vector", lo->info.name, lp->part_num, rc);
}

/*
 * Atomically (within extents and the slab entry) copy the slab map entry 
 * from the input buffer and recalculate checksums
 */
static void sme_set_atomic(F_LAYOUT_t *lo, F_SLABMAP_ENTRY_t *sme, F_SLABMAP_ENTRY_t *_sme)
{
	volatile F_SLAB_ENTRY_t *sep = &sme->slab_rec;
	F_SLAB_ENTRY_t se, old_se;
	F_EXTENT_ENTRY_t ext, old_ext;
	int retries, retries_max = 5;
	unsigned int n;

	for (n = 0;  n < lo->info.chunks; n++) {
		volatile F_EXTENT_ENTRY_t *extp = &sme->extent_rec[n];

		retries = 0;
		old_ext._v64 = __atomic_load_8(&sme->extent_rec[n], __ATOMIC_SEQ_CST);
		ext = _sme->extent_rec[n];
		do {
			/* Flags could be updated concurrently */
			if (old_ext.mapped && old_ext.failed)
				ext.failed = old_ext.failed;
			ext.checksum = 0;
			ext.checksum = f_crc4_fast((char*)&ext, sizeof(ext));
			if (likely(__atomic_compare_exchange_8(extp, &old_ext, ext._v64, 
				0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)))
				break;
		} while (++retries < retries_max);
		ASSERT(retries < retries_max);
	}
	
	retries = 0;
	old_se._v128 = __atomic_load_16(&sme->slab_rec, __ATOMIC_SEQ_CST);
//	 __atomic_load(&sme->slab_rec, &old_se, __ATOMIC_SEQ_CST);
	se = _sme->slab_rec;
	do {
		/* Flags could be updated concurrently */
		if (old_se.mapped ) {
			ASSERT(old_se.stripe_0 == se.stripe_0);
			se.failed = old_se.failed;
			se.degraded = old_se.degraded;
			se.recovery = old_se.recovery;
			se.recovered = old_se.recovered;
		}
		se.checksum = 0;
		se.checksum = f_crc4_sm_fast(&se);
		if (likely(__atomic_compare_exchange_16(sep, &old_se, se._v128, 
			0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)))
			break;
	} while (++retries < retries_max);
	ASSERT(retries < retries_max);
}

static int cmp_pdi_by_usage(const void *a, const void *b)
{
	F_POOLDEV_INDEX_t *pdia = (F_POOLDEV_INDEX_t *)a;
	F_POOLDEV_INDEX_t *pdib = (F_POOLDEV_INDEX_t *)b;
	unsigned int ua = pdia->pool_index == F_PDI_NONE ? UINT_MAX : pdia->prt_extents_used;
	unsigned int ub = pdib->pool_index == F_PDI_NONE ? UINT_MAX : pdib->prt_extents_used;
	if (ua > ub)
		return 1;
	else if (ua == ub)
		return 0;
	return -1;
}

static int pdi_matrix_init(F_PDI_MATRIX_t *mx)
{
	int i, j;

	mx->addr = (F_POOLDEV_INDEX_t *) calloc(mx->rows * mx->cols, sizeof(F_POOLDEV_INDEX_t));
	if (!mx->addr) return -ENOMEM;

	/* Initialize the matrix */
	for (i = 0; i < mx->rows; i++) {
		F_POOLDEV_INDEX_t *pdi = ((F_POOLDEV_INDEX_t (*)[mx->cols]) mx->addr)[i];
		for (j = 0; j < mx->cols; j++, pdi++) {
			pdi->idx_ag = i;
			pdi->idx_dev = j;
			pdi->pool_index = F_PDI_NONE;
			pdi->prt_extents_used = 0;
		}
	}

	return 0;
}

static F_POOLDEV_INDEX_t *pdi_matrix_lookup(F_PDI_MATRIX_t *mx, size_t row, size_t col)
{
	ASSERT(mx->addr && col < mx->cols && row < mx->rows);
	return mx->addr + (row * mx->cols + col);
}

/* Lookup by pool index in a particular matrix row */
static F_POOLDEV_INDEX_t *pdi_matrix_lookup_by_id(F_PDI_MATRIX_t *mx, size_t row, unsigned int id)
{
	F_POOLDEV_INDEX_t *pdi;
	int i;

	pdi = ((F_POOLDEV_INDEX_t (*)[mx->cols]) mx->addr)[row];
	for (i = 0; i < mx->cols; i++, pdi++) {
		if (pdi->pool_index == id)
			return pdi;
	}
	return NULL;
}

/* Sort the matrix rows by extents_used for every row */
static void pdi_matrix_sort(F_PDI_MATRIX_t *mx)
{
	F_POOLDEV_INDEX_t *pdi;
	int i;
	for (i = 0; i < mx->rows; i++) {
		pdi = ((F_POOLDEV_INDEX_t (*)[mx->cols]) mx->addr)[i];
		qsort(pdi, mx->cols, sizeof(F_POOLDEV_INDEX_t), cmp_pdi_by_usage);
	}
}

/* Re-sort a prevously sorted matrix row by extents_used */
static void pdi_matrix_resort(F_PDI_MATRIX_t *mx, size_t row)
{
	F_POOLDEV_INDEX_t *pdi0 = ((F_POOLDEV_INDEX_t (*)[mx->cols]) mx->addr)[row];

#if 0
	F_POOLDEV_INDEX_t *pdi = NULL;
	int i;
	/* This works for cases when only the first element in the row usage is updated */
	for (i = 1; i < mx->cols; i++) {
		pdi = pdi0 + i;
		if (pdi->prt_extents_used >= pdi0->prt_extents_used || pdi->pool_index == F_PDI_NONE)
			break;
	}
	/* i now reflects the position to move 0 element */
	if (--i > 0 && i < mx->cols) {
		F_POOLDEV_INDEX_t tmpdi;
		/* 
		 * i now reflects the position to move 0 element to,
		 * shift i elements left and move 0 element to pos i
		 */ 
		memcpy(&tmpdi, pdi0, sizeof(F_POOLDEV_INDEX_t));
		memcpy(pdi0, pdi0+1, i*sizeof(F_POOLDEV_INDEX_t));
		memcpy(pdi0+i, &tmpdi, sizeof(F_POOLDEV_INDEX_t));
	}
#endif			
	qsort(pdi0, mx->cols, sizeof(F_POOLDEV_INDEX_t), cmp_pdi_by_usage);
}

/*
 * Generate a device list to include the least used device from each AG
 */
static int pdi_matrix_gen_devlist_across_AGs(F_PDI_MATRIX_t *mx, F_POOLDEV_INDEX_t *devlist, unsigned int *size)
{
	F_POOL_t *pool = f_get_pool();
	F_POOLDEV_INDEX_t *pdi, *pdi0;
	F_POOLDEV_INDEX_t *col0_list = (F_POOLDEV_INDEX_t *) alloca(sizeof(F_POOLDEV_INDEX_t)*mx->rows);
	unsigned int i;

	if (!col0_list) return -ENOMEM;
	if (*size > mx->rows) return -EINVAL;

	memset(col0_list, 0, sizeof(F_POOLDEV_INDEX_t)*mx->rows);

	/* Generate a PDI list from the matrix 0 column */
	for (i = 0, pdi0 = col0_list; i < mx->rows && i < *size; i++) {
		F_POOL_DEV_t *pdev;
		pdi = ((F_POOLDEV_INDEX_t (*)[mx->cols]) mx->addr)[i];
		pdev = f_find_pdev_by_media_id(pool, pdi->pool_index);
		if (!pdev || DevFailed(pdev->sha) || DevMissing(pdev->sha) || DevDisabled(pdev->sha))
			continue;
		memcpy(pdi0, pdi, sizeof(F_POOLDEV_INDEX_t));
		pdi0++;
	}

	*size = i;

	/* Sort the resulting list by usage and copy the required number of PDIs to the output list */
	qsort(col0_list, *size, sizeof(F_POOLDEV_INDEX_t), cmp_pdi_by_usage);
	memcpy(devlist, col0_list, (*size)*sizeof(F_POOLDEV_INDEX_t));
	return 0;
}

/*
 * Generate a device list suitable for replacement of a slab extent. The list should exclude devices 
 * from AGs currently used in slab except for the AG containing the failed device
 */
static int pdi_matrix_gen_devlist_for_replace(F_PDI_MATRIX_t *mx, 
	F_POOLDEV_INDEX_t *devlist, unsigned int *size, F_SLABMAP_ENTRY_t *sme)
{
	F_POOL_t *pool = f_get_pool();
	F_POOLDEV_INDEX_t *pdi, *pdi0;
	F_POOLDEV_INDEX_t *list = 
		(F_POOLDEV_INDEX_t *) alloca(sizeof(F_POOLDEV_INDEX_t)*mx->rows*mx->cols);
	unsigned long *agmap = alloca(BITS_TO_BYTES(pool->pool_ags));
	unsigned int i, j, n;

	if (!list) return -ENOMEM;

	memset(list, 0, sizeof(F_POOLDEV_INDEX_t)*mx->rows*mx->cols);

	ASSERT(!get_slab_agmap(mx->lp, sme, agmap));

	/* Generate a PDI list from the matrix rows not in AG map */
	for (i = 0, n = 0, pdi0 = list; i < mx->rows; i++) {
		if (test_bit(i, agmap)) continue;
		pdi = ((F_POOLDEV_INDEX_t (*)[mx->cols]) mx->addr)[i];
		for (j = 0; j < mx->cols; j++, pdi++) {
			F_POOL_DEV_t *pdev;
			pdev = f_find_pdev_by_media_id(pool, pdi->pool_index);
			if (!pdev || DevFailed(pdev->sha) || DevMissing(pdev->sha) || 
				DevDisabled(pdev->sha))
				continue;
			memcpy(pdi0, pdi, sizeof(F_POOLDEV_INDEX_t));
			pdi0++; n++;
		}
	}

	*size = n;

	/* Sort the resulting list by usage and copy the required number of PDIs to the output list */
	qsort(list, *size, sizeof(F_POOLDEV_INDEX_t), cmp_pdi_by_usage);
	memcpy(devlist, list, (*size)*sizeof(F_POOLDEV_INDEX_t));
	return 0;
}

static void pdi_matrix_release(F_PDI_MATRIX_t *mx)
{
	if (mx && mx->addr) free(mx->addr);
}

/*
 * Create a 2-dimensional device allocation matrix with each AG devices sorted by device usage
 */
static int create_lp_dev_matrix(F_LO_PART_t *lp)
{
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	F_POOLDEV_INDEX_t *pdi, *mpdi;
	int i, rc = -ENOMEM;

	lp->dmx = (F_PDI_MATRIX_t *) calloc(1, sizeof(F_PDI_MATRIX_t));
	if (lp->dmx) {
		lp->dmx->lp	= lp;
		lp->dmx->rows   = pool->pool_ags;
		lp->dmx->cols   = pool->ag_devs;
		lp->dmx->init   = pdi_matrix_init;
		lp->dmx->lookup = pdi_matrix_lookup;
		lp->dmx->lookup_by_id = pdi_matrix_lookup_by_id;
		lp->dmx->sort   = pdi_matrix_sort;
		lp->dmx->resort = pdi_matrix_resort;
		lp->dmx->gen_devlist = pdi_matrix_gen_devlist_across_AGs;
		lp->dmx->gen_devlist_for_replace = pdi_matrix_gen_devlist_for_replace;
		lp->dmx->release = pdi_matrix_release;
		rc = lp->dmx->init(lp->dmx);
	}
	if (rc) {
		LOG(LOG_ERR, "%s[%d]: error %d allocating layout dev matrix", lo->info.name, lp->part_num, rc);
		if (lp->dmx) free(lp->dmx);
		return rc;
	}

	/* Copy PDIs from layout devlist to the allocation matrix */
	for (i = 0; i < lo->devlist_sz; i++) {
		pdi = &lo->devlist[i];
		mpdi = lp->dmx->lookup(lp->dmx, pdi->idx_ag, pdi->idx_dev);
		mpdi->pool_index = pdi->pool_index;
		mpdi->prt_extents_used = pdi->prt_extents_used;
	}

	lp->dmx->sort(lp->dmx);
	return 0;
}

/* Release device allocation matrix */
static void release_lp_dev_matrix(F_LO_PART_t *lp)
{
	if (lp->dmx) {
		lp->dmx->release(lp->dmx);
		free(lp->dmx);
	}
}

/*
 * Allocate a free device extent: set pdev allocation bitmap
 * and adjust pdev/pdi counters
 * Device index to allocate from has to be set in the F_EXTENT_ENTRY_t  by the caller.
 * Returns device extent number or error
 */
int f_alloc_dev_extent(F_LO_PART_t *lp, F_EXTENT_ENTRY_t *ext)
{
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	F_POOL_DEV_t *pdev = f_find_pdev_by_media_id(pool, ext->media_id);
	F_POOLDEV_INDEX_t *pdi = f_find_pdi_by_media_id(lo, ext->media_id);
	F_POOLDEV_INDEX_t *mpdi;
//	int trg_ix;
	int boff, extent, rc;
	off_t off, sha_off;

	ASSERT(pdev && pdi);
	ASSERT(pdev->sha);
	sha_off = (void *)pdev->sha - pool->pds_lfa->global;
	ASSERT(sha_off < pool->pds_lfa->global_size);

//	mpdi = lp->dmx->lookup(lp->dmx, pdi->idx_ag, 0);
	mpdi = lp->dmx->lookup_by_id(lp->dmx, pdi->idx_ag, pdi->pool_index);
	ASSERT(pdi->pool_index == mpdi->pool_index);

	/*
	 * We currently don't allow allocation on missing devices
	 * This is for future extensions
	 */
	if (DevMissing(pdev->sha))
		atomic_inc(&lp->missing_dev_slabs);

	/*
	 * Find a free extent on that device, we use libfabric atomic operations
	 * to avoid locking. Access to the extent bitmap is randomized by setting 
	 * the initial bit offset boff to search from.
	 */
	boff = (pdev->extent_count / pool->ionode_count) * pool->mynode.ionode_idx;
	off = sha_off + offsetof(F_PDEV_SHA_t, extent_bmap);
	extent = f_lfa_gbfcs(pool->pds_lfa->global_abd, off, boff, pdev->extent_count);
	if (extent < 0) {
		LOG(LOG_WARN, "%s[%d]: allocation failed on device id %d, err %d", 
			lo->info.name, lp->part_num, ext->media_id, extent);
		return extent;
	}

	off = sha_off + offsetof(F_PDEV_SHA_t, extents_used);
	rc = f_lfa_giafl(pool->pds_lfa->global_abd, off);
	if (rc) {
		LOG(LOG_WARN, "%s[%d]: error %d updating device %d usage", 
			lo->info.name, lp->part_num, rc, ext->media_id);
	}

	/* Extents used in that partition */
	pdi->prt_extents_used++;
	mpdi->prt_extents_used = pdi->prt_extents_used;

	/* Re-sort the matrix row we picked the device from */ 
	lp->dmx->resort(lp->dmx, pdev->idx_ag);

	LOG(LOG_DBG2, "%s[%d]: extent %u allocated on %d, used/total %lu/%u/%u", lo->info.name, lp->part_num, 
		extent, ext->media_id, pdev->sha->extents_used, pdi->prt_extents_used, pdev->extent_count);
	return extent;
}

/*
 * Release device extent: clear pdev allocation bitmaps
 * and adjust pdev/pdi counters
 */
void f_release_dev_extent(F_LO_PART_t *lp, F_EXTENT_ENTRY_t *ext)
{
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	F_POOL_DEV_t *pdev = f_find_pdev_by_media_id(pool, ext->media_id);
	F_POOLDEV_INDEX_t *pdi = f_find_pdi_by_media_id(lo, ext->media_id);
	F_POOLDEV_INDEX_t *mpdi;
//	int trg_ix;
	int  rc;
	off_t off, sha_off;

	ASSERT(pdev && pdi);
	ASSERT(pdev->sha);
	sha_off = (void *)pdev->sha - pool->pds_lfa->global;
	ASSERT(sha_off < pool->pds_lfa->global_size);

	mpdi = lp->dmx->lookup_by_id(lp->dmx, pdi->idx_ag, pdi->pool_index);
	ASSERT(mpdi);

	/* Decerement the missing device slab count if that was a missing device */
	if (DevMissing(pdev->sha))
		atomic_dec(&lp->missing_dev_slabs);

	/* Update extent map and decrement counters */
//	trg_ix = pdev->dev->f.ionode_idx;
	off = sha_off + offsetof(F_PDEV_SHA_t, extent_bmap);
	rc = f_lfa_gbcf(pool->pds_lfa->global_abd, off, ext->extent);
	if (rc) {
		LOG(LOG_WARN, "%s[%d]: error %d updating device %d usage", 
			lo->info.name, lp->part_num, rc, ext->media_id);
	}


	off = sha_off + offsetof(F_PDEV_SHA_t, extents_used);
	rc = f_lfa_gdafl(pool->pds_lfa->global_abd, off);
	if (rc) {
		LOG(LOG_WARN, "%s[%d]: error %d updating device %d usage", 
			lo->info.name, lp->part_num, rc, ext->media_id);
	}

	if (ext->failed) {
		off = sha_off + offsetof(F_PDEV_SHA_t, failed_extents);
		rc = f_lfa_gdafl(pool->pds_lfa->global_abd, off);
		if (rc) {
			LOG(LOG_WARN, "%s[%d]: error %d updating device %d failed exts", 
				lo->info.name, lp->part_num, rc, ext->media_id);
		}
	}

	/* Extents used in that partition */
	pdi->prt_extents_used--;
	mpdi->prt_extents_used = pdi->prt_extents_used;

	/* Re-sort the matrix row we picked the device from */ 
	lp->dmx->resort(lp->dmx, pdev->idx_ag);

	LOG(LOG_DBG2, "%s[%d]: extent %u released on %d, used/total %lu/%u/%u", lo->info.name, lp->part_num, 
		ext->extent, ext->media_id, pdev->sha->extents_used, pdi->prt_extents_used, pdev->extent_count);
}

/* 
 * Allocate slab extent: allocate a pool device extent and update the extent struct
 */
static inline int alloc_slab_extent(F_LO_PART_t *lp, F_EXTENT_ENTRY_t *ext)
{
	int extent = f_alloc_dev_extent(lp, ext);

	if (extent >= 0) {
		/* Fill in the extent */
		ext->extent = extent;
		ext->mapped = 1;
	} else {
		memset(ext, 0, sizeof(F_EXTENT_ENTRY_t));
	}

	return extent;
}

/* 
 * Release slab extent: release a device extent and 
 * clear the extent structure in slab map 
 */
static inline void release_slab_extent(F_LO_PART_t *lp, F_SLABMAP_ENTRY_t *sme, unsigned int n)
{
	/* Release device extent */
	f_release_dev_extent(lp, &sme->extent_rec[n]);
	
	/* Clear the slab map extent record */
	memset(&sme->extent_rec[n], 0, sizeof(F_EXTENT_ENTRY_t));
}

/* 
 * Allocate device extents for a slab.
 * Pool devices are sorted by their utilization, i.e. with preference for
 * less utilized devices
 */
static unsigned int alloc_slab_extents_by_util(F_LO_PART_t *lp, 
	F_SLABMAP_ENTRY_t *sme, F_POOLDEV_INDEX_t *devlist, int devnum)
{
	F_LAYOUT_t *lo = lp->layout;
	unsigned int n;
	int i, rc = 0;

	LOG(LOG_DBG, "%s[%d]: allocating extents for slab %lu", lo->info.name, lp->part_num,
		f_map_prt_to_local(lp->slabmap, stripe_to_slab(lo, sme->slab_rec.stripe_0)));

	for (i = 0, n = 0; i < devnum && n < lo->info.chunks; i++) {
		F_POOLDEV_INDEX_t *pdi = &devlist[i];		
		ASSERT(pdi->pool_index != F_PDI_NONE);

		/* Try to allocate a device extent */
		sme->extent_rec[n].media_id = pdi->pool_index;
		rc = alloc_slab_extent(lp, &sme->extent_rec[n]);
		if (rc < 0) {
			LOG(LOG_WARN, "%s[%d]: allocation failed on device id %d", 
				lo->info.name, lp->part_num, pdi->pool_index);
			continue;
		}
		n++;
	}

	return n;
}

/* 
 * Allocate device extents for a slab.
 * Pool devices are sorted by their pool indexes
 */
static unsigned int alloc_slab_extents_by_index(F_LO_PART_t *lp, 
	F_SLABMAP_ENTRY_t *sme, F_POOLDEV_INDEX_t *devlist, int devnum)
{
	F_LAYOUT_t *lo = lp->layout;
	f_slab_t slab = f_map_prt_to_local(lp->slabmap, stripe_to_slab(lo, sme->slab_rec.stripe_0));
	unsigned int n;
	int i, rc = 0;

	LOG(LOG_DBG, "%s[%d]: allocating extents for slab %u", lo->info.name, lp->part_num, slab);

	ASSERT(devnum >= lo->info.chunks);
	for (i = (slab * lo->info.chunks) % devnum, n = 0; n < lo->info.chunks; 
								i = (i < devnum-1) ? i+1 : 0) {
		F_POOLDEV_INDEX_t *pdi = &devlist[i];		
		ASSERT(pdi->pool_index != F_PDI_NONE);

		/* Try to allocate a device extent */
		sme->extent_rec[n].media_id = pdi->pool_index;
		rc = alloc_slab_extent(lp, &sme->extent_rec[n]);
		if (rc < 0) {
			LOG(LOG_WARN, "%s[%d]: allocation failed on device id %d", 
				lo->info.name, lp->part_num, pdi->pool_index);
			continue;
		}
		n++;
	}

	return n;
}

/* 
 * Allocate device extents for a slab.
 * Allocation algorithm is determind by the variance in the pool
 * devices usage
 */
static unsigned int alloc_slab_extents(F_LO_PART_t *lp, F_SLABMAP_ENTRY_t *sme)
{
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	f_slab_t slab = f_map_prt_to_local(lp->slabmap, stripe_to_slab(lo, sme->slab_rec.stripe_0));
	F_POOLDEV_INDEX_t *sorted_devlist = NULL;
	unsigned int n = 0, devnum = pool->pool_ags;
	int rc;

	sorted_devlist = calloc(pool->pool_ags, sizeof(F_POOLDEV_INDEX_t));
	if (!sorted_devlist) {
		LOG(LOG_ERR, "%s[%d]: error allocating device list array", lo->info.name, lp->part_num);
		return 0;
	}

	pthread_rwlock_wrlock(&pool->lock);

	/* Make sure the next allocator thread sees an updated list */ 
	rc = lp->dmx->gen_devlist(lp->dmx, sorted_devlist, &devnum);
	if (rc) {
		LOG(LOG_ERR, "%s[%d]: slab %u: error %d in gen_devlist",
			lo->info.name, lp->part_num, slab, rc);
		return 0;
	}
	if (devnum < lo->info.chunks) {
		n = devnum;
		LOG(LOG_DBG, "%s[%d]: slab %u: not enough devices available: %d of %d", 
			lo->info.name, lp->part_num, slab, devnum, lo->info.chunks);
		goto _ret;
	}

	if (lo->slab_alloc_type == F_BY_IDX) 
		n = alloc_slab_extents_by_index(lp, sme, sorted_devlist, devnum);
	else
		n = alloc_slab_extents_by_util(lp, sme, sorted_devlist, devnum);

_ret:
	pthread_rwlock_unlock(&pool->lock);
	free(sorted_devlist);
//	print_sheetmap_entry(lo, sme);

	return n;
}

/*
 * Release sheet extents, note that the slab could be only partially allocated 
 */
static unsigned int release_slab_extents(F_LO_PART_t *lp, F_SLABMAP_ENTRY_t *sme)
{
	F_LAYOUT_t *lo = lp->layout;
	unsigned int n;

	for (n = 0; n < lo->info.chunks; n++) {
		/* Data extent is not mapped - must be a partially allocated slab */
		if (n < lo->info.chunks && !sme->extent_rec[n].mapped) {
			LOG(LOG_DBG, "%s[%d]: ext %u not mapped", lo->info.name, lp->part_num, n);
			break;
		}
		release_slab_extent(lp, sme, n);
	}

	return n;
}

/*
 * Release a slab, freeing the underlying extents
 */
static int release_slab(F_LO_PART_t *lp, f_slab_t slab)
{
	F_LAYOUT_t *lo = lp->layout;
	F_SLABMAP_ENTRY_t *_sme, *sme = NULL;
	unsigned int n;
	int rc = 0;

	ASSERT(slab < lp->slab_count);
	if (lp->slab_usage[slab].used) {
		LOG(LOG_ERR, "%s[%d]: slab %u stll has %d stripes allocated",
			lo->info.name, lp->part_num, slab, lp->slab_usage[slab].used);
		return -EINVAL;
	}

	sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lp->slabmap, slab);
	if (!sme) {
		LOG(LOG_ERR, "%s[%d]: error getting SM entry %u", lo->info.name, lp->part_num, slab);
		return -EINVAL;
	}

	/* Sanity check */
	if (!sme->slab_rec.mapped) {
		LOG(LOG_ERR, "%s[%d]: slab %u s not mapped", lo->info.name, lp->part_num, slab);
		return -EINVAL;
	}

	/* 
	 * Copy the slabmap entry to a temp buffer to be able to release it 
	 * prior to releasing device extents 
	 */
	_sme = alloca(lp->slabmap->geometry.entry_sz);
	memcpy(_sme, sme, lp->slabmap->geometry.entry_sz);

	/*
	 * Clear and flush the slab map entry before releasing
	 * device extents to avoid the stripe repair confusion in case we crash here.
	 */
	memset(sme, 0, lp->slabmap->geometry.entry_sz); //FIXME: atomic update

	/* Update bitmaps */
	clear_slab_allocated(lp, slab);
	if (!slab_in_sync(lp, slab)) {
		set_slab_in_sync(lp, slab);  // unmapped slab is in sync by default
		lp->sync_count++;
		if (_sme->slab_rec.degraded)
			atomic_dec(&lp->degraded_slabs);
		else if (_sme->slab_rec.failed)
			atomic_dec(&lp->failed_slabs);
//		clear_slab_recovering(lp, slab);
	}
	reset_slab_usage(lp, slab);

	/* Flush the slab map before releasing device extents */
	f_map_mark_dirty(lp->slabmap, slab);
	LOG(LOG_DBG2, "%s[%d]: flushing slabmap for slab %u", lo->info.name, lp->part_num, slab);
	rc = f_map_flush(lp->slabmap);
	if (rc) {
		LOG(LOG_ERR, "%s[%d]: error %d flushing slabmap for slab %u",
			lo->info.name, lp->part_num, rc, slab);
		goto _ret;
	}

	/* Slab record released and saved, now release the device extents */
	n = release_slab_extents(lp, _sme);
	if (n < lo->info.chunks)
		LOG(LOG_WARN, "%s[%d]: slab %u: released %d extents of %d",
			lo->info.name, lp->part_num, slab, n, lo->info.chunks);

	atomic_inc(&lp->slabmap_version);
	LOG(LOG_DBG, "%s[%d]: slab %u released", lo->info.name, lp->part_num, slab);
_ret:
	return rc;
}

/*
 * Allocate a new slab for this partition. 
 * A slab to allocate could be passed in slabp, otherwise find and allocate the first available
 */
static int __alloc_new_slab(F_LO_PART_t *lp, f_slab_t *slabp)
{
	F_LAYOUT_t *lo = lp->layout;
	F_SLABMAP_ENTRY_t *sme, *_sme;
	F_ITER_t *sm_iter;
	f_slab_t s = (*slabp == F_SLAB_INVALID) ? find_free_slab(lp) : *slabp;
	loglevel alloc_err_lvl = !LayoutNoSpace(lo) ? LOG_WARN : LOG_DBG;
	int n, rc = 0;

	if (s == lp->slab_count) {
		LOG(LOG_ERR, "%s[%d]: no free slabs left", lo->info.name, lp->part_num);
		return -ENOSPC;
	}

	sm_iter = f_map_new_iter(lp->slabmap, F_NO_CONDITION, 0);
	sm_iter = f_map_seek_iter(sm_iter, s);
	assert(sm_iter);
	sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lp->slabmap, sm_iter->entry);
	if (!sme) {
		LOG(LOG_ERR, "%s[%d]: error on SM entry %u", lo->info.name, lp->part_num, s);
		goto _ret;
	}

	/* Sanity check */
	if (sme->slab_rec.mapped) {
		LOG(LOG_ERR, "%s[%d]: slab %u already mapped", lo->info.name, lp->part_num, s);
		rc = -EINVAL;
		goto _ret;
	}

	_sme = alloca(lp->slabmap->geometry.entry_sz);
	memcpy(_sme, sme, lp->slabmap->geometry.entry_sz);

	/* Set s0 (global) before allocating slab extents */
	_sme->slab_rec.stripe_0 = slab_to_stripe0(lo, f_map_prt_to_global(lp->slabmap,s));

	/* Allocate slab extents */
	n = alloc_slab_extents(lp, _sme);
	if (n < 0) {
		LOG(LOG_ERR, "%s[%d]: failed to allocate extents for slab %u", lo->info.name, lp->part_num, s);
		rc = -ENOSPC;
		goto _ret;
	}

	/* Enough extents allocated? If not, release allocated extents and set layout no space */
	if (n < lo->info.chunks) {
		unsigned int m = release_slab_extents(lp, _sme);
		if (!LayoutNoSpace(lo)) SetLayoutNoSpace(lo);
		LOG(alloc_err_lvl, "%s[%d]: not enough devices (%d of %d) found for slab %u, "
			"released %d extents", lo->info.name, lp->part_num, n, lo->info.chunks, s, m);
		rc = -ENOSPC;
		goto _ret;
	}	

	/* All slab extents allocated, set the mapped flag and calculate CRC */
	_sme->slab_rec.mapped = 1;
	sme_set_atomic(lo, sme, _sme);

	/* update bitmaps */
	reset_slab_usage(lp, s);
	set_slab_allocated(lp, s);
	set_slab_in_sync(lp, s);
	lp->sync_count++;

	f_map_mark_dirty(lp->slabmap, s);
	LOG(LOG_DBG2, "%s[%d]: flushing slabmap for slab %u", lo->info.name, lp->part_num, s);
	rc = f_map_flush(lp->slabmap);
	if (rc) {
		LOG(LOG_ERR, "%s[%d]: error %d flushing slabmap for slab %u",
			lo->info.name, lp->part_num, rc, s);
		release_slab(lp, s);
		goto _ret;
	}
	
	atomic_inc(&lp->slabmap_version);
	*slabp = s;
	LOG(LOG_DBG, "%s[%d]: slab %u allocated", lo->info.name, lp->part_num, s);
_ret:
	if (sm_iter ) {f_map_free_iter(sm_iter); sm_iter = NULL;}	
	return rc;
}

/*
 * Allocate a frst available new slab for this partition.
 */ 
static inline int alloc_new_slab(F_LO_PART_t *lp, f_slab_t *slabp)
{
	*slabp = F_SLAB_INVALID;
	return __alloc_new_slab(lp, slabp);
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

static inline bool can_allocate_from_slab(F_LO_PART_t *lp, f_slab_t slab)
{ 
	F_LAYOUT_t *lo = lp->layout;

	// Skip unallocated slabs
	if (!slab_allocated(lp, slab)) {
		LOG(LOG_DBG, "%s[%d]: slab %u is not allocated", lo->info.name, lp->part_num, slab);
		return false;
	}

	// Skip full slabs
	if (lp->slab_usage[slab].used == lo->info.slab_stripes) {
		LOG(LOG_DBG3, "%s[%d]: slab %u is full", lo->info.name, lp->part_num, slab);
		return false;
	}
	// Skip degraded slabs
	if (!slab_in_sync(lp, slab)) {
		LOG(LOG_DBG, "%s[%d]: slab %u is not in sync, skipping allocation", 
			lo->info.name, lp->part_num, slab);
		return false;
	}
	return true;
}

/* 
 * Pre-allocate stripe (set CVE_PREALLOC) 
 */
static inline int alloc_stripe(F_LO_PART_t *lp, f_stripe_t s)
{
	F_LAYOUT_t *lo = lp->layout;
	unsigned long old;
	void *p = f_map_get_p(lp->claimvec, s);

	if (!p) {
		LOG(LOG_ERR, "%s[%d]: error accessing claim vector entry %lu", lo->info.name, lp->part_num, s);
		return -ENOENT;
	}

	LOG(LOG_DBG3, "%s[%d]: allocating stripe %lu", lo->info.name, lp->part_num, s);

	/* Set the stripe preallocated */
	old = atomic_test_and_set_bbit(BBIT_NR_IN_LONG(s), CVE_PREALLOC, p);

	/* Check if someone beat us to it (should nver happen) */
	ASSERT(old == CVE_FREE);

	/* Set the dirty bit */
	f_map_mark_dirty(lp->claimvec, s);
	return 0;
}

/* 
 * Commit stripe (set CVE_ALLOCATED) 
 */
static inline int commit_stripe(F_LO_PART_t *lp, f_stripe_t s)
{
	F_LAYOUT_t *lo = lp->layout;
	unsigned long old;
	void *p = f_map_get_p(lp->claimvec, s);

	LOG(LOG_DBG3, "%s[%d]: committing stripe %lu", lo->info.name, lp->part_num, s);

	if (!p) {
		LOG(LOG_ERR, "%s[%d]: error accessing claim vector entry %lu", 
			lo->info.name, lp->part_num, s);
		return -ENOENT;
	}

	/* Set the stripe preallocated */
	old = atomic_test_and_set_bbit(BBIT_NR_IN_LONG(s), CVE_ALLOCATED, p);

	/* Check the previous state */
	ASSERT(old == CVE_PREALLOC || old == CVE_ALLOCATED);

	/* Set the dirty bit */
	f_map_mark_dirty(lp->claimvec, s);
	return 0;
}

/* 
 * Set stripe laminated (set CVE_LAMINATED) 
 */
static inline int laminate_stripe(F_LO_PART_t *lp, f_stripe_t s)
{
	F_LAYOUT_t *lo = lp->layout;
	unsigned long old;
	void *p = f_map_get_p(lp->claimvec, s);

	LOG(LOG_DBG3, "%s[%d]: setting stripe %lu laminated", lo->info.name, lp->part_num, s);

	if (!p) {
		LOG(LOG_ERR, "%s[%d]: error accessing claim vector entry %lu", 
			lo->info.name, lp->part_num, s);
		return -ENOENT;
	}

	/* Set the stripe preallocated */
	old = atomic_test_and_set_bbit(BBIT_NR_IN_LONG(s), CVE_LAMINATED, p);

	/* Check the previous state */
	ASSERT(old == CVE_ALLOCATED);

	/* Set the dirty bit */
	f_map_mark_dirty(lp->claimvec, s);
	return 0;
}

/*
 * Release a stripe by clearing its claim vector
 * Set drop_slab to false to prevent releasing empty slabs.
 */
static int release_stripe(F_LO_PART_t *lp, f_stripe_t s, bool drop_slab)
{
	F_LAYOUT_t *lo = lp->layout;
	unsigned long old;
	void *p;
	int rc = 0;

	LOG(LOG_DBG3, "%s[%d]: releasing stripe %lu", lo->info.name, lp->part_num, s);

	p = f_map_get_p(lp->claimvec, s);
	if (!p) {
		LOG(LOG_ERR, "%s[%d]: error accessing claim vector entry %lu", lo->info.name, lp->part_num, s);
		return -ENOENT;
	}

	/* Set the stripe preallocated */
	old = atomic_test_and_set_bbit(BBIT_NR_IN_LONG(s), CVE_FREE, p);

	/* Check if someone beat us to it (should never happen) */
	ASSERT(old != CVE_FREE);

	/* Set the dirty bit */
	f_map_mark_dirty(lp->claimvec, s);

	/* Consider releasing this stripe slab if this was the last allocated stripe there */
	dec_slab_used(lp, s);
	if (!slab_used(lp, s) && drop_slab) {
		f_slab_t slab = stripe_to_slab(lo, s);
		if (slab < lp->min_alloc_slabs) {
			LOG(LOG_INFO, "%s[%d]: slab %u is within min alloc sheets %u, not releasing", 
				lo->info.name, lp->part_num, slab, lp->min_alloc_slabs);
		    	return 0;
	    	} 
		rc = release_slab(lp, slab);
		if (rc) {
			LOG(LOG_ERR, "%s[%d]: error %d releasing slab %u", 
				lo->info.name, lp->part_num, rc, slab);
			return rc;
		}
    	}

	return 0;
}

/*
 * Release count of stripes from the pre-allocated tree, all if the count is 0.
 * Called from the stripe allocator with layout partition lock taken.
 */
static int release_prealloc_stripes(F_LO_PART_t *lp, int count)
{
	F_LAYOUT_t *lo = lp->layout;
	struct f_stripe_entry *se, *next;
	struct list_head tmplist;
	struct f_stripe_bucket *sb, *nsb;
	int remcount, n = 0, rc = 0;

	LOG(LOG_DBG, "%s[%d]: releasing %d preallocated stripes", 
		lo->info.name, lp->part_num, count ? count : atomic_read(&lp->prealloced_stripes));

	INIT_LIST_HEAD(&tmplist);

	/* Quickly copy all extra stripes into a temp list first */
	pthread_spin_lock(&lp->alloc_lock);
	remcount = count ? atomic_read(&lp->prealloced_stripes) - count : 0;
	if (!atomic_read(&lp->prealloced_stripes)) {
		pthread_spin_unlock(&lp->alloc_lock);
		LOG(LOG_DBG, "%s[%d]: empty pre-allocation list, not releasing", lo->info.name, lp->part_num); 
		return 0;
	}
	while (atomic_read(&lp->prealloced_stripes) > remcount) {
		list_for_each_entry_safe(sb, nsb, &lp->alloc_buckets, list) {
			if (list_empty(&sb->head)) {
				LOG(LOG_DBG, "%s[%d]: empty bucket, count %d",
					lo->info.name, lp->part_num, atomic_read(&sb->count));
				continue;
			}
			se = list_first_entry(&sb->head, struct f_stripe_entry, list);
			list_move_tail(&se->list, &tmplist);
			n++;

			/* Free empty bucket */
			if (!atomic_dec_return(&sb->count)) {
				ASSERT(list_empty(&sb->head));
				list_del_init(&sb->list);
				free_stripe_bucket(sb);
				atomic_dec(&lp->bucket_count);
			}
			if (atomic_dec_return(&lp->prealloced_stripes) == remcount)
				break;
		}
	}
	pthread_spin_unlock(&lp->alloc_lock);

	ASSERT(!list_empty(&tmplist));
		
	/* Now release all extra stripes */
	list_for_each_entry_safe(se, next, &tmplist, list) {
		rc = release_stripe(lp, se->stripe, true);
		if (rc < 0) {
			LOG(LOG_ERR, "%s[%d]: error %d releasing stripe %lu", 
				lo->info.name, lp->part_num, rc, se->stripe); 
		}
		list_del_init(&se->list);
		free_stripe_entry(se);
	}

	if (!count && atomic_read(&lp->prealloced_stripes)) 
		LOG(LOG_WARN, "%s[%d]: allocated stripes count %d after releasing all stripes", 
			lo->info.name, lp->part_num, atomic_read(&lp->prealloced_stripes));
	return rc;
}

/*
 * Go through the pre-allocated stripes list and purge all stripes
 * from degraded (not in sync) slabs
 */
static int purge_prealloc_stripes(F_LO_PART_t *lp)
{
	F_LAYOUT_t *lo = lp->layout;
	struct f_stripe_entry *se, *next;
	struct f_stripe_bucket *sb, *nsb;
	struct list_head tmplist;
	int count = 0, rc = 0;

	INIT_LIST_HEAD(&tmplist);

	/* Quickly copy degraded stripes into a temp list first */
	pthread_spin_lock(&lp->alloc_lock);
	if (!atomic_read(&lp->prealloced_stripes)) {
		pthread_spin_unlock(&lp->alloc_lock);
		LOG(LOG_DBG, "%s[%d]: empty pre-allocation list, skipping check", lo->info.name, lp->part_num); 
		return 0;
	}
	list_for_each_entry_safe(sb, nsb, &lp->alloc_buckets, list) {
		if (list_empty(&sb->head)) {
			LOG(LOG_DBG, "%s[%d]: empty bucket, count %d",
				lo->info.name, lp->part_num, atomic_read(&sb->count));
			continue;
		}
		list_for_each_entry_safe(se, next, &sb->head, list) {
			if (slab_in_sync(lp, se->slab))
				continue;
			list_move_tail(&se->list, &tmplist);

			/* Free empty bucket */
			if (!atomic_dec_return(&sb->count)) {
				ASSERT(list_empty(&sb->head));
				list_del_init(&sb->list);
				free_stripe_bucket(sb);
				atomic_dec(&lp->bucket_count);
			}

			atomic_dec(&lp->prealloced_stripes);
			count++;
		}
	}
	pthread_spin_unlock(&lp->alloc_lock);

	if (list_empty(&tmplist))
		return 0;

	LOG(LOG_DBG, "%s[%d]: releasing %d degraded stripes", lo->info.name, lp->part_num, count );

	/* Now release all degraded stripes */
	list_for_each_entry_safe(se, next, &tmplist, list) {
		rc = release_stripe(lp, se->stripe, true);
		if (rc < 0) {
			LOG(LOG_ERR, "%s[%d]: error %d removing stripe %lu", 
				lo->info.name, lp->part_num, rc, se->stripe); 
		}
		list_del_init(&se->list);
		free_stripe_entry(se);
	}

	if (count) {
		LOG(LOG_DBG, "%s[%d]: allocated stripes count %d after purging %d stripes", 
			lo->info.name, lp->part_num, atomic_read(&lp->prealloced_stripes), count);
	}
	return 0;
}

/* Claim Vector iterator condition: entry is free */
/*
static F_COND_t cv_free = {
    .pset = CV_FREE_P,
};
*/

/*
 * Find unused stripes in the slab and add them to the preallocated
 * stripes tree. 
 */
static int prealloc_stripes_in_slab(F_LO_PART_t *lp, f_slab_t slab, int count)
{
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	struct list_head alloclist;
	struct f_stripe_bucket *sb;
	struct f_stripe_entry *se, *next;
	F_ITER_t *cv_it;
	f_stripe_t s0 = slab_to_stripe0(lo, slab);
	unsigned long devmap[F_DEVMAP_SIZE];
	int i, n, rc;

	if (!count)
		return 0;
	
	if (!slab_allocated(lp, slab)) {
		LOG(LOG_WARN, "%s[%d]: slab %u is not yet allocated, skipping",
			lo->info.name, lp->part_num, slab);
		return -ENOENT;
	}

	LOG(LOG_DBG, "%s[%d]: allocating %d stripes in slab %u", lo->info.name, lp->part_num, count, slab);
	INIT_LIST_HEAD(&alloclist);

	if (log_print_level > LOG_DBG2)
		f_print_cv(dbg_stream, lp->claimvec);

	rc = f_get_slab_devmap(lp, slab, devmap);
	ASSERT(rc == 0);
	ASSERT(!bitmap_empty(devmap, pool->info.pdev_max_idx+1));

	cv_it = f_map_new_iter(lp->claimvec, F_NO_CONDITION, 0);
//	cv_it = f_map_new_iter(lp->claimvec, cv_free, 0);
	assert(cv_it);
	for (n = 0, i = 0; i < lo->info.slab_stripes && n < count; i++) {
		int v;
		/* Probe if the entry is in memory and force its creation if not */
		assert (f_map_probe_iter_at(cv_it, s0 + i, (void*)&v));
		if (v < 0) {
			/* create zeroed BoS in memory */
			cv_it = f_map_seek_iter(cv_it, s0 + i);
			v = 0;
		} /*else {
			cv_it = f_map_next(cv_it);
		}
		assert(cv_it);

		i = cv_it->entry - s0;
*/
		if (v != CVE_FREE) {
			LOG(LOG_DBG3, "%s[%d]: stripe %lu in slab %u: %d", 
				lo->info.name, lp->part_num, s0 + i, slab, v);
			continue;
		} else {
			rc = alloc_stripe(lp, s0 + i);
			if (rc < 0) {
				LOG(LOG_ERR, "%s[%d]: error allocating stripe %lu", 
					lo->info.name, lp->part_num, s0 + i);
				continue;
			}
		}
		n++;
		se = alloc_stripe_entry(lp);
		se->stripe = s0 + i;
		se->slab = slab;
		LOG(LOG_DBG3, "%s[%d]: stripe %lu allocated in slab %u", 
			lo->info.name, lp->part_num, se->stripe, slab);
		list_add_tail(&se->list, &alloclist);

		/* don't hug the cpu, yield every 1K or so entries */
		if (n && ((n & 0x3ff) == 0))
			sched_yield();
	}

	LOG(LOG_DBG, "%s[%d]: %d stripes allocated in slab %u (used %d)", 
			lo->info.name, lp->part_num, n, slab, slab_used(lp, s0));

	if (list_empty(&alloclist)) {
		LOG(LOG_DBG, "%s[%d]: no stripes (%d) allocated in slab %u (used %d)", 
			lo->info.name, lp->part_num, n, slab, slab_used(lp, s0));
		return 0;
	}

	rc = f_map_flush(lp->claimvec);
	if (rc) {
		LOG(LOG_ERR, "%s[%d]: error %d flushing claim vector", lo->info.name, lp->part_num, rc);
		list_for_each_entry_safe(se, next, &alloclist, list) {
			release_stripe(lp, se->stripe, false);
			list_del_init(&se->list);
			free_stripe_entry(se);
		}
		return 0;
	}

	/* Claim vector is flushed, now insert stripes into the preallocated stripes hash */ 
	pthread_spin_lock(&lp->alloc_lock);
	sb = get_stripe_bucket(lp, devmap);
	ASSERT(!IS_ERR(sb));
	list_for_each_entry_safe(se, next, &alloclist, list) {
		list_move_tail(&se->list, &sb->head);
		atomic_inc(&lp->prealloced_stripes);
		atomic_inc(&sb->count);
		inc_slab_used(lp, se->stripe);
	}
	pthread_spin_unlock(&lp->alloc_lock);

	return n;
}

/*
 * Go through all allocated slabs until we pre-allocate enough stripes 
 * to satisfy the request.
 */
static int prealloc_stripes(F_LO_PART_t *lp, int count)
{
	F_LAYOUT_t *lo = lp->layout;
	int *alloced;
	int per_slab_count = DIV_CEIL(count, lp->min_alloc_slabs);
	int max_slab = max_slab_allocated(lp);
	int i, rc, n = 0;

	if (!slabs_allocated(lp)) {
		LOG(LOG_INFO, "%s[%d]: no allocated slabs found", lo->info.name, lp->part_num);
		return 0;
	}

	if (!count) return 0;

	LOG(LOG_DBG, "%s[%d]: allocating %d stripes", lo->info.name, lp->part_num, count);

	alloced = alloca(sizeof(int) * lp->min_alloc_slabs);
	if (!alloced) {
		LOG(LOG_ERR, "%s[%d]: error allocating slab allocation array", lo->info.name, lp->part_num);
		return 0;
	}
	memset(alloced, 0, sizeof(int) * lp->min_alloc_slabs);

	/* Try to allocate stripes evenly distributed across slabs located on different devices */
	for (i = 0; n < count && i < lp->min_alloc_slabs; i++) {
		f_slab_t slab;
		for (slab = i; alloced[i] < per_slab_count && 
				slab < lp->slab_count; slab += lp->min_alloc_slabs) {

			/* Can we allocate from this slab? */
			if (!can_allocate_from_slab(lp, slab)) {
				if (slab < max_slab) continue;
				break;
			}
		
			LOG(LOG_DBG3, "%s[%d]: allocating %d stripes in slab %u", 
				lo->info.name, lp->part_num, per_slab_count, slab);

			rc = prealloc_stripes_in_slab(lp, slab, per_slab_count - alloced[i]);
			if (rc < 0) {
				LOG(LOG_ERR, "%s[%d]: error %d allocating stripes in slab %u", 
					lo->info.name, lp->part_num, rc, slab);
				continue;
			} else if (!rc) {
				LOG(LOG_DBG, "%s[%d]: no stripes allocated in slab %u", 
					lo->info.name, lp->part_num, slab);
			} else {
				alloced[i] += rc;
				n += rc;
				LOG(LOG_DBG, "%s[%d]: allocated %d of %d in slab %u, %d left",
					lo->info.name, lp->part_num, rc, count, slab, count - n);
			}
		}
	}
	
	if (!n) LOG(LOG_DBG, "%s[%d]: no stripes allocated in existing slabs", lo->info.name, lp->part_num);

	return n;
}

/*
 * Stripe allocation API
 */
/*
 * Stripes are preallocated (claim vector set to P) when aded to the allocation tree,
 * so we only update the in memory usage structures here
 */
//int r_get_stride(struct r_layout *rl, struct rv_stretch_node *rvsn, int width, bool primary, int bank)
static int __get_stripe(F_LO_PART_t *lp, f_stripe_t match_stripe, f_stripe_t *stripe)
{
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	struct f_stripe_entry *se, *best_se = NULL;
	struct f_stripe_bucket *sb, *nsb, *best_sb = NULL;
	unsigned long stripe_map[F_DEVMAP_SIZE];
	unsigned long match_map[F_DEVMAP_SIZE];
	int bmap_size = pool->info.pdev_max_idx+1;
	int i, w, best_w = bmap_size+1;
	int chunks = lo->info.chunks;
	f_slab_t match_slab = F_SLAB_INVALID;
	int rc;

	/* initialize and populate bitmaps */
	bitmap_zero(stripe_map, bmap_size);
	bitmap_zero(match_map, bmap_size);

	/* Get the stripe bitmap to match */
	if (match_stripe != F_STRIPE_INVALID) {
		match_slab = stripe_to_slab(lo, match_stripe);
		rc = f_get_slab_devmap(lp, match_slab, match_map);
		ASSERT(!rc && !bitmap_empty(match_map, bmap_size));
	}

	/* randomize responses for initial requests */
	if (bitmap_empty(match_map, bmap_size)) {
		int n = stripe_buckets_used(lp);
		int b = 0;

		ASSERT(n);
		
		for (i = 0; i < n; i++) {
			b = (atomic_read(lo->stats + FL_STRIPE_GET) + (i * 2)) % n;
			sb = nth_bucket(lp, b);

			ASSERT(sb);

			if (list_empty(&sb->head))
				continue;
			
			/* any good stripes on that list? */
			se = find_sync_stripe(lp, sb);
			if (!se)
				continue;

			LOG(LOG_DBG3, "%s[%d]:  initial request, stripe %lu slab %u",
				lo->info.name, lp->part_num, se->stripe, se->slab);
			best_w = 0;
			best_sb = sb;
			best_se = se;
			goto got_stripe;
		}
	}

	/* find the best matching stripe bucket */
	i = 0;
	list_for_each_entry_safe(sb, nsb, &lp->alloc_buckets, list) {

		/* skip empty lists */
		if (list_empty(&sb->head))
			continue;

		/* any good stripes on that list? */
		se = find_sync_stripe(lp, sb);
		if (!se)
			continue;

		/* match them against the stretch bitmap */
		bitmap_and(stripe_map, sb->devmap, match_map, bmap_size);

		/* count how many shared devices */
		w = bitmap_weight(stripe_map, bmap_size);

		/* zero weight means none, ideal case */
		if (!w) {
			best_w = w;
			best_sb = sb;
			best_se = se;
			break;
		}

		/* Choose stripe with the least # of shared drives */
		if (w < best_w) {
			best_w = w;
			best_sb = sb;
			best_se = se;
		}
		i++;
	}

	/* Should this be an assert? */
	if (!best_se) {
		LOG(LOG_ERR, "%s[%d]: failed to find stripe after checking %d bucket(s)", lo->info.name, lp->part_num, i);
//		atomic_inc(rl->stats + RL_STRIPE_GET_ERR);
		return -ENOMEM;
	}

got_stripe:
	if (!best_w) {
		atomic_inc(lo->stats + FL_STRIPE_GET_W0);
	} else if (best_w <= chunks/4) {
		atomic_inc(lo->stats + FL_STRIPE_GET_W25);
	} else if (best_w <= chunks/2) {
		atomic_inc(lo->stats + FL_STRIPE_GET_W50);
	} else if (best_w <= 3*chunks/4) {
		atomic_inc(lo->stats + FL_STRIPE_GET_W75);
	} else if (best_w >= chunks) {
		LOG(LOG_DBG3, "%s[%d]: w %u: failed to find matching stripe after checking %d bucket(s)", 
			lo->info.name, lp->part_num, best_w, i);
		atomic_inc(lo->stats + FL_STRIPE_GET_W100);
	}

		
	list_del_init(&best_se->list);
	*stripe = best_se->stripe;

	/* Update counters, move all stride stripes to the preallocated stripes counter */
	atomic_dec(&lp->prealloced_stripes);

	/* Empty bucket? Release it */
	if (!atomic_dec_return(&best_sb->count)) {
		ASSERT(list_empty(&best_sb->head));
		list_del_init(&best_sb->list);
		free_stripe_bucket(best_sb);
		atomic_dec(&lp->bucket_count);
	}


	LOG(LOG_DBG3,"%s[%d]: stripe %lu slab %u w %u", lo->info.name, lp->part_num, best_se->stripe, best_se->slab, best_w);
	free_stripe_entry(best_se);

	return 0;
}

/*
 * Add a stripe to the stripe release list.
 */
static inline void add_releaseq(F_LO_PART_t *lp, struct f_stripe_entry *se)
{
	ASSERT(list_empty(&se->list));
	pthread_spin_lock(&lp->releaseq_lock);
	list_add_tail(&se->list, &lp->releaseq);
	pthread_spin_unlock(&lp->releaseq_lock);

	/* wake up the pool allocator */
	pthread_cond_signal(&lp->a_thread_cond);
}
/*
 * Released stripes could go to:
 * 	stripe allocator daemon claim decrement queue
 * 	or the pre-allocated stripe list for that layout
 */ 
static int __put_stripe(F_LO_PART_t *lp, f_stripe_t stripe)
{
	struct f_stripe_entry *se = alloc_stripe_entry(lp);
	int rc = 0;

	atomic_inc(lp->stats + FL_STRIPE_RELEASE_REQ);

	if (IS_ERR(se)) {
		rc = PTR_ERR(se);
		goto err;
	}
		
	se->stripe = stripe;
	se->type = F_RELEASE;

	add_releaseq(lp, se);
	atomic_inc(lp->stats + FL_STRIPE_RELEASE_CLAIMDEC);
	return 0;

err:
	if (!IS_ERR(se))
		free_stripe_entry(se);
	atomic_inc(lp->stats + FL_STRIPE_RELEASE_ERR);
	return rc;
}

/* ms to timespec */
static inline void  msec2timespec(struct timespec *ts,uint64_t msec)
{
	ts->tv_sec = msec / 1000;
	ts->tv_nsec = (msec % 1000U) * 1000000U;
}

/*
 * No stripes allocated, wait for the allocator to signal that stripes have been allocated.
 * Returns -ETIMEDOUT if no signal was received during 3 allocator runs
 */
static inline int wait_stripes(F_LO_PART_t *lp)
{
	F_LAYOUT_t *lo = lp->layout;
	struct timespec to, wait;
	long wintl = 3 * lo->thread_run_intl;
	int rc;
	
	msec2timespec(&wait, wintl); /* ms to timespec */

	LOG(LOG_DBG, "%s[%d]: waiting %ld sec for stripes to be allocated", 
		lo->info.name, lp->part_num, wait.tv_sec);
	clock_gettime(CLOCK_REALTIME, &to);
	timespecadd(&to, &wait);

	pthread_mutex_lock(&lp->stripes_wait_lock);
	rc = pthread_cond_timedwait(&lp->stripes_wait_cond, &lp->stripes_wait_lock, &to);
	pthread_mutex_unlock(&lp->stripes_wait_lock);

	return -rc;
}

/*
 * Get a set of preallocated stripes.
 * ss->count should be set by the caller but could be adjusted down if there is not enough stripes.
 * It is expected that the caller will retry the call for the remainder.
 * If no stripes available but no out_of_space condition exists will wait for stripes to be allocated.
 * All stripe #s in the set are global.
 * Returns # of stripes allocated or error
 */
int f_get_stripe(F_LAYOUT_t *lo, f_stripe_t match_stripe, struct f_stripe_set *ss)
{
	F_LO_PART_t *lp = lo->lp;
	int i, rc;

	ASSERT(lp);
	atomic_inc(lo->stats + FL_STRIPE_GET_REQ);

	LOG(LOG_DBG2, "%s[%d]: received req for %d stripes", lo->info.name, lp->part_num, ss->count);

_retry:
	pthread_spin_lock(&lp->alloc_lock);
	if (atomic_read(&lp->prealloced_stripes) < ss->count) {
		pthread_spin_unlock(&lp->alloc_lock);
		if (out_of_space(lp)) {
			atomic_inc(lo->stats + FL_STRIPE_GET_NOSPC_ERR);
			return LayoutActive(lo) ? -ENOSPC : -ESRCH;
		} 
/*
		if (!lp->increase_prealloc) {
			lp->increase_prealloc = 1;
			LOG(LOG_WARN, "%s[%d]: no stripes pre-allocated", lo->info.name, lp->part_num);
		}
*/			
		pthread_cond_signal(&lp->a_thread_cond);
		atomic_inc(lo->stats + FL_STRIPE_GET_ERR);

		if (!atomic_read(&lp->prealloced_stripes)) {
			rc = wait_stripes(lp);
			if (rc == -ETIMEDOUT && !atomic_read(&lp->prealloced_stripes)) 
				return LayoutActive(lo) ? -ENOMEM : -ESRCH;
		} else { /* Return what we have for now */
			ss->count = min(ss->count, atomic_read(&lp->prealloced_stripes));
			LOG(LOG_DBG, "%s[%d]: adjusted stripe count to %d", 
				lo->info.name, lp->part_num, ss->count);
		}
		goto _retry;
	}

	for (i = 0; i < ss->count; i++) {
		f_stripe_t stripe;

		ss->stripes[i] = F_STRIPE_INVALID;
		rc = __get_stripe(lp, match_stripe, &stripe);
		if (rc) goto _err;

		match_stripe = stripe;
		ss->stripes[i] = f_map_prt_to_global(lp->claimvec, stripe);
		LOG(LOG_DBG3,"%s[%d]: stripe %lu", lo->info.name, lp->part_num, ss->stripes[i]);
	}
	pthread_spin_unlock(&lp->alloc_lock);

	LOG(LOG_DBG2, "%s[%d]: completed req for %d stripes", lo->info.name, lp->part_num, ss->count);
	atomic_inc(lo->stats + FL_STRIPE_GET);

	return i;

_err:
	pthread_spin_unlock(&lp->alloc_lock);
	atomic_inc(lo->stats + FL_STRIPE_GET_ERR);
	while (i--) {
		if (ss->stripes[i] != F_STRIPE_INVALID) {
			ASSERT(f_map_prt_my_global(lp->claimvec, ss->stripes[i]));
			__put_stripe(lp, f_map_prt_to_local(lp->claimvec, ss->stripes[i]));
		}
	}
	return rc;
}

/*
 * Release a set of stripes (set claim vector to FREE).
 * All stripe #s n the set are expected to be global and to belong to the local allocator partition.
 * Returns 0 or error, -ESRCH if layout thread exited
 */
int f_put_stripe(F_LAYOUT_t *lo, struct f_stripe_set *ss)
{
	F_LO_PART_t *lp = lo->lp;
	struct f_stripe_entry *se;
	int i, rc = 0;

	if (!LayoutActive(lo)) {
		LOG(LOG_ERR, "%s[%d]: lp thread exiting, rejecting %d stripes to release", 
			lo->info.name, lp->part_num, ss->count);
		return -ESRCH;
	}

	LOG(LOG_DBG2, "%s[%d]: releasing %d stripes", lo->info.name, lp->part_num, ss->count);

	for (i = 0; i < ss->count; i++) {
		f_stripe_t stripe;
		
		ASSERT(f_map_prt_my_global(lp->claimvec, ss->stripes[i]));
		stripe = f_map_prt_to_local(lp->claimvec, ss->stripes[i]);

		/* stripe should not be on the pre-allocated list */
		se = find_stripe(lp, stripe);
		if (se) {
			LOG(LOG_ERR, "%s[%d]: stripe %lu is on preallocated list", 
				lo->info.name, lp->part_num, stripe);
			ASSERT(!se);
		}

		rc += __put_stripe(lp, stripe);
	}

	LOG(LOG_DBG2, "%s[%d]: released %d stripes rc=%d", lo->info.name, lp->part_num, i, rc);
	return rc;
}

/*
 * Commit a set of preallocated stripes (set claim vector to ALLOCATED).
 * All stripe #s n the set are expected to be global and to belong to the local allocator partition.
 * Returns 0 or error code, -ESRCH if layout thread exited
 */
int f_commit_stripe(F_LAYOUT_t *lo, struct f_stripe_set *ss)
{
	F_LO_PART_t *lp = lo->lp;
	int i, rc = 0;

	ASSERT(lp);
	atomic_inc(lo->stats + FL_STRIPE_COMMIT_REQ);

	if (!LayoutActive(lo)) {
		LOG(LOG_ERR, "%s[%d]: lp thread exiting, rejecting %d stripes to commit", 
			lo->info.name, lp->part_num, ss->count);
		return -ESRCH;
	}

	LOG(LOG_DBG2, "%s[%d]: committing %d stripes", lo->info.name, lp->part_num, ss->count);

	for (i = 0; i < ss->count; i++) {
		f_stripe_t stripe;

		ASSERT(f_map_prt_my_global(lp->claimvec, ss->stripes[i]));
		stripe = f_map_prt_to_local(lp->claimvec, ss->stripes[i]);
		rc += commit_stripe(lp, stripe);
	}
	
	if (rc) atomic_inc(lo->stats + FL_STRIPE_COMMIT_ERR); 

	rc = f_submit_encode_stripes(lo, ss);
	if (rc) LOG(LOG_ERR, "%s[%d]: error %d submitting stripes for encoding", 
		lo->info.name, lp->part_num, rc);

	rc = f_map_flush(lp->claimvec);
	if (rc) LOG(LOG_ERR, "%s[%d]: error %d flushing claim vector", lo->info.name, lp->part_num, rc);

	LOG(LOG_DBG2, "%s[%d]: committed %d stripes rc=%d", lo->info.name, lp->part_num, i, rc);
	return rc;
}

/* 
 * Set stripe laminated (set CVE_LAMINATED) 
 */
int f_laminate_stripe(F_LAYOUT_t *lo, f_stripe_t s)
{
	return laminate_stripe(lo->lp, s);
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
	F_LAYOUT_t *lo = lp->layout;
	struct f_stripe_entry *se, *next;
	LIST_HEAD(releaseq);
	int rc = 0, n = 0;

	pthread_spin_lock(&lp->releaseq_lock);
	if (list_empty(&lp->releaseq)) {
		/* Nothing to do */
		pthread_spin_unlock(&lp->releaseq_lock);
		return 0;
	}

	/* Quickly grab the queue and release the lock */
	list_splice_init(&lp->releaseq, &releaseq);
	pthread_spin_unlock(&lp->releaseq_lock);

	list_for_each_entry_safe(se, next, &releaseq, list) {
		rc = release_stripe(lp, se->stripe, true);
		if (rc < 0) {
			LOG(LOG_ERR, "%s[%d]: error %d releasing stripe %lu, skipping",
				lo->info.name, lp->part_num, rc, se->stripe);
			continue;
		} else {
			/* Done with this stripe entry */
			list_del_init(&se->list);
			free_stripe_entry(se);
		}
		n++;

		/* don't hug the cpu, yield every 1K or so entries */
		if (n && ((n & 0x3ff) == 0))
			sched_yield();
	}

	/* Put the unprocessed entries back on the queue */
	if (!list_empty(&releaseq)) {
		pthread_spin_lock(&lp->releaseq_lock);
		list_splice(&releaseq, &lp->releaseq);
		pthread_spin_unlock(&lp->releaseq_lock);
	}
			
	return 0;
}

/* Virtual map iterator function, filters failed and degraded slabs */ 
static int sm_is_slab_f_d(void *arg, const F_PU_VAL_t *entry)
{
	const F_SLAB_ENTRY_t *se = &entry->se;
	return (se->mapped && (se->failed || se->degraded));
}

static F_COND_t sm_slab_f_d = {
	.vf_get = &sm_is_slab_f_d,
};

/*
 * Release degraded slabs taking them out of allocation.
 */
static int process_degraded_slabs(F_LO_PART_t *lp)
{
	F_LAYOUT_t *lo = lp->layout;
	F_ITER_t *sm_it;
	int df = 0, rc = 0;

	sm_it = f_map_get_iter(lp->slabmap, sm_slab_f_d, 0);
	for_each_iter(sm_it) {
		f_slab_t slab = sm_it->entry;
		f_stripe_t s0 = slab_to_stripe0(lo, slab);

		/* double check bitmaps */
		ASSERT(slab_allocated(lp, slab) && !slab_in_sync(lp, slab));

		/* Degraded and not used slab, just release it */
		if (!slab_used(lp, s0)) {
			LOG(LOG_DBG, "%s[%d]: releasing degraded/failed slab %u", lo->info.name, lp->part_num, slab);
			rc = release_slab(lp, slab);
			if (rc) LOG(LOG_ERR, "%s[%d]: error %d releasing D/F slab %u", 
				lo->info.name, lp->part_num, rc, slab);
		} else df++;
	} 
	f_map_free_iter(sm_it);

	if (atomic_read(&lp->degraded_slabs) + atomic_read(&lp->failed_slabs) != df) {
		 LOG(LOG_WARN, "%s[%d]: degraded slab count (%d) != actual (%d)",
			lo->info.name, lp->part_num, atomic_read(&lp->degraded_slabs), 
			df - atomic_read(&lp->failed_slabs));
	}

	return rc;
}

/* A placeholder for a more accurate calculation */
static unsigned int get_layout_slab_count(F_LAYOUT_t *lo)
{
	F_POOL_t *pool = lo->pool;
	F_POOL_DEV_t *pdev;
	F_POOLDEV_INDEX_t *pdi;
	unsigned long pexts = 0;
	int i;

	for (i = 0; i < lo->devlist_sz; i++) {
		pdi = &lo->devlist[i];
		pdev = f_find_pdev_by_media_id(pool, pdi->pool_index);	
		pexts += pdev->extent_count;
	}
	
	return DIV_CEIL(pexts, lo->info.chunks);
}

/*
 * Check if any of the layout devices are marked as failed
 * and update the affected slabs if any
 */
static void check_layout_devices(F_LAYOUT_t *lo)
{
	F_POOL_t *pool = lo->pool;
	F_POOL_DEV_t *pdev;
	F_POOLDEV_INDEX_t *pdi;
	int i;

	for (i = 0; i < lo->devlist_sz; i++) {
		pdi = &lo->devlist[i];
		pdev = f_find_pdev_by_media_id(pool, pdi->pool_index);
		if (pdev && DevFailed(pdev->sha)) {
			f_fail_pdev(lo, pdi->pool_index);
			f_replace(lo, pdi->pool_index, F_PDI_NONE);
//			f_replace(lo, F_PDI_NONE, F_PDI_NONE);
//			f_replace(lo, pdi->pool_index, 2);
		}
	}
}

/*
 * Release the layout partition structure.
 */
static inline void layout_partition_free(F_LO_PART_t *lp)
{
	if (lp->wpool) f_wpool_exit(lp->wpool, 0);
	if (lp->slabmap) f_map_exit(lp->slabmap);
	if (lp->claimvec) f_map_exit(lp->claimvec);
	rcu_unregister_thread();
	release_lp_dev_matrix(lp);
	pthread_mutex_destroy(&lp->a_thread_lock);
	pthread_cond_destroy(&lp->a_thread_cond);
	pthread_mutex_destroy(&lp->stripes_wait_lock);
	pthread_cond_destroy(&lp->stripes_wait_cond);
	pthread_spin_destroy(&lp->releaseq_lock);
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
	F_LAYOUT_t *lo = lp->layout;
	F_POOL_t *pool = lo->pool;
	int chunk_size_factor   = F_CHUNK_SIZE_MAX / lo->info.chunk_sz;
	size_t slab_usage_size, cv_bmap_size;
	int rc = -ENOMEM;

	rcu_register_thread();
	/* maps have initialized in f_prepare_layouts_maps() */
	lp->claimvec = lo->claimvec;
	lo->claimvec = NULL;
	lp->slabmap = lo->slabmap;
	lo->slabmap = NULL;

	if (pthread_mutex_init(&lp->a_thread_lock, NULL)) goto _err;
	if (pthread_cond_init(&lp->a_thread_cond, NULL)) goto _err;
	if (pthread_mutex_init(&lp->stripes_wait_lock, NULL)) goto _err;
	if (pthread_cond_init(&lp->stripes_wait_cond, NULL)) goto _err;
	if (pthread_spin_init(&lp->releaseq_lock, PTHREAD_PROCESS_PRIVATE)) goto _err;
	INIT_LIST_HEAD(&lp->releaseq);
	atomic_set(&lp->allocated_slabs, 0);
	atomic_set(&lp->degraded_slabs, 0);
	atomic_set(&lp->missing_dev_slabs, 0);
	atomic_set(&lp->failed_slabs, 0);
	atomic_set(&lp->prealloced_stripes, 0);
	atomic_set(&lp->allocated_stripes, 0);
	atomic_set(&lp->bucket_count, 0);
	atomic_set(&lp->bucket_count_max, 0);

	lp->w_thread_cnt = 16;
	lp->wpool = f_wpool_init(lp->w_thread_cnt, wp_farray, NULL);
	if (!lp->wpool) goto _err;

	lo->info.slab_count	= get_layout_slab_count(lo);
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

	LOG(LOG_DBG, "%s[%d]: part initialized: %u/%lu slabs/stripes",
		lo->info.name, lp->part_num, lp->slab_count, lp->stripe_count);
	return 0;

_err:
	layout_partition_free(lp);
	return rc;
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

	/* Flush the slab map if requested */
	if (LPSMFlush(lp)) {
		rc = f_map_flush(lp->slabmap);
		if (rc) {
			LOG(LOG_ERR, "%s[%d]: error %s flushing slabmap", 
				lo->info.name, lp->part_num, strerror(-rc));
		} else {
			atomic_inc(&lp->slabmap_version);
			ClearLPSMFlush(lp);
		}
	}

	/* Flush the claim vector map if requested */
	if (LPCVFlush(lp)) {
		rc = f_map_flush(lp->claimvec);
		if (rc) {
			LOG(LOG_ERR, "%s[%d]: error %s flushing claim vector", 
				lo->info.name, lp->part_num, strerror(-rc));
		} else {
			ClearLPCVFlush(lp);
		}
	}

	/* Process stripes to be released */
	rc = process_releaseq(lp);
	if (rc) {
		LOG(LOG_WARN, "%s[%d]: error %s processing preallocated stripes release", 
				lo->info.name, lp->part_num, strerror(rc));
	}

	/* Drop preallocated stripes from degraded slabs */
	rc = purge_prealloc_stripes(lp);
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
		rc = release_prealloc_stripes(lp, rel_count);
		if (rc) {
			LOG(LOG_WARN, "%s[%d]: error %d releasing %d pre-allocated stripes",
				lo->info.name, lp->part_num, rc, rel_count);
		}
	}

	/* Signal threads waiting on stripes */
	if (allocated) 
		pthread_cond_signal(&lp->stripes_wait_cond);
		
	if (log_print_level > 0) {
		f_print_sm(dbg_stream, lp->slabmap, lo->info.chunks, lo->info.slab_stripes);
		f_print_cv(dbg_stream, lp->claimvec);
	}
_ret:
	return rc;
}

/*
 * Layout allocator thread
 */
static void *f_allocator_thread(void *ctx)
{
	F_LAYOUT_t *lo = (F_LAYOUT_t *)ctx;
	F_POOL_t *pool = lo->pool;
	F_LO_PART_t *lp = lo->lp;
	int *rcbuf;
	int ion_cnt, ion_rank, i;
	int rc = 0;

	ASSERT(pool && lo && lp);

	ON_ERROR((MPI_Comm_rank(pool->ionode_comm, &ion_rank)), "MPI_Comm_rank");
	ON_ERROR((MPI_Comm_size(pool->ionode_comm, &ion_cnt)), "MPI_Comm_size");
	rcbuf = alloca(ion_cnt*sizeof(rc));
	ASSERT(rcbuf);
	memset(rcbuf, 0, ion_cnt*sizeof(rc));

	LOG(LOG_INFO, "%s[%d]: starting allocator on %s", lo->info.name, lp->part_num, pool->mynode.hostname);

	rc = layout_partition_init(lp);

	/* Load and process this partition of the slab map and the claim vector */
	if (!rc) rc = read_maps(lp);

	if (!rc) rc = create_lp_dev_matrix(lp);

	/* Check if all layout devices are present and healthy */
	check_layout_devices(lo);

	if (rc) goto _ret;

	if (ion_cnt != lo->part_count) {
		LOG(LOG_WARN, "%s[%d]: allocator on %s started in partial config: %d of %d parts", 
			lo->info.name, lp->part_num, pool->mynode.hostname, ion_cnt, lo->part_count);
		goto _ret;
	}

	/*
	 * Synchronize all allocator threads across all IO-nodes and make sure 
	 * all slab map partitions were successfully loaded
	 */ 
	rcbuf[ion_rank] = rc;
	ON_ERROR(MPI_Allgather(MPI_IN_PLACE, 1, MPI_INT, rcbuf, 1, MPI_INT, pool->ionode_comm), "MPI_Allgather");

	for (i = 0; i < ion_cnt; i++) {
		/* Bring down all allocators if any of them failed */
		LOG(LOG_DBG, "%s[%d]: loaded slab map part %d rc: %d", 
			lo->info.name, lp->part_num, i, rcbuf[i]);
		if (rcbuf[i] !=0) {
			if (!ion_rank) LOG(LOG_ERR, "%s[%d]: error %d loading slab map part %d", 
				lo->info.name, lp->part_num, rcbuf[i], i);
			SetLayoutThreadFailed(lo);
			rc = -1;
		}
	}
	
	/* Load global PDS LFA */
	if (!rc) {
		rc = f_lfa_gget(pool->pds_lfa->global_abd, 0, pool->pds_lfa->global_size);
		if (rc) LOG(LOG_WARN, "%s[%d]: error %d loading global PDS LFA", 
				lo->info.name, lp->part_num, rc);
	}

	/* All is well, signal the parent thread */
	if (!rc) {
		pthread_mutex_lock(&lp->lock_ready);
		lp->ready = 1;
		SetLayoutActive(lo);
		pthread_mutex_unlock(&lp->lock_ready);
		pthread_cond_signal(&lp->cond_ready);
		if (log_print_level > 0) 
			printf("%s[%d]: allocator thread is ready\n", lo->info.name, lp->part_num);
	}

	while (!LayoutQuit(lo) && !rc) {
		struct timespec to, wait;
		
		msec2timespec(&wait, lo->thread_run_intl); /* ms to timespec */
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
			LOG(LOG_DBG3, "%s[%d]: allocator run @%lu", lo->info.name, lp->part_num, to.tv_sec);
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
//		if (i++ > 10) SetLayoutQuit(lo);
	}

_ret:
	ClearLayoutActive(lo);

	/* Release pre-allocated stripes and check the release queue */
	ASSERT(!release_prealloc_stripes(lp, 0));
	ASSERT(!process_releaseq(lp));

	/* Update maps */
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
