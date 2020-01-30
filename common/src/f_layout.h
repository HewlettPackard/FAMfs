/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */

#ifndef F_LAYOUT_H_
#define F_LAYOUT_H_

#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>

#include "famfs_env.h"
#include "f_dict.h"
#include "list.h"


#define DRIVE_MAP_SIZE  BITS_TO_LONGS(F_STRIPE_DISK_COUNT)


typedef uint64_t	f_stripe_t;
typedef uint32_t	f_slab_t;

#define R_STRIPE_SET_MAX	(64*KiB)
struct f_stripe_set {
    uint32_t		count;
    f_stripe_t		*stripes;
};

#define F_LWM_ALLOC_STRIPES	2048	/* Stripe preallocation list low water mark */
#define F_HWM_ALLOC_STRIPES	4096	/* Stripe preallocation list high water mark */
#define F_MAX_ALLOC_STRIPES	10*1024	/* Stripe preallocation max */
#define F_MIN_ALLOC_SLABS	2	/* min # of slabs to allocate across */
#define F_STRIPE_BUCKETS	1024	/* # of stripe preallocation lists */

struct f_slab_usage {
    uint32_t		used;		/* # stripes used (allocated) in slab*/
#if 0
    uint32_t		claimed;	/* # stripes claimed (by r-volume) in slab */
    uint32_t		committed;	/* # stripes committed in slab */
    uint32_t		next;		/* next stripe to allocate in slab */
#endif
};

/* devel stats counters. */
enum fl_stats_types {
    FL_STRIPE_GET_REQ,
    FL_STRIPE_GET,
    FL_STRIPE_GET_W0,
    FL_STRIPE_GET_W25,
    FL_STRIPE_GET_W50,
    FL_STRIPE_GET_W75,
    FL_STRIPE_GET_W100,
    FL_STRIPE_GET_ERR,
    FL_STRIPE_GET_NOSPC_ERR,
    FL_STRIPE_RELEASE_REQ,
    FL_STRIPE_RELEASE_ERR,
    FL_STRIPE_RELEASE_CLAIMDEC,
    FL_SE_ALLOC,
    FL_SE_FREE,
    FL_SB_ALLOC,
    FL_SB_FREE,
    FL_NR_STATS,	/* # of stats counters. Must be last! */
};

/* Pool device index shareable atomics (blob) */
typedef struct f_pdi_sha_ {
    FI_UINT32_t __attribute__ ((aligned(4))) \
			extents_used;
    FI_UINT32_t		failed_extents;
} F_PDI_SHA_t;

typedef struct f_pooldev_index_ {
    uint32_t		pool_index;

    /* The device index in two-dimentional array of pool devices */
    uint16_t		idx_ag;		/* 1st index: AG */
    uint16_t		idx_dev;	/* 2nd index: pool device */

    uint32_t		pl_extents_used;
    F_PDI_SHA_t		*sha;
} F_POOLDEV_INDEX_t;

/* Partition info */
typedef struct f_layout_partition_ {
    pthread_rwlock_t	lock;		/* partition lock */
    struct f_layout_	*layout;	/* layout back pointer */
    uint32_t		part_num;	/* partition number */
    pthread_t		thread;		/* partition (allocation) daemon thread struct */
    int			thread_res;	/* allocator thread exit code */
    pthread_mutex_t	lock_ready;	/* allocator thread ready condition mutex */
    pthread_cond_t	cond_ready;	/* allocator thread condition ready */
    pthread_mutex_t	a_thread_lock;	/* allocator thread wait condition mutex */
    pthread_cond_t	a_thread_cond;	/* allocator thread wait condition */
    int			ready;		/* allocator thread ready flag */

    uint32_t		slab0;		/* first slab in this partition */
    uint32_t		slab_count;	/* total number of slabs in this partition */
    uint64_t		stripe0;	/* first stripe in this partition */
    uint64_t		stripe_count;	/* total number of stripes in this partition */

    /* Slab usage maps */
    struct f_slab_usage *slab_usage;	/* stripe usage in each slab */
    unsigned long	*slab_bmap;	/* Allocated slab bitmap */
    unsigned long	*sync_bmap;	/* Sync-ed slabs bitmap */
    unsigned long	*recovering_bmap; /* Recovering slabs bitmap */
    unsigned long	*error_logged_bmap; /* Sheet error logging bitmap */
    unsigned long	*cv_bmap;	/* Allocated stripes bitmap */
    uint32_t		bmap_size;	/* Bitmap size */
    f_slab_t		sync_count;
//    uint32_t		sync_search;

     /* Stripe allocation */
    struct list_head	alloc_buckets;	/* pre-allocation buckets list */
    atomic_t		bucket_count;	/* number of allocation buckets */
    atomic_t		bucket_count_max; /* max number of allocation buckets - stats */
    atomic_t		prealloced_stripes; /* number of stripes on the prealloc list */
    uint64_t		lwm_stripes;	/* stripe preallocation list low water mark */
    uint64_t		hwm_stripes;	/* stripe preallocation list high water mark */
    uint64_t		max_alloc_stripes; /* preallocated stripes limit */
    uint16_t		min_alloc_slabs; /* min # of slabs to pre-allocate stripes across */
    int			increase_prealloc; /* flag to increase stripe allocation limits */

    /* Stripe release/claim decrement */
    struct list_head	claimdecq;	/* claim decrement queue */
    pthread_rwlock_t	claimdec_lock;	/* claim decrement queue lock */
    pthread_spinlock_t	alloc_lock;	/* stripe allocation lock */
#if 0
    struct list_head	releaseq;	/* stripe release queue */
    pthread_spinlock_t	releaseq_lock;	/* stripe release queue lock */
#endif

    atomic_t	slabmap_version;	/* partition slabmap version */
    atomic_t	allocated_slabs;	/* partition allocated slabs counter */
    atomic_t	degraded_slabs;		/* partition degraded slabs counter */
    atomic_t	missing_dev_slabs;	/* slabs with missing devices counter */
    atomic_t	failed_slabs;		/* partition failed slabs counter */
    atomic_t	allocated_stripes;	/* partition allocated stripes counter */
//    atomic_t	mapped_stripes;		/* partition mapped stripes counter */

    int			alloc_error;	/* last allocation error */

    /* REMOVEME: devel stats counters. */
    atomic_t		stats[FL_NR_STATS];

    struct {
	unsigned long	    flags;	/* layout flags: f_layout_flags */
    }			io;
} F_LO_PART_t;

/* Layout partition specific flags */
enum layout_partition_flags {
    _LP_ACTIVE,		/* Layout active */
    _LP_NOSPC,		/* Layout is out of space */
    _LP_RECOVER,	/* Layout is being recovered */
    _LP_SM_FLUSH,	/* Slabmap needs to be flushed */
    _LP_SPCERR_LOGGED,	/* Layout out of space error logged */
    _LP_RECOVER_QUEUED,	/* A Recovery request is queued */
};
BITOPS(LP, Active, 	f_layout_partition_, _LP_ACTIVE)
BITOPS(LP, NoSpace,	f_layout_partition_, _LP_NOSPC)
BITOPS(LP, Recover,	f_layout_partition_, _LP_RECOVER)
BITOPS(LP, SMFlush,	f_layout_partition_, _LP_SM_FLUSH)
BITOPS(LP, SpcErrLogged, f_layout_partition_, _LP_SPCERR_LOGGED)
BITOPS(LP, RecoverQueued, f_layout_partition_, _LP_RECOVER_QUEUED)

/* Layout info structure: the minimalictic data about the layout and the pool
 * that is read from the configuration file.
 */
typedef struct f_layout_info_ {
    char		*name;		/* layout moniker */
    uint64_t		stripe_count;	/* total number of stripes */
    uint32_t		conf_id;	/* layout ID in configuration file */
    uint32_t		chunk_sz;	/* chunk size in bytes */
    uint32_t		slab_stripes;	/* number of stripes in one slab, stripes_in_slab */
    uint32_t		slab_count;	/* total number of slabs */
    uint32_t		devnum;		/* total number of devices */
    uint32_t		misdevnum;	/* number of missing devices */
    uint16_t		chunks;		/* number of chunks constituting a stripe */
    uint16_t		data_chunks;	/* number of data chunks in stripe */
} F_LAYOUT_INFO_t;

/*
 * Layout structure
 */
typedef struct f_layout_ {
    struct list_head	list;		/* list of layouts */
    uuid_t		uuid;		/* layout UUID */
    pthread_rwlock_t	lock;		/* layout lock */
    F_DICT_t		*dict;		/* layout dictionary */
    pthread_spinlock_t	dict_lock;	/* dictionary lock */
    F_LAYOUT_INFO_t	info;
    struct f_pool_	*pool;		/* reference to parent pool structure */

    long		thread_run_intl; /* layout allocator thread run interval */
//    atomic_t		active_thread_count; /* layout active allocator threads count */
    uint32_t		part_count;	/* layout allocator threads count */
    struct f_layout_partition_	*lp;	/* layout partition structure or NULL */

    struct f_map_	*slabmap;	/* slab map */
    struct f_map_	*claimvec;	/* claim vector map */

    struct {
	unsigned long	    flags;	/* layout flags: f_layout_flags */
    }			io;

    /* Dynamically allocated array of pool device indexes */
    F_POOLDEV_INDEX_t	*devlist;	/* pool device indexes */
    uint32_t		devlist_sz;	/* size of the pool device indexes array */
} F_LAYOUT_t;

enum f_layout_flags {
    _L_ACTIVE,		/* Layout active */
    _L_NOSPC,		/* Layout is out of space */
    _L_RECOVER,		/* Layout is being recovered */
    _L_ABORTRC,		/* Abort layout recovery */
    _L_SPCERR_LOGGED,	/* Layout out of space error logged */
    _L_THREAD_FAILED,	/* Layout allocator thread failed */
    _L_QUIT,		/* Layout exiting */
};
BITOPS(Layout, Active,		f_layout_, _L_ACTIVE)
BITOPS(Layout, NoSpace,		f_layout_, _L_NOSPC)
BITOPS(Layout, Recover,		f_layout_, _L_RECOVER)
BITOPS(Layout, AbortRC,		f_layout_, _L_ABORTRC)
BITOPS(Layout, SpcErrLogged,	f_layout_, _L_SPCERR_LOGGED)
BITOPS(Layout, ThreadFailed,	f_layout_, _L_THREAD_FAILED)
BITOPS(Layout, Quit,		f_layout_, _L_QUIT)


#endif /* F_LAYOUT_H_ */

