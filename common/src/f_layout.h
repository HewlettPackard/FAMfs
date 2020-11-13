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

#include "f_env.h"
#include "f_ktypes.h"
#include "f_bitops.h"
#include "f_lfa.h"
#include "f_map.h"
#include "f_dict.h"
#include "f_wpool.h"
#include "list.h"


#define F_DEVMAP_SIZE  BITS_TO_LONGS(F_STRIPE_DEV_COUNT)


struct n_stripe_;

typedef uint64_t	f_stripe_t;
typedef uint32_t	f_slab_t;

#define R_STRIPE_SET_MAX	(64*KiB)
struct f_stripe_set {
    uint32_t		count;
    f_stripe_t		*stripes;
};

struct f_slab_set {
    uint32_t		count;
    uint32_t		reserved;
    f_slab_t		*slabs;
} __attribute__ ((aligned(8)));

typedef union {
    F_MAP_KEYSET_t;
    struct f_slab_set;
} F_MAP_KEYSET_u;

/* Stripe entry type */
enum req_type {
	F_ALLREQ,
	F_ALLOC,
	F_RELEASE,
	F_BULK_RELEASE,
};

struct f_stripe_bucket {
	struct			list_head list;		/* buckets list head */
	struct			list_head head;		/* stripes list head */
	atomic_t		count;			/* stripe count */
	unsigned long		devmap[F_DEVMAP_SIZE];	/* device allocation bitmap */
	struct f_layout_partition_ *lp;			/* Layout pointer */
};

struct f_stripe_entry {
	struct	list_head list;				/* list head */
	
	f_stripe_t		stripe;			/* stripe # */
	f_slab_t		slab;			/* stripe slab # */
	enum			req_type type;		/* Stripe entry type */
	struct f_layout_partition_ *lp;			/* Layout partition pointer */
};

#define F_LWM_ALLOC_STRIPES	256	/* Stripe preallocation list low water mark */
//#define F_LWM_ALLOC_STRIPES	2048	/* Stripe preallocation list low water mark */
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

/*
 * Parameters that govern which sheet allocation type is used.
 * If device utilization variance exceeds F_DEV_UTIL_VAR_HWM switch to
 * the utilization based allocation, otherwise use equal distribution
 * allocation (by index)
 */
#define F_DEV_UTIL_VAR_LWM      10
#define F_DEV_UTIL_VAR_HWM      25

typedef enum {
        F_BY_UTIL = 0,
        F_BY_IDX,
} F_SLAB_ALLOC_TYPE_t;

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
    FL_STRIPE_COMMIT_REQ,
    FL_STRIPE_COMMIT_ERR,
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
    struct {				/* Using struct to be able to BITOPS() */
	FI_UINT64_t	flags;		/* pool device index flags, */
    } io;
} F_PDI_SHA_t;

/* Flag specs for f_pdi_sha_ */
enum pdi_flags {
    _PDI_FAILED,	/* device failed */
    _PDI_DISABLED,	/* device disabled (for example, being replaced) */
    _PDI_MISSING,	/* device is missing from the pool */
};
BITOPS(PDI, Failed,     f_pdi_sha_, _PDI_FAILED)
BITOPS(PDI, Disabled,   f_pdi_sha_, _PDI_DISABLED)
BITOPS(PDI, Missing,    f_pdi_sha_, _PDI_MISSING)


typedef struct f_pooldev_index_ {
    uint32_t		pool_index;

    /* The device index in two-dimentional array of pool devices */
    uint16_t		idx_ag;		/* 1st index: AG */
    uint16_t		idx_dev;	/* 2nd index: pool device */

    uint32_t		prt_extents_used;/* per layout partition usage */
    F_PDI_SHA_t		*sha;
} F_POOLDEV_INDEX_t;

/* 2-dimensional device allocation matrix */
struct f_pdi_matrix_;
struct f_slabmap_entry_;
struct f_layout_partition_;
typedef int (*mx_init_fn) (struct f_pdi_matrix_ *mx);
typedef F_POOLDEV_INDEX_t * (*mx_lookup_fn) (struct f_pdi_matrix_ *mx, size_t row, size_t col);
typedef F_POOLDEV_INDEX_t * (*mx_lookup_by_id_fn) (struct f_pdi_matrix_ *mx, size_t row, unsigned int id);
typedef void (*mx_sort_fn) (struct f_pdi_matrix_ *mx);
typedef void (*mx_resort_fn) (struct f_pdi_matrix_ *mx, size_t row);
typedef int (*mx_gen_devlist_fn) (struct f_pdi_matrix_ *mx, 
	F_POOLDEV_INDEX_t *devlist, unsigned int *size);
typedef int (*mx_gen_devlist_for_replace_fn) (struct f_pdi_matrix_ *mx, 
	F_POOLDEV_INDEX_t *devlist, unsigned int *size, struct f_slabmap_entry_ *sme);
typedef void (*mx_release_fn) (struct f_pdi_matrix_ *mx);
typedef void (*mx_print_fn) (struct f_pdi_matrix_ *mx);

typedef struct f_pdi_matrix_ {
    struct f_layout_partition_		*lp;
    F_POOLDEV_INDEX_t			*addr;
    size_t				rows;
    size_t				cols;
    /* Matrix operations */
    mx_init_fn				init;
    mx_lookup_fn			lookup;
    mx_lookup_by_id_fn			lookup_by_id;
    mx_sort_fn				sort;
    mx_resort_fn			resort;
    mx_gen_devlist_fn			gen_devlist;
    mx_gen_devlist_for_replace_fn	gen_devlist_for_replace;
    mx_release_fn			release;
    mx_print_fn				print;
} F_PDI_MATRIX_t;

/* Partition info */
typedef struct f_layout_partition_ {
    pthread_rwlock_t	lock;		/* partition lock */
    struct f_layout_	*layout;	/* layout back pointer */
    uint32_t		part_num;	/* partition number */
    pthread_t		thread;		/* partition (allocation) daemon thread struct */
    int			thread_res;	/* allocator thread exit code */
    pthread_mutex_t	lock_ready;	/* allocator thread ready condition mutex */
    pthread_cond_t	cond_ready;	/* allocator thread condition ready */
    int			ready;		/* allocator thread ready flag */
    pthread_mutex_t	a_thread_lock;	/* allocator thread wait condition mutex */
    pthread_cond_t	a_thread_cond;	/* allocator thread wait condition */
    pthread_mutex_t	stripes_wait_lock;/* stripes wait condition mutex */
    pthread_cond_t	stripes_wait_cond;/* stripes wait condition */

    pthread_t		r_thread;	/* partition recovery thread struct */
    pthread_mutex_t	r_thread_lock;	/* recovery thread wait condition mutex */
    pthread_cond_t	r_thread_cond;	/* recovery thread wait condition */
    int			r_thread_res;	/* recovery thread exit code */
    pthread_mutex_t	r_done_lock;	/* recovery done wait condition mutex */
    pthread_cond_t	r_done_cond;	/* recovery done wait condition */

    void		*rctx;		/* recovery context */

    uint32_t		slab0;		/* first slab in this partition */
    uint32_t		slab_count;	/* total number of slabs in this partition */
    uint64_t		stripe0;	/* first stripe in this partition */
    uint64_t		stripe_count;	/* total number of stripes in this partition */

    /* Partition local maps */
    struct f_map_	*slabmap;	/* partition slab map */
    struct f_map_	*claimvec;	/* partition claim vector map */

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
    struct list_head	releaseq;	/* stripe release queue */
    pthread_spinlock_t	releaseq_lock;	/* stripe release queue lock */

    atomic_t	slabmap_version;	/* partition slabmap version */
    atomic_t	allocated_slabs;	/* partition allocated slabs counter */
    atomic_t	degraded_slabs;		/* partition degraded slabs counter */
    atomic_t	missing_dev_slabs;	/* slabs with missing devices counter */
    atomic_t	failed_slabs;		/* partition failed slabs counter */
    atomic_t	allocated_stripes;	/* partition allocated stripes counter */
//    atomic_t	mapped_stripes;		/* partition mapped stripes counter */

    int			alloc_error;	/* last allocation error */

    F_PDI_MATRIX_t	*dmx; 		/* device allocation matrix (by AG/dev in AG) */

    int			w_thread_cnt;	/* worker threads count */
    F_WPOOL_t 		*wpool;		/* worker threads pool for background tasks */

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
    _LP_CV_FLUSH,	/* Claim vector needs to be flushed */
    _LP_SPCERR_LOGGED,	/* Layout out of space error logged */
    _LP_RECOVER_QUEUED,	/* A Recovery request is queued */
};
BITOPS(LP, Active, 	f_layout_partition_, _LP_ACTIVE)
BITOPS(LP, NoSpace,	f_layout_partition_, _LP_NOSPC)
BITOPS(LP, Recover,	f_layout_partition_, _LP_RECOVER)
BITOPS(LP, SMFlush,	f_layout_partition_, _LP_SM_FLUSH)
BITOPS(LP, CVFlush,	f_layout_partition_, _LP_CV_FLUSH)
BITOPS(LP, SpcErrLogged, f_layout_partition_, _LP_SPCERR_LOGGED)
BITOPS(LP, RecoverQueued, f_layout_partition_, _LP_RECOVER_QUEUED)

/* Layout info structure: the minimalictic data about the layout and the pool
 * that is read from the configuration file.
 */
typedef struct f_layout_info_ {
    char		*name;		/* layout moniker */
    uint64_t		stripe_count;	/* total number of stripes */
    size_t		stripe_sz;	/* stripe data size, bytes */
    uint32_t		conf_id;	/* layout ID in configuration file */
    uint32_t		chunk_sz;	/* chunk size in bytes */
    uint32_t		slab_stripes;	/* number of stripes in one slab, stripes_in_slab */
    uint32_t		slab_count;	/* total number of slabs */
    uint32_t		devnum;		/* total number of devices */
    uint32_t		misdevnum;	/* number of missing devices */
    uint32_t		cv_intl_factor;	/* claim vector interleave factor */
    uint16_t		chunks;		/* number of chunks constituting a stripe */
    uint16_t		data_chunks;	/* number of data chunks in stripe */

    int			sq_depth;	/* preallocated stripes queue size per CN */
    int			sq_lwm;		/* low water mark for preallocated queue */

    uint32_t		pdi_max_idx;	/* the higest media_id used in the layout */
    uint16_t		*pdi_by_media;	/* devlist indexed by media_id, size: pdi_max_idx+1 */
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
    struct f_map_	*file_ids;	/* open file IDs bitmap */

    long		thread_run_intl; /* layout allocator thread run interval */
//    atomic_t		active_thread_count; /* layout active allocator threads count */
    uint32_t		part_count;	/* layout allocator threads count */
    struct f_layout_partition_	*lp;	/* layout partition structure or NULL */

    struct f_map_	*slabmap;	/* global slab map */
    struct f_map_	*claimvec;	/* global claim vector map */

    F_SLAB_ALLOC_TYPE_t	slab_alloc_type;/* layout slab allocation type */

    /* REMOVEME: devel stats counters. */
    atomic_t 	stats[FL_NR_STATS];

    struct {
	unsigned long	    flags;	/* layout flags: f_layout_flags */
    }			io;

    /* Dynamically allocated array of pool device indexes */
    F_POOLDEV_INDEX_t	*devlist;	/* pool device indexes */
    uint32_t		devlist_sz;	/* size of the pool device indexes array */

    /* I/O client only */
    struct n_stripe_	*fam_stripe;	/* FAM stripe attributes */
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


F_POOLDEV_INDEX_t *f_find_pdi_by_media_id(F_LAYOUT_t *lo, unsigned int media_id);
void f_print_sm(FILE *f, struct f_map_ *sm, uint16_t chunks, uint32_t slab_stripes);
void f_print_cv(FILE *f, struct f_map_ *cv);
int f_slabmap_update(struct f_map_ *sm, F_MAP_KEYSET_u *set);

#endif /* F_LAYOUT_H_ */

