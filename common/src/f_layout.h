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

/* Pool device index shareable atomics (blob) */
typedef struct f_pdi_sha_ {
    FI_UINT32_t __attribute__ ((aligned(4))) \
			extents_used;
    FI_UINT32_t		failed_extents;
} F_PDI_SHA_t;

typedef struct f_pooldev_index_ {
    uint32_t		pool_index;
    uint32_t		pl_extents_used;
    F_PDI_SHA_t		*sha;
} F_POOLDEV_INDEX_t;

/* Partition info */
typedef struct f_layout_partition_ {
    uint32_t		part_num;	/* partition number */
    pthread_t		*thread;	/* partition (allocation) daemon thread struct */

    uint32_t		slab0;		/* first slab in this partition */
    uint32_t		slab_count;	/* total number of slabs in this partition */
    uint64_t		stripe0;	/* first stripe in this partition */
    uint64_t		stripe_count;	/* total number of stripes in this partition */

#if 0
    atomic_t	allocated_sheets;	/* partition allocated slabs counter */
    atomic_t	degraded_sheets;	/* partition degraded slabs counter */
    atomic_t	missing_dev_sheets;	/* slabs with missing devices counter */
    atomic_t	failed_sheets;		/* partition failed sheets counter */
    atomic_t	allocated_stripes;	/* partition allocated stripes counter */
    atomic_t	mapped_stripes;		/* partition mapped stripes counter */
#endif
    int			alloc_error;	/* last allocation error */

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
    uint32_t		slab_stripes;	/* number of stripes in one slab, stripes_in_sheet */
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
    atomic_t		active_thread_count; /* layout active allocator threads count */
    uint32_t		thread_count;	/* layout allocator threads count */
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
};
BITOPS(Layout, Active,		f_layout_, _L_ACTIVE)
BITOPS(Layout, NoSpace,		f_layout_, _L_NOSPC)
BITOPS(Layout, Recover,		f_layout_, _L_RECOVER)
BITOPS(Layout, AbortRC,		f_layout_, _L_ABORTRC)
BITOPS(Layout, SpcErrLogged,	f_layout_, _L_SPCERR_LOGGED)
BITOPS(Layout, ThreadFailed,	f_layout_, _L_THREAD_FAILED)


#endif /* F_LAYOUT_H_ */

