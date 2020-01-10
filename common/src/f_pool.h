/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */

#ifndef F_POOL_H_
#define F_POOL_H_

#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>

#include "famfs_env.h"
#include "famfs_bitops.h"
#include "f_dict.h"
#include "list.h"


/* libfabric atomic types */
typedef uint32_t	FI_UINT32_t;
typedef uint64_t	FI_UINT64_t;

/* Pool device shareable atomics (blob) */
typedef struct f_pdev_sha_ {
    FI_UINT64_t __attribute__ ((aligned(8))) \
			read_errors;
    FI_UINT64_t		write_errors;
    FI_UINT64_t		extents_used;
    FI_UINT64_t		failed_extents;
    struct {				/* Using struct to be able to BITOPS() */
	FI_UINT64_t	flags;		/* pool device flags, */
    } io;
    FI_UINT64_t		bmap_size;	/* extent_bmap size, bytes, multiple of 8 */
    FI_UINT64_t		extent_bmap[];
} F_PDEV_SHA_t;
/* struct f_pdev_sha_ actual size */
#define F_PDEV_SZ(bmap_size) (sizeof(F_PDEV_SHA_t) + bmap_size*sizeof(FI_UINT64_t))
/* extent_bmap size (bytes) required for the given extent count */
#define F_EXT_BM_SIZE(ext) DIV_UP(ext, 8*sizeof(FI_UINT64_t))

/* Flag specs for f_pdev_sha_ */
enum pool_dev_flags {
    _DEV_FAILED,	/* device failed */
    _DEV_DISABLED,	/* device disabled (for example, being replaced) */
    _DEV_MISSING,	/* device is missing from the pool */
};

BITOPS(Dev, Failed,     f_pdev_sha_, _DEV_FAILED)
BITOPS(Dev, Disabled,   f_pdev_sha_, _DEV_DISABLED)
BITOPS(Dev, Missing,    f_pdev_sha_, _DEV_MISSING)

/* Allocation group of devices */
typedef struct f_ag_ {
    uuid_t	uuid;	/* group's uuid */
    char	*geo;	/* geolocation, reference */
    uint32_t	gid;	/* group's ID */
    uint32_t	pdis;	/* size of gpdi */
    uint16_t	*gpdi;	/* array of group's pool device indexes, pool_index */
} F_AG_t;

typedef struct f_pool_dev_ {
    struct f_pool_	*pool;		/* pool structure, reference */
    struct f_dev_	*dev;		/* FAMfs device: libfabric endpoint or block device */
    pthread_rwlock_t	rwlock;		/* pool device lock */
    uuid_t		uuid;		/* pool device uuid */
    size_t		size;		/* pool device size in bytes */
    size_t		extent_sz;	/* extent size in bytes */
    uint32_t		extent_start;	/* first data extent on this device */
    uint32_t		extent_count;	/* number of extents in this device */
    uint16_t		pool_index;	/* persistent device's index for Slab map;
					same as device.id in configuration file */

    /* The device index in two-dimentional array of pool devices */
    uint16_t		idx_ag;		/* 1st index: AG */
    uint16_t		idx_dev;	/* 2nd index: pool device */

    F_PDEV_SHA_t	sha;		/* pool device shareable atomics counters */
} F_POOL_DEV_t;
/* pool_index special value: not an index, i.e. this device array element is empty */
#define F_PDI_NONE	(( __typeof__ (((F_POOL_DEV_t*)0)->pool_index)) \
			 ((1ULL << 8*sizeof(((F_POOL_DEV_t*)0)->pool_index)) - 1))

/* Pool info */
typedef struct f_pool_info_ {
    uint64_t		extent_sz;	/* pool extent size in bytes */
    uint64_t		extent_start;	/* data starts at this offset on pool devices */
    size_t		size_def;	/* default device size, bytes */
    uint64_t		pkey_def;	/* default FAM device protection key */
    uint32_t		layouts_count;	/* number of layouts in pool */
    uint32_t		dev_count;	/* number of active pool devices */
    uint32_t		missing_count;	/* number of missing pool devices */
    uint32_t		pdev_max_idx;	/* the attribute array size: max used device index */
} F_POOL_INFO_t;

typedef struct f_pool_ {
    uuid_t		uuid;		/* pool uuid */
    pthread_rwlock_t	lock;		/* pool lock */
    F_DICT_t		*dict;		/* pool dictionary */
    pthread_spinlock_t	dict_lock;	/* dictionary lock */
    F_POOL_INFO_t	info;		/* front-most pool attributes */
    struct list_head	layouts;	/* pool layouts list */
//    uint32_t	nparts;		/* layout partition number estimate */
    uint32_t		pool_ags;	/* allocation group array size; also this is
					a size of 1st dimention of pool devices array */
    uint32_t		ag_devs;	/* size of the pool device array, 2nd dimension */
    uint32_t		pool_devs;	/* size of the pool device array, total */
    F_AG_t		*ags;		/* allocation group array */
    struct f_pool_dev_	*devlist;	/* two-dimentional array of pool devices */
    struct {
	unsigned long	    flags;	/* f_pool_flags */
    }			io;
//    pthread_t		*fpoold;	/* pool background thread */
//    pthread_spinlock_t	rpoold_lock;	/* rpoold start/stop lock */
} F_POOL_t;

/* Flag specs for f_pool */
enum f_pool_flags {
    _POOL_BG_ACTIVE,	/* Background task is active. */
    _POOL_FAM_EMUL,	/* FAM device emulation with fabric attached memory on IO nodes */
};
BITOPS(Pool, BGActive,  f_pool_, _POOL_BG_ACTIVE)
BITOPS(Pool, FAMEmul,  f_pool_, _POOL_FAM_EMUL)

#endif /* F_POOL_H_ */

