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
#include "famfs_maps.h"

struct f_dev_t; /* defined in common/src/famfs_lf_connect.h */

struct f_pool {
    pthread_rwlock_t	lock;		/* pool lock */
    F_DICT_t		*dict;		/* pool dictionary */
    pthread_spinlock_t	dict_lock;	/* dictionary lock */
    F_POOL_INFO_t	info;		/* front-most pool attributes */
    uint32_t		pool_ags;	/* allocation group array size */
    uint32_t		pool_devs;	/* size of the pool device array, 2nd dimension */
    F_AG_t		*ags;		/* allocation group array */
    struct f_pool_dev_	*devlist;	/* two-dimentional array of pool devices */
    struct {
	unsigned long	flags;		/* f_pool_flags */
    }
//    pthread_t		*fpoold;	/* pool background thread */
//    pthread_spinlock_t	rpoold_lock;	/* rpoold start/stop lock */
};

/* Flag specs for f_pool */
enum f_pool_flags {
    F_POOL_BG_ACTIVE,	/* Background task is active. */
    F_POOL_FAM_EMUL,	/* FAM device emulation with fabric attached memory on IO nodes */
};
BITOPS(Pool, BGActive,  f_pool, F_POOL_BG_ACTIVE)
BITOPS(Pool, FAMEmul,  f_pool, F_POOL_FAM_EMUL)

/* Allocation group of devices */
typedef struct f_ag_ {
    uuid_t	uuid;	/* group's uuid */
    uint32_t	gid;	/* group's ID */
    uint32_t	pdis;	/* size of gpdi */
    uint16_t	*gpdi;	/* array of group's pool device indexes */
} F_AG_t;

typedef struct f_pool_dev_ {
    struct f_pool	*pool;		/* pool struct pointer */
    struct f_dev_t	*dev;		/* FAMfs device: libfabric endpoint or block device */
    pthread_rwlock_t	rwlock;		/* pool device lock */
    uuid_t		uuid;		/* pool device uuid */
    size_t		size;		/* pool device size in bytes */
    size_t		extent_sz;	/* extent size in bytes */
    uint32_t		extent_start;	/* first data extent on this device */
    uint32_t		extent_count;	/* number of extents in this device */
    uint16_t		pool_index;	/* device's index in the pool device array */
    F_PDEV_SHA_t	sha;		/* pool device shareable atomics counters */
} F_POOL_DEV_t;
/* pool_index special value: not an index, i.e. this device array element is empty */
#define F_PDI_NONE	((1U << ilog2(8*sizeof(((F_POOL_DEV_t*)0)->pool_index))) - 1)

#endif F_POOL_H_

