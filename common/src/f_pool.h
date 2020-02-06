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
#include <mpi.h>

#include "famfs_env.h"
#include "famfs_bitops.h"
#include "f_dict.h"
#include "list.h"


/* defined in famfs_lf_connect.h */
struct fam_map_; /* TODO: Remove me! */
struct f_zfm_;
struct f_ionode_info_;
struct lf_info_;
struct lf_dom_;
struct n_params_;


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
    uuid_t		uuid;		/* group's uuid */
    uint16_t		*gpdi;		/* array of group's pool device indexes, pool_index */
    uint32_t		gid;		/* group's ID */
    uint32_t		pdis;		/* size of gpdi */
    uint16_t		ionode_idx;	/* IO node index in ionodes, matched by topology */
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

    F_PDEV_SHA_t	*sha;		/* pool device shareable atomics counters */
} F_POOL_DEV_t;
/* pool_index special value: not an index, i.e. this device array element is empty */
#define F_PDI_NONE	(( __typeof__ (((F_POOL_DEV_t*)0)->pool_index)) \
			 ((1ULL << 8*sizeof(((F_POOL_DEV_t*)0)->pool_index)) - 1))

/* Pool info */
typedef struct f_pool_info_ {
    uint64_t		extent_sz;	/* pool extent size in bytes */
    uint64_t		data_offset;	/* data starts at this offset on pool devices */
    size_t		size_def;	/* default device size, bytes */
    uint64_t		pkey_def;	/* default FAM device protection key */
    uint32_t		layouts_count;	/* number of layouts in pool */
    uint32_t		dev_count;	/* number of pool devices: active and missing */
    uint32_t		missing_count;	/* number of missing pool devices */
    uint32_t		pdev_max_idx;	/* the attribute array size: max used device index */

			/* pool devlist lookup helper arrays that have index in devlist */
    uint16_t		*pdev_indexes;	/* all pool devices, array of 'dev_count' size */
    uint16_t		*media_ids;	/* indexed by media_id, 0..pdev_max_idx */
} F_POOL_INFO_t;

typedef struct f_mynode_ {
    char		*hostname;	/* this node's hostname */
    struct lf_dom_	*domain;	/* libfabric domain which is open on this node */
    struct lf_dom_	*emul_domain;	/* libfabric domain for FAM emulation or NULL */
    F_POOL_DEV_t	*emul_devlist;	/* array of FAM emulated devices or NULL */
    uint32_t		emul_devs;	/* number of emulated FAMs; size of emul_devlist */
    uint32_t		ionode_id;	/* for IO node ONLY: index in ionodes array */
    struct {
	unsigned long	    flags;	/* f_mynode_flags */
    }			io;
} F_MYNODE_t;
/* Flag specs for f_mynode_ */
enum f_mynode_flags {
    _NODE_IS_IONODE,	/* This is IO node */
    _NODE_MDS,		/* MD server is running on this IO node */
    _NODE_FCE_HLPR,	/* Force Helper threads [on this IO node] */
};
BITOPS(Node, IsIOnode,	  f_mynode_, _NODE_IS_IONODE)
BITOPS(Node, HasMDS,	  f_mynode_, _NODE_MDS)
BITOPS(Node, ForceHelper, f_mynode_, _NODE_FCE_HLPR)

typedef struct f_pool_ {
    uuid_t		uuid;		/* pool uuid */
    pthread_rwlock_t	lock;		/* pool lock */
    F_DICT_t		*dict;		/* pool dictionary */
    pthread_spinlock_t	dict_lock;	/* dictionary lock */
    F_POOL_INFO_t	info;		/* front-most pool attributes */
    struct list_head	layouts;	/* pool layouts list */
    struct lf_info_	*lf_info;	/* libfabric info */
    struct n_params_	*lfs_params;	/* legacy N_PARAMS_t */
    F_MYNODE_t		mynode;		/* structure that represents this node */
    MPI_Comm		ionode_comm;	/* MPI communicator for IO nodes */
//    MPI_Comm		helper_comm;	/* MPI communicator for Helpers */
    int			zero_ion_rank;	/* rank in COMM_WORLD of zero rank in ionode_comm */
    int			verbose;	/* debug flag */
//    uint32_t	nparts;		/* layout partition number estimate */
    uint32_t		pool_ags;	/* allocation group array size; also this is
					a size of 1st dimention of pool devices array */
    uint32_t		ag_devs;	/* size of the pool device array, 2nd dimension */
    uint32_t		pool_devs;	/* size of the pool device array, total */
    uint32_t		ionode_count;	/* number of IO nodes */
    F_AG_t		*ags;		/* allocation group array */
    struct f_pool_dev_	*devlist;	/* two-dimentional array of pool devices */
    struct f_ionode_info_ *ionodes;	/* array of IO node info of .ionode_count size */
    struct fam_map_	*ionode_fams;	/* FAM map: IO nodes to FAMs */
    char		**ionodelist;	/* reference to ionode hostnames */
    struct {
	unsigned long	    flags;	/* f_pool_flags */
    }			io;
//    pthread_t		*fpoold;	/* pool background thread */
//    pthread_spinlock_t	rpoold_lock;	/* rpoold start/stop lock */
} F_POOL_t;

/* Flag specs for f_pool */
enum f_pool_flags {
    _POOL_BG_ACTIVE,	/* Background task is active. */
    _POOL_FAM_EMUL,	/* FAM device emulation enabled on IO nodes */
};
BITOPS(Pool, BGActive,	f_pool_, _POOL_BG_ACTIVE)
BITOPS(Pool, FAMEmul,	f_pool_, _POOL_FAM_EMUL)

#endif /* F_POOL_H_ */

