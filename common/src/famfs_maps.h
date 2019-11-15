/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAMFS_MAPS_H_
#define FAMFS_MAPS_H_

#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>

#include "famfs_env.h"
#include "famfs_bbitmap.h"
#include "famfs_configurator.h"


/*
 * Slab Map (SM)
 *
 * [F_SLAB_ENTRY_t 0][F_EXTENT_ENTRY_t 0][F_EXTENT_ENTRY_t 1]...[F_EXTENT_ENTRY_t N]
 * [F_SLAB_ENTRY_t 1]...
 */

/* Slab entry (media/extent pointers) */

/*  Slab entry describes a single slab mapping. Slab consists of one or more extents.
 * For each extent there are extent map entries that follow the slab map entry.
 * Slab is "mapped" if some extents are mapped. Write operations can only be directed
 * to mapped extents. When slab is mapped it is logically placed into layout space
 * by assigning its base stripe number, i.e. "stripe_0".
 *
 * If the slab layout supports redundancy and at least one of the slab extents
 * has failed, the slab it declared "degraded". When the redundancy is restored,
 * by successful recovery attempt of the failed extent, the degraded flag is reset.
 *
 * If more extents have been declared as failed than the layout redundancy can support,
 * then the slab map entry is declared as "failed". It is not possible to access or
 * recover data on a failed slab and it must be remapped or deallocated.
 *
 * When a recovery operation is in progress on an extent within current slab map entry,
 * the slab is in "recovery" mode. When all stripes have been recovered, the recovery
 * flag is reset.
 */
typedef struct f_slab_entry_ {
    // --------- Slab Map Entry Whole  (128 bit) --------------------------
    union {
	struct /* SME */ {
	    // ------- Slab Map Entry Stripe 0 (64 bit)   -----------------
	    uint64_t    stripe_0;        /* stripe number of the first stripe of this slab */
	    // ------- Slab Map Entry properties (64 bit) -----------------
	    union {
		struct /* PROP */ {
		    union {
			// ----- Recovery progress and status -------------
			struct {
			    unsigned int recovered : 31; /* recoverd stripe counter */
			    unsigned int  recovery :  1; /* slab is recovering */
			};
			uint32_t    rc;
		    };
		    // ------------- 32-bit boundary -----------------------
		    unsigned int    mapped       :  1; /* slab is mapped */
                    unsigned int    failed       :  1; /* slab has failed */
                    unsigned int    degraded     :  1; /* slab is degraded (dev failed) */
                    unsigned int    _reserved    :  9; /* reserved */
                    unsigned int    _reserved2   : 16; /* reserved for extents' CRC16 */
		    unsigned int    checksum     :  4; /* slab entry checksum */
		} /* PROP */;
		struct {
		    uint64_t        _pv;       /* 64-bit value for cmpxchg */
		} prop;
	    };
	}; /* SME */
	uint128_t    _v128;	/* SME as 128 bit word */
	uint64_t     _h[2];	/* SME as two 64 bit words */
    };
// -------- Extent Map Entry[0] starts here --------------------------------
} __attribute__((packed)) F_SLAB_ENTRY_t;

/* Extent map entry */

/* There may be one or more extents within a slab. Extent must be "mapped" to
 * a physical media before a write operation could be directed to it.
 * If the extent is mapped, "media_id" is the index in media_guid table.
 *
 * If a write operation directed to a mapped extent completes with error, the extent
 * must be declared "failed".
 * Extents could be also forced into failed state, for example when an entire media
 * is declared as failed.
 *
 * If the slab layout supports recovery then it may be possible to recover failed extent
 * stripe by stripe, starting from the beginning of the sheet.
 * When all slab's stripes have recovered, the failed status is reset.
 */
typedef struct f_extent_entry_ {
    union {
	struct {
	    unsigned int    extent     : 32;	/* extent number */
//	      unsigned int    disk_index : 12; /* disk device index in stripe label */
	    unsigned int    media_id   : 16;	/* media id (index) in media_guid table */
	    unsigned int    mapped     :  1;	/* this extent is mapped (i.e. valid) */
	    unsigned int    failed     :  1;	/* this extent has failed */
	    unsigned int    _reserved  : 10;
	    unsigned int    checksum   :  4;
	};
	uint64_t    _v64;			/* 64-bit value for cmpxchg */
    };
} __attribute__((packed)) F_EXTENT_ENTRY_t;


/*
 * Claim Vector (CV)
 *
 * [Claim 0][Claim 1]...[Claim N]
 *
 * Partitioning: the claim vector splits first to the number partitions which is equal
 * to the number of IO nodes.
 *
 * Distributed DB key-value pair (KV): each CV partition is represented by set of KVs.
 * The key is a 64-bit unsigned int, a physical stripe number of the first CV entry
 * in the value, divided by the number of map entries per KV value.
 * The number of keys calculated based on the fixed value length which defaults to
 * the whole CV partition or could be power of two times less. This value length
 * should be at least 32 bytes (128 entries).
 * If a key is missing, the value shall be considered of all zeros.
 */
typedef struct f_claim_packed__ {
    union {
	/* Claim vector entry: pre-allocated, allocated, laminated or free */
	struct {
	    unsigned char	_cve_0: 2;	/* the first claim vector entry */
	    unsigned char	_cve_1: 2;
	    unsigned char	_cve_2: 2;
	    unsigned char	_cve_3: 2;
	};
	unsigned long		_v64;		/* 64-bit value for bifold-bit api */
	unsigned int		_hv[2];
	unsigned short		_hhv[4];	/* for 16-bit cmpxchg */
	unsigned char		_hhhv[8];	/* for 8-bit cmpxchg */
    };
} __attribute__((packed)) F_CLAIM_PACKED_t;

#define F_CV_BYTE_N	BBITS_PER_BYTE	/* number of CV entries per byte */

/* Claim vector entry value type: a tetral digit (of type int) */
typedef BBIT_VALUE_t F_CVE_VALUE_t;
/* ... and it's possible values: */
#define CVE_FREE	BBIT_ZERO	/* this stripe is not in use */
#define CVE_PREALLOC	BBIT_01		/* pre-allocated stripe */
#define CVE_ALLOCATED	BBIT_10		/* allocated stripe */
#define CVE_LAMINATED	BBIT_11		/* laminated stripe */
/* Claim vector entry patterns (could be OR-ed) */
#define CV_FREE_P	BB_PAT_ZERO	/* this stripe is not in use */
#define CV_PREALLOC_P	BB_PAT01	/* pre-allocated stripe */
#define CV_ALLOCATED_P	BB_PAT10	/* allocated stripe */
#define CV_LAMINATED_P	BB_PAT11	/* laminated stripe */


/*
 * Map entries are persistent as key-value (KV) pair's values in DB.
 * Key (uint64_t) is a stripe number for CV and slab number for SM.
 *
 */
typedef uint64_t F_PU_KEY_t;
typedef struct f_pu_val_ {
    union {
	struct {
	    F_SLAB_ENTRY_t	se;
	    F_EXTENT_ENTRY_t	ee;
	};
	F_CLAIM_PACKED_t	cv_packed;
    };
} __attribute__((packed)) F_PU_VAL_t;


/* List of stripes */
typedef struct f_stripe_head_ {
    struct f_stripe_head_	*next;
    /* bunch of 'count' stripes started at 'stripe0' */
    uint64_t			stripe0;
    uint64_t			count;
} F_STRIPE_HEAD_t;

/* Add a stripe to head of single-linked stripe list from free list or allocate it. */
static inline void f_stripe_add(uint64_t stripe0, uint64_t count,
    F_STRIPE_HEAD_t **s_p, F_STRIPE_HEAD_t **f_p)
{
	F_STRIPE_HEAD_t *f = *f_p, *s = *s_p;

	if (f) {
		*f_p = f->next;
		f->next = NULL;
	} else {
		f = (F_STRIPE_HEAD_t *) calloc(sizeof(*f), 1);
	}
	f->stripe0 = stripe0;
	f->count = count;
	if (s)
		f->next = s;
	*s_p = f;
}

/* f_stripe_move
 * Move a stripe from head of stripe list to head of free stripes list.
 * Return the number of stripes or zero if stripe list is empty.
 */
static inline uint64_t f_stripe_move(F_STRIPE_HEAD_t **s_p, F_STRIPE_HEAD_t **f_p)
{
	F_STRIPE_HEAD_t *f = *f_p, *s = *s_p;

	if (s == NULL)
		return 0;
	*s_p = s->next;
	s->next = f;
	*f_p = s;
	return s->count;
}

/* Free the single-linked stripe list */
static inline void f_stripe_destroy(F_STRIPE_HEAD_t *h)
{
	F_STRIPE_HEAD_t *s;

	while ((s = h)) {
		h = s->next;
		free(s);
	}
}

/* Map info */
typedef struct f_map_info_ {
	union {
	    uint64_t		info;
	    struct {
		int		map_id;		/* map id */
		unsigned int	ro:1;		/* read-only map */
		unsigned int	_r:31;
	    } __attribute__((packed));
	};
} F_MAP_INFO_t;

/* Pool info */
typedef struct f_pool_info_ {
	uint64_t	extent_sz;	/* pool extent size in bytes */
	uint64_t	extent0_start;	/* data starts at this offset on pool devices */
	uint32_t	layouts_count;	/* number of layouts in pool */
	uint32_t	dev_count;	/* number of active pool devices */
} F_POOL_INFO_t;

/* Layout info structure: the minimalictic data about the layout and the pool
 * that is read from the configuration file.
 */
typedef struct f_layout_info_ {
	/* About pool */
	F_POOL_INFO_t	*pool_info;
	/* About this layout */
	char		*name;		/* layout moniker */
	uint32_t	conf_id;	/* Layout ID in configuration file */
	uint32_t	chunk_sz;	/* chunk size in bytes */
	uint32_t	devnum;		/* total number of devices */
	uint32_t	slab_stripes;	/* number of stripes in one slab */
	uint16_t	chunks;		/* number of chunks constituting a stripe */
	uint16_t	data_chunks;	/* number of data chunks in stripe */
} F_LAYOUT_INFO_t;

#define LO_TO_SM_ID(layout_id)	((layout_id) *2 )	/* Layout ID to Slab map ID */
#define LO_TO_CV_ID(layout_id)	((layout_id) *2 + 1)	/* Layout ID to Claim vector */
#define LO_MAP_TO_ID(map_id)	(map_id/2)		/* Map ID to layout ID */

/* Layout configutation functions; defined in famfs_maps.c */
int f_layout_parse_name(struct f_layout_info_ *info); /* moniker parser */
int f_set_layout_info(unifycr_cfg_t *cfg);
F_LAYOUT_INFO_t *f_get_layout_info(int layout_id);
void f_free_layout_info(void);

/*
 * DB-independent persistent KV store interface
 */
/* create_persistent_map() function type: create/open KV store global index */
typedef int (*F_CREATE_PERSISTENT_MAP_fn)(F_MAP_INFO_t *i, int intl, char *name);
/* ps_bget() function type: BGET_NEXT */
typedef ssize_t (*F_PS_BGET_fn)(unsigned long *buf, int map_id, size_t size,
    uint64_t *keys);
/* ps_bput() function type: */
typedef int (*F_PS_BPUT_fn)(unsigned long *buf, int map_id, size_t size,
    void **keys, size_t value_len);
/* ps_bdel() function type: */
typedef int (*F_PS_BDEL_fn)(int map_id, size_t size, void **keys);

typedef struct f_meta_iface_ {
	F_CREATE_PERSISTENT_MAP_fn	create_map_fn;
	F_PS_BGET_fn			bget_fn;
	F_PS_BPUT_fn			bput_fn;
	F_PS_BDEL_fn			bdel_fn;
} F_META_IFACE_t;

/* Map API: persistent KV store interface */
void f_set_meta_iface(F_META_IFACE_t *iface);
int f_create_persistent_sm(int layout_id, int intl, F_MAP_INFO_t *info_p);
int f_create_persistent_cv(int layout_id, int intl, F_MAP_INFO_t *info_p);
ssize_t f_db_bget(unsigned long *buf, int map_id, uint64_t *keys, size_t size,
    uint64_t *off_p);
int f_db_bput(unsigned long *buf, int map_id, void **keys, size_t size,
    size_t value_len);
int f_db_bdel(int map_id, void **keys, size_t size);

#endif /* FAMFS_MAPS_H_ */
