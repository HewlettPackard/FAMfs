/*
 * (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor
 *   Boston, MA 02110-1301, USA.
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef F_MAPS_H_
#define F_MAPS_H_

#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>

#include "f_env.h"
#include "f_error.h"
#include "f_ktypes.h"
#include "f_bbitmap.h"
#include "f_dict.h"


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
		    unsigned int    checksum     :  4; /* slab entry CRC-4 checksum */
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
 * stripe by stripe, starting from the beginning of the slab.
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
 * FAM or pool device extent map
 *
 * Extent map size is compile time constant. Nevertheless the map includes the map
 * size intended to be kept persistent with the device label.
 * Each bit stands for the used extent which is mapped to a layout slab map.
 * Actual extent_bmap size in bits is extent_count defined in pool device structure.
 */
typedef struct f_extent_bitmap_ {
    unsigned char __attribute__ ((aligned(8))) \
			bm_size;	/* extent_bmap size, bytes, multiple of 8 */
    unsigned char	_reserved[7];
    unsigned long	extent_bmap[];
} __attribute__((packed)) F_EXTENT_BITMAP_t;

/*
 *  Slab Map entry:
 * [F_SLAB_ENTRY_t 0][F_EXTENT_ENTRY_t 0][F_EXTENT_ENTRY_t 1]...[F_EXTENT_ENTRY_t N]
 */
typedef struct f_slabmap_entry_ {
    F_SLAB_ENTRY_t	slab_rec;
    F_EXTENT_ENTRY_t	extent_rec[0];
} F_SLABMAP_ENTRY_t;
/* Pad to the next even chunk */
#define F_SLABMAP_ENTRY_SZ(chunks)	(sizeof(F_SLAB_ENTRY_t) + \
		     ROUND_UP(chunks, 2)*sizeof(F_EXTENT_ENTRY_t))
/* Slab map must have this data page (BoS) size if shared in memory */
#define F_SLABMAP_BOSL_SZ		(4*KIB)


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
} __attribute__((packed, aligned(8))) F_CLAIM_PACKED_t;

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
} __attribute__((packed, aligned(8))) F_PU_VAL_t;

/* The Dictionary structure for pool device header; it could be mapped
 * to both F_POOL_LABEL_t and F_DICT_t where pdict_ref is the device uuid and
 * dict_ref is pool uuid and the pool label KVs kept in F_POOL_LABEL_t order.
 */
#define F_HDR_KVPAIRS	18		/* KV array size; only 5 are used so far */
typedef struct f_hdr_dict_ {
    uint32_t __attribute__ ((aligned(8))) \
			psize;		/* zero */
    uint32_t		count;		/* key-value pair count, 4..F_HDR_KVPAIRS */
    uint32_t		kv_size;	/* key-value pair array size, F_HDR_KVPAIRS */
    uint32_t		revision;	/* FAMfs software version - FAMFS_VERSION */
    long long		_reserved;	/* zero */
    FVAR_KVPAIR_t	uuid;		/* device UUID, F_KEY_UUID */
    FVAR_KVPAIR_t	pool_uuid;	/* pool UUID, F_KEY_UUID */
    FVAR_KVPAIR_t	kv_pairs[F_HDR_KVPAIRS];
} F_HDR_DICT_t;

/* Pool device label */
/* magic strings */
#define F_LABEL_MAGIC		"FAMFSDEV"
#define F_LABEL_MAGIC_LEN	8
typedef struct f_pool_label_ {
    unsigned char	magic[F_LABEL_MAGIC_LEN];	/* pool device label magic */
    union {
	F_HDR_DICT_t	header;		/* 504 bytes: mandatory pool attributes dictionary */
	struct {			/* shortcuts for mandatory pool attributes */
	FVAR_KVPAIR_t	_reserved1;
	FVAR_KVPAIR_t	uuid;		/* this device UUID, F_KEY_PDEV_UUID */
	FVAR_KVPAIR_t	pool_uuid;	/* pool UUID, F_KEY_UUID */
	FVAR_KVPAIR_t	pool_name;	/* pool name, F_KEY_NAME */
	FVAR_KVPAIR_t	ext_size;	/* first data extent, FP_KEY_EXT_START */
	FVAR_KVPAIR_t	_reserved2;
	FVAR_KVPAIR_t	ext_count;	/* full number of data extents, FP_KEY_EXT_COUNT */
	};
    } __attribute__ ((packed));
} F_POOL_LABEL_t;

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
#define LO_TO_SM_ID(layout_id)	((layout_id) *2 )	/* Layout ID to Slab map ID */
#define LO_TO_CV_ID(layout_id)	((layout_id) *2 + 1)	/* Layout ID to Claim vector */
#define LO_MAP_TO_ID(map_id)	(map_id/2)		/* Map ID to layout ID */

/* Calculate the slab map entry CRC-4 checksum */
static inline unsigned char f_crc4_sm_fast(F_SLAB_ENTRY_t *se)
{
    /* Look in transposed table */
    return crc4_table_tp[ f_crc4_sm_chk(se) ];
}

#if 0
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
#endif

/* FAMFS configutation access; defined in f_maps.c */
struct f_pool_;
struct f_layout_;
struct f_layout_info_;
struct unifycr_cfg_t_;
struct f_pooldev_index_;

int f_layout_parse_name(struct f_layout_info_ *info); /* moniker parser */
int f_set_layouts_info(struct unifycr_cfg_t_ *cfg);
int f_free_layouts_info(void);
struct f_pool_dev_ *f_find_pdev(unsigned int index);
struct f_pool_dev_ *f_pdi_to_pdev(struct f_pool_ *p, struct f_pooldev_index_ *pdi);
struct f_pool_ *f_get_pool(void);
struct f_layout_ *f_get_layout(int layout_id);
struct f_layout_ *f_get_layout_by_name(const char *moniker);
struct f_layout_info_ *f_get_layout_info(int layout_id);
//int f_host_is_ionode(const char *hostname);
//int f_host_is_mds(const char *hostname);
void f_print_layouts(void);
int f_get_lo_stripe_sizes(struct f_pool_ *p, size_t **stripe_sz_per_lo);

/*
 * DB-independent persistent KV store interface
 */
/* create_persistent_map() function type: create/open KV store global index */
typedef int (*F_CREATE_PERSISTENT_MAP_fn)(F_MAP_INFO_t *i, int intl, char *name);
/* ps_bget() function type: BGET_NEXT */
typedef ssize_t (*F_PS_BGET_fn)(unsigned long *buf, int map_id, size_t size,
    uint64_t *keys, int op);
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
#define F_PS_GET_EQ	0	/* BGET Op: GET_EQ */
#define F_PS_GET_NEXT	1	/* BGET Op: GET_NEXT */

/* Map API: persistent KV store interface */
void f_set_meta_iface(F_META_IFACE_t *iface);
int f_create_persistent_sm(int layout_id, int intl, F_MAP_INFO_t *info_p);
int f_create_persistent_cv(int layout_id, int intl, F_MAP_INFO_t *info_p);
ssize_t f_db_bget(unsigned long *buf, int map_id, uint64_t *keys, size_t size,
    uint64_t *off_p, int op);
int f_db_bput(unsigned long *buf, int map_id, void **keys, size_t size,
    size_t value_len);
int f_db_bdel(int map_id, void **keys, size_t size);

/* TODO: Move me to debug.h */
/* If not defined yet, use verbosity level from pool struct */
#ifndef DEBUG_LVL
#define DEBUG_LVL(lvl, fmt, ...) DEBUG_LVL_(f_get_pool()->verbose, lvl, fmt, ## __VA_ARGS__)
#endif


/* Validate structure's size and/or alignment */
    _Static_assert( sizeof(F_SLAB_ENTRY_t) == 16,	"F_SLAB_ENTRY_t");
    _Static_assert( sizeof(F_EXTENT_ENTRY_t) == 8,	"F_EXTENT_ENTRY_t");
    _Static_assert( sizeof(FVAR_KVPAIR_t) == 24,	"FVAR_KVPAIR_t");

#endif /* F_MAPS_H_ */
