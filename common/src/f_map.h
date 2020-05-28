/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */

#ifndef F_MAP_H_
#define F_MAP_H_

#include <sys/types.h>
#include <inttypes.h>
#include <pthread.h>

#include "famfs_global.h"
#include "famfs_maps.h"
#include "list.h"

#include <urcu-qsbr.h>
//#include <urcu-call-rcu.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter" /* Matt.7.1 */
#include <urcu/rcuja.h>
#pragma GCC diagnostic pop
#define F_JA_MAX_KEY64	(UINT64_MAX-1)

//#define DEBUG_MAP	/* dbg_printf */


/*
 * Maps are persistent and kept in distributed KV store.
 * Map in memory is a collection of blocks of slabs (BoS) where
 * each "slab" could represent one (or two or four) FAMfs slabs,
 * i.e. the number of map entries for consecutive stripes which belong to
 * particular slab(s).
 * The map is loaded from KV store by bunches of KV pairs so each pair makes
 * a persistent unit.
 * A persistent unit (PU) is exactly one key-value pair. KV value consists of
 * 2^^PU_FACTOR map entries so the entry number shifted right by PU_FACTOR
 * provides a key (uint64_t) for the KV pair which contains this entry.
 *
 * The BoS has a "loaded" flag for KV read and the "dirty" bitmap per PU
 * for flush. The keys of BoS' PUs run consecutivly.
 * If PU does not exist in KV store, the map loads zeros to BoS memory.
 * If all BoS' PUs do not exist in the store, the BoS entry would not created
 * on the map load in the map's Judy sparse array. If not loaded, the entry
 * could be added at any time by the first bosl_get_p() call with cleared
 * "loaded" flag of BoS.
 * When flushed, KVs get updated in the store for each "dirty" PU for all BoSes.
 * Note that KV could be created if missing from the store.
 */

/*
 * Map is a collection of BoSes in memory and PUs in the KV store.
 * The map could be partitioned or not. Slab map is an example of solid map.
 * Claim vector is a partitioned map.
 * The entry in a partitioned map has two enumerations: global and local.
 * Local entry numbers run continiously in whole partition.
 * Global entries are interleaved evenly amoung map partitions, so global entry
 * number is unique number (uint64_t).
 * The map could be logically segmented by slabs. The number of entries in a slab
 * should be a power of two (1, 2 and so on).
 * For example, the claim vector (CV) map has a fixed number of entries (stripes)
 * per slab. The slab map (SM) has exactly one entry per slab.
 * Map ID is a non-negative integer number:
 *	layout_id * 2		- for Slab map, see LO_TO_SM_ID(layout_id)
 *	layout_id * 2 + 1	- for Claim vector, see LO_TO_CV_ID
 * where layout_id - is layout index in configurator, starting with zero.
 * Use LO_MAP_TO_ID macro to convert map ID to layout_id.
 */

/*
 * Map constants:
 * PU_FACTOR - the shift factor to convert entry number to a key of the
 * persistent unit (PU).
 * Default PU_FACTOR is eight which means the KV has 2^8 = 256 entries.
 * The minimum PU_FACTOR is F_MAP_KEY_FACTOR_MIN (8) for bitmaps and
 * zero for structured maps.
 * PU_COUNT - theumber of map entries in PU, 1 << PU_FACTOR.
 * BOS_PU_COUNT - block of slabs (BoS) size in PUs, (1..F_MAP_MAX_BOS_PUS)
 */
#define F_MAP_KEY_FACTOR_MIN	8
#define F_MAP_MAX_BOS_PUS	512

/*
 * Map entry type.
 * BITMAP - one- or bifold bitmap; entry size is one or two bits.
 * STRUCTURED - a structure, aligned to 8 bytes, of arbitrary size (in bytes).
 */

/* Map can store the conventional bitmaps, bifold bitmaps or structures.
   Check .entry_sz in map geometry to find the entry size, in bits for bitmaps or
   bytes for the structured map. */
typedef enum {
    F_MAPTYPE_BITMAP = 0,
    F_MAPTYPE_STRUCTURED,
} F_MAPTYPE_t;
#define f_map_is_structured(map_p)	(map_p->type == F_MAPTYPE_STRUCTURED)
#define f_map_is_bbitmap(map_p)		(map_p->type == F_MAPTYPE_BITMAP && \
					 map_p->geometry.entry_sz == 2)
/*
 * Locking
 */
typedef enum {
    F_MAPLOCKING_DEFAULT = 0,	/* RCU locking only on BoS search */
    F_MAPLOCKING_BOSL,		/* pthread_rwlock protected BoS access */
    F_MAPLOCKING_END,
} F_MAPLOCKING_t;

/*
 * Iterators.
 * Iterator provides the next entry under given condition.
 * new_iter(condition) - return the new iterator over certain map values.
 * seek_iter(iterator, entry) - unconditionally (re)set the iterator
 * to 'entry' position and ensure BoS is created, so get ready for setting entries.
 * The iterator must be freed by free_iter(iterator).
 *
 * The following abstract functions make use of iterators:
 * for_each(iterator) - iterate all map entries with given condition;
 * find_next(iterator) - return iterator for the next entry under condition or NULL;
 * get_weight(iterator[, size]) - return the number of iterations within 'size' keys
 *
 * Conditions.
 * The condition type is a poiner to:
 * If map type is Bi-fold BITMAPS - a pattern set for "true" condition (int).
 * If the tyoe is STRUCTURED - provide an entry evaluation function (see below).
 */

/*
 * Virtual map entry value functions - only for STRUCTURED maps:
 * F_MAP_EVAL_SE_fn - evaluate the entry value as a boolean;
 * F_MAP_SET_SE_fn - set the entry value in the cloned map.
 */
typedef int (*F_MAP_EVAL_SE_fn)(void *arg, const F_PU_VAL_t *entry);
typedef void (*F_MAP_SET_SE_fn)(void *arg, const F_PU_VAL_t *entry);
/*
 * The virtual function may receive one arbitrary argument.
 * The map API client could pass some data to the function that
 * would determine the entry value. For example, for a slab map 'entry'
 * *arg is the extent number 'n' in map entry: *entry.ee[n]
 * Note: By default iterator allocates sizeof(long) bytes for *arg,
 * if more data is needed, please re-alloc iterator.vf_arg
 */

/* Judy sparse array */
typedef struct cds_ja F_JUDY_t;

typedef struct {
    unsigned int		entry_sz;	/* map entry size, bits or bytes */
    unsigned int		pu_factor;	/* number of entries per persistent unit */
    unsigned int		intl_factor;	/* PU interleave factor >= pu_factor */
    unsigned int		bosl_pu_count;	/* number of persistent units in BoS */
} F_MAP_GEO_t;

/* F_MAP */
typedef struct f_map_ {
//    pthread_mutex_t		pu_lock;	/* persistent KV store access lock */
    size_t			bosl_sz;	/* BoS data size, bytes */
    uint64_t			nr_bosl;	/* number of allocated BoSses */
    F_JUDY_t			*bosses;	/* Judy sparse array of BoSses */
    pthread_spinlock_t		bosl_lock;	/* BoS access lock */
    unsigned int		bosl_entries;	/* BoS entry count */
    F_MAPTYPE_t			type;		/* BITMAP or STRUCTURED */
    int				id;		/* map id */
    int				reg_id;		/* ID that this map is registered with KV store */
    F_MAP_GEO_t			geometry;	/* map geometry */
    unsigned int		part;		/* partition number */
    unsigned int		parts;		/* number of partitions */
    union {
	unsigned int		_flags;
	struct {
	    unsigned int	locking:2;	/* locking level, 0: default */
	    unsigned int	loaded:1;	/* 1: loaded from persistent storage */
	    unsigned int	own_part:1;	/* 1: only local entries in partitioned
						   map, all from partition 'part' */
	    unsigned int	ronly:1;	/* 1: read-only flag: there isn't any
						   partition on this node */
	    unsigned int	shm:2;		/* memory model(F_MAPMEM_t): private/shared */
	    unsigned int	true0:1;	/* don't assume zeros in non-existing KVs (and BoSSes); set dirty bit for every KV on load */
	};
    };
    /* Shared map only */
    struct f_map_sb_		*shm_sb;	/* shared map superblock */
} F_MAP_t;

#define f_map_is_partitioned(map_p)	(map_p->parts > 1U)
#define f_map_has_globals(map_p)	(map_p->own_part == 0U)
#define f_map_is_ro(map_p)		(map_p->ronly == 1U) /* read-only map on Client */
#define f_map_has_true_zeros(map_p)	(map_p->true0 == 1U)


/*
 * Block of slabs (BoS)
 */
#define F_BOSL_DIRTY_MAX	(F_MAP_MAX_BOS_PUS/(8*sizeof(unsigned long))) /* 4 */
/* Judy node */
typedef struct f_bosl_ {
    struct cds_ja_node		node;
    struct rcu_head		head;		/* RCU delayed reclaim */
    uint64_t			entry0;		/* number of the first entry in BoS */
    unsigned long		*page;		/* data page with map entries;
						shared map data (f_shmap_data_) */
    F_MAP_t			*map;		/* backreference to map */
    pthread_rwlock_t		rwlock;		/* protect iterators on BoS deletion */
    pthread_spinlock_t		dirty_lock;	/* dirty bitmap lock */
    unsigned long		dirty[F_BOSL_DIRTY_MAX]; /* dirty bitmap */
    union {
	uint32_t		_flags;
	struct {
	    unsigned int	shm:2;		/* map memory model */
	    //unsigned int	loaded:1;	/* 1: loaded from persistent storage */
	};
    };
    atomic_t			claimed;	/* atomic count of being used by iterators */
} F_BOSL_t;
/* current size of dirty[] - the number of PU in BoS */
#define F_BOSL_DIRTY_SZ(m)	(BITS_TO_LONGS(m->geometry.bosl_pu_count)*sizeof(long))


/*
 * Map in shared memory
 */

/*
 * Map shm flag: kepp map in the process' private (default) or shared memory.
 * SHMEM mode supports single writer, multiple readers.
 * Allocate F_MAP_t, F_BOSL_t and BoS data pages in shared memory.
 */
typedef enum {
    F_MAPMEM_PRIVATE = 0,	/* Map structures belongs to a process */
    F_MAPMEM_SHARED_WR,		/* Owner of shared map structures */
    F_MAPMEM_SHARED_RD,		/* Reader of shared map: should not parse any pointer */
    F_MAPMEM_SHARED_S,		/* Supermap that describes the collection of SHMEM regions */
} F_MAPMEM_t;
#define f_map_in_shmem(m) ((m)->shm != F_MAPMEM_PRIVATE)
#define f_shmap_owner(m) ((m)->shm == F_MAPMEM_SHARED_WR)
#define f_shmap_reader(m) ((m)->shm == F_MAPMEM_SHARED_RD)

/*
 * Supermap has one or more super BoS. Each super BoS (SBoS) contains the shared
 * map's BoSses as own PUs, so its PU size is equal to the shared map BoS page size
 * and the number of PUs is limited to F_MAP_MAX_BOS_PUS (512).
 * Supermap describes the collection of shared memory regions,
 * one per SBoS.
 * Supermap can only grow and total_bosl keeps record of total number
 * of allocated BoSses i.e. total_bosl followes map->nr_bosl.
 * That means it gets incremented on every new BoS allocation in shared map.
 * On reader side f_map_get_bosl() will check total_bosl if no BoS found and,
 * if total_bosl has changed, this function will add new Bos[ses] to map Judy array.
 */

/*
 * Superblock of shared map - private structure of the map writer or
 * reader process. This structure is intended for single thread use.
 */
typedef struct f_map_sb_ {
    struct f_shmap_sb_	*shmap_sb;	/* shared map superblock in SHMEM */
    struct list_head	shmap_data;	/* list of SBoSses */
    F_MAP_t		*super_map;	/* supermap */
    int			id;		/* map id (if registered) or zero */
    int			shm;		/* shared map 'shm' memory model */
    int			shm_id;		/* IPC shared memory segment ID */
    char		*name;		/* SHMEM SB file name */
} F_MAP_SB_t;

/* Superblock of shared map - in shared memory.
 * The writer is the owner of this structure, protected by R/W lock.
 * Readers should hold the lock while reading SB and
 * should never dereference super_bosl->bosses.
 */
#define F_SHMAP_NAME_PREFIX	"shm_s"
#define F_SHMAP_NAME_LEN	ROUND_UP(FVAR_MONIKER_MAX+8, 8)
typedef struct f_shmap_sb_ {
    char		name[F_SHMAP_NAME_LEN];	/* SHMEM SB file name */
    pthread_rwlock_t	sb_rwlock;	/* SB mutual exclusion */
//    uint64_t		total_bosl;	/* total number of BoSses in supermap */
    F_MAP_t		super_map;	/* collection of super BoSses */
} __attribute__((aligned(PAGE_SIZE))) F_SHMAP_SB_t;

#define F_SHMAP_DATA_NAME	"shm_d"
typedef struct f_shmap_data_ {
    char		name[F_SHMAP_NAME_LEN];	/* SHMEM data file name */
    F_BOSL_t		super_bosl;	/* super BoS */
    uint64_t __attribute__((aligned(PAGE_SIZE)))
			e0[F_MAP_MAX_BOS_PUS];
    unsigned long	pages[];		/* BoS data pages */
} __attribute__((aligned(PAGE_SIZE))) F_SHMAP_DATA_t;
#define F_SHMAP_SZ(bosl_sz)		((bosl_sz)*F_MAP_MAX_BOS_PUS)
#define F_SHMAP_DATA_SZ(bosl_sz)	(sizeof(F_SHMAP_DATA_t)+F_SHMAP_SZ(bosl_sz))

/* SBoS list entry */
typedef struct f_map_sboss_ {
    struct list_head	node;		/* SBoS node in shmap_data list */
    F_SHMAP_DATA_t	*data;		/* SBoS data page in SHMEM */
    char		*dname;		/* SHMEM data file name */
    size_t		size;
    int			shm_id;		/* IPC shared memory segment ID */
} F_MAP_SBOSS_t;


/*
 * Iterators
 */

/*
 * The iterator needs a condition to evaluate every map entry as a true or false.
 * There are two types of condition in iterators: one for the structured maps and
 * one for the bitmaps.
 * Also the condition is internally used by the dirty PU iterator.
 * Because the iterator created with one and only condition, the union is used.
 * For bifold bitmaps (bbitmaps) 'pset' is a BBIT pattern which can stand for
 * the combination(s) of bifold values. For conventional bitmaps 'pset' is treated
 * as a boolean and must be set to true (F_BIT_CONDITION).
 * Zero condition is a special case. With "no condition" the iterator would loop
 * over all entries.
 */

/* Iterator's condition - evaluate an entry value as a boolean */
typedef union {
    F_MAP_EVAL_SE_fn		vf_get;		/* structured entry evaluation function */
    uint64_t			pset;		/* BBIT pattern set: [0..BB_PAT_MASK] */
    uint64_t			partition;	/* dirty PU Iterator partiton */
} F_COND_t;
/* All maps: */
#define F_NO_CONDITION		((F_COND_t)0LU)	/* Iterator will iterate ALL entries */
/* Simple (one-bit) bitmaps only: */
#define B_PAT0			1LU		/* Iterate over clear bits in bitmaps */
#define B_PAT1			2LU		/* Iterate over set bits in bitmaps */
#define F_BIT_CONDITION		((F_COND_t)B_PAT1) /* Iterate over set bits in bitmaps */

/*
 * Map clone function needs an entry setter. That is similiar to F_COND_t condition,
 * but instead of evaluating the map entry the setter "sets" the cloned entry.
 * Note: there is no entry clear function. If a map entry is evaluated as false,
 * the cloned entry would be filled with zeros.
 */

/* Map clone entry setter - set the entry value which has been evaluated as true */
typedef union {
    F_MAP_SET_SE_fn		vf_set;		/* structured entry set function */
    BBIT_VALUE_t		one_val;	/* BBIT value */
} F_SETTER_t;

typedef struct f_iter_ {
    F_MAP_t			*map;		/* back pointer to iterator's map */
    uint64_t			entry;		/* current position */
    F_BOSL_t			*bosl;		/* current BoS or NULL */
    F_COND_t			cond;		/* condition (or zero, i.e. all entries) */
    unsigned long		*word_p;	/* current entry pointer in BoS->page */
    union {
	uint32_t		_flags;
	struct {
	    unsigned int	at_end:1;	/* 1: depleted */
	};
    };
    /* Only on stuctured map */
    void			*vf_arg;	/* optional vf_get/vf_set argument */
} F_ITER_t;

/* Array of keys - this is an argument to f_map_update() */
typedef struct f_map_keyset_ {
    uint32_t		_count;
    uint32_t		key_sz;
    union {
	void		*keys;
	uint32_t	*keys_32;
	uint64_t	*keys_64;
    };
} __attribute__ ((aligned(8))) F_MAP_KEYSET_t;


/*
 * Map API
 */

/* Create map in memory */
F_MAP_t *f_map_init(F_MAPTYPE_t type, int entry_sz, size_t bosl_sz, F_MAPLOCKING_t locking);
/* Set map is partitioned; chose only 'own' partition (local) entries or whole (global) */
int f_map_init_prt(F_MAP_t *map, int parts, int node, int part_0, int global);
/* Make persistent map as read-only, so flush would return w/o putting/deleting KVs */
static inline void f_map_set_ro(F_MAP_t *map, int ro) { map->ronly = (unsigned)ro; }
/* Free all map structures */
void f_map_exit(F_MAP_t *map);
/* Copy in-memory map entries to a new map with given evaluator and setter */
int f_map_reshape(F_MAP_t **new, F_SETTER_t setter, F_MAP_t *origin, F_COND_t cond);
/* Helper: create a bitmap and clone BBIT or structured map to it */
F_MAP_t *f_map_reduce(size_t hint_bosl_sz, F_MAP_t *orig, F_COND_t cond, int arg);
/* Print map description: KV size, in-memory size and so on */
void f_map_fprint_desc(FILE *f, F_MAP_t *map);
/* Share (WR) or attach to the shared (RO) registered map in SHMEM */
int f_map_shm_attach(F_MAP_t *map, F_MAPMEM_t rw);

/*
 * Persistent map backend: the KV store
 */
/* Attach map to persistent KV store */
int f_map_register(F_MAP_t *map, int layout_id);
/* Map load callback function - it's called once per PU */
typedef void (*F_MAP_LOAD_CB_fn)(uint64_t e, void *arg, const F_PU_VAL_t *pu);
/* Load all KVs for [one partition of] the registered map; call back on PU */
int f_map_load_cb(F_MAP_t *map, F_MAP_LOAD_CB_fn cb, void *cb_arg);
/* Load all KVs for [one partition of] the registered map */
static inline int f_map_load(F_MAP_t *map) { return f_map_load_cb(map, NULL, NULL); }
/* Put all 'dirty' PUs of all BoSses to KV store; delete zero PUs. */
int f_map_flush(F_MAP_t *map);
/* Update (load from KV store) only map entries given in the stripe list */
int f_map_update(F_MAP_t *map, F_MAP_KEYSET_t *set);
/* Mark KV dirty */
void f_map_mark_dirty(F_MAP_t *map, uint64_t entry);

/* Note: Please use this function from common library to read the layout configuration
 * for a map: F_LAYOUT_INFO_t *f_get_layout_info(int layout_id);
 */


/*
 * Low-level data access.
 * Note: RCU read-side lock should not be held when calling these functions,
 * however, QSBR threads need to be online and rcu_quiescent_state() must be called
 * some time later.
 */
unsigned long *f_map_get_p(F_MAP_t *map, uint64_t entry); /* returns NULL if no BoS */
unsigned long *f_map_new_p(F_MAP_t *map, uint64_t entry); /* if no entry, create it */
F_BOSL_t *f_map_get_bosl(F_MAP_t *map, uint64_t entry); /* returns NULL if no BoS */
F_BOSL_t *f_map_new_bosl(F_MAP_t *map, uint64_t entry); /* if no BoS, create it */
int f_map_put_bosl(F_BOSL_t *bosl);
int f_map_delete_bosl(F_MAP_t *map, F_BOSL_t *bosl); /* remove all BoS entries from online map */
void f_map_mark_dirty_bosl(F_BOSL_t *bosl, uint64_t entry); /* mark KV dirty in BoS PU bitmap */
uint64_t f_map_max_bosl(F_MAP_t *map); /* max BoS number */

/* Check if the entry belongs to this BoS */
static inline int f_map_entry_in_bosl(F_BOSL_t *bosl, uint64_t entry)
{
	return (bosl && IN_RANGE(entry, bosl->entry0,
				 bosl->entry0 + bosl->map->bosl_entries - 1));
}


/*
 * Map iterators
 */

/* Create new iterator with condition and optional arg for structured map */
F_ITER_t *f_map_new_iter(F_MAP_t *map, F_COND_t cond, int arg);

/* Release iterator */
void f_map_free_iter(F_ITER_t *iter);

/* Iterate to the next entry which matches the iterator's condition or return NULL */
F_ITER_t *f_map_next(F_ITER_t *iter);

/* Create an iterator with condition, find the first entry or return NULL */
static inline F_ITER_t *f_map_get_iter(F_MAP_t *map, F_COND_t cond, int arg)
{
	F_ITER_t *ret, *iter = f_map_new_iter(map, cond, arg);

	if (!(ret = f_map_next(iter)))
		f_map_free_iter(iter); /* no map entry matches the condition */
	return ret;
}

/* Check if iterator's condition is true */
bool f_map_check_iter(const F_ITER_t *iter);

/* Check if iterator's condition is true would it point at entry 'e' */
bool f_map_probe_iter_at(const F_ITER_t *it, uint64_t entry, void *value_p);

/* Reset the iterator unconditionally.
 * Also ensure that BoS is created for 'entry'.
 * seek_iter() may return NULL if out-of-memory.
 * Hint: Create a new iterator or call this function on existing iterator
 * before creating a new entry in the map or calling f_map_weight().
 */
F_ITER_t *f_map_seek_iter(F_ITER_t *iter, uint64_t entry);


/* Iterator loops - iterate entries that match iterator's condition */

/* for_each(iterator) - iterate map entries from the current position */
#define for_each_iter(iter)					\
	for (; !f_map_iter_depleted(iter); (void)f_map_next(iter))

/* for_each_iter_from() - loop over matching map entries starting at 'start' */
#define for_each_iter_from(iter, start)				\
	for (iter = f_map_seek_iter(iter, (uint64_t)start);	\
	     !f_map_iter_depleted(iter) &&			\
		(f_map_check_iter(iter) || f_map_next(iter));	\
	     (void)f_map_next(iter))

/* Return the number of entries which matches the iterator's condition
 within given size; pass F_MAP_WHOLE for weighting the whole map. */
uint64_t f_map_weight(const F_ITER_t *iter, size_t size);
#define F_MAP_WHOLE (~(size_t)0)

/* Is Iterator at end? */
static inline bool f_map_iter_depleted(const F_ITER_t *iter) {
	return !iter || (iter->at_end == 1);
}

/* Create new iterator w/o condition; for loop over all entries. */
static inline F_ITER_t *f_map_new_iter_all(F_MAP_t *map) {
	return f_map_new_iter(map, F_NO_CONDITION, 0);
}

/*
 * Low-level data access to BoSSes with iterator.
 * Note: RCU read-side lock should not be held when calling these functions,
 * however, QSBR threads need to be online and rcu_quiescent_state() must be called
 * some time later.
 */
F_ITER_t *f_map_next_bosl(F_ITER_t *it); /* advance to the next BoS */
#define for_each_bosl(iter)						\
	for (; !f_map_iter_depleted(iter); (void)f_map_next_bosl(iter))


/*
 * Local and global entry numbers are the same for non-partitioned map.
 * For partition, the local entry ID (uint64_t) is calculated based on PU
 * interleaving which starts at the "partition zero" node and runs through
 * all nodes.
 * So we need to know: P - the partition number, N -the number of partitions and
 * P0 - the zero partition number in order to map local entry to global one and
 * vice versa.
 * Local entry number:
 *	Entry = [ Global/(N*INTL) ]*INTL + Global%INTL		(1)
 * where Global is a global entry number and
 *       INTL is an interleave entry count calculated as
 *	INTL = (1 << (INTL_FACTOR)
 * Note that equation (1) is true on node I (of 0..N) only if
 * [ Global/INTL ] == P = ((I + P0) % N)			(2)
 * is true, i.e. Entry belongs to the partition P.
 * Also note that INTL_FACTOR must be more or equal to PU_FACTOR.
 * Abovementioned restriction implies that only one partition of the partitioned
 * map is available on a node.
 *
 * Here is the reverse equation for the global entry number:
 *   Global = (Entry % INTL) + ([ Entry/INTL ]*N + P)*INTL	(3)
 * Map API provides functions to calculate Global from Entry ID and backward.
*/

/* Convert local entry to global number according to partitioned map's geometry */
static inline uint64_t f_map_prt_to_global(F_MAP_t *map, uint64_t entry)
{
	uint64_t intl = 1UL << map->geometry.intl_factor;

	if (!f_map_is_partitioned(map))
		return entry;
	return (entry % intl + ((entry >> map->geometry.intl_factor) *
				map->parts + map->part)*intl);
}

/* Convert global number to local entry */
static inline uint64_t f_map_prt_to_local(F_MAP_t *map, uint64_t global)
{
	uint64_t intl = 1UL << map->geometry.intl_factor;

	if (!f_map_is_partitioned(map))
		return global;
	return (((global >> map->geometry.intl_factor)/map->parts)*intl +
		global % intl);
}

/* Does this global entry belong to this partition? */
static inline int f_map_prt_has_global(F_MAP_t *map, uint64_t global,
    unsigned int part)
{
	return ((global >> map->geometry.intl_factor) % map->parts
		  == part);
}

/* Does this global entry belong to this map? */
static inline int f_map_prt_my_global(F_MAP_t *map, uint64_t global)
{
	return f_map_prt_has_global(map, global, map->part);
}

/* Check if the continuous unit number belongs to partition 'part'.
 * If not, advance the unit up to the next slice in partition.
 * pu - continious persistent unit number (must be global!);
 * factor - unit's interleave factor,
 * parts - number of map partitions.
 */
#define f_map_pu_round_up(pu, factor, parts, part)			\
	({ unsigned int u = (pu) >> (factor);				\
	   unsigned int il = u % (parts);				\
	   unsigned int p = (unsigned)(part);				\
	   if (il != p)							\
		pu = (u + ((il>p)? (parts):0UL) + p - il) << (factor);	\
	   (pu); })


/*
 * Value size calculation
 */

/* Return the offset of entry 'n' from zero entry, in bytes */
static inline size_t f_map_value_off(F_MAP_t *map, uint64_t n)
{
	size_t entry_sz = map->geometry.entry_sz;

	if (f_map_is_structured(map))
		return n*entry_sz;
	else
		return n*entry_sz/8;
}

/* Calculate the offset for map entry 'e' in units of type(*p) */
#define f_map_values_p_off(map, e, p)				\
    ({	size_t entry_sz = map->geometry.entry_sz;		\
      e*entry_sz/(sizeof(*p)*(f_map_is_structured(map)? 1:8)); })

/* Calculate the required memory for 'n' entries in units of type(*p) */
#define f_map_values_sz(map, n, p)				\
    ({	size_t entry_sz = map->geometry.entry_sz;		\
      (DIV_CEIL(n * entry_sz,					\
		(sizeof(*p)*(f_map_is_structured(map)? 1:8))); })

/* Calculate PU memory size (bytes) */
#define f_map_pu_size(map)					\
    (f_map_value_off(map, 1UL << map->geometry.pu_factor))

/* Calculate the memory size for 'n' PUs in units of type(*p) */
#define f_map_pu_p_sz(map, n, p)				\
    (DIV_CEIL(							\
	f_map_value_off(map,					\
		  (unsigned long)n << map->geometry.pu_factor),	\
	sizeof(*p)))

/*
 * DEBUG
 */
#ifdef DEBUG_MAP
#define dbg_printf(fmt, args...)				\
	fprintf(stderr, "[debug map %d %s()@%s:%u] " fmt,	\
		getpid(),__func__,__FILE__,__LINE__, ## args)

#else
#define dbg_printf(fmt, args...)				\
do {								\
    /* do nothing but check printf format */			\
    if (0)							\
	fprintf(stderr, "[debug map %d %s()@%s:%u] " fmt,	\
		getpid(),__func__,__FILE__,__LINE__, ## args);	\
} while (0)
#endif

/* Validate structure's size and/or alignment */
    _Static_assert( TYPE_ALINGMENT(F_SHMAP_DATA_t) == PAGE_SIZE,
		   "F_SHMAP_DATA_t alignment");
    _Static_assert( offsetof(struct f_shmap_data_, pages[0]) % PAGE_SIZE == 0,
		   "F_SHMAP_DATA_t pages[] alignment");

#endif /* F_MAP_H_ */
