/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */

#ifndef F_MAP_H_
#define F_MAP_H_

#include <sys/types.h>
#include <inttypes.h>
//#include <stdint.h>
#include <pthread.h>

#include "famfs_global.h"
//#include "famfs_env.h"
//#include "famfs_bbitmap.h"
#include "famfs_maps.h"

#include <urcu-qsbr.h>
//#include <urcu-call-rcu.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter" /* Matt.7.1 */
#include <urcu/rcuja.h>
#pragma GCC diagnostic pop


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
 * The minimum PU_FACTOR is F_MAP_KEY_FACTOR_MIN (8).
 * PU_COUNT - theumber of map entries in PU, 1 << PU_FACTOR.
 * BOS_PU_COUNT - block of slabs (BoS) size in PUs, (1..F_MAP_MAX_BOS_PUS)
 */
#define F_MAP_KEY_FACTOR_MIN	8
#define F_MAP_MAX_BOS_PUS	512

/*
 * Locking
 */

/*
 * Map entry type.
 * BITMAP - one- or bifold bitmap; entry size is one or two bits.
 * STRUCTURED - a structure, aligned to 8 bytes, of arbitrary size (in bytes).
 */

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
 * Virtual map functions (for STRUCTURED entry only):
 * F_MAP_GET_fn(*entry) - reduce the entry value to a bit;
 * F_MAP_SET_fn(*entry, value) - set the entry to the value.
 */
typedef int (*F_MAP_GET_fn)(void *arg, const F_PU_VAL_t *entry);
/* TODO
typedef void (*F_MAP_SET_fn)(void *arg, F_PU_VAL_t *entry, bool value);
typedef void (*F_MAP_SETBB_fn)(void *arg, F_PU_VAL_t *entry, \
	unsigned int bit, BBIT_VALUE_t value);
*/

/* Map can store the [bifold] bitmaps or a long word aligned structures. */
typedef enum {
    F_MAPTYPE_BITMAP = 0,
    F_MAPTYPE_STRUCTURED,
} F_MAPTYPE_t;

typedef enum {
    F_MAPLOCKING_DEFAULT = 0,
    F_MAPLOCKING_END,
} F_MAPLOCKING_t;

/* Judy sparse array */
typedef struct cds_ja F_JUDY_t;

typedef struct {
    unsigned int		entry_sz;	/* map entry size, bits or bytes */
    unsigned int		pu_factor;	/* number of entries per persistent unit */
    unsigned int		intl_factor;	/* PU interleave factor >= pu_factor */
    unsigned int		bosl_pu_count;	/* number of persistent units in BoS */

    //unsigned int		slab_entries;	/* number of entries in one slab */
} F_MAP_GEO_t;

/* F_MAP */
typedef struct f_map_ {
    pthread_mutex_t		pu_lock;	/* persistent KV store access lock */
    size_t			bosl_sz;	/* BoS data size, bytes */
    uint64_t			nr_bosl;	/* number of allocated BoSses */
    F_JUDY_t			*bosses;	/* Judy sparse array of BoSses */
    pthread_spinlock_t		bosl_lock;	/* BoS access lock */
    unsigned int		bosl_entries;	/* BoS entry count */
    F_MAPTYPE_t			type;		/* BITMAP or STRUCTURED */
    int				id;		/* map id */
    F_MAP_GEO_t			geometry;	/* map geometry */
    unsigned int		part;		/* partition number */
    unsigned int		parts;		/* number of partitions */
    union {
	unsigned int		_flags;
	struct {
	    unsigned int	locking:2;	/* locking level, 0: default */
	    unsigned int	loaded:1;	/* 1: loaded from persistent storage */
	    unsigned int	own_part:1;	/* 1: local entries only, from 'part' */
	};
    };
} F_MAP_t;

#define f_map_is_partitioned(map_p)	(map_p->parts > 1)
#define f_map_is_structured(map_p)	(map_p->type == F_MAPTYPE_STRUCTURED)
#define f_map_is_bbitmap(map_p)		(map_p->type == F_MAPTYPE_BITMAP && \
					 map_p->geometry.entry_sz == 2)

/* Block of slabs */
#define F_BOSL_DIRTY_SZ	(F_MAP_MAX_BOS_PUS/(8*sizeof(unsigned long))) /* 4 */
/* Judy node */
typedef struct f_bosl_ {
    struct cds_ja_node		node;
    struct rcu_head		head;		/* RCU delayed reclaim */
    uint64_t			entry0;		/* number of the first entry in BoS */
    unsigned long		*page;		/* data page with map entries */
    F_MAP_t			*map;		/* backreference to map */
    pthread_rwlock_t		rwlock;		/* protect iterators on BoS deletion */
    pthread_spinlock_t		dirty_lock;	/* dirty bitmap lock */
    unsigned long		dirty[F_BOSL_DIRTY_SZ];	/* dirty bitmap */
    //unsigned int		length;		/* BoS entry count */
    union {
	uint32_t		_flags;
	struct {
	    unsigned int	loaded:1;	/* 1: loaded from persistent storage */
	};
    };
} F_BOSL_t;


/*
 * Iterators
 */

/* Iterator's condition */
typedef union {
    /* Condition is either evaluation function or BBIT pattern set */
    F_MAP_GET_fn		vf_get;		/* value evaluation function or NULL */
    uint64_t			pset;		/* BBIT pattern set: [0..BB_PAT_MASK] */
} F_COND_t;
#define f_cond_has_vf(cond)	(cond.pset > BB_PAT_MASK)
#define F_NO_CONDITION		((F_COND_t)0LU)	/* Iterator will iterate ALL entries */

typedef struct f_iter_ {
    F_MAP_t			*map;		/* back pointer to iterator's map */
    uint64_t			entry;		/* current position */
    F_BOSL_t			*bosl;		/* current BoS or NULL */
    F_COND_t			cond;		/* condition (or zero, i.e. all entries) */
    union {
	/* BBIT map */
	unsigned long		*word_p;	/* current entry pointer in BoS->page */
	/* Stuctured map */
	void			*vf_arg;	/* optional vf_get() argument */
    };
} F_ITER_t;

/*
 * Map API
 */

/* Create map in memory */
F_MAP_t *f_map_init(F_MAPTYPE_t type, int entry_sz, size_t bosl_sz, F_MAPLOCKING_t locking);
/* Set map is partitioned; chose only 'own' partition (local) entries or whole (global) */
int f_map_init_prt(F_MAP_t *map, int parts, int node, int part_0, int global);
void f_map_exit(F_MAP_t *map); /* free memory */

/*
 * Read/write the persistent KV store
 */
int f_map_register(F_MAP_t *map, int layout_id); /* Attach map to persistent KV store */
int f_map_load(F_MAP_t *map); /* load all KVs for [one partition of] the registered map */
/* Update (load from KV store) only map entries given in the stripe list */
int f_map_update(F_MAP_t *map, F_STRIPE_HEAD_t *stripe_list);
int f_map_flush(F_MAP_t *map); /* Put all 'dirty' KVs of all BoSses to KV store */
void f_map_mark_dirty(F_MAP_t *map, uint64_t entry); /* explicitly mark KV dirty */

/* Note: Please use this function from common library to read the layout configuration
 * for a map: F_LAYOUT_INFO_t *f_get_layout_info(int layout_id);
 */

/*
 * Low-level data access.
 * Note: RCU read-side lock should not be held when calling these functions,
 * however, QSBR threads need to be online and rcu_quiescent_state() must be called
 * some time later.
 */
unsigned long *f_map_get_p(F_MAP_t *map, uint64_t entry); /* returns NULL if no entry */
unsigned long *f_map_new_p(F_MAP_t *map, uint64_t entry); /* if no entry, create it */
F_BOSL_t *f_map_get_bosl(F_MAP_t *map, uint64_t entry); /* returns NULL if no BoS */
F_BOSL_t *f_map_new_bosl(F_MAP_t *map, uint64_t entry); /* if no BoS, create it */
void f_map_mark_dirty_bosl(F_BOSL_t *bosl, uint64_t entry); /* mark KV dirty in BoS PU bitmap */
/* Check if the entry belongs to this BoS */
static inline int f_map_entry_in_bosl(F_BOSL_t *bosl, uint64_t entry)
{
	return (bosl && IN_RANGE(entry, bosl->entry0,
				 bosl->entry0 + bosl->map->bosl_entries - 1));
}
int f_map_delete_bosl(F_MAP_t *map, F_BOSL_t *bosl); /* remove all BoS entries from online map */

/*
 * Iterators
 */
/* Create new iterator */
F_ITER_t *f_map_new_iter(F_MAP_t *map, F_COND_t cond);
void f_map_free_iter(F_ITER_t *iter);
/* Reset the iterator unconditionally and ensure BoS is created */
F_ITER_t *f_map_seek_iter(F_ITER_t *iter, uint64_t entry);
/* Create a new iterator with condition on map */
static inline F_ITER_t *f_map_get_iter(F_MAP_t *map, F_COND_t cond)
{
	F_ITER_t *iter = f_map_new_iter(map, cond);
	return f_map_seek_iter(iter, 0);
}
/* check if iterator's condition is true */
bool f_map_check_iter(F_ITER_t *iter);

/* for_each(iterator) - iterate all map entries with given condition */
#define for_each_iter(iter)					\
	for (; iter; iter = f_map_next(iter))
#define for_each_iter_from(iter, start, size)			\
	for (iter = f_map_seek_iter(iter, (uint64_t)start),	\
	     iter != NULL;					\
	     iter = f_map_next(iter))
/* get iterator for the next entry which matches the iterator's condition or return NULL */
F_ITER_t *f_map_next(F_ITER_t *iter);
/* get the number of entries which matches the iterator's condition within given size */
uint64_t f_map_weight(const F_ITER_t *iter, size_t size);


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


#endif /* F_MAP_H_ */
