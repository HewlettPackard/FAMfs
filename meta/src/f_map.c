/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */
//#include <assert.h>
#include <unistd.h>

#include "f_map.h"
#include "famfs_bitmap.h"

#define e_to_bosl(bosl, e)	(e - bosl->entry0)
#define is_iter_reset(it)	(it->entry == ~0LU)


static F_BOSL_t *bosl_alloc(size_t size)
{
	F_BOSL_t *bosl;

	bosl = (F_BOSL_t *) calloc(sizeof(F_BOSL_t), 1);
	if (bosl) {
		if (posix_memalign((void**)&bosl->page, 4096, size)) {
			free(bosl);
			return NULL;
		}
		memset(bosl->page, 0, size);

		pthread_spin_init(&bosl->dirty_lock, PTHREAD_PROCESS_PRIVATE);
		pthread_rwlock_init(&bosl->rwlock, NULL);
	}
	return bosl;
}

static void bosl_free(F_BOSL_t *bosl)
{
	pthread_rwlock_destroy(&bosl->rwlock);
	pthread_spin_destroy(&bosl->dirty_lock);
	free(bosl->page);
	free(bosl);
}

static inline void _f_map_clear_pu_dirty_bosl(F_BOSL_t *bosl, uint64_t pu)
{
	pthread_spin_lock(&bosl->dirty_lock);
	clear_bit64(pu, bosl->dirty);
	pthread_spin_unlock(&bosl->dirty_lock);
}

static inline void _f_map_mark_pu_dirty_bosl(F_BOSL_t *bosl, uint64_t pu)
{
	pthread_spin_lock(&bosl->dirty_lock);
	set_bit64(pu, bosl->dirty);
	pthread_spin_unlock(&bosl->dirty_lock);
}

static int map_free_all_nodes(struct cds_ja *ja)
{
	uint64_t key;
	struct cds_ja_node *node;
	int ret = 0;

	rcu_read_lock();
	cds_ja_for_each_key_rcu(ja, key, node) {
		F_BOSL_t *bosl;

		ret = cds_ja_del(ja, key, node);
		if (ret)
			goto _err;
		/* Alone using the array */
		bosl = container_of(node, F_BOSL_t, node);
		bosl_free(bosl);
	}
_err:
	rcu_read_unlock();
	return ret;
}

static F_MAP_t *map_alloc(void)
{
	F_MAP_t *map;

	map = (F_MAP_t *) calloc(sizeof(F_MAP_t), 1);
	if (map)
		map->bosses = cds_ja_new(64); /* 64-bit key */
	return map;
}

/* RCU read-side lock should _not_ be held when calling this function,
 * however, QSBR threads need to be online.
 */
static int map_free(F_MAP_t *map)
{
	int ret;

	if ((ret = map_free_all_nodes(map->bosses)))
		return ret;
	if ((ret = cds_ja_destroy(map->bosses)))
		return ret;
	pthread_spin_destroy(&map->bosl_lock);
	pthread_mutex_destroy(&map->pu_lock);
	free(map);
	rcu_quiescent_state();
	return 0;
}

static int _map_insert_bosl(F_MAP_t *map, uint64_t entry, F_BOSL_t **bosl_p)
{
	F_BOSL_t *bosl;
	struct cds_ja_node *node;
	uint64_t node_idx, length;
	int ret = 0;

	bosl = bosl_alloc(map->bosl_sz);
	if (!bosl)
		return -ENOMEM;

	length = map->bosl_entries;
	bosl->loaded = map->loaded;
	node_idx = entry / length;
	bosl->entry0 = node_idx * length;

	rcu_read_lock();
	node = cds_ja_add_unique(map->bosses, node_idx, &bosl->node);
	if (node != &bosl->node) {
		bosl_free(bosl);
		bosl = container_of(node, F_BOSL_t, node);
		rcu_read_unlock();

		ret = -EEXIST;
		goto _ret;
	}
	pthread_spin_lock(&map->bosl_lock);
	map->nr_bosl++;
	pthread_spin_unlock(&map->bosl_lock);
	rcu_read_unlock();

	bosl->map = map;

_ret:
	/* TODO: Use per-thread lock count */
	rcu_quiescent_state();

	if (bosl_p)
		*bosl_p = bosl;
	return ret;
}

static inline F_BOSL_t *map_insert_bosl(F_MAP_t *map, uint64_t entry)
{
	F_BOSL_t *bosl;

	assert(_map_insert_bosl(map, entry, &bosl) == 0);
	return bosl;
}

/* Return a poiner to the entry in BoS or NULL if out of BoS range */
static unsigned long *_bosl_ffind(F_BOSL_t *bosl, uint64_t e)
{
	F_MAP_t *map = bosl->map;
	unsigned long *p = bosl->page;

	return p + f_map_values_p_off(map, e, p);
}

/* Return a poiner to the entry in BoS or NULL if out of BoS range */
static unsigned long *bosl_ffind(F_BOSL_t *bosl, uint64_t e)
{
	if (f_map_entry_in_bosl(bosl, e))
		return _bosl_ffind(bosl, e_to_bosl(bosl, e));
	return NULL;
}

/* Copy one PU from buffer 'from' @pu_from to BoS @pu_to */
static void copy_pu_to_bosl(F_BOSL_t *bosl_to, uint64_t pu_to,
    unsigned long *buf_from, uint64_t pu_from)
{
	F_MAP_t *map = bosl_to->map;
	size_t size;
	unsigned long *from, *to;

	assert(pu_to < F_MAP_MAX_BOS_PUS);
	assert(pu_to < map->geometry.bosl_pu_count);
	size = f_map_pu_size(map);
	from = buf_from + f_map_pu_p_sz(map, pu_from, from);
	to   = bosl_to->page + f_map_pu_p_sz(map, pu_to, to);

	/* No lock! */
	memcpy(to, from, size);
	bosl_to->loaded = 1;
}

/* Copy one PU from BoS @pu_from to 'buf' @pu_to.
 * Clear dirty bit.
 */
static void copy_pu_from_bosl(unsigned long *buf, uint64_t pu_to,
    F_BOSL_t *bosl, uint64_t pu_from)
{
	F_MAP_t *map = bosl->map;
	size_t size;
	unsigned long *from, *to;

	assert(pu_from < F_MAP_MAX_BOS_PUS);
	size = f_map_pu_size(map);
	from = bosl->page + f_map_pu_p_sz(map, pu_from, from);
	to   = buf + f_map_pu_p_sz(map, pu_to, to);

	pthread_spin_lock(&bosl->dirty_lock);
	clear_bit64(pu_from, bosl->dirty);
	memcpy(to, from, size);
	pthread_spin_unlock(&bosl->dirty_lock);
}

/*
 * Return true if PU in BoS @pu is clean, i.e. zeroed.
 * Note: only bosl.map and .page pointers are required
 * for this function.
 */
static int bosl_is_pu_clean(F_BOSL_t *bosl, unsigned int pu)
{
	unsigned long *p;
	size_t w, pu_p_sz;

	p = bosl->page;
	pu_p_sz = f_map_pu_p_sz(bosl->map, 1, p);
	p += pu * pu_p_sz;
	for (w = 0; w < pu_p_sz; w++)
		if (p[w])
			return 0;
	return 1;
}


/*
 * API
 */

/* f_map_init - Create map in memory */
F_MAP_t *f_map_init(F_MAPTYPE_t type, int entry_sz, size_t bosl_sz,
    F_MAPLOCKING_t locking)
{
	F_MAP_t *map;
	size_t psize = getpagesize();

	/* Safe defaults */
	switch (type) {
	case F_MAPTYPE_BITMAP:
		if (!IN_RANGE(entry_sz, 1, 2))
			entry_sz = 2; /* claim vector has 2 bits per entry */
		break;
	case F_MAPTYPE_STRUCTURED:
		if (entry_sz <= 0 || (entry_sz % 8))
			return NULL;
		break;
	default: return NULL;
	}

	if (bosl_sz % psize) return NULL;
	if (bosl_sz == 0) bosl_sz = psize;

	if (!IN_RANGE(locking, 0, F_MAPLOCKING_END-1)) return NULL;

	map = map_alloc();
	map->type = type;
	map->parts = 1;
	map->id = -1; /* In-memory map: detached from KV store */
	map->bosl_sz = bosl_sz;
	map->geometry.entry_sz = entry_sz;
	/* Map defaults */
	if (f_map_is_structured(map)) {
		map->geometry.pu_factor = 0;
		map->geometry.bosl_pu_count = bosl_sz /			\
				((1 << map->geometry.pu_factor)*entry_sz);
	} else {
		map->geometry.pu_factor = F_MAP_KEY_FACTOR_MIN;
		map->geometry.bosl_pu_count = bosl_sz /			\
			(1 << (map->geometry.pu_factor - 3 + entry_sz-1));
	}
	map->geometry.intl_factor = map->geometry.pu_factor;
	/* Calculated */
	map->bosl_entries = map->geometry.bosl_pu_count * \
		(1 << map->geometry.pu_factor);
	/* init locks */
	map->locking = locking;
	pthread_mutex_init(&map->pu_lock, NULL);
	pthread_spin_init(&map->bosl_lock, PTHREAD_PROCESS_PRIVATE);

	if (map->geometry.bosl_pu_count == 0 ||
	    map->geometry.bosl_pu_count > F_MAP_MAX_BOS_PUS)
	{
		map_free(map);
		map = NULL;
	}
	return map;
}

/**
 * f_map_init_prt
 *
 * Set map as partitioned. This call must follow f_map_init().
 * @param parts	- total number of map partitions;
 * @param node	- this node;
 * @param part_0 - node of partition zero;
 * @param global - 0: map has only its own partition entries, use local entry numbers;
 *		   1: map has all entries, use 'global' numbers.
 **/
int f_map_init_prt(F_MAP_t *map, int parts, int node, int part_0, int global)
{
	/* sanity */
	if (map == NULL || parts <= 1 ||
	    !IN_RANGE(part_0, 0, parts) || !IN_RANGE(node, 0, parts))
		return -EINVAL;

	map->parts = parts;
	map->part = (node + part_0) % parts;
	map->own_part = global?0:1;
	return 0;
}

/* Free map */
void f_map_exit(F_MAP_t *map)
{
	map_free(map);
}

/*
 * f_map_register
 *
 * Attach map to persistent KV store: create DB global index.
 * layout_id - layout index in configuration, starting with zero.
 */
int f_map_register(F_MAP_t *m, int layout_id)
{
	uint64_t recs_per_slice;
	int rc;

	if (m->geometry.intl_factor < m->geometry.pu_factor)
		return -1;
	recs_per_slice = 1U << (m->geometry.intl_factor - m->geometry.pu_factor);

	/* Attach map to KV store global index */
	if (f_map_is_structured(m)) {
		/* Create global index for Slab Map */
		rc = f_create_persistent_sm(layout_id, recs_per_slice, &m->id);
	} else {
		/* Create global index index for Claim vector */
		rc = f_create_persistent_cv(layout_id, recs_per_slice, &m->id);
	}
	return rc;
}

/* f_map_load - Load all KVs for [one partition of] the registered map */
int f_map_load(F_MAP_t *map)
{
	F_BOSL_t *bos_buf;
	F_ITER_t *it;
	unsigned int part, parts, pu_per_bos, pu_factor;
	unsigned int i, count, intl;
	size_t size;
	size_t total = 0, pu_cnt = 0;
	ssize_t rcv_cnt;
	uint64_t *offsets, *off, *keys;
	int map_id, ret = 0;

	if (map == NULL)
		return -1;

	parts = map->parts;
	pu_per_bos = map->geometry.bosl_pu_count;
	offsets = (uint64_t *) calloc(sizeof(uint64_t), parts);
	keys = (uint64_t *) calloc(sizeof(uint64_t), pu_per_bos);
	if (!offsets || !keys)
		return -ENOMEM;

	intl = 1U << map->geometry.intl_factor;
	pu_factor = map->geometry.pu_factor;
	map_id = map->id;

	/* Allocate I/O buffer */
	bos_buf = bosl_alloc(map->bosl_sz);

	/* New unconditional map iterator */
	it = f_map_new_iter(map, F_NO_CONDITION);

	/* Until we reach the end on all partitions */
	count = f_map_has_globals(map)? parts:1;
	do {
		/* For each map partition */
		for (part = 0; part < parts; part++) {
			if (part != map->part && !f_map_has_globals(map))
				continue;

			off = &offsets[part];
			if (*off == 0U)
				*off = part * intl; /* global ID of local PU#0 */
			else if (*off == ~(0UL))
				continue; /* the partition end reached */
			//printf(" load map id:%d part:%u @%lu\n", map_id, part, *off);

			/* BGET pu_per_bos entries */
			size = pu_per_bos;
			rcv_cnt = f_db_bget(bos_buf->page, map_id, keys, size, off);
			if (rcv_cnt < 0) {
				ret = (int) rcv_cnt;
				goto _exit;
			}
			size = (size_t) rcv_cnt;
			assert (size <= pu_per_bos);

			/* Mark partition end */
			if (size == 0) {
				*off = ~(0UL); /* special mark: at partition end */
				count--;
			}
			total += size; /* stats */

			/* For all buffer PUs */
			for (i = 0; size > 0; i++, size--) {
				uint64_t e, pu;

				e = keys[i];
				if (!f_map_has_globals(map)) {
					/* TODO: Need a special case for re-partitioning */
					if (!f_map_prt_has_global(map, e, part))
						continue;
					e = f_map_prt_to_local(map, e);
				}
				pu_cnt++; /* stats */

				/* Prepare BoS */
				assert (f_map_seek_iter(it, e));
				/* Copy PU values */
				e = e_to_bosl(it->bosl, e);
				pu = e >> pu_factor;
				copy_pu_to_bosl(it->bosl, pu,
						bos_buf->page, i);
				/* Clear PU dirty bit */
				// _f_map_clear_pu_dirty_bosl(it->bosl, pu);
			}
		}
	} while (count > 0);
	map->loaded = 1;

_exit:
	//printf(" Load map:%d read %zu, got %zu PUs rc:%d\n", map_id, total, pu_cnt, ret);
	f_map_free_iter(it);
	bosl_free(bos_buf);
	free(offsets);
	free(keys);
	return ret;
}

/* Update (load from KV store) only map entries given in the stripe list */
int f_map_update(F_MAP_t *map, F_STRIPE_HEAD_t *stripes)
{
	F_BOSL_t *bos_buf;
	F_STRIPE_HEAD_t *done = NULL;
	F_ITER_t *it = NULL;
	unsigned int part, parts, pu_per_bos, pu_factor;
	unsigned int i, count, intl;
	size_t size;
	ssize_t rcv_cnt;
	uint64_t *keys;
	int map_id, ret = 0;

	if (map == NULL)
		return -1;

	pu_per_bos = map->geometry.bosl_pu_count;
	keys = (uint64_t *) malloc(sizeof(uint64_t) * pu_per_bos);
	if (!keys)
		return -ENOMEM;

	intl = 1U << map->geometry.intl_factor;
	pu_factor = map->geometry.pu_factor;
	map_id = map->id;
	parts = map->parts;

	/* Allocate I/O buffer */
	bos_buf = bosl_alloc(map->bosl_sz);

	/* New unconditional map iterator */
	it = f_map_new_iter(map, F_NO_CONDITION);

	/* Until we reach the end on all partitions */
	count = f_map_has_globals(map)? parts:1;
	do {
		/* For each map partition */
		for (part = 0; part < parts; part++) {
			if (part != map->part && !f_map_has_globals(map))
				continue;

			/* BGET pu_per_bos entries */
			size = pu_per_bos;
			rcv_cnt = f_db_bget(bos_buf->page, map_id, keys, size, NULL);
			if (rcv_cnt < 0) {
				ret = (int) rcv_cnt;
				goto _exit;
			}
			size = (size_t) rcv_cnt;
			assert (size <= pu_per_bos);
		}
	} while (count > 0);
	map->loaded = 1;

_exit:
	f_map_free_iter(it);
	free(keys);
	bosl_free(bos_buf);
	return ret;
}

/* Reset iterator so it could be re-used */
static void iter_reset(F_ITER_t *it) {
	it->entry = 0;
	it->entry--; /* invalid entry */
	it->bosl = NULL;
	it->at_end = 0;
}

/* Round up to this partition if map is global */
#define pu_round_up_to_part(pu, factor, parts, partition)	\
	do {							\
		unsigned int il = (pu >> factor) % parts;	\
		pu += (1UL << factor) *				\
		      ((il>partition)?parts:0U +partition -il);	\
	} while (0)

/* Iterate over dirty PUs on global maps.
 * It's aware of partition on local (own_part:1) maps.
 * This call takes and hold BoS R/W lock(s) - until freed.
 */
static F_ITER_t *iter_next_dirty_pu(F_ITER_t *iter)
{
	F_MAP_t *map = iter->map;
	F_BOSL_t *bosl;
	struct cds_ja_node *node;
	uint64_t node_idx, idx, e;
	unsigned int pu, pu_factor, factor, e_per_pu, pu_per_bos;
	unsigned int partition = 0;
	unsigned long *dirty = NULL;
	size_t dirty_sz;
	bool bitmap, global;

	bitmap = !f_map_is_structured(map);
	global = f_map_has_globals(map);
	if (global)
		partition = iter->cond.partition;
	pu_factor = map->geometry.pu_factor;
	e_per_pu = 1U << pu_factor;
	factor = map->geometry.intl_factor - pu_factor;
	pu_per_bos = map->geometry.bosl_pu_count;
	dirty_sz = DIV_CEIL(pu_per_bos, 8); /* dirty PU bitmap size, bytes */
	assert(dirty_sz <= sizeof(*dirty)*F_BOSL_DIRTY_SZ);
	dirty = (unsigned long *) malloc(dirty_sz);
	if (dirty == NULL) return NULL;

	/* Progress to the next PU */
	e = iter->entry;
	e += e_per_pu;
	e &= ~((uint64_t)e_per_pu - 1); /* PU entry mask */
	node_idx = e / map->bosl_entries;
	bosl = iter->bosl;
	if (!f_map_entry_in_bosl(bosl, e))
		goto _find_bos;

	/* Round up to this partition if map is global */
	pu = e_to_bosl(bosl, e) >> pu_factor;
	if (global)
		pu_round_up_to_part(pu, factor, map->parts, partition);

	/* For each BoS in Judy array */
	while (1) {
		/* Copy dirty bitmap under lock */
		pthread_spin_lock(&bosl->dirty_lock);
		memcpy(dirty, bosl->dirty, dirty_sz);
		pthread_spin_unlock(&bosl->dirty_lock);

		/* Search for dirty PU in current BoS */
		do {
			pu = find_next_bit(dirty, pu_per_bos, pu);
		/* ignore other partitions if map is global */
		} while (global && pu < pu_per_bos &&
			 ((pu >> factor) % map->parts != partition) &&
			 pu++); /* increment pu for next bit */

		/* Is there next dirty PU in BoS? */
		if (pu < pu_per_bos) {
			/* Yes; set iterator to 'e' and return it */
			iter->entry = (pu << pu_factor) + bosl->entry0;
			if (bitmap)
				iter->word_p = bosl_ffind(bosl, iter->entry);
			iter->bosl = bosl;
			break;
		}

		/* Leave BoS */
		//if (pthread_rwlock_unlock(&bosl->rwlock)) return NULL;
		atomic_dec(&bosl->claimed);
		node_idx++;

_find_bos:
		iter->bosl = NULL;

		rcu_read_lock();
		node = cds_ja_lookup_above_equal(map->bosses,
						 node_idx, &idx);
		if (node == NULL) {
			rcu_read_unlock();
			iter = NULL; /* No dirty PU found */
			break;
		}
		bosl = container_of(node, F_BOSL_t, node);
		atomic_inc(&bosl->claimed);
		rcu_read_unlock();

		/* Enter BoS */
		//if (pthread_rwlock_rdlock(&bosl->rwlock)) return NULL;
		pu = 0;
		if (global) {
			pu_round_up_to_part(pu, factor,
					    map->parts, partition);
		}
		node_idx = idx;
	}

	/* TODO: Use per-thread lock count */
	rcu_quiescent_state();
	free(dirty);
	return iter;
}
#undef pu_round_up_to_part

/*
 * f_map_flush
 * Flush map: put all 'dirty' PUs of all BoSses to KV store.
 * If the whole PU is zeroed, this flush would delete the PU.
 */
int f_map_flush(F_MAP_t *map)
{
	F_BOSL_t *bos_buf;
	F_ITER_t *it, *iter = NULL;
	unsigned int part, parts, pu_per_bos, pu_factor;
	size_t size, value_len;
	void **keysp;
	uint64_t *keys;
	int map_id, ret = 0;

	if (map == NULL)
	    return -1;

	pu_per_bos = map->geometry.bosl_pu_count;
	assert(pu_per_bos <= F_MAP_MAX_BOS_PUS);
	keysp = (void **) malloc(sizeof(void *) * pu_per_bos);
	if (!keysp)
	    return -ENOMEM;
	keys = (uint64_t *) malloc(sizeof(uint64_t) * pu_per_bos);
	if (!keys) {
	    free(keysp);
	    return -ENOMEM;
	}

	pu_factor = map->geometry.pu_factor;
	value_len = f_map_pu_size(map);
	map_id = map->id;
	parts = map->parts;

	/* Allocate I/O buffer */
	bos_buf = bosl_alloc(map->bosl_sz);
	bos_buf->map = map; /* map reference for bosl_is_pu_clean() */

	/* New iterator */
	iter = f_map_new_iter(map, F_NO_CONDITION);

	/* For each map partition */
	for (part = 0; part < parts; part++) {
	    if (part != map->part && !f_map_has_globals(map))
		continue;

	    iter_reset(iter);
	    iter->cond.partition = part;
	    size = 0;
	    //printf(" flush map id:%d part:%u\n", map_id, part);

	    /* For each dirty PU (in this partition if map is global)... */
	    do {
		if ((it = iter_next_dirty_pu(iter))) {
		    uint64_t pu, e;

		    /* Copy PU key */
		    e = it->entry;
		    if (!f_map_has_globals(map))
			e = f_map_prt_to_global(map, e);
		    //printf("   key[%zu]=%lu\n", size, e);
		    keys[size] = e;
		    keysp[size] = &keys[size];

		    /* Copy PU value and clear dirty bit */
		    pu = e_to_bosl(it->bosl, it->entry) >> pu_factor;
		    copy_pu_from_bosl(bos_buf->page, size++,
				      it->bosl, pu);
		}

		/* There are PUs to flush */
		if (size == pu_per_bos || (size > 0 && !it)) {
		    unsigned int st = 0;
		    bool clean;

		    clean = bosl_is_pu_clean(bos_buf, 0);
		    //printf("    number of keys:%zu clean:%d\n", size, (int)clean);
		    do {
			unsigned int i, bunch;
			unsigned long *buf;

			/* Scan buffer for bunch of empty or non-empty PUs */
			//printf("    scan @%u\n", st);
			for (i = st + 1; i < size; i++)
			    if (bosl_is_pu_clean(bos_buf, i) != clean)
				break;
			bunch = i - st;

			if (clean) {
			    /* Bulk DEL bunch of empty PUs */
			    ret = f_db_bdel(map_id, &keysp[st], bunch);
			    //printf("   bdel bunch of %u @%u map_id:%u ret:%d\n", bunch, st, map_id, ret);
			} else {
			    /* Bulk PUT bunch of PUs from buffer @st */
			    buf = bos_buf->page + f_map_pu_p_sz(map, st, buf);
			    ret = f_db_bput(buf, map_id, &keysp[st],
					    bunch, value_len);
			    //printf("   bput bunch of %u @%u map_id:%u ret:%d\n", bunch, st, map_id, ret);
			}
			if (ret)
			    goto _err;

			clean = !clean;
			st = i;
		    } while (st < size);
		    size = 0;
		}
	    } while (it);
	}
_err:
	f_map_free_iter(iter);
	free(keys);
	free(keysp);
	bosl_free(bos_buf);
	return ret;
}

/*
 * f_map_mark_dirty_bosl
 * Mark KV dirty in BoS PU dirty bitmap.
 */
void f_map_mark_dirty_bosl(F_BOSL_t *bosl, uint64_t entry)
{
	unsigned int pu_factor = bosl->map->geometry.pu_factor;

	assert (f_map_entry_in_bosl(bosl, entry));
	_f_map_mark_pu_dirty_bosl(bosl,
				  e_to_bosl(bosl, entry) >> pu_factor);
}

/* f_map_mark_dirty - explicitly mark KV dirty */
void f_map_mark_dirty(F_MAP_t *map, uint64_t entry)
{
	F_BOSL_t *bosl = f_map_get_bosl(map, entry);

	if (bosl)
		f_map_mark_dirty_bosl(bosl, entry);
}

/*
 * Low-level data access
 */

/*
 * f_map_get_p
 * Return pointer to long word that contains this entry or NULL if no entry
 */
unsigned long *f_map_get_p(F_MAP_t *map, uint64_t entry)
{
	unsigned long *p = NULL;
	F_BOSL_t *bosl;

	if ((bosl = f_map_get_bosl(map, entry)))
		p = bosl_ffind(bosl, entry);
	return p;
}

/*
 * f_map_new_p
 * Same as f_map_get_p but it creates the new entry
 */
unsigned long *f_map_new_p(F_MAP_t *map, uint64_t entry)
{
	unsigned long *p = f_map_get_p(map, entry);

	if (!p) {
		F_BOSL_t *bosl;

		if ((bosl = map_insert_bosl(map, entry)))
			p = bosl_ffind(bosl, entry);
	}
	//assert(p);
	return p;
}

/*
 * f_map_get_bosl
 * BoS lookup in Judy sparse array by entry
 * Return BoS that contains this entry or NULL if no entry
 */
F_BOSL_t *f_map_get_bosl(F_MAP_t *map, uint64_t entry)
{
	F_BOSL_t *bosl;
	struct cds_ja_node *node;

	rcu_read_lock();
	node = cds_ja_lookup(map->bosses, entry / map->bosl_entries);
	if (node == NULL) {
		rcu_read_unlock();
		return NULL;
	}
	bosl = container_of(node, F_BOSL_t, node);
	rcu_read_unlock();

	return bosl;
}

/*
 * f_map_new_bosl
 * Same as f_map_get_bosl but it creates the new a new BoS
 */
F_BOSL_t *f_map_new_bosl(F_MAP_t *map, uint64_t entry)
{
	F_BOSL_t *bosl = f_map_get_bosl(map, entry);

	if (!bosl)
		bosl = map_insert_bosl(map, entry);
	//assert(bosl);
	return bosl;
}

/* Delete all BoS entries. */
int f_map_delete_bosl(F_MAP_t *map, F_BOSL_t *bosl)
{
	uint64_t length = map->bosl_entries;
	int ret;

	rcu_read_lock();
	ret = cds_ja_del(map->bosses, bosl->entry0 / length,
			 &bosl->node);
	if (ret) {
		rcu_read_unlock();
		return ret;
	}
	pthread_spin_lock(&map->bosl_lock);
	map->nr_bosl--;
	pthread_spin_unlock(&map->bosl_lock);
	bosl_free(bosl);
	rcu_read_unlock();

	/* TODO: Use per-thread lock count */
	rcu_quiescent_state();
	return ret;
}


/*
 * Iterator
 */

/* Get bitmap value under long pointer */
static inline int _get_bit_value(uint64_t e, unsigned long *p, unsigned int bbits)
{
	switch (bbits) {
	case 1:	return test_bit((int)e % BITS_PER_LONG, p);
	case 2: return (int)BBIT_GET_VAL(p, e % BBITS_PER_LONG);
	default: assert (0);
	}
}

/* Test bbitmap entry pattern */
static inline bool _check_iter_cond_bbit(const F_ITER_t *it)
{
	F_BOSL_t *bosl = it->bosl;

	return test_bbit_patterns(e_to_bosl(bosl, it->entry),
				  it->cond.pset, bosl->page);
}

/* Is bit clear (if cond.pset:0) or set (otherwise)? */
static inline bool _check_iter_cond_bit(const F_ITER_t *it)
{
	F_BOSL_t *bosl = it->bosl;

	return !(it->cond.pset) ==
		!test_bit64(e_to_bosl(bosl, it->entry), bosl->page);
}

static inline bool __check_iter_cond_vf(const F_ITER_t *it, const F_PU_VAL_t *v)
{
	return !!(it->cond.vf_get(it->vf_arg, v));
}

static inline bool _check_iter_cond_vf(const F_ITER_t *it)
{
	F_BOSL_t *bosl = it->bosl;
	unsigned long *p;

	p = _bosl_ffind(bosl, e_to_bosl(bosl, it->entry));
	return __check_iter_cond_vf(it, (F_PU_VAL_t *)p);
}

static inline bool check_iter_cond(const F_ITER_t *iter)
{
	return ((iter->cond.pset == 0U) ||
		(f_map_is_structured(iter->map)? &_check_iter_cond_vf :
		 (f_map_is_bbitmap(iter->map)? &_check_iter_cond_bbit :
				&_check_iter_cond_bit))(iter));
}

/* Find entry in this BoS that matches the iterator's condition */
static F_ITER_t *bosl_find_cond(F_ITER_t *it)
{
    F_BOSL_t *bosl = it->bosl;
    uint64_t e, length;

    e = it->entry;
    length = it->map->bosl_entries;

    /* safity check */
    if (!f_map_entry_in_bosl(bosl, e))
	return NULL;

    /* fast path */
    if (check_iter_cond(it))
	return it;

    e = e_to_bosl(bosl, e);
    if (f_map_is_structured(it->map)) {
	for (++e; e < length; e++) {
	    it->entry++;
	    if (_check_iter_cond_vf(it))
		goto _found;
	}
    } else {
	if (f_map_is_bbitmap(it->map)) {
	    e = find_next_bbit(bosl->page, it->cond.pset, length, e);
	} else {
	    if (it->cond.pset)
		e = find_next_bit(bosl->page, length, e);
	    else
		e = find_next_zero_bit(bosl->page, length, e);
	}
	if (e < length) {
	    it->word_p = _bosl_ffind(bosl, e);
		goto _found;
	}
    }
    return NULL;

_found:
    it->entry = e + bosl->entry0;
    assert(check_iter_cond(it));
    return it;
}

/* Create a new iterator */
F_ITER_t *f_map_new_iter(F_MAP_t *map, F_COND_t cond)
{
	F_ITER_t *iter;
	unsigned int entry_sz;
	uint64_t c = cond.pset;

	/* sanity check */
	assert(map);
	entry_sz = map->geometry.entry_sz;
	if (!f_map_is_structured(map))
		assert(entry_sz == 1 || entry_sz == 2);
	else
		assert(entry_sz % 8 == 0);
	assert(map->geometry.intl_factor >=
		map->geometry.pu_factor);

	iter = (F_ITER_t *) calloc(sizeof(F_ITER_t), 1);
	if (!iter)
		return NULL;

	iter_reset(iter);
	iter->map = map;
	iter->cond.pset = c;
	if (f_map_is_structured(map)) {
		iter->vf_arg = calloc(sizeof(long), 1);
		if (!iter->vf_arg) {
			free(iter);
			iter = NULL;
		}
	}
	return iter;
}

void f_map_free_iter(F_ITER_t *iter)
{
	if (iter) {
		if (f_map_is_structured(iter->map))
			free(iter->vf_arg);
		free(iter);
	}
}

/* Check if iterator's condition is true */
bool f_map_check_iter(F_ITER_t *iter) {
	return check_iter_cond(iter);
}

/*
 * f_map_seek_iter
 *
 * (Re-)set the iterator to 'entry' unconditionally.
 * Create a new BoS for 'entry' if it does not exist.
 * Use this function to populate online map starting at 'entry'.
 */
F_ITER_t *f_map_seek_iter(F_ITER_t *iter, uint64_t entry)
{
	F_ITER_t *it = iter;
	F_MAP_t *map = it->map;
	F_BOSL_t *bosl;
	unsigned long *p = NULL;

	/* fast path? */
	if (it->entry == entry)
		return it;
	if ((bosl = it->bosl))
		p = bosl_ffind(bosl, entry);
	if (p == NULL) {
		int rc;

		/* update BoS pointer; create a new BoS on demand */
		rc = _map_insert_bosl(map, entry, &bosl);

		if (rc && rc != -EEXIST)
			return NULL;
		it->bosl = bosl;
		p = bosl_ffind(bosl, entry);
	}
	assert(p);
	if (!f_map_is_structured(it->map))
		it->word_p = p;
	it->entry = entry;
	return it;
}

/*
 * f_map_next
 * Get iterator for the next entry which matches the iterator's condition
 * or return NULL.
 */
F_ITER_t *f_map_next(F_ITER_t *iter)
{
	F_MAP_t *map;
	struct cds_ja_node *node;
	uint64_t node_idx, idx;
	uint64_t length;
	bool bitmap;
	unsigned int per_long, entry_sz;

	/* sanity check */
	if (!iter || !(map = iter->map))
		return NULL;
	entry_sz = map->geometry.entry_sz;
	bitmap = !f_map_is_structured(map);

	/* iter++ */
	iter->entry++;

	/* fast path? */
	length = map->bosl_entries;
	node_idx = iter->entry / length;
	per_long = BITS_PER_LONG / entry_sz;
	if (f_map_entry_in_bosl(iter->bosl, iter->entry)) {
		/* use current BoS */
		if (bitmap && iter->entry &&
		    (iter->entry % per_long == 0))
			iter->word_p++;
		if (bosl_find_cond(iter))
			return iter;
		node_idx++;
	}

	/* For each BoS in Judy array */
	do {
		rcu_read_lock();
		node = cds_ja_lookup_above_equal(map->bosses,
						 node_idx, &idx);
		if (node == NULL) {
			rcu_read_unlock();
			iter->at_end = 1;
			iter = NULL;
			break;
		}
		iter->bosl = container_of(node, F_BOSL_t, node);
		rcu_read_unlock();

		iter->entry = idx * length;
		if (bitmap)
			iter->word_p = iter->bosl->page;
		node_idx = idx + 1;
	} while (!bosl_find_cond(iter));

	/* TODO: Use per-thread lock count */
	rcu_quiescent_state();
	return iter;
}

/*
 * f_map_probe_iter_at
 * Check if iterator's condition is true would it point at given entry.
 * This function is alike f_map_seek_iter() + check_iter_cond()
 * but it does not affect the iterator.
 * Return: evaluated entry value regarding iterator's condition if BoS found,
 *	   false - if no BoS.
 * If given the pointer to value:
 * - for bitmap set it to integer entry value (0..3) or -1 if no BoS;
 * - for structured map set to the pointer to the map value (F_PU_VAL_t)
 * or NULL if no BoS
 */
bool f_map_probe_iter_at(const F_ITER_t *it, uint64_t entry, void *value_p)
{
	F_MAP_t *map = it->map;
	F_BOSL_t *bosl;
	unsigned long *p;
	uint64_t e;

	if (f_map_entry_in_bosl(it->bosl, entry))
		bosl = it->bosl;
	else
		bosl = f_map_get_bosl(map, entry);
	if (bosl == NULL) {
		if (value_p) {
			if (f_map_is_structured(map))
				*(void**)value_p = NULL;
			else
				*(int*)value_p = -1;
		}
		return false;
	}

	e = e_to_bosl(bosl, entry);
	p = _bosl_ffind(bosl, e);
	/* structured map? */
	if (f_map_is_structured(map)) {
		if (value_p)
			*(void **)value_p = (void*)p;
		return __check_iter_cond_vf(it, (F_PU_VAL_t *)p);
	}
	/* bitmap */
	if (value_p)
		*(int*)value_p = _get_bit_value(e, p, map->geometry.entry_sz);
	if (map->geometry.entry_sz == 1)
		return !(it->cond.pset) ==
			!test_bit((int)e % BITS_PER_LONG, p);
	/* bbitmap */
	return test_bbit_patterns(e % BBITS_PER_LONG,
				  it->cond.pset, p);
}

static uint64_t bosl_weight_vf(const F_ITER_t *it, const unsigned long *p,
    uint64_t start, uint64_t len)
{
	uint64_t e, w;
	const void *v = (void *)p;
	size_t entry_sz = it->map->geometry.entry_sz;

	w = 0;
	v += entry_sz*start;
	for (e = start; e < start + len; e++) {
		if (__check_iter_cond_vf(it, (F_PU_VAL_t *)v))
			w++;
		v += entry_sz;
	}
	return w;
}

static uint64_t bosl_weight(const F_ITER_t *it, const unsigned long *p,
    uint64_t start, uint64_t nr)
{
	if (f_map_is_structured(it->map)) {
		return bosl_weight_vf(it, p, start, nr);
	} else {
		if (it->map->geometry.entry_sz == 1) {
			uint64_t w = __bitmap_weight64(p, start, nr);

			return (it->cond.pset)? w : (nr-w);
		} else {
			return __bbitmap_weight(p, it->cond.pset, start, nr);
		}
	}
}

/*
 * f_map_weight
 *
 * Return the number of entries which matches the iterator's condition
 * starting at iterator position and within the given size.
 *
 * Note: the iterator must be 'got' or 'sought' at a position
 * conditionally by next() or unconditionally by either get_iter() or
 * f_map_seek_iter() before calling this function. The function should
 * assert the iterator is on a position otherwise terminated, for example,
 * when it called immediately after new_iter() or reset_iter().
 */
uint64_t f_map_weight(const F_ITER_t *iter, size_t size)
{
	F_BOSL_t *bosl = iter->bosl;
	F_MAP_t *map = iter->map;
	struct cds_ja_node *node;
	uint64_t cnt, node_idx, idx;
	uint64_t weight = 0;
	uint64_t e, entry;
	uint64_t length = map->bosl_entries;

	assert (!is_iter_reset(iter)); /* No iterator position! */
	entry = iter->entry;
	node_idx = entry / length;

	/* If we have the current BoS, weight entries there */
	if (f_map_entry_in_bosl(bosl, entry)) {
		e = e_to_bosl(bosl, entry);
		cnt = length - e;
		if (cnt > size)
			cnt = size;
		weight = bosl_weight(iter, bosl->page, e, cnt);
		size -= cnt;
		if (size == 0)
			return weight;
		node_idx++;
	}

	/* For all next BoSses */
	do {
		rcu_read_lock();
		node = cds_ja_lookup_above_equal(map->bosses,
						 node_idx, &idx);
		if (node == NULL) {
			rcu_read_unlock();
			break;
		}

		/* Account for entries when there is no BoS */
		cnt = length * (idx - node_idx);
		if (size <= cnt) {
			rcu_read_unlock();
			break;
		}
		size -= cnt;

		bosl = container_of(node, F_BOSL_t, node);
		rcu_read_unlock();

		/* Add weight of entries in this BoS */
		cnt = min(size, length);
		weight += bosl_weight(iter, bosl->page, 0, cnt);
		size -= cnt;

		node_idx = idx + 1;
	} while (size > 0);

	/* TODO: Use per-thread lock count */
	rcu_quiescent_state();
	return weight;
}


