/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */

#include "f_map.h"

//#include <assert.h>
#include <unistd.h>

#define e_to_bosl(bosl, e) (e - bosl->entry0)


static F_BOSL_t *bosl_alloc(size_t size)
{
	F_BOSL_t *bosl;

	bosl = (F_BOSL_t *) calloc(sizeof(F_BOSL_t), 1);
	if (bosl) {
		if (posix_memalign((void**)&bosl->page, 4096, size)) {
			free(bosl);
			bosl = NULL;
		} else
			memset(bosl->page, 0, size);
	}
	pthread_spin_init(&bosl->dirty_lock, PTHREAD_PROCESS_PRIVATE);
	pthread_rwlock_init(&bosl->rwlock, NULL);
	return bosl;
}

static void bosl_free(F_BOSL_t *bosl)
{
	pthread_rwlock_destroy(&bosl->rwlock);
	pthread_spin_destroy(&bosl->dirty_lock);
	free(bosl->page);
	free(bosl);
}

static inline void _f_map_mark_pu_dirty_bosl(F_BOSL_t *bosl, uint64_t pu)
{
	pthread_spin_lock(&bosl->dirty_lock);
	set_bit(pu, bosl->dirty);
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
	unsigned int entry_sz = map->geometry.entry_sz;
	unsigned long *p;

	if (f_map_is_structured(map)) {
		/* size in bytes */
		assert(entry_sz % 8 == 0);
		p = bosl->page + e*entry_sz/sizeof(long);
	} else {
		/* size in bits */
		assert(entry_sz == 1 || entry_sz == 2);
		p = bosl->page + e*entry_sz/BITS_PER_LONG;
	}
	return p;
}

/* Return a poiner to the entry in BoS or NULL if out of BoS range */
static unsigned long *bosl_ffind(F_BOSL_t *bosl, uint64_t e)
{
	if (f_map_entry_in_bosl(bosl, e))
		return _bosl_ffind(bosl, e_to_bosl(bosl, e));
	return NULL;
}

/* */
void copy_values_to_bosl(F_BOSL_t *bosl_to, uint64_t off_to,
    unsigned long *from, uint64_t off_from, size_t size)
{
	F_MAP_t *map = bosl_to->map;
	unsigned int entry_sz = map->geometry.entry_sz;
	unsigned long *to = bosl_to->page;
	bool bmap = !f_map_is_structured(map);
	unsigned int per_long, per_byte;

	if (bmap) {
		per_byte = 8/entry_sz;
		size /= per_byte;
		per_long = per_byte*sizeof(long);
		to += off_to/per_long;
		from += off_from/per_long;
	} else {
		size *= entry_sz;
		per_long = entry_sz/sizeof(long);
		to += off_to*per_long;
		from += off_from*per_long;
	}
	memcpy(to, from, size);
	bosl_to->loaded = 1;
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
	F_ITER_t *it = NULL;
	unsigned int part, parts, pu_per_bos, e_per_pu, pu_factor;
	unsigned int i, count, intl;
	size_t size;
	ssize_t rcv_cnt;
	uint64_t *offsets, *off, *keys;
	int map_id, ret = 0;

	if (map == NULL)
		return -1;

	parts = map->parts;
	offsets = (uint64_t *) calloc(sizeof(uint64_t), parts);
	keys = (uint64_t *) calloc(sizeof(uint64_t), parts);
	if (!offsets || !keys)
		return -ENOMEM;

	pu_per_bos = map->geometry.bosl_pu_count;
	intl = 1U << map->geometry.intl_factor;
	pu_factor = map->geometry.pu_factor;
	e_per_pu = 1U << pu_factor;
	map_id = map->id;

	/* Allocate I/O buffer */
	bos_buf = bosl_alloc(map->bosl_sz);

	/* New unconditional map iterator */
	it = f_map_new_iter(map, F_NO_CONDITION);

	/* Until we reach the end on all partitions */
	count = map->own_part?1:parts;
	do {
		/* For each map partition */
		for (part = 0; part < parts; part++) {
			if (map->own_part && part != map->part)
				continue;
 // printf(" f_map_load parts:%u count:%u part:%u\n", parts, count, part);

			off = &offsets[part];
			if (*off == 0U)
				*off = part * intl; /* First PU in range */
			else if (*off == ~(0UL))
				continue; /* the partition end reached */

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

			/* For all buffer PUs */
			for (i = 0; size > 0; i++, size--) {
				uint64_t e, pu;

				e = keys[i] * e_per_pu;
 //printf("      i:%u e:%lu\n", i, e);
				if (!f_map_prt_has_global(map, e, part)) {
					/* TODO: Need a special case for re-partitioning */
					break;
				}
				e = (map->own_part)? f_map_prt_to_local(map, e) : e;
				/* Prepare BoS */
				assert (f_map_seek_iter(it, e));
				/* copy values */
				e = e_to_bosl(it->bosl, e);
				copy_values_to_bosl(it->bosl, e,
						    bos_buf->page, i * e_per_pu,
						    e_per_pu);
				/* mark PU dirty */
				pu = e >> pu_factor;
				_f_map_mark_pu_dirty_bosl(it->bosl, pu);
			}
		}
	} while (count > 0);
	map->loaded = 1;

_exit:
	f_map_free_iter(it);
	free(offsets);
	free(keys);
	bosl_free(bos_buf);
	return ret;
}

/* Update (load from KV store) only map entries given in the stripe list */
int f_map_update(F_MAP_t *map, F_STRIPE_HEAD_t *stripes)
{
	int ret;

	return ret;
}

/* f_map_flush - Flush map: put all 'dirty' KVs of all BoSses to KV store */
int f_map_flush(F_MAP_t *map)
{
	int ret;

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
static inline bool _check_iter_cond_bbit(F_ITER_t *it) {
	return test_bbit_patterns(it->entry % BBITS_PER_LONG,
				  it->cond.pset, it->word_p);
}

static inline bool __check_iter_cond_vf(const F_ITER_t *it, const F_PU_VAL_t *v) {
	return !!(it->cond.vf_get(it->vf_arg, v));
}

static inline bool _check_iter_cond_vf(F_ITER_t *it) {
	F_BOSL_t *bosl = it->bosl;
	unsigned long *p = _bosl_ffind(bosl, e_to_bosl(bosl, it->entry));
	int rc = __check_iter_cond_vf(it, (F_PU_VAL_t *)p);

	return rc;
}

static inline bool check_iter_cond(F_ITER_t *iter)
{
	return ((iter->cond.pset == 0U) ||
		(f_map_is_bbitmap(iter->map)? &_check_iter_cond_bbit :
					&_check_iter_cond_vf)(iter));
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
	} else if (f_map_is_bbitmap(it->map)) {
		e = find_next_bbit(bosl->page, it->cond.pset, length, e);
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
	F_ITER_t *iter = (F_ITER_t *) calloc(sizeof(F_ITER_t), 1);
	uint64_t c = cond.pset;

	iter->map = map;
	iter->entry--; /* invalid entry */
	//iter->bosl = NULL;
	iter->cond.pset = c;
	if (f_cond_has_vf(cond))
		iter->vf_arg = calloc(sizeof(long), 1);

	return iter;
}

void f_map_free_iter(F_ITER_t *iter)
{
	if (f_cond_has_vf(iter->cond))
		free(iter->vf_arg);
	free(iter);
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
#if 0
	/* check condition */
	if (check_iter_cond(it))
		return it;

	/* slow path */
	it = f_map_next(it);
#endif
	return it;
}

/*
 * f_map_next
 * Get iterator for the next entry which matches the iterator's condition
 * or return NULL.
 */
F_ITER_t *f_map_next(F_ITER_t *iter)
{
	F_MAP_t *map = iter->map;
	struct cds_ja_node *node;
	uint64_t node_idx, idx;
	uint64_t length = map->bosl_entries;
	bool bbitmap = f_map_is_bbitmap(map);

	/* iter++ */
	iter->entry++;

	/* fast path? */
	node_idx = iter->entry / length;
	if (f_map_entry_in_bosl(iter->bosl, iter->entry)) {
		/* use current BoS */
		if (bbitmap && iter->entry &&
		    (iter->entry % BBITS_PER_LONG == 0))
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
			iter = NULL;
			break;
		}
		iter->bosl = container_of(node, F_BOSL_t, node);
		rcu_read_unlock();

		iter->entry = idx * length;
		if (bbitmap)
			iter->word_p = iter->bosl->page;
		node_idx = idx + 1;
	} while (!bosl_find_cond(iter));

	/* TODO: Use per-thread lock count */
	rcu_quiescent_state();
	return iter;
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
    uint64_t start, uint64_t len)
{
	bool bbitmap = f_map_is_bbitmap(it->map);

	if (bbitmap)
		return __bbitmap_weight(p, it->cond.pset, start, len);
	else
		return bosl_weight_vf(it, p, start, len);;
}

/*
 * f_map_weight
 *
 * Return the number of entries which matches the iterator's condition
 * within given size.
 */
uint64_t f_map_weight(const F_ITER_t *iter, size_t size)
{
	F_BOSL_t *bosl = iter->bosl;
	F_MAP_t *map = iter->map;
	struct cds_ja_node *node;
	uint64_t cnt, node_idx, idx;
	uint64_t weight = 0;
	uint64_t e, entry = iter->entry;
	uint64_t length = map->bosl_entries;

	node_idx = entry / length;
	/* If we have the current BoS, weight entries there */
	if (f_map_entry_in_bosl(bosl, entry)) {
		e = entry - node_idx*length;
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
		cnt = length * (idx - node_idx + 1);
		if (size <= cnt) {
			rcu_read_unlock();
			break;
		}
		size -= cnt;

		bosl = container_of(node, F_BOSL_t, node);
		rcu_read_unlock();

		/* Add weight of entries in this BoS */
		cnt = min(size, length);
		weight = bosl_weight(iter, bosl->page, 0, cnt);
		size -= cnt;

		node_idx = idx + 1;
	} while (size > 0);

	/* TODO: Use per-thread lock count */
	rcu_quiescent_state();
	return weight;
}


