/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */
#include <assert.h>
#include <fcntl.h> /* For O_* constants */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "f_map.h"
#include "famfs_bitmap.h"
#include "famfs_error.h"
#include "list.h"


#define e_to_bosl(bosl, e)	((e) - (bosl)->entry0)
#define is_iter_reset(it)	(it->entry == ~0LU)


static inline unsigned long *bosl_page_alloc(size_t size)
{
	unsigned long *p;

	if (posix_memalign((void**)&p, 4096, size))
		return NULL;
	memset(p, 0, size);
	return p;
}

static void bosl_init(F_BOSL_t *bosl)
{
	pthread_spin_init(&bosl->dirty_lock, PTHREAD_PROCESS_PRIVATE);
	pthread_rwlock_init(&bosl->rwlock, NULL);
	atomic_inc(&bosl->claimed);
}

static F_BOSL_t *_bosl_alloc(unsigned long *page, unsigned int map_shm)
{
	F_BOSL_t *bosl;

	bosl = (F_BOSL_t *) calloc(sizeof(F_BOSL_t), 1);
	if (bosl) {
		bosl_init(bosl);
		bosl->page = page;
		bosl->shm = map_shm;
	}
	return bosl;
}

static F_BOSL_t *bosl_alloc(size_t size, unsigned int map_shm)
{
	F_BOSL_t *bosl;
	unsigned long *page;

	if ((page = bosl_page_alloc(size)) == NULL)
		return NULL;
	bosl = _bosl_alloc(page, map_shm);
	if (bosl == NULL)
		free(page);
	return bosl;
}

static void bosl_free(F_BOSL_t *bosl)
{
	/* BoS claimed accounting */
	int c = atomic_dec_return(&bosl->claimed);

	/* DEBUG */
	if (c != 0) {
		dbg_printf("free map:%p count:%d e0:%lu\n",
			   bosl->map, c, bosl->entry0);
		assert(0);
	}

	pthread_rwlock_destroy(&bosl->rwlock);
	pthread_spin_destroy(&bosl->dirty_lock);
	if (!f_map_in_shmem(bosl))
		free(bosl->page);
	if (bosl->shm != F_MAPMEM_SHARED_S)
		free(bosl);
}

/* Increment BoS use counter */
static int acquire_bosl(F_BOSL_t *bosl)
{
	if (bosl->map && bosl->map->locking >= F_MAPLOCKING_BOSL)
		return pthread_rwlock_rdlock(&bosl->rwlock);
	atomic_inc(&bosl->claimed);
	return 0;
}

/* Decrement BoS use counter that set by iter_get_bosl/get_bosl */
static int put_bosl(F_BOSL_t *bosl)
{
	if (!bosl)
		return 0;
	if (bosl->map && bosl->map->locking >= F_MAPLOCKING_BOSL)
		return pthread_rwlock_unlock(&bosl->rwlock);
	return atomic_dec_return(&bosl->claimed);
}

static void bosl_free_cb(struct rcu_head *head)
{
	F_BOSL_t *bosl = container_of(head, struct f_bosl_, head);

	bosl_free(bosl);
}

static void rcu_bosl_free(F_BOSL_t *bosl)
{
	call_rcu(&bosl->head, bosl_free_cb);
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
		rcu_bosl_free(bosl);
	}
_err:
	rcu_read_unlock();
	return ret;
}

static F_MAP_t *map_alloc(int key_size)
{
	F_MAP_t *map;

	map = (F_MAP_t *) calloc(sizeof(F_MAP_t), 1);
	if (map) {
		map->bosses = cds_ja_new(key_size); /* Usually 64-bit key */
		pthread_spin_init(&map->bosl_lock, PTHREAD_PROCESS_PRIVATE);
		//pthread_mutex_init(&map->pu_lock, NULL);
	}
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
	rcu_quiescent_state();
	pthread_spin_destroy(&map->bosl_lock);
	//pthread_mutex_destroy(&map->pu_lock);
	if (map->shm != F_MAPMEM_SHARED_S)
		free(map);
	return 0;
}

static int _map_insert_bosl(F_MAP_t *map, uint64_t entry, F_BOSL_t **bosl_p,
    unsigned long *page)
{
	F_BOSL_t *bosl = NULL;
	struct cds_ja_node *node;
	uint64_t node_idx, length;
	int ret = 0;

	if (map->shm == F_MAPMEM_SHARED_S) {
		if (bosl_p && (bosl = *bosl_p)) {
			bosl_init(bosl);
			bosl->page = page;
			bosl->shm = map->shm;
		}
	}
	if (!bosl) {
		if (page)
			bosl = _bosl_alloc(page, map->shm);
		else
			bosl = bosl_alloc(map->bosl_sz, map->shm);
		if (!bosl)
			return -ENOMEM;
	}

	length = map->bosl_entries;
	//bosl->loaded = map->loaded;
	node_idx = entry / length;
	bosl->entry0 = node_idx * length;

	rcu_read_lock();
	node = cds_ja_add_unique(map->bosses, node_idx, &bosl->node);
	if (node != &bosl->node) {
		bosl_free(bosl);
		bosl = container_of(node, F_BOSL_t, node);
		rcu_read_unlock();
		dbg_printf(" e:%lu - EEXIST\n", node_idx);

		ret = -EEXIST;
		goto _ret;
	}
	pthread_spin_lock(&map->bosl_lock);
	map->nr_bosl++;
	pthread_spin_unlock(&map->bosl_lock);
	rcu_read_unlock();

	bosl->map = map;
	dbg_printf(" e:%lu - added, bosl:%p\n", node_idx, bosl);

_ret:
	/* TODO: Use per-thread lock count */
	rcu_quiescent_state();

	if (bosl_p)
		*bosl_p = bosl;
	return ret;
}

static int sbosl_alloc_page(F_MAP_t *m, uint64_t entry, unsigned long **pp);
/* Add BoS to Judy array; return 0 or EEXIST */
static int map_insert_and_get_bosl(F_MAP_t *m, uint64_t entry,
    F_BOSL_t **bosl_p)
{
	unsigned long *page = NULL;
	int rc;

	if (f_map_in_shmem(m)) {
		struct cds_ja_node *node;

		/* Allocate page only when need for a new bosl */
		rcu_read_lock();
		node = cds_ja_lookup(m->bosses, entry / m->bosl_entries);
		if (node) {
			*bosl_p = container_of(node, F_BOSL_t, node);
			rcu_read_unlock();

			return -EEXIST;
		}
		rcu_read_unlock();

		if (!f_shmap_owner(m)) {
		    err("illegitimate insert BoS operation for map id:%d shm:%d",
			m->id, m->shm);
			return -EINVAL;
		}

		if ((rc = sbosl_alloc_page(m, entry, &page)))
			return rc;
	}
	*bosl_p = NULL;

	/* TODO: Implement get/put bosl */
	return _map_insert_bosl(m, entry, bosl_p, page);
}

static inline F_BOSL_t *map_insert_bosl(F_MAP_t *map, uint64_t entry)
{
	F_BOSL_t *bosl = NULL;

	assert( map_insert_and_get_bosl(map, entry, &bosl) == 0 );
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
static unsigned long *bosl_ffind(F_BOSL_t *bosl, uint64_t entry)
{
	if (f_map_entry_in_bosl(bosl, entry))
		return _bosl_ffind(bosl, e_to_bosl(bosl, entry));
	return NULL;
}

/* Copy one PU from buffer 'from' to BoS @pu_to */
static void copy_pu_to_bosl(F_BOSL_t *bosl_to, uint64_t pu_to,
    unsigned long *from)
{
	F_MAP_t *map = bosl_to->map;
	size_t size;
	unsigned long *to;

	assert(pu_to < F_MAP_MAX_BOS_PUS);
	assert(pu_to < map->geometry.bosl_pu_count);
	size = f_map_pu_size(map);
	//from = buf_from + f_map_pu_p_sz(map, pu_from, from);
	to   = bosl_to->page + f_map_pu_p_sz(map, pu_to, to);

	/* No lock! */
	memcpy(to, from, size);
	//bosl_to->loaded = 1;
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

static int _map_init(F_MAP_t **map_p, F_MAPTYPE_t type, int entry_sz, size_t bosl_sz,
    F_MAPLOCKING_t locking, int key_size)
{
	F_MAP_t *map = *map_p;
	size_t psize = getpagesize();

	if (!IN_RANGE(key_size, 31, 64))
		return -EINVAL;

	/* Safe defaults */
	switch (type) {
	case F_MAPTYPE_BITMAP:
		if (!IN_RANGE(entry_sz, 1, 2))
			entry_sz = 2; /* claim vector has 2 bits per entry */
		break;
	case F_MAPTYPE_STRUCTURED:
		if (entry_sz <= 0 || (entry_sz % 8))
			goto _err;
		break;
	default: goto _err;
	}
	if (bosl_sz == 0)
		bosl_sz = psize;
	else
		bosl_sz = ROUND_UP(bosl_sz, psize);
	/* 0: F_MAPLOCKING_DEFAULT */
	assert (IN_RANGE(locking, 0, F_MAPLOCKING_END-1));

	if (map == NULL) {
		map = map_alloc(key_size);
	} else {
		map->bosses = cds_ja_new(key_size); /* 64-bit key */
		pthread_spin_init(&map->bosl_lock, PTHREAD_PROCESS_PRIVATE);
	}
	if (map == NULL)
		return -ENOMEM;

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
		map->geometry.bosl_pu_count = bosl_sz >>		\
				(map->geometry.pu_factor-3 + entry_sz-1);
	}
	map->geometry.intl_factor = map->geometry.pu_factor;
	/* Calculated */
	map->bosl_entries = map->geometry.bosl_pu_count <<
				map->geometry.pu_factor;
	/* init locks */
	map->locking = locking;

	/* Sanity check */
	assert (map->geometry.intl_factor >=
		map->geometry.pu_factor);
	assert (IN_RANGE(map->geometry.bosl_pu_count,
			 1, F_MAP_MAX_BOS_PUS));
	*map_p = map;
	return 0;

_err:
	if (map)
		map_free(map);
	return -1;
}


/*
 * API
 */

/* f_map_init - Create map in memory */
F_MAP_t *f_map_init(F_MAPTYPE_t type, int entry_sz, size_t bosl_sz,
    F_MAPLOCKING_t locking)
{
	F_MAP_t *m = NULL;

	/* new map with 64-bit keys */
	_map_init(&m, type, entry_sz, bosl_sz, locking, 64);
	return m;
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
	if (map == NULL || parts <= 0 ||
	    !IN_RANGE(part_0, 0, parts-1) || !IN_RANGE(node, 0, parts-1))
		return -EINVAL;

	map->parts = parts;
	map->part = (node + part_0) % parts;
	map->own_part = global?0:1;
	return 0;
}

static void shmap_free(F_MAP_SB_t *priv_sb);

/* Free map */
void f_map_exit(F_MAP_t *map)
{
    /* Unmap the shared map */
    if (f_map_in_shmem(map)) {
	F_MAP_SB_t *priv_sb;
	F_MAP_t *sm;

	map_free(map);
	rcu_quiescent_state();

	priv_sb = map->shm_sb;
	assert( priv_sb );
	sm = priv_sb->super_map;
	map_free(sm);
	rcu_quiescent_state();

	/* Unmap and free shared map's supermap */
	shmap_free(priv_sb);

    /*if (f_shmap_owner(map))
	return; */
    } else
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
	F_MAP_INFO_t info;
	uint64_t recs_per_slice;
	int rc;

	if (m->geometry.intl_factor < m->geometry.pu_factor)
		return -1;
	//recs_per_slice = 1U << (m->geometry.intl_factor - m->geometry.pu_factor);
	recs_per_slice = 1U << m->geometry.intl_factor;

	/* Attach map to KV store global index */
	if (f_map_is_structured(m)) {
		/* Create global index for Slab Map */
		rc = f_create_persistent_sm(layout_id, recs_per_slice, &info);
	} else {
		/* Create global index index for Claim vector */
		rc = f_create_persistent_cv(layout_id, recs_per_slice, &info);
	}

	/* On success, set map id (table index #) and RO flag */
	if (rc == 0) {
		m->reg_id = layout_id;
		m->id = info.map_id;
		f_map_set_ro(m, info.ro);
	}
	return rc;
}

/* f_map_load - Load all KVs for [one partition of] the registered map */
int f_map_load_cb(F_MAP_t *map, F_MAP_LOAD_CB_fn cb, void *cb_arg)
{
	F_ITER_t *it = NULL;
	unsigned long *buf, *bos_buf = NULL;
	unsigned int part, parts, pu_per_bos, pu_factor;
	unsigned int i, count, intl;
	size_t size;
	size_t total = 0, pu_cnt = 0;
	ssize_t rcv_cnt;
	uint64_t *offsets, *off, *keys;
	int map_id, ret = -ENOMEM;

	if (map == NULL)
		return -1;
	if (map->id == -1)
		return 0; /* no DB backend for in-memory map */

	parts = map->parts;
	pu_per_bos = map->geometry.bosl_pu_count;
	offsets = (uint64_t *) calloc(sizeof(uint64_t), parts);
	keys = (uint64_t *) calloc(sizeof(uint64_t), pu_per_bos);
	map_id = map->id;
	/* Allocate I/O buffer */
	bos_buf = bosl_page_alloc(map->bosl_sz);
	if (!offsets || !keys || !bos_buf)
		goto _exit;

	intl = 1U << map->geometry.intl_factor;
	pu_factor = map->geometry.pu_factor;

	/* New unconditional map iterator */
	it = f_map_new_iter_all(map);
	if (!it)
		goto _exit;

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

			dbg_printf("load map id:%d part:%u @%lu\n",
				   map_id, part, *off);

			/* BGET/MDHIM_GET_NEXT pu_per_bos entries */
			size = pu_per_bos;
			rcv_cnt = f_db_bget(bos_buf, map_id, keys, size, off,
					    F_PS_GET_NEXT);
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
			} else {
				/* Round key up to next slice if out of partition */
				f_map_pu_round_up(*off, map->geometry.intl_factor,
						  parts, part);
				// *off += intl*parts;
			}
			total += size; /* stats */

			/* For all buffer PUs */
			for (i = 0; size > 0; i++, size--) {
				uint64_t e, pu;

				e = keys[i];
				if (!f_map_has_globals(map)) {
					/* TODO: Need a special case for re-partitioning */
					if (!f_map_prt_has_global(map, e, part)) {

						dbg_printf(" L%d:%lu/%lu\n",
						    map->part, e/map->bosl_entries,
						    (e % map->bosl_entries) >> pu_factor);

						continue;
					}
					e = f_map_prt_to_local(map, e);
				}
				pu_cnt++; /* stats */

				/* Prepare BoS */
				assert (f_map_seek_iter(it, e));
				/* Copy PU values */
				pu = e_to_bosl(it->bosl, e) >> pu_factor;
				buf = bos_buf + f_map_pu_p_sz(map, i, buf);
				copy_pu_to_bosl(it->bosl, pu, buf);
				/* Set PU dirty bit */
				if (map->true0)
				    _f_map_mark_pu_dirty_bosl(it->bosl, pu);
				/* Callback */
				if (cb)
					cb(e, cb_arg, (F_PU_VAL_t *)it->word_p);
			}
		}
	} while (count > 0);
	map->loaded = 1;
	ret = 0;
_exit:
	/* DEBUG */
	if (total != pu_cnt || ret != 0)
		dbg_printf("p%d: map:%d Load totals: read %zu, got %zu PUs rc:%d\n",
			   map->part, map_id, total, pu_cnt, ret);
	f_map_free_iter(it);
	free(bos_buf);
	free(offsets);
	free(keys);
	return ret;
}

static void keyset_free(F_MAP_KEYSET_t *keyset)
{
	free(keyset->keys);
	free(keyset);
}

static int compare_uint64(const void *a, const void *b)
{
    const uint64_t *ia = (const uint64_t *)a;
    const uint64_t *ib = (const uint64_t *)b;
    return (ia > ib) - (ia < ib);
}

static int keyset_part(F_MAP_KEYSET_t *to, F_MAP_t *map, unsigned int part,
    F_MAP_KEYSET_t *from)
{
	unsigned int i, count = 0;
	uint64_t entry;

	to->keys = calloc(from->_count, sizeof(uint64_t));
	if (!to->keys)
		return -ENOMEM;

	switch (from->key_sz) {
	case 8: /* uint64_t */
		for (i = 0; i < from->_count; i++) {
			entry = from->keys_64[i];
			if (!f_map_prt_has_global(map, entry, part))
				continue;
			to->keys_64[count++] = entry;
		}
		break;
	case 4: /* uint32_t */
		for (i = 0; i < from->_count; i++) {
			entry = from->keys_32[i];
			if (!f_map_prt_has_global(map, entry, part))
				continue;
			to->keys_64[count++] = entry;
		}
		break;
	default: err("Unsupported map key size:%u", from->key_sz);
		assert(0);
	}
	qsort(to->keys_64, count, sizeof(uint64_t), compare_uint64);
	to->_count = count;
	to->key_sz = from->key_sz;
	return 0;
}

/* Update (load from KV store) only map entries given in 'keyset' */
int f_map_update(F_MAP_t *map, F_MAP_KEYSET_t *keyset)
{
	F_MAP_KEYSET_t *kset_parted = NULL;
	F_ITER_t *it = NULL;
	unsigned long *buf, *bos_buf = NULL;
	unsigned int part, parts, pu_per_bos, pu_factor;
	unsigned int i, k, count;
	size_t size;
	size_t total = 0, pu_cnt = 0;
	ssize_t rcv_cnt;
	uint64_t *keys;
	int map_id, ret = -ENOMEM;

	if (map == NULL)
		return -1;
	if (map->id == -1)
		return 0; /* no DB backend for in-memory map */

	parts = map->parts;
	pu_per_bos = map->geometry.bosl_pu_count;
	keys = (uint64_t *) malloc(pu_per_bos*sizeof(uint64_t));
	kset_parted = (F_MAP_KEYSET_t *) calloc(1, sizeof(F_MAP_KEYSET_t));
	/* Allocate I/O buffer */
	bos_buf = bosl_page_alloc(map->bosl_sz);
	if (!kset_parted || !keys || !bos_buf)
		goto _exit;

	pu_factor = map->geometry.pu_factor;
	map_id = map->id;

	/* New unconditional map iterator */
	it = f_map_new_iter_all(map);
	if (!it)
		goto _exit;

	/* For each map partition */
	for (part = 0; part < parts; part++) {
		if (part != map->part && !f_map_has_globals(map))
			continue;

		if ((ret = keyset_part(kset_parted, map, part, keyset)))
			goto _exit;
		count = kset_parted->_count;
		k = 0;

		while (count > 0) {

			/* BGET/MDHIM_GET_EQ 'size' keys */
			size = count>pu_per_bos? pu_per_bos:count;

			dbg_printf("update map id:%d (reg#%d) part:%u\r\n%zu keys:",
				   map_id, map->reg_id, part, size);

			for (i = 0; i < size; i++) {
				keys[i] = kset_parted->keys_64[k++];
#ifdef DEBUG_MAP
				printf(" %lu", keys[i]);
#endif
			}
			dbg_printf("");

			rcv_cnt = f_db_bget(bos_buf, map_id, keys, size, NULL,
					    F_PS_GET_EQ);
			if (rcv_cnt != (ssize_t)size) {
				ret = rcv_cnt<0? rcv_cnt:-ENOENT;
				goto _exit;
			}
			count -= size;
			total += size; /* stats */

			/* For all buffer PUs */
			for (i = 0; size > 0; i++, size--) {
				uint64_t e, pu;

				e = keys[i];
				if (!f_map_has_globals(map)) {
					/* TODO: Need a special case for re-partitioning */
					if (!f_map_prt_has_global(map, e, part)) {
						dbg_printf(" L%d:%lu/%lu\n",
						    map->part, e/map->bosl_entries,
						    (e % map->bosl_entries) >> pu_factor);

						continue;
					}
					e = f_map_prt_to_local(map, e);
				}
				pu_cnt++; /* stats */

				/* Prepare BoS */
				assert (f_map_seek_iter(it, e));

				/* Copy PU values */
				pu = e_to_bosl(it->bosl, e) >> pu_factor;
				buf = bos_buf + f_map_pu_p_sz(map, i, buf);

				pthread_spin_lock(&it->bosl->dirty_lock);
				copy_pu_to_bosl(it->bosl, pu, buf);

				/* Clear PU dirty bit */
				//_f_map_clear_pu_dirty_bosl(it->bosl, pu);
				clear_bit64(pu, it->bosl->dirty);
				pthread_spin_unlock(&it->bosl->dirty_lock);
			}
		}
	}
	//map->loaded = 1;
	assert( total == pu_cnt );
	ret = 0;

_exit:
	/* DEBUG */
	if (ret != 0)
		dbg_printf("p%d: map:%d Update totals: update %zu PUs rc:%d\n",
			   map->part, map_id, total, ret);
	f_map_free_iter(it);
	free(bos_buf);
	keyset_free(kset_parted);
	free(keys);
	/* Return error (negative) or updated PU count */
	return ret;
}

/* Reset iterator so it could be re-used */
static void iter_reset(F_ITER_t *it) {
	it->entry = 0;
	it->entry--; /* invalid entry */
	it->bosl = NULL;
	it->at_end = 0;
}

/* Get iterator's BoS; next_bosl/put_bosl should put it. */
static F_BOSL_t *iter_get_bosl(F_ITER_t *it) {
	F_BOSL_t *bosl = it->bosl;

	acquire_bosl(bosl);
	return bosl;
}

/* Iterate over dirty PUs on global maps.
 * It's aware of partition on local (own_part:1) maps.
 * This call takes and hold BoS R/W lock(s) - until freed.
 */
static F_ITER_t *iter_next_dirty_pu(F_ITER_t *iter)
{
	F_MAP_t *map = iter->map;
	F_BOSL_t *bosl;
	struct cds_ja_node *node;
	uint64_t node_idx, idx;
	uint64_t entry, cpu, bosl_pu0;
	unsigned int pu_factor, factor, pu_per_bos;
	unsigned int partition = 0;
	unsigned long *dirty = NULL;
	size_t dirty_sz;
	bool global;

	global = f_map_has_globals(map);
	if (global)
	    partition = iter->cond.partition;
	pu_factor = map->geometry.pu_factor;
	/* DB interleave PU factor */
	factor = map->geometry.intl_factor - pu_factor;
	pu_per_bos = map->geometry.bosl_pu_count;
	/* Dirty PU bitmap size, bytes */
	dirty_sz = F_BOSL_DIRTY_SZ(map);
	assert(dirty_sz <= sizeof(*dirty)*F_BOSL_DIRTY_MAX);

	dirty = (unsigned long *) malloc(dirty_sz);
	if (dirty == NULL) return NULL;

	/* cpu: continuous PU number */
	if (unlikely(is_iter_reset(iter))) {
	    cpu = 0;
	} else {
	    /* Progress to the next PU */
	    cpu = (iter->entry >> pu_factor) + 1;
	}

	/* Round PU up to next slice if out of partition in global map */
	if (global)
	    f_map_pu_round_up(cpu, factor, map->parts, partition);

	entry = cpu << pu_factor;
	node_idx = entry / map->bosl_entries;
	bosl = iter->bosl;
	if (!f_map_entry_in_bosl(bosl, entry))
		goto _find_bos;
	bosl_pu0 = node_idx * pu_per_bos;


	/* For each BoS in Judy array */
	while (1) {
	    unsigned int pu; /* BoS PU number */

	    /* Copy dirty bitmap under lock */
	    pthread_spin_lock(&bosl->dirty_lock);
	    memcpy(dirty, bosl->dirty, dirty_sz);
	    pthread_spin_unlock(&bosl->dirty_lock);

	    /* Search for dirty PU in current BoS */
	    do {
		pu = cpu - bosl_pu0;
		pu = find_next_bit(dirty, pu_per_bos, pu);
		cpu = bosl_pu0 + pu;
		entry = cpu << pu_factor;
		cpu++;
	    } while (pu < pu_per_bos &&
		/* ignore other partitions if map is global */
		global && !f_map_prt_has_global(map, entry, partition) &&
		/* ensure PU belongs to 'partition' */
		f_map_pu_round_up(cpu, factor, map->parts, partition));

	    /* Is there next dirty PU in BoS? */
	    if (pu < pu_per_bos) {
		/* Yes; set iterator to 'e' and return it */
		iter->entry = entry;
		iter->word_p = _bosl_ffind(bosl, pu << pu_factor);
		iter->bosl = bosl;
		break;
	    }

	    /* Leave BoS */
	    node_idx++;
_find_bos:
	    put_bosl(bosl);
	    iter->bosl = NULL;

	    rcu_read_lock();
	    node = cds_ja_lookup_above_equal(map->bosses,
					     node_idx, &idx);
	    if (node == NULL) {
		rcu_read_unlock();
		iter = NULL; /* No dirty PU in map */
		break;
	    }
	    bosl = container_of(node, F_BOSL_t, node);
	    rcu_read_unlock();

	    /* Enter BoS */
	    acquire_bosl(bosl);
	    node_idx = idx;
	    cpu = bosl_pu0 = node_idx * pu_per_bos;
	    /* Round PU up to next slice if out of partition in global map */
	    if (global)
		f_map_pu_round_up(cpu, factor, map->parts, partition);
	}

	/* TODO: Use per-thread lock count */
	rcu_quiescent_state();
	free(dirty);
	return iter;
}

/*
 * f_map_flush
 * Flush map: put all 'dirty' PUs of all BoSses to KV store.
 * If the whole PU is zeroed, this flush would delete the PU.
 */
int f_map_flush(F_MAP_t *map)
{
	F_BOSL_t *bos_buf = NULL;
	F_ITER_t *it = NULL;
	F_ITER_t *iter = NULL;
	unsigned int part, parts, pu_per_bos, pu_factor;
	size_t size, value_len;
	void **keysp;
	uint64_t *keys = NULL;
	int map_id, ret = -ENOMEM;

	if (map == NULL)
	    return -1;

	if (map->id == -1)
	    return 0; /* no DB backend for in-memory map */

	if (f_map_is_ro(map))
	    return 0; /* read-only: running on client node */

	pu_per_bos = map->geometry.bosl_pu_count;
	assert(pu_per_bos <= F_MAP_MAX_BOS_PUS);
	keysp = (void **) malloc(sizeof(void *) * pu_per_bos);
	if (!keysp)
	    goto _err;
	keys = (uint64_t *) malloc(sizeof(uint64_t) * pu_per_bos);
	if (!keys)
	    goto _err;

	pu_factor = map->geometry.pu_factor;
	value_len = f_map_pu_size(map);
	map_id = map->id;
	parts = map->parts;

	/* Allocate I/O buffer */
	bos_buf = bosl_alloc(map->bosl_sz, 0);
	if (!bos_buf)
	    goto _err;
	bos_buf->map = map; /* map reference for bosl_is_pu_clean() */

	/* New iterator */
	iter = f_map_new_iter_all(map);
	if (!iter)
	    goto _err;

	/* For each map partition */
	for (part = 0; part < parts; part++) {
	    if (part != map->part /* && !f_map_has_globals(map) */)
		continue;

	    iter_reset(iter);
	    iter->cond.partition = part;
	    size = 0;
	    dbg_printf(" flush map id:%d part:%u\n", map_id, part);

	    /* For each dirty PU (in this partition if map is global)... */
	    do {
		if ((it = iter_next_dirty_pu(iter))) {
		    uint64_t pu, e;

		    /* Copy PU key */
		    e = it->entry;
		    if (!f_map_has_globals(map))
			e = f_map_prt_to_global(map, e);
		    keys[size] = e;
		    keysp[size] = &keys[size];

		    /* Copy PU value and clear dirty bit */
		    pu = e_to_bosl(it->bosl, it->entry) >> pu_factor;
		    copy_pu_from_bosl(bos_buf->page, size++,
				      it->bosl, pu);

		    /* Flush should not put/delete PUs in foreign partitions */
		    if (!f_map_prt_my_global(map, e)) {
			err(" e:%lu BoS:%lu PU:%lu",
			    e, it->bosl->entry0/map->bosl_entries, pu);
			assert (0); /* ...assert if it does */
		    }
		}

		/* There are PUs to flush */
		if (size == pu_per_bos || (size > 0 && !it)) {
		    unsigned int st = 0;
		    bool clean;

		    clean = bosl_is_pu_clean(bos_buf, 0);

		    dbg_printf("    number of keys:%zu clean:%d\n",
			       size, (int)clean);
		    do {
			unsigned int i, bunch;
			unsigned long *buf;

			/* Scan buffer for bunch of empty or non-empty PUs */
			for (i = st + 1; i < size; i++)
			    if (bosl_is_pu_clean(bos_buf, i) != clean)
				break;
			bunch = i - st;

			if (clean) {
			    /* Bulk DEL bunch of empty PUs */
			    ret = f_db_bdel(map_id, &keysp[st], bunch);
			    /* DEBUG */
			    if (0) {
				printf(" D%d", map->part);
				for (unsigned int j=st; j<bunch; j++) {
				    uint64_t ke = *((uint64_t *)keysp[j]);
				    printf(" %lu/%lu", ke/map->bosl_entries,
					   (ke % map->bosl_entries)>>pu_factor);
				}
				printf("\n");
			    }
			} else {
			    /* Bulk PUT bunch of PUs from buffer @st */
			    buf = bos_buf->page + f_map_pu_p_sz(map, st, buf);
			    ret = f_db_bput(buf, map_id, &keysp[st],
					    bunch, value_len);
			}
			if (ret) {
			    printf("map id:%d flush DB error:%d on %s\n",
				   map_id, ret, clean?"bdel":"bput");
			    goto _err;
			}

			clean = !clean;
			st = i;
		    } while (st < size);
		    size = 0;
		}
	    } while (it);
	}
	ret = 0;
_err:
	if (it)
		f_map_put_bosl(it->bosl);
	f_map_free_iter(iter);
	free(keys);
	free(keysp);
	if (bos_buf)
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

/* Clear KV dirty bit */
void f_map_clear_dirty(F_MAP_t *map, uint64_t entry) {
    F_BOSL_t *bosl = f_map_get_bosl(map, entry);

    if (bosl)
	_f_map_clear_pu_dirty_bosl(bosl,
		e_to_bosl(bosl, entry) >> map->geometry.pu_factor);
}

/* Test KV dirty bit */
int f_map_is_dirty(F_MAP_t *map, uint64_t entry) {
    F_BOSL_t *bosl = f_map_get_bosl(map, entry);
    uint64_t e = e_to_bosl(bosl, entry);
    int b;

    if (!bosl)
	return 0; /* no BoS */

    e >>= map->geometry.pu_factor; /* to PU number */
    pthread_spin_lock(&bosl->dirty_lock);
    b = test_bit64(e, bosl->dirty);
    pthread_spin_unlock(&bosl->dirty_lock);

    return b;
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
		p = _bosl_ffind(bosl, e_to_bosl(bosl, entry));
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
			p = _bosl_ffind(bosl, e_to_bosl(bosl, entry));
	}
	//assert(p);
	return p;
}

/*
 * BoS lookup in Judy sparse array by entry
 * Return BoS that contains this entry or NULL if no entry
 */
static F_BOSL_t *map_get_bosl(F_MAP_t *map, uint64_t entry)
{
	F_BOSL_t *bosl;
	struct cds_ja_node *node;

	rcu_read_lock();
	node = cds_ja_lookup(map->bosses, entry / map->bosl_entries);
	if (node == NULL) {
		rcu_read_unlock();

		dbg_printf("  ? e:%lu - not found! bosl_entries:%u\n",
			   entry / map->bosl_entries, map->bosl_entries);

		return NULL;
	}
	bosl = container_of(node, F_BOSL_t, node);
	rcu_read_unlock();

	dbg_printf("  e:%lu - bosl:%p\n",
		   entry / map->bosl_entries, bosl);
	return bosl;
}

static int shmap_read_all_bosses(F_MAP_t *m);
/*
 * f_map_get_bosl
 * BoS lookup in Judy sparse array by entry
 * Return BoS that contains this entry or NULL if no entry
 */
F_BOSL_t *f_map_get_bosl(F_MAP_t *map, uint64_t entry)
{
	F_BOSL_t *bosl;
	struct cds_ja_node *node;
	int rc, update = 1;

_get_bosl:
	rcu_read_lock();
	node = cds_ja_lookup(map->bosses, entry / map->bosl_entries);
	if (node == NULL) {
	    rcu_read_unlock();

	    /* Shared map reader may need SBoS update to retrieve recent BoS */
	    if (f_shmap_reader(map) && update--) {
		if ((rc = shmap_read_all_bosses(map))) {
		    err("f_map_get_bosl map id:%d error:%d "
			"- unable to read SHMEM!",
			rc, map->id);
		    return NULL;
		}
		goto _get_bosl;
	    }
	    dbg_printf("e0:%lu not found!\n",
		       ROUND_DOWN(entry, map->bosl_entries));
	    return NULL;
	}
	bosl = container_of(node, F_BOSL_t, node);
	rcu_read_unlock();

	/*
	dbg_printf("e0:%lu bosl:%p page:%p nr_bosl:%lu\n",
		   ROUND_DOWN(entry, map->bosl_entries),
		   bosl, bosl->page, bosl->map->nr_bosl);
	*/
	assert( map == bosl->map );
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

int f_map_put_bosl(F_BOSL_t *bosl) {
	return put_bosl(bosl);
}

/* Delete all BoS entries. */
int f_map_delete_bosl(F_MAP_t *map, F_BOSL_t *bosl)
{
	uint64_t length = map->bosl_entries;
	int ret;

	/* FIXME
	if ((ret = put_bosl(bosl)))
		return ret;
	*/

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
	rcu_bosl_free(bosl);
	rcu_read_unlock();

	/* TODO: Use per-thread lock count */
	rcu_quiescent_state();
	return ret;
}

static uint64_t max_bosl(F_MAP_t *map)
{
	uint64_t idx = 0;
	struct cds_ja_node *node;

	rcu_read_lock();
	node = cds_ja_lookup_below_equal(map->bosses, F_JA_MAX_KEY64, &idx);
	if (node)
		idx++;
	rcu_read_unlock();
	return idx;
}

static F_BOSL_t *_next_bosl(F_MAP_t *map, F_BOSL_t *bosl, uint64_t node_idx)
{
	struct cds_ja_node *node;

	(void)put_bosl(bosl);

	rcu_read_lock();
	node = cds_ja_lookup_above_equal(map->bosses, node_idx, NULL);
	if (node == NULL) {
		rcu_read_unlock();
		return NULL;
	}
	bosl = container_of(node, F_BOSL_t, node);
	(void)acquire_bosl(bosl);
	rcu_read_unlock();

	return bosl;
}

static F_BOSL_t *next_bosl(F_BOSL_t *bosl)
{
	return _next_bosl(bosl->map, bosl, bosl->entry0/bosl->map->bosl_entries+1);
}

static F_BOSL_t *get_bosl(F_MAP_t *map, uint64_t entry)
{
	return _next_bosl(map, NULL, entry/map->bosl_entries);
}


/*
 * Get/Set value
 */
/* Set 'e' in 'bosl' with 'setter' */
static void set_value_bosl(F_BOSL_t *bosl, uint64_t e, F_SETTER_t setter)
{
	F_MAP_t *map = bosl->map;
	unsigned long *p;

	p = _bosl_ffind(bosl, e);
	/* structured map? */
	if (f_map_is_structured(map)) {
		setter.vf_set(NULL, (F_PU_VAL_t *)p);
	} else {
		unsigned int bbits = map->geometry.entry_sz;

		switch (bbits) {
		case 1: set_bit((int)e % BITS_PER_LONG, p);
			break;
		case 2: set_bbit(e % BBITS_PER_LONG, setter.one_val, p);
			break;
		default: assert (0);
		}
	}
}


/*
 * Iterator
 */

/* Test bbitmap entry pattern */
static inline bool _check_iter_cond_bbit(const F_ITER_t *it)
{
	F_BOSL_t *bosl = it->bosl;

	return test_bbit_patterns(e_to_bosl(bosl, it->entry),
				  it->cond.pset, bosl->page);
}

static inline bool test_bit_patterns(int bit, int pset, unsigned long *page)
{
	switch (pset) {
	/* test zero */
	case 1: return !test_bit(bit, page);
	/* test one */
	case 2: return test_bit(bit, page);
	/* any */
	default: return true;
	}
}

/* Apply the bit pattern (B_PAT0, B_PAT1) to iterator value and return boolean */
static inline bool _check_iter_cond_bit(const F_ITER_t *it)
{
	F_BOSL_t *bosl = it->bosl;

	return test_bit_patterns((int)e_to_bosl(bosl, it->entry),
				 (int)it->cond.pset, bosl->page);
}

static inline bool __check_iter_cond_vf(const F_ITER_t *it, const F_PU_VAL_t *v)
{
	return !!(it->cond.vf_get(it->vf_arg, v));
}

static inline bool _check_iter_cond_vf(const F_ITER_t *it)
{
	return __check_iter_cond_vf(it, (F_PU_VAL_t *)it->word_p);
}

static inline bool _check_iter_cond(const F_ITER_t *it)
{
	return (f_map_is_structured(it->map)? &_check_iter_cond_vf :
		 f_map_is_bbitmap(it->map)? &_check_iter_cond_bbit :
				&_check_iter_cond_bit)(it);
}

static inline bool check_iter_cond(const F_ITER_t *it)
{
	if (f_map_has_true_zeros(it->map)) {
		F_MAP_t *m = it->map;
		uint64_t pu = e_to_bosl(it->bosl, it->entry) >> m->geometry.pu_factor;

		if (!test_bit64(pu, it->bosl->dirty))
			return false;
	}
	return (it->cond.pset == F_NO_CONDITION.pset || _check_iter_cond(it));
}

/* Find entry in this BoS that matches the iterator's condition */
static F_ITER_t *bosl_find_cond(F_ITER_t *it)
{
    F_BOSL_t *bosl = it->bosl;
    F_MAP_t *m = it->map;
    unsigned int pu_count = m->geometry.bosl_pu_count;
    unsigned int pu_factor = m->geometry.pu_factor;
    uint64_t pset = it->cond.pset;
    int true0 = f_map_has_true_zeros(it->map);
    uint64_t e, end, length;

    e = e_to_bosl(bosl, it->entry);
    end = length = m->bosl_entries;

    do {
	/* true zeros mode: don't assume missing PU are zeros */
	if (true0) {
	    uint64_t pu = e >> pu_factor;

	    if (!test_bit64(pu, bosl->dirty)) {
		pu = find_next_bit(bosl->dirty, pu_count, pu);
		if (pu >= pu_count)
		    return NULL; /* no PU */

		e = pu << pu_factor;
		end = (pu+1) << pu_factor;
	    }
	}

	end = min(end, length);
	if (e >= end)
	    return NULL; /* not in this BoS */

	if (pset == F_NO_CONDITION.pset)
	    goto _found; /* this one */

	/* find from 'e' */
	if (f_map_is_structured(m)) {
	    for (; e < end; e++) {
		it->word_p = _bosl_ffind(bosl, e);
		if (_check_iter_cond_vf(it))
		    goto _found;
	    }
	} else {
	    if (f_map_is_bbitmap(m)) {
		e = find_next_bbit(bosl->page, pset, end, e);
	    } else {
		if (pset & B_PAT1)
		    e = find_next_bit(bosl->page, end, e);
		else
		    e = find_next_zero_bit(bosl->page, end, e);
	    }
	    if (e < end) {
		it->word_p = _bosl_ffind(bosl, e);
		goto _found;
	    }
	}
	/* e: end */
    } while(e < length);

    return NULL;

_found:
    it->entry = e + bosl->entry0;
    /* TODO: Make this Extracheck! */
    assert(check_iter_cond(it));
    return it;
}

/* Create a new iterator on map with condition and optional arg
 * for structured map which is passed to evaluation virtual function.
 */
F_ITER_t *f_map_new_iter(F_MAP_t *map, F_COND_t cond, int arg)
{
	F_ITER_t *iter;
	unsigned int entry_sz;
	uint64_t c = cond.pset;

	/* sanity check */
	assert(map);
	entry_sz = map->geometry.entry_sz;
	if (!f_map_is_structured(map)) {
		assert(entry_sz == 1 || entry_sz == 2);
		if (f_map_is_bbitmap(map))
			assert(!bb_pset_chk(c) || c == F_NO_CONDITION.pset);
		else
			assert( c <= B_PAT1 );
	} else
		assert(entry_sz % 8 == 0);

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
		*(int*)iter->vf_arg = arg;
	} else
		assert (arg==0); /* Bitmap's iterator doesn't have any arg! */
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
bool f_map_check_iter(const F_ITER_t *iter) {
	return is_iter_reset(iter)?false:check_iter_cond(iter);
}

/*
 * f_map_seek_iter
 *
 * Reset the iterator to 'entry' unconditionally.
 * Create a new BoS for 'entry' if it does not exist.
 * Use this function to populate online map starting at 'entry'.
 * If out-of-memory, it would return NULL free the iterator.
 */
F_ITER_t *f_map_seek_iter(F_ITER_t *iter, uint64_t entry)
{
	F_ITER_t *it = iter;
	F_MAP_t *map = it->map;
	F_BOSL_t *bosl;
	unsigned long *p = NULL;

	iter_reset(iter);
	if ((bosl = it->bosl))
		p = bosl_ffind(bosl, entry);
	if (p == NULL) {
		int rc;

		/* update BoS pointer; create a new BoS on demand */
		rc = map_insert_and_get_bosl(map, entry, &bosl);

		if (rc && rc != -EEXIST) {
			assert(rc == ENOMEM);
			f_map_free_iter(iter);
			return NULL;
		}
		it->bosl = bosl;
		p = _bosl_ffind(bosl, e_to_bosl(bosl, entry));
	}
	assert(p);
	it->word_p = p;
	it->entry = entry;
	return it;
}

uint64_t f_map_max_bosl(F_MAP_t *map) {
	return max_bosl(map);
}

/* Advance iterator to the next BoS regadring iterator's condition. */
F_ITER_t *f_map_next_bosl(F_ITER_t *it)
{
	F_MAP_t *map;
	uint64_t idx;

	if (!it || !(map = it->map))
	    return NULL;

	if (unlikely(is_iter_reset(it))) {
	    it->entry++;
	    idx = 0;
	} else
	    idx = it->entry/map->bosl_entries + 1;

	do {
	    it->bosl = _next_bosl(map, it->bosl, idx);
	    if (it->bosl == NULL) {
		it->at_end = 1;
		return NULL;
	    }
	    it->entry = it->bosl->entry0;
	    it->word_p = it->bosl->page;
	    idx = it->entry/map->bosl_entries + 1;
	} while (!bosl_find_cond(it));

	/* TODO: Use per-thread lock count */
	rcu_quiescent_state();
	return it;
}

/*
 * f_map_next
 * Get iterator for the next entry which matches the iterator's condition
 * or return NULL.
 */
F_ITER_t *f_map_next(F_ITER_t *it)
{
	F_MAP_t *map;
	struct cds_ja_node *node;
	uint64_t node_idx, idx;
	uint64_t length;

	/* sanity check */
	if (!it || !(map = it->map))
	    return NULL;

	/* Advance the iterator */
	it->entry++;

	/* Entry in current BoS? */
	length = map->bosl_entries;
	node_idx = it->entry / length;
	if (f_map_entry_in_bosl(it->bosl, it->entry)) {
	    unsigned int per_long, entry_sz;

	    /* Advance the pointer */
	    if (likely(it->entry)) {
		entry_sz = map->geometry.entry_sz;
		if (!f_map_is_structured(map)) {
		    per_long = BITS_PER_LONG / entry_sz;
		    if (it->entry % per_long == 0)
			it->word_p++;
		} else
		    it->word_p += entry_sz/sizeof(*it->word_p);
	    } else
		it->word_p = it->bosl->page;

	    /* Find the first element with condition */
	    if (bosl_find_cond(it))
		return it;
	    node_idx++;
	}

	/* For each BoS in Judy array */
	do {
	    rcu_read_lock();
	    node = cds_ja_lookup_above_equal(map->bosses,
					     node_idx, &idx);
	    if (node == NULL) {
		rcu_read_unlock();
		it->at_end = 1;
		it = NULL;
		break;
	    }
	    it->bosl = container_of(node, F_BOSL_t, node);
	    rcu_read_unlock();

	    it->entry = idx * length;
	    assert (it->bosl->entry0 == it->entry);
	    it->word_p = it->bosl->page;
	    node_idx = idx + 1;
	} while (!bosl_find_cond(it));

	/* TODO: Use per-thread lock count */
	rcu_quiescent_state();
	return it;
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
	uint64_t e, pu;
	int true0 = f_map_has_true_zeros(map);
	bool ret = false;

	if (f_map_entry_in_bosl(it->bosl, entry))
		bosl = it->bosl;
	else
		bosl = f_map_get_bosl(map, entry);
	if (bosl == NULL) {
		ret = (!true0 && it->cond.pset == F_NO_CONDITION.pset);
		goto _no_entry;
	}

	e = e_to_bosl(bosl, entry);
	p = _bosl_ffind(bosl, e);
	pu = e >> map->geometry.pu_factor;
	if (true0 && !test_bit64(pu, bosl->dirty))
		goto _no_entry;

	/* structured map? */
	if (f_map_is_structured(map)) {
		if (value_p)
			*(void **)value_p = (void*)p;
		return __check_iter_cond_vf(it, (F_PU_VAL_t *)p);
	}
	/* bitmaps */
	if (map->geometry.entry_sz == 1) {
		/* bitmap */
		int bit = e % BITS_PER_LONG;
		ret = (it->cond.pset == F_NO_CONDITION.pset)?true:
			test_bit_patterns(bit, (int)it->cond.pset, p);
		if (value_p)
			*(int*)value_p = test_bit(bit, p);
	} else {
		/* bbitmap */
		int bit = e % BBITS_PER_LONG;
		ret = (it->cond.pset == F_NO_CONDITION.pset)?true:
			test_bbit_patterns(bit, (int)it->cond.pset, p);
		if (value_p)
			*(int*)value_p = (int)BBIT_GET_VAL(p, bit);
	}
	return ret;

_no_entry:
	if (value_p) {
		/* special value stands for "no entry" */
		if (f_map_is_structured(map))
			*(void**)value_p = NULL;
		else
			*(int*)value_p = -1;
	}
	return ret;
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

static inline uint64_t _bosl_weight(const F_ITER_t *it, const unsigned long *page,
    uint64_t start, uint64_t nr, int pset)
{
	if (f_map_is_structured(it->map))
		return bosl_weight_vf(it, page, start, nr);

	if (it->map->geometry.entry_sz == 1) {
		uint64_t w = __bitmap_weight64(page, start, nr);

		switch (pset) {
		case B_PAT0: return nr-w;
		case B_PAT1: return w;
		default: return nr;
		}
	} else {
		return __bbitmap_weight64(page, pset, start, nr);
	}
}

static uint64_t bosl_weight_true0(const F_ITER_t *it, const F_BOSL_t *bosl,
    uint64_t start, uint64_t nr)
{
    F_MAP_t *m = it->map;
    unsigned int pu_count = m->geometry.bosl_pu_count;
    unsigned int pu_factor = m->geometry.pu_factor;
    uint64_t e, end, length, pu_l;
    uint64_t w = 0;
    const unsigned long *page = bosl->page;

    e = start;
    length = min(m->bosl_entries, start+nr);
    pu_l = DIV_CEIL(length, 1U << pu_factor);
    assert (pu_l <= pu_count);

    do {
	/* true zeros mode: don't assume missing PU are zeros */
	uint64_t pu, pu_e;
	pu = e >> pu_factor;

	if (!test_bit64(pu, bosl->dirty)) {
	    /* the nearest marked PU */
	    pu = find_next_bit(bosl->dirty, pu_l, pu);
	    if (pu >= pu_l)
		break; /* no PU */

	    e = pu << pu_factor;
	}

	/* last continiously set PU */
	pu_e = find_next_zero_bit(bosl->dirty, pu_l, pu);
	end = pu_e << pu_factor;
	end = min(end, length);
	assert (e < end);

	/* count from 'e' */
	if (it->cond.pset == F_NO_CONDITION.pset)
	    w += end - e;
	else
	    w += _bosl_weight(it, page, e, end-e, it->cond.pset);

	e = end;
    } while (e < length);

    return w;
}

static uint64_t bosl_weight(const F_ITER_t *it, const F_BOSL_t *bosl,
    uint64_t start, uint64_t nr)
{
	if (f_map_has_true_zeros(it->map))
		return bosl_weight_true0(it, bosl, start, nr);

	if (it->cond.pset == F_NO_CONDITION.pset)
		return nr;

	return _bosl_weight(it, bosl->page, start, nr, (int)it->cond.pset);
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
	F_BOSL_t *bosl;
	F_MAP_t *map;
	struct cds_ja_node *node;
	uint64_t cnt, node_idx, idx;
	uint64_t weight = 0;
	uint64_t e, entry;
	uint64_t length;

	if (iter == NULL)
		return 0;

	assert (!is_iter_reset(iter)); /* No iterator position! */
	bosl = iter->bosl;
	map = iter->map;
	length = map->bosl_entries;
	entry = iter->entry;
	node_idx = entry / length;

	/* If we have the current BoS, weight entries there */
	if (f_map_entry_in_bosl(bosl, entry)) {
		e = e_to_bosl(bosl, entry);
		cnt = length - e;
		if (cnt > size)
			cnt = size;
		weight = bosl_weight(iter, bosl, e, cnt);
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
		weight += bosl_weight(iter, bosl, 0, cnt);
		size -= cnt;

		node_idx = idx + 1;
	} while (size > 0);

	/* TODO: Use per-thread lock count */
	rcu_quiescent_state();
	return weight;
}

/* Return the current map size, entries */
static uint64_t map_size(F_MAP_t *map)
{
	return max_bosl(map)*map->bosl_entries;
}

/* Generic map clone that loops with for_each_iter(orig) */
int map_clone(F_MAP_t *clone, F_SETTER_t setter, F_MAP_t *orig, F_COND_t cond)
{
	F_ITER_t *o, *c;
	int ret = -ENOMEM;

	/* TODO: Add support for all BoSses copy */
	c = f_map_new_iter_all(clone);
	if (c == NULL)
		return ret;
	/* FIXME: No support for evaluation fn argument (structured maps) */
	o = f_map_get_iter(orig, cond, 0);
	for_each_iter(o) {
		if (!f_map_seek_iter(c, o->entry))
			goto _err;
		set_value_bosl(c->bosl, e_to_bosl(c->bosl, o->entry), setter);
	}
	ret = 0;
_err:
	f_map_free_iter(o);
	f_map_free_iter(c);
	return ret;
}

/* Copy each BoS data from orig to clone */
int map_clone_asis(F_MAP_t *clone, F_MAP_t *orig)
{
	F_BOSL_t *or, *cl;

	assert (clone->bosl_sz == orig->bosl_sz);
	or = get_bosl(orig, 0);
	while (or) {
		cl = f_map_new_bosl(clone, or->entry0);
		memcpy(cl->page, or->page, orig->bosl_sz);
		or = next_bosl(or);
	}
	return 0;
}

int map_expand(F_MAP_t *clone, F_SETTER_t setter, F_MAP_t *orig, F_COND_t cond)
{
	/* TODO: Optimize value copy */
	return map_clone(clone, setter, orig, cond);
}

/* Reduce map values with 'cond' to bitmap */
int map_reduce(F_MAP_t *clone, F_MAP_t *orig, F_COND_t cond, int arg)
{
	F_ITER_t *c, *o = NULL;
	F_BOSL_t *cl, *or;
	size_t oe_sz;
	bool bbitmap;
	unsigned int pu, orig_e, cbe;
	int ret = -ENOMEM;

	oe_sz = orig->geometry.entry_sz;
	bbitmap = f_map_is_bbitmap(orig);

	/* True zero featute not supported! */
	assert (bbitmap && !f_map_has_true_zeros(orig));

	orig_e = 1 << orig->geometry.pu_factor;
	cbe = clone->bosl_entries;

	c = f_map_new_iter_all(clone);
	if (!c)
	    goto _err;
	o = f_map_get_iter(orig, cond, arg);
	if (!o)
	    goto _ret; /* empty map */

	or = iter_get_bosl(o);
	while (or) {
	    for (pu = 0; pu < orig->geometry.bosl_pu_count; pu++)
	    {
		uint64_t entry;
		const void *or_p;
		unsigned int ne, oe;

		if (bosl_is_pu_clean(or, pu))
		    continue;

		/* Reduce one PU of origin map to clone bitmap */
		ne = orig_e; /* number of entries to clone */
		oe = pu * orig_e;
		entry = or->entry0 + oe;
		or_p = or->page + oe*oe_sz;

		do {
		    unsigned int i, ce, n;

		    assert( f_map_seek_iter(c, entry) );
		    cl = c->bosl;
		    ce = e_to_bosl(cl, entry);
		    if (ce + ne > cbe) {
			/* Split ce entries to two BoSses */
			assert (cbe > ce);
			n = cbe - ce;
		    } else
			n = ne;

		    if (bbitmap) {
			unsigned int *cl_p = (void *)c->word_p;

			/* bbitmap's PU start entry is aligned to KEY_FACTOR_MIN-3 */
			assert (oe % BBITS_PER_LONG == 0);
			/* Check pu_factor if assertion fails! */
			assert (ce % BITS_PER_LONG == 0);
			assert (n % BITS_PER_LONG == 0);

			/* Reduce n entries of bbitmap to bitmap */
			for (i = 0; i < n/BBITS_PER_LONG; i++) {
			    *cl_p++ = bb_reduce(*(unsigned long *)or_p++,
						cond.pset);
			}
		    } else {

			/* Reduce n entries of structured map to bitmap */
			for (i = 0; i < n; i++, ce++) {
			    /* Set bitmap bit if origin map condition is met */
			    if (__check_iter_cond_vf(o, (F_PU_VAL_t *)or_p))
				set_bit(ce, cl->page);
			    or_p += oe_sz;
			}
		    }
		    entry += n;
		    ne -= n;
		} while (ne);
	    }
	    or = next_bosl(or);
	}
_ret:
	ret = 0;
_err:
	f_map_free_iter(c);
	f_map_free_iter(o);
	return ret;
}

/*
 * Map reshape
 *
 * Copy in-memory map entries to a new map evaluating the values with given
 * evaluator condition.
 * If *clone_p is NULL, create the exact clone of the same map type, otherwise
 * the target map (*clone_p) should be created beforehand with f_map_init().
 * Every map entry is evaluated to boolean with 'cond' first then the target
 * value is set by 'setter'.
 * If 'cond' is zero (F_NO_CONDITION), the setter would be ignored.
 * If target has the same type of the origin map, entries are being copied as is.
 * If target is a conventional (one bit) bitmap, 'setter' is ignored.
 * The dirty PU bitmaps are ignored and not copied. Generally the new map is not
 * a persistent map and it is not supposed to be registered with a DB backend.
 * Return: 0 on success or -ENOMEM if out-of-memory.
 */
int f_map_reshape(F_MAP_t **clone_p, F_SETTER_t setter, F_MAP_t *orig, F_COND_t cond)
{
	F_MAP_t *clone, *m = NULL;
	int origin_bbits, clone_bbits;
	int ret;
	bool asis;

	clone = *clone_p;
	if (!clone)
		clone = m = f_map_init(orig->type, orig->geometry.entry_sz,
				       orig->bosl_sz, orig->locking);
	if (!clone) {
		ret = -ENOMEM;
		goto _err;
	}
	asis = (orig->type == clone->type) &&
		(orig->bosl_entries == clone->bosl_entries);
	if (cond.pset && !asis) {
		ret = -EINVAL;
		goto _err;
	}
	origin_bbits = f_map_is_bbitmap(orig);

	/* True zero featute not supported! */
	assert (origin_bbits && !f_map_has_true_zeros(orig));

	clone_bbits = f_map_is_bbitmap(clone);
	if (clone_bbits > origin_bbits) {
		/* Expand */
		ret = map_expand(clone, setter, orig, cond);
	} else if (origin_bbits > clone_bbits) {
		/* Reduce */
		/* FIXME: No argument to evaluation fn yet! */
		ret = map_reduce(clone, orig, cond, 0);
	} else {
		/* Clone */
		if (asis)
			ret = map_clone_asis(clone, orig);
		else
			ret = map_clone(clone, setter, orig, cond);
	}

	ret = 0;
_err:
	if (m) {
		if (ret)
			map_free(m);
		else
			*clone_p = m;
	}
	return ret;
}

/* Create a new bitmap and fill it reducing BBIT or structured map entries to boolean
   with condition 'cond'. It takes BoS size as a hint that could be zero. */
F_MAP_t *f_map_reduce(size_t hint_bosl_sz, F_MAP_t *orig, F_COND_t cond, int arg)
{
	F_MAP_t *m;
	int rc;
	size_t bosl_sz = orig->bosl_sz;
	bool bbitmap = f_map_is_bbitmap(orig);

	if (!bbitmap && !f_map_is_structured(orig))
		return NULL; /* can't reduce bitmap to itself */

	/* Calculate optimal BoS buffer size */
	if (hint_bosl_sz == 0) {
		/* Try to maintain origin's BoS entries */
		if (bbitmap && (bosl_sz & 1))
			bosl_sz /= 2;
	} else if (hint_bosl_sz >= bosl_sz) {
		/* try to accomodate whole bitmap in one BoS */
		bosl_sz = DIV_CEIL(map_size(orig), 8); /* to bytes */
		bosl_sz = ROUND_UP(bosl_sz, 4096U); /* round up to page */
	} else {
		/* try to follow the hint */
		bosl_sz = ((hint_bosl_sz + 2047)/4096U)*4096U; /* round to page */
	}

	/* New bitmap */
	m = f_map_init(F_MAPTYPE_BITMAP, 1, bosl_sz, orig->locking);
	if (!m)
		return NULL; /* out-of-memory */

	rc = map_reduce(m, orig, cond, arg);
	if (rc) {
		map_free(m);
		m = NULL;
	}
	return m;
}

/* Count the number of dirty PUs on map */
static uint64_t get_dirty_count(F_MAP_t *m)
{
    F_ITER_t *it;
    size_t dirty_sz;
    uint64_t count = 0;

    /* Dirty PU bitmap size, bytes */
    dirty_sz = BITS_TO_LONGS(m->geometry.bosl_pu_count)*sizeof(long);
    it = f_map_new_iter(m, F_NO_CONDITION, 0);
    it = f_map_next_bosl(it);
    for_each_bosl(it)
	count += bitmap_weight(it->bosl->dirty, dirty_sz);

    f_map_free_iter(it);
    return count;
}

/* Print map description: KV size, in-memory size and so on */
void f_map_fprint_desc(FILE *f, F_MAP_t *m)
{
    uint64_t dirty_count = get_dirty_count(m);

    if (m->id == -1) {
	fprintf(f, "Map is unregistered, %s",
		f_map_is_structured(m)?"structured map":
			(m->geometry.entry_sz==1?"bitmap":"bbitmap"));
    } else {
	fprintf(f, "Map ID:%d is %s",
		m->id, f_map_is_structured(m)?"structured map":
			(m->geometry.entry_sz==1?"bitmap":"bbitmap"));
    }
    if (m->shm)
	fprintf(f, ", shared (%s #%d)",
	    f_shmap_owner(m)?"WR":(f_shmap_reader(m)?"RD":"SM"), m->reg_id);
    if (m->loaded)
	fprintf(f, ", loaded");
    if (dirty_count)
	fprintf(f, ", dirty (%lu PUs)", dirty_count);
    else
	fprintf(f, ", clean");
    fprintf(f, ";\n");
    if (m->parts<=1)
	fprintf(f, "  non-partitioned map; ");
    else if (f_map_has_globals(m))
	fprintf(f, "  partitioned global map with %u partitions; ",
	    m->parts);
    else
	fprintf(f, "  part %u of %u in partitioned local map; ",
	    m->part, m->parts);
    fprintf(f, "interleave: %u entr%s (%u PUs);\n",
	    1U<<m->geometry.intl_factor,
	    m->geometry.intl_factor?"ies":"y",
	    1U<<(m->geometry.intl_factor-m->geometry.pu_factor));
    fprintf(f, "  entry size:%u, %u PU per BoS, BoS size:%lu (%u entries);\n",
	    m->geometry.entry_sz, m->geometry.bosl_pu_count,
	    m->bosl_sz, m->bosl_entries);
    fprintf(f, "  map size:%lu entries, total BoS count:%lu.\n",
	    map_size(m), m->nr_bosl);
}


/*
 * Map in shared memory
 */
#define F_SHM_ATTACH_TMO 1000000U /* shared segment attach timeout, usec: 1 sec */
#define F_SHM_INODE	"/dev/shm" /* IPC shared segment key base inode */

#ifdef F_SHM_OPEN
static int shmem_open(void **shm_p, const char *name,
    size_t size, int ro, int *shm_id_p)
{
    F_SHMAP_SB_t *shm;
    int fd, flags;

    flags = ro? O_RDONLY:O_RDWR;
    if (-1 == (fd = shm_open(name, flags, 0)))
	return (errno == ENOENT)?-ENOENT:-1;

    flags = ro? PROT_READ : PROT_WRITE|PROT_READ;
    if (NULL == (shm = mmap(NULL, size, flags, MAP_SHARED, fd, SEEK_SET)))
	return -1;

    *shm_p = shm;
    return 0;
}

static int shmem_create(void **shm_p, const char *name,
    size_t size, int *shm_id_p)
{
    int force = 1;
    void *shm;
    int fd;
    int flags = O_RDWR|O_CREAT;

    if (!force)
	flags |= O_EXCL;

    if (-1 == (fd = shm_open(name, flags, 0777)))
	return errno == EEXIST && !force ? -EEXIST : -1;

    if (-1 == ftruncate(fd, size))
	return -1;

    if (NULL == (shm = mmap(NULL, size,
			    PROT_WRITE|PROT_READ, MAP_SHARED, fd, SEEK_SET)))
	return -1;

    bzero(shm, size);
    *shm_p = shm;
    return 0;
}
#else
#include <time.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>

static long ticks = 0;

static time_t get_proc_starttime(pid_t pid)
{
    struct sysinfo s_info;
    time_t uptime;
    FILE *fp;
    char stat_fn[18], *p;
    char *stat_str = NULL;
    long starttime = 0;
    unsigned long ul;
    int i;

    --starttime; /* max number */

    /* uptime? */
    if (sysinfo(&s_info))
	goto _err;
    /* since epoch */
    uptime = time(0) - s_info.uptime;

    /* jiffies per sec */
    if (!ticks)
	ticks = sysconf(_SC_CLK_TCK);

    /* the time the process started after system boot */
    stat_str = (char *) malloc(2048);
    if (stat_str == NULL)
	goto _err;
    sprintf(stat_fn, "/proc/%u/stat", (unsigned) pid);

    if (-1 == access(stat_fn, R_OK))
	goto _err;

    if ((fp = fopen (stat_fn, "r")) == NULL)
	goto _err;

    if (fgets(stat_str, 2048, fp) == NULL)
	goto _close;

    /* to field 3 */
    p = strchr(stat_str, ')') +2;
    /* to field 22 */
    for (i = 0; i < 19 && p; i++)
	p = strchr(p, ' ') +1;
    /* parse starttime */
    if (!p || !(ul = strtoul(p, NULL, 10)))
	goto _close;

    /* to time_t */
    starttime = uptime + ul/ticks;

_close:
    fclose(fp);
_err:
    free(stat_str);
    return starttime;
}

/* Given process PID and last attach time
  return true if owner is still alive. */
static int shmem_verify_owner(pid_t pid, time_t time)
{
    char proc_pid[16];
    time_t ctime;
    struct stat sts;

    sprintf(proc_pid, "/proc/%u", pid);
    if (stat(proc_pid, &sts) == -1) {
	if (errno != ENOENT)
	    err("shmem_verify_owner %s error - %m", proc_pid);

	dbg_printf(" verify_owner pid:%u not found\n", pid);
	return 0;
    }

    /* PID creation time */
    ctime = get_proc_starttime(pid);

#ifdef DEBUG_MAP
    if (difftime(ctime, time) > 0)
	dbg_printf(" verify_owner pid:%u is old, difftime:%.1fs\n",
		   pid, difftime(ctime, time));
#endif

    /* owner had to be alive when last attach */
    return (difftime(ctime, time) > 0)? 0:1;
}

static int hf_shm_id(const char *name) {
    const char *p = name;
    unsigned char l, i, id;

    assert(p && *p);
    i = *(p+strlen(p)-1) - '0';
    l = *(p+strlen(p)-3) - '0';
    id = (l << 4) + i;
    return id;
}

/* Open and attach to shared memory segment.
  shm_id_p not NULL ("reader") - check for REMID and verify creator/PID time;
	   is NULL ("owner") - set REMID and loop until shmget returns ENOENT.
  rd:1 - open segment read-only */
static int shmem_open(void **shm_p, const char *name,
    size_t size, int ro, int *shm_id_p)
{
    void *shm;
    key_t key;
    struct shmid_ds sbuf = { .shm_nattch = 0, };
    int shm_id, id;
    int flags = SHM_NORESERVE;
    unsigned int slp;
    int rd = !!(shm_id_p);
    int w_f = 0;
    int rc = -1;

    id = hf_shm_id(name);
    key = ftok(F_SHM_INODE, id);
    if (key == -1) {
	err("ftok - %m");
	goto _err;
    }

    do {
	/* sleep 1 sec if segment in use */
	slp = w_f? F_SHM_ATTACH_TMO:F_SHM_ATTACH_TMO>>6;

	/* quiry identifier of the shared memory segment */
	if (-1 == (shm_id = shmget(key, size, flags | 0666))) {
	    if (errno == ENOENT) {
		    if (rd)
			goto _retry;
		    return -ENOENT; /* WR: Success */
	    }
	    err("map %s id:%d key:0x%08x shmget error - %m",
		name, id, key);
	    goto _err;
	}

	/* only for map owner: set REMID (delete) segment flag */
	if (!rd && -1 == shmctl(shm_id, IPC_RMID, NULL)) {
	    err("shmctl RMID error - %m");
	    goto _err;
	}

	/* read segment stat (shmid_ds) structure */
	if (-1 == shmctl(shm_id, IPC_STAT, &sbuf)) {
	    rc = errno;
	    if (rc == EINVAL || rc == EIDRM) {
		if (w_f == 0)
		    goto _sleep; /* IPC_RMID success! */

		err("shmem_open %s shmctl STAT WARNING - %m\n", name);
		slp = F_SHM_ATTACH_TMO >> 6;
		goto _retry;
	    }
	    err("shmem_open %s shmctl error - %m", name);
	    goto _err;
	}

	/* only for readers: are there current attaches? */
	if (rd && sbuf.shm_nattch > 0 &&
	    !(sbuf.shm_perm.mode & SHM_DEST)) {
	    /* verify segment owner */
	    if (shmem_verify_owner(sbuf.shm_cpid, sbuf.shm_ctime))
		break; /* RD: ready to attach the segment */
	/*  only for map owner: segment to be destroyed soon */
	} else if (!rd && sbuf.shm_nattch == 0)
	    slp = F_SHM_ATTACH_TMO >> 6;

_retry:
	if (w_f == 0) {
	    if (rd)
		err("shmem_open %s waits for source", name);
	    else
		err("shmem_open %s waits for stale clients:%lu",
		    name, sbuf.shm_nattch);
	}
	w_f = 1;
_sleep:
	usleep(slp);
    } while (1);

    if (shm_id_p)
	*shm_id_p = shm_id;

    if ((void*)-1 == (shm = shmat(shm_id, NULL, ro?SHM_RDONLY:0))) {
	err("shmat id:%d - %m", shm_id);
	goto _err;
    }

    dbg_printf("shmem_open %s %s %s id:%d shm_id:%d shm:%p\n",
	       name, rd?"RD":"WR", ro?"R/O":"R/W", id, shm_id, shm);

    *shm_p = shm;
    return 0;

_err:
    err("shmem_open %s %s %s id:%d error:%d",
	name, rd?"RD":"WR", ro?"R/O":"R/W", id, rc);
    return rc;
}

/* Clean up SHM segment and always create a new one.
  This function blocks on attached (staled) segment(s) - no TMO!
  Return 0 (Success) or -EEXIST or I/O error. */
static int shmem_create(void **shm_p, const char *name,
    size_t size, int *shm_id_p)
{
    void *shm;
    key_t key;
    int shm_id, id;
    int w_f = 0;
    int flags = IPC_CREAT | SHM_NORESERVE;

    /* Fail shmget if segment exists */
    flags |= IPC_EXCL;

    id = hf_shm_id(name);
    key = ftok(F_SHM_INODE, id);
    if (key == -1) {
	err("ftok - %m\n");
	goto _err;
    }

    do {
	int rc;

	if (-1 != (shm_id = shmget(key, size, flags | 0666)))
	    break;

	if (errno != EEXIST) {
	    err("map %s id:%d new key:0x%08x shmget error - %m",
		name, id, key);
	    goto _err;
	}

	if (w_f == 0)
	    dbg_printf("shmem_create %s - clean up stale shared region",
			name);
	w_f = 1;

	/* Set REMID flag and wait until nattch drops to zero */
	rc = shmem_open(shm_p, name, size, 0, NULL);
	if (rc != -ENOENT) {
	    err("shmem_create %s open error:%d", name, rc);
	    goto _err;
	}
    } while (1);
    *shm_id_p = shm_id;

    if ((void*)-1 == (shm = shmat(shm_id, NULL, 0))) {
	err("shmat - %m\n");
	goto _err;
    }

    dbg_printf("shmem_create %s id:%d shm_id:%d shm:%p\n",
	       name, id, shm_id, shm);

    *shm_p = shm;
    return 0;

_err:
    err("shmem_create %s id:%d error!", name, id);
    return -1;
}
#endif

static void sboss_free(F_MAP_SBOSS_t *sboss, int unlink)
{
    if (sboss->size)
#ifdef F_SHM_OPEN
	munmap(sboss->data, sboss->size);
    if (unlink && shm_unlink(sboss->dname))
#else
	shmdt(sboss->data);
    if (unlink && shmctl(sboss->shm_id, IPC_RMID, NULL) == -1)
#endif
	ioerr("shm_detach: unlink '%s' failed - %m", sboss->data->name);
    free(sboss->dname);
    free(sboss);
}

/* Scan SBoS' BoSses for dirty PUs, clone BoSses to map.
  This function should be called by shared map reader with RD lock held! */
static int shmap_read_bosses(F_MAP_t *m, F_MAP_SBOSS_t *sboss)
{
    F_MAP_SB_t *priv_sb = m->shm_sb;
    F_MAP_t *sm = priv_sb->super_map;
    F_SHMAP_DATA_t *sdata = sboss->data;
    F_BOSL_t *sbosl;
    uint64_t e0;
    unsigned long *pages = sdata->pages;
    unsigned long pu, dirty_sz, *page;
    int rc;

    if (!f_shmap_reader(m)) {
	err("shmap_read_bosses: invalid map shm:%d, map_id:%d",
	    m->shm, m->id);
	return -EINVAL;
    }

    dbg_printf("read from SBoS:%s nr_bosl:%lu\n",
	       sdata->name, sm->nr_bosl);

    dirty_sz = sm->geometry.bosl_pu_count;
    assert( dirty_sz == F_MAP_MAX_BOS_PUS );
    sbosl = &sdata->super_bosl;
    /* For each set dirty PU: add BoS @ e0 to map */
    for_each_set_bit(pu, sbosl->dirty, dirty_sz) {
	e0 = sdata->e0[pu];
	page = pages + pu*(m->bosl_sz/sizeof(*pages));
	//f_map_new_bosl(m, e0);
	if (!map_get_bosl(m, e0)) {
	    F_BOSL_t *bosl;
	    if ((rc = _map_insert_bosl(m, e0, &bosl, page)))
		return rc;

	    dbg_printf(". inserted bosl:%p e0:%lu page:%p\n",
		       bosl, bosl->entry0, bosl->page);
	}
    }
    return 0;
}

/* Add one (if shared map owner) or some (if reader) super page(s).
  Each superpage is a SBoS'es data page that is mapped to SHMEM */
static int sbosl_add_pages(F_MAP_t *m)
{
    F_MAP_SB_t *priv_sb = m->shm_sb;
    F_SHMAP_SB_t *sb = priv_sb->shmap_sb;
    F_SHMAP_DATA_t *sdata;
    F_MAP_t *sm = priv_sb->super_map;
    F_MAP_SBOSS_t *sboss = NULL;
    char sb_name[F_SHMAP_NAME_LEN] = { 0 };
    size_t l, size;
    uint64_t entry, id;
    int count, rc = 0;

    /* new mapping */
    if (f_shmap_owner(m)) {
	if ((rc = pthread_rwlock_wrlock(&sb->sb_rwlock)))
	    goto _free;
	/* Add one SBoS */
	id = sb->super_map.nr_bosl;
	count = 1;
    } else {
	uint64_t nr_bosl;

	if ((rc = pthread_rwlock_rdlock(&sb->sb_rwlock)))
	    goto _free;
	id = sb->super_map.nr_bosl;
	if (id == 0) {
	    rc = -ESRCH; /* WR is not ready yet */
	    goto _err;
	}

	/* Add SBoSses which are missing on this reader */
	pthread_spin_lock(&sm->bosl_lock);
	nr_bosl = sm->nr_bosl;
	pthread_spin_unlock(&sm->bosl_lock);

	assert( nr_bosl <= id ); /* TODO: Add support for BoS deletion */
	if (nr_bosl == id)
	    goto _unlock; /* Success: nothing to do */
	count = id - nr_bosl;
	id = nr_bosl; /* SBoS IDs starts with zero */
    }
    entry = id*F_SHMAP_SZ(1);
#ifndef F_SHM_OPEN
    id++;
#endif

    do {
	/* Allocate a new SBoS */
	sboss = (F_MAP_SBOSS_t *) calloc(1, sizeof(F_MAP_SBOSS_t));
	if (!sboss)
	    return -ENOMEM;
	INIT_LIST_HEAD(&sboss->node);

	/* memory region name */
	assert( id > 0 );
	l = snprintf(sb_name, F_SHMAP_NAME_LEN, "%s%c_%1.1lu",
		     F_SHMAP_DATA_NAME, (char)priv_sb->id, id);
	strncpy(sb_name+l, sb->name+l, F_SHMAP_NAME_LEN-l-1);

	size = F_SHMAP_DATA_SZ(m->bosl_sz);
	if (f_shmap_owner(m)) {
	    F_BOSL_t *super_bosl;

	    /* Create SBoS */
	    rc = shmem_create((void**)&sdata, sb_name, size, &sboss->shm_id);
	    if (rc)
		goto _err;
	    strcpy(sdata->name, sb_name);
	    sboss->data = sdata;
	    sboss->size = size;

	    /* Add SBoS to supermap */
	    super_bosl = &sdata->super_bosl;
	    rc = _map_insert_bosl(sm, entry, &super_bosl, sdata->pages);
	    if (rc)
		goto _err;
	    assert( super_bosl == &sdata->super_bosl );

	    dbg_printf("WR id:%lu total bosses:%lu SBOSS %lu page:%p\n",
		       id, sb->super_map.nr_bosl, super_bosl->entry0, super_bosl->page);

	} else {
	    F_BOSL_t *bosl = NULL;

	    /* Open SBoS read-only */
	    rc = shmem_open((void**)&sdata, sb_name, size, 1, &sboss->shm_id);
	    if (rc)
		goto _err;
	    sboss->data = sdata;
	    sboss->size = size;

	    /* Add SBoS to supermap */
	    rc = _map_insert_bosl(sm, entry, &bosl, sdata->pages);
	    if (rc)
		goto _err;
	    /* hack to free bosl on map_exit */
	    bosl->shm = F_MAPMEM_SHARED_RD;

	    dbg_printf("RD id:%lu/%d total bosses:%lu SBOSS %lu page:%p\n",
		       id, count, sb->super_map.nr_bosl,
		       bosl->entry0, bosl->page);

	    /* Update map from this SBoS' BoSSes: scan for dirty PUs */
	    if ((rc = shmap_read_bosses(m, sboss)))
		goto _err;
	}

	/* add to SBoS list */
	sboss->dname = strdup(sb_name);
	list_add_tail(&sboss->node, &priv_sb->shmap_data);

	entry = id*F_SHMAP_SZ(1);
	id++;
    } while (--count);

_unlock:
    rc = pthread_rwlock_unlock(&sb->sb_rwlock);
    if (rc)
	err("shmap add_page unlock error:%d", rc);
    return 0;

_err:
    pthread_rwlock_unlock(&sb->sb_rwlock);
_free:
    if (sboss)
	sboss_free(sboss, f_shmap_owner(m));
    err("sbosl_add_pages error:%d", rc);
    return rc;
}

static int shmap_read_all_bosses(F_MAP_t *m)
{
    F_MAP_SB_t *priv_sb = m->shm_sb;
    F_SHMAP_SB_t *sb = priv_sb->shmap_sb;
    struct list_head *pos, *tmp;
    int r, rc = 0;

    if(!f_shmap_reader(m)) {
	err("read_all_bosses: invalid map shm:%d, map_id:%d",
	    m->shm, m->id);
	return -EINVAL;
    }

    /* Update shared map reader's SBoSses */
    if ((rc = sbosl_add_pages(m)))
	return rc;

    if ((rc = pthread_rwlock_rdlock(&sb->sb_rwlock)))
	return rc;

    /* Scan each SBoS' dirty PUs */
    list_for_each_prev_safe(pos, tmp, &priv_sb->shmap_data) {
	F_MAP_SBOSS_t *sboss = container_of(pos, struct f_map_sboss_, node);

	dbg_printf("SBoS %s shm_id:%d\n",
		   sboss->dname, sboss->shm_id);

	if ((rc = shmap_read_bosses(m, sboss)))
	    goto _unlock;
    }
_unlock:
    rcu_quiescent_state();

    r = pthread_rwlock_unlock(&sb->sb_rwlock);
    if ((rc = rc?:r))
	err("read_all_bosses error:%d", rc);
    return rc;
}

static void shmap_free(F_MAP_SB_t *priv_sb)
{
    F_SHMAP_SB_t *sb = priv_sb->shmap_sb;
    F_MAP_t *sm = priv_sb->super_map;
    struct list_head *pos, *tmp;

    /* Unmap and free SBoS data pages */
    list_for_each_prev_safe(pos, tmp, &priv_sb->shmap_data) {
	F_MAP_SBOSS_t *sboss = container_of(pos, struct f_map_sboss_, node);

	dbg_printf("free SBoS %s shm_id:%d\n",
		   sboss->dname, sboss->shm_id);

	list_del(pos);
	sboss_free(sboss, f_shmap_owner(priv_sb));
    }

    /* unmap SB and free supermap */
    switch (priv_sb->shm) {
    case F_MAPMEM_SHARED_WR:
	pthread_rwlock_destroy(&sb->sb_rwlock);
	break;
    case F_MAPMEM_SHARED_RD:
	free(sm);
	break;
    default: err("shm_detach: op not supported");
    }
    if (sb)
#ifdef F_SHM_OPEN
	munmap(sb, sizeof(F_SHMAP_SB_t));
#else
	shmdt(sb);
#endif

    if ((priv_sb->shm == F_MAPMEM_SHARED_WR) &&
#ifdef F_SHM_OPEN
	 shm_unlink(priv_sb->name))
#else
	 shmctl(priv_sb->shm_id, IPC_RMID, NULL) == -1)
#endif
	ioerr("shm_detach: shm_unlink");
    free(priv_sb->name);
    free(priv_sb);
}

/* Allocate new BoS data page in SHMEM - only for map shm:F_MAPMEM_SHARED_WR */
static int sbosl_alloc_page(F_MAP_t *m, uint64_t entry, unsigned long **page_p)
{
    F_MAP_SB_t *priv_sb = m->shm_sb;
    F_SHMAP_SB_t *sb;
    F_SHMAP_DATA_t *sdata;
    F_MAP_t *sm;
    F_BOSL_t *sbosl;
    unsigned long *page;
    uint64_t super_id, super_pu;
    int rc;

    assert( priv_sb );
    assert( page_p );
    assert( f_shmap_owner(m) );
    sb = priv_sb->shmap_sb;
    sm = priv_sb->super_map;

    /* allocate new page */
    if ((rc = pthread_rwlock_wrlock(&sb->sb_rwlock)))
	return rc;

    /* Find SBoS */
    super_id = sm->nr_bosl;
    sbosl = map_get_bosl(sm, F_SHMAP_SZ(--super_id));
    assert( sbosl );
    sdata = container_of(sbosl->page, struct f_shmap_data_, pages[0]);

    /* SBoS data page */
    super_pu = find_first_zero_bit(sbosl->dirty, F_MAP_MAX_BOS_PUS);
    assert( super_pu < F_MAP_MAX_BOS_PUS );
    /* mark BoS as used */
    _f_map_mark_pu_dirty_bosl(sbosl, super_pu);
    /* BoS e0 */
    sdata->e0[super_pu] = ROUND_DOWN(entry, m->bosl_entries);
    page = _bosl_ffind(sbosl, super_pu);

    dbg_printf("WR new BoS @%lu for e:%lu e0:%lu page:%p in SBoS %lu\n",
	       super_pu, entry, sdata->e0[super_pu], page, super_id);

    /* return BoS data page */
    assert( sm->geometry.pu_factor == 0 );
    *page_p = page;

    pthread_rwlock_unlock(&sb->sb_rwlock);

    if (++super_pu == F_MAP_MAX_BOS_PUS) {

	/* pre-allocate new SBoS */
	return sbosl_add_pages(m);
    }
    return rc;
}

/* Share the map in SHMEM */
int f_map_shm_attach(F_MAP_t *m, F_MAPMEM_t rw)
{
    F_MAP_SB_t *priv_sb;
    F_SHMAP_SB_t *sb = NULL;
    F_MAP_t *sm = NULL;
    pthread_rwlockattr_t attr;
    char sb_name[F_SHMAP_NAME_LEN] = { 0 };
    size_t size;
    signed char reg_id;
    unsigned int tmo, slp;
    int rc = 0;

    if (!m || m->shm_sb)
	return -EINVAL; /* already attached */
    if (m->nr_bosl || m->loaded)
	return -EADDRINUSE; /* already in use */

    priv_sb = (F_MAP_SB_t *) calloc(1, sizeof(F_MAP_SB_t));
    if (!priv_sb)
	return -ENOMEM;
    INIT_LIST_HEAD(&priv_sb->shmap_data);
    reg_id = (signed char)m->reg_id;
    priv_sb->id = (reg_id + 0x30) & 0xff; /* IPC shared memory region signature */

    snprintf(sb_name, F_SHMAP_NAME_LEN, "%s%c_0",
	     F_SHMAP_NAME_PREFIX, (char)priv_sb->id);
    priv_sb->name = strdup(sb_name);
    priv_sb->shm = rw;

    size = sizeof(F_SHMAP_SB_t);
    switch (rw) {
    case F_MAPMEM_SHARED_WR:
	/* create new SB object if existing */
	if ((rc = shmem_create((void**)&sb, sb_name, size, &priv_sb->shm_id)))
	    goto _err;
	strcpy(sb->name, sb_name);
	priv_sb->shmap_sb = sb;

	pthread_rwlockattr_init(&attr);
	pthread_rwlockattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	pthread_rwlock_init(&sb->sb_rwlock, &attr);

	/* create supermap */
	sm = &sb->super_map;
	rc = _map_init(&sm, F_MAPTYPE_STRUCTURED, m->bosl_sz,
			F_SHMAP_SZ(m->bosl_sz), 0, 64);
	if (rc)
		goto _err;
	break;

    case F_MAPMEM_SHARED_RD:
	/* we can wait a little till writer */
	tmo = 0;
	slp = F_SHM_ATTACH_TMO/8;
	do {
	    /* open SB R/W */
	    if ((rc = shmem_open((void**)&sb, sb_name, size, 0, &priv_sb->shm_id)))
	    {
		if (rc == -ENOENT)
		    usleep(slp);
		else
		    goto _err;
	    } else
		break;
	    tmo += slp;
	} while (tmo <= F_SHM_ATTACH_TMO);
	if (rc) {
		err("shm_attach: %s TMO", sb_name);
		goto _err;
	}
	priv_sb->shmap_sb = sb;

	tmo = 0;
	slp = F_SHM_ATTACH_TMO/8;
	rc = -ENOENT;
	do {
	    /* WR ready? */
	    if (sb->super_map.nr_bosl) {
		rc = 0;
		break;
	    }
	    usleep(slp);
	    tmo += slp;
	} while (tmo <= F_SHM_ATTACH_TMO);
	if (rc) {
		err("shm_attach: %s not ready\n", sb_name);
		goto _err;
	}

	rc = pthread_rwlock_rdlock(&sb->sb_rwlock);
	if (rc)
	    goto _err;
	/* Create Supermap */
	/* TODO: Clone Supermap from SHMEM SB */
	sm = f_map_init(F_MAPTYPE_STRUCTURED, m->bosl_sz,
			F_SHMAP_SZ(m->bosl_sz), 0);
	if (sm == NULL) {
	    pthread_rwlock_unlock(&sb->sb_rwlock);
	    rc = -ENOMEM;
	    goto _err;
	}
	rc = pthread_rwlock_unlock(&sb->sb_rwlock);
	if (rc)
	    goto _err;

	m->ronly = 1;
	break;

    case F_MAPMEM_PRIVATE: return 0;
    default: err("shm_attach: op not supported"); return -EINVAL;
    }
    sm->shm = F_MAPMEM_SHARED_S;
    priv_sb->super_map = sm;

    m->shm = rw;
    m->shm_sb = priv_sb;

    /* Set data pages in SHMEM for one(WR) or more(RD) SBoSses */
    rc = sbosl_add_pages(m);
    if (rc)
	goto _err;

    return 0;

_err:
    if (sm)
	map_free(sm);
    shmap_free(priv_sb);
    return rc;
}
#undef F_SHM_ATTACH_TMO
#undef F_SHM_INODE

