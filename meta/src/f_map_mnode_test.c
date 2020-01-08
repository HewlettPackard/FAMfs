/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <mpi.h>

#include "famfs_bitmap.h"
#include "f_map.h"
#include "f_pool.h"
#include "f_layout.h"
#include "mdhim.h"


/* TEST options */
#define TEST_MDHIM_DBG	0	/* 1: MDHIM debug enabled */
#define RND_REPS	1000	/* number of passes for random test */
#define SQ_REPS		1000	/* number of passes for sequential test */
#define BOS_PAGE_MAX	4	/* max BoS page size, in kernel pages */
#define layout_id	0	/* use Layout 0 default configuration */
#define MEM_KEY_BITS	64	/* in-memory maps: max global entry bits */
#define DB_KEY_BITS	31	/* DB-backed maps: max global entry bits */
#define META_DB_PATH	"/dev/shm"
#define SM_EXT_MAX	3	/* max extent # in Slab map */


#define MPI_BARRIER		MPI_Barrier(MPI_COMM_WORLD)
#define bitmap_new_iter(m, c)	(f_map_new_iter(m, c, 0))
#define e_to_bosl(bosl, e)	(e - bosl->entry0)
#define it_to_pu(it)		(e_to_bosl(it->bosl, it->entry) >>	\
				 it->map->geometry.pu_factor)
#define bosl_pu_in_my_part(bosl, pu)					\
	(f_map_prt_my_global(bosl->map,					\
			     bosl->entry0 + (pu << bosl->map->geometry.pu_factor)))

/* Advance continuous PU number to 'partition' */
#define pu_round_up_to_part(pu, factor, parts, part)			\
	({ unsigned int il = ((pu) >> (factor)) % (parts);		\
	   pu += (((il>part)?(parts):0U)+(part)-il) << (factor);	\
	   (pu); })

/* Set highest and lowest order(RAND_MAX) bits randomly in 64-bit word */
#define gen_rand_key(ul, bits)			\
	({ ul = RAND_MAX+1U;			\
	int _v = bits - __builtin_clzl(ul) + 1;	\
	ul = (uint64_t)rand();			\
	if (_v > 0) {				\
		ul = ul << _v;			\
		ul += rand();			\
	}					\
	ul; })

/* MDHIM and Layout config */
F_LAYOUT_INFO_t *lo_info = NULL;
unifycr_cfg_t md_cfg;
struct mdhim_t *md;
struct index_t *unifycr_indexes[2*F_LAYOUTS_MAX+1]; /* +1 for primary_index */
static int my_node;
static int node_size = 0;

static int create_persistent_map(F_MAP_INFO_t *info, int intl, char *name);
static ssize_t ps_bget(unsigned long *buf, int map_id, size_t size, uint64_t *keys);
static int ps_bput(unsigned long *buf, int map_id, size_t size, void **keys,
    size_t value_len);
static int ps_bdel(int map_id, size_t size, void **keys);

static F_META_IFACE_t iface = {
	.create_map_fn = &create_persistent_map,
	.bget_fn = &ps_bget,
	.bput_fn = &ps_bput,
	.bdel_fn = &ps_bdel,
};

static int meta_init_conf(unifycr_cfg_t *server_cfg_p, mdhim_options_t **db_opts_p,
    int argc, char *argv[])
{
	int rc;

	rc = unifycr_config_init(server_cfg_p, argc, argv);
	if (rc != 0)
		return rc;
	if (server_cfg_p->meta_db_path)
		free(server_cfg_p->meta_db_path);
	server_cfg_p->meta_db_path = strdup(META_DB_PATH);

	f_set_meta_iface(&iface);
	return mdhim_options_cfg(server_cfg_p, db_opts_p);
}

/* Initialize MDHIM threads and structures.
 * This is MDHIM Collective call.
 */
static void meta_init_store(mdhim_options_t *db_opts) {
	int i;

	assert (db_opts->rserver_factor == 1);
#if TEST_MDHIM_DBG > 0
	mdhim_options_set_debug_level(db_opts, MLOG_DBG); /* Uncomment for DB DEBUG! */
#endif
	md = mdhimInit(NULL, db_opts);

	unifycr_indexes[0] = md->primary_index;
	for (i = 1; i <= 2*F_LAYOUTS_MAX; i++)
		unifycr_indexes[i] = NULL;
	if (node_size == 0) {
		node_size = md->mdhim_comm_size;
		my_node = md->mdhim_rank;
	}
}

/* Delete DB files.
 * MDHIM Collective call: MPI_Barrier(md->mdhim_comm)
 */
static int meta_sanitize() {
    mdhim_options_t *db_opts;
    int *ids, *types, max_id, indexes, i;
    int rank, ret, rc = 0;
    bool manifest = false;

    char dbfilename[GEN_STR_LEN] = {0};
    char statfilename[GEN_STR_LEN+12] = {0};
    char manifestname[GEN_STR_LEN] = {0};

    db_opts = md->db_opts;
    rank = md->mdhim_rank;

    indexes = 2*F_LAYOUTS_MAX+1;
    ids = (int*) malloc(sizeof(int)*indexes);
    types = (int*) malloc(sizeof(int)*indexes);
    max_id = 0;
    for (i = 0; i < indexes; i++) {
	if (!unifycr_indexes[i])
		continue;
	ids[max_id] = unifycr_indexes[i]->id;
	types[max_id] = unifycr_indexes[i]->type;
	manifest = (unifycr_indexes[i]->myinfo.rangesrv_num == 1);
	max_id++;
    }
    rc = mdhimClose(md);
    if (rc) {
	printf("%d: mdhimClose error:%d\n", rank, rc);
	return rc;
    }

    /* TODO: For each registered DB table */
    for (i = 0; i < max_id; i++) {
        sprintf(dbfilename, "%s/%s-%d-%d", db_opts->db_path,
                db_opts->db_name, ids[i], rank);
        sprintf(statfilename, "%s_stats", dbfilename);
        sprintf(manifestname, "%s%d_%d_%d", db_opts->manifest_path,
                types[i], ids[i], rank);

        ret = mdhimSanitize(dbfilename, statfilename,
			    manifest?manifestname:NULL);
	if (ret) {
	    printf("%d: mdhimSanitize %s error:%d\n",
		rank, dbfilename, ret);
	    if (rc == 0)
		rc = ret; /* report first error */
	}
    }
    free(ids);
    free(types);
    mdhim_options_destroy(db_opts);
    md = NULL;
    return rc;
}

/* Open DB [named] table 'id'.
 * MDHIM Collective call: MPI_Barrier(md->mdhim_client)
 */
static int create_persistent_map(F_MAP_INFO_t *info, int intl, char *name)
{
    unsigned int id = info->map_id + 1;

    if (id > 2*F_LAYOUTS_MAX)
	return -1;
    if (unifycr_indexes[id] == NULL) {
	unifycr_indexes[id] = create_global_index(md, md->db_opts->rserver_factor,
					intl, LEVELDB, MDHIM_LONG_INT_KEY, name);
	if (unifycr_indexes[id] == NULL)
		return -1;

	printf("%d: create_persistent_map:%d %s index[%u] interleave:%d\n",
	       md->mdhim_rank, info->map_id, name, id, intl);

    }
    return 0;
}

static ssize_t ps_bget(unsigned long *buf, int map_id, size_t size, uint64_t *keys)
{
        struct index_t *primary_index = unifycr_indexes[map_id + 1];

        return mdhim_ps_bget(md, primary_index, buf, size, keys);
}

static int ps_bput(unsigned long *buf, int map_id, size_t size, void **keys,
    size_t value_len)
{
        struct index_t *primary_index = unifycr_indexes[map_id + 1];

	return mdhim_ps_bput(md, primary_index, buf, size, keys, value_len);
}

static int ps_bdel(int map_id, size_t size, void **keys)
{
	struct index_t *primary_index = unifycr_indexes[map_id + 1];

	return mdhim_ps_bdel(md, primary_index, size, keys);
}


/* Virtual map function (F_MAP_EVAL_SE_fn) example.
   It reduces the slab map entry value to single bit */
static int sm_is_extent_failed(void *arg, const F_PU_VAL_t *entry)
{
    int r = 0;
    unsigned int n = *(unsigned int *)arg; /* extent # */

    const F_SLAB_ENTRY_t *se = &entry->se;
    const F_EXTENT_ENTRY_t *ee = &entry->ee + n;

    if (se->mapped)
	r = ee->failed;
    return r;
}

/* Example of Slab map entry condition: extent is failed.
 * Set .vf_arg to extent number!
 */
static F_COND_t sm_extent_failed = {
    .vf_get = &sm_is_extent_failed,
};

/* Example of Claim Vector condition: BBPAT_11 - entry is "laminated" */
static F_COND_t cv_laminated = {
    .pset = CV_LAMINATED_P,
};

/* The [simple] bitmap condition: a bit is set */
static F_COND_t laminated = F_BIT_CONDITION;

/* These conditions shall match any non-zero value */
/* PSET_NON_ZERO - any non-zero value in [b]bitmap */
#define PSET_NON_ZERO	((F_COND_t)(BB_PAT01|BB_PAT10|BB_PAT11))
/* Return the number of 1-bits in 'entry' */
static int sm_se_or_ee_not_zero(void *arg, const F_PU_VAL_t *entry)
{
    int r;
    unsigned int i, n = *(unsigned int *)arg; /* extent count */

    const F_SLAB_ENTRY_t *se = &entry->se;
    const F_EXTENT_ENTRY_t *ee = &entry->ee;

    r = __builtin_popcountll(se->_v128);

    for (i = 0; i < n; i++, ee++)
	r += __builtin_popcountl(ee->_v64);
    return r;
}

/* Example of Slab map entry condition: extent is failed.
 * Set .vf_arg to extent number!
 */
static F_COND_t se_or_ee_not_zero = {
    .vf_get = &sm_se_or_ee_not_zero,
};


/* unittest: f_map */
int main (int argc, char *argv[]) {
    F_MAP_t *m, *map, *mlog;
    F_BOSL_t *bosl;
    F_ITER_t *it;
    F_PU_VAL_t *pu;
    F_SLAB_ENTRY_t *se;
    F_EXTENT_ENTRY_t *ee;
    mdhim_options_t *db_opts = NULL;
    size_t page, page_sz, pu_sz;
    uint64_t e, ul;
    unsigned long *p;
    unsigned int ui, e_sz, pages;
    unsigned int iext, ext;
    unsigned int dirty_sz, pu_factor;
    int pass, tg, t;
    int global, reversed;
    int v, rc, i;

    srand((unsigned int)time(NULL));
    page = getpagesize();
    global = reversed = 0;
    pass = rc = v = 0;
    e = ul = 0;
    ui = ext = 0;
    p = NULL; it = NULL;


    /*
     * Test group one: Init KV store
     */
    tg = 1;
    printf("Running group %d tests: start/stop KV store (MDHIM)\n", tg);
    pass = v = 0;
    e = 0;
    p = NULL; it = NULL;

    t = 1; /* Read default metadata (db_opts, layouts) config */
    rc = meta_init_conf(&md_cfg, &db_opts, argc, argv);
    if (rc != 0) goto err;
    if (!md_cfg.layout_name || !db_opts) goto err;

    t = 2; /* Load and parse layout configuration */
    rc = f_set_layout_info(&md_cfg);
    if (rc != 0) goto err;
    if ((lo_info = f_get_layout_info(layout_id)) == NULL) goto err;

    t = 3; /* Bring up DB thread */
    meta_init_store(db_opts);
    if (md == NULL || unifycr_indexes[0] == NULL) goto err;
    if (node_size <= 0) goto err;

    if (my_node == 0)
	unifycr_config_print(&md_cfg, NULL);

    printf("%d: Layout %d %s (%uD+%uP) chunk:%u slab_stripes:%u devnum:%u\n",
	my_node,
	lo_info->conf_id, lo_info->name, lo_info->data_chunks,
	(lo_info->chunks - lo_info->data_chunks), lo_info->chunk_sz,
	lo_info->slab_stripes, lo_info->devnum);

    /* Prepare for next test group: sanitize DB */
    t = 4; /* create bifold map */
    pages = 1;
    page_sz = pages*page;
    e_sz = 1;

    rcu_register_thread();
    m = map = f_map_init(F_MAPTYPE_BITMAP, e_sz, page_sz, 0);
    if (!m) goto err0;
    if (node_size <= 0) goto err0; /* check meta_init_store() */

    t = 5; /* Set map partition to part my_node of [0..node_size-1] */
    rc = f_map_init_prt(m, node_size, my_node, 0, global);
    if (rc) goto err1;

    t = 6; /* Register map with Layout0 */
    rc = f_map_register(m, layout_id);
    if (rc) goto err1;
    if (f_map_is_ro(m)) goto err1;

    t = 7; /* free map */
    f_map_exit(map); m = map = NULL;
    rcu_unregister_thread();

    t = 8; /* Remove old DB files for Layout0 */
    rc = meta_sanitize(); db_opts = NULL;
    if (rc) goto err;
    f_free_layout_info();
    unifycr_config_free(&md_cfg);


    /*
     * Test group two: Bitmaps with KV store backend, random keys
     */
    tg = 2;
    printf("Running group %d tests: bitmaps with KV store backend, random keys\n", tg);

    t = 0;
    /* Read default metadata (db_opts, layouts) config */
    rc = meta_init_conf(&md_cfg, &db_opts, argc, argv);
    if (rc != 0) goto err;
    /* Load and parse layout configuration */
    rc = f_set_layout_info(&md_cfg);
    if (rc != 0) goto err;
    /* Bring up DB thread */
    meta_init_store(db_opts);
    if (md == NULL) goto err;

    rcu_register_thread();

    /* For different BoS page size */
    for (pages = 1; pages < BOS_PAGE_MAX; pages++) {
	page_sz = pages*page;

	/* One and two-bits bitmaps */
	for (e_sz = 1; e_sz <= 2; e_sz++) {
	    pass = rc = v = 0;
	    e = 0;
	    p = NULL; it = NULL;

	    t = 1; /* Create one-bit (e_sz:1) or bifold (e_sz:2) map */
	    map = f_map_init(F_MAPTYPE_BITMAP, e_sz, (pages==1)?0:page_sz,
			   F_MAPLOCKING_DEFAULT);
	    if (!map) goto err0;
	    dirty_sz = map->geometry.bosl_pu_count;
	    pu_factor = map->geometry.pu_factor;

	    t = 2; /* Create bitmap for tracking writes to KV store */
	    mlog = f_map_init(F_MAPTYPE_BITMAP, 1, 0, 0);
	    if (!mlog) goto err0;

	    /* Test partitioned map with only partition, all partitions */
	    for (global = 0; global <= 1; global++) {
		printf("%d: with BoS pages:%u, %s%sbitmap\n",
		       my_node, pages, global?"global ":"", (e_sz==2)?"b":"");

		t = 3; /* Set map partition */
		m = map;
		/* partition:my_node of [0..node_size-1] */
		rc = f_map_init_prt(m, node_size, my_node, 0, global);
		if (rc || !(m->own_part ^ (unsigned)global)) goto err1;

		t = 4; /* Register map with Layout0 */
		rc = f_map_register(m, layout_id);
		if (rc != 0) goto err1;
		if (f_map_is_ro(m)) goto err1;

		/* Test iterations */
		for (pass = 0; pass < RND_REPS; pass++) {
		    /* actual and maximal numbers of entries in map */
		    int actual, max_globals;

		    t = 5; /* Load the map */
		    rc = f_map_load(m);
		    if (rc != 0) goto err1;
		    /* maximal numbers of entries in map */
		    max_globals = pass;
		    if (global)
			max_globals += (node_size - 1)*RND_REPS;

		    t = 6; /* Count entries in loaded map */
		    it = bitmap_new_iter(m,(e_sz==1)?laminated:cv_laminated);
		    it = f_map_seek_iter(it, 0); /* create BoS zero */
		    if (!it) goto err2;
		    actual = v = (int)f_map_weight(it, F_MAP_WHOLE);
		    if (!IN_RANGE(v, pass, max_globals)) goto err3;

		    t = 7; /* Add an unique random entry */
		    for (i = 0; i <= actual; i++) {
			/* random 31-bit key */
			e = gen_rand_key(ul, DB_KEY_BITS);
			if (f_map_has_globals(m)) {
			    /* avoid creation entry in foreign partition */
			    pu_round_up_to_part(e,
				m->geometry.intl_factor,
				m->parts, m->part);
			    /* assure the added global belongs to this partition */
			    if (!f_map_prt_my_global(m, e))
				goto err2;
			    assert((e >> DB_KEY_BITS) == 0);
			} else {
			    /* 'global' entry ID in partition map is limited
			    to DB_KEY_BITS so make 'local' entry ID shorter */
			    e /= m->parts;
			    assert((f_map_prt_to_global(m, e) >> DB_KEY_BITS) == 0);
			}
			/* ensure 'e' is not already in the map */
			if (!(p = f_map_get_p(mlog, e)))
			    break; /* Not in mlog */
			/* There is a BoS in mlog for 'e' */
			v = BIT_NR_IN_LONG(e);
			if (!test_bit(v, p))
			    break; /* Not in mlog */
		    }
		    rc = i;
		    if (i > actual) goto err3; /* failed to generate the key */

		    t = 8; /* Set [b]bitmap entry @e */
		    bosl = f_map_new_bosl(m, e); /* create BoS on demand */
		    /* set entry */
		    ul = e - bosl->entry0;
		    if (e_sz == 1)
			v = test_and_set_bit(ul, bosl->page);
		    else
			v = test_and_set_bbit(ul, BBIT_11, bosl->page);
		    if (v) goto err2;
		    /* printf(" Add e:%lu BoS/PU:%lu/%lu\n",
			e, e/m->bosl_entries, ul >> m->geometry.pu_factor); */

		    t = 9; /* Check the entry is set in memory */
		    if (!f_map_probe_iter_at(it, e, NULL)) goto err3;

		    t = 10; /* Mark PU durty */
		    f_map_mark_dirty_bosl(bosl, e);
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    if (v != 1) goto err2;
		    ui = ul >> m->geometry.pu_factor;
		    ul = find_first_bit(bosl->dirty, dirty_sz);
		    if (ul != ui) goto err2;

		    t = 11; /* flush map */
		    v = 0;
		    rc = f_map_flush(m);
		    if (rc != 0) goto err2;
		    /* check dirty bit cleared */
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    if (v) goto err2;

		    t = 12; /* Count map entries */
		    v = 0;
		    for_each_iter_from(it, 0)
			v++;
		    if (v != (actual + 1)) goto err3;
		    f_map_free_iter(it); it = NULL;

		    t = 13; /* Add 'e' to bitmap 'mlog' */
		    p = f_map_new_p(mlog, e);
		    if (!p) goto err2;
		    i = BIT_NR_IN_LONG(e);
		    if (test_and_set_bit(i, p)) goto err2; /* already set? */
		}

		t = 14; /* Check my entries in loaded map */
		e = 0;
		ul = 0;
		it = f_map_get_iter(map, PSET_NON_ZERO, 0);
		for_each_iter(it) {
		    e = it->entry;
		    if (global && !f_map_prt_my_global(map, e))
			continue;
		    /* present in log? */
		    if (!(p = f_map_get_p(mlog, e)))
			goto err3; /* No BoS in mlog for 'e' */
		    v = BIT_NR_IN_LONG(e);
		    if (!test_bit(v, p))
			goto err3; /* Not set in mlog bitmap */
		    /* check value */
		    if (!f_map_probe_iter_at(it, e, (void*)&v))
			goto err3;
		    if (v != ((1 << e_sz) - 1))
			goto err3;
		    ul++;
		}
		t = 15; /* Check number of entries in my partition */
		if (ul != RND_REPS) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 16; /* Check all log entries are in loaded map */
		ul = 0;
		v = 0;
		it = f_map_get_iter(mlog, F_BIT_CONDITION, 0);
		for_each_iter(it) {
		    e = it->entry;
		    if (!(p = f_map_get_p(map, e))) {
			bosl = it->bosl;
			goto err3;
		    }
		    if (e_sz == 1) {
			v = BIT_NR_IN_LONG(e);
			if (!test_bit(v, p)) goto err3;
		    } else {
			v = BBIT_NR_IN_LONG(e);
			if (!test_bbit(v, BBIT_11, p)) goto err3;
		    }
		    ul++;
		}
		t = 17; /* Check number of entries in log */
		if (ul != RND_REPS) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 18; /* Clear all PUs in DB */
		pu_sz = f_map_pu_size(map);
		/* Note: For bitmap (e_sz:1) the condition evaluated
		  as a boolean, cv_laminated is 'true' so that is the same
		  as F_BIT_CONDITION, i.e. iterate over set bits */
		it = f_map_get_iter(map, cv_laminated, 0);
		for_each_iter(it) {
		    e = it->entry;
		    if (global && !f_map_prt_my_global(map, e))
			continue;
		    /* clear PU of 'it->entry' in map */
		    bosl = it->bosl;
		    ui = it_to_pu(it);
		    p = bosl->page + f_map_pu_p_sz(map, ui, p);
		    memset(p, 0, pu_sz);
		    /* mark PU dirty */
		    f_map_mark_dirty(map, it->entry);
		}
		f_map_free_iter(it); it = NULL;
		/* delete empty PU in DB */
		rc = f_map_flush(map);
		if (rc != 0) goto err2;

		t = 19; /* Delete all BoS entries */
		it = f_map_get_iter(map, F_NO_CONDITION, 0);
		ui = map->nr_bosl;
		if (!global && (ui > RND_REPS+1)) goto err1; /* +1 for BoS #0 */
		ul = 0;
		for_each_iter(it) {
		    unsigned long bit;

		    bosl = it->bosl;
		    /* check dirty bits cleared for map partition */
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    for_each_set_bit(bit, bosl->dirty, dirty_sz) {
			printf("%d: dirty bit:%lu/%lu%s\n", my_node,
			    bosl->entry0/bosl->map->bosl_entries, bit,
			    (global&&!bosl_pu_in_my_part(bosl, bit))?" F":"");
		    }
		    if (v) goto err3;
		    if (atomic_read(&bosl->claimed) != 1) goto err3;
		    if ((rc = f_map_delete_bosl(map, bosl))) goto err2;
		    it->bosl = NULL; /* make for_each_iter() go next BoS */
		    ul++;
		}
		t = 20; /* Extra check: map BoS accounting (nr_bosl) */
		if (ul != ui) goto err1;
		v = f_map_max_bosl(map);
		if (map->nr_bosl) {
		    ul = ((unsigned long)v) * map->bosl_entries;
		    bosl = f_map_get_bosl(map, ul);
		    goto err2;
		}
		if (v) goto err3;
		f_map_free_iter(it); it = NULL;

		MPI_BARRIER;

		t = 21; /* Count foreign entries in loaded map */
		rc = f_map_init_prt(map, node_size, my_node, 0, 1);
		if (rc != 0) goto err1;
		rc = f_map_load(map);
		if (rc != 0) goto err1;
		ul = 0;
		it = f_map_get_iter(map, PSET_NON_ZERO, 0);
		for_each_iter(it) {
		    e = it->entry;
		    ul++;
		    printf("%lu e:%lu buf:%016lX\n", ul, e, *it->word_p);
		}
		if (ul) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 22; /* Delete all map BoSses */
		it = f_map_new_iter(map, F_NO_CONDITION, 0);
		it = f_map_next_bosl(it);
		for_each_bosl(it)
		    if ((rc = f_map_delete_bosl(map, it->bosl))) goto err3;
		if (map->nr_bosl) goto err1;
		f_map_free_iter(it); it = NULL;

		t = 23; /* Delete all bitmap entries */
		m = mlog; /* for error print */
		ul = mlog->nr_bosl;
		it = f_map_new_iter(mlog, F_BIT_CONDITION, 0);
		it = f_map_next_bosl(it);
		for_each_bosl(it) {
		    bosl = it->bosl;
		    v = atomic_read(&bosl->claimed);
		    if (v != 2) goto err3;
		    if ((rc = f_map_delete_bosl(mlog, bosl))) goto err3;
		}
		t = 24; /* Extra check: map BoS accounting (nr_bosl) */
		if ((ul = mlog->nr_bosl)) goto err1;
		if ((v = f_map_max_bosl(mlog))) goto err2;
		f_map_free_iter(it); it = NULL;
		bosl = NULL; p = NULL;
		// printf(" - %d Ok\n", t);

		rcu_quiescent_state();

		MPI_BARRIER;
	    }
	    t = 25; /* map exit: must survive */
	    f_map_exit(map);
	    f_map_exit(mlog);
	    m = mlog = map = NULL;
	}
    }
    rcu_unregister_thread();

    t = 26;
    rc = meta_sanitize();
    if (rc) goto err;
    f_free_layout_info();
    unifycr_config_free(&md_cfg);


    /*
     * Test group three: Bitmaps with KV store backend, sequential keys
     */
    tg = 3;
    printf("Running group %d tests: bitmaps with KV store backend, sequential keys\n", tg);
    global = 0;

    t = 0;
    /* Read default metadata (db_opts, layouts) config */
    rc = meta_init_conf(&md_cfg, &db_opts, argc, argv);
    if (rc != 0) goto err;
    /* Load and parse layout configuration */
    rc = f_set_layout_info(&md_cfg);
    if (rc != 0) goto err;
    /* Bring up DB thread */
    meta_init_store(db_opts);
    if (md == NULL) goto err;

    rcu_register_thread();

    /* For different BoS page size */
    for (pages = 1; pages < BOS_PAGE_MAX; pages++) {
	page_sz = pages*page;

	/* One and two-bits bitmaps */
	for (e_sz = 1; e_sz <= 2; e_sz++) {
	    pass = rc = v = 0;
	    p = NULL; it = NULL;

	    t = 1; /* Create one-bit (e_sz:1) or bifold (e_sz:2) map */
	    map = f_map_init(F_MAPTYPE_BITMAP, e_sz, (pages==1)?0:page_sz,
			   F_MAPLOCKING_DEFAULT);
	    if (!map) goto err0;
	    dirty_sz = map->geometry.bosl_pu_count;
	    pu_factor = map->geometry.pu_factor;

	    t = 2; /* Create bitmap for tracking writes to KV store */
	    mlog = f_map_init(F_MAPTYPE_BITMAP, 1, 0, 0);
	    if (!mlog) goto err0;

	    /* Test partitioned map with sequential keys going up or down */
	    for (reversed = 0; reversed <= 1; reversed++) {
		printf("%d: with BoS pages:%u, %sbitmap, %screasing keys\n",
		       my_node, pages, (e_sz==2)?"b":"", reversed?"de":"in");

		t = 3; /* Set map partition */
		m = map;
		/* partition:my_node of [0..node_size-1] */
		rc = f_map_init_prt(m, node_size, my_node, 0, global);
		if (rc || (m->own_part != 1U)) goto err1;

		t = 4; /* Register map with Layout0 */
		rc = f_map_register(m, layout_id);
		if (rc != 0) goto err1;
		if (f_map_is_ro(m)) goto err1;

		/* Test iterations */
		for (pass = 0; pass < SQ_REPS; pass++) {
		    /* Keys runs up [0..SQ_REPS[ or down [SQ_REPS-1..0] */
		    e = reversed? SQ_REPS-1-pass : pass;

		    t = 5; /* Load the map */
		    rc = f_map_load(m);
		    if (rc != 0) goto err1;

		    t = 6; /* Count entries in loaded map */
		    it = bitmap_new_iter(m,(e_sz==1)?laminated:cv_laminated);
		    it = f_map_seek_iter(it, 0); /* create BoS zero */
		    if (!it) goto err2;
		    v = (int)f_map_weight(it, F_MAP_WHOLE);
		    if (v != pass) goto err3;

		    t = 7; /* Sequentially add an unique map entry */
		    assert((f_map_prt_to_global(m, e) >> DB_KEY_BITS) == 0);
		    bosl = f_map_new_bosl(m, e); /* create BoS on demand */
		    if (bosl == NULL) goto err1;
		    /* check the entry is not set in memory */
		    if (f_map_probe_iter_at(it, e, NULL)) goto err3;

		    t = 8; /* Set entry to one (or BBIT_11) */
		    ul = e - bosl->entry0;
		    if (e_sz == 1)
			v = test_and_set_bit(ul, bosl->page);
		    else
			v = test_and_set_bbit(ul, BBIT_11, bosl->page);
		    if (v) goto err2;
		    /* printf(" Add e:%lu BoS/PU:%lu/%lu\n",
			e, e/m->bosl_entries, ul >> m->geometry.pu_factor); */

		    t = 9; /* Check the entry is set in memory */
		    if (!f_map_probe_iter_at(it, e, NULL)) goto err3;

		    t = 10; /* Mark PU durty */
		    f_map_mark_dirty_bosl(bosl, e);
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    if (v != 1) goto err2;
		    ui = ul >> m->geometry.pu_factor;
		    ul = find_first_bit(bosl->dirty, dirty_sz);
		    if (ul != ui) goto err2;

		    t = 11; /* flush map */
		    v = 0;
		    rc = f_map_flush(m);
		    if (rc != 0) goto err2;
		    /* check dirty bit cleared */
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    if (v) goto err2;

		    t = 12; /* Count map entries */
		    v = 0;
		    for_each_iter_from(it, 0)
			v++;
		    if (v != (pass + 1)) goto err3;
		    f_map_free_iter(it); it = NULL;

		    t = 13; /* Add 'e' to bitmap 'mlog' */
		    p = f_map_new_p(mlog, e);
		    if (!p) goto err2;
		    i = BIT_NR_IN_LONG(e);
		    if (test_and_set_bit(i, p)) goto err2; /* already set? */
		}

		t = 14; /* Check my entries in loaded map */
		e = 0;
		ul = 0;
		it = f_map_get_iter(map, PSET_NON_ZERO, 0);
		for_each_iter(it) {
		    e = it->entry;
		    /* present in log? */
		    if (!(p = f_map_get_p(mlog, e)))
			goto err3; /* No BoS in mlog for 'e' */
		    v = BIT_NR_IN_LONG(e);
		    if (!test_bit(v, p))
			goto err3; /* Not set in mlog bitmap */
		    /* check value */
		    if (!f_map_probe_iter_at(it, e, (void*)&v))
			goto err3;
		    if (v != ((1 << e_sz) - 1))
			goto err3;
		    ul++;
		}
		t = 15; /* Check number of entries in my partition */
		if (ul != SQ_REPS) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 16; /* Check all log entries are in loaded map */
		ul = 0;
		v = 0;
		it = f_map_get_iter(mlog, F_BIT_CONDITION, 0);
		for_each_iter(it) {
		    e = it->entry;
		    if (!(p = f_map_get_p(map, e))) {
			bosl = it->bosl;
			goto err3;
		    }
		    if (e_sz == 1) {
			v = BIT_NR_IN_LONG(e);
			if (!test_bit(v, p)) goto err3;
		    } else {
			v = BBIT_NR_IN_LONG(e);
			if (!test_bbit(v, BBIT_11, p)) goto err3;
		    }
		    ul++;
		}
		t = 17; /* Check number of entries in log */
		if (ul != SQ_REPS) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 18; /* Clear all PUs in DB */
		pu_sz = f_map_pu_size(map);
		/* Note: For bitmap (e_sz:1) the condition evaluated
		  as a boolean, cv_laminated is 'true' so that is the same
		  as F_BIT_CONDITION, i.e. iterate over set bits */
		it = f_map_get_iter(map, cv_laminated, 0);
		for_each_iter(it) {
		    e = it->entry;
		    /* clear PU of 'it->entry' in map */
		    bosl = it->bosl;
		    ui = it_to_pu(it);
		    p = bosl->page + f_map_pu_p_sz(map, ui, p);
		    memset(p, 0, pu_sz);
		    /* mark PU dirty */
		    f_map_mark_dirty(map, it->entry);
		}
		f_map_free_iter(it); it = NULL;
		/* delete empty PU in DB */
		rc = f_map_flush(map);
		if (rc != 0) goto err2;

		t = 19; /* Delete all BoS entries */
		it = f_map_get_iter(map, F_NO_CONDITION, 0);
		ui = map->nr_bosl;
		if (ui > SQ_REPS) goto err1;
		ul = 0;
		for_each_iter(it) {
		    unsigned long bit;

		    bosl = it->bosl;
		    /* check dirty bits cleared for map partition */
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    for_each_set_bit(bit, bosl->dirty, dirty_sz) {
			printf("%d: dirty bit:%lu/%lu\n", my_node,
			    bosl->entry0/bosl->map->bosl_entries, bit);
		    }
		    if (v) goto err3;
		    if (atomic_read(&bosl->claimed) != 1) goto err3;
		    if ((rc = f_map_delete_bosl(map, bosl))) goto err2;
		    it->bosl = NULL; /* make for_each_iter() go next BoS */
		    ul++;
		}
		t = 20; /* Extra check: map BoS accounting (nr_bosl) */
		v = f_map_max_bosl(map);
		if (ul != ui) goto err1;
		if (map->nr_bosl) goto err2;
		if (v) goto err3;
		f_map_free_iter(it); it = NULL;

		MPI_BARRIER;

		t = 21; /* Count foreign entries in loaded map */
		rc = f_map_init_prt(map, node_size, my_node, 0, 1);
		if (rc != 0) goto err1;
		rc = f_map_load(map);
		if (rc != 0) goto err1;
		ul = 0;
		it = f_map_get_iter(map, PSET_NON_ZERO, 0);
		for_each_iter(it) {
		    e = it->entry;
		    ul++;
		    printf("%lu e:%lu buf:%016lX\n", ul, e, *it->word_p);
		}
		if (ul) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 22; /* Delete all map BoSses */
		it = f_map_new_iter(map, F_NO_CONDITION, 0);
		it = f_map_next_bosl(it);
		for_each_bosl(it)
		    if ((rc = f_map_delete_bosl(map, it->bosl))) goto err3;
		if (map->nr_bosl) goto err1;
		f_map_free_iter(it); it = NULL;

		t = 23; /* Delete all bitmap entries */
		m = mlog; /* for error print */
		ul = mlog->nr_bosl;
		it = f_map_new_iter(mlog, F_BIT_CONDITION, 0);
		it = f_map_next_bosl(it);
		for_each_bosl(it) {
		    bosl = it->bosl;
		    v = atomic_read(&bosl->claimed);
		    if (v != 2) goto err3;
		    if ((rc = f_map_delete_bosl(mlog, bosl))) goto err3;
		}
		t = 24; /* Extra check: map BoS accounting (nr_bosl) */
		if ((ul = mlog->nr_bosl)) goto err1;
		if ((v = f_map_max_bosl(mlog))) goto err2;
		f_map_free_iter(it); it = NULL;
		bosl = NULL; p = NULL;
		// printf(" - %d Ok\n", t);

		rcu_quiescent_state();

		MPI_BARRIER;
	    }
	    t = 25; /* map exit: must survive */
	    f_map_exit(map);
	    f_map_exit(mlog);
	    m = mlog = map = NULL;
	}
    }
    rcu_unregister_thread();

    t = 26;
    rc = meta_sanitize();
    if (rc) goto err;
    f_free_layout_info();
    unifycr_config_free(&md_cfg);


    /*
     * Test group four: Structured map with KV store backend, random keys
     */
    tg = 4;
    printf("Running group %d tests: structured map with KV store backend, random keys\n", tg);

    t = 0;
    /* Read default metadata (db_opts, layouts) config */
    rc = meta_init_conf(&md_cfg, &db_opts, argc, argv);
    if (rc != 0) goto err;
    /* Load and parse layout configuration */
    rc = f_set_layout_info(&md_cfg);
    if (rc != 0) goto err;
    /* Bring up DB thread */
    meta_init_store(db_opts);
    if (md == NULL) goto err;

    rcu_register_thread();

    /* For different BoS page size */
    for (pages = 1; pages < BOS_PAGE_MAX; pages++) {
	page_sz = pages*page;

	/* Number of extents in slab entry */
	for (ext = 1; ext <= SM_EXT_MAX; ext++) {
	    iext = ext - 1; /* extent index in Slab map: at top extent entry */
	    pass = rc = v = 0;
	    e = 0;
	    p = NULL; it = NULL;

	    t = 1; /* Create structured map */
	    e_sz = sizeof(F_SLAB_ENTRY_t) + ext*sizeof(F_EXTENT_ENTRY_t);
	    assert(!map);
	    map = f_map_init(F_MAPTYPE_STRUCTURED, e_sz, (pages==1)?0:page_sz,
			   F_MAPLOCKING_DEFAULT);
	    if (!map) goto err0;
	    dirty_sz = map->geometry.bosl_pu_count;
	    pu_factor = map->geometry.pu_factor;

	    t = 2; /* Create local bitmap for tracking writes to KV store */
	    assert(!mlog);
	    mlog = f_map_init(F_MAPTYPE_BITMAP, 1, 0, 0);
	    if (!mlog) goto err0;

	    /* Test partitioned map with only partition, all partitions */
	    for (global = 0; global <= 1; global++) {
		printf("%d: with BoS pages:%u, %sstructured map, %d extent%s\n",
		       my_node, pages, global?"global ":"", ext, (ext==1)?"":"s");

		t = 3; /* Set map partition */
		m = map;
		/* partition:my_node of [0..node_size-1] */
		rc = f_map_init_prt(m, node_size, my_node, 0, global);
		if (rc) goto err1;

		t = 4; /* Register map with Layout0 */
		rc = f_map_register(m, layout_id);
		if (rc != 0) goto err1;
		if (f_map_is_ro(m)) goto err1;

		/* Test iterations */
		for (pass = 0; pass < RND_REPS; pass++) {
		    /* actual and maximal numbers of entries in map */
		    int actual, max_globals;

		    t = 5; /* Load empty map */
		    rc = f_map_load(m);
		    if (rc != 0) goto err1;
		    /* maximal numbers of entries in map */
		    max_globals = pass;
		    if (global)
			max_globals += (node_size - 1)*RND_REPS;

		    t = 6; /* Count entries in loaded map */
		    it = f_map_new_iter(m, sm_extent_failed, iext);
		    it = f_map_seek_iter(it, 0); /* create BoS zero */
		    if (!it) goto err2;
		    actual = v = (int)f_map_weight(it, F_MAP_WHOLE);
		    if (!IN_RANGE(v, pass, max_globals)) goto err3;

		    t = 7; /* Add an unique random entry */
		    for (i = 0; i <= actual; i++) {
			/* random 31-bit key */
			e = gen_rand_key(ul, DB_KEY_BITS);
			if (f_map_has_globals(m)) {
			    /* avoid creation entry in foreign partition */
			    pu_round_up_to_part(e,
				m->geometry.intl_factor,
				m->parts, m->part);
			    /* assure the added global belongs to this partition */
			    if (!f_map_prt_my_global(m, e))
				goto err2;
			    assert((e >> DB_KEY_BITS) == 0);
			} else {
			    /* 'global' entry ID in partition map is limited
			    to DB_KEY_BITS so make 'local' entry ID shorter */
			    e /= m->parts;
			    assert((f_map_prt_to_global(m, e) >> DB_KEY_BITS) == 0);
			}
			/* ensure 'e' is not already in the map */
			if (!(p = f_map_get_p(mlog, e)))
			    break; /* Not in mlog */
			/* There is a BoS in mlog for 'e' */
			v = BIT_NR_IN_LONG(e);
			if (!test_bit(v, p))
			    break; /* Not in mlog */
		    }
		    rc = i;
		    if (i > actual) goto err3; /* failed to generate the key */

		    t = 8; /* Set slab map entry @e */
		    bosl = f_map_new_bosl(m, e); /* create BoS on demand */
		    ul = e - bosl->entry0;
		    if (!(p = f_map_get_p(m, e))) goto err2;
		    /* printf(" Add e:%lu BoS/PU:%lu/%lu p:%p\n",
			e, e/m->bosl_entries, ul >> pu_factor, p); */
		    pu = (F_PU_VAL_t *)p;
		    /* it should be empty */
		    se = &pu->se;
		    v = __builtin_popcountll(se->_v128);
		    if (v) goto err2;
		    ee = &pu->ee;
		    for (ui = 0; ui < ext; ui++, ee++) {
			v = __builtin_popcountl(ee->_v64);
			if (v) goto err2;
		    }
		    /* set SM entry to 'mapped' and count 'mapped' entries */
		    se->mapped = 1;
		    ee = &pu->ee + iext; /* index of top extent */
		    ee->failed = 1;

		    t = 9; /* Check the entry is set in memory */
		    if (!f_map_probe_iter_at(it, e, NULL)) goto err3;

		    t = 10; /* Mark PU durty */
		    ui = ul >> pu_factor;
		    f_map_mark_dirty_bosl(bosl, e);
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    if (v != 1) goto err2;
		    ul = find_first_bit(bosl->dirty, dirty_sz);
		    if (ul != ui) goto err2;

		    t = 11; /* flush map */
		    rc = f_map_flush(m);
		    if (rc != 0) goto err2;
		    /* check dirty bit cleared */
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    if (v) goto err2;

		    t = 12; /* Count man entries */
		    v = 0;
		    for_each_iter_from(it, 0)
			v++;
		    if (v != (actual + 1)) goto err3;
		    f_map_free_iter(it); it = NULL;

		    t = 13; /* Add to 'mlog' the new map entry 'e' */
		    p = f_map_new_p(mlog, e);
		    if (!p) goto err2;
		    i = BIT_NR_IN_LONG(e);
		    if (test_and_set_bit(i, p)) goto err2; /* already set? */
		}

		t = 14; /* Check my entries in loaded map */
		e = ul = 0;
		it = f_map_get_iter(map, se_or_ee_not_zero, ext);
		for_each_iter(it) {
		    e = it->entry;
		    if (global && !f_map_prt_my_global(map, e))
			continue;
		    /* present in log? */
		    ui = 0;
		    bosl = it->bosl;
		    if (!(p = f_map_get_p(mlog, e)))
			goto err3; /* No BoS in mlog for 'e' */
		    ui = 1;
		    v = BIT_NR_IN_LONG(e);
		    if (!(rc = test_bit(v, p)))
			goto err3; /* Not in mlog: extra map entry? */
		    /* check value */
		    ui = 2;
		    if (!f_map_probe_iter_at(it, e, (void*)&pu))
			goto err3;
		    ui = 3;
		    if (!pu || !(pu->se.mapped))
			goto err3;
		    ui = 4;
		    ee = &pu->ee;
		    ee += iext; /* index of top extent */
		    if (!ee->failed) goto err3;
		    ul++;
		}
		t = 15; /* Check number of entries in my partition */
		if (ul != RND_REPS) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 16; /* Check all log entries are in loaded map */
		ul = 0;
		it = f_map_get_iter(mlog, F_BIT_CONDITION, 0);
		for_each_iter(it) {
		    v = 0;
		    e = it->entry;
		    bosl = it->bosl;
		    if (!(p = f_map_get_p(map, e)))
			goto err3;
		    for (ui = 0; ui < e_sz/sizeof(*p); ui++)
			v += __builtin_popcountl(*p++);
		    if (v != 2) goto err3;
		    ul++;
		}
		t = 17; /* Check number of entries in log */
		if (ul != RND_REPS) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 18; /* Clear all PUs in DB */
		pu_sz = f_map_pu_size(map);
		it = f_map_get_iter(map, sm_extent_failed, iext);
		for_each_iter(it) {
		    e = it->entry;
		    if (global && !f_map_prt_my_global(map, e))
			continue;
		    /* clear PU of 'it->entry' in map */
		    bosl = it->bosl;
		    ui = it_to_pu(it);
		    p = bosl->page + f_map_pu_p_sz(map, ui, p);
		    memset(p, 0, pu_sz);
		    /* mark PU dirty */
		    f_map_mark_dirty(map, it->entry);
		}
		f_map_free_iter(it); it = NULL;
		/* delete empty PU in DB */
		rc = f_map_flush(map);
		if (rc != 0) goto err2;

		t = 19; /* Delete all BoS entries */
		it = f_map_get_iter(map, F_NO_CONDITION, 0);
		ui = map->nr_bosl;
		if (!global && (ui > RND_REPS+1)) goto err1; /* +1 for BoS #0 */
		ul = 0;
		for_each_iter(it) {
		    unsigned long bit;

		    bosl = it->bosl;
		    /* check dirty bits cleared for map partition */
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    for_each_set_bit(bit, bosl->dirty, dirty_sz) {
			printf("%d: dirty bit:%lu/%lu%s\n", my_node,
			    bosl->entry0/bosl->map->bosl_entries, bit,
			    (global&&!bosl_pu_in_my_part(bosl, bit))?" F":"");
		    }
		    if (v) goto err3;
		    /* BoS used counter? */
		    if (atomic_read(&bosl->claimed) != 1) goto err3;
		    /* delete BoS */
		    if ((rc = f_map_delete_bosl(map, bosl))) goto err2;
		    it->bosl = NULL; /* make for_each_iter() go next BoS */
		    ul++;
		}
		t = 20; /* Extra check: map BoS accounting (nr_bosl) */
		if (ul != ui) goto err1;
		v = f_map_max_bosl(map);
		if (map->nr_bosl) {
		    ul = ((unsigned long)v) * map->bosl_entries;
		    bosl = f_map_get_bosl(map, ul);
		    goto err2;
		}
		if (v) goto err3;
		f_map_free_iter(it); it = NULL;
		bosl = NULL; p = NULL;

		MPI_BARRIER;

		t = 21; /* Count foreign entries in loaded map */
		/* load all map partitions */
		rc = f_map_init_prt(map, node_size, my_node, 0, 1);
		if (rc != 0) goto err1;
		rc = f_map_load(map);
		if (rc != 0) goto err1;
		ul = 0;
		it = f_map_get_iter(map, se_or_ee_not_zero, ext);
		for_each_iter(it) {
		    e = it->entry;
		    ul++;
		    printf("%lu e:%lu buf:%016lX\n", ul, e, *it->word_p);
		}
		if (ul) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 22; /* Delete all map BoSses */
		it = f_map_new_iter(map, F_NO_CONDITION, 0);
		it = f_map_next_bosl(it);
		for_each_bosl(it)
		    if ((rc = f_map_delete_bosl(map, it->bosl))) goto err3;
		if (map->nr_bosl) goto err1;
		f_map_free_iter(it); it = NULL;

		t = 23; /* Delete all log entries */
		m = mlog; /* for error print */
		ul = mlog->nr_bosl;
		it = f_map_new_iter(mlog, F_BIT_CONDITION, 0);
		it = f_map_next_bosl(it);
		for_each_bosl(it) {
		    bosl = it->bosl;
		    v = atomic_read(&bosl->claimed);
		    if (v != 2) goto err3;
		    if ((rc = f_map_delete_bosl(mlog, bosl))) goto err3;
		}
		t = 24; /* Extra check: map BoS accounting (nr_bosl) */
		if ((ul = mlog->nr_bosl)) goto err1;
		if ((v = f_map_max_bosl(mlog))) goto err2;
		f_map_free_iter(it); it = NULL;
		bosl = NULL; p = NULL;
		// printf(" - %d Ok\n", t);

		rcu_quiescent_state();

		MPI_BARRIER;
	    }
	    t = 25; /* map exit: must survive */
	    f_map_exit(map);
	    f_map_exit(mlog);
	    m = mlog = map = NULL;
	}
    }
    rcu_unregister_thread();

    t = 26;
    rc = meta_sanitize();
    if (rc) goto err1;
    f_free_layout_info();
    unifycr_config_free(&md_cfg);


    /*
     * Test group five: Structured map with KV store backend, sequential keys
     */
    tg = 5;
    printf("Running group %d tests: structured map with KV store backend, sequential keys\n", tg);
    global = 0;

    t = 0;
    /* Read default metadata (db_opts, layouts) config */
    rc = meta_init_conf(&md_cfg, &db_opts, argc, argv);
    if (rc != 0) goto err;
    /* Load and parse layout configuration */
    rc = f_set_layout_info(&md_cfg);
    if (rc != 0) goto err;
    /* Bring up DB thread */
    meta_init_store(db_opts);
    if (md == NULL) goto err;

    rcu_register_thread();

    /* For different BoS page size */
    for (pages = 1; pages < BOS_PAGE_MAX; pages++) {
	page_sz = pages*page;

	/* Number of extents in slab entry */
	for (ext = 1; ext <= SM_EXT_MAX; ext++) {
	    iext = ext - 1; /* extent index in Slab map: at top extent entry */
	    pass = rc = v = 0;
	    e = 0;
	    p = NULL; it = NULL;

	    t = 1; /* Create structured map */
	    e_sz = sizeof(F_SLAB_ENTRY_t) + ext*sizeof(F_EXTENT_ENTRY_t);
	    assert(!map);
	    map = f_map_init(F_MAPTYPE_STRUCTURED, e_sz, (pages==1)?0:page_sz,
			   F_MAPLOCKING_DEFAULT);
	    if (!map) goto err0;
	    dirty_sz = map->geometry.bosl_pu_count;
	    pu_factor = map->geometry.pu_factor;

	    t = 2; /* Create local bitmap for tracking writes to KV store */
	    assert(!mlog);
	    mlog = f_map_init(F_MAPTYPE_BITMAP, 1, 0, 0);
	    if (!mlog) goto err0;

	    /* Test partitioned map with sequential keys going up or down */
	    for (reversed = 0; reversed <= 1; reversed++) {
		printf("%d: with BoS pages:%u, structured map, %d extent%s, %screasing keys\n",
		       my_node, pages, ext, (ext==1)?"":"s", reversed?"de":"in");

		t = 3; /* Set map partition */
		m = map;
		/* partition:my_node of [0..node_size-1] */
		rc = f_map_init_prt(m, node_size, my_node, 0, global);
		if (rc || (m->own_part != 1U)) goto err1;

		t = 4; /* Register map with Layout0 */
		rc = f_map_register(m, layout_id);
		if (rc != 0) goto err1;
		if (f_map_is_ro(m)) goto err1;

		/* Test iterations */
		for (pass = 0; pass < SQ_REPS; pass++) {
		    /* Keys runs up [0..SQ_REPS[ or down [SQ_REPS-1..0] */
		    e = reversed? SQ_REPS-1-pass : pass;

		    t = 5; /* Load empty map */
		    rc = f_map_load(m);
		    if (rc != 0) goto err1;

		    t = 6; /* Count entries in loaded map */
		    it = f_map_new_iter(m, sm_extent_failed, iext);
		    it = f_map_seek_iter(it, 0); /* create BoS zero */
		    if (!it) goto err2;
		    v = (int)f_map_weight(it, F_MAP_WHOLE);
		    if (v != pass) goto err3;

		    t = 7; /* Sequentially add an unique map entry */
		    assert((f_map_prt_to_global(m, e) >> DB_KEY_BITS) == 0);
		    bosl = f_map_new_bosl(m, e); /* create BoS on demand */
		    if (bosl == NULL) goto err1;
		    ul = e - bosl->entry0;
		    /* check the entry is not set in memory */
		    if (!(p = f_map_get_p(m, e))) goto err2;
		    /* printf(" Add e:%lu BoS/PU:%lu/%lu p:%p\n",
			e, e/m->bosl_entries, ul >> pu_factor, p); */
		    pu = (F_PU_VAL_t *)p;
		    se = &pu->se;
		    v = __builtin_popcountll(se->_v128);
		    if (v) goto err2;
		    ee = &pu->ee;
		    for (ui = 0; ui < ext; ui++, ee++) {
			v = __builtin_popcountl(ee->_v64);
			if (v) goto err2;
		    }

		    t = 8; /* Set slab map entry @e */
		    /* set SM entry to 'mapped' and count 'mapped' entries */
		    se->mapped = 1;
		    ee = &pu->ee + iext; /* index of top extent */
		    ee->failed = 1;

		    t = 9; /* Check the entry is set in memory */
		    if (!f_map_probe_iter_at(it, e, NULL)) goto err3;

		    t = 10; /* Mark PU durty */
		    ui = ul >> pu_factor;
		    f_map_mark_dirty_bosl(bosl, e);
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    if (v != 1) goto err2;
		    ul = find_first_bit(bosl->dirty, dirty_sz);
		    if (ul != ui) goto err2;

		    t = 11; /* flush map */
		    rc = f_map_flush(m);
		    if (rc != 0) goto err2;
		    /* check dirty bit cleared */
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    if (v) goto err2;

		    t = 12; /* Count man entries */
		    v = 0;
		    for_each_iter_from(it, 0)
			v++;
		    if (v != (pass + 1)) goto err3;
		    f_map_free_iter(it); it = NULL;

		    t = 13; /* Add to 'mlog' the new map entry 'e' */
		    p = f_map_new_p(mlog, e);
		    if (!p) goto err2;
		    i = BIT_NR_IN_LONG(e);
		    if (test_and_set_bit(i, p)) goto err2; /* already set? */
		}

		t = 14; /* Check my entries in loaded map */
		e = ul = 0;
		it = f_map_get_iter(map, se_or_ee_not_zero, ext);
		for_each_iter(it) {
		    e = it->entry;
		    /* present in log? */
		    ui = 0;
		    bosl = it->bosl;
		    if (!(p = f_map_get_p(mlog, e)))
			goto err3; /* No BoS in mlog for 'e' */
		    ui = 1;
		    v = BIT_NR_IN_LONG(e);
		    if (!(rc = test_bit(v, p)))
			goto err3; /* Not in mlog: extra map entry? */
		    /* check value */
		    ui = 2;
		    if (!f_map_probe_iter_at(it, e, (void*)&pu))
			goto err3;
		    ui = 3;
		    if (!pu || !(pu->se.mapped))
			goto err3;
		    ui = 4;
		    ee = &pu->ee;
		    ee += iext; /* index of top extent */
		    if (!ee->failed) goto err3;
		    ul++;
		}
		t = 15; /* Check number of entries in my partition */
		if (ul != SQ_REPS) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 16; /* Check all log entries are in loaded map */
		ul = 0;
		it = f_map_get_iter(mlog, F_BIT_CONDITION, 0);
		for_each_iter(it) {
		    v = 0;
		    e = it->entry;
		    bosl = it->bosl;
		    if (!(p = f_map_get_p(map, e)))
			goto err3;
		    for (ui = 0; ui < e_sz/sizeof(*p); ui++)
			v += __builtin_popcountl(*p++);
		    if (v != 2) goto err3;
		    ul++;
		}
		t = 17; /* Check number of entries in log */
		if (ul != SQ_REPS) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 18; /* Clear all PUs in DB */
		pu_sz = f_map_pu_size(map);
		it = f_map_get_iter(map, sm_extent_failed, iext);
		for_each_iter(it) {
		    e = it->entry;
		    /* clear PU of 'it->entry' in map */
		    bosl = it->bosl;
		    ui = it_to_pu(it);
		    p = bosl->page + f_map_pu_p_sz(map, ui, p);
		    memset(p, 0, pu_sz);
		    /* mark PU dirty */
		    f_map_mark_dirty(map, it->entry);
		}
		f_map_free_iter(it); it = NULL;
		/* delete empty PU in DB */
		rc = f_map_flush(map);
		if (rc != 0) goto err2;

		t = 19; /* Delete all BoS entries */
		it = f_map_get_iter(map, F_NO_CONDITION, 0);
		ui = map->nr_bosl;
		if (ui > SQ_REPS) goto err1; /* +1 for BoS #0 */
		ul = 0;
		for_each_iter(it) {
		    unsigned long bit;

		    bosl = it->bosl;
		    /* check dirty bits cleared for map partition */
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    for_each_set_bit(bit, bosl->dirty, dirty_sz) {
			printf("%d: dirty bit:%lu/%lu\n", my_node,
			    bosl->entry0/bosl->map->bosl_entries, bit);
		    }
		    if (v) goto err3;
		    /* BoS used counter? */
		    if (atomic_read(&bosl->claimed) != 1) goto err3;
		    /* delete BoS */
		    if ((rc = f_map_delete_bosl(map, bosl))) goto err2;
		    it->bosl = NULL; /* make for_each_iter() go next BoS */
		    ul++;
		}
		t = 20; /* Extra check: map BoS accounting (nr_bosl) */
		if (ul != ui) goto err1;
		v = f_map_max_bosl(map);
		if (map->nr_bosl) {
		    ul = ((unsigned long)v) * map->bosl_entries;
		    bosl = f_map_get_bosl(map, ul);
		    goto err2;
		}
		if (v) goto err3;
		f_map_free_iter(it); it = NULL;
		bosl = NULL; p = NULL;

		MPI_BARRIER;

		t = 21; /* Count foreign entries in loaded map */
		/* load all map partitions */
		rc = f_map_init_prt(map, node_size, my_node, 0, 1);
		if (rc != 0) goto err1;
		rc = f_map_load(map);
		if (rc != 0) goto err1;
		ul = 0;
		it = f_map_get_iter(map, se_or_ee_not_zero, ext);
		for_each_iter(it) {
		    e = it->entry;
		    ul++;
		    printf("%lu e:%lu buf:%016lX\n", ul, e, *it->word_p);
		}
		if (ul) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 22; /* Delete all map BoSses */
		it = f_map_new_iter(map, F_NO_CONDITION, 0);
		it = f_map_next_bosl(it);
		for_each_bosl(it)
		    if ((rc = f_map_delete_bosl(map, it->bosl))) goto err3;
		if (map->nr_bosl) goto err1;
		f_map_free_iter(it); it = NULL;

		t = 23; /* Delete all log entries */
		m = mlog; /* for error print */
		ul = mlog->nr_bosl;
		it = f_map_new_iter(mlog, F_BIT_CONDITION, 0);
		it = f_map_next_bosl(it);
		for_each_bosl(it) {
		    bosl = it->bosl;
		    v = atomic_read(&bosl->claimed);
		    if (v != 2) goto err3;
		    if ((rc = f_map_delete_bosl(mlog, bosl))) goto err3;
		}
		t = 24; /* Extra check: map BoS accounting (nr_bosl) */
		if ((ul = mlog->nr_bosl)) goto err1;
		if ((v = f_map_max_bosl(mlog))) goto err2;
		f_map_free_iter(it); it = NULL;
		bosl = NULL; p = NULL;
		// printf(" - %d Ok\n", t);

		rcu_quiescent_state();

		MPI_BARRIER;
	    }
	    t = 25; /* map exit: must survive */
	    f_map_exit(map);
	    f_map_exit(mlog);
	    m = mlog = map = NULL;
	}
    }
    rcu_unregister_thread();

    t = 26;
    rc = meta_sanitize();
    if (rc) goto err1;
    f_free_layout_info();
    unifycr_config_free(&md_cfg);

    MPI_BARRIER;
    MPI_Finalize();

    if (my_node == 0)
	printf("SUCCESS\n");
    return 0;

err3:
    if (it) {
	printf("  Iterator @%s%lu PU:%lu p:%p -> %016lx\n",
	    f_map_iter_depleted(it)?"END ":"", it->entry,
	    (it->entry % it->map->bosl_entries)/(1U << it->map->geometry.pu_factor),
	    it->word_p, *it->word_p);
	if (f_map_entry_in_bosl(it->bosl, it->entry))
	    printf("    entry @%lu in BoS:%lu\n",
		   it->entry - it->bosl->entry0,
		   it->bosl->entry0/it->map->bosl_entries);
    }
err2:
    if (bosl) {
	printf("  BoS #%lu starts @%lu page:%p\n",
	    bosl->entry0/bosl->map->bosl_entries, bosl->entry0,
	    bosl->page);
    }
err1:
    if (m) {
	uint64_t max_bosl = f_map_max_bosl(m);

	printf("  Map BoS sz:%lu (%u entries), %u per PU, %u PU(s) per BoS\n",
	    m->bosl_sz, m->bosl_entries,
	    1U << m->geometry.pu_factor,
	    m->geometry.bosl_pu_count);
	if (max_bosl || m->nr_bosl)
	    printf("  map BoS count:%lu, max:%lu\n", m->nr_bosl, max_bosl-1);
	else
	    printf("  map BoS count:0\n");
	printf("  Part %u of %u in %spartitioned %s R%c map; "
		"interleave:%u entries, %u PUs\n",
	    m->part, m->parts, (m->parts<=1)?"non-":"",
	    f_map_has_globals(m)?"global":"local",
	    f_map_is_ro(m)?'O':'W',
	    1U<<m->geometry.intl_factor,
	    1U<<(m->geometry.intl_factor-m->geometry.pu_factor));
	printf("    entry:%lu @%lu PU:%lu\n",
	    e, (e % m->bosl_entries),
	    (e % m->bosl_entries)/(1U << m->geometry.pu_factor));
    }
    if (p != NULL)
	printf("  p:%p -> %016lX\n", p, *p);
err0:
    printf("  Test parameters: entry_size:%u, %u pages per BoS\n",
	e_sz, pages);
    if (tg==3 || tg==5)
	printf("  sequential keys go %s\n", reversed?"down":"up");
    if (ext)
	printf("  slab map has %d extent(s)\n", ext);
    printf("  Test variables: rc=%d var=%d ul=%lu ui=%u\n",
	rc, v, ul, ui);
err:
    printf("%d - Test %d.%d (pass %d) FAILED\n", my_node, tg, t, pass);
    MPI_Abort(MPI_COMM_WORLD, 1);
    return 1;
}

