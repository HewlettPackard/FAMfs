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

#include "famfs_bitmap.h"
#include "f_map.h"

//#include "famfs_configurator.h"
//#include "mdhim_options.h"
#include "mdhim.h"


/* TEST options */
#define TEST_MDHIM_DBG	0	/* 1: MDHIM debug enabled */
#define RND_REPS	1000	/* number of passes for random test */
#define BOS_PAGE_MAX	4	/* max BoS page size, in kernel pages */
#define layout_id	0	/* use Layout 0 default configuration */
#define MEM_KEY_BITS	64	/* in-memory maps: max global entry bits */
#define DB_KEY_BITS	31	/* DB-backed maps: max global entry bits */
//#define MAX_PMAP_SZ	(1UL << DB_KEY_BITS)
#define META_DB_PATH	"/dev/shm"


#define e_to_bosl(bosl, e)	(e - bosl->entry0)
#define it_to_pu(it)		(e_to_bosl(it->bosl, it->entry) >>	\
				 it->map->geometry.pu_factor)

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
static int my_node = 1;
static int node_size = 2;

static int create_persistent_map(int map_id, int intl, char *name);
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
	if (server_cfg_p->meta_db_path) {
		free(server_cfg_p->meta_db_path);
		server_cfg_p->meta_db_path = strdup(META_DB_PATH);
	}
	f_set_meta_iface(&iface);
	return mdhim_options_cfg(server_cfg_p, db_opts_p);
}

static void meta_init_store(mdhim_options_t *db_opts) {
	int i;
#if TEST_MDHIM_DBG > 0
	mdhim_options_set_debug_level(db_opts, MLOG_DBG); /* Uncomment for DB DEBUG! */
#endif
	md = mdhimInit(NULL, db_opts);
	unifycr_indexes[0] = md->primary_index;
	for (i = 1; i <= 2*F_LAYOUTS_MAX; i++)
		unifycr_indexes[i] = NULL;
}

static int meta_sanitize() {
    mdhim_options_t *db_opts;
    int *ids, *types, max_id, indexes, i;
    int rank, ret, rc = 0;

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
	max_id++;
    }
    mdhimClose(md);

    /* TODO: For each registered DB table */
    for (i = 0; i < max_id; i++) {
        sprintf(dbfilename, "%s/%s-%d-%d", db_opts->db_path,
                db_opts->db_name, ids[i], rank);
        sprintf(statfilename, "%s_stats", dbfilename);
        sprintf(manifestname, "%s%d_%d_%d", db_opts->manifest_path,
                types[i], ids[i], rank);

        ret = mdhimSanitize(dbfilename, statfilename, manifestname);
        if (rc == 0)
                rc = ret; /* report first error */
    }
    free(ids);
    free(types);
    mdhim_options_destroy(db_opts);
    md = NULL;

    return rc;
}

static int create_persistent_map(int map_id, int intl, char *name)
{
    unsigned int id = map_id+1;

    if (id > 2*F_LAYOUTS_MAX)
	return -1;
    if (unifycr_indexes[id] == NULL) {
	unifycr_indexes[id] = create_global_index(md, md->db_opts->rserver_factor,
					intl, LEVELDB, MDHIM_LONG_INT_KEY, name);
	if (unifycr_indexes[id] == NULL)
		return -1;
 /*
	printf(" create_persistent_map:%d %s index[%u] interleave:%d\n",
	       map_id, name, id, intl);
 */
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
    unsigned int n = *(unsigned int *)arg;

    const F_SLAB_ENTRY_t *se = &entry->se;
    const F_EXTENT_ENTRY_t *ee = &entry->ee + n;

    //assert(entry.se.mapped);
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

#define bitmap_new_iter(m, c)	(f_map_new_iter(m, c, 0))

/* Example of Claim Vector condition: BBPAT_11 - entry is "laminated" */
static F_COND_t cv_laminated = {
    .pset = CV_LAMINATED_P,
};

/* The [simple] bitmap condition: a bit is set */
static F_COND_t laminated = F_BIT_CONDITION;


/* unittest: f_map */
int main (int argc, char *argv[]) {
    F_MAP_t *m;
    F_BOSL_t *bosl;
    F_ITER_t *it;
    F_PU_VAL_t *pu;
    F_SLAB_ENTRY_t *se;
    F_EXTENT_ENTRY_t *ee;
    mdhim_options_t *db_opts = NULL;
    size_t page, page_sz, pu_sz;
    uint64_t e, ul;
    unsigned long *p;
    unsigned int ui, e_sz, long_bbits, pages;
    unsigned int iext, ext;
    int pass, tg, t;
    int global, v, rc;
    int i, ii;

    srand((unsigned int)time(NULL));
    page = getpagesize();
    global = 1;
    pass = rc = v = 0;
    e = ul = 0;
    ui = ext = 0;
    p = NULL; it = NULL;

    /*
     * Test group one: in-memory bitmaps
     */
    tg = 1;
    printf("Running group %d tests: in-memory bitmaps\n", tg);

    rcu_register_thread();
    /* For dofferent BoS page size */
    for (pages = 1; pages < BOS_PAGE_MAX; pages++) {
	page_sz = pages*page;
	/* One and two-bits bitmaps */
	for (e_sz = 1; e_sz <= 2; e_sz++) {

	    t = 0; /* create bifold map */
	    m = f_map_init(F_MAPTYPE_BITMAP, e_sz, (pages==1)?0:page_sz,
			   F_MAPLOCKING_DEFAULT);
	    if (!m || m->geometry.pu_factor != F_MAP_KEY_FACTOR_MIN) goto err0;
	    if (f_map_is_partitioned(m) || f_map_is_structured(m)) goto err0;
	    if (f_map_is_bbitmap(m) != (e_sz == 2)) goto err0;
	    if (m->type != F_MAPTYPE_BITMAP) goto err0;
	    if (e_sz != m->geometry.entry_sz) goto err1;
	    /* check BoS size */
	    if (m->bosl_entries != (unsigned int)(m->bosl_sz*8/e_sz)) goto err1;
	    /* set partition */
	    rc = f_map_init_prt(m, node_size, my_node, 0, global);
	    if (rc || !f_map_is_partitioned(m)) goto err1;

	    /* Iteration of a test group - we need to repeat tests with a random arg(s) */
	    for (pass = 0; pass < RND_REPS; pass++) {
		t = 1; /* Add single entry at random */
		/* random 64-bit key */
		e = gen_rand_key(ul, MEM_KEY_BITS);
		/* set entry @e */
		bosl = f_map_new_bosl(m, e);
		if (!bosl || bosl->map->nr_bosl != 1) goto err1;
		if (!f_map_entry_in_bosl(bosl, e) || e < bosl->entry0) goto err2;

		t = 2; /* Get entry pointer */
		ul = e - bosl->entry0;
		p = f_map_get_p(m, e);
		if (p == NULL) goto err2;
		if (p != (bosl->page + ((e_sz == 1)?BIT_WORD(ul):BBIT_WORD(ul)))) goto err2;

		t = 3; /* Check page is clean */
		if (e_sz == 1) {
		    // v = bitmap_weight(bosl->page, m->bosl_entries);
		    v = __bitmap_weight64(bosl->page, 0, m->bosl_entries);
		} else {
		    v = bbitmap_weight(bosl->page, BB_PAT11, m->bosl_entries);
		}
		if (v) goto err2;

		t = 4; /* set SM entry to 'allocated' */
		if (e_sz == 1) {
		    long_bbits = BITS_PER_LONG;
		    set_bit(ul, bosl->page);
		} else {
		    long_bbits = BBITS_PER_LONG;
		    set_bbit(ul, BBIT_11, bosl->page);
		}
		/* calculate entry # from pointer (p) and actual BBIT offset in *p */
		ul = bosl->entry0 + ((uint64_t)(p - bosl->page))*long_bbits;
		if (*p == 0UL) goto err2; /* Error: BBIT11 not set in *p */
		/* actual bbit position in the word */
		v = long_bbits - __builtin_clzl(*p)/e_sz - 1;
		ul += (unsigned int)v;
		if (ul != e) goto err2; /* Error: bit position is not correct */

		t = 5; /* count ones */
		if (e_sz == 1)
		    v = bitmap_weight(bosl->page, m->bosl_entries);
		else
		    v = bbitmap_weight(bosl->page, BB_PAT11, m->bosl_entries);
		if (v != 1) goto err2;

		t = 6; /* Iterate the map */
		it = bitmap_new_iter(m, (e_sz==1)?laminated:cv_laminated);
		if (!f_map_seek_iter(it, bosl->entry0)) goto err2; /* ENOMEM */
		/* @e? */
		if (f_map_check_iter(it)) {
			if (e != bosl->entry0) goto err3;
		} else {
			it = f_map_next(it); /* Forward it to 'e' */
			if (it == NULL) goto err2;
		}
		if (it->bosl != bosl) goto err3;
		if (it->entry != e) goto err3;

		t = 7; /* ne 'next' entry */
		if (f_map_next(it)) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 8; /* delete all BoS entries */
		rc = f_map_delete_bosl(m, bosl);
		if (rc) goto err2;
		if (m->nr_bosl) goto err2;

		t = 9; /* SHould not find any entry */
		if ((p = f_map_get_p(m, e))) goto err2;
		if ((p = f_map_get_p(m, 0))) goto err2;
	    }
	    t = 10; /* map exit: must survive */
	    f_map_exit(m); m = NULL; bosl = NULL; p = NULL;
	    //rcu_quiescent_state();
	}
    }

    /*
     * Test group two: in-memory structured map
     */
    tg = 2;
    printf("Running group %d tests: in-memory structured map\n", tg);

    /* For dofferent BoS page size */
    for (pages = 1; pages < BOS_PAGE_MAX; pages++) {
	page_sz = pages*page;
	/* Number of extents in slab entry */
	for (ext = 1; ext <= 3; ext++) {
	    iext = ext - 1; /* extent index in Slab map: at top extent entry */
	    pass = rc = v = 0;
	    e = 0;
	    p = NULL; it = NULL;

	    t = 0; /* Create bifold map */
	    e_sz = sizeof(F_SLAB_ENTRY_t) + ext*sizeof(F_EXTENT_ENTRY_t);
	    m = f_map_init(F_MAPTYPE_STRUCTURED, e_sz, (pages==1)?0:page_sz,
			   F_MAPLOCKING_DEFAULT);
	    if (!m || f_map_is_partitioned(m) || !f_map_is_structured(m)) goto err0;
	    if (m->nr_bosl != 0 || e_sz != m->geometry.entry_sz) goto err1;
	    /* Check BoS size */
	    ul = m->bosl_sz / ((1U << m->geometry.pu_factor)*e_sz) *
				(1U << m->geometry.pu_factor);
	    if (m->bosl_entries != (unsigned int)ul) goto err1;

	    /* Iteration of the group - we need to repeat tests with random entry */
	    for (pass = 0; pass < RND_REPS; pass++) {

		t = 1; /* Add single entry at random */
		e = gen_rand_key(ul, MEM_KEY_BITS);
		/* set entry @e */
		bosl = f_map_new_bosl(m, e);
		if (!bosl || bosl->map->nr_bosl != 1) goto err1;
		if (!f_map_entry_in_bosl(bosl, e) || e < bosl->entry0) goto err2;

		t = 2; /* Get entry pointer */
		ul = e - bosl->entry0;
		p = f_map_get_p(m, e);
		if (p == NULL) goto err2;
		if (p != (bosl->page + ul*e_sz/sizeof(long))) goto err2;
		pu = (F_PU_VAL_t *)p;

		t = 4; /* Check page is clean */
		ul = bosl->map->bosl_sz/sizeof(long);
		v = bitmap_weight(bosl->page, ul*BITS_PER_LONG);
		if (v) goto err2;

                t = 5; /* Set SM entry to 'mapped' and count 'mapped' entries */
                se = &pu->se;
                se->mapped = 1;
                ee = &pu->ee;
		ee += iext; /* index of top extent */
		ee->failed = 1;
		/* iterator... */
		it = f_map_new_iter(m, sm_extent_failed, iext);
		if (!f_map_seek_iter(it, bosl->entry0)) goto err2; /* ENOMEM */
		/* @e? */
		if (f_map_check_iter(it)) {
			if (e != bosl->entry0) goto err3;
		} else {
			it = f_map_next(it); /* Forward it to 'e' */
			if (it == NULL) goto err2;
		}
		if (it->bosl != bosl) goto err3;
		if (it->entry != e) goto err3;

		t = 6; /* Check no 'next' */
		if (f_map_next(it)) goto err3;

		t = 7; /* Test f_map_weight() */
		it = f_map_seek_iter(it, bosl->entry0);
		ul = f_map_weight(it, e + 1UL);
		if (ul != 1U) goto err3;
		/* ...iterator */
		f_map_free_iter(it); it = NULL;

		t = 8; /* Delete all BoS entries */
		rc = f_map_delete_bosl(m, bosl);
		if (rc) goto err2;
		if (m->nr_bosl) goto err2;

		t = 9; /* Should not find any entry */
		if ((p = f_map_get_p(m, e))) goto err2;
		if ((p = f_map_get_p(m, 0))) goto err2;

		t = 10; /* Create new iterator and seek at zero */
		it = f_map_get_iter(m, F_NO_CONDITION, 0);
		if (it) goto err2;

		t = 11; /* Iterate the empty map */
		it = f_map_new_iter_all(m);
		it = f_map_seek_iter(it, 0); /* BoS #0 */
		if (!it || !((bosl = it->bosl))) goto err2;
		if (bosl->entry0 != 0 || !f_map_get_p(m, 0)) goto err3;
		if (m->nr_bosl != 1) goto err3;
		if (!f_map_next(it)) goto err3;
		if (it->entry != 1) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 12; /* Delete all BoS entries */
		rc = f_map_delete_bosl(m, bosl);
		if (rc) goto err2;
		if (m->nr_bosl) goto err2;
	    }
	    t = 13; /* Must survive map exit */
	    f_map_exit(m); m = NULL; bosl = NULL; p = NULL;
	}
    }
    rcu_unregister_thread();

    /*
     * Test group three: Init KV store
     */
    tg = 3;
    printf("Running group %d tests: start/stop KV store (MDHIM)\n", tg);
    pass = v = 0;
    e = 0;
    p = NULL; it = NULL;

    t = 1; /* Read default metadata (db_opts, layouts) config */
    rc = meta_init_conf(&md_cfg, &db_opts, argc, argv);
    if (rc != 0) goto err;
    if (!md_cfg.layout0_name || !db_opts) goto err;

    t = 2; /* Load and parse layout0 configuration */
    rc = f_set_layout_info(&md_cfg);
    if (rc != 0) goto err;
    if ((lo_info = f_get_layout_info(layout_id)) == NULL) goto err;
    printf(" Layout%d %s (%uD+%uP) chunk:%u slab_stripes:%u devnum:%u\n",
	lo_info->conf_id, lo_info->name, lo_info->data_chunks,
	(lo_info->chunks - lo_info->data_chunks), lo_info->chunk_sz,
	lo_info->slab_stripes, lo_info->devnum);

    t = 3; /* Bring up DB thread */
    meta_init_store(db_opts);
    if (md == NULL || unifycr_indexes[0] == NULL) goto err;

    /* Prepare for next test group: sanitize DB */
    t = 4; /* create bifold map */
    pages = 1;
    page_sz = pages*page;
    e_sz = 1;

    rcu_register_thread();
    m = f_map_init(F_MAPTYPE_BITMAP, e_sz, (pages==1)?0:page_sz,
		   F_MAPLOCKING_DEFAULT);
    if (!m) goto err0;

    t = 5; /* Set map partition to part my_node of [0..node_size-1] */
    global = 0;
    rc = f_map_init_prt(m, node_size, my_node, 0, global);
    if (rc) goto err1;

    t = 6; /* Register map with Layout0 */
    rc = f_map_register(m, layout_id);
    if (rc) goto err1;

    t = 7; /* free map */
    f_map_exit(m); m = NULL;
    rcu_unregister_thread();

    t = 8; /* Remove old DB files for Layout0 */
    rc = meta_sanitize(); db_opts = NULL;
    if (rc) goto err1;
    f_free_layout_info();
    unifycr_config_free(&md_cfg);

    /*
     * Test group four: Bitmaps with KV store backend
     */
    tg = 4;
    printf("Running group %d tests: bitmaps with KV store backend\n", tg);

    t = 0;
    /* Read default metadata (db_opts, layouts) config */
    rc = meta_init_conf(&md_cfg, &db_opts, argc, argv);
    if (rc != 0) goto err;
    /* Load and parse layout0 configuration */
    rc = f_set_layout_info(&md_cfg);
    if (rc != 0) goto err;
    /* Bring up DB thread */
    meta_init_store(db_opts);
    if (md == NULL) goto err;

    /* For different BoS page size */
    rcu_register_thread();
    for (pages = 1; pages < BOS_PAGE_MAX; pages++) {
	page_sz = pages*page;

	/* One and two-bits bitmaps */
	for (e_sz = 1; e_sz <= 2; e_sz++) {
	    pass = rc = v = 0;
	    e = 0;
	    p = NULL; it = NULL;

	    t = 1; /* Create bifold map */
	    m = f_map_init(F_MAPTYPE_BITMAP, e_sz, (pages==1)?0:page_sz,
			   F_MAPLOCKING_DEFAULT);
	    if (!m) goto err0;

	    /* Test partitioned map with only partition, all partitions */
	    for (global = 0; global <= 1; global++) {
	    printf(" with BoS pages:%u, %s%sbitmap\n",
		pages, global?"global ":"", (e_sz==2)?"b":"");

		t = 2; /* Set map partition */
		e = 0;
		/* partition:my_node of [0..node_size-1] */
		rc = f_map_init_prt(m, node_size, my_node, 0, global);
		if (rc || !(m->own_part ^ (unsigned)global)) goto err1;

		/* Test iterations */
		for (pass = 0; pass < RND_REPS; pass++) {

		    t = 3; /* Register map with Layout0 */
		    e = 0;
		    rc = f_map_register(m, layout_id);
		    if (rc != 0) goto err1;

		    t = 4; /* Load empty map */
		    rc = f_map_load(m);
		    if (rc != 0) goto err1;

		    t = 5; /* Create BoS for entry #0 */
		    it = f_map_new_iter_all(m);
		    it = f_map_seek_iter(it, 0);
		    if (!it || !((bosl = it->bosl))) goto err2;
		    if (bosl->entry0 != 0) goto err3;
		    if (!(p = f_map_get_p(m, 0))) goto err3;

		    t = 6; /* Iterate the empty map */
		    if (!f_map_next(it)) goto err3;
		    if (it->entry != 1) goto err3;
		    f_map_free_iter(it); it = NULL;

		    t = 7; /* Count entries in loaded map */
		    /* Note: For bitmap (e_sz:1) the condition evaluated
		    as a boolean, cv_laminated is 'true' so that is the same
		    as F_BIT_CONDITION, i.e. iterate over set bits */
		    it = bitmap_new_iter(m, cv_laminated);
		    it = f_map_seek_iter(it, 0);
		    if (!it) goto err2;
		    v = (int)f_map_weight(it, F_MAP_WHOLE);
		    if (v != pass) goto err3;

		    t = 8; /* Add an unique random entry */
		    ii = max(pass, (int)m->bosl_entries);
		    for (i = 0; i < ii; i++) {
			/* random 31-bit key */
			e = gen_rand_key(ul, DB_KEY_BITS);
			if (f_map_has_globals(m)) {
			    /* Avoid creation entry in foreign partition */
			    if (!f_map_prt_my_global(m, e))
				continue;
			} else {
			    /* 'global' entry ID in partition map is limited
			    to DB_KEY_BITS so make 'local' entry ID shorter */
			    e >>= ilog2(m->parts);
			}
			/* entry already in the map? */
			if (!f_map_probe_iter_at(it, e, (void*)&v))
			    break;
			/* yes, it should be 1 or 3 */
			if (v != ((1 << e_sz) - 1)) goto err3;
		    }
		    rc = i;
		    if (i >= ii) goto err3; /* failed to generate the key */
		    /* set entry @e */
		    bosl = f_map_new_bosl(m, e); /* create BoS on demand */
		    ul = e - bosl->entry0;
		    /* set entry */
		    if (e_sz == 1)
			set_bit(ul, bosl->page);
		    else
			set_bbit(ul, BBIT_11, bosl->page);
		    ui = ul/(1U << m->geometry.pu_factor);
 /*
 printf(" Add e:%lu @%lu in BoS %lu e0:%lu PU:%u p:%p\n",
 e, ul, bosl->entry0/m->bosl_entries, bosl->entry0, ui, bosl->page);
 printf(" - %d Ok\n", t);
 */

		    t = 9; /* Check the entry is set in memory */
		    if (!f_map_probe_iter_at(it, e, NULL)) goto err3;

		    t = 10; /* Mark PU durty */
		    f_map_mark_dirty_bosl(bosl, e);
		    v = bitmap_weight(bosl->dirty,
				      m->geometry.bosl_pu_count);
		    if (v != 1) goto err2;
		    ul = find_first_bit(bosl->dirty, m->geometry.bosl_pu_count);
		    if (ul != ui) goto err2;

		    t = 11; /* flush map */
		    v = 0;
		    rc = f_map_flush(m);
		    if (rc != 0) goto err2;
		    /* check dirty bit cleared */
		    v = bitmap_weight(bosl->dirty,
				      m->geometry.bosl_pu_count);
		    if (v) goto err2;

		    t = 12; /* Count man entries */
		    v = 0;
		    f_map_next(it);
		    for_each_iter(it)
			v++;
		    if (v != (pass + 1)) goto err3;
		    f_map_free_iter(it); it = NULL;
// printf(" - %d Ok\n", t);
		}

		t = 13; /* Clear all PUs in DB */
		pu_sz = f_map_pu_size(m);
		it = f_map_get_iter(m, cv_laminated, 0);
		for_each_iter(it) {
		    /* clear PU of 'it->entry' in map */
		    bosl = it->bosl;
		    ui = it_to_pu(it);
		    p = bosl->page + f_map_pu_p_sz(m, ui, p);
		    memset(p, 0, pu_sz);
		    /* mark PU dirty */
		    f_map_mark_dirty(m, it->entry);
		}
		f_map_free_iter(it); it = NULL;
		/* delete empty PU in DB */
		rc = f_map_flush(m);
		if (rc != 0) goto err2;

		t = 14; /* delete all BoS entries */
		it = f_map_get_iter(m, F_NO_CONDITION, 0);
		ui = m->nr_bosl;
		if (ui > RND_REPS+1) goto err2; /* +1 for BoS #0 */
		v = 0;
		for_each_iter(it) {
		    if ((rc = f_map_delete_bosl(m, it->bosl))) goto err1;
		    it->bosl = NULL;
		    v++;
		}
		if (m->nr_bosl) goto err1;
		f_map_free_iter(it); it = NULL;
		rcu_quiescent_state();
	    }
	    t = 15; /* map exit: must survive */
	    f_map_exit(m); m = NULL; bosl = NULL; p = NULL;
	}
    }
    rcu_unregister_thread();

    t = 16;
    rc = meta_sanitize();
    if (rc) goto err1;
    f_free_layout_info();
    unifycr_config_free(&md_cfg);

    /*
     * Test group five: Structured map with KV store backend
     */
    tg = 5;
    printf("Running group %d tests: structured map with KV store backend\n", tg);

    t = 0;
    /* Read default metadata (db_opts, layouts) config */
    rc = meta_init_conf(&md_cfg, &db_opts, argc, argv);
    if (rc != 0) goto err;
    /* Load and parse layout0 configuration */
    rc = f_set_layout_info(&md_cfg);
    if (rc != 0) goto err;
    /* Bring up DB thread */
    meta_init_store(db_opts);
    if (md == NULL) goto err;

    /* For different BoS page size */
    rcu_register_thread();
    for (pages = 1; pages < BOS_PAGE_MAX; pages++) {
	page_sz = pages*page;

	/* Number of extents in slab entry */
	for (ext = 1; ext <= 3; ext++) {
	    iext = ext - 1; /* extent index in Slab map: at top extent entry */
	    pass = rc = v = 0;
	    e = 0;
	    p = NULL; it = NULL;

	    t = 1; /* Create structured map */
	    e_sz = sizeof(F_SLAB_ENTRY_t) + ext*sizeof(F_EXTENT_ENTRY_t);
	    m = f_map_init(F_MAPTYPE_STRUCTURED, e_sz, (pages==1)?0:page_sz,
			   F_MAPLOCKING_DEFAULT);
	    if (!m) goto err0;

	    /* Test partitioned map with only partition, all partitions */
	    for (global = 0; global <= 1; global++) {
		printf(" with BoS pages:%u, %sstructured map, %d extent%s\n",
		       pages, global?"global ":"", ext, (ext==1)?"":"s");

		t = 2; /* Set map partition */
		e = 0;
		/* partition:my_node of [0..node_size-1] */
		rc = f_map_init_prt(m, node_size, my_node, 0, global);
		if (rc || !(m->own_part ^ (unsigned)global)) goto err1;

		/* Test iterations */
		for (pass = 0; pass < RND_REPS; pass++) {

		    t = 3; /* Register map with Layout0 */
		    e = 0;
		    rc = f_map_register(m, layout_id);
		    if (rc != 0) goto err1;

		    t = 4; /* Load empty map */
		    rc = f_map_load(m);
		    if (rc != 0) goto err1;

		    t = 5; /* Create BoS for entry #0 */
		    it = f_map_new_iter_all(m);
		    it = f_map_seek_iter(it, 0);
		    if (!it || !((bosl = it->bosl))) goto err2;
		    if (bosl->entry0 != 0) goto err3;
		    if (!(p = f_map_get_p(m, 0))) goto err3;

		    t = 6; /* Iterate the empty map */
		    if (!f_map_next(it)) goto err3;
		    if (it->entry != 1) goto err3;
		    f_map_free_iter(it); it = NULL;

		    t = 7; /* Count entries in loaded map */
		    it = f_map_new_iter(m, sm_extent_failed, iext);
		    it = f_map_seek_iter(it, 0);
		    if (!it) goto err2;
		    v = (int)f_map_weight(it, F_MAP_WHOLE);
		    if (v != pass) goto err3;

		    t = 8; /* Add an unique random entry */
		    ii = max(pass, (int)m->bosl_entries);
		    for (i = 0; i < ii; i++) {
			/* random 31-bit key */
			e = gen_rand_key(ul, DB_KEY_BITS);
			if (f_map_has_globals(m)) {
			    /* Avoid creation entry in foreign partition */
			    if (!f_map_prt_my_global(m, e))
				continue;
			} else {
			    /* 'global' entry ID in partition map is limited
			    to DB_KEY_BITS so make 'local' entry ID shorter */
			    e >>= ilog2(m->parts);
			}
			/* entry already in the map? */
			if (!f_map_probe_iter_at(it, e, (void*)&se))
			    break;
			/* yes, read slab entry */
			if (!se || !(se->mapped)) goto err3;
		    }
		    rc = i;
		    if (i >= ii) goto err3; /* failed to generate the key */

		    t = 9; /* Set slab map entry @e */
		    bosl = f_map_new_bosl(m, e); /* create BoS on demand */
		    ul = e - bosl->entry0;
		    ui = ul/(1U << m->geometry.pu_factor);
		    if (!(p = f_map_get_p(m, e))) goto err2;
		    // printf(" Add e:%lu (%lu in BoS) p:%p\n", e, ul, p);
		    pu = (F_PU_VAL_t *)p;
		    /* set SM entry to 'mapped' and count 'mapped' entries */
		    se = &pu->se;
		    se->mapped = 1;
		    ee = &pu->ee;
		    ee += iext; /* index of top extent */
		    ee->failed = 1;

		    t = 10; /* Check the entry is set in memory */
		    if (!f_map_probe_iter_at(it, e, NULL)) goto err3;

		    t = 11; /* Mark PU durty */
		    f_map_mark_dirty_bosl(bosl, e);
		    v = bitmap_weight(bosl->dirty,
				      m->geometry.bosl_pu_count);
		    if (v != 1) goto err2;
		    ul = find_first_bit(bosl->dirty, m->geometry.bosl_pu_count);
		    if (ul != ui) goto err2;

		    t = 12; /* flush map */
		    rc = f_map_flush(m);
		    if (rc != 0) goto err2;
		    /* check dirty bit cleared */
		    v = bitmap_weight(bosl->dirty,
				      m->geometry.bosl_pu_count);
		    if (v) goto err2;

		    t = 13; /* Count man entries */
		    v = 0;
		    f_map_next(it);
		    for_each_iter(it)
			v++;
		    if (v != (pass + 1)) goto err3;
		    f_map_free_iter(it); it = NULL;
		}

		t = 14; /* Clear all PUs in DB */
		pu_sz = f_map_pu_size(m);
		it = f_map_get_iter(m, sm_extent_failed, iext);
		for_each_iter(it) {
		    /* clear PU of 'it->entry' in map */
		    bosl = it->bosl;
		    ui = it_to_pu(it);
		    p = bosl->page + f_map_pu_p_sz(m, ui, p);
		    memset(p, 0, pu_sz);
		    /* mark PU dirty */
		    f_map_mark_dirty(m, it->entry);
		}
		f_map_free_iter(it); it = NULL;
		/* delete empty PU in DB */
		rc = f_map_flush(m);
		if (rc != 0) goto err2;

		t = 15; /* delete all BoS entries */
		it = f_map_get_iter(m, F_NO_CONDITION, 0);
		ui = m->nr_bosl;
		if (ui > RND_REPS+1) goto err2; /* +1 for BoS #0 */
		v = 0;
		for_each_iter(it) {
		    if ((rc = f_map_delete_bosl(m, it->bosl))) goto err1;
		    it->bosl = NULL;
		    v++;
		}
		if (m->nr_bosl) goto err1;
		f_map_free_iter(it); it = NULL;
		rcu_quiescent_state();
	    }
	    t = 16; /* map exit: must survive */
	    f_map_exit(m); m = NULL; bosl = NULL; p = NULL;
	}
    }
    rcu_unregister_thread();

    t = 16;
    rc = meta_sanitize();
    if (rc) goto err1;
    f_free_layout_info();
    unifycr_config_free(&md_cfg);

    printf("SUCCESS\n");
    return 0;

err3:
    printf("  Iterator @%s%lu BoS#%lu PU:%lu p:%p\n",
	f_map_iter_depleted(it)?" END ":"", it->entry,
	it->bosl->entry0/it->map->bosl_entries,
	(it->entry - it->bosl->entry0)/(1U << it->map->geometry.pu_factor),
	(f_map_is_structured(it->map)?NULL:it->word_p));
err2:
    printf("  BoS #%lu starts @%lu page:%p p:%p e:%lu @%lu PU:%lu\n",
	e/m->bosl_entries, bosl->entry0,
	bosl->page, p,
	e, (e - bosl->entry0),
	(e - bosl->entry0)/(1U << m->geometry.pu_factor));
err1:
    printf("  Map entry:%lu in BoS sz:%lu (%u entries) "
		"BoS count:%lu, %u PU per BoS\n",
	e, m->bosl_sz, m->bosl_entries, m->nr_bosl,
	m->geometry.bosl_pu_count);
    printf("  Test variables: rc=%d var=%d ul=%lu ui=%u\n",
	rc, v, ul, ui);
    printf("  Part %u of %u in %spartitioned %s map; interleave:%u entries, %u PUs\n",
	m->part, m->parts, (m->parts<=1)?"non-":"",
	f_map_has_globals(m)?"global":"local",
	1U<<m->geometry.intl_factor,
	1U<<(m->geometry.intl_factor-m->geometry.pu_factor));
err0:
    printf("  entry_size:%u, %u pages per BoS\n", e_sz, pages);
    if (tg == 2 || tg == 5)
	printf("  slab map has %d extent(s)\n", ext);
err:
    printf("Test %d.%d (pass %d) FAILED\n", tg, t, pass);
    return 1;
}

