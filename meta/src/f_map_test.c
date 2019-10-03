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
#define RND_REPS	1000	/* number of passes for random test */
#define BOS_PAGE_MAX	4	/* max BoS page size, in kernel pages */
#define layout_id	0	/* use Layout 0 default configuration */


/* Set highest and lowest order(RAND_MAX) bits randomly in 64-bit word */
#define gen_rand_key(ul, v)			\
	({ ul = RAND_MAX+1U;			\
	v = 64 - __builtin_clzl(ul) + 1;	\
	ul = (uint64_t)rand();			\
	ul = ul << v;				\
	ul += rand();				\
	ul; })

/* MDHIM and Layout config */
F_LAYOUT_INFO_t *lo_info = NULL;
unifycr_cfg_t md_cfg;
struct mdhim_t *md;
struct index_t *unifycr_indexes[2*F_LAYOUTS_MAX+1]; /* +1 for primary_index */

static int create_persistent_map(int map_id, int intl, char *name);
static ssize_t ps_bget(unsigned long *buf, int map_id, size_t size, uint64_t *keys);
static int ps_bput(unsigned long *buf, int map_id, size_t size, uint64_t *keys);

static F_META_IFACE_t iface = {
	.create_map_fn = &create_persistent_map,
	.bget_fn = &ps_bget,
	.bput_fn = &ps_bput,
};

static int meta_init_conf(unifycr_cfg_t *server_cfg_p, mdhim_options_t **db_opts_p) {
	f_set_meta_iface(&iface);
	return mdhim_options_cfg(server_cfg_p, db_opts_p);
}

static void meta_init_store(mdhim_options_t *db_opts) {
	int i;

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
    }
    return 0;
}

static ssize_t ps_bget(unsigned long *buf, int map_id, size_t size, uint64_t *keys)
{
        struct index_t *primary_index = unifycr_indexes[map_id + 1];

        return mdhim_ps_bget(md, primary_index, buf, size, keys);
}

static int ps_bput(unsigned long *buf, int map_id, size_t size, uint64_t *keys)
{
	return 0;
}


/* Virtual map function example */
/* Default F_MAP_GET_fn function: it reduces the entry value to a bit */
int f_sm_is_extent_failed(void *arg, const F_PU_VAL_t *entry)
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

/* Default SM entry condition: extent is failed.
 * Set .vf_arg1 to extent number!
 */
static F_COND_t f_sm_extent_failed = {
    .vf_get = &f_sm_is_extent_failed,
};

/* Default CV entry condition: BBPAT_11 "laminated" */
static F_COND_t f_cv_laminated = {
    .pset = CV_LAMINATED_P,
};


/* unittest: f_map */
int main (int argc, char *argv[]) {
    F_MAP_t *m;
    F_BOSL_t *bosl;
    F_ITER_t *it;
    F_PU_VAL_t *pu;
    F_SLAB_ENTRY_t *se;
    F_EXTENT_ENTRY_t *ee;
    mdhim_options_t *db_opts = NULL;
    uint64_t e, ul;
    unsigned long *p;
    int pass, tg, t;
    int all_parts, v, rc;
    unsigned int e_sz, long_bbits, pages, ext;
    size_t page, page_sz;

    srand((unsigned int)time(NULL));
    page = getpagesize();

    rcu_register_thread();

    all_parts = 0;

    /* Test group one: in-memory bitmaps */
    tg = 1;
    printf("Running group %d tests: in-memory bitmaps\n", tg);

    /* For dofferent BoS page size */
    for (pages = 1; pages < BOS_PAGE_MAX; pages++) {
	page_sz = pages*page;
	/* One and two-bits bitmaps */
	for (e_sz = 1; e_sz <= 2; e_sz++) {
	    pass = rc = v = 0;
	    e = 0;
	    p = NULL; it = NULL;

	    t = 0; /* create bifold map */
	    m = f_map_init(F_MAPTYPE_BITMAP, e_sz, (pages==1)?0:page_sz,
			   F_MAPLOCKING_DEFAULT);
	    if (!m || m->geometry.pu_factor != F_MAP_KEY_FACTOR_MIN) goto err0;
	    if (f_map_is_partitioned(m) || f_map_is_structured(m)) goto err0;
	    if (m->type != F_MAPTYPE_BITMAP) goto err0;
	    if (e_sz != m->geometry.entry_sz) goto err1;
	    /* check BoS size */
	    if (m->bosl_entries != (unsigned int)(m->bosl_sz*8/e_sz)) goto err1;
	    /* set partition */
	    rc = f_map_init_prt(m, 2, 1, 0, 0);
	    if (rc || !f_map_is_partitioned(m)) goto err1;

	    /* Iteration of a test group - we need to repeat tests with a random arg(s) */
	    for (pass = 0; pass < RND_REPS; pass++) {
		t = 1; /* Add single entry at random */
		/* random 64-bit key */
		e = gen_rand_key(ul, v);
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
		if (e_sz == 1)
		    v = bitmap_weight(bosl->page, m->bosl_entries);
		else
		    v = bbitmap_weight(bosl->page, BB_PAT11, m->bosl_entries);
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
		/* TODO: Add support for bitmap conditions */
		if (e_sz == 2) {
		it = f_map_new_iter(m, f_cv_laminated);
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
		}

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
	    rcu_quiescent_state();
	}
    }

    /* Test group two: in-memory structured map */
    tg = 2;
    printf("Running group %d tests: in-memory structured map\n", tg);

    /* For dofferent BoS page size */
    for (pages = 1; pages < BOS_PAGE_MAX; pages++) {
	page_sz = pages*page;
	/* One and two-bits bitmaps */
	for (ext = 1; ext <= 3; ext++) {
	    pass = rc = v = 0;
	    e = 0;
	    p = NULL; it = NULL;

	    t = 0; /* create bifold map */
	    e_sz = sizeof(F_SLAB_ENTRY_t) + ext*sizeof(F_EXTENT_ENTRY_t);
	    m = f_map_init(F_MAPTYPE_STRUCTURED, e_sz, (pages==1)?0:page_sz,
			   F_MAPLOCKING_DEFAULT);
	    if (!m || f_map_is_partitioned(m) || !f_map_is_structured(m)) goto err0;
	    if (m->nr_bosl != 0 || e_sz != m->geometry.entry_sz) goto err1;
	    /* check BoS size */
	    ul = m->bosl_sz / ((1U << m->geometry.pu_factor)*e_sz) *
				(1U << m->geometry.pu_factor);
	    if (m->bosl_entries != (unsigned int)ul) goto err1;

	    /* Iteration of a test group - we need to repeat tests with a random arg(s) */
	    for (pass = 0; pass < RND_REPS; pass++) {
		t = 1; /* Add single entry at random */
		e = gen_rand_key(ul, v);
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
		//f_map_weight()
		ul = bosl->map->bosl_sz/sizeof(long);
		v = bitmap_weight(bosl->page, ul*BITS_PER_LONG);
		if (v) goto err2;

                t = 5; /* set SM entry to 'mapped' and count 'mapped' entries */
                se = &pu->se;
                se->mapped = 1;
                ee = &pu->ee;
		ee += ext;
		ee->failed = 1;
		/* iterator... */
		it = f_map_new_iter(m, f_sm_extent_failed);
		*(unsigned int*)it->vf_arg = ext;
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

		t = 6; /* no 'next' */
		if (f_map_next(it)) goto err3;

		t = 7; /* test f_map_weight() */
		it = f_map_seek_iter(it, bosl->entry0);
		ul = f_map_weight(it, e + 1UL);
		if (ul != 1U) goto err3;
		/* ...iterator */
		f_map_free_iter(it); it = NULL;

		t = 8; /* delete all BoS entries */
		rc = f_map_delete_bosl(m, bosl);
		if (rc) goto err2;
		if (m->nr_bosl) goto err2;

		t = 9; /* SHould not find any entry */
		if ((p = f_map_get_p(m, e))) goto err2;
		if ((p = f_map_get_p(m, 0))) goto err2;

		t = 10; /* f_map_seek_iter(it, 0) */
		it = f_map_get_iter(m, F_NO_CONDITION);
		if (!it || !((bosl = it->bosl))) goto err2;
		if (bosl->entry0 != 0 || !f_map_get_p(m, 0)) goto err3;
		if (m->nr_bosl != 1) goto err3;

		t = 11; /* Iterate the empty map */
		if (!f_map_next(it)) goto err3;
		if (it->entry != 1) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 12; /* delete all BoS entries */
		rc = f_map_delete_bosl(m, bosl);
		if (rc) goto err2;
		if (m->nr_bosl) goto err2;
	    }
	    t = 13; /* map exit: must survive */
	    f_map_exit(m); m = NULL; bosl = NULL; p = NULL;
	    rcu_quiescent_state();
	}
    }
    rcu_unregister_thread();

    /* Test group four: Init KV store */
    tg = 3;
    printf("Running group %d tests: init KV store\n", tg);
    pass = 0;

    t = 0; /* read default config */
    rc = unifycr_config_init(&md_cfg, argc, argv);
    if (rc != 0) goto err;
    if (md_cfg.meta_db_path) {
	free(md_cfg.meta_db_path);
	md_cfg.meta_db_path = strdup("/dev/shm");
    }

    t = 1; /* apply metadata (db_opts, layouts) config */ 
    rc = meta_init_conf(&md_cfg, &db_opts);
    if (rc != 0) goto err;
    if (!md_cfg.layout0_name || !db_opts) goto err;

    t = 2; /* load lnd parse layout0 configuration */
    rc = f_set_layout_info(&md_cfg);
    if (rc != 0) goto err;
    if ((lo_info = f_get_layout_info(layout_id)) == NULL) goto err;
    printf(" Layout%d %s (%uD+%uP) chunk:%u slab_stripes:%u devnum:%u\n",
	lo_info->conf_id, lo_info->name, lo_info->data_chunks,
	(lo_info->chunks - lo_info->data_chunks), lo_info->chunk_sz,
	lo_info->slab_stripes, lo_info->devnum);

    t = 3; /* bring up DB thread */
    meta_init_store(db_opts);
    if (md == NULL || unifycr_indexes[0] == NULL) goto err;

    /* Test group three: Bitmaps with KV store backend */
    tg = 4;
    printf("Running group %d tests: bitmaps with KV store backend\n", tg);

    /* For dofferent BoS page size */
    rcu_register_thread();
    for (pages = 1; pages < BOS_PAGE_MAX; pages++) {
	page_sz = pages*page;
	/* One and two-bits bitmaps */
	for (e_sz = 1; e_sz <= 2; e_sz++) {
	    pass = rc = v = 0;
	    e = 0;
	    p = NULL; it = NULL;

	    t = 0; /* create bifold map */
	    m = f_map_init(F_MAPTYPE_BITMAP, e_sz, (pages==1)?0:page_sz,
			   F_MAPLOCKING_DEFAULT);
	    if (!m) goto err0;

	    /* Test partitioned map with only partition, all partitions */
	    for (all_parts = 0; all_parts <= 1; all_parts++) {

		t = 1; /* set partition */
		rc = f_map_init_prt(m, 2, 1, 0, all_parts);
		if (rc || !(m->own_part ^ (unsigned int)all_parts)) goto err1;

		/* Test iterations */
		for (pass = 0; pass < RND_REPS; pass++) {
		    F_BOSL_t *bosl0 = NULL;

		    t = 2; /* Register map with Layout0 */
		    rc = f_map_register(m, layout_id);
		    if (rc != 0) goto err1;

		    t = 3; /* Load empty map */
		    rc = f_map_load(m);
		    if (rc != 0) goto err1;

		    t = 4; /* f_map_seek_iter(it, 0) */
		    it = f_map_get_iter(m, F_NO_CONDITION);
		    if (!it || !((bosl = it->bosl))) goto err2;
		    if (bosl->entry0 != 0 || !f_map_get_p(m, 0)) goto err3;
		    if (m->nr_bosl != 1) goto err3;

		    t = 5; /* Iterate the empty map */
		    if (!f_map_next(it)) goto err3;
		    if (it->entry != 1) goto err3;
		    f_map_free_iter(it); it = NULL;

		    t = 6; /* Add single entry at random */
		    /* random 64-bit key */
		    e = gen_rand_key(ul, v);
		    /* save old BoS pointer if 'e' in another BoS */
		    if (!f_map_entry_in_bosl(bosl, e))
			bosl0 = bosl;
		    /* set entry @e */
		    bosl = f_map_new_bosl(m, e); /* if no BoS, create it */
		    ul = e - bosl->entry0;
		    /* set entry */
		    if (e_sz == 1) {
			long_bbits = BITS_PER_LONG;
			set_bit(ul, bosl->page);
		    } else {
			long_bbits = BBITS_PER_LONG;
			set_bbit(ul, BBIT_11, bosl->page);
		    }

		    t = 7; /* mark PU durty */
		    f_map_mark_dirty_bosl(bosl, e);
		    v = bitmap_weight(bosl->dirty,
				      m->geometry.bosl_pu_count);
		    if (v != 1) goto err2;

		    t = 8; /* flush map */
		    rc = f_map_flush(m);
		    if (rc != 0) goto err2;

		    t = 9; /* delete all BoS entries */
		    if ((rc = f_map_delete_bosl(m, bosl))) goto err2;
		    if (bosl0)
			if ((rc = f_map_delete_bosl(m, bosl0))) goto err2;
		    if (m->nr_bosl) goto err2;
 //printf(" - %d Ok\n", t);
		}
	    }
	    t = 13; /* map exit: must survive */
	    f_map_exit(m); m = NULL; bosl = NULL; p = NULL;
	    rcu_quiescent_state();
	}
    }
    rcu_unregister_thread();

    /* Test group six: shutdown KV store thread */
    tg = 6;
    printf("Running group %d tests: KV store shutdown\n", tg);
    t = 0;
    rc = meta_sanitize();
    if (rc) goto err1;
    f_free_layout_info();

    printf("SUCCESS\n");
    return 0;

err3:
    printf("   Iterator @%lu BoS#%lu p:%p\n",
	it->entry,
	it->bosl->entry0/it->map->bosl_entries,
	(f_cond_has_vf(it->cond)?NULL:it->word_p));
err2:
    printf("  page:%p p:%p BoS #%lu e0:%lu\n",
	bosl->page, p, e/m->bosl_entries, bosl->entry0);
err1:
    printf("  Map entry:%lu in BoS sz:%lu (%u entries) BoS count:%lu rc=%d var=%d\n"
	   "  Part %u of %u - %s\n",
	e, m->bosl_sz, m->bosl_entries, m->nr_bosl, rc, v,
	m->part, m->parts,
	m->own_part?"single":"global");
err0:
    printf("  entry_size:%u, %u pages per BoS\n", e_sz, pages);
err:
    printf("Test %d.%d (pass %d) FAILED\n", tg, t, pass);
    return 1;
}

