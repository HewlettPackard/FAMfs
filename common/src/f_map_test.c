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


/* TEST options */
#define RND_REPS	1000	/* number of passes for random test */
#define BOS_PAGE_MAX	4	/* max BoS page size, in kernel pages */
#define layout_id	0	/* use Layout 0 default configuration */
#define MEM_KEY_BITS	64	/* in-memory maps: max global entry bits */
#define DB_KEY_BITS	31	/* DB-backed maps: max global entry bits */

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

static int my_node = 1;
static int node_size = 2;


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
int main (int argc __attribute__ ((unused)),
	  char *argv[] __attribute__ ((unused)))
{
    F_MAP_t *m;
    F_BOSL_t *bosl;
    F_ITER_t *it;
    F_PU_VAL_t *pu;
    F_SLAB_ENTRY_t *se;
    F_EXTENT_ENTRY_t *ee;
    size_t page, page_sz;
    uint64_t e, ul;
    unsigned long *p;
    unsigned int ui, e_sz, long_bbits, pages;
    unsigned int iext, ext;
    int pass, tg, t;
    int global, v, rc;

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
		    v = bitmap_weight(bosl->page, m->bosl_entries);
		    // v = __bitmap_weight64(bosl->page, 0, m->bosl_entries);
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
    printf("Test %d.%d (pass %d) FAILED\n", tg, t, pass);
    return 1;
}

