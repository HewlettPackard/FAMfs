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
 */

/*
 * Written by: Dmitry Ivanov
 *
 * Test shared map in SHMEM
 */

#include <mpi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "f_bitmap.h"
#include "f_map.h"
#include "f_layout.h"

/* TEST options */
//#define DEBUG_TST			/* be very verbosive */
#define RND_REPS	1000	/* number of passes for random test */
#define BOS_PAGE_MAX	4	/* max BoS page size, in kernel pages */
//#define MEM_KEY_BITS	64	/* in-memory maps: max global entry bits */
#define MEM_KEY_BITS	31	/* in-memory maps: FAMFS limit to global entry bits */
#define NR_READERS	3	/* number of readers */
#define NR_SPAWNS (NR_READERS+1)


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

#define msg0(str, ...) if (rank==0) printf( str "\n", ## __VA_ARGS__)
#define msg(str, ...) printf("%d: " str "\n", rank, ## __VA_ARGS__)
#ifdef DEBUG_TST
#define dbg(fmt, args...)			\
	fprintf(stderr, "%d: " fmt "\n",	\
		rank, ## args)
#else
#define dbg(fmt, args...)			\
do { /* do nothing but check printf format */	\
    if (0)					\
	fprintf(stderr, "%d: " fmt "\n",	\
		rank, ## args);			\
} while (0)
#endif

static int rank = 0;
static int mpi_size = 0;

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

static uint64_t unique_rand_key(uint64_t *entries, int sz, int mem_key_bits)
{
    uint64_t e, ul;
    int i;

    do {
	e = gen_rand_key(ul, mem_key_bits);
	for (i=0; i<sz; i++) {
	    if (e == entries[i])
		break;
	}
	if (i==sz)
	    return e;
    } while (1);
}

static int in_entries(uint64_t entry, uint64_t *entries, int sz)
{
    int i;

    for (i=0; i<sz; i++) {
	if (entry == entries[i])
	    return 1;
    }
    return 0;
}


int main(int argc, char *argv[])
{
  F_MAP_t *m;
  F_BOSL_t *bosl;
  F_ITER_t *it;
  F_PU_VAL_t *pu;
  F_SLAB_ENTRY_t *se;
  F_EXTENT_ENTRY_t *ee;
  size_t page, page_sz;
  uint64_t e, ul;
  uint64_t *entries = NULL;
  unsigned long *p;
  unsigned int ui, e_sz, long_bbits, pages;
  unsigned int iext, ext;
  int pass, tg, t, v, vv;
  int flag, provided;

  int np = NR_SPAWNS;
  int errcodes[NR_SPAWNS];
  int i, rc;
  MPI_Comm parentcomm, intercomm;

  if ((rc = MPI_Initialized(&flag)) != MPI_SUCCESS) {
	err("Error while calling MPI_Initialized");
	exit(1);
  }
  if (!flag) {
	rc = MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &provided);
	if (rc != MPI_SUCCESS) {
	    err("Error while calling MPI_Init_thread");
	    goto _err;
	}
	if (provided != MPI_THREAD_MULTIPLE) {
	    err("Error while initializing MPI with threads");
	    goto _err;
	}
  }

  MPI_Comm_get_parent(&parentcomm);
  if (parentcomm == MPI_COMM_NULL) {
    /* Create MPI processes: NR_READERS plus one writer */
#ifdef DEBUG_TST
    /* Don't forget to create gdb file like this:
    file ./f_shmap_test
    run
    bt
    */
    char *av[] = {"-x", "gdb", NULL};
    rc = MPI_Comm_spawn("/usr/bin/gdb", av, np,
#else
    rc = MPI_Comm_spawn("./f_shmap_test", MPI_ARGV_NULL, np,
#endif
			MPI_INFO_NULL, 0,
			MPI_COMM_WORLD, &intercomm, errcodes /* MPI_ERRCODES_IGNORE */);
    if (rc != MPI_SUCCESS) {
	err("failed to spawn f_shmap_test processes");
	exit(1);
    }
    for (i=0, rc=0; i<np; i++)
	rc = (rc)? :errcodes[i];
    if (rc)
	err("process error %d", rc);

  } else {
    /*
     * Unittest: map in SHMEM
    */

    /* Initialize MPI */
    tg = 0;
    if ((rc = MPI_Comm_size(MPI_COMM_WORLD, &mpi_size)) != MPI_SUCCESS) {
	err("Error getting the size of the communicator:%d", rc);
	goto _err;
    }
    if ((rc = MPI_Comm_rank(MPI_COMM_WORLD, &rank)) != MPI_SUCCESS) {
	err("Error getting the rank:%d", rc);
	goto _err;
    }

    srand((unsigned int)time(NULL));
    page = getpagesize();
    pass = rc = v = vv = 0;
    e = ul = 0;
    ui = ext = 0;
    p = NULL; it = NULL;
    entries = (uint64_t*) malloc(sizeof(uint64_t)*RND_REPS);

    /*
     * Test group one: in-memory bitmaps
     */
    MPI_Barrier(MPI_COMM_WORLD);
    tg = 1;
    msg0("Running group %d tests: bitmaps and bifold bitmaps in SHMEM", tg);

    rcu_register_thread();
    /* For dofferent BoS page size */
    for (pages = 1; pages < BOS_PAGE_MAX; pages++) {
	page_sz = pages*page;
	/* One and two-bits bitmaps */
	for (e_sz = 1; e_sz <= 2; e_sz++) {

	    t = 0; /* create bifold map */
	    m = f_map_init(F_MAPTYPE_BITMAP, e_sz, (pages==1)?0:page_sz,
			   F_MAPLOCKING_DEFAULT);
	    if (!m) goto err0;
	    dbg("Pages:%u e_sz:%u - map_shm_attach", pages, e_sz);
	    rc = f_map_shm_attach(m, rank?F_MAPMEM_SHARED_RD:F_MAPMEM_SHARED_WR);
	    if (rc) goto err0;
	    /* check BoS size */
	    if (m->bosl_entries != (unsigned int)(m->bosl_sz*8/e_sz)) goto err1;

	    /* Populate shared map: WR */
	    if (rank == 0) {

		/* Iteration of a test group - we need to repeat tests with a random arg(s) */
		for (pass = 0; pass < RND_REPS; pass++) {
		    t = 1; /* Add single entry at random */
		    /* random 64-bit key */
		    e = unique_rand_key(entries, pass, MEM_KEY_BITS);
		    entries[pass] = e;
		    dbg(" e_sz:%d pass:%d Add e:%lu", e_sz, pass, e);

		    /* set entry @e */
		    bosl = f_map_new_bosl(m, e);
		    if (!bosl) goto err1;
		    if (!f_map_entry_in_bosl(bosl, e)) goto err2;

		    t = 2; /* Get entry pointer */
		    ul = e - bosl->entry0;
		    p = f_map_get_p(m, e);
		    if (p == NULL) goto err2;
		    if (p != (bosl->page+((e_sz == 1)?BIT_WORD(ul):BBIT_WORD(ul)))) goto err2;

		    /* count existing bosl entries */
		    vv = 0;
		    for (i=0; i<pass; i++)
			if (f_map_entry_in_bosl(bosl, entries[i]))
			    vv++;

		    t = 3; /* Store BoS page bit count */
		    if (e_sz == 1) {
			v = bitmap_weight(bosl->page, m->bosl_entries);
			// v = __bitmap_weight64(bosl->page, 0, m->bosl_entries);
		    } else {
			v = bbitmap_weight(bosl->page, BB_PAT11, m->bosl_entries);
		    }
		    if (v != vv) goto err2;

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
		    if (ul != e && !in_entries(ul, entries, pass))
			goto err2; /* Error: bit position is not correct */

		    t = 5; /* count ones */
		    if (e_sz == 1)
			v = bitmap_weight(bosl->page, m->bosl_entries);
		    else
			v = bbitmap_weight(bosl->page, BB_PAT11, m->bosl_entries);
		    if (v != (vv+1)) goto err2;

		    t = 6; /* Iterate the map */
		    it = bitmap_new_iter(m, (e_sz==1)?laminated:cv_laminated);
		    ul = m->nr_bosl;
		    if (!f_map_seek_iter(it, bosl->entry0)) goto err2; /* ENOMEM */
		    if (it->bosl != bosl) goto err3;
		    if (ul != m->nr_bosl) goto err3;

		    t = 7; /* Test value @e */
		    if (!f_map_probe_iter_at(it, e, NULL)) goto err2;
		    f_map_free_iter(it); it = NULL;

		    t = 8; /* Iterate all entries */
		    it = bitmap_new_iter(m, (e_sz==1)?laminated:cv_laminated);
		    if (!f_map_next(it)) goto err2;
		    v = 0; ul = 0;
		    for_each_iter(it) {
			ul = it->entry;

		    if (pass == RND_REPS-1)
			dbg("  e:%lu e0:%lu @%lu bosl:%p page:%p",
			    ul, it->bosl->entry0, (ul-it->bosl->entry0),
			    it->bosl, it->bosl->page);

			if (!in_entries(ul, entries, pass+1))
			    goto err3;
			v++;
		    }
		    if (v != (pass+1)) goto err3;
		    f_map_free_iter(it); it = NULL;

#if 0 /* shmap: BoS delete not supported */
		    t = 8; /* delete all BoS entries */
		    rc = f_map_delete_bosl(m, bosl);
		    if (rc) goto err2;
		    if (m->nr_bosl) goto err2;

		    t = 9; /* SHould not find any entry */
		    if ((p = f_map_get_p(m, e))) goto err2;
		    if ((p = f_map_get_p(m, 0))) goto err2;
#endif
		}
	    }
	    MPI_Barrier(MPI_COMM_WORLD);
	    t = 10; /* broadcast entries */
	    rc = MPI_Bcast(entries, RND_REPS, MPI_UNSIGNED_LONG, 0, MPI_COMM_WORLD);
	    if (rc != MPI_SUCCESS) goto err0;

	    /* Read shared map */
	    if (rank > 0) {

		/* Iteration of a test group - we need to repeat tests with a random arg(s) */
		for (pass = 0; pass < RND_REPS; pass++) {
		    t = 11; /* Get BoS of current entry */
		    e = entries[pass];
		    dbg("pass:%d Retrieve e:%lu", pass, e);
		    bosl = f_map_get_bosl(m, e);
		    if (!bosl) goto err1;
		    //dbg(" bosl:%p page:%p", bosl, bosl->page);
		    if (!f_map_entry_in_bosl(bosl, e)) goto err2;

		    t = 12; /* Get entry pointer */
		    ul = e - bosl->entry0;
		    p = f_map_get_p(m, e);
		    if (p == NULL) goto err2;
		    if (p != (bosl->page+((e_sz == 1)?BIT_WORD(ul):BBIT_WORD(ul)))) goto err2;

		    /* count existing bosl entries */
		    vv = 0;
		    for (i=0; i<RND_REPS; i++)
			if (f_map_entry_in_bosl(bosl, entries[i]))
			    vv++;

		    t = 13; /* Count ones in BoS */
		    if (e_sz == 1) {
			v = bitmap_weight(bosl->page, m->bosl_entries);
			// v = __bitmap_weight64(bosl->page, 0, m->bosl_entries);
		    } else {
			v = bbitmap_weight(bosl->page, BB_PAT11, m->bosl_entries);
		    }
		    if (v != vv) goto err2;

		    t = 14; /* Check SM entry is 'allocated' */
		    if (e_sz == 1) {
			long_bbits = BITS_PER_LONG;
			if (!test_bit(ul, bosl->page)) goto err3;
		    } else {
			long_bbits = BBITS_PER_LONG;
			if (!test_bbit(ul, BBIT_11, bosl->page)) goto err3;
		    }

		    t = 15; /* Check actual bit position */
		    /* calculate entry # from pointer (p) and actual BBIT offset in *p */
		    ul = bosl->entry0 + ((uint64_t)(p - bosl->page))*long_bbits;
		    if (*p == 0UL) goto err2; /* Error: BBIT11 not set in *p */
		    /* actual bbit position in the word */
		    v = long_bbits - __builtin_clzl(*p)/e_sz - 1;
		    ul += (unsigned int)v;
		    if (ul != e && !in_entries(ul, entries, RND_REPS))
			goto err2; /* Error: bit position is not correct */

		    t = 16; /* Check iterator API @e */
		    it = bitmap_new_iter(m, (e_sz==1)?laminated:cv_laminated);
		    if (!f_map_seek_iter(it, bosl->entry0)) goto err2; /* ENOMEM */
		    /* value@e */
		    if (!f_map_probe_iter_at(it, e, NULL)) goto err2;
		    f_map_free_iter(it); it = NULL;

#if 0 /* shmap: BoS delete not supported */
		    t = 17; /* delete all BoS entries */
		    rc = f_map_delete_bosl(m, bosl);
		    if (rc) goto err2;
		    if (m->nr_bosl) goto err2;

		    t = 18; /* SHould not find any entry */
		    if ((p = f_map_get_p(m, e))) goto err2;
		    if ((p = f_map_get_p(m, 0))) goto err2;
#endif
		}

		t = 17; /* Iterate the map */
		it = bitmap_new_iter(m, (e_sz==1)?laminated:cv_laminated);
		if (!f_map_next(it)) goto err2;
		v = 0; ul = 0;
		for_each_iter(it) {
		    ul = it->entry;

		    dbg("  e:%lu bosl:%p e0:%lu @%lu",
			ul, it->bosl, it->bosl->entry0, (ul-it->bosl->entry0));

		    if (!in_entries(ul, entries, RND_REPS)) {
			bosl = it->bosl;
			goto err3;
		    }
		    v++;
		}
		if (v != RND_REPS) goto err3;
		f_map_free_iter(it); it = NULL;
	    }
	    t = 19; /* map exit: must survive */
	    f_map_exit(m);
	    m = NULL; bosl = NULL; p = NULL;

	    MPI_Barrier(MPI_COMM_WORLD);
	}
    }

    /*
     * Test group two: in-memory structured map
     */
    MPI_Barrier(MPI_COMM_WORLD);
    tg = 2;
    msg0("Running group %d tests: structured map in SHMEM", tg);

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
	    if (!m) goto err0;
	    rc = f_map_shm_attach(m, rank?F_MAPMEM_SHARED_RD:F_MAPMEM_SHARED_WR);
	    if (rc) goto err0;

	    /* Populate shared map: WR */
	    if (rank == 0) {

		/* Iteration of the group - we need to repeat tests with random entry */
		for (pass = 0; pass < RND_REPS; pass++) {

		    t = 1; /* Add single entry at random */
		    e = unique_rand_key(entries, pass, MEM_KEY_BITS);
		    entries[pass] = e;
		    dbg ("e_sz:%u pass:%d Add entry:%lu", e_sz, pass, e);

		    /* Create/get BoS for entry 'e' */
		    bosl = f_map_new_bosl(m, e);
		    if (!bosl) goto err1;
		    if (!f_map_entry_in_bosl(bosl, e)) goto err2;

		    t = 2; /* Get entry pointer */
		    ul = e - bosl->entry0;
		    p = f_map_get_p(m, e);
		    if (p == NULL) goto err2;
		    if (p != (bosl->page + ul*e_sz/sizeof(long))) goto err2;
		    pu = (F_PU_VAL_t *)p;

		    t = 3; /* Store BoS page bit count */
		    it = f_map_new_iter(m, sm_extent_failed, iext);
		    f_map_next(it); /*  the first entry */
		    v = f_map_weight(it, F_MAP_WHOLE);
		    if (v != pass) goto err2;
		    f_map_free_iter(it); it = NULL;

		    t = 4; /* Set SM entry to 'mapped' and count 'mapped' entries */
		    se = &pu->se;
		    v = 0;
		    if (se->mapped) goto err2;
		    se->mapped = 1;
		    ee = &pu->ee;
		    ee += iext; /* index of top extent */
		    v = 1;
		    if (ee->failed) goto err2;
		    ee->failed = 1;
		    //f_print_sm(stderr, m, ext, 1);

		    t = 5; /* Count ones */
		    it = f_map_new_iter(m, sm_extent_failed, iext);
		    f_map_next(it); /*  the first entry */
		    v = f_map_weight(it, F_MAP_WHOLE);
		    if (v != (pass+1)) goto err2;

		    t = 6; /* Test f_map_seek_iter() */
		    ul = m->nr_bosl;
		    if (!f_map_seek_iter(it, bosl->entry0)) goto err2; /* ENOMEM */
		    if (it->bosl != bosl) goto err3;
		    if (ul != m->nr_bosl) goto err3;

		    t = 7; /* Test value @e */
		    if (!f_map_probe_iter_at(it, e, NULL)) goto err2;
		    f_map_free_iter(it); it = NULL;

		    t = 8; /* Iterate all entries */
		    it = f_map_new_iter(m, sm_extent_failed, iext);
		    if (!f_map_next(it)) goto err3;
		    v = 0; ul = 0;
		    for_each_iter(it) {
			ul = it->entry;
			/*
			dbg("  e:%lu bosl:%p e0:%lu @%lu",
			    ul, it->bosl, it->bosl->entry0, (ul-it->bosl->entry0));
			*/
			if (!in_entries(ul, entries, pass+1)) {
			    bosl = it->bosl;
			    goto err3;
			}
			v++;
		    }
		    if (v != (pass+1)) goto err3;
		    f_map_free_iter(it); it = NULL;

		    t = 9; /* Check low-level bosl API */
		    v = 0; ui = 0;
		    ul = m->bosl_sz/sizeof(long);
		    it = f_map_new_iter(m, sm_extent_failed, iext);
		    it = f_map_next_bosl(it);
		    for_each_bosl(it) {
			ui++;
			bosl = it->bosl;
			vv = bitmap_weight(bosl->page, ul*BITS_PER_LONG);
			if (vv & 0x1) goto err3;
			v += vv/2;
		    }
		    if (ui != m->nr_bosl) goto err2;
		    if (v != (pass+1)) goto err1;
		    f_map_free_iter(it); it = NULL;

#if 0
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
#endif
		}

	    }
	    MPI_Barrier(MPI_COMM_WORLD);
	    t = 10; /* broadcast entries */
	    rc = MPI_Bcast(entries, RND_REPS, MPI_UNSIGNED_LONG, 0, MPI_COMM_WORLD);
	    if (rc != MPI_SUCCESS) goto err0;

	    /* Read shared map */
	    if (rank > 0) {

		/* Iteration of the group - we need to repeat tests with random entry */
		for (pass = 0; pass < RND_REPS; pass++) {

		    t = 11; /* Find BoS with current entry */
		    e = entries[pass];
		    dbg(" e_sz:%u pass:%d Retrieve e:%lu", e_sz, pass, e);
		    bosl = f_map_get_bosl(m, e);
		    if (!bosl) goto err1;
		    dbg("  bosl:%p page:%p nr_bosl:%lu",
			bosl, bosl->page, bosl->map->nr_bosl);
		    if (!f_map_entry_in_bosl(bosl, e)) goto err2;

		    t = 12; /* Get entry pointer */
		    ul = e - bosl->entry0;
		    p = f_map_get_p(m, e);
		    if (p == NULL) goto err2;
		    if (p != (bosl->page + ul*e_sz/sizeof(long))) goto err2;
		    pu = (F_PU_VAL_t *)p;

		    t = 13; /* Check BoS page bit count */
		    ul = m->bosl_sz/sizeof(long);
		    v = bitmap_weight(bosl->page, ul*BITS_PER_LONG);
		    if ((v == 0) || (v & 0x1)) goto err2;

		    t = 14; /* Check SM entry is 'mapped' */
		    se = &pu->se;
		    v = 0;
		    if (se->mapped != 1) goto err1;
		    ee = &pu->ee;
		    ee += iext; /* index of top extent */
		    v = 1;
		    if (ee->failed != 1) goto err1;

		    t = 15; /* Check iterator API @e */
		    it = f_map_new_iter(m, sm_extent_failed, iext);
		    ul = m->nr_bosl;
		    if (!f_map_seek_iter(it, bosl->entry0)) goto err2; /* ENOMEM */
		    if (it->bosl != bosl) goto err3;
		    if (ul != m->nr_bosl) goto err3;
		    /* value@e */
		    if (!f_map_probe_iter_at(it, e, NULL)) goto err2;
		    f_map_free_iter(it); it = NULL;
		}

		t = 16; /* Iterate all entries */
		it = f_map_new_iter(m, sm_extent_failed, iext);
		if (!f_map_next(it)) goto err3;
		v = 0; ul = 0;
		for_each_iter(it) {
		    ul = it->entry;

		    dbg("  e:%lu bosl:%p e0:%lu @%lu",
			ul, it->bosl, it->bosl->entry0, (ul-it->bosl->entry0));

		    if (!in_entries(ul, entries, RND_REPS)) {
			bosl = it->bosl;
			goto err3;
		    }
		    v++;
		}
		if (v != RND_REPS) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 17; /* Check low-level bosl API */
		v = 0; ui = 0;
		ul = m->bosl_sz/sizeof(long);
		it = f_map_new_iter(m, sm_extent_failed, iext);
		f_map_next_bosl(it);
		for_each_bosl(it) {
		    ui++;
		    bosl = it->bosl;
		    vv = bitmap_weight(bosl->page, ul*BITS_PER_LONG);
		    if (vv & 0x1) goto err3;
		    v += vv/2;
		}
		if (ui != m->nr_bosl) goto err2;
		if (v != RND_REPS) goto err2;
		f_map_free_iter(it); it = NULL;

		t = 18; /* Test f_map_weight() */
		it = f_map_new_iter(m, sm_extent_failed, iext);
		f_map_next(it); /*  the first entry */
		v = f_map_weight(it, F_MAP_WHOLE);
		if (v != RND_REPS) goto err2;
	    }
	    t = 19; /* Must survive map exit */
	    f_map_exit(m);
	    m = NULL; bosl = NULL; p = NULL;

	    MPI_Barrier(MPI_COMM_WORLD);
	}
    }
    rcu_unregister_thread();
    msg("SUCCESS");

  }
  free(entries);
  fflush(stdout);
  MPI_Finalize();
  return 0;

err3:
    msg("  Iterator @%s%lu BoS#%lu PU:%lu p:%p",
	f_map_iter_depleted(it)?" END ":"", it->entry,
	it->bosl->entry0/it->map->bosl_entries,
	(it->entry - it->bosl->entry0)/(1U << it->map->geometry.pu_factor),
	(f_map_is_structured(it->map)?NULL:it->word_p));
err2:
    msg("  BoS #%lu starts @%lu page:%p p:%p e:%lu @%lu PU:%lu",
	e/m->bosl_entries, bosl->entry0,
	bosl->page, p,
	e, (e - bosl->entry0),
	(e - bosl->entry0)/(1U << m->geometry.pu_factor));
err1:
    f_map_fprint_desc(stdout, m);
    msg("  Test variables: var=%d ul=%lu ui=%u vv=%d",
	v, ul, ui, vv);
err0:
    msg("  Test params: entry_size:%u, %u pages per BoS", e_sz, pages);
    if (tg==2)
	msg("  slab map has %d extent(s)", ext);
    msg("Test %d.%d (pass %d) FAILED rc:%d", tg, t, pass, rc);

    free(entries);
_err:
    MPI_Abort(MPI_COMM_WORLD, 1);
    return 1;
}

