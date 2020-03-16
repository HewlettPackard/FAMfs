/*
 * Copyright (c) 2019, HPE
 *
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

#include "famfs_bitmap.h"
#include "f_map.h"

/* TEST options */
#define RND_REPS	1000	/* number of passes for random test */
#define BOS_PAGE_MAX	4	/* max BoS page size, in kernel pages */
#define MEM_KEY_BITS	64	/* in-memory maps: max global entry bits */

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

#define err(str, ...) fprintf(stderr, #str "\n", ## __VA_ARGS__)
#define msg0(str, ...) if (rank==0) printf( str "\n", ## __VA_ARGS__)
#define msg(str, ...) printf("%d: " str "\n", rank, ## __VA_ARGS__)


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
  unsigned long *p;
  unsigned int ui, e_sz, long_bbits, pages;
  unsigned int iext, ext;
  int pass, tg, t, v;
  int flag, provided;

  int np = NR_SPAWNS;
  int errcodes[NR_SPAWNS];
  int i, rc;
  MPI_Comm parentcomm, intercomm;

  if ((rc = MPI_Initialized(&flag)) != MPI_SUCCESS) {
	err("Error while calling MPI_Initialized");
	goto err0;
  }
  if (!flag) {
	rc = MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &provided);
	if (rc != MPI_SUCCESS) {
	    err("Error while calling MPI_Init_thread");
	    goto err0;
	}
	if (provided != MPI_THREAD_MULTIPLE) {
	    err("Error while initializing MPI with threads");
	    goto err0;
	}
  }

  MPI_Comm_get_parent(&parentcomm);
  if (parentcomm == MPI_COMM_NULL) {
    /* Create MPI processes: NR_READERS plus one writer */
#if 0
    char *av[] = {"-x", "gdb", NULL};
    rc = MPI_Comm_spawn("/usr/bin/gdb", av, np,
#else
    rc = MPI_Comm_spawn("./f_shmap_test", MPI_ARGV_NULL, np,
#endif
			MPI_INFO_NULL, 0,
			MPI_COMM_WORLD, &intercomm, errcodes /* MPI_ERRCODES_IGNORE */);
    if (rc != MPI_SUCCESS) {
	err("failed to spawn f_shmap_test processes");
	return 1;
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
	goto err0;
    }
    if ((rc = MPI_Comm_rank(MPI_COMM_WORLD, &rank)) != MPI_SUCCESS) {
	err("Error getting the rank:%d", rc);
	goto err0;
    }

    srand((unsigned int)time(NULL));
    page = getpagesize();
    pass = rc = v = 0;
    e = ul = 0;
    ui = ext = 0;
    p = NULL; it = NULL;

    /*
     * Test group one: in-memory bitmaps
     */
    MPI_Barrier(MPI_COMM_WORLD);
    tg = 1;
    msg0("Running group %d tests: bitmaps and bifold bitmaps", tg);

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
	    rc = f_map_shm_attach(m, NULL,
				  rank? F_MAPMEM_SHARED_RD : F_MAPMEM_SHARED_WR);
	    if (rc) goto err0;
	    /* check BoS size */
	    if (m->bosl_entries != (unsigned int)(m->bosl_sz*8/e_sz)) goto err1;

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
		if (!rank &&
		    !f_map_seek_iter(it, bosl->entry0)) goto err2; /* ENOMEM */
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
	    if (rank>0) {
		f_map_exit(m);
		//msg("RD map_exit");
	    }
	    MPI_Barrier(MPI_COMM_WORLD);
	    if (rank==0) {
		f_map_exit(m);
		//msg("WR map_exit");
	    }
	    MPI_Barrier(MPI_COMM_WORLD);
	    m = NULL; bosl = NULL; p = NULL;
	    //rcu_quiescent_state();
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
	    rc = f_map_shm_attach(m, NULL,
				  rank? F_MAPMEM_SHARED_RD : F_MAPMEM_SHARED_WR);
	    if (rc) goto err0;

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
	    if (rank>0) {
		f_map_exit(m);
		//msg("RD map_exit");
	    }
	    MPI_Barrier(MPI_COMM_WORLD);
	    if (rank==0) {
		f_map_exit(m);
		//msg("WR map_exit");
	    }
	    MPI_Barrier(MPI_COMM_WORLD);
	    m = NULL; bosl = NULL; p = NULL;
	}
    }
    rcu_unregister_thread();
    msg("SUCCESS");

  }
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
    msg("  Test variables: var=%d ul=%lu ui=%u",
	v, ul, ui);
err0:
    msg("  Test params: entry_size:%u, %u pages per BoS", e_sz, pages);
    if (tg==2)
	msg("  slab map has %d extent(s)", ext);
    msg("Test %d.%d (pass %d) FAILED rc:%d", tg, t, pass, rc);

    MPI_Abort(MPI_COMM_WORLD, 1);
    return 1;
}

