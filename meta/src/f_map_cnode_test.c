/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 *
 * Client node test: map access outside of range server nodes.
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
#include "mdhim.h"


/* TEST options */
#define TEST_MDHIM_DBG	0	/* 1: MDHIM debug enabled */
#define RND_REPS	1000	/* number of passes for random test */
#define BOS_PAGE_MAX	4	/* max BoS page size, in kernel pages */
#define layout_id	0	/* use Layout 0 default configuration */
#define MEM_KEY_BITS	64	/* in-memory maps: max global entry bits */
#define DB_KEY_BITS	31	/* DB-backed maps: max global entry bits */
#define META_DB_PATH	"/dev/shm"
#define SM_EXT_MAX	3	/* max extent # in Slab map */
#define CL_DEF_PART	0	/* Default partition to be read on Client */


/* MDHIM client communicator includes all nodes; RS - all but node 0. */
#define BARRIER_WORLD		MPI_Barrier(MPI_COMM_WORLD)
#define BARRIER_MDHIM		MPI_Barrier(md->mdhim_client_comm)
#define BARRIER_RS		MPI_Barrier(rs_comm)
#define is_client_node()	(rank == mpi_size-1)

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

#define err(str, ...) fprintf(stderr, #str "\n", ## __VA_ARGS__)
#define msg0(str, ...) if (rank==0) printf( str "\n", ## __VA_ARGS__)
#define msg(str, ...) printf("%d: " str "\n", rank, ## __VA_ARGS__)


/* MDHIM MDS vector: '1' means that range server is running on node */
extern char *mds_vec;
extern int  num_mds;

/* MDHIM and Layout config */
F_LAYOUT_INFO_t *lo_info = NULL;
unifycr_cfg_t md_cfg;
struct mdhim_t *md;
struct index_t *unifycr_indexes[2*F_LAYOUTS_MAX+1]; /* +1 for primary_index */
/* MPI node rank and size in COMM_WORLD */
static int rank = 0;
static int mpi_size = 0;
/* MPI range server communicator or COMM_NULL if not on a range server node */
static MPI_Comm rs_comm = MPI_COMM_NULL;

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

	assert(md->primary_index);
	unifycr_indexes[0] = md->primary_index;
	for (i = 1; i <= 2*F_LAYOUTS_MAX; i++)
		unifycr_indexes[i] = NULL;

	/* Check RS is running on nodes [0..size-2] and not running on last node */
	if (md->primary_index->myinfo.rangesrv_num > 0) {
		 int rs_size, rc;

		rc = MPI_Comm_size(md->primary_index->rs_comm, &rs_size);
		if (rc != MPI_SUCCESS) {
			err("%d: Cannot get MDHIM RS size:%d", rank, rc);
			assert(0);
		}
		if (rs_size != unifycr_indexes[0]->rangesrv_master + 1) {
			err("%d: MDHIM reports wrong master:%d RS, rs_size:%d",
			    rank, unifycr_indexes[0]->rangesrv_master, rs_size);
			assert(0);
		}
		if (rs_size != mpi_size - 1) {
			err("%d: Wrong MDHIM RS size:%d, MPI size:%d",
			    rank, rs_size, mpi_size);
			assert(0);
		}
	} else {
		if (!is_client_node()) {
			err("%d: RS is running here!? mpi_size:%d",
			    rank, mpi_size);
			assert(0);
		}
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
        uint32_t rangesrv_num;

	if (!unifycr_indexes[i])
		continue;
	rangesrv_num = unifycr_indexes[i]->myinfo.rangesrv_num;
	if (rangesrv_num == 0)
		continue;
	ids[max_id] = unifycr_indexes[i]->id;
	types[max_id] = unifycr_indexes[i]->type;
	manifest = (rangesrv_num == 1);
	max_id++;
    }
    rc = mdhimClose(md);
    if (rc) {
	err("%d: mdhimClose error:%d", rank, rc);
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
	    err("%d: mdhimSanitize %s error:%d",
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

    rs_comm = MPI_COMM_NULL;
    if (unifycr_indexes[id] == NULL) {
	unifycr_indexes[id] = create_global_index(md, md->db_opts->rserver_factor,
					intl, LEVELDB, MDHIM_LONG_INT_KEY, name);
	if (unifycr_indexes[id] == NULL)
		return -1;

	msg("create_persistent_map:%d %s index[%u] interleave:%d rs:%d",
	    info->map_id, name, id, intl,
	    unifycr_indexes[id]->myinfo.rangesrv_num);

    }
    if (unifycr_indexes[id]->myinfo.rangesrv_num > 0) {
	/* Copy MPI communicator if a range server */
	rs_comm = unifycr_indexes[id]->rs_comm;
	if (mpi_size - 1 != (unifycr_indexes[id]->rangesrv_master + 1)) {
	    err("%d: create_persistent_map:%u rs_size:%d master:%d",
		rank, id, mpi_size-1,
		unifycr_indexes[id]->rangesrv_master);
	    return -1;
	}
    } else {
	/* If no range server running, set RO flag to protect persistent map */
	info->ro = 1;
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
    int global, v, rc, i;
    int flag, provided, map_part, map_parts;

    srand((unsigned int)time(NULL));
    page = getpagesize();
    global = 1;
    pass = rc = v = 0;
    e = ul = 0;
    ui = ext = 0;
    p = NULL; it = NULL;

    /* Initialize MPI */
    if ((rc = MPI_Initialized(&flag)) != MPI_SUCCESS) {
	err("Error while calling MPI_Initialized");
	exit(1);
    }
    if (!flag) {
	rc = MPI_Init_thread(NULL, NULL, MPI_THREAD_MULTIPLE, &provided);
	if (rc != MPI_SUCCESS) {
	    err("Error while calling MPI_Init_thread");
	    exit(1);
	}
	if (provided != MPI_THREAD_MULTIPLE) {
	    err("Error while initializing MPI with threads");
	    exit(1);
	}
    }
    if ((rc = MPI_Comm_size(MPI_COMM_WORLD, &mpi_size)) != MPI_SUCCESS) {
	err("Error getting the size of the communicator:%d", rc);
	exit(1);
    }
    if ((rc = MPI_Comm_rank(MPI_COMM_WORLD, &rank)) != MPI_SUCCESS) {
	err("Error getting the rank:%d", rc);
	exit(1);
    }
    /* If rank == mpi_size-1, that's a client node w/o MDHIM RS */
    map_parts = mpi_size - 1;
    if (map_parts <= 0) {
	/* At least three nodes recommended for the test */
	err("Not enough nodes available for this test: %d", mpi_size);
	exit(1);
    }
    /* Set MDS vector */
    mds_vec = calloc(sizeof(*mds_vec), mpi_size);
    num_mds = mpi_size-1;
    for (i = 0; i < num_mds; i++)
	mds_vec[i] = 1;


    /*
     * Test group one: Init KV store
     */
    tg = 1;
    msg0("Running group %d tests: start/stop KV store (MDHIM)", tg);
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

    t = 3; /* Bring up DB thread */
    meta_init_store(db_opts);
    if (md == NULL || unifycr_indexes[0] == NULL) goto err;
    if (md->mdhim_comm_size == 0) goto err;

    msg("Layout%d %s (%uD+%uP) chunk:%u slab_stripes:%u devnum:%u",
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

    t = 5; /* Set map partition to part 'rank' of [0..size-1] */
    global = 0;
    map_part = (rank == map_parts)? CL_DEF_PART:rank;
    rc = f_map_init_prt(m, map_parts, map_part, 0, global);
    if (rc) goto err1;

    t = 6; /* Register map with Layout0 */
    rc = f_map_register(m, layout_id);
    if (rc) goto err1;
    if (f_map_is_ro(m) != is_client_node()) goto err1;

    t = 7; /* free map */
    f_map_exit(map); m = map = NULL;
    rcu_unregister_thread();

    t = 8; /* Remove old DB files for Layout0 */
    rc = meta_sanitize(); db_opts = NULL;
    if (rc) goto err;
    f_free_layout_info();
    unifycr_config_free(&md_cfg);

    /*
     * Test group two: Bitmaps with KV store backend
     */
    tg = 2;
    msg0("Running group %d tests: bitmaps with KV store backend", tg);

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

		msg("with BoS pages:%u, %s%sbitmap",
		    pages, global?"global ":"", (e_sz==2)?"b":"");

		t = 3; /* Set map partition */
		m = map;
		/* partition: map_node of [0..size-1] */
		rc = f_map_init_prt(m, map_parts, map_part, 0, global);
		if (rc || !(m->own_part ^ (unsigned)global)) goto err1;

		t = 4; /* Register map with Layout0 */
		rc = f_map_register(m, layout_id);
		if (rc != 0) goto err1;

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
			max_globals += (map_parts-1)*RND_REPS;

		    t = 6; /* Count entries in loaded map */
		    it = bitmap_new_iter(m,(e_sz==1)?laminated:cv_laminated);
		    it = f_map_seek_iter(it, 0); /* create BoS zero */
		    if (!it) goto err2;
		    actual = v = (int)f_map_weight(it, F_MAP_WHOLE);
		    /* Client node may go ahead of its default partition */
		    if (!is_client_node() && !IN_RANGE(v, pass, max_globals))
			goto err3;

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
		    /* client node may read this bit set by part 0 node */
		    if (v && !is_client_node()) goto err2;
		    /* expect one more entry in map */
		    if (!v)
			actual++;
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

		    t = 11; /* Flush map */
		    v = 0;
		    rc = f_map_flush(m);
		    if (rc != 0) goto err2;
		    /* on client node flush() should not clear dirty PU bit */
		    if (is_client_node() && !test_and_clear_bit(ui, bosl->dirty))
			goto err1;
		    /* check dirty bit cleared */
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    if (v) goto err2;

		    t = 12; /* Count map entries */
		    v = 0;
		    for_each_iter_from(it, 0)
			v++;
		    if (v != actual) goto err3;
		    f_map_free_iter(it); it = NULL;

		    t = 13; /* Add 'e' to bitmap 'mlog' */
		    p = f_map_new_p(mlog, e);
		    if (!p) goto err2;
		    i = BIT_NR_IN_LONG(e);
		    if (test_and_set_bit(i, p)) goto err2; /* already set? */
		}

		if (!is_client_node())
		    goto t_2_14;

		t = 14; /* Clear map on Client node */
		it = f_map_new_iter(map, F_NO_CONDITION, 0);
		it = f_map_next_bosl(it);
		for_each_bosl(it)
		    if ((rc = f_map_delete_bosl(map, it->bosl))) goto err3;
		if (map->nr_bosl) goto err1;
		f_map_free_iter(it); it = NULL;

		goto t_2_before_del;
t_2_14:
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

t_2_before_del:
		BARRIER_MDHIM;

		if (!is_client_node())
		    goto t_2_del;

		t = 19; /* Read the whole map */
		rc = f_map_init_prt(map, map_parts, 0, 0, 1);
		if (rc != 0) goto err1;
		rc = f_map_load(map);
		if (rc != 0) goto err1;
		it = f_map_new_iter(map, PSET_NON_ZERO, 0);
		it = f_map_seek_iter(it, 0);
		rc = (int)f_map_weight(it, F_MAP_WHOLE);
		/* check the total number of map entries */
		v = RND_REPS*map_parts;
		if (rc != v) goto err3;
		f_map_free_iter(it); it = NULL;

t_2_del:
		BARRIER_MDHIM;

		t = 20; /* Delete all PUs in DB */
		rc = f_map_flush(map);
		if (rc != 0) goto err2;

		t = 21; /* Delete all BoS entries */
		it = f_map_get_iter(map, F_NO_CONDITION, 0);
		ui = map->nr_bosl;
		if (!is_client_node()) {
		    /* maximum expected number of BoSses; +1 for BoS #0 */
		    ul = RND_REPS*(global? map_parts:1) + 1;
		    if (ui > ul) goto err1;
		}
		ul = 0;
		for_each_iter(it) {
		    unsigned long bit;

		    bosl = it->bosl;
		    /* check dirty bits cleared for map partition */
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    for_each_set_bit(bit, bosl->dirty, dirty_sz) {
			printf("p%d dirty bit:%lu/%lu%s\n", map_part,
			    bosl->entry0/bosl->map->bosl_entries, bit,
			    (global&&!bosl_pu_in_my_part(bosl, bit))?" F":"");
		    }
		    if (v) goto err3;
		    if (atomic_read(&bosl->claimed) != 1) goto err3;
		    if ((rc = f_map_delete_bosl(map, bosl))) goto err2;
		    it->bosl = NULL; /* make for_each_iter() go next BoS */
		    ul++;
		}
		t = 22; /* Extra check: map BoS accounting (nr_bosl) */
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

		BARRIER_MDHIM;

		t = 23; /* Check the whole map is empty */
		rc = f_map_init_prt(map, map_parts, map_part, 0, 1);
		if (rc != 0) goto err1;
		rc = f_map_load(map);
		if (rc != 0) goto err1;
		ul = 0;
		it = f_map_get_iter(map, PSET_NON_ZERO, 0);
		for_each_iter(it) {
		    e = it->entry;
		    ul++;
		    msg("%lu e:%lu buf:%016lX", ul, e, *it->word_p);
		}
		if (ul) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 24; /* Delete all map BoSses */
		it = f_map_new_iter(map, F_NO_CONDITION, 0);
		it = f_map_next_bosl(it);
		for_each_bosl(it)
		    if ((rc = f_map_delete_bosl(map, it->bosl))) goto err3;
		if (map->nr_bosl) goto err1;
		f_map_free_iter(it); it = NULL;

		t = 25; /* Delete all bitmap entries */
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
		t = 26; /* Extra check: map BoS accounting (nr_bosl) */
		if ((ul = mlog->nr_bosl)) goto err1;
		if ((v = f_map_max_bosl(mlog))) goto err2;
		f_map_free_iter(it); it = NULL;
		bosl = NULL; p = NULL;
		// msg(" - %d Ok", t);

		rcu_quiescent_state();

		BARRIER_MDHIM;
	    }
	    t = 27; /* map exit: must survive */
	    f_map_exit(map);
	    f_map_exit(mlog);
	    m = mlog = map = NULL;
	}
    }
    rcu_unregister_thread();

    t = 28;
    rc = meta_sanitize();
    if (rc) goto err;
    f_free_layout_info();
    unifycr_config_free(&md_cfg);

    /*
     * Test group three: Structured map with KV store backend
     */
    tg = 3;
    msg0("Running group %d tests: structured map with KV store backend", tg);

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
	    mlog = f_map_init(F_MAPTYPE_BITMAP, 1, 0, 0);
	    if (!mlog) goto err0;

	    /* Test partitioned map with only partition, all partitions */
	    for (global = 0; global <= 1; global++) {
		msg("with BoS pages:%u, %sstructured map, %d extent%s",
		    pages, global?"global ":"", ext, (ext==1)?"":"s");

		t = 3; /* Set map partition */
		m = map;
		/* partition: 'map_part' of [0..size-1] */
		rc = f_map_init_prt(m, map_parts, map_part, 0, global);
		if (rc) goto err1;

		t = 4; /* Register map with Layout0 */
		rc = f_map_register(m, layout_id);
		if (rc != 0) goto err1;

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
			max_globals += (map_parts-1)*RND_REPS;

		    t = 6; /* Count entries in loaded map */
		    it = f_map_new_iter(m, sm_extent_failed, iext);
		    it = f_map_seek_iter(it, 0); /* create BoS zero */
		    if (!it) goto err2;
		    actual = v = (int)f_map_weight(it, F_MAP_WHOLE);
		    /* Client node may go ahead of its default partition */
		    if (!is_client_node() && !IN_RANGE(v, pass, max_globals))
			goto err3;

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
		    ee = &pu->ee;
		    v = __builtin_popcountll(se->_v128);
		    for (ui = 0; ui < ext && v == 0; ui++, ee++)
			v = __builtin_popcountl(ee->_v64);
		    /* client node may read this bit set by part 0 node */
		    if (v && !is_client_node()) goto err2;
		    /* set SM entry to 'mapped' and count 'mapped' entries */
		    if (!v) actual++;
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

		    t = 11; /* Flush map */
		    rc = f_map_flush(m);
		    if (rc != 0) goto err2;
		    /* on client node flush() should not clear dirty PU bit */
		    if (is_client_node() && !test_and_clear_bit(ui, bosl->dirty))
			goto err1;
		    /* check dirty bit cleared */
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    if (v) goto err2;

		    t = 12; /* Count man entries */
		    v = 0;
		    for_each_iter_from(it, 0)
			v++;
		    if (v != actual) goto err3;
		    f_map_free_iter(it); it = NULL;

		    t = 13; /* Add to 'mlog' the new map entry 'e' */
		    p = f_map_new_p(mlog, e);
		    if (!p) goto err2;
		    i = BIT_NR_IN_LONG(e);
		    if (test_and_set_bit(i, p)) goto err2; /* already set? */
		}
		if (!is_client_node())
		    goto t_3_14;

		t = 14; /* Clear map on Client node */
		it = f_map_new_iter(map, F_NO_CONDITION, 0);
		it = f_map_next_bosl(it);
		for_each_bosl(it)
		    if ((rc = f_map_delete_bosl(map, it->bosl))) goto err3;
		if (map->nr_bosl) goto err1;
		f_map_free_iter(it); it = NULL;

		goto t_3_before_del;
t_3_14:
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

t_3_before_del:
		BARRIER_MDHIM;

		if (!is_client_node())
		    goto t_3_del;

		t = 19; /* Read the whole map */
		rc = f_map_init_prt(map, map_parts, 0, 0, 1);
		if (rc != 0) goto err1;
		rc = f_map_load(map);
		if (rc != 0) goto err1;
		it = f_map_new_iter(map, se_or_ee_not_zero, ext);
		it = f_map_seek_iter(it, 0);
		rc = (int)f_map_weight(it, F_MAP_WHOLE);
		/* check the total number of map entries */
		v = RND_REPS*map_parts;
		if (rc != v) goto err3;
		f_map_free_iter(it); it = NULL;

t_3_del:
		BARRIER_MDHIM;

		t = 20; /* Delete empty PU in DB */
		rc = f_map_flush(map);
		if (rc != 0) goto err2;

		t = 21; /* Delete all BoS entries */
		it = f_map_get_iter(map, F_NO_CONDITION, 0);
		ui = map->nr_bosl;
		if (!is_client_node()) {
		    /* maximum expected number of BoSses; +1 for BoS #0 */
		    ul = RND_REPS*(global? map_parts:1) + 1;
		    if (ui > ul) goto err1;
		}
		ul = 0;
		for_each_iter(it) {
		    unsigned long bit;

		    bosl = it->bosl;
		    /* check dirty bits cleared for map partition */
		    v = bitmap_weight(bosl->dirty, dirty_sz);
		    for_each_set_bit(bit, bosl->dirty, dirty_sz) {
			printf("p%d dirty bit:%lu/%lu%s\n", map_part,
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
		t = 22; /* Extra check: map BoS accounting (nr_bosl) */
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

		BARRIER_MDHIM;

		t = 23; /* Count entries in loaded map */
		/* load all map partitions */
		rc = f_map_init_prt(map, map_parts, map_part, 0, 1);
		if (rc != 0) goto err1;
		rc = f_map_load(map);
		if (rc != 0) goto err1;
		ul = 0;
		it = f_map_get_iter(map, se_or_ee_not_zero, ext);
		for_each_iter(it) {
		    e = it->entry;
		    ul++;
		    msg("%lu e:%lu buf:%016lX", ul, e, *it->word_p);
		}
		if (ul) goto err3;
		f_map_free_iter(it); it = NULL;

		t = 24; /* Delete all map BoSses */
		it = f_map_new_iter(map, F_NO_CONDITION, 0);
		it = f_map_next_bosl(it);
		for_each_bosl(it)
		    if ((rc = f_map_delete_bosl(map, it->bosl))) goto err3;
		if (map->nr_bosl) goto err1;
		f_map_free_iter(it); it = NULL;

		t = 25; /* Delete all log entries */
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
		t = 26; /* Extra check: map BoS accounting (nr_bosl) */
		if ((ul = mlog->nr_bosl)) goto err1;
		if ((v = f_map_max_bosl(mlog))) goto err2;
		f_map_free_iter(it); it = NULL;
		bosl = NULL; p = NULL;
		// msg(" - %d Ok", t);

		rcu_quiescent_state();

		BARRIER_MDHIM;
	    }
	    t = 27; /* map exit: must survive */
	    f_map_exit(map);
	    f_map_exit(mlog);
	    m = mlog = map = NULL;
	}
    }
    rcu_unregister_thread();

    t = 28;
    rc = meta_sanitize();
    if (rc) goto err1;
    f_free_layout_info();
    unifycr_config_free(&md_cfg);

    BARRIER_WORLD;
    MPI_Finalize();

    msg0("SUCCESS");
    return 0;

err3:
    if (it) {
	msg("  Iterator @%s%lu PU:%lu p:%p -> %016lx",
	    f_map_iter_depleted(it)?"END ":"", it->entry,
	    (it->entry % it->map->bosl_entries)/(1U << it->map->geometry.pu_factor),
	    it->word_p, *it->word_p);
	if (f_map_entry_in_bosl(it->bosl, it->entry))
	    msg("    entry @%lu in BoS:%lu",
		it->entry - it->bosl->entry0,
		it->bosl->entry0/it->map->bosl_entries);
    }
err2:
    if (bosl) {
	msg("  BoS #%lu starts @%lu page:%p",
	    bosl->entry0/bosl->map->bosl_entries, bosl->entry0,
	    bosl->page);
    }
err1:
    if (m) {
	msg("  Map BoS sz:%lu (%u entries), %u per PU, %u PU(s) per BoS",
	    m->bosl_sz, m->bosl_entries,
	    1U << m->geometry.pu_factor,
	    m->geometry.bosl_pu_count);
	msg("  map BoS count:%lu, max:%lu",
	    m->nr_bosl, f_map_max_bosl(m)-1);
	msg("  Part %u of %u in %spartitioned %s map; "
		"interleave:%u entries, %u PUs",
	    m->part, m->parts, (m->parts<=1)?"non-":"",
	    f_map_has_globals(m)?"global":"local",
	    1U<<m->geometry.intl_factor,
	    1U<<(m->geometry.intl_factor-m->geometry.pu_factor));
	msg("    entry:%lu @%lu PU:%lu",
	    e, (e % m->bosl_entries),
	    (e % m->bosl_entries)/(1U << m->geometry.pu_factor));
    }
    if (p != NULL)
	msg("  p:%p -> %016lX", p, *p);
err0:
    msg("Test parameters: entry_size:%u, %u pages per BoS, global:%d",
	e_sz, pages, global);
    if (ext)
	msg("  slab map has %d extent(s)", ext);
    msg("Test variables: rc=%d var=%d ul=%lu ui=%u",
	rc, v, ul, ui);
err:
    err("%d - Test %d.%d (pass %d) FAILED", rank, tg, t, pass);
    MPI_Abort(MPI_COMM_WORLD, 1);
    return 1;
}

