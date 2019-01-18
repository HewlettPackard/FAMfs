/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <limits.h>
#include <ifaddrs.h>

#include <mpi.h>

#include "famfs_env.h"
#include "famfs_stats.h"
#include "famfs_stripe.h"
#include "famfs_lf_connect.h"
#include "node.h"
#include "w_pool.h"
#include "ec_perf.h"


#define SRV_WK_INIT	W_T_LOAD
#define SRV_WK_TRIGGER	1

static int rank, rank_size;
static W_POOL_t *w_srv_pool = NULL;	/* FAM target emulation thread pool */

static const char *PERF_NAME[] = { "Enc", "Rec", "Write", "Read", 0 };
#define PERF_STAT_ENC	1
#define PERF_STAT_REC	2
#define PERF_STAT_W	4
#define PERF_STAT_R	8

static pthread_spinlock_t pstats_lock;	/* struct perf_stat_ lock */
static struct perf_stat_  perf_stats;	/* data transfer/encode/decode statistic */
static unsigned char   *enc_tbl;	/* EC encode table */
static unsigned char   *dec_tbl;	/* EC decode table */
static unsigned char   *rs_a;		/* R-S matrix for encode->decode conversion */

//static int lf_srv_init(LF_SRV_t *priv);
static int lf_srv_trigger(LF_SRV_t *priv);
static void lf_srv_wait(W_POOL_t* srv_pool, LF_SRV_t **servers, N_PARAMS_t *params);
static int worker_srv_func(W_TYPE_t type, void *arg, int thread_id);
static int worker_func(W_TYPE_t type, void *params, int thread_id);
static void do_phy_stripes(uint64_t *stripe, W_TYPE_t op, N_PARAMS_t *params, W_POOL_t* pool, uint64_t *done);
static void perf_stats_init(PERF_STAT_t *stats);
static void perf_stats_reduce(PERF_STAT_t *src, PERF_STAT_t *dst, size_t off, MPI_Op op);
static void perf_stats_print(PERF_STAT_t *stats, size_t off, int mask, const char *msg, uint64_t units);
static void perf_stats_print_bw(PERF_STAT_t *stats, int mask, const char *msg, uint64_t tu, uint64_t bu);


static int lf_target_init(LF_SRV_t ***lf_servers_p, N_PARAMS_t *params)
{
    LF_SRV_t **lf_servers;
    int srv_cnt, node_id, lf_client_idx;
    int i, part, rc;

    node_id = params->node_id;
    srv_cnt = params->node_servers;

    if (params->part_mreg == 0)
	ON_ERROR(posix_memalign(&params->fam_buf, getpagesize(), params->vmem_sz), "srv memory alloc failed");

    lf_servers = (LF_SRV_t **) malloc(srv_cnt*sizeof(void*));
    ASSERT(lf_servers);
    for (i = 0; i < srv_cnt; i++) {
	LF_CL_t *cl;

	lf_servers[i] = (LF_SRV_t *) malloc(sizeof(LF_SRV_t));
	lf_servers[i]->params = params;
	//lf_servers[i]->length = part_length;
	//lf_servers[i]->virt_addr = NULL;
	cl = (LF_CL_t*) calloc(1, sizeof(LF_CL_t));
	cl->partition = i;
	//cl->fam_id = fam_id_by_index(params->fam_map, i);
	cl->service = node2service(params->lf_port, node_id, i);
	if ( params->set_affinity)
	    alloc_affinity(&cl->cq_affinity, srv_cnt, i + 1);
	lf_servers[i]->lf_client = cl;
    }

    w_srv_pool = pool_init(srv_cnt, &worker_srv_func, lf_servers[0]->lf_client->cq_affinity);
    if (w_srv_pool == NULL) {
	err("Error initializing LF server threads");
	return 1;
    }
    for (i = 0; i < srv_cnt; i++) {
	ON_ERROR( pool_add_work(w_srv_pool, SRV_WK_INIT, lf_servers[i]),
		"Error queueing LF target init work %u of %u", i, srv_cnt);
    }

    /* Wait for all LF servers started */
    rc = pool_wait_works_done(w_srv_pool, LFSRV_START_TMO);
    if (rc) {
	err("LF SRV start timeout on %s", params->nodelist[node_id]);
	return 1;
    }
    if (rank == 0) {
	printf("LF target scalable:%d local:%d basic:%d (prov_key:%d virt_addr:%d allocated:%d)\n",
		params->lf_mr_flags.scalable, params->lf_mr_flags.local, params->lf_mr_flags.basic,
		params->lf_mr_flags.prov_key, params->lf_mr_flags.virt_addr, params->lf_mr_flags.allocated);
    }

    MPI_Barrier(MPI_COMM_WORLD);

    /* Exchange keys */
    if (params->lf_mr_flags.prov_key) {
	size_t len = srv_cnt * sizeof(uint64_t);

	/* For each partition */
	for (part = 0; part < srv_cnt; part++) {
	    lf_client_idx = to_lf_client_id(node_id, srv_cnt, part);
	    params->mr_prov_keys[lf_client_idx] = lf_servers[part]->lf_client->mr_key;
	}
	ON_ERROR( MPI_Allgather(/* &mr_prov_keys[srv_cnt*node_id] */ MPI_IN_PLACE, len, MPI_BYTE,
				params->mr_prov_keys, len, MPI_BYTE, MPI_COMM_WORLD),
		 "MPI_Allgather");
    }
    /* Exchange virtual addresses */
    if (params->lf_mr_flags.virt_addr) {
	size_t len = srv_cnt * sizeof(uint64_t);

	/* For each partition */
	for (part = 0; part < srv_cnt; part++) {
	    lf_client_idx = to_lf_client_id(node_id, srv_cnt, part);
	    params->mr_virt_addrs[lf_client_idx] = (uint64_t) lf_servers[part]->virt_addr;
	}
	ON_ERROR( MPI_Allgather(MPI_IN_PLACE, len, MPI_BYTE,
				params->mr_virt_addrs, len, MPI_BYTE, MPI_COMM_WORLD),
		 "MPI_Allgather");
    }

    *lf_servers_p = lf_servers;
    return 0;
}

static void node_exit(int rc) {
	if (rc) {
		sleep(10);
		MPI_Abort(MPI_COMM_WORLD, (rc>0)?rc:-rc);
	}
	MPI_Finalize();
	if (rank == 0) {
		exit(rc);
	} else if (rc != 0) {
		{ sleep(10); } while (1);
	ASSERT(0); /* Should not reach this */
	}
}

static void usage(const char *name) {
    if (rank == 0)
	ion_usage(name);
    node_exit(1);
}

int main(int argc, char **argv) {
    PERF_STAT_t		stats_agg_bw;
    struct ec_perf	node_stat;
    LF_SRV_t		**lf_servers = NULL;
    W_POOL_t		*w_pool;
    N_PARAMS_t		*params = NULL;
    size_t		chunk_sz;
    int			i, k, node_id, srv_cnt, rc;
    int			nchunks, data, parities;
    int			initialized = 0, provided;
    uint64_t		stripes, node_stat_max, node_stat_agg;


    ASSERT(sizeof(size_t) == 8);
    ASSERT(sizeof(PERF_STAT_t) == 4*sizeof(struct ec_perf));

    rc = MPI_Initialized(&initialized);
    if (rc == MPI_SUCCESS) {
	if (!initialized)
	    rc = MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &provided);
	else
	    rc = MPI_Query_thread(&provided);
    }
    if (rc != MPI_SUCCESS || provided < MPI_THREAD_MULTIPLE) {
	printf("MPI_Init failure\n");
	exit(1);
    }
    MPI_Comm_size(MPI_COMM_WORLD, &rank_size);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    /* Parse command */
    if ((rc = arg_parser(argc, argv, (rank == 0), -1, &params))) {
	err("Error parsing command arguments");
	usage(argv[0]);
    }
    ON_ERROR( pthread_spin_init(&pstats_lock, PTHREAD_PROCESS_SHARED), "pthr spin init");
    nchunks = params->nchunks;
    parities = params->parities;
    data = nchunks - parities;
    node_id = params->node_id;
    srv_cnt = params->node_servers;
    chunk_sz = params->chunk_sz;
    stripes = params->vmem_sz / chunk_sz;

    /* Emulate ION FAMs with libfabric targets */
    if (!params->fam_map) {
	rc = lf_target_init(&lf_servers, params);
	if (rc) {
	    err("Can't start FAM emulation target on %s",
		params->nodelist[node_id]);
	    node_exit(1);
	}
    }

    /* Standalone: FAM clients */
    lf_clients_init(params);

    w_pool = pool_init(params->w_thread_cnt, &worker_func, params->lf_clients[0]->cq_affinity);
    if (w_pool == NULL) {
	printf("Error initializing worker pool\n");
	rc = 1;
	goto exit_srv_thr;
    }

/*
 * Execute command flow
 */
    for (k = 0; k < params->cmdc; k++) {
	W_TYPE_t cmd = params->cmdv[k];
	uint64_t dsize, phy_stripe;
	int mask = 0;

	MPI_Barrier(MPI_COMM_WORLD);

	if (params->cmd_trigger == (k+1))
	    lf_srv_wait(w_srv_pool, lf_servers, params);

	if (rank == 0)
	    printf("\nExecuting %s ...\n", cmd2str(cmd));

	perf_stats_init(&perf_stats);
	ec_perf_init(&node_stat);
	ec_perf_start(&node_stat);
	dsize = 0;

	switch (cmd) {
	case W_T_LOAD:
	case W_T_VERIFY:
	    phy_stripe = 0;
	    while (phy_stripe < stripes)
		do_phy_stripes(&phy_stripe, cmd, params, w_pool, &dsize);
	    dsize *= chunk_sz * data;

	    mask = (cmd == W_T_LOAD)? PERF_STAT_W : PERF_STAT_R;
	    break;
	case W_T_ENCODE:
	case W_T_DECODE:
	    if (params->parities > 2) {
		u8 err_ix_list[16];
		enc_tbl = make_encode_matrix(data, params->parities, &rs_a);
		for (i = 0; i < params->recover; i++)
		    err_ix_list[i] = i;
		dec_tbl = make_decode_matrix(data, params->recover, err_ix_list, (u8 *)rs_a);
	    }
	    phy_stripe = 0;
	    while (phy_stripe < stripes)
		do_phy_stripes(&phy_stripe, cmd, params, w_pool, &dsize);
	    dsize *= chunk_sz * nchunks;

	    mask = (cmd == W_T_ENCODE ? PERF_STAT_ENC : PERF_STAT_REC) | PERF_STAT_W | PERF_STAT_R;
	    if (params->parities > 2) {
		free(enc_tbl);
		free(dec_tbl);
		free(rs_a);
		enc_tbl = NULL;
		dec_tbl = NULL;
		rs_a = NULL;
	    }
	    break;
	default:;
	}

	/* Wait for all jobs done */
	rc = pool_wait_works_done(w_pool, params->cmd_timeout_ms);
	if (rc) {
		err("Command timeout on %s",
		    params->nodelist[params->node_id]);
		node_exit(1);
	}
	ec_perf_add(&node_stat, dsize);

	MPI_Barrier(MPI_COMM_WORLD);

	/* Collect performance statistics from all nodes */
	perf_stats_reduce(&perf_stats, &stats_agg_bw, offsetof(struct ec_perf, data), MPI_SUM);
	perf_stats_reduce(&perf_stats, &stats_agg_bw, offsetof(struct ec_perf, elapsed), MPI_SUM);
	//perf_stats_reduce(&perf_stats, &stats_max_time, offsetof(struct ec_perf, elapsed), MPI_MAX);
	MPI_Reduce(&node_stat.data, &node_stat_agg, 1, MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);
	MPI_Reduce(&node_stat.elapsed, &node_stat_max, 1, MPI_UINT64_T, MPI_MAX, 0, MPI_COMM_WORLD);

	if (rank == 0) {
	    printf("Cmd done: %s time %.3lf ms\n  Aggregated FAM R/W %.3lf GiB, bandwidth %.2lf MiB/S\n",
		cmd2str(cmd), (double)node_stat_max/mSec,
		(double)node_stat_agg/GiB, ((double)node_stat_agg/MiB)/((double)node_stat_max/uSec));
	    perf_stats_print(&stats_agg_bw, offsetof(struct ec_perf, data), mask, "Data, GiB", GiB);
	    perf_stats_print_bw(&stats_agg_bw, mask, "BW per node, MiB/S", uSec*params->w_thread_cnt, MiB);
	    /* Check aggregated data: submitted == actual R/W bytes */
	    dsize = ((mask&PERF_STAT_W) ? stats_agg_bw.lw_bw.data:0) +
		    ((mask&PERF_STAT_R) ? stats_agg_bw.lr_bw.data:0);
	    if ( node_stat_agg != dsize ) {
		err("Data accounting error, actual:%lu submitted:%lu bytes",
			dsize, node_stat_agg);
		node_exit(1);
	    }
	}
    }
    if (rank == 0)
	printf("DONE\n");

    /* Wait all jobs */
    rc = pool_exit(w_pool, 0); /* 0: don't cancel */

exit_srv_thr:
    if (!params->fam_map) {
	pool_exit(w_srv_pool, 0); /* 0: don't cancel */
	for (i = 0; i < srv_cnt; i++)
	    lf_srv_free(lf_servers[i]);
	free(lf_servers);

	MPI_Barrier(MPI_COMM_WORLD);
    }
    if (rc == 0)
	printf("%d: SUCCESS!!!\n", rank);
    else
	printf("%d: ERROR %d\n", rank, rc);

    /* free params->lf_clients and params->stripe_buf */
    free_lf_params(&params);
    node_exit(rc);
    return rc;
}

static void perf_stats_init(PERF_STAT_t *stats) {
	ec_perf_init(&stats->ec_bw);
	ec_perf_init(&stats->rc_bw);
	ec_perf_init(&stats->lw_bw);
	ec_perf_init(&stats->lr_bw);
}

static inline void perf_add_data(struct ec_perf *to, struct ec_perf *from) {
	to->data += from->data;
	to->elapsed += from->elapsed;
}

static inline void perf_stats_add(PERF_STAT_t *to, PERF_STAT_t *from) {
	struct ec_perf *src = (struct ec_perf *)from;
	struct ec_perf *dst = (struct ec_perf *)to;
	int i;

	for (i = 0; i < 4; i++, src++, dst++)
		perf_add_data(dst, src);
}

static void perf_stats_add_locked(PERF_STAT_t *to, PERF_STAT_t *from, pthread_spinlock_t *lock) {
	pthread_spin_lock(lock);
	perf_stats_add(to, from);
	pthread_spin_unlock(lock);
}

static void perf_stats_reduce(PERF_STAT_t *stats, PERF_STAT_t *to, size_t off, MPI_Op op) {
	struct ec_perf *src = (struct ec_perf *)((char*)stats+off);
	struct ec_perf *dst = (struct ec_perf *)((char*)to+off);
	int i;

	for (i = 0; i < 4; i++, src++, dst++)
		MPI_Reduce((void*)src, (void*)dst, 1, MPI_UINT64_T, op, 0, MPI_COMM_WORLD);
}

static void perf_stats_print(PERF_STAT_t *stats, size_t off, int mask, const char *msg, uint64_t units) {
	struct ec_perf *src = (struct ec_perf *)((char*)stats+off);
	int i;

	for (i = 0; i < 4; i++, src++)
		if (1 << i & mask)
			printf("\t %s %s %.3lf\n", PERF_NAME[i], msg, (double)*(uint64_t*)src/units);
}

static void perf_stats_print_bw(PERF_STAT_t *stats, int mask, const char *msg, uint64_t tu, uint64_t bu) {
	struct ec_perf *p = (struct ec_perf *)stats;
	int i;

	for (i = 0; i < 4; i++, p++)
		if (1 << i & mask && p->elapsed)
			printf("\t %s %s %.3lf\n",
				PERF_NAME[i], msg, ((double)p->data/bu)/((double)p->elapsed/tu));
}

static int assign_map_chunk(N_CHUNK_t **chunk_p, N_PARAMS_t *params,
    int extent_n, int chunk_n)
{
	N_CHUNK_t	*chunk;

	chunk = (N_CHUNK_t *)calloc(1, sizeof(N_CHUNK_t));
	if(!chunk)
		return 1;

	chunk->node = chunk_n;
	map_stripe_chunk(chunk, extent_n, params->nchunks, params->parities);

	*chunk_p = chunk;
	return 0;
}

static void do_phy_stripes(uint64_t *stripe, W_TYPE_t op, N_PARAMS_t *params, W_POOL_t* pool, uint64_t *done)
{
    LF_CL_t	**all_clients = params->lf_clients;
    int		node_cnt = params->node_cnt;	/* worker's node count */
    int		node_id = params->node_id;	/* my node */
    int		nchunks = params->nchunks;
    int		fam_cnt = params->fam_cnt;	/* FAM count */
    int		workers = params->w_thread_cnt;
    uint64_t	stripes = params->vmem_sz / params->chunk_sz;
    uint64_t	stripe0 = *stripe;
    uint64_t	batch;
    uint64_t	extent_str = params->extent_sz / params->chunk_sz;
    unsigned int srv_cnt = params->node_servers;
    unsigned int tmo;
    int		j;
    int		fam_idx = 0;

    /* Queuing timeout */
    tmo = params->cmd_timeout_ms / 1000U;
    tmo = (tmo == 0U)? 1:tmo;

    batch = get_batch_stripes(stripes - stripe0, node_cnt * workers);
    /* must check for stripe>stripes if batch is 1 */

    /* Do stripe banches */
    //printf("%s: do_phy_stripes @%lu batch:%ld\n", params->nodelist[node_id], stripe0, batch);
    for (j = 0; j < workers; j++) {
	uint64_t start, end, count;
	unsigned int e, s_extent, e_extent;

	/* Split stripe batch to extents */
	start = stripe0 + batch * (j + workers * node_id);
	if (start >= stripes) {
		ASSERT(batch == 1);
		break;
	}
	count = batch;
	end = start + count - 1;
	s_extent = start / extent_str;
	e_extent = end / extent_str;
	//printf("%s: worker:%d extents:%d..%d\n", params->nodelist[node_id], j, s_extent, e_extent);
	for (e = s_extent; e <= e_extent && count; e++) {
		W_PRIVATE_t *priv = NULL;
		uint64_t j_count, next;
		unsigned int partition;
		int n;

		next = (e + 1) * extent_str;
		/* ceil */
		j_count = next - start;
		if (j_count > count) {
			j_count = count;
			count = 0;
		} else
			count -= j_count;

		priv = (W_PRIVATE_t *)malloc(sizeof(W_PRIVATE_t));
		ASSERT(priv);
		priv->params = params;
		priv->thr_id = -1; /* not set */
		priv->chunks = (N_CHUNK_t **) malloc(nchunks * sizeof(void*));
		/* Allocate the array (per node) of LF client context references */
		priv->lf_clients = (LF_CL_t **) calloc(nchunks, sizeof(void*));
		ASSERT(priv->chunks && priv->lf_clients);
		partition = extent_to_part(e, params->srv_extents);

		/* bunch of stripes belongs to the same extent 'e' */
		priv->bunch.extent = e;
		priv->bunch.phy_stripe = start;
		priv->bunch.stripes = j_count;
		priv->bunch.ext_stripes = extent_str;
                perf_stats_init(&priv->perf_stat);

		/* Setup fabric for extent on each node */
		for (n = 0; n < nchunks; n++) {
			int fam_extent = e;
			/* TODO: Fix FAM allocation */
			int lf_client_idx = to_lf_client_id(fam_idx++, srv_cnt, partition);
			if (fam_idx == fam_cnt)
				fam_idx = 0;

			priv->lf_clients[n] = all_clients[lf_client_idx];
			ASSERT(partition == priv->lf_clients[n]->partition);

			/* Allocate N_CHUNK_t and map chunk to extent */
			ON_ERROR( assign_map_chunk(&priv->chunks[n], params, e, n),
				"Error allocating chunk");

			/* Add dest partition offset? */
			if (params->part_mreg != 0)
			    fam_extent -= partition * params->srv_extents;
			ASSERT(fam_extent >= 0);

			priv->chunks[n]->lf_client_idx = lf_client_idx;
			priv->chunks[n]->p_stripe0_off = fam_extent * params->extent_sz;

			/* FI_MR_VIRT_ADDR? */
			if (params->lf_mr_flags.virt_addr)
				priv->chunks[n]->p_stripe0_off += (off_t) priv->lf_clients[n]->dst_virt_addr;
		}

		/* Queue job */
		if (params->verbose) {
			printf("%s: add_work %s in slab %d for stripes %lu..%lu\n",
				params->nodelist[node_id], cmd2str(op), e, start, start+j_count-1);
		}
		{
			unsigned int t = tmo;
			int rc = pool_add_work(pool, op, priv);

			while(rc && errno == EAGAIN && t) {
				sleep(1);
				rc = pool_add_work(pool, op, priv);
				--t;
			}
    			ON_ERROR(rc, "%s queueing %s work in extent %d",
				t?"Error":"Timeout", cmd2str(op), e);
		}
		*done += j_count;

		start = next;
		if (start >= stripes)
			break;
	}

    }

    /* mark stripes done */
    stripe0 += batch * (node_cnt * workers);
    *stripe = stripe0;
}

/* Select libfabric RMA read or write event counter */
enum cntr_op_ {
	CNTR_OP_R = 0,
	CNTR_OP_W,
};

static inline const char* cntr_op_to_str(enum cntr_op_ op)
{
    switch (op) {
	case CNTR_OP_R:	return "read";
	case CNTR_OP_W:	return "write";
	default:	return "?";
    }
}

static void stripe_io_counter_clear(W_PRIVATE_t *priv, enum cntr_op_ op)
{
    N_PARAMS_t		*params = priv->params;
    int			i, thread_id;

    thread_id = priv->thr_id;
    for (i = 0; i < params->nchunks; i++) {
    	LF_CL_t		*node = priv->lf_clients[i];
	N_CHUNK_t	*chunk = priv->chunks[i];
	struct fid_cntr	*cntr;

	switch (op) {
	case CNTR_OP_R:
		cntr = node->rcnts[thread_id];
		chunk->r_event = fi_cntr_read(cntr);
		//ON_FI_ERROR(fi_cntr_set(cntr, cnt), "cntr set");
		break;
	case CNTR_OP_W:
		cntr = node->wcnts[thread_id];
		chunk->w_event = fi_cntr_read(cntr);;
		//ON_FI_ERROR(fi_cntr_set(cntr, cnt), "cntr set");
		break;
	default:;
	}
    }
#if 0
    uint64_t c;
    int ms_sleep = 10000;
    do {
	c = 0;
	for (i = 0; i < params->nchunks; i++) {
    	    LF_CL_t *node = priv->lf_clients[i];
	    struct fid_cntr *cntr = NULL;

	    switch (op) {
	    case CNTR_OP_R:
		cntr = node->rcnts[thread_id];
		break;
	    case CNTR_OP_W:
		cntr = node->wcnts[thread_id];
		break;
	    default:;
	    }
	    c += fi_cntr_read(cntr);
	}
	if (c)
	    nanosleep((const struct timespec[]){{0, 1000L}}, NULL);
    } while (c && --ms_sleep);
    if (c) {
	fprintf(stderr, "%d/%d fi_cntr_set timeout! node\n", rank, thread_id);
	exit(1);
    }
#endif
}

static int stripe_io_counter_wait(W_PRIVATE_t *priv, enum cntr_op_ op)
{
    N_PARAMS_t		*params = priv->params;
    int			i, thread_id, rc;

    thread_id = priv->thr_id;
    for (i = 0; i < params->nchunks; i++) {
    	LF_CL_t		*node = priv->lf_clients[i];
	N_CHUNK_t	*chunk = priv->chunks[i];
	struct fid_cntr	*cntr;
	uint64_t	*event;

	switch (op) {
	case CNTR_OP_R:
		event = &chunk->r_event;
		cntr = node->rcnts[thread_id];
		break;
	case CNTR_OP_W:
		event = &chunk->w_event;
		cntr = node->wcnts[thread_id];
		break;
	default:
		return 1;
	}
	if (*event == 0)
		continue;

	rc = fi_cntr_wait(cntr, *event, params->io_timeout_ms);
	if (rc == -FI_ETIMEDOUT) {
		printf("%d/%d: Timeout on %s in extent %lu on FAM node %d(p%d) - cnt:%lu/%lu\n",
			rank, thread_id, cntr_op_to_str(op), priv->bunch.extent,
			node->node_id, node->partition,
			fi_cntr_read(cntr), *event);
		return 1;
#if 0
	} else if (rc == -FI_EAVAIL) { /* 259 */
		printf("FI_EAVAIL on %s\n", params->nodelist[chunk_n]);
#endif
	} else if (rc) {
		printf("%d/%d: %lu %s error(s):%d in %s extent %lu on FAM node %d(p%d) - cnt:%lu/%lu\n",
			rank, thread_id, fi_cntr_readerr(cntr), cntr_op_to_str(op),
			rc, params->nodelist[i],
			priv->bunch.extent, node->node_id, node->partition,
			fi_cntr_read(cntr), *event);
		return 1;
	}
   }
   return 0;
}

/* Write one chunk */
static int write_chunk(W_PRIVATE_t *priv, int chunk_n, uint64_t stripe)
{
    LF_CL_t		*node = priv->lf_clients[chunk_n];
    N_CHUNK_t		*chunk = priv->chunks[chunk_n];
    N_PARAMS_t		*params = priv->params;
    fi_addr_t		*tgt_srv_addr;
    struct fid_ep	*tx_ep;
    size_t		transfer_sz, len;
    uint64_t		stripe0;
    off_t		off;
    char		*buf = chunk->lf_buf;
    int			ii, blocks, thread_id;

    thread_id = priv->thr_id;
    ASSERT(thread_id >= 0 && thread_id < params->w_thread_cnt);
    tx_ep = node->tx_epp[thread_id];
    tgt_srv_addr = &node->tgt_srv_addr[thread_id];
    transfer_sz = params->transfer_sz;
    len = params->chunk_sz;
    stripe0 = priv->bunch.extent * priv->bunch.ext_stripes;
    /* fabric destination address */
    //off = chunk->lf_stripe0_off + (stripe - stripe0) * len;
    off = (stripe - stripe0) * len;
    ASSERT( off < params->part_sz );
    off += chunk->p_stripe0_off;
    blocks = len/transfer_sz;

    if (params->verbose) {
	ALLOCA_CHUNK_PR_BUF(pr_buf);

	printf("will write %d blocks of %lu bytes to %s chunk of stripe %lu in FAM node %d(p%d) @%p"
	       " desc:%p mr_key:%lu\n",
		blocks, transfer_sz,
		pr_chunk(pr_buf, chunk->data, chunk->parity), stripe,
		node->node_id, node->partition, (void*)off,
		node->local_desc[thread_id], node->mr_key);
    }

    // Do RMA
    for (ii = 0; ii < blocks; ii++) {
	ON_FI_ERROR(fi_write(tx_ep, buf, transfer_sz, node->local_desc[thread_id], *tgt_srv_addr, off,
			     node->mr_key, (void*)buf /* NULL */),
		    "%d: block:%d fi_write failed on FAM node %d(p%d)",
		    rank, ii, node->node_id, node->partition);
	off += transfer_sz;
	buf += transfer_sz;
	chunk->w_event++;
    }
    return 0;
}

/* Read one chunk */
static int read_chunk(W_PRIVATE_t *priv, int chunk_n, uint64_t stripe)
{
    LF_CL_t		*node = priv->lf_clients[chunk_n];
    N_CHUNK_t		*chunk = priv->chunks[chunk_n];
    N_PARAMS_t		*params = priv->params;
    fi_addr_t		*tgt_srv_addr;
    struct fid_ep	*tx_ep;
    size_t		transfer_sz, len;
    uint64_t		stripe0;
    off_t		off;
    char		*buf = chunk->lf_buf;
    int			ii, blocks, thread_id;

    thread_id = priv->thr_id;
    ASSERT(thread_id >= 0 && thread_id < params->w_thread_cnt);
    tx_ep = node->tx_epp[thread_id];
    tgt_srv_addr = &node->tgt_srv_addr[thread_id];
    transfer_sz = params->transfer_sz;
    len = params->chunk_sz;
    stripe0 = priv->bunch.extent * priv->bunch.ext_stripes;
    /* fabric destination address */
    //off = chunk->lf_stripe0_off + (stripe - stripe0) * len;
    off = (stripe - stripe0) * len;
    ASSERT( off < params->part_sz );
    off += chunk->p_stripe0_off;
    blocks = len/transfer_sz;

    if (params->verbose) {
	ALLOCA_CHUNK_PR_BUF(pr_buf);

	printf("will read %d blocks of %lu bytes from %s chunk of stripe %lu on FAM node %d(p%d) @%ld\n",
		blocks, transfer_sz,
		pr_chunk(pr_buf, chunk->data, chunk->parity), stripe,
		node->node_id, node->partition, off);
    }

    // Do RMA
    for (ii = 0; ii < blocks; ii++) {
	ON_FI_ERROR(fi_read(tx_ep, buf, transfer_sz, node->local_desc[thread_id], *tgt_srv_addr, off,
			    node->mr_key, (void*)buf /* NULL */),
		    "fi_read failed on FAM node %d(p%d)",
		    node->node_id, node->partition);
	off += transfer_sz;
	buf += transfer_sz;
	chunk->r_event++;
    }
    return 0;
}

static void encode_stripe(W_PRIVATE_t *priv) {
    int i, j, k;
    int n = priv->params->nchunks;
    int p = priv->params->parities;
    u8  *dvec[n], *pvec[n];

    if (!p) {
	if (priv->params->verbose && rank == 0)
	    printf("Encode called with 0 parities\n");
	return;
    }
    for (i = 0, j = 0, k = 0; i < n; i++) {
        if (priv->chunks[i]->parity >= 0)
            pvec[k++] = (u8 *)priv->chunks[i]->lf_buf;
        else
            dvec[j++] = (u8 *)priv->chunks[i]->lf_buf;
    }
    ec_perf_start(&priv->perf_stat.ec_bw);
    encode_data(ISAL_CMD, priv->params->chunk_sz, n - p, p, enc_tbl, dvec, pvec);
    ec_perf_add(&priv->perf_stat.ec_bw, priv->params->chunk_sz*n);
}

static void recover_stripe(W_PRIVATE_t *priv) {
    int i, j, k;
    int n = priv->params->nchunks;
    int p = priv->params->parities;
    int r = priv->params->recover;
    u8  *dvec[n], *rvec[r];

    if (!r) {
	if (priv->params->verbose)
            printf("Recover called with 0 buffers\n");
        return;
    }
    ASSERT(r <= p);

    for (i = 0, j = 0, k = 0; i < n; i++) {
	if (priv->chunks[i]->data <= (r - 1) && priv->chunks[i]->data >= 0)
	    rvec[k++] = (u8 *)priv->chunks[i]->lf_buf;
	else
	    dvec[j++] = (u8 *)priv->chunks[i]->lf_buf;
    }

    ec_perf_start(&priv->perf_stat.rc_bw);
    decode_data(ISAL_CMD, priv->params->chunk_sz, n - r, r, dec_tbl, dvec, rvec);
    ec_perf_add(&priv->perf_stat.rc_bw, priv->params->chunk_sz*n);
}

/* Populate stripe with zeros and put LBA to first 8 bytes of every logical block */
static void populate_stripe(W_PRIVATE_t *priv, uint64_t stripe) {
    N_PARAMS_t	*params = priv->params;
    size_t	transfer_sz, chunk_sz;
    uint64_t	block, blocks, lba;
    int		n, i, data;

    transfer_sz = params->transfer_sz;	/* LB size */
    chunk_sz = params->chunk_sz;
    blocks = chunk_sz / transfer_sz;	/* logical blocks per chunk */
    n = params->nchunks;
    data = n - params->parities;
    for (i = 0; i < n; i++) {
	N_CHUNK_t	*chunk = priv->chunks[i];
	char		*buf = chunk->lf_buf;

	if (chunk->data < 0)
	    continue;

	lba = chunk_to_lba(stripe, data, chunk->data, blocks);
	memset(buf, 0, chunk_sz);
	for (block = 0; block < blocks; block++) {
	    *((uint64_t*)buf) = lba++;
	    buf += transfer_sz;
	}
    }
}

/* Return number of blocks in stripe that have data error */
static uint64_t verify_stripe(W_PRIVATE_t *priv, uint64_t stripe) {
    N_PARAMS_t	*params = priv->params;
    size_t	transfer_sz, chunk_sz;
    uint64_t	block, blocks, lba, err = 0;
    int		n, i, data;

    transfer_sz = params->transfer_sz;	/* LB size */
    chunk_sz = params->chunk_sz;
    blocks = chunk_sz / transfer_sz;	/* logical blocks per chunk */
    n = params->nchunks;
    data = n - params->parities;
    for (i = 0; i < n; i++) {
	N_CHUNK_t	*chunk = priv->chunks[i];
	uint64_t	j, *p = (uint64_t*) chunk->lf_buf;
	int		error = 0;

	if (chunk->data < 0)
	    continue;

	lba = chunk_to_lba(stripe, data, chunk->data, blocks);
	for (block = 0; block < blocks; block++) {
	    if (*p != lba)
		error++;
	    p++;
	    for (j = 1; j < transfer_sz/sizeof(*p); j++, p++) {
		if (*p)
			error++;
	    }
	    lba++;
	    // p += transfer_sz/sizeof(*p);
	}
	if (error)
	    err++;
    }
    return err;
}


static void work_free(W_PRIVATE_t *priv)
{
    if (priv == NULL)
	return;

    for (int n = 0; n < priv->params->nchunks; n++) {
	N_CHUNK_t *chunk = priv->chunks[n];

	free(chunk);
    }
    free(priv->chunks);
    free(priv->lf_clients);
    free(priv);
}

static int worker_func(W_TYPE_t cmd, void *arg, int thread_id)
{
    W_PRIVATE_t		*priv = (W_PRIVATE_t *)arg;
    N_PARAMS_t		*params = priv->params;
    N_CHUNK_t		*chunk;
    B_STRIPES_t		*bunch = &priv->bunch;
    uint64_t		stripe, ver_err, ver_errors;
    int			rc = 0, nchunks, i, data;

    nchunks = params->nchunks;
    priv->thr_id = thread_id;
    data = nchunks - params->parities;

    /* Copy reference to the worker's I/O buffer */
    for (i = 0; i < nchunks; i++)
	priv->chunks[i]->lf_buf = params->stripe_buf[thread_id] + i * params->chunk_sz;

    switch (cmd) {
    case W_T_LOAD:
	if (params->verbose) {
		printf("Populate data in %lu stripes @%lu for extent %lu on node %d, chunks: ",
			bunch->stripes, bunch->phy_stripe, bunch->extent, params->node_id);
		for (i = 0; i < nchunks; i++) {
			chunk = priv->chunks[i];
			if (chunk->data >= 0)
				printf("%d:D%d ", i, chunk->data);
		}
		printf("\n");
	}

	stripe_io_counter_clear(priv, CNTR_OP_W);

	for (stripe = bunch->phy_stripe; stripe < (bunch->phy_stripe + bunch->stripes); stripe++)
	{
	    populate_stripe(priv, stripe);

	    /* Write all data chunks of one stripe */
	    ec_perf_start(&priv->perf_stat.lw_bw);
	    for (i = 0; i < nchunks; i++) {
		chunk = priv->chunks[i];
		if (chunk->data >= 0) {
		    /* Read chunk from fabric */
		    rc = write_chunk(priv, i, stripe);
		    if (rc) return rc;
		}
	    }
	    rc = stripe_io_counter_wait(priv, CNTR_OP_W);
	    if (rc) return rc;
	    ec_perf_add(&priv->perf_stat.lw_bw, params->chunk_sz*(unsigned int)data);
	}
	if (params->verbose)
	    printf("%d/%d Write FAM BW %.2f MiB/S\n",
		   rank, thread_id, perf_get_bw(&priv->perf_stat.lw_bw, uSec, MiB));
	break;

    case W_T_VERIFY:
	if (params->verbose) {
		printf("Verifying data in %lu stripes @%lu for extent %lu on node %d, chunks: ",
			bunch->stripes, bunch->phy_stripe, bunch->extent, params->node_id);
		for (i = 0; i < nchunks; i++) {
			chunk = priv->chunks[i];
			if (chunk->data >= 0)
				printf("%d:D%d ", i, chunk->data);
		}
		printf("\n");
	}

	stripe_io_counter_clear(priv, CNTR_OP_R);
	ver_errors = 0;

	for (stripe = bunch->phy_stripe; stripe < (bunch->phy_stripe + bunch->stripes); stripe++)
	{
	    /* Read all data chunks of one stripe */
	    ec_perf_start(&priv->perf_stat.lr_bw);
	    for (i = 0; i < nchunks; i++) {
		chunk = priv->chunks[i];
		if (chunk->data >= 0) {
		    /* Read chunk from fabric */
		    rc = read_chunk(priv, i, stripe);
		    if (rc) return rc;
		}
	    }
	    rc = stripe_io_counter_wait(priv, CNTR_OP_R);
	    if (rc) return rc;
	    ec_perf_add(&priv->perf_stat.lr_bw, params->chunk_sz*(unsigned int)data);

	    ver_err = verify_stripe(priv, stripe);
	    ver_errors += ver_err;
	    if (params->verbose)
		printf("%d: Verify %lu errors in %lu stripe!\n", rank, ver_err, stripe);
	}
	if (params->verbose)
	    printf("%d/%d Read FAM BW %.2f MiB/S\n",
		   rank, thread_id, perf_get_bw(&priv->perf_stat.lr_bw, uSec, MiB));
	if (ver_errors) {
	    err("%d/%d verify errors in %lu stripe(s)!",
		rank, thread_id, ver_errors);
	    rc = 1;
	}
	break;

    case W_T_ENCODE:
	if (params->verbose) {
		printf("Encode %d parities ", params->parities);
		for (i = 0; i < nchunks; i++) {
			chunk = priv->chunks[i];
			if (chunk->parity >= 0)
				printf("%d:P%d ", i, chunk->parity);
		}
		printf("on %lu stripes @%lu for extent %lu on node %d from chunks: ",
			bunch->stripes, bunch->phy_stripe, bunch->extent, params->node_id);
		for (i = 0; i < nchunks; i++) {
			chunk = priv->chunks[i];
			if (chunk->data >= 0)
				printf("%d:D%d ", i, chunk->data);
		}
		printf("\n");
	}

	stripe_io_counter_clear(priv, CNTR_OP_R);
	stripe_io_counter_clear(priv, CNTR_OP_W);

	for (stripe = bunch->phy_stripe; stripe < (bunch->phy_stripe + bunch->stripes); stripe++)
	{
	    /* Encode one stripe */
	    ec_perf_start(&priv->perf_stat.lr_bw);
	    for (i = 0; i < nchunks; i++) {
		chunk = priv->chunks[i];
		if (chunk->data >= 0) {
		    /* Read chunk from fabric */
		    rc = read_chunk(priv, i, stripe);
		    if (rc) return rc;
		}
	    }
	    rc = stripe_io_counter_wait(priv, CNTR_OP_R);
	    if (rc) return rc;
	    ec_perf_add(&priv->perf_stat.lr_bw, params->chunk_sz*(unsigned int)data);

            encode_stripe(priv);

	    ec_perf_start(&priv->perf_stat.lw_bw);
	    for (i = 0; i < nchunks; i++) {
		chunk = priv->chunks[i];
		if (chunk->parity >= 0) {
		    /* Write chunk to fabric */
		    rc = write_chunk(priv, i, stripe);
		    if (rc) return rc;
		}
	    }
	    rc = stripe_io_counter_wait(priv, CNTR_OP_W);
	    if (rc) return rc;
	    ec_perf_add(&priv->perf_stat.lw_bw, params->chunk_sz*(unsigned int)params->parities);
	}
	if (params->verbose)
	    printf("%d/%d Enc/R_FAM/W_FAM BW %.2f\t%.2f\t%.2f MiB/S\n",
		rank, thread_id,
		perf_get_bw(&priv->perf_stat.ec_bw, uSec, MiB),
		perf_get_bw(&priv->perf_stat.lr_bw, uSec, MiB),
		perf_get_bw(&priv->perf_stat.lw_bw, uSec, MiB));
	break;

    case W_T_DECODE:
	/* Recover 'recover' data chunks (D0..) */
	if (params->verbose) {
		printf("Decode %d data chunks: ", params->recover);
		for (i = 0; i < nchunks; i++) {
			chunk = priv->chunks[i];
			if (chunk->data >= 0 && chunk->data < params->recover)
				printf("%d:D%d ", i, chunk->data);
		}
		printf("on %lu stripes starting at %lu for extent %lu on node %d from: ",
			bunch->stripes, bunch->phy_stripe, bunch->extent, params->node_id);
		for (i = 0; i < nchunks; i++) {
			chunk = priv->chunks[i];
			if (chunk->data >= params->recover || chunk->data < 0) {
				if (chunk->data >= 0)
					printf("%d:D%d ", i, chunk->data);
				else
					printf("%d:P%d ", i, chunk->parity);
			}
		}
		printf("\n");
	}

	stripe_io_counter_clear(priv, CNTR_OP_R);
	stripe_io_counter_clear(priv, CNTR_OP_W);

	for (stripe = bunch->phy_stripe; stripe < (bunch->phy_stripe + bunch->stripes); stripe++)
	{
	    /* Dncode one stripe */
	    ec_perf_start(&priv->perf_stat.lr_bw);
	    for (i = 0; i < nchunks; i++) {
		chunk = priv->chunks[i];
		/* read valid data chunks and all parity chunks */
		if (chunk->data >= params->recover || chunk->data < 0) {
		    /* Read chunk from fabric */
		    rc = read_chunk(priv, i, stripe);
		    if (rc) return rc;
		}
	    }
	    rc = stripe_io_counter_wait(priv, CNTR_OP_R);
	    if (rc) return rc;
	    ec_perf_add(&priv->perf_stat.lr_bw,
		params->chunk_sz * (unsigned int)(data - params->recover + params->parities));

	    /* Decode 'recover' data chunks */
            recover_stripe(priv);

	    ec_perf_start(&priv->perf_stat.lw_bw);
	    for (i = 0; i < nchunks; i++) {
		chunk = priv->chunks[i];
		if (chunk->data >= 0 && chunk->data < params->recover) {
		    /* Write recovered chunk to fabric */
		    rc = write_chunk(priv, i, stripe);
		    if (rc) return rc;
		}
	    }
	    rc = stripe_io_counter_wait(priv, CNTR_OP_W);
	    if (rc) return rc;
	    ec_perf_add(&priv->perf_stat.lw_bw, params->chunk_sz*(unsigned int)params->recover);
	}
	if (params->verbose)
	    printf("%d/%d Rec/R_FAM/W_FAM BW %.2f\t%.2f\t%.2f MiB/S\n",
		rank, thread_id,
		perf_get_bw(&priv->perf_stat.rc_bw, uSec, MiB),
		perf_get_bw(&priv->perf_stat.lr_bw, uSec, MiB),
		perf_get_bw(&priv->perf_stat.lw_bw, uSec, MiB));
	break;
    default:
	return 1;
    }

    /* Collect performance statistic */
    perf_stats_add_locked(&perf_stats, &priv->perf_stat, &pstats_lock);

    work_free(priv);
    return rc;
}

/* Fabric server initialization */
static int worker_srv_func(W_TYPE_t cmd, void *arg, int thread_id)
{
    LF_SRV_t *priv = (LF_SRV_t *)arg;

    priv->thread_id = thread_id;

    switch (cmd) {
    case SRV_WK_INIT:
	return lf_srv_init(priv);
    case SRV_WK_TRIGGER:
	if (priv->params->cmd_trigger > 0)
	    return lf_srv_trigger(priv);
	/* fall through */
    default:
	return 1;
    }
}

static int lf_srv_trigger(LF_SRV_t *priv)
{
    N_PARAMS_t		*params = priv->params;
    LF_CL_t		*cl = priv->lf_client;
    int                 err, timeout = params->io_timeout_ms;
    uint64_t		events;

    events = 1;

    /* Sit there till the first RMA access */
 printf("%d:%d waiting...\n", params->node_id, priv->thread_id);
    err = fi_cntr_wait(cl->rcnt, events, timeout);
    if (err == -FI_ETIMEDOUT)
	return 0; /* just fine */
    else if (err) {
	ioerr("srv fi_cntr_wait failed:%d", err);
	return err;
    }

 printf("%d:%d first access!\n", params->node_id, priv->thread_id);
    return 0;
}

static void lf_srv_wait(W_POOL_t* srv_pool, LF_SRV_t **servers, N_PARAMS_t *params)
{
    unsigned int i;
    int rc;

    srv_pool->any_done_only = 1;
    for (i = 0; i < params->node_servers; i++) {
	ON_ERROR( pool_add_work(srv_pool, SRV_WK_TRIGGER, servers[i]),
		"Error queueing LF target access trigger work %u of %u", i, params->node_servers);
    }

    rc = pool_wait_single_work_done(srv_pool, params->cmd_timeout_ms);
    if (rc) {
	err("LF SRV trigger timeout on %s", params->nodelist[params->node_id]);
	node_exit(1);
    }
}

