/*
 * Copyright (c) 2017-2019, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <ctype.h>
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
#include "famfs_lf_cqprogress.h"

#include "lf_connect.h"
#include "lf_test.h"
#include "ec_perf.h"
#include "w_pool.h"
#include "mpi_utils.h"


/* If defined: limit send queue depth when CQ is used */
//#define IBV_SQ_WR_DEPTH 0 /* 1..8; 0 - sync I/O */


static int rank, rank_size;

static const char *PERF_NAME[] = { "Write", "Read", 0 };
#define PERF_STAT_W	1
#define PERF_STAT_R	2
#define PERF_NAME_SZ ((int)(sizeof(PERF_NAME)/sizeof(char *)))

static pthread_spinlock_t pstats_lock;	/* struct perf_stat_ lock */
static struct perf_stat_  perf_stats;	/* data transfer/encode/decode statistic */

static int worker_func(W_TYPE_t type, W_PRIVATE_t *priv, int thread_id);
static void work_free(W_PRIVATE_t *priv);
static int do_phy_stripes(uint64_t *stripe, W_TYPE_t op, W_PRIVATE_t *priv,
    int cl_rank, int cl_size, uint64_t *done);

static void perf_stats_init(PERF_STAT_t *stats);
static void perf_stats_reduce(PERF_STAT_t *src, PERF_STAT_t *dst, size_t off, MPI_Op op, MPI_Comm comm);
static void perf_stats_print(PERF_STAT_t *stats, size_t off, int mask, const char *msg, uint64_t units);
static void perf_stats_print_bw(PERF_STAT_t *stats, int mask, const char *msg, uint64_t tu, uint64_t bu);


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

/*
 * Get the number of servers from MPI: srv_size.
 * Return true if srv_size not equal to SRV node count list (-H) size
 * and the list should be expanded.
**/
static int check_srv_cnt(N_PARAMS_t *params, int role_rank, int role_size,
    int zero_srv_rank, int *srv_size_p)
{
    LF_ROLE_t lf_role;
    int rc, realloc_nodelist, srv_size;

    srv_size = -1;
    lf_role = params->clientlist? LF_ROLE_CLT : LF_ROLE_SRV;
    if (lf_role == LF_ROLE_SRV)
	srv_size = role_size;

    /* Broadcast the number of LF servers to all */
    rc = MPI_Bcast(&srv_size, 1, MPI_INT, zero_srv_rank, MPI_COMM_WORLD);
    if (rc != MPI_SUCCESS) {
	err("%d: Failed to broadcast the number of LF servers", rank);
	node_exit(1);
    }
    *srv_size_p = srv_size;

    /* Have to extend the LF server node list 'nodelist'? */
    realloc_nodelist = 0;
    if (!params->fam_map) {
	if (lf_role == LF_ROLE_SRV && rank == zero_srv_rank) {
	    int nchunks = params->nchunks;

	    ASSERT(role_rank == 0);
	    /* Number of servers must me a multiple of 'nchunks' */
	    if (srv_size < nchunks || (srv_size % nchunks != 0)) {
		err("MPI communicator has %d servers" \
		    " but FAM should be emulated with a multiple of %d",
		    srv_size, nchunks);
		node_exit(1);
	    }
	}
	if (srv_size != params->node_cnt)
	    realloc_nodelist = 1;
    }

    return realloc_nodelist;
}

/*
 * Exchange the list of LF server nodes across
 * all ranks in COMM_WORLD:
 * Re-allocate params->nodelist,
 * set params->node_cnt, fam_cnt and node_id.
**/
static int exchange_nodelist(N_PARAMS_t *params, MPI_Comm mpi_comm,
    int role_rank, int role_size, int srv_size, int zero_srv_rank)
{
	LF_ROLE_t lf_role = params->clientlist? LF_ROLE_CLT : LF_ROLE_SRV;
	char **newlist;
	int i, len, rc;

	ASSERT(zero_srv_rank >= 0);
	ASSERT(srv_size);
	len = 0;
	newlist = (char **)malloc(srv_size*sizeof(char*));

	if (lf_role == LF_ROLE_SRV) {
	    ssize_t slen, dlen;
	    size_t xlen;
	    char *p, *endp;
	    int *ids, id;

	    ASSERT(srv_size == role_size);
	    ids = (int *)calloc(srv_size, sizeof(int));

	    /* Strip node # from node_name */
	    p = params->node_name;
	    while (*p && !isdigit(*++p)) ;
	    /* In 'node01-ib' slen,dlen,xlen stand for 'node', '01' and '-ib' length */
	    slen = p - params->node_name;
	    id = (int) strtol(p, &endp, 10);
	    dlen = endp - p;
	    xlen = strlen(endp);
	    ids[role_rank] = id;
	    len = slen + dlen + xlen;
	    ASSERT(len < 16 && len > 1);
	    ASSERT(id >= 0);

	    rc = MPI_Allgather(MPI_IN_PLACE, sizeof(int), MPI_BYTE,
			       ids, sizeof(int), MPI_BYTE, mpi_comm);
	    if (rc != MPI_SUCCESS) {
		err("%d/%d: MPI_Allgather id:%d", role_rank, srv_size, id);
		return rc;
	    }
	    /* TODO: Gather node lengths and abort if it differs */

	    /* Re-create the node list */
	    len++;
	    for (i = 0; i < srv_size; i++) {
		newlist[i] = (char *)malloc(len*sizeof(char));
		sprintf(newlist[i], "%.*s%0*u%.*s",
			(int)slen, params->node_name,
			(int)dlen, ids[i],
			(int)xlen, endp);
	    }
	    params->node_id = role_rank;
	    if (role_rank == 0) {
		printf("Actual libfabric server nodes |");
		for (i = 0; i < srv_size; i++)
		    printf("%s%s", (i>0)?",":"", newlist[i]);
		printf("| (total:%d)\n", srv_size);
	    }
	}

	/* Broadcast new nodelist to all */
	for (i = 0; i < srv_size; i++) {
	    int nlen;

	    rc = MPI_Bcast(&len, 1, MPI_INT, zero_srv_rank, MPI_COMM_WORLD);
	    if (rc != MPI_SUCCESS) {
		err("MPI_Bcast");
		return rc;
	    }
	    nlen = len * sizeof(char);
	    if (lf_role != LF_ROLE_SRV)
		newlist[i] = (char *)malloc(nlen);

	    ASSERT(nlen > 1);
	    rc = MPI_Bcast(newlist[i], nlen, MPI_BYTE, zero_srv_rank, MPI_COMM_WORLD);

	    if (rc != MPI_SUCCESS) {
		err("MPI_Bcast");
		return rc;
	    }
	}

	/* Replace 'nodelist' */
	nodelist_free(params->nodelist, params->node_cnt);
	params->nodelist = newlist;
	params->fam_cnt = srv_size;
	params->node_cnt = srv_size;

	return MPI_SUCCESS;
}

static void work_alloc(W_PRIVATE_t **priv_p, N_PARAMS_t *params)
{
    W_PRIVATE_t *priv;
    int n, nchunks;

    nchunks = params->nchunks;
    priv = (W_PRIVATE_t *)malloc(sizeof(W_PRIVATE_t));
    ASSERT(priv);
    priv->params = params;
    //priv->thr_id = -1; /* not set */
    priv->chunks = (N_CHUNK_t **) malloc(nchunks * sizeof(void*));

    /* Allocate the array (per node) of LF client context references */
    priv->lf_clients = (LF_CL_t **) calloc(nchunks, sizeof(void*));
    ASSERT(priv->chunks && priv->lf_clients);

    for (n = 0; n < nchunks; n++) {
	priv->chunks[n] = (N_CHUNK_t *)calloc(1, sizeof(N_CHUNK_t));
	ASSERT(priv->chunks[n]);
    }

    *priv_p = priv;
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
    N_PARAMS_t		*params = NULL;
    MPI_Comm		mpi_comm = MPI_COMM_NULL;
    LF_ROLE_t		lf_role;
    size_t		chunk_sz;
    int			i, k, node_id, srv_cnt, rc;
    int			nchunks, data, parities;
    int			initialized = 0, provided;
    int			role_rank, role_size;
    int			srv_size, zero_srv_rank, realloc_nodelist;
    uint64_t		stripes, node_stat_max, node_stat_agg;


    ASSERT(sizeof(size_t) == 8);
    ASSERT(sizeof(PERF_STAT_t) == 2*sizeof(struct ec_perf));
    ON_ERROR( pthread_spin_init(&pstats_lock, PTHREAD_PROCESS_SHARED), "pthr spin init");

    rc = MPI_Initialized(&initialized);
    if (rc == MPI_SUCCESS) {
	if (!initialized)
	    rc = MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &provided);
	else
	    rc = MPI_Query_thread(&provided);
    }
    if (rc != MPI_SUCCESS || provided < MPI_THREAD_MULTIPLE) {
	err("MPI_Init failure rc:%d", rc);
	exit(1);
    }
    MPI_Comm_size(MPI_COMM_WORLD, &rank_size);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    /* Parse command */
    if ((rc = arg_parser(argc, argv, (rank == 0), 0, &params))) {
	err("Error parsing command arguments");
	usage(argv[0]);
    }
    if (params->recover || params->parities) {
	err("Stripe should not have a parity! (given: -P%d -R%d)",
	    params->parities, params->recover);
        node_exit(1);
    }

    /* Split COMM_WORLD between LF servers and clients */
    lf_role = params->clientlist? LF_ROLE_CLT : LF_ROLE_SRV;
    zero_srv_rank = mpi_split_world(&mpi_comm, lf_role, LF_ROLE_SRV, rank, rank_size);
    if (mpi_comm == MPI_COMM_NULL) {
	err("%d: Failed to split MPI world on %s", rank, params->node_name);
	node_exit(1);
    }
    ASSERT(zero_srv_rank >= 0);
    MPI_Comm_rank(mpi_comm, &role_rank);
    MPI_Comm_size(mpi_comm, &role_size);

    nchunks = params->nchunks;
    parities = params->parities;
    data = nchunks - parities;
    srv_cnt = params->node_servers;
    chunk_sz = params->chunk_sz;
    stripes = params->vmem_sz / chunk_sz;

    /* Have to expand LF server nodelist? */
    realloc_nodelist = check_srv_cnt(params, role_rank, role_size, \
					 zero_srv_rank, &srv_size);

    if (realloc_nodelist) {
	size_t len = params->fam_cnt * srv_cnt * sizeof(uint64_t);

	/* Exchange new SRV node list; re-allocate params->nodelist */
	rc = exchange_nodelist(params, mpi_comm, role_rank, role_size, \
			srv_size, zero_srv_rank);
	if (rc != MPI_SUCCESS) {
	    err("%d: Failed to exchange the new SRV node list", rank);
	    node_exit(1);
	}

	if (params->mr_prov_keys) {
	    free(params->mr_prov_keys);
	    params->mr_prov_keys = (uint64_t *)malloc(len);
	}
	if (params->mr_virt_addrs) {
	    free(params->mr_virt_addrs);
	    params->mr_virt_addrs = (uint64_t *)malloc(len);
	}
    }

    /* Initialize libfabric */
    node_id = params->node_id;
    if (lf_role == LF_ROLE_SRV) {
	/* Emulate ION FAMs with libfabric targets */
	if (!params->fam_map) {
	    rc = lf_servers_init(&lf_servers, params, role_rank);
	    if (rc) {
		err("Can't start FAM emulation target on %s",
		    params->nodelist[node_id]);
		node_exit(1);
	    }

	    /* Exchange keys */
	    if (params->lf_mr_flags.prov_key) {
		size_t len = srv_cnt * sizeof(uint64_t);

		if ((rc = MPI_Allgather(MPI_IN_PLACE, len, MPI_BYTE,
				params->mr_prov_keys, len, MPI_BYTE, mpi_comm))) {
		    err("MPI_Allgather failed");
		    node_exit(1);
		}
	    }
	    /* Exchange virtual addresses */
	    if (params->lf_mr_flags.virt_addr) {
		size_t len = srv_cnt * sizeof(uint64_t);

		if ((rc = MPI_Allgather(MPI_IN_PLACE, len, MPI_BYTE,
				params->mr_virt_addrs, len, MPI_BYTE, mpi_comm))) {
		    err("MPI_Allgather failed");
		    node_exit(1);
		}
	    }
	}
	if (params->verbose)
	    printf("%d: SRV:%d %s OK\n",
		   rank, params->node_id, params->node_name);
    }

    MPI_Barrier(MPI_COMM_WORLD);

    /* Broadcast LF MR prov_keys and virt_addrs from SRV#0 to all clients */
    if (!params->lf_mr_flags.scalable) {
	int total_parts = params->fam_cnt * srv_cnt;

	rc = mpi_broadcast_arr64(params->mr_prov_keys, total_parts, zero_srv_rank);
	if (rc != MPI_SUCCESS) {
	    err("%d: Failed to broadcast LF PROV_KEYS", rank);
	    node_exit(1);
	}
	rc = mpi_broadcast_arr64(params->mr_virt_addrs, total_parts, zero_srv_rank);
	if (rc != MPI_SUCCESS) {
	    err("%d: Failed to broadcast LF VIRT_ADDRS", rank);
	    node_exit(1);
	}
    }

    /* Init LF clients */
    if (lf_role == LF_ROLE_CLT) {
	if (role_size > LFS_MAXCLIENTS) {
	    err("Too many clients: %d, please check -c [--clientlist]", role_size);
	    node_exit(1);
	}

	if (params->w_thread_cnt != 1) {
	    err("Option ignored: -w");
	    params->w_thread_cnt = 1;
	}

	rc = lf_clients_init(params);
	if (rc) {
	    err("Failed to connect to LF from %s",
		params->clientlist[node_id]);
	    node_exit(1);
	}
	if (params->verbose)
	    printf("%d: CLT:%d %s Ok\n",
		   rank, params->node_id, params->node_name);

	MPI_Barrier(mpi_comm);

	if (role_rank == 0) {
	    printf("LF initiator scalable:%d local:%d basic:%d (prov_key:%d virt_addr:%d allocated:%d)\n",
		   params->lf_mr_flags.scalable, params->lf_mr_flags.local, params->lf_mr_flags.basic,
		   params->lf_mr_flags.prov_key, params->lf_mr_flags.virt_addr, params->lf_mr_flags.allocated);
	}
    }

    MPI_Barrier(MPI_COMM_WORLD);

/*
 * Execute command flow
 */
    if (lf_role == LF_ROLE_CLT) {
	W_PRIVATE_t *priv;

	work_alloc(&priv, params);

	for (k = 0; k < params->cmdc; k++) {
	    W_TYPE_t cmd = params->cmdv[k];
	    uint64_t dsize, phy_stripe;
	    int mask = 0;

	    MPI_Barrier(mpi_comm);

	    if (role_rank == 0)
		printf("\nExecuting %s ...\n", cmd2str(cmd));

	    perf_stats_init(&perf_stats);
	    ec_perf_init(&node_stat);
	    ec_perf_start(&node_stat);
	    dsize = 0;

	    switch (cmd) {
	    case W_T_LOAD:
	    case W_T_VERIFY:
		phy_stripe = 0;
		while (phy_stripe < stripes && rc == 0) {
		    rc = do_phy_stripes(&phy_stripe, cmd, priv,
					role_rank, role_size, &dsize);
		}
		dsize *= chunk_sz * data;

		mask = (cmd == W_T_LOAD)? PERF_STAT_W : PERF_STAT_R;
		break;
	    default:;
	    }

	    ec_perf_add(&node_stat, dsize);

	    MPI_Barrier(mpi_comm);

	    /* Collect performance statistics from all nodes */
	    perf_stats_reduce(&perf_stats, &stats_agg_bw, offsetof(struct ec_perf, data), MPI_SUM, mpi_comm);
	    perf_stats_reduce(&perf_stats, &stats_agg_bw, offsetof(struct ec_perf, elapsed), MPI_SUM, mpi_comm);
	    MPI_Reduce(&node_stat.data, &node_stat_agg, 1, MPI_UINT64_T, MPI_SUM, 0, mpi_comm);
	    MPI_Reduce(&node_stat.elapsed, &node_stat_max, 1, MPI_UINT64_T, MPI_MAX, 0, mpi_comm);

	    if (role_rank == 0) {
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
	work_free(priv);

	if (role_rank == 0)
	    printf("DONE\n");
    }

    MPI_Barrier(MPI_COMM_WORLD);

    if (!params->fam_map && lf_role == LF_ROLE_SRV) {
	for (i = 0; i < srv_cnt; i++)
	    lf_srv_free(lf_servers[i]);
	free(lf_servers);

	MPI_Barrier(mpi_comm);
	if (params->verbose && role_rank == 0)
	    printf("Servers exited\n");
	MPI_Comm_free(&mpi_comm);
    }
    if (rc == 0)
	printf("%d: SUCCESS!!!\n", rank);
    else
	printf("%d: ERROR %d\n", rank, rc);

    /* free params->lf_clients and params->stripe_buf */
    free_lf_params(&params);
    MPI_Barrier(MPI_COMM_WORLD);
    node_exit(rc);
    return rc;
}

static void perf_stats_init(PERF_STAT_t *stats) {
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

	for (i = 0; i < PERF_NAME_SZ; i++, src++, dst++)
		perf_add_data(dst, src);
}

static void perf_stats_add_locked(PERF_STAT_t *to, PERF_STAT_t *from, pthread_spinlock_t *lock) {
	pthread_spin_lock(lock);
	perf_stats_add(to, from);
	pthread_spin_unlock(lock);
}

static void perf_stats_reduce(PERF_STAT_t *stats, PERF_STAT_t *to, size_t off, MPI_Op op, MPI_Comm comm) {
	struct ec_perf *src = (struct ec_perf *)((char*)stats+off);
	struct ec_perf *dst = (struct ec_perf *)((char*)to+off);
	int i;

	for (i = 0; i < PERF_NAME_SZ; i++, src++, dst++)
		MPI_Reduce((void*)src, (void*)dst, 1, MPI_UINT64_T, op, 0, comm);
}

static void perf_stats_print(PERF_STAT_t *stats, size_t off, int mask, const char *msg, uint64_t units) {
	struct ec_perf *src = (struct ec_perf *)((char*)stats+off);
	int i;

	for (i = 0; i < PERF_NAME_SZ; i++, src++)
		if (1 << i & mask)
			printf("\t %s %s %.3lf\n", PERF_NAME[i], msg, (double)*(uint64_t*)src/units);
}

static void perf_stats_print_bw(PERF_STAT_t *stats, int mask, const char *msg, uint64_t tu, uint64_t bu) {
	struct ec_perf *p = (struct ec_perf *)stats;
	int i;

	for (i = 0; i < PERF_NAME_SZ; i++, p++)
		if (1 << i & mask && p->elapsed)
			printf("\t %s %s %.3lf\n",
				PERF_NAME[i], msg, ((double)p->data/bu)/((double)p->elapsed/tu));
}

static int do_phy_stripes(uint64_t *stripe, W_TYPE_t op, W_PRIVATE_t *priv,
    int cl_rank, int cl_size, uint64_t *done)
{
	N_PARAMS_t	*params = priv->params;
	LF_CL_t		**all_clients = params->lf_clients;
	int		nchunks = params->nchunks;
	int		fam_cnt = params->fam_cnt;	/* FAM count */
	uint64_t	stripes = params->vmem_sz / params->chunk_sz;
	uint64_t	stripe0 = *stripe;
	uint64_t	extent_str = params->extent_sz / params->chunk_sz;
	uint64_t	start;
	unsigned int	srv_cnt = params->node_servers;
	unsigned int	extent, partition;
	int		fam_idx = 0;
	int		n, rc = 0;

	/* Map stripes to a client: strided pattern */
	start = stripe0 + cl_rank;
	if (start >= stripes)
		goto _done;

	/* Calculate the extent and partition for this stripe*/
	extent = start / extent_str;
	partition = extent_to_part(extent, params->srv_extents);

	/* bunch of stripes consists just of one */
	priv->bunch.extent = extent;
	priv->bunch.phy_stripe = start;
	priv->bunch.stripes = 1;
	priv->bunch.ext_stripes = extent_str;
	perf_stats_init(&priv->perf_stat);

	/* Setup fabric for extent on each node */
	for (n = 0; n < nchunks; n++) {
		N_CHUNK_t *chunk;
		int fam_extent = extent;
		/* TODO: Fix FAM allocation */
		int lf_client_idx = to_lf_client_id(fam_idx++, srv_cnt, partition);
		if (fam_idx == fam_cnt)
			fam_idx = 0;

		priv->lf_clients[n] = all_clients[lf_client_idx];
		ASSERT(partition == priv->lf_clients[n]->partition);

		/* Map chunk to extent */
		chunk = priv->chunks[n];
		chunk->node = n;
		map_stripe_chunk(chunk, extent, nchunks, params->parities);

		/* Add dest partition offset? */
		if (params->opts.part_mreg != 0)
		    fam_extent -= partition * params->srv_extents;
		ASSERT(fam_extent >= 0);

		priv->chunks[n]->lf_client_idx = lf_client_idx;
		priv->chunks[n]->p_stripe0_off = fam_extent * params->extent_sz;

		/* FI_MR_VIRT_ADDR? */
		if (params->lf_mr_flags.virt_addr)
			priv->chunks[n]->p_stripe0_off += (off_t) priv->lf_clients[n]->dst_virt_addr;
	}

	if (params->verbose) {
		printf("%s: work %s in slab %d for stripe %lu\n",
			params->node_name, cmd2str(op), extent, start);
	}

	/* Actual I/O */
	rc = worker_func(op, priv, 0);
	if (rc == 0)
		*done += 1;

	/* mark stripes done */
_done:
	stripe0 += cl_size;
	*stripe = stripe0;

	return rc;
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
	    if (params->opts.use_cq) {
		chunk->r_event = 0;
	    } else {
		cntr = node->rcnts[thread_id];
		chunk->r_event = fi_cntr_read(cntr);
		//ON_FI_ERROR(fi_cntr_set(cntr, cnt), "cntr set");
	    }
	    break;
	case CNTR_OP_W:
	    if (params->opts.use_cq) {
		chunk->r_event = 0;
	    } else {
		cntr = node->wcnts[thread_id];
		chunk->w_event = fi_cntr_read(cntr);;
		//ON_FI_ERROR(fi_cntr_set(cntr, cnt), "cntr set");
	    }
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
    struct fid_cq	*tx_cq = NULL;
    struct fid_cntr	*cntr = NULL;
    ssize_t		cnt;
    uint64_t		*event, count;
    int			i, thread_id, rc;

    thread_id = priv->thr_id;
    for (i = 0; i < params->nchunks; i++) {
    	LF_CL_t		*node = priv->lf_clients[i];
	N_CHUNK_t	*chunk = priv->chunks[i];

	switch (op) {
	case CNTR_OP_R:
	    if (params->opts.use_cq) {
		tx_cq = node->tx_cqq[thread_id];
	    } else {
		cntr = node->rcnts[thread_id];
	    }
	    event = &chunk->r_event;
	    break;
	case CNTR_OP_W:
	    if (params->opts.use_cq) {
		tx_cq = node->tx_cqq[thread_id];
	    } else {
		cntr = node->wcnts[thread_id];
	    }
	    event = &chunk->w_event;
	    break;
	default:
	    return 1;
	}
	if (*event == 0)
		continue;

	if (params->opts.use_cq) {
	    cnt = *event;
	    /* TODO: Implement timeout */
	    do {
		rc = lf_check_progress(tx_cq, &cnt);
	    } while (rc >= 0 && cnt > 0);
	    if (rc == 0)
		*event = 0;
	} else {
	    rc = fi_cntr_wait(cntr, *event, params->io_timeout_ms);
	}
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
	    int err;
	    if (params->opts.use_cq) {
		count = *event - (unsigned int)cnt;
		err = errno;
	    } else {
		count = fi_cntr_read(cntr);
		err = (int)fi_cntr_readerr(cntr);
	    }
	    printf("%d/%d: %d %s error(s):%d in %s extent %lu on FAM node %d(p%d) - cnt:%lu/%lu\n",
		   rank, thread_id, err, cntr_op_to_str(op),
		   rc, params->nodelist[i],
		   priv->bunch.extent, node->node_id, node->partition,
		   count, *event);
	    return 1;
	}
   }
   return 0;
}

static inline ssize_t fi_write_(struct fid_ep *ep, void *buf, size_t len, void *desc,
    fi_addr_t dest_addr, uint64_t addr, uint64_t key, void *context) {
	return fi_write(ep, buf, len, desc, dest_addr, addr, key, context);
}

/* Write or read one chunk */
static int do_chunk(W_PRIVATE_t *priv, int chunk_n, uint64_t stripe, enum cntr_op_ op)
{
    LF_CL_t		*node = priv->lf_clients[chunk_n];
    N_CHUNK_t		*chunk = priv->chunks[chunk_n];
    N_PARAMS_t		*params = priv->params;
    fi_addr_t		*tgt_srv_addr;
    struct fid_ep	*tx_ep;
    ssize_t	(*fi_rma)(struct fid_ep*, void*, size_t, void*,
			  fi_addr_t, uint64_t, uint64_t, void*);
    size_t		transfer_sz, len;
    uint64_t		stripe0;
    uint64_t		*event, cnt;
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
    off = (stripe - stripe0) * len;
    ASSERT( off < params->part_sz );
    off += chunk->p_stripe0_off;
    blocks = len/transfer_sz;
    fi_rma = (op == CNTR_OP_R)? &fi_read : &fi_write_;
    event = (op == CNTR_OP_R)? &chunk->r_event : &chunk->w_event;

    if (params->verbose) {
	ALLOCA_CHUNK_PR_BUF(pr_buf);

	printf("will %s %d blocks of %lu bytes %s %s chunk of stripe %lu in FAM node %d(p%d) @%p"
	       " desc:%p mr_key:%lu\n",
		cntr_op_to_str(op), blocks, transfer_sz,
		(op == CNTR_OP_R)?"from":"to",
		pr_chunk(pr_buf, chunk->data, chunk->parity), stripe,
		node->node_id, node->partition, (void*)off,
		node->local_desc[thread_id], node->mr_key);
    }

    // Do RMA
    cnt = 0;
    for (ii = 0; ii < blocks; ii++) {
	int rc;

	do {
	    rc = fi_rma(tx_ep, buf, transfer_sz, node->local_desc[thread_id],
			*tgt_srv_addr, off, node->mr_key, (void*)buf /* NULL */);
	    if (rc == 0) {
		off += transfer_sz;
		buf += transfer_sz;
		(*event)++;
	    } else if (rc < 0 && rc != -FI_EAGAIN)
		break;

	    if (params->opts.use_cq) {
#ifdef IBV_SQ_WR_DEPTH
		if (rc == 0 && *event <= IBV_SQ_WR_DEPTH + cnt)
#else
		if (rc == 0)
#endif
		    break;

		/* If we got FI_EAGAIN, check LF progress to free some slot(s) in send queue */
		do {
		    ssize_t cmp = 0;
		    ON_FI_ERROR( lf_check_progress(node->tx_cqq[thread_id], &cmp),
				"lf_check_progress");
		    if (cmp)
			cnt += (unsigned)cmp;
#ifdef IBV_SQ_WR_DEPTH
		} while (*event > IBV_SQ_WR_DEPTH + cnt);
#else
		} while (0);
#endif
	    }
	} while (rc == -FI_EAGAIN);
	ON_FI_ERROR(rc, "%d: block:%d fi_%s failed on FAM node %d(p%d)",
		    rank, ii, cntr_op_to_str(op),
		    node->node_id, node->partition);
    }
    /* Some iops already finished due to the limited send queue depth: cnt */
    ASSERT(cnt <= *event);
    *event -= cnt;

    return 0;
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

static int worker_func(W_TYPE_t cmd, W_PRIVATE_t *priv, int thread_id)
{
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
	    if (params->verify)
		populate_stripe(priv, stripe);

	    /* Write all data chunks of one stripe */
	    ec_perf_start(&priv->perf_stat.lw_bw);
	    for (i = 0; i < nchunks; i++) {
		chunk = priv->chunks[i];
		if (chunk->data >= 0) {
		    /* Read chunk from fabric */
		    rc = do_chunk(priv, i, stripe, CNTR_OP_W);
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
		    rc = do_chunk(priv, i, stripe, CNTR_OP_R);
		    if (rc) return rc;
		}
	    }
	    rc = stripe_io_counter_wait(priv, CNTR_OP_R);
	    if (rc) return rc;
	    ec_perf_add(&priv->perf_stat.lr_bw, params->chunk_sz*(unsigned int)data);

	    if (params->verify) {
		ver_err = verify_stripe(priv, stripe);
		ver_errors += ver_err;
		if (params->verbose)
		    printf("%d: Verify %lu errors in %lu stripe!\n", rank, ver_err, stripe);
	    }
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

    default:
	return 1;
    }

    /* Collect performance statistic */
    perf_stats_add_locked(&perf_stats, &priv->perf_stat, &pstats_lock);

    return rc;
}


