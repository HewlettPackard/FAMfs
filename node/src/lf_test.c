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
#include "famfs_lf_connect.h"
#include "lf_test.h"
#include "ec_perf.h"


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


void split_mpi_world(LF_ROLE_t role, MPI_Comm *mpi_comm)
{
	LF_ROLE_t	*lf_roles;
	MPI_Comm	world_comm, comm = MPI_COMM_NULL;
	MPI_Group	group_all, group;
	int		*ranks, size, i, rc;

	lf_roles = (LF_ROLE_t *) calloc(rank_size, sizeof(int));
	lf_roles[rank] = role;
	rc = MPI_Allgather(MPI_IN_PLACE, sizeof(int), MPI_BYTE,
			   lf_roles, sizeof(int), MPI_BYTE, MPI_COMM_WORLD);
	if (rc != MPI_SUCCESS) {
		err("MPI_Allgather");
		return;
	}
	ranks = (int *) calloc(rank_size, sizeof(int));
	for (i = 0, size = 0; i < rank_size; i++)
		if (lf_roles[i] == role)
			ranks[size++] = i;
	free(lf_roles);

	rc = MPI_Comm_dup(MPI_COMM_WORLD, &world_comm);
	if (rc != MPI_SUCCESS) {
		err("MPI_Comm_dup failed:%d", rc);
		return;
	}
	rc = MPI_Comm_group(world_comm, &group_all);
	if (rc != MPI_SUCCESS) {
		err("MPI_Comm_group failed:%d", rc);
		return;
	}
	rc = MPI_Group_incl(group_all, size, ranks, &group);
	free(ranks);
	if (rc != MPI_SUCCESS) {
		err("MPI_Group_incl failed:%d role:%d size:%d",
		    rc, role, size);
		return;
	}
	rc = MPI_Comm_create(world_comm, group, &comm);
	if (rc != MPI_SUCCESS) {
		err("MPI_Comm_create failed:%d role:%d size:%d",
		    rc, role, size);
		return;
	}
	ASSERT(comm != MPI_COMM_NULL);
	memcpy(mpi_comm, &comm, sizeof(MPI_Comm));
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
    N_PARAMS_t		*params = NULL;
    MPI_Comm		mpi_comm = MPI_COMM_NULL;
    LF_ROLE_t		lf_role;
    size_t		chunk_sz;
    int			i, k, node_id, srv_cnt, rc;
    int			nchunks, data, parities;
    int			initialized = 0, provided;
    int			role_rank, role_size;
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
    split_mpi_world(lf_role, &mpi_comm);
    if (mpi_comm == MPI_COMM_NULL) {
	err("%d: Failed to split MPI world on %s", rank, params->node_name);
	node_exit(1);
    }
    MPI_Comm_rank(mpi_comm, &role_rank);
    MPI_Comm_size(mpi_comm, &role_size);

    nchunks = params->nchunks;
    parities = params->parities;
    data = nchunks - parities;
    node_id = params->node_id;
    srv_cnt = params->node_servers;
    chunk_sz = params->chunk_sz;
    stripes = params->vmem_sz / chunk_sz;

    /* Have to expand LF server nodelist? */
    int realloc_nodelist = 0;
    int *zero_srv_sz = (int *)calloc(rank_size, sizeof(int));
    zero_srv_sz[rank] = -1;
    if (lf_role == LF_ROLE_SRV && \
	!params->fam_map && \
	role_rank == 0)
    {
	/* Number of LF servers must me a multiple of 'nchunks' */
	if (role_size < nchunks || (role_size % nchunks != 0)) {
	    err("MPI communicator has %d servers" \
		" but FAM should be emulated with a multiple of %d",
		role_size, nchunks);
	    node_exit(1);
	}

	/* Have to amend LF server node list 'nodelist' & 'node_id'? */
	if (role_size != params->node_cnt) {
	    realloc_nodelist = 1;
	    zero_srv_sz[rank] = role_size;
	}
    }

    /* Broadcast realloc_nodelist with the number of LF servers to all */
    rc = MPI_Allgather(MPI_IN_PLACE, sizeof(int), MPI_BYTE,
		       zero_srv_sz, sizeof(int), MPI_BYTE, MPI_COMM_WORLD);
    if (rc != MPI_SUCCESS) {
	err("MPI_Allgather");
	node_exit(1);
    }
    int srv_size = 0;
    int zero_srv_rank = -1;
    for (i = 0; i < rank_size; i++) {
	if (zero_srv_sz[i] >= 0) {
	    realloc_nodelist = 1;
	    srv_size = zero_srv_sz[i];
	    zero_srv_rank = i;
	    break;
	}
    }

    if (realloc_nodelist) {
	char **newlist;
	int len;

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
		node_exit(1);
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
		node_exit(1);
	    }
	    nlen = len * sizeof(char);
	    if (lf_role != LF_ROLE_SRV)
		newlist[i] = (char *)malloc(nlen);

	    ASSERT(nlen > 1);
	    rc = MPI_Bcast(newlist[i], nlen, MPI_BYTE, zero_srv_rank, MPI_COMM_WORLD);

	    if (rc != MPI_SUCCESS) {
		err("MPI_Bcast");
		node_exit(1);
	    }
	}

	/* Replace 'nodelist' */
	nodelist_free(params->nodelist, params->node_cnt);
	params->nodelist = newlist;
	params->fam_cnt = srv_size;
	params->node_cnt = srv_size;

	if (!params->lf_mr_flags.scalable) {
	    int fam_cnt = params->fam_cnt;

	    params->mr_prov_keys = (uint64_t *)malloc(srv_cnt*fam_cnt*sizeof(uint64_t));
	    params->mr_virt_addrs = (uint64_t *)malloc(srv_cnt*fam_cnt*sizeof(uint64_t));
	}
    }

    /* Initialize libfabric */
    if (lf_role == LF_ROLE_SRV) {
	/* Emulate ION FAMs with libfabric targets */
	if (!params->fam_map) {
	    rc = lf_servers_init(&lf_servers, params, role_rank, mpi_comm);
	    if (rc) {
		err("Can't start FAM emulation target on %s",
		    params->nodelist[node_id]);
		node_exit(1);
	    }
	}
	if (params->verbose)
	    printf("%d: SRV:%d %s OK\n",
		   rank, params->node_id, params->node_name);
    }

    MPI_Barrier(MPI_COMM_WORLD);

    if (lf_role == LF_ROLE_CLT) {
	/* Standalone: FAM clients */
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

	if (role_size > LFS_MAXCLIENTS) {
	    err("Too many clients: %d, please check -c [--clientlist]", role_size);
	    node_exit(1);;
	}

	priv = (W_PRIVATE_t *)malloc(sizeof(W_PRIVATE_t));
	ASSERT(priv);
	priv->params = params;
	//priv->thr_id = -1; /* not set */
	priv->chunks = (N_CHUNK_t **) malloc(nchunks * sizeof(void*));

	/* Allocate the array (per node) of LF client context references */
	priv->lf_clients = (LF_CL_t **) calloc(nchunks, sizeof(void*));
	ASSERT(priv->chunks && priv->lf_clients);

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
		int fam_extent = extent;
		/* TODO: Fix FAM allocation */
		int lf_client_idx = to_lf_client_id(fam_idx++, srv_cnt, partition);
		if (fam_idx == fam_cnt)
			fam_idx = 0;

		priv->lf_clients[n] = all_clients[lf_client_idx];
		ASSERT(partition == priv->lf_clients[n]->partition);

		/* Allocate N_CHUNK_t and map chunk to extent */
		ON_ERROR( assign_map_chunk(&priv->chunks[n], params, extent, n),
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


