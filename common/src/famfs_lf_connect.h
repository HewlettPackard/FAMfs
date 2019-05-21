/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAMFS_LF_CONNECT_H
#define FAMFS_LF_CONNECT_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_ext_zhpe.h>
#include <mpi.h>

#include "famfs_env.h"

#define to_lf_client_id(node, part_count, part) (node*part_count + part)
/* TODO: Remove me */
#define node2lf_mr_pkey(node_id, node_servers, partition) (node_id*node_servers + partition + 1)
#define node2service(base, node_id, part_id) (base + part_id + node_id*100)


typedef struct fam_map_ {
	int	ionode_cnt;		/* IO node count */
	int	total_fam_cnt;		/* Total FAM count */
	int	*node_fams;		/* [node]: <number of FAMs> */
	unsigned long long **fam_ids;	/* [node]->[fam] = <FAM Id> */
} FAM_MAP_t;

typedef struct lf_mr_mode_ {
	unsigned int scalable:1;
	unsigned int basic:1;
	unsigned int local:1;
	unsigned int prov_key:1;
	unsigned int virt_addr:1;
	unsigned int allocated:1;
	unsigned int zhpe_support:1;
	unsigned int _f:25;
} __attribute__((packed)) LF_MR_MODE_t;

typedef struct lf_prg_mode_ {
	unsigned int progress_manual:1;
	unsigned int progress_auto:1;
	unsigned int _f:30;
} __attribute__((packed)) LF_PRG_MODE_t;

/* libfabric client data */
typedef struct lf_cl_ {
	/* Index for including this in a top structure */
	int			node_id;	/* node ID for FAM emulation */
//	struct fi_info		*fi;
	struct fid_fabric	*fabric;
	struct fid_domain	*domain;
//	struct fid_eq		*eq;		/* event queues associated with control operations */

	struct fid_ep		*ep;		/* scalable endpoint */
	struct fid_av		*av;
	struct fid_mr		*mr;		/* memory region */
	uint64_t		mr_key;		/* memory region protection key */
	//fi_addr_t		*srv_addr;
	struct fid_cntr		*rcnt;		/* Srv: RMA counter */
	/* per worker arrays of pointers, size:'size' */
	struct fid_ep		**tx_epp;
	struct fid_cq		**tx_cqq;
	struct fid_ep		**rx_epp;
	struct fid_cq		**rx_cqq;
	struct fid_cntr		**rcnts;
	struct fid_cntr		**wcnts;
	int			*cq_affinity;	/* CQ affinity vector */
	fi_addr_t		*tgt_srv_addr;	/* Endpoint addresses converted to target receive context */
	struct fid_mr		**local_mr;	/* memory region for local buffer registration */
	void			**local_desc;	/* ocal buffer descriptors */

	int			service;	/* remote port number */
	//int			chunk;		/* stripe chunk index: 0:D0... P0... */
	unsigned int		partition;	/* fam (or partition) number served on this node */
	int			free_domain_fl;	/* true: Free fabric, domain and av */
	unsigned long long	fam_id;		/* FAM region ID */
	int			size;		/* Compute: # of workers; IO node: # of contexts or zero */
	uint64_t		dst_virt_addr;	/* remote buffer virtual address */
} LF_CL_t;

typedef struct n_params_ {
	char	    **nodelist;		/* Array of node names; size is .node_cnt */
	char	    **clientlist;	/* LF client only: array of client node names; size is client_cnt */
	char	    *node_name;		/* Node name: the pointer to nodelist or clientlist */
	size_t	    vmem_sz;		/* Size of FAM (single partition) per node, bytes */
	size_t	    chunk_sz;		/* Chunk size, bytes */
	size_t	    extent_sz;		/* Extent size, bytes */
	size_t	    transfer_sz;	/* libfabric I/O transfer (block) size */
	off_t	    part_sz;		/* partition size if srv_extents>0 else vmem_sz */
	uint64_t    cmd_timeout_ms;	/* single command execution timeout, ms */
	uint64_t    io_timeout_ms;	/* I/O block timeout, ms */
	int	    client_cnt;		/* Number of LF client nodes */
	int	    node_cnt;		/* nodelist size */
	int	    node_id;		/* My node index in clientlist if any otherwise in nodelist */
	int	    nchunks;		/* Number of chunks in a stripe */
	int	    parities;		/* Number of parity chunks */
	int	    recover;		/* Number of data chunks to recover */
	int	    w_thread_cnt;	/* Size of working thread pool */
	int	    lf_port;		/* libfabric port number (on node 0) */
	int	    lf_srv_rx_ctx;	/* libfabric: number of SEPs rx contexts on a server */
	LF_MR_MODE_t  lf_mr_flags;	/* libfabric: 1 - use scalable memory registration model */
	LF_PRG_MODE_t lf_progress_flags;/* libfabric: force FI_PROGRESS_AUTO or _MANUAL */
	int	    verbose;		/* debug flag */
	int         multi_domains;	/* 1: Client has to open multiple domains: one per initiator's node */
	int	    verify;		/* 0: Don't fill and verify data buffer */
	int	    set_affinity;	/* set CPU affinity to workers and CQ */
        int         use_cq;             /* use completion queue instead of counters */
	char	    *lf_fabric;		/* libfabric fabric */
	char	    *lf_domain;		/* libfabric domain */
	char	    *prov_name;		/* libfabric provider name */
	unsigned int	srv_extents;	/* number of extents served by one LF SRV */
	unsigned int	node_servers;	/* number of LF servers per node */

	int		cmd_trigger;	/* >0: trigget this command by LF server remote access */
	int		part_mreg;	/* 1: register separate buffer per LF server partition */
	MPI_Comm	mpi_comm;	/* MPI communicator for this node in servers/clients */
	//int		client_only;	/* Run only LF client(s) */

	W_TYPE_t	cmdv[ION_CMD_MAX]; /* parsed commands */
	int		cmdc;		/* parsed command count */

	FAM_MAP_t	*fam_map;	/* Node FAM IDs */
	int		fam_cnt;	/* IO node count */
	void		*fam_buf;	/* IO node: RAM buffer for FAM module emulation */

	/* Per node partition array, look at to_lf_client_id() for the index */
	LF_CL_t		**lf_clients;	/* LF client per node, partition */
			/* arrays per LF client (node, partition): */
	uint64_t	*mr_prov_keys;	/* provider memory registration key */
	uint64_t	*mr_virt_addrs;	/* MR virtual address */

	/* Per worker thread; size: w_thread_cnt */
	char		**stripe_buf;	/* local buffers (if any) or NULLs */
} N_PARAMS_t;

typedef struct lf_srv_ {
	struct n_params_	*params;	/* reference to struct n_params_ */
	LF_CL_t			*lf_client;	/* open libfabric objects to be closed/freed */
	void			*virt_addr;	/* mapped memory buffer */
	size_t			length;		/* FAM address range (length, bytes) */
	int			thread_id;	/* worker's thread id */
} LF_SRV_t;


/* defined in famfs_lf_connect.c */
int lf_clients_init(N_PARAMS_t *params);
int lf_client_init(LF_CL_t *client, N_PARAMS_t *params);
void lf_client_free(LF_CL_t *client);
int lf_servers_init(LF_SRV_t ***lf_servers_p, N_PARAMS_t *params,
    int rank, MPI_Comm mpi_comm);
int lf_srv_init(LF_SRV_t *priv);
void lf_srv_free(LF_SRV_t *priv);
ssize_t lf_check_progress(struct fid_cq *cq, ssize_t *cmp);

/* defined in util.c */
int arg_parser(int argc, char **argv, int verbose, int client_rank_size, N_PARAMS_t **params_p);
void free_lf_params(N_PARAMS_t **params_p);

static inline void lf_clients_free(LF_CL_t **all_clients, int count) {
    for (int i = count-1; i >= 0; i--) {
	if (all_clients[i])
	    lf_client_free(all_clients[i]);
    }
    free(all_clients);
}

static inline uint64_t get_batch_stripes(uint64_t stripes, int servers) {
    uint64_t batch = stripes / (unsigned int)servers;
    return (batch == 0)? 1:batch;
}

static inline unsigned long long fam_id_by_index(FAM_MAP_t *m, int index)
{
    if (m) {
	unsigned long long *ids;
	int ionode, i, idx = 0;

	ids = m->fam_ids[0];
	for (ionode = 0; ionode < m->ionode_cnt; ionode++, ids++)
	    for (i = 0; i < m->node_fams[ionode]; i++, idx++)
		if (idx == index)
		    return ids[i];
    }
    return 0ULL;
}

static inline int fam_node_by_index(FAM_MAP_t *m, int index)
{
    if (m) {
	int ionode, idx;

	for (ionode = idx = 0; ionode < m->ionode_cnt; ionode++) {
	    idx += m->node_fams[ionode];
	    if (index < idx)
		return ionode;
	}
    }
    return -1;
}


/*
 * MPI utils
**/

/* defined in util.c */
int mpi_split_world(MPI_Comm *mpi_comm, int my_role, int zero_role, int gbl_rank, int gbl_size);

static inline int mpi_broadcast_arr64(uint64_t *keys, int size, int rank0)
{
    return MPI_Bcast(keys, size*sizeof(uint64_t), MPI_BYTE, rank0, MPI_COMM_WORLD);
}

#endif /* FAMFS_LF_CONNECT_H */
