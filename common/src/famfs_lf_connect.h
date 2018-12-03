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

#include "famfs_env.h"

#define part2fam_id(node_id, partitions, part) (node_id*partitions + part)
#if 1 /* TODO: Remove me */
#define node2lf_mr_pkey(node_id, node_servers, partition) (node_id*node_servers + partition + 1)
#else
/* 0: Workaround for old zhpe code that does not accept PROV_KEY from user properly (Sep 29 2018) */
#define node2lf_mr_pkey(node_id, node_servers, partition) (0)
#endif
#define node2service(base, node_id, part_id) (base + part_id + node_id*100)

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

/* libfabric client data */
typedef struct lf_cl_ {
	struct fi_info		*fi;
	struct fid_fabric	*fabric;
	struct fid_domain	*domain;
	struct fid_eq		*eq;		/* event queues associated with control operations */
	struct fid_ep		*ep;		/* scalable endpoint */
	struct fid_av		*av;
	struct fid_mr		*mr;		/* memory region */
	uint64_t		mr_key;		/* memory region protection key */
	fi_addr_t		*srv_addr;
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
	unsigned int		partition;	/* partition number served on this node */
	int			node_id;	/* remote node Id */
	int			size;		/* Compute: # of workers; IO node: # of contexts or zero */
	uint64_t		dst_virt_addr;	/* remote buffer virtual address */
} LF_CL_t;

typedef struct n_params_ {
	char	    **nodelist;		/* Array of node names; size is .node_cnt */
	char	    **clientlist;	/* Array of client node names; size is client_cnt */
	size_t	    vmem_sz;		/* Size of FAM (single partition) per node, bytes */
	size_t	    chunk_sz;		/* Chunk size, bytes */
	size_t	    extent_sz;		/* Extent size, bytes */
	size_t	    transfer_sz;	/* libfabric I/O transfer (block) size */
	off_t	    part_sz;		/* partition size if srv_extents>0 else vmem_sz */
	uint64_t    cmd_timeout_ms;	/* single command execution timeout, ms */
	uint64_t    io_timeout_ms;	/* I/O block timeout, ms */
	int	    node_cnt;		/* Number of nodes */
	int	    client_cnt;		/* Number of nodes */
	int	    node_id;		/* My node index in clientlist if any otherwise in nodelist */
	int	    parities;		/* Number of parity chunks */
	int	    recover;		/* Number of data chunks to recover */
	int	    w_thread_cnt;	/* Size of working thread pool */
	int	    lf_port;		/* libfabric port number (on node 0) */
	int	    lf_srv_rx_ctx;	/* libfabric: number of SEPs rx contexts on a server */
	LF_MR_MODE_t lf_mr_flags;	/* libfabric: 1 - use scalable memory registration model */
	int	    verbose;		/* debug flag */
	int	    set_affinity;	/* set CPU affinity to workers and CQ */
	char	    *prov_name;		/* libfabric provider name */
	char	    *lf_domain;		/* libfabric domain */
	unsigned int	srv_extents;	/* number of extents served by one LF SRV */
	unsigned int	node_servers;	/* number of LF servers per node */

	int		cmd_trigger;	/* >0: trigget this command by LF server remote access */
	int		part_mreg;	/* 1: register separate buffer per LF server partition */
	//int		client_only;	/* Run only LF client(s) */

	W_TYPE_t	cmdv[ION_CMD_MAX]; /* parsed commands */
	int		cmdc;		/* parsed command count */

	/* Per node partition array, look at to_lf_client_id() for the index */
	LF_CL_t		**lf_clients;	/* LF client per node, partition */
			/* arrays per LF client (node, partition): */
	uint64_t	*mr_prov_keys;	/* provider memory registration key */
	uint64_t	*mr_virt_addrs;	/* MR virtual address */

	/* Per worker thread; size: w_thread_cnt */
	char		**stripe_buf;	/* local buffers (if any) or NULLs */
} N_PARAMS_t;


/* defined in famfs_lf_connect.c */
int lf_client_init(LF_CL_t *lf_node, N_PARAMS_t *params);
void lf_client_free(LF_CL_t *client);

/* defined in util.c */
int arg_parser(int argc, char **argv, int verbose, int client_rank_size, N_PARAMS_t **params_p);
void free_lf_params(N_PARAMS_t **params_p);

static inline int to_lf_client_id(int node, unsigned int part_count, unsigned int part) {
    return node * part_count + part;
}

static inline void lf_clients_free(LF_CL_t **all_clients, int count) {
    for (int i = 0; i < count; i++)
	lf_client_free(all_clients[i]);
    free(all_clients);
}

static inline uint64_t get_batch_stripes(uint64_t stripes, int servers) {
    uint64_t batch = stripes / (unsigned int)servers;
    return (batch == 0)? 1:batch;
}

#endif /* FAMFS_LF_CONNECT_H */
