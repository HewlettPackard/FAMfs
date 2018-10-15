/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef LF_CLIENT_H
#define LF_CLIENT_H

#include <string.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_rma.h>


#define LFSRV_CNT_RMA 0

#define node2lf_mr_pkey(node_id, node_servers, partition) (node_id*node_servers + partition + 1)
#define node2service(base, node_id, part_id) (base + part_id + node_id*100)

#define ON_FI_ERROR(action, msg, ...)       \
    do {                                    \
        int64_t __err;                      \
        if ((__err = (action))) {           \
            printf(#msg ": %ld - %s\n", ## __VA_ARGS__, __err, fi_strerror(-__err)); \
            exit(1);                        \
        }                                   \
    } while (0);

#define ON_ERROR(action, msg, ...)          \
    do {                                    \
        int __err;                          \
        if ((__err = (action))) {           \
            printf(#msg ": %d - %m\n", ## __VA_ARGS__, __err); \
            exit(1);                        \
        }                                   \
    } while (0);

#define    ASSERT(x)    if (!(x))    { printf("%s:%s(%d) " #x "\n", __FILE__, __FUNCTION__, __LINE__); exit(1); }

#define err(str, ...) fprintf(stderr, #str ": %m\n", ## __VA_ARGS__)

#ifndef min
#define min(a,b)			\
    ({	__typeof__ (a) _a = (a);	\
	__typeof__ (b) _b = (b);	\
	_a < _b ? _a : _b; })
#endif /* min */

typedef enum w_type_ {
        W_T_LOAD = 0,
        W_T_ENCODE,
        W_T_DECODE,
        W_T_VERIFY,
        W_T_EXIT,
        W_T_NONE,
} W_TYPE_t;

typedef struct lf_mr_mode_ {
	unsigned int scalable:1;	
	unsigned int local:1;
	unsigned int prov_key:1;
	unsigned int virt_addr:1;
	unsigned int _f:28;
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
	//pthread_spinlock_t pstats_lock;	/* struct perf_stat_ lock */
	//struct perf_stat_  perf_stats;	/* data transfer/encode/decode statistic */
        //unsigned char   *enc_tbl;	/* EC encode table */
        //unsigned char   *dec_tbl;	/* EC decode table */
        //unsigned char   *rs_a;		/* R-S matrix for encode->decode conversion */
        int		cmd_trigger;	/* >0: trigget this command by LF server remote access */
	int		part_mreg;	/* 1: register separate buffer per LF server partition */
	//int		client_only;	/* Run only LF client(s) */

	/* Per node partition array, look at to_lf_client_id() for the index */
	char		**stripe_buf;	/* [0]: stripe buffer */
	LF_CL_t		**lf_clients;	/* LF client per node, partition */
			/* arrays per LF client (node, partition): */
	uint64_t	*mr_prov_keys;	/* provider memory registration key */
	uint64_t	*mr_virt_addrs;	/* MR virtual address */
} N_PARAMS_t;

static inline int to_lf_client_id(int node, unsigned int part_count, unsigned int part) {
    return node * part_count + part;
}

// char** getstrlist(const char *buf, int *count);

static inline const char *cmd2str(W_TYPE_t type)
{
        switch(type) {
        case W_T_LOAD:  return "LOAD";
        case W_T_ENCODE:return "ENCODE";
        case W_T_DECODE:return "DECODE";
        case W_T_VERIFY:return "VERIFY";
        default:        return "Unknown";
        }
}

int str2argv(char *str, char **argv, int argmax);
int arg_parser(int argc, char **argv, N_PARAMS_t **params_p);
void free_lf_clients(N_PARAMS_t **params_p);
int lfs_connect(char *cmd);

#endif /* LF_CLIENT_H */
