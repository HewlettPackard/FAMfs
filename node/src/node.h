/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef NODE_H
#define NODE_H

#include <string.h>
#include <sys/time.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_rma.h>

#include "ec_perf.h"


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

#define err(str, ...) fprintf(stderr, #str "\n", ## __VA_ARGS__)


/* Performance statistics */
#define PERF_STAT_ENC	1
#define PERF_STAT_REC	2
#define PERF_STAT_W	4
#define PERF_STAT_R	8
typedef struct perf_stat_ {
        struct perf             ec_bw;	/* ISA lib encoding time&data counters */
        struct perf             rc_bw;	/* ISA lib decoding time&data counters */
        struct perf             lw_bw;	/* data transfer from local buffer to FAM */
        struct perf             lr_bw;	/* data transfer to local buffer from FAM */
} PERF_STAT_t;

typedef struct lf_mr_mode_ {
	unsigned int scalable:1;
	unsigned int basic:1;
	unsigned int local:1;
	unsigned int prov_key:1;
	unsigned int virt_addr:1;
	unsigned int allocated:1;
	unsigned int _f:26;
} __attribute__((packed)) LF_MR_MODE_t;

typedef struct n_params_ {
	char	    **nodelist;		/* Array of node names; size is .node_cnt */
	size_t	    vmem_sz;		/* Size of FAM (single partition) per node, bytes */
	size_t	    chunk_sz;		/* Chunk size, bytes */
	size_t	    extent_sz;		/* Extent size, bytes */
	size_t	    transfer_sz;	/* libfabric I/O transfer (block) size */
	off_t	    part_sz;		/* partition size if srv_extents>0 else vmem_sz */
	uint64_t    cmd_timeout_ms;	/* single command execution timeout, ms */
	uint64_t    io_timeout_ms;	/* I/O block timeout, ms */
	int	    node_cnt;		/* Number of nodes */
	int	    node_id;		/* My node index in .nodelist */
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

	pthread_spinlock_t pstats_lock;	/* struct perf_stat_ lock */
	struct perf_stat_  perf_stats;	/* data transfer/encode/decode statistic */
        unsigned char   *enc_tbl;	/* EC encode table */
        unsigned char   *dec_tbl;	/* EC decode table */
        unsigned char   *rs_a;		/* R-S matrix for encode->decode conversion */

	int	    cmd_trigger;	/* >0: trigget this command by LF server remote access */
	int	    part_mreg;		/* 1: register separate buffer per LF server partition */
} N_PARAMS_t;

/* libfabric client data */
typedef struct lf_cl_ {
	struct fi_info		*fi;
	struct fid_fabric	*fabric;
	struct fid_domain	*domain;
	struct fid_eq		*eq;		/* event queues associated with control operations */
	struct fid_ep		*ep;		/* scalable endpoint */
	struct fid_av		*av;
	struct fid_mr		*mr;		/* memory region */
	struct fid_cntr		*rcnt;		/* Srv: RMA counter */
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
	uint64_t		dst_virt_addr;	/* remote buffer virtual address */
} LF_CL_t;

typedef struct lf_srv_ {
	struct n_params_	*params;	/* reference to struct n_params_ */
	LF_CL_t			*lf_client;	/* open libfabric objects to be closed/freed */
	void			*virt_addr;	/* mapped memory buffer */
	size_t			length;		/* FAM address range (length, bytes) */
	int			thread_id;	/* worker's thread id */
} LF_SRV_t;

/* Chunk attributes */
typedef struct n_chunk_ {
	char		*lf_buf;	/* reference to libfabric I/O buffer */
//	const char	*lf_pname;	/* libfabric node name */
//	int		lf_port;	/* libfabric port number */
//	off_t		lf_stripe0_off;	/* libfabric address of [first stripe in] extent */
	off_t		p_stripe0_off;	/* libfabric offset of the first stripe in partition */
	uint64_t	r_event;	/* read transfer complete counter */
	uint64_t	w_event;	/* write transfer complete counter */
	int		parity;		/* parity chunk number (0...) or -1 */
	int		data;		/* data chunk number or -1 */
	int		node;		/* libfabric node index in nodelist */
} N_CHUNK_t;

typedef struct b_stripes_ {
	uint64_t	extent;		/* extent # */
	uint64_t	phy_stripe;	/* physical stripe number */
	uint64_t	l_stripe;	/* logical stripe */
	uint64_t	stripes;	/* stripe count */
	uint64_t	ext_stripes;	/* extent size in stripes */
} B_STRIPES_t;

typedef struct w_private_ {
	struct n_params_	*params;	/* reference to struct n_params_ */
	struct b_stripes_	bunch;		/* bunch of stripes belongs to the same extent */
	struct perf_stat_	perf_stat;	/* per thread data transfer/encode/decode statistic */
	int			thr_id;		/* worker's thread id */
	/* Arrays of pointers to chunk and libfabric client for this stripe */
	struct n_chunk_		**chunks;	
	struct lf_cl_		**lf_clients; /* array of references */
} W_PRIVATE_t;

char** getstrlist(const char *buf, int *count);

static inline size_t _getval(char *name, char *v, size_t df) {
    size_t  val = 0;
    char    *evv, *last;

    if (v) 
        evv = v;
    else
        evv = getenv(name);
    if (evv) {
        val = strtod(evv, &last);
        if (*last) {
            switch (*last) {
            case 'k':
            case 'K':
                val *= 1024;
                break;
            case 'm':
            case 'M':
                val *= 1024*1024;
                break;
            case 'g':
            case 'G':
                val *= 1024*1024*1024L;
                break;
            }
        }
	return val;
    }
    return df;
}

#define getval(name, vstr) _getval("" #name "", vstr, name)

static inline char *_getstr(char *name, char *dfl) {
    char *str =  getenv(name);
    return str ? str : dfl;
}

#define getstr(name) _getstr("" #name "", name)

static inline const char *str_tk(const char *buf, const char *accept)
{
	const char *p;
	size_t l;

	p = strpbrk(buf, accept);
	if (!p) {
		if ((l = strlen(buf)))
			p = buf + l;
	}
	return p;
}

#endif
