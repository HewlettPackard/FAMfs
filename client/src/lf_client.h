/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef LF_CLIENT_H
#define LF_CLIENT_H

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

#define ON_ERROR(action, msg)               \
    do {                                    \
        int __err;                          \
        if ((__err = (action))) {           \
            printf("%s: %d - %m\n", msg, __err); \
            exit(1);                        \
        }                                   \
    } while (0);

#define    ASSERT(x)    if (!(x))    { printf("%s:%s(%d) " #x "\n", __FILE__, __FUNCTION__, __LINE__); exit(1); }

#define err(str, ...) fprintf(stderr, #str "\n", ## __VA_ARGS__)

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
	//pthread_spinlock_t pstats_lock;	/* struct perf_stat_ lock */
	//struct perf_stat_  perf_stats;	/* data transfer/encode/decode statistic */
        //unsigned char   *enc_tbl;	/* EC encode table */
        //unsigned char   *dec_tbl;	/* EC decode table */
        //unsigned char   *rs_a;		/* R-S matrix for encode->decode conversion */

	char		**stripe_buf;	/* [0]: stripe buffer */
	LF_CL_t		**lf_clients;	/* LF client per node, partition */
			/* arrays per LF client (node, partition): */
	uint64_t	*mr_prov_keys;	/* provider memory registration key */
	uint64_t	*mr_virt_addrs;	/* MR virtual address */
} N_PARAMS_t;

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
	//struct perf_stat_	perf_stat;	/* per thread data transfer/encode/decode statistic */
	int			thr_id;		/* worker's thread id */
	/* Arrays of pointers to chunk and libfabric client for this stripe */
	struct n_chunk_		**chunks;	
	struct lf_cl_		**lf_clients; /* array of references */
} W_PRIVATE_t;

typedef struct {
    pthread_mutex_t lck;
    uint64_t        cnt;
    uint64_t        ttl;
    uint64_t        min;
    uint64_t        max;
    uint64_t        bcnt;
    uint64_t        bmin;
    uint64_t        bmax;
    uint64_t        ett;
    uint64_t        emin;
    uint64_t        emax;
} lfio_stats_t;

extern lfio_stats_t        lf_wr_stat;  // libfaric write
extern lfio_stats_t        lf_rd_stat;  // libfaric read
extern lfio_stats_t        md_fg_stat;  // MDHIM file position get
extern lfio_stats_t        md_fp_stat;  // MDHIM file position put
extern lfio_stats_t        md_ag_stat;  // MDHIM file attr get
extern lfio_stats_t        md_ap_stat;  // MDHIM file attr put



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
    return str ? str : strdup(dfl);
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

#define N_XFER_SZ	1*1024*1024L 
#define LFCLN_ITER	1
#define LFSRV_PORT	50666
#define LF_PROV_NAME	"sockets"
#define LFSRV_BUF_SZ	32*1024*1024*1024L
#define	N_PARITY	1
#define N_CHUNK_SZ	1*1024*1024L
#define N_WRK_COUNT	1
#define N_EXTENT_SZ	1*1024*1024*1024L
#define CMD_MAX		16
#define	IO_TIMEOUT_MS	30*1000 /* single I/O execution timeout, 30 sec */
#define LFSRV_RCTX_BITS 8	/* LF SRV: max number of rx contexts, bits */
#define LFSRV_START_TMO 15000	/* the timeout for start all LF servers */
//#define LFS_COMMAND     "-H o186i126 -P0 --memreg scalable --provider 'sockets' --cmd_trigger ENCODE"	/* default configuration command line */
#define LFS_COMMAND     "x -H o186i126 -P0 --memreg scalable --provider sockets ENCODE"	/* default configuration command line */
#define LFS_MAXARGS     64

#define LF_MR_MODEL_SCALABLE	"scalable"
#define LF_MR_MODEL_LOCAL	"local"	/* BASIC and FI_Mr_LOCAL */
#define LF_MR_MODEL_BASIC	"basic" /* FI_MR_ALLOCATED [| FI_MR_PROV_KEY | FI_MR_VIRT_ADDR - not now] */
//#define LF_MR_MODEL	LF_MR_MODEL_BASIC /* Default: local memory registration */
#define LF_MR_MODEL	LF_MR_MODEL_SCALABLE /* Default: local memory registration */

//#define LF_TARGET_RMA_EVENT	/* Require generation of completion events when target of RMA and/or atomics */

#if CKPFS_STATS

#define DUMP_STATS(name, sb) if (do_lf_stats) {\
    char *__ev = getenv("##name");\
    if (!__ev)\
        __ev = name;\
    printf("dumping %s\n", __ev);\
    pthread_mutex_lock(&sb.lck);\
    FILE *__fp = fopen(__ev, "a+");\
    if (__fp) {\
        fprintf(__fp, "%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n", \
                sb.bcnt, sb.ttl, sb.min, sb.max, \
                sb.cnt, sb.bmin, sb.bmax,\
                sb.ett, sb.emin, sb.emax);\
        fclose(__fp);\
    }\
    pthread_mutex_unlock(&sb.lck);\
}

#define UPDATE_STATS(sb, n, s, ts) if (do_lf_stats) {\
    int _n_ = (n), _s_ = (s);\
    uint64_t _e_ = elapsed(&(ts));\
    if (_n_) {\
        pthread_mutex_lock(&sb.lck);\
        sb.bcnt++;\
        sb.cnt += _n_;\
        sb.ttl += _s_;\
        if (_s_ < sb.min || !sb.min)\
           sb.min = _s_;\
        if (_s_ > sb.max)\
            sb.max = _s_;\
        if (_n_ < sb.bmin || !sb.bmin)\
            sb.bmin = _n_;\
        if (_n_ > sb.bmax)\
            sb.bmax = _n_;\
        pthread_mutex_unlock(&sb.lck);\
    }\
    if (_e_) {\
        sb.ett += _e_;\
        if (_e_ < sb.emin || !sb.emin)\
            sb.emin = _e_;\
        if (_e_ > sb.emax)\
            sb.emax = _e_;\
    }\
}

#else
#define DUMP_STATS(name, sb) do {;} while (0);
#define UPDATE_STATS(sb, n, s, ts) do {;} while(0);
#endif

#define LF_WR_STATS_FN  "lf-writes.csv"
#define LF_RD_STATS_FN  "lf-reads.csv"
#define MD_FG_STATS_FN  "md-fget.csv"
#define MD_FP_STATS_FN  "md-fput.csv"
#define MD_AG_STATS_FN  "md-aget.csv"
#define MD_AP_STATS_FN  "md-aput.csv"


int str2argv(char *str, char **argv, int argmax);
int arg_parser(int argc, char **argv, N_PARAMS_t **params_p);
void free_lf_clients(N_PARAMS_t **params_p);
int lfs_connect(char *cmd);

#endif /* LF_CLIENT_H */
