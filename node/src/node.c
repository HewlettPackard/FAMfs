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

#define ISAL_USE_AVX2	259
#define ISAL_USE_SSE2	257
#if (HAVE_CPU_FEATURE_AVX2 == 1)
# define ISAL_CMD ISAL_USE_AVX2
#else
# define ISAL_CMD ISAL_USE_SSE2
#endif

#include "node.h"
#include "w_pool.h"
#include "ec_perf.h"

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

#define LF_MR_MODEL_SCALABLE	"scalable"
#define LF_MR_MODEL_LOCAL	"local"	/* FI_MR_LOCAL */
#define LF_MR_MODEL_BASIC	"basic"
//#define LF_MR_MODEL	LF_MR_MODEL_BASIC
#define LF_MR_MODEL	LF_MR_MODEL_SCALABLE /* Default: local memory registration */
//#define MR_MODEL_BASIC_SYM	/* Replace FI_MR_BASIC with (FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_VIRT_ADDR) */

//#define LF_TARGET_RMA_EVENT	/* Require generation of completion events when target of RMA and/or atomics */

#define PR_BUF_SZ	12


#define SRV_WK_INIT	W_T_LOAD
#define SRV_WK_TRIGGER	1

static int rank, rank_size, cmdc;
static W_TYPE_t cmdv[CMD_MAX];
static char **stripe_buf = NULL;	/* per worker array of local buffers */
static char *fam_buf = NULL; 		/* FAM target RAM buffer */

static int lf_srv_init(LF_SRV_t *priv);
static int lf_srv_trigger(LF_SRV_t *priv);
static void lf_srv_wait(W_POOL_t* srv_pool, LF_SRV_t **servers, N_PARAMS_t *params);
static int worker_srv_func(W_TYPE_t type, void *arg, int thread_id);
static int worker_func(W_TYPE_t type, void *params, int thread_id);
static void do_phy_stripes(uint64_t *stripe, W_TYPE_t op, N_PARAMS_t *params, W_POOL_t* pool, LF_CL_t **lf_clients, uint64_t *done);
static int lf_client_init(LF_CL_t *lf_node_p, N_PARAMS_t *params);
static void lf_client_free(LF_CL_t *cl);
static void lf_clients_free(LF_CL_t **lf_clients, int count);
static void perf_stats_init(PERF_STAT_t *stats);
static void perf_stats_reduce(PERF_STAT_t *src, PERF_STAT_t *dst, size_t off, MPI_Op op);
static void perf_stats_print(PERF_STAT_t *stats, size_t off, int mask, const char *msg, uint64_t units);
static void perf_stats_print_bw(PERF_STAT_t *stats, int mask, const char *msg, uint64_t tu, uint64_t bu);

static const char *PERF_NAME[] = { "Enc", "Rec", "Write", "Read", 0 };


#define N_STRLIST_DELIM ","
char** getstrlist(const char *buf, int *count)
{
	char **nodelist;
	const char *p;
	char *node;
	size_t l;
	int i;

	p = buf;
	l = strcspn(p, N_STRLIST_DELIM);
	i = 0;
	while (l) {
		i++;
		p += l;
		if (!*p)
			break;
		l = strcspn(++p, N_STRLIST_DELIM);
	}
	if (i == 0)
		return NULL;

	/* Allocate the nodelist array */
	nodelist = (char **)malloc(i*sizeof(char*));

	i = 0;
	p = buf;
	l = strcspn(p, N_STRLIST_DELIM);
	while (l) {
		node = (char *)malloc(l+1);
		strncpy(node, p, l);
		node[l] = '\0';
		nodelist[i++] = node;
		p += l;
		if (!*p)
			break;
		l = strcspn(++p, N_STRLIST_DELIM);
	}
	*count = i;

	return nodelist;
}

void nodelist_free(char **nodelist, int size) {
	int i;

	for (i = 0; i < size; i++)
		free(nodelist[i]);
	free(nodelist);
}

static int find_my_node(char* const* nodelist, int node_cnt) {
	char *p, *hostname = NULL;
	size_t len;
	int i, idx = -1;

	hostname =(char*) malloc(HOST_NAME_MAX);
	if (!hostname || !gethostname(hostname, HOST_NAME_MAX-1)) {
		hostname[HOST_NAME_MAX-1] = '\0';

		/* Strip domain */
		p = strchr(hostname, '.');
		len = p? (unsigned int)(p - hostname) : strlen(hostname);

		for (i = 0; i < node_cnt; i++) {
			if (!strncmp(hostname, nodelist[i], len)) {
				idx = i;
				break;
			}
		}
	}

	if (idx < 0) {
		struct ifaddrs *ifa;

		ON_ERROR( getifaddrs(&ifa), "Failed to obtain my IPs");
		while (ifa) {
			if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
				struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
				//printf("%s: %s\n", ifa->ifa_name, inet_ntoa(sa->sin_addr));
				char *ina = inet_ntoa(sa->sin_addr);

				for (i = 0; i < node_cnt; i++) {
					if (!strcmp(ina, nodelist[i])) {
						idx = i;
						break;
					}
				}
				if (idx >= 0)
					break;
			}
			ifa = ifa->ifa_next;
		}
	}

	if (idx < 0)
		printf("%d: Cannot find my node %s in node list (-H)!\n",
			rank, hostname?hostname:"?");
	free(hostname);
	return idx;
}

static void alloc_affinity(int **affp, int size, int pos)
{
    int		i, cpu_setsize, *affinity = NULL;

    if (!affp)
	return;

    affinity = (int *) malloc(size * sizeof(int));
    ASSERT(affinity && size);
    cpu_setsize = get_nprocs();
    for (i = 0; i < size; i++)
	affinity[i] = (i*(cpu_setsize/size) + pos) % cpu_setsize;
    *affp = affinity;
}

void node_exit(int rc) {
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

static uint64_t get_batch_stripes(uint64_t stripes, int servers) {
    uint64_t batch = stripes / (unsigned int)servers;
    return (batch == 0)? 1:batch;
}

void usage(const char *name) {
	if (rank) return;
	printf("\nUsage:\n%s <mandatory options> [<more options>] <command> [<command>...]\n"
	    "\t-H |--hostlist <node name list>\n"
	    "\t-P |--parities <number of parity chunks in a stripe>\n"
	    "\t-M |--memory <virtual memory size>\n"
	    "\t-C |--chunk <chunk size>\n"
	    "\t-E |--extent <extent size>\n"
	    "\t-w |--workers <worker thread count>\n"
	    "\t-R |--recover <number of data chunks to recover>\n"
	    "  Optional:\n"
	    "\t-p |--port <libfabric port>\n"
	    "\t-i |--iters <iterations>\n"
	    "\t-t |--transfer <transfer block size>\n"
	    "\t-T |--timeout <I/O timeout>\n"
	    "\t   --provider <libfabric provider name>\n"
	    "\t   --domain <libfabric domain>\n"
	    "\t   --rxctx <number of rx contexts in lf server>\n"
	    "\t   --srv_extents <partition size, in extents>\n"
	    "\t   --cmd_trigger - trigger command execution by LF remote access\n"
	    "\t   --part_mreg <1|0> - 1(default): every partition registers own memory buffer\n"
	    "\t   --memreg basic|local|basic,local|scalable (default:scalable)\n"
	    "\t-a [--affinity]\n"
	    "\t-v [--verbose]\n"
	    "  Command is one of:\n"
	    "\tLOAD - populate data\n"
	    "\tENCODE\n"
	    "\tDECODE\n"
	    "\tVERIFY\n"
	    "\n",
	    name);
}


int main(int argc, char **argv) {
    PERF_STAT_t		stats_agg_bw;
    struct perf		node_stat;
    int			opt, opt_idx = 0;
    char		port[6], **nodelist = NULL;
    int			node_cnt = 0, recover = 0, verbose = 0, cmd_trigger = 0, part_mreg = 1;
    int			provided = -1;
    int			iters = -1, parities = -1, workers = -1, lf_port = -1;
    size_t		vmem_sz = 0, chunk_sz = 0, extent_sz = 0;
    uint64_t            transfer_len = 0; /* transfer [block] size */
    W_TYPE_t		cmd;
    unsigned int	srv_extents = 0; 
    int			initialized = 0, set_affinity = 0, lf_srv_rx_ctx = 0;
    int			lf_mr_scalable, lf_mr_local, lf_mr_basic;
    uint64_t		*mr_prov_keys = NULL, *mr_virt_addrs = NULL;
    char		*lf_provider_name = NULL, *lf_domain = NULL, *memreg = NULL;
    N_PARAMS_t		*params = NULL;
    LF_CL_t		**lf_all_clients = NULL;
    LF_SRV_t		**lf_servers = NULL;
    W_POOL_t		*w_pool, *w_srv_pool = NULL;
    int			i, k, data, node_id, srv_cnt, rc;
    uint64_t		cmd_timeout, io_timeout = 0;
    uint64_t		phy_stripe, stripes, extents;
    uint64_t		node_stat_max, node_stat_agg;


    ASSERT(sizeof(size_t) == 8);
    ASSERT(sizeof(PERF_STAT_t) == 4*sizeof(struct perf));

    rc = MPI_Initialized(&initialized);
    if (rc == MPI_SUCCESS) {
	if (!initialized)
	    rc = MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &provided);
	else
	    rc = MPI_Query_thread(&provided);
    }
    if (rc != MPI_SUCCESS) {
	printf("MPI_Init failure\n");
	exit(1);
    }
    MPI_Comm_size(MPI_COMM_WORLD, &rank_size);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    enum opt_long_ {
	OPT_PROVIDER = 1000,
	OPT_DOMAIN,
	OPT_RXCTX,
	OPT_SRV_EXTENTS,
	OPT_MEMREG,
	OPT_CMD_TRIGGER,
	OPT_PART_MREG,
    };
    static struct option long_opts[] =
    {
	{"affinity",	0, 0, 'a'},
	{"verbose",	0, 0, 'v'},
	{"help",	0, 0, 'h'},
	{"port",	1, 0, 'p'},
	{"iters",	1, 0, 'i'},
	{"transfer",	1, 0, 't'},
	{"timeout",	1, 0, 'T'},
	{"hostlist",	1, 0, 'H'},
	{"parities",	1, 0, 'P'},
	{"recover",	1, 0, 'R'},
	{"memory",	1, 0, 'M'},
	{"chunk",	1, 0, 'C'},
	{"extent",	1, 0, 'E'},
	{"workers",	1, 0, 'w'},
	/* no short option */
	{"provider",	1, 0, OPT_PROVIDER},
	{"domain",	1, 0, OPT_DOMAIN},
	{"rxctx",	1, 0, OPT_RXCTX},
	{"srv_extents",	1, 0, OPT_SRV_EXTENTS},
	{"memreg",	1, 0, OPT_MEMREG},
	{"cmd_trigger",	0, 0, OPT_CMD_TRIGGER},
	{"part_mreg",	1, 0, OPT_PART_MREG},
	{0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "avhp:i:t:T:H:P:R:M:C:E:w:",
	    long_opts, &opt_idx)) != -1)
    {
        switch (opt) {
	    case 0:
		if (long_opts[opt_idx].flag != 0)
		    break;
		printf("option %s", long_opts[opt_idx].name);
		if (optarg)
		    printf(" with arg %s", optarg);
		printf("\n");
		break;
	    case 'p':
		lf_port = getval(LFSRV_PORT, optarg);
		break;
	    case 'i':
		iters = getval(LFCLN_ITER, optarg);
		break;
	    case 't':
		transfer_len = getval(N_XFER_SZ, optarg);
		break;
	    case 'T':
		io_timeout = getval(IO_TIMEOUT_MS, optarg);
		break;
	    case 'H':
		nodelist = getstrlist(optarg, &node_cnt);
		if (!nodelist) {
		    printf("Node name list - bad delimiter!");
		    node_exit(1);
		}
		break;
	    case 'P':
		parities = getval(N_PARITY, optarg);
                break;
	    case 'R':
		recover = atoi(optarg);
                break;
	    case 'M':
		vmem_sz = getval(LFSRV_BUF_SZ, optarg);
		break;
	    case 'C':
		chunk_sz = getval(N_CHUNK_SZ, optarg);
		break;
	    case 'E':
		extent_sz = getval(N_EXTENT_SZ, optarg);
		break;
	    case 'w':
		workers = getval(N_WRK_COUNT, optarg);
		break;
	    case 'a':
		set_affinity++;
		break;
	    case 'v':
		verbose++;
		break;
	    case OPT_PROVIDER:
		lf_provider_name = strdup(optarg);
		break;
	    case OPT_DOMAIN:
		lf_domain = strdup(optarg);
		break;
	    case OPT_RXCTX:
		lf_srv_rx_ctx = atoi(optarg);
		break;
	    case OPT_SRV_EXTENTS:
		srv_extents = strtoul(optarg, NULL, 10);
		break;
	    case OPT_MEMREG:
		memreg = strdup(optarg);
		break;
	    case OPT_CMD_TRIGGER:
		cmd_trigger++;
		break;
            case '?':
	    case OPT_PART_MREG:
		part_mreg = atoi(optarg);
		break;
            case 'h':
            default:
		usage(argv[0]);
		node_exit(1);
        }
    }

    /* Parse command */
    cmdc = 0;
    while (optind < argc) {
	if (cmdc >= CMD_MAX) {
		printf("Warning: extra %d command(s) ignored!\n", argc - optind);
		break;
	}
	for (cmd = 0; cmd < W_T_EXIT; cmd++) {
	    if (!strcmp(argv[optind], cmd2str(cmd))) {
		optind++;
		break;
	    }
	}
	if (cmd == W_T_EXIT) {
	    printf("Unrecognized command:%s\n", argv[optind]);
	    usage(argv[0]);
	    node_exit(1);
	}
	cmdv[cmdc++] = cmd;
    }
    if (cmdc == 0) {
	printf("No command given!\n");
	node_exit(1);
    }

    /* Sanity check */
    ON_ERROR( (node_cnt == 0 || node_cnt > rank_size),
	"Bad node count, please check -H [--hostlist]");

    /* Defaults */
    if (iters < 0)
	iters = getval(LFCLN_ITER, NULL);
    if (parities < 0)
	parities = getval(N_PARITY, NULL);
    if (workers < 0)
	workers = getval(N_WRK_COUNT, NULL);
    if (lf_port < 0)
	lf_port = getval(LFSRV_PORT, NULL);
    sprintf(port, "%5d", lf_port);
    if (lf_provider_name == NULL)
	if ((lf_provider_name = getstr(LF_PROV_NAME)))
		lf_provider_name = strdup(lf_provider_name);
    if (memreg == NULL)
	if ((memreg = getstr(LF_MR_MODEL)))
		memreg = strdup(memreg);
    lf_mr_scalable = strcasecmp(memreg, LF_MR_MODEL_SCALABLE)? 0:1;
    lf_mr_basic = strncasecmp(memreg, LF_MR_MODEL_BASIC, strlen(LF_MR_MODEL_BASIC))? 0:1;
    lf_mr_local = strcasecmp(memreg + lf_mr_basic*(strlen(LF_MR_MODEL_BASIC)+1),
	LF_MR_MODEL_LOCAL)? 0:1;
    if (!transfer_len)
	transfer_len = getval(N_XFER_SZ, NULL);
    if (io_timeout == 0)
	io_timeout = getval(IO_TIMEOUT_MS, NULL);
    if (!vmem_sz)
	vmem_sz = getval(LFSRV_BUF_SZ, NULL);
    if (!chunk_sz)
	chunk_sz = getval(N_CHUNK_SZ, NULL);
    if (!extent_sz)
	extent_sz = getval(N_EXTENT_SZ, NULL);
    data = node_cnt - parities;
    extents = (vmem_sz * node_cnt) / extent_sz;
    stripes = vmem_sz / chunk_sz;
    cmd_timeout = io_timeout * get_batch_stripes(stripes, node_cnt*workers);

    /* Sanity check */
    node_id = find_my_node(nodelist, node_cnt);
    ON_ERROR (node_id < 0, "Cannot find my node in node list (-H)!");

    /* Default: srv_cnt=1 (single partition) */
    if (srv_extents == 0)
	srv_extents = vmem_sz/extent_sz;
    srv_cnt = vmem_sz/extent_sz/srv_extents;

    printf("Running on node:%d (%d)\n", rank, node_id);

    if (rank == 0) {
	unsigned int exts = vmem_sz/extent_sz;

	if (lf_srv_rx_ctx > 0 && lf_mr_scalable == 0) {
	    fprintf(stderr, "Scalable endpoinds not supported when FI_MR_BASIC is required\n");
	    node_exit(1);
	}
	if ( extent_sz % chunk_sz != 0) {
	    fprintf(stderr, "Extent must be multiple of chunks\n");
	    node_exit(1);
	}
	if ( chunk_sz % transfer_len != 0) {
	    fprintf(stderr, "Chunk must be multiple of transfer blocks\n");
	    node_exit(1);
	}
	if ( (stripes*chunk_sz) != vmem_sz ) {
	    fprintf(stderr, "vmem_sz is not divisible by chunk_sz!\n");
	    node_exit(1);
	}
	if (data < parities) {
	    printf("Wrong number of data chunks:%d for %d parity chunks on %d nodes\n",
		data, parities, node_cnt);
	    node_exit(1);
	}
	if (recover < 0 || recover > parities) {
	    fprintf(stderr, "Wrong number of chunks to recover %d parities\n", parities);
	    node_exit(1);
	}
	if (!lf_mr_scalable && !lf_mr_local && !lf_mr_basic) {
	    fprintf(stderr, "Wrong LF memory registration type:%s (expect %s, %s or %s)\n",
		memreg, LF_MR_MODEL_BASIC, LF_MR_MODEL_LOCAL, LF_MR_MODEL_SCALABLE);
	    node_exit(1);
	}
	if (cmd_trigger > cmdc) {
	    err("Wrong command trigger:%d - there is no such command!", cmd_trigger);
	    node_exit(1);
	} 

	printf("Commands: ");
	for (i = 0; i < cmdc; i++)
	    printf("%s%s", (i>0)?",":"", cmd2str(cmdv[i]));
	printf("\n");
	if (cmd_trigger > 0) {
	    printf("\tthis command will be triggered by LF remote access: %s\n",
		cmd2str(cmdv[cmd_trigger-1]));
	}

	printf("Nodelist: ");
	for (i = 0; i < node_cnt; i++)
	    printf("%s%s", (i>0)?",":"", nodelist[i]);
	printf("\n");

	printf("Chunk %dD+%dP=%d %zu bytes\n", data, parities, node_cnt, chunk_sz);
	printf("Number data chunk(s) to recover:%d (starting with chunk 0)\n", recover);
	if (recover || parities)
	    printf("  ISA-L uses %s\n", ISAL_CMD==ISAL_USE_AVX2?"AVX2":"SSE2");
	printf("Extent %zu bytes\n", extent_sz);
	printf("VMEM %zu bytes in %d partition(s) per node\n", vmem_sz, srv_cnt);
	printf("Transfer block size %zu bytes\n", transfer_len);
	printf("libfabric mr_mode:%s%s%s",
	    lf_mr_scalable?LF_MR_MODEL_SCALABLE:(lf_mr_basic?LF_MR_MODEL_BASIC:""),
	    (lf_mr_basic&&lf_mr_local)?",":"",
	    lf_mr_local?LF_MR_MODEL_LOCAL:"");
	printf(" base port:%s\n  number of workers:%d, srv rx ctx:%d, I/O timeout %lu ms\n",
	    port, workers, lf_srv_rx_ctx, io_timeout);
	printf("Command timeout %.1f s\n", cmd_timeout/1000.);
	printf("Iterations: %d\n", iters);

	if (extents*extent_sz != vmem_sz*node_cnt) {
		fprintf(stderr, "Wrong VMEM:%lu, it must be a multiple of extent size (%lu)!\n",
			vmem_sz, extent_sz);
		node_exit(1);
	}
	if (exts % srv_extents) {
		fprintf(stderr, "Wrong srv_extents:%d, extents (%u) must be devisible by it.\n",
			srv_extents, exts);
			node_exit(1);
	}
	printf("Calculated:\n\tPhy extents per node %u, total:%lu\n"
		"\tStripes per extent:%lu, total:%ld\n",
		exts, extents, extent_sz/chunk_sz, stripes);
    }

    params = (N_PARAMS_t*)malloc(sizeof(N_PARAMS_t));
    params->enc_tbl = NULL;
    params->dec_tbl = NULL;
    ON_ERROR( pthread_spin_init(&params->pstats_lock, PTHREAD_PROCESS_SHARED), "pthr spin init");
    params->nodelist = nodelist;
    params->vmem_sz = vmem_sz;
    params->chunk_sz = chunk_sz;
    params->extent_sz = extent_sz;
    params->node_cnt = node_cnt;
    /* TODO: Find my node in nodelist */
    params->node_id = node_id;
    params->parities = parities;
    params->recover = recover;
    params->w_thread_cnt = workers;
    params->transfer_sz = transfer_len;
    params->io_timeout_ms = io_timeout;
    params->cmd_timeout_ms = cmd_timeout;
    params->lf_port = lf_port;
    params->prov_name = lf_provider_name;
    params->lf_domain = lf_domain;

    memset(&params->lf_mr_flags, 0, sizeof(LF_MR_MODE_t));
    if (lf_mr_basic) {
	/* LF_MR_MODEL_BASIC */
#ifdef MR_MODEL_BASIC_SYM
	params->lf_mr_flags.prov_key = 1;
	params->lf_mr_flags.allocated = 1;
	params->lf_mr_flags.virt_addr = 1;
#else
	params->lf_mr_flags.basic = 1;
	/* basic registration is equivalent to FI_MR_VIRT_ADDR, FI_MR_ALLOCATED, and FI_MR_PROV_KEY set to 1 */
	params->lf_mr_flags.prov_key = 1;
	params->lf_mr_flags.allocated = 1;
	params->lf_mr_flags.virt_addr = 1;
#endif
    } else if (lf_mr_scalable)
	params->lf_mr_flags.scalable = 1;
    params->lf_mr_flags.local = lf_mr_local;

    params->verbose = verbose;
    params->set_affinity = set_affinity;
    params->lf_srv_rx_ctx = lf_srv_rx_ctx;
    params->srv_extents = srv_extents;
    params->node_servers = srv_cnt;
    params->part_sz = (off_t)vmem_sz / srv_cnt;
    params->cmd_trigger = cmd_trigger;
    params->part_mreg = part_mreg;

    if (part_mreg == 0)
	ON_ERROR(posix_memalign((void **)&fam_buf, getpagesize(), params->vmem_sz), "srv memory alloc failed");

    if (!lf_mr_scalable) {
	mr_prov_keys = (uint64_t *)malloc(srv_cnt*node_cnt*sizeof(uint64_t));
	mr_virt_addrs = (uint64_t *)malloc(srv_cnt*node_cnt*sizeof(uint64_t));
    }

    lf_servers = (LF_SRV_t **) malloc(srv_cnt*sizeof(void*));
    ASSERT(lf_servers);
    size_t part_length = params->vmem_sz / srv_cnt;
    for (i = 0; i < srv_cnt; i++) {
	LF_CL_t *cl;

	lf_servers[i] = (LF_SRV_t *) malloc(sizeof(LF_SRV_t));
	lf_servers[i]->params = params;
	lf_servers[i]->length = part_length;
	lf_servers[i]->virt_addr = NULL;
	cl = (LF_CL_t*) calloc(1, sizeof(LF_CL_t));
	cl->partition = i;
	cl->service = node2service(params->lf_port, node_id, i);
	if (set_affinity)
	    alloc_affinity(&cl->cq_affinity, srv_cnt, i + 1);
	lf_servers[i]->lf_client = cl;
    }

    w_srv_pool = pool_init(srv_cnt, &worker_srv_func, lf_servers[0]->lf_client->cq_affinity);
    if (w_srv_pool == NULL) {
	err("Error initializing LF server threads");
	node_exit(1);
    }
    for (i = 0; i < srv_cnt; i++) {
	ON_ERROR( pool_add_work(w_srv_pool, SRV_WK_INIT, lf_servers[i]),
		"Error queueing LF target init work %u of %u", i, srv_cnt);
    }

    /* Wait for all LF servers started */
    rc = pool_wait_works_done(w_srv_pool, LFSRV_START_TMO);
    if (rc) {
	err("LF SRV start timeout on %s", params->nodelist[params->node_id]);
	node_exit(1);
    }
    if (rank == 0) {
	printf("LF target local:%d basic:%d (prov_key:%d virt_addr:%d allocated:%d)\n",
		params->lf_mr_flags.local, params->lf_mr_flags.basic,
		params->lf_mr_flags.prov_key, params->lf_mr_flags.virt_addr, params->lf_mr_flags.allocated);
    }

    MPI_Barrier(MPI_COMM_WORLD);

    /* Exchange keys */
    if (params->lf_mr_flags.prov_key) {
	size_t len = srv_cnt * sizeof(uint64_t);

	for (i = 0; i < srv_cnt; i++)
	    mr_prov_keys[srv_cnt * node_id + i] = lf_servers[i]->lf_client->mr_key;

	ON_ERROR( MPI_Allgather(/* &mr_prov_keys[srv_cnt*node_id] */ MPI_IN_PLACE, len, MPI_BYTE,
				mr_prov_keys, len, MPI_BYTE, MPI_COMM_WORLD),
		 "MPI_Allgather");
    }
    /* Exchange virtual addresses */
    if (params->lf_mr_flags.virt_addr) {
	size_t len = srv_cnt * sizeof(uint64_t);

	/* For each partition */
	for (i = 0; i < srv_cnt; i++)
	    mr_virt_addrs[srv_cnt * node_id + i] = (uint64_t) lf_servers[i]->virt_addr;

	ON_ERROR( MPI_Allgather(MPI_IN_PLACE, len, MPI_BYTE,
				mr_virt_addrs, len, MPI_BYTE, MPI_COMM_WORLD),
		 "MPI_Allgather");
    }

    /* Pre-allocate LF client worker's private data buffers */
    stripe_buf = (char **)malloc(workers * sizeof(void*));
    ASSERT(stripe_buf);
    int psize = getpagesize();
    for (i = 0; i < workers; i++) {
	/* Stripe I/O buffer */
	ON_ERROR(posix_memalign((void **)&stripe_buf[i], psize,
				params->chunk_sz * params->node_cnt),
		 "chunk memory alloc failed");
	if (params->lf_mr_flags.allocated)
	    mlock(stripe_buf[i], params->chunk_sz * params->node_cnt);
    }

    /* Allocate one LF_CL_t structure per FAM partition */
    lf_all_clients = (LF_CL_t **)malloc(node_cnt * srv_cnt * sizeof(void*));
    ASSERT(lf_all_clients);
    /* Setup fabric for each node */
    for (i = 0; i < node_cnt; i++) {
	for (int part = 0; part < srv_cnt; part++) {
	    LF_CL_t *cl;

	    cl = (LF_CL_t *) malloc(sizeof(LF_CL_t));
	    ASSERT(cl);
	    cl->node_id = i;
	    cl->partition = (unsigned int)part;
	    if (params->lf_mr_flags.prov_key)
		cl->mr_key = mr_prov_keys[srv_cnt * i + part];
	    /* FI_MR_VIRT_ADDR? */
	    if (params->lf_mr_flags.virt_addr) {
		if (params->part_mreg == 0)
		    cl->dst_virt_addr = (uint64_t)fam_buf;
		else
		    cl->dst_virt_addr = (uint64_t)mr_virt_addrs[srv_cnt * i + part];
	    }

	    /* Create tx contexts per working thread (w_thread_cnt) */
	    ON_ERROR( lf_client_init(cl, params), 
		     "Error in libfabric client init");
	    lf_all_clients[i*srv_cnt+part] = cl;

	}
    }
    if (rank == 0) {
	printf("LF initiator local:%d basic:%d (prov_key:%d virt_addr:%d allocated:%d)\n",
		params->lf_mr_flags.local, params->lf_mr_flags.basic,
		params->lf_mr_flags.prov_key, params->lf_mr_flags.virt_addr, params->lf_mr_flags.allocated);
    }

    if (params->set_affinity && rank == 0) {
	printf("Set CQ and worker affinity: ");
	for (i = 0; i < params->w_thread_cnt; i++)
		printf("%d ", lf_all_clients[0]->cq_affinity[i]);
	printf("\n");
    } 

    w_pool = pool_init(params->w_thread_cnt, &worker_func, lf_all_clients[0]->cq_affinity);
    if (w_pool == NULL) {
	printf("Error initializing worker pool\n");
	rc = 1;
	goto exit_srv_thr;
    }

/*
 * Execute command flow
 */
    for (k = 0; k < cmdc; k++) {
	uint64_t dsize;
	int mask = 0;

	MPI_Barrier(MPI_COMM_WORLD);

	if (cmd_trigger == (k+1))
	    lf_srv_wait(w_srv_pool, lf_servers, params);

	cmd = cmdv[k];
	if (rank == 0 /* && params->verbose */)
	    printf("\nExecuting %s ...\n", cmd2str(cmd));

	perf_stats_init(&params->perf_stats);
	perf_init(&node_stat);
	perf_start(&node_stat);
	dsize = 0;

	switch (cmd) {
	case W_T_LOAD:
	case W_T_VERIFY:
	    phy_stripe = 0;
	    while (phy_stripe < stripes)
		do_phy_stripes(&phy_stripe, cmd, params, w_pool, lf_all_clients, &dsize);
	    dsize *= chunk_sz * data;

	    mask = (cmd == W_T_LOAD)? PERF_STAT_W : PERF_STAT_R;
	    break;
	case W_T_ENCODE:
	case W_T_DECODE:
	    if (params->parities > 2) {
		u8 err_ix_list[16];
		params->enc_tbl = make_encode_matrix(node_cnt - params->parities, params->parities, &params->rs_a);
		for (i = 0; i < params->recover; i++)
		    err_ix_list[i] = i;
		params->dec_tbl = make_decode_matrix(node_cnt - params->parities, params->recover, err_ix_list, (u8 *)params->rs_a);
	    }
	    phy_stripe = 0;
	    while (phy_stripe < stripes)
		do_phy_stripes(&phy_stripe, cmd, params, w_pool, lf_all_clients, &dsize);
	    dsize *= chunk_sz * (data + parities);

	    mask = (cmd == W_T_ENCODE ? PERF_STAT_ENC : PERF_STAT_REC) | PERF_STAT_W | PERF_STAT_R;
	    if (params->parities > 2) {
		free(params->enc_tbl);
		free(params->dec_tbl);
		params->enc_tbl = NULL;
		params->dec_tbl = NULL;
		free(params->rs_a);
	    }
	    break;
	default:;
	}

	/* Wait for all jobs done */
	rc = pool_wait_works_done(w_pool, params->cmd_timeout_ms);
	if (rc) {
		fprintf(stderr, "Command timeout on %s\n",
			params->nodelist[params->node_id]);
		node_exit(1);
	}
	perf_add(&node_stat, dsize);

	MPI_Barrier(MPI_COMM_WORLD);

	/* Collect performance statistics from all nodes */
	perf_stats_reduce(&params->perf_stats, &stats_agg_bw, offsetof(struct perf, data), MPI_SUM);
	perf_stats_reduce(&params->perf_stats, &stats_agg_bw, offsetof(struct perf, elapsed), MPI_SUM);
	//perf_stats_reduce(&params->perf_stats, &stats_max_time, offsetof(struct perf, elapsed), MPI_MAX);
	MPI_Reduce(&node_stat.data, &node_stat_agg, 1, MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);
	MPI_Reduce(&node_stat.elapsed, &node_stat_max, 1, MPI_UINT64_T, MPI_MAX, 0, MPI_COMM_WORLD);

	if (rank == 0) {
	    printf("Cmd done: %s time %.3lf ms\n  Aggregated FAM R/W %.3lf GiB, bandwidth %.2lf MiB/S\n",
		cmd2str(cmd), (double)node_stat_max/mSec,
		(double)node_stat_agg/GiB, ((double)node_stat_agg/MiB)/((double)node_stat_max/uSec));
	    perf_stats_print(&stats_agg_bw, offsetof(struct perf, data), mask, "Data, GiB", GiB);
	    perf_stats_print_bw(&stats_agg_bw, mask, "BW per node, MiB/S", uSec*workers, MiB);
	    /* Check aggregated data: submitted == actual R/W bytes */
	    dsize = ((mask&PERF_STAT_W) ? stats_agg_bw.lw_bw.data:0) +
		    ((mask&PERF_STAT_R) ? stats_agg_bw.lr_bw.data:0);
	    if ( node_stat_agg != dsize ) {
		fprintf(stderr, "Data accounting error, actual:%lu submitted:%lu bytes\n",
			dsize, node_stat_agg);
		node_exit(1);
	    }
	}
    }
    if (rank == 0)
	printf("DONE\n");

    /* Wait all jobs */
    rc = pool_exit(w_pool, 0); /* 0: don't cancel */
    lf_clients_free(lf_all_clients, params->node_cnt * params->node_servers);
    for (i = 0; i < params->w_thread_cnt; i++) {
	if (params->lf_mr_flags.allocated)
	    munlock(stripe_buf[i], params->chunk_sz * params->node_cnt);
	free(stripe_buf[i]);
    }
    free(stripe_buf);

exit_srv_thr:
    pool_exit(w_srv_pool, 0); /* 0: don't cancel */
    for (i = 0; i < srv_cnt; i++) {
	LF_CL_t *cl = lf_servers[i]->lf_client;

	lf_client_free(cl);
	free(lf_servers[i]->virt_addr);
    	free(lf_servers[i]);
    }
    free(fam_buf);
    free(lf_servers);

    MPI_Barrier(MPI_COMM_WORLD);
    if (rc == 0)
	printf("%d: SUCCESS!!!\n", rank);
    else
	printf("%d: ERROR %d\n", rank, rc);

    nodelist_free(nodelist, node_cnt);
    free(lf_provider_name);
    free(lf_domain);
    free(memreg);
    free(mr_prov_keys);
    free(mr_virt_addrs);
    free(params);
    node_exit(rc);
    return rc;
}

static void perf_stats_init(PERF_STAT_t *stats) {
	perf_init(&stats->ec_bw);
	perf_init(&stats->rc_bw);
	perf_init(&stats->lw_bw);
	perf_init(&stats->lr_bw);
}

static inline void perf_add_data(struct perf *to, struct perf *from) {
	to->data += from->data;
	to->elapsed += from->elapsed;
}

static inline void perf_stats_add(PERF_STAT_t *to, PERF_STAT_t *from) {
	struct perf *src = (struct perf *)from;
	struct perf *dst = (struct perf *)to;
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
	struct perf *src = (struct perf *)((char*)stats+off);
	struct perf *dst = (struct perf *)((char*)to+off);
	int i;

	for (i = 0; i < 4; i++, src++, dst++)
		MPI_Reduce((void*)src, (void*)dst, 1, MPI_UINT64_T, op, 0, MPI_COMM_WORLD);
}

static void perf_stats_print(PERF_STAT_t *stats, size_t off, int mask, const char *msg, uint64_t units) {
	struct perf *src = (struct perf *)((char*)stats+off);
	int i;

	for (i = 0; i < 4; i++, src++)
		if (1 << i & mask)
			printf("\t %s %s %.3lf\n", PERF_NAME[i], msg, (double)*(uint64_t*)src/units);
}

static void perf_stats_print_bw(PERF_STAT_t *stats, int mask, const char *msg, uint64_t tu, uint64_t bu) {
	struct perf *p = (struct perf *)stats;
	int i;

	for (i = 0; i < 4; i++, p++)
		if (1 << i & mask)
			printf("\t %s %s %.3lf\n",
				PERF_NAME[i], msg, ((double)p->data/bu)/((double)p->elapsed/tu));
}

static inline char* pr_chunk(char *buf, int d, int p) {
	if (d >= 0)
		snprintf(buf, PR_BUF_SZ, "D%d", d);
	else if (p >= 0)
		snprintf(buf, PR_BUF_SZ, "P%d", p);
	else
		sprintf(buf, "???");
	return buf;
}

/*
 * Calculate chunk's logical block number in given stripe.
 * Where blocks - number of blocks per chunk.
 **/
static inline uint64_t chunk_to_lba(uint64_t stripe, int data, int chunk, uint64_t blocks)
{
	return (stripe * (unsigned int)data + (unsigned int)chunk) * blocks;
}

/* Get partition number by extent */
static inline unsigned int extent_to_part(unsigned int e, unsigned int srv_extents) {
	return srv_extents? (e / srv_extents) : 0;
}

static int assign_map_chunk(N_CHUNK_t **chunk_p, N_PARAMS_t *params,
    int extent_n, unsigned int part, int chunk_n)
{
	N_CHUNK_t	*chunk;
	int		e, p, node_cnt;

	node_cnt = params->node_cnt;
	chunk = (N_CHUNK_t *)calloc(1, sizeof(N_CHUNK_t));
	if(!chunk)
		return 1;

	chunk->node = chunk_n;
	/* p = (chunk_n - extent_n) mod node_cnt */
	p = (chunk_n - extent_n) % node_cnt;
	p = (p < 0)? (p + node_cnt) : p;
	if (p < params->parities) {
		chunk->parity = p;
		chunk->data = -1;
	} else {
		chunk->data = p - params->parities;
		ASSERT(chunk->data >= 0 && chunk->data < (node_cnt - params->parities));
		chunk->parity = -1;
	}
	//chunk->lf_stripe0_off = extent_n * params->extent_sz;
	e = extent_n - part * params->srv_extents;
	ASSERT(e >= 0);
	chunk->p_stripe0_off = e * params->extent_sz;

	*chunk_p = chunk;
	return 0;
}

static void do_phy_stripes(uint64_t *stripe, W_TYPE_t op, N_PARAMS_t *params, W_POOL_t* pool,
    LF_CL_t **all_clients, uint64_t *done)
{
    int		node_cnt = params->node_cnt;
    int		node_id = params->node_id;
    int		workers = params->w_thread_cnt;
    uint64_t	stripes = params->vmem_sz / params->chunk_sz;
    uint64_t	stripe0 = *stripe;
    uint64_t	batch;
    uint64_t	extent_str = params->extent_sz / params->chunk_sz;
    unsigned int srv_cnt = params->node_servers;
    unsigned int tmo;
    int		j;

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
		priv->chunks = (N_CHUNK_t **) malloc(node_cnt * sizeof(void*));
		/* Allocate the array (per node) of LF client context references */
		priv->lf_clients = (LF_CL_t **) calloc(node_cnt, sizeof(void*));
		ASSERT(priv->chunks && priv->lf_clients);
		partition = extent_to_part(e, params->srv_extents);

		/* bunch of stripes belongs to the same extent 'e' */
		priv->bunch.extent = e;
		priv->bunch.phy_stripe = start;
		priv->bunch.stripes = j_count;
		priv->bunch.ext_stripes = extent_str;
                perf_stats_init(&priv->perf_stat);

		/* Setup fabric for extent on each node */
		for (n = 0; n < node_cnt; n++) {
			priv->lf_clients[n] = all_clients[n*srv_cnt + partition];
			ASSERT(partition == priv->lf_clients[n]->partition);

			/* Allocate N_CHUNK_t and map chunk to extent */
			ON_ERROR( assign_map_chunk(&priv->chunks[n], params, e, partition, n),
				"Error allocating chunk");

			/* FI_MR_VIRT_ADDR? */
			if (params->lf_mr_flags.virt_addr)
				priv->chunks[n]->p_stripe0_off += (off_t) priv->lf_clients[n]->dst_virt_addr;

			/* Add dest partition offset */
			if (params->part_mreg == 0)
				priv->chunks[n]->p_stripe0_off += (params->vmem_sz / srv_cnt) * partition;
		}

		/* Queue job */
		if (params->verbose) {
			printf("%s: add_work %s in extent %d for stripes %lu..%lu\n",
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

static int lf_client_init(LF_CL_t *lf_node, N_PARAMS_t *params)
{
    struct fi_info      *hints, *fi;
    struct fid_fabric   *fabric;
    struct fid_domain   *domain;
    struct fid_mr       *mr;
    struct fid_ep       *ep = NULL;
    struct fi_av_attr   av_attr;
    struct fid_av       *av;
    fi_addr_t           *srv_addr;
    struct fi_cq_attr   cq_attr;
    struct fi_tx_attr	tx_attr;
    static struct fi_cntr_attr cntr_attr = {
	.events = FI_CNTR_EVENTS_COMP,
	.flags = 0
    };
    struct fid_ep	**tx_epp;
    struct fid_cq	**tx_cqq;
    struct fid_cntr	**rcnts, **wcnts;
    fi_addr_t		*tgt_srv_addr;
    struct fid_mr	**local_mr = NULL;
    void		**local_desc;

    char		port[6] = { 0 };
    int			node, partition_id, thread_cnt, service;
    int			*cq_affinity = NULL;
    const char		*pname;
    int			i, rc;

    node = lf_node->node_id;
    partition_id = lf_node->partition;
    thread_cnt = params->w_thread_cnt;
    service = node2service(params->lf_port, node, partition_id);
    sprintf(port, "%5d", service);

    // Provider discovery
    hints = fi_allocinfo();
    hints->caps                 = FI_RMA;
    if (params->lf_srv_rx_ctx)
	hints->caps		|= FI_NAMED_RX_CTX;
    hints->mode                 = FI_CONTEXT;

    if (params->lf_mr_flags.scalable)
	hints->domain_attr->mr_mode = FI_MR_SCALABLE;
    else if (params->lf_mr_flags.basic)
	hints->domain_attr->mr_mode = FI_MR_BASIC;
    else {
	if (params->lf_mr_flags.allocated)
	    hints->domain_attr->mr_mode |= FI_MR_ALLOCATED;
	if (params->lf_mr_flags.prov_key)
	    hints->domain_attr->mr_mode |= FI_MR_PROV_KEY;
	if (params->lf_mr_flags.virt_addr)
	    hints->domain_attr->mr_mode |= FI_MR_VIRT_ADDR;
    }
    if (params->lf_mr_flags.local)
	hints->domain_attr->mr_mode |= FI_MR_LOCAL;

    // hints->domain_attr->threading = FI_THREAD_ENDPOINT; /* FI_THREAD_FID */
    hints->ep_attr->type        = FI_EP_RDM;
    free(hints->fabric_attr->prov_name);
    hints->fabric_attr->prov_name = strdup(params->prov_name);
    if (params->lf_domain) {
	free(hints->domain_attr->name);
	hints->domain_attr->name = strdup(params->lf_domain);
    }

    pname = params->nodelist[node];
    rc  = fi_getinfo(FI_VERSION(1, 5), pname, port, 0, hints, &fi);
    if (rc != FI_SUCCESS) {
	fprintf(stderr, "%d node:%d part:%d cannot connect to %s:%s\n",
		rank, node, partition_id, pname, port);
	ON_FI_ERROR(rc, "fi_getinfo failed");
    }
    fi_freeinfo(hints);
    if (fi->next) {
	/* TODO: Add 'domain' option */
	fprintf(stderr, "Ambiguous initiator provider:%s in domains %s and %s\n",
		fi->fabric_attr->prov_name, fi->domain_attr->name, fi->next->domain_attr->name);
	ON_ERROR(1, "lf_client_init failed");
    }

    /* Query provider capabilities */
    if (fi->domain_attr->mr_mode & FI_MR_PROV_KEY)
	params->lf_mr_flags.prov_key = 1;
    if (fi->domain_attr->mr_mode & FI_MR_LOCAL)
	params->lf_mr_flags.local = 1;
    if (fi->domain_attr->mr_mode & FI_MR_VIRT_ADDR)
	params->lf_mr_flags.virt_addr = 1;
    if (fi->domain_attr->mr_mode & FI_MR_ALLOCATED)
	params->lf_mr_flags.allocated = 1;

    // Create fabric object
    ON_FI_ERROR(fi_fabric(fi->fabric_attr, &fabric, NULL), "fi_fabric failed");

    // Check support for scalable endpoint
    if (fi->domain_attr->max_ep_tx_ctx > 1) {
	size_t min_ctx =
		min(fi->domain_attr->tx_ctx_cnt, fi->domain_attr->rx_ctx_cnt);
	ON_ERROR((unsigned int)thread_cnt > min_ctx,
		"Maximum number of requested contexts exceeds provider limitation");
    } else {
	fprintf(stderr, "Provider %s (in %s) doesn't support scalable endpoints\n",
		fi->fabric_attr->prov_name, pname);
	ON_ERROR(1, "lf_client_init failed");
    }

    // Create domain object
    ON_FI_ERROR(fi_domain(fabric, fi, &domain, NULL),
		"%d: cannot connect to node %d (p%d) port %d - fi_domain failed",
		rank, node, partition_id, service);

    // Create address vector bind to endpoint and event queue
    memset(&av_attr, 0, sizeof(av_attr));
    av_attr.type = FI_AV_MAP;
    //av_attr.type = FI_AV_UNSPEC;
    av_attr.rx_ctx_bits = LFSRV_RCTX_BITS;
    av_attr.ep_per_node = (unsigned int)thread_cnt;
    ON_FI_ERROR(fi_av_open(domain, &av_attr, &av, NULL), "fi_av_open failed");

    // Create endpoint
    if (params->lf_srv_rx_ctx) {
	/* scalable endpoint */
	fi->caps |= FI_NAMED_RX_CTX;
	ON_FI_ERROR(fi_scalable_ep(domain, fi, &ep, NULL), "fi_scalable_ep failed");
	ON_FI_ERROR(fi_scalable_ep_bind(ep, &av->fid, 0), "fi_scalable_ep_bind failed");
    }

    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.format = FI_CQ_FORMAT_TAGGED;
    cq_attr.size = 100;
    cq_attr.wait_obj = FI_WAIT_UNSPEC;
    //cq_attr.wait_cond = FI_CQ_COND_NONE;
    if (params->set_affinity) {
	alloc_affinity(&cq_affinity, thread_cnt, node + 2);
	cq_attr.flags = FI_AFFINITY;
    }

    tx_attr = *fi->tx_attr;
    tx_attr.comp_order = FI_ORDER_NONE;
 //   tx_attr.op_flags = FI_COMPLETION;

    /* per worker --> */
    tx_epp = (struct fid_ep **) malloc(thread_cnt * sizeof(void*));
    tx_cqq = (struct fid_cq **) malloc(thread_cnt  * sizeof(void*));
    ASSERT(tx_epp && tx_cqq);
    rcnts = (struct fid_cntr **) malloc(thread_cnt * sizeof(void*));
    wcnts = (struct fid_cntr **) malloc(thread_cnt * sizeof(void*));
    ASSERT(rcnts && wcnts);
    local_desc = (void **) calloc(thread_cnt, sizeof(void*));

    /* Register the local buffers */
    if (params->lf_mr_flags.local) {
	local_mr = (struct fid_mr **) malloc(thread_cnt * sizeof(void*));
	ASSERT(local_mr);
	for (i = 0; i < thread_cnt; i++) {
	    ON_FI_ERROR( fi_mr_reg(domain, stripe_buf[i], params->chunk_sz * params->node_cnt,
				FI_READ|FI_WRITE, 0, i, 0, &mr, NULL),
				//FI_READ|FI_WRITE, 0, i, FI_RMA_EVENT, &mr, NULL),
		    	"fi_mr_reg failed");
	    local_mr[i] = mr;
	}
#if 1
	/* Wait until registration is completed */ 
	int tmo = 3; /* 3 sec */
	for (i = 0; i < thread_cnt; i++) {
	    mr = local_mr[i];
	    uint64_t mr_key = fi_mr_key(mr);
	    while (tmo-- && mr_key == FI_KEY_NOTAVAIL) {
		mr_key = fi_mr_key(mr);
		sleep(1);
	    }
	    if (mr_key == FI_KEY_NOTAVAIL) {
		fprintf(stderr, "%d/%d: Memory registration has not completed, partition:%d\n",
			rank, node, partition_id);
		ON_FI_ERROR(FI_KEY_NOTAVAIL, "fi_mr_key failed");
	    }
	}
#endif
	/* Get local descriptors */
	for (i = 0; i < thread_cnt; i++)
	    local_desc[i] = fi_mr_desc(local_mr[i]);
    }

    for (i = 0; i < thread_cnt; i++) {
	if (params->lf_srv_rx_ctx) {
	    /* scalable endpoint */

	    // Create independent transmitt queues
	    ON_FI_ERROR(fi_tx_context(ep, i, &tx_attr, &tx_epp[i], NULL), "fi_tx_context failed");
	} else {
	    /* non-scalable endpoint */
	    ON_FI_ERROR(fi_endpoint(domain, fi, &tx_epp[i], NULL),
			"%d: cannot create endpoint #%d for node %d (p%d) - fi_endpoint failed",
			rank, i, node, partition_id);
	    ON_FI_ERROR(fi_ep_bind(tx_epp[i], &av->fid, 0), "fi_ep_bind failed");
	}

	// Create counters
	ON_FI_ERROR(fi_cntr_open(domain, &cntr_attr, &rcnts[i], NULL), "fi_cntr_open r failed");
	ON_FI_ERROR(fi_cntr_open(domain, &cntr_attr, &wcnts[i], NULL), "fi_cntr_open w failed");

#if 1
	// Create completion queues
	if (params->set_affinity)
	    cq_attr.signaling_vector = cq_affinity[i];

	ON_FI_ERROR(fi_cq_open(domain, &cq_attr, &tx_cqq[i], NULL), "fi_cq_open failed");

	// Bind completion queues to endpoint
	ON_FI_ERROR(fi_ep_bind(tx_epp[i], &tx_cqq[i]->fid, FI_TRANSMIT | FI_SELECTIVE_COMPLETION),
		    "fi_ep_bind tx context failed");
#endif

	// Bind counters to endpoint
	ON_FI_ERROR(fi_ep_bind(tx_epp[i], &rcnts[i]->fid, FI_READ),  "fi_ep_bind r cnt failed");
	ON_FI_ERROR(fi_ep_bind(tx_epp[i], &wcnts[i]->fid, FI_WRITE),  "fi_ep_bind w cnt failed");

	ON_FI_ERROR(fi_enable(tx_epp[i]), "fi_enable tx_ep failed");
    }
    /* <-- (per worker) */

    // Enable endpoint
    if (params->lf_srv_rx_ctx)
	ON_FI_ERROR(fi_enable(ep), "fi_enale failed");

    // Perform address translation
    srv_addr = (fi_addr_t *)malloc(sizeof(fi_addr_t));
    ASSERT(srv_addr);
    if (1 != (i = fi_av_insert(av, fi->dest_addr, 1, srv_addr, 0, NULL))) {
        printf("ft_av_insert failed, returned %d\n", i);
        return 1;
    }

    tgt_srv_addr = (fi_addr_t *)malloc(thread_cnt * sizeof(fi_addr_t));
    ASSERT(tgt_srv_addr);
    /* Convert endpoint address to target receive context */
    for (i = 0; i < thread_cnt; i++) {
	if (params->lf_srv_rx_ctx) {
	    tgt_srv_addr[i] = fi_rx_addr(*srv_addr, i % params->lf_srv_rx_ctx, LFSRV_RCTX_BITS);
	    ON_FI_ERROR( tgt_srv_addr[i] == FI_ADDR_NOTAVAIL, "FI_ADDR_NOTAVAIL");
	} else
	    tgt_srv_addr[i] = *srv_addr;
    }

    lf_node->fi = fi;
    lf_node->fabric = fabric;
    lf_node->domain = domain;
    lf_node->ep = ep;
    lf_node->av = av;
    lf_node->tx_epp = tx_epp;
    lf_node->tx_cqq = tx_cqq;
    lf_node->rcnts = rcnts;
    lf_node->wcnts = wcnts;
    lf_node->srv_addr = srv_addr;
    lf_node->tgt_srv_addr = tgt_srv_addr;
    lf_node->local_mr = local_mr;
    lf_node->local_desc = local_desc;
    lf_node->size = thread_cnt;
    if (!params->lf_mr_flags.prov_key)
	lf_node->mr_key = node2lf_mr_pkey(node, params->node_servers, partition_id);
    lf_node->cq_affinity = cq_affinity;
    lf_node->service = service;

    /* not used on active RMA side */
    lf_node->eq = NULL;
    lf_node->rx_epp = NULL;
    lf_node->rx_cqq = NULL;
    lf_node->mr = NULL;
    lf_node->rcnt = NULL;

    if (params->verbose)
	printf("%d CL attached to node %d(p%d) on %s:%s mr_key:%lu\n",
		rank, node, partition_id, pname, port, lf_node->mr_key);

    return 0;
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
    for (i = 0; i < params->node_cnt; i++) {
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
	for (i = 0; i < params->node_cnt; i++) {
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
    for (i = 0; i < params->node_cnt; i++) {
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
		printf("%d/%d: Timeout on %s in extent %lu (p%d) node %d cnt:%lu/%lu\n",
			rank, thread_id, cntr_op_to_str(op), priv->bunch.extent,
			node->partition,
			i, fi_cntr_read(cntr), *event);
		return 1;
#if 0
	} else if (rc == -FI_EAVAIL) { /* 259 */
		printf("FI_EAVAIL on %s\n", params->nodelist[chunk_n]);
#endif
	} else if (rc) {
		printf("%d/%d: %lu %s error(s):%d on %s extent %lu (p%d) cnt:%lu/%lu\n",
			rank, thread_id, fi_cntr_readerr(cntr), cntr_op_to_str(op),
			rc, params->nodelist[i],
			priv->bunch.extent, node->partition,
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
	char pr_buf[PR_BUF_SZ];

	printf("will write %d blocks of %lu bytes to %s chunk of stripe %lu on %s p%d @%p desc:%p\n",
		blocks, transfer_sz,
		pr_chunk(pr_buf, chunk->data, chunk->parity), stripe,
		params->nodelist[chunk_n], node->partition, (void*)off, node->local_desc[thread_id]);
    }

    // Do RMA
    for (ii = 0; ii < blocks; ii++) {
	ON_FI_ERROR(fi_write(tx_ep, buf, transfer_sz, node->local_desc[thread_id], *tgt_srv_addr, off,
			     node->mr_key, (void*)buf /* NULL */),
		    "%d: block:%d fi_write failed on %s (p%d)",
		    rank, ii, params->nodelist[chunk_n], node->partition);
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
	char pr_buf[PR_BUF_SZ];

	printf("will read %d blocks of %lu bytes from %s chunk of stripe %lu on %s p%d @%ld\n",
		blocks, transfer_sz,
		pr_chunk(pr_buf, chunk->data, chunk->parity), stripe,
		params->nodelist[chunk_n], node->partition, off);
    }

    // Do RMA
    for (ii = 0; ii < blocks; ii++) {
	ON_FI_ERROR(fi_read(tx_ep, buf, transfer_sz, node->local_desc[thread_id], *tgt_srv_addr, off,
			    node->mr_key, (void*)buf /* NULL */),
		    "fi_read failed");
	off += transfer_sz;
	buf += transfer_sz;
	chunk->r_event++;
    }
    return 0;
}

static void encode_stripe(W_PRIVATE_t *priv) {
    int i, j, k;
    int n = priv->params->node_cnt;
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
    perf_start(&priv->perf_stat.ec_bw);
    encode_data(ISAL_CMD, priv->params->chunk_sz, n - p, p, priv->params->enc_tbl, dvec, pvec);
    perf_add(&priv->perf_stat.ec_bw, priv->params->chunk_sz*n);
}

static void recover_stripe(W_PRIVATE_t *priv) {
    int i, j, k;
    int n = priv->params->node_cnt;
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

    perf_start(&priv->perf_stat.rc_bw);
    decode_data(ISAL_CMD, priv->params->chunk_sz, n - r, r, priv->params->dec_tbl, dvec, rvec);
    perf_add(&priv->perf_stat.rc_bw, priv->params->chunk_sz*n);
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
    n = params->node_cnt;
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
    n = params->node_cnt;
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
    int n, node_cnt;

    if (priv == NULL)
	return;

    node_cnt = priv->params->node_cnt;
    for (n = 0; n < node_cnt; n++) {
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
    int			rc = 0, node_cnt, i, data;

    node_cnt = params->node_cnt;
    priv->thr_id = thread_id;
    data = params->node_cnt - params->parities;

    /* Copy reference to the worker's I/O buffer */
    for (i = 0; i < node_cnt; i++)
	priv->chunks[i]->lf_buf = stripe_buf[thread_id] + i * params->chunk_sz;

    switch (cmd) {
    case W_T_LOAD:
	if (params->verbose) {
		printf("Populate data in %lu stripes @%lu for extent %lu on node %d, chunks: ",
			bunch->stripes, bunch->phy_stripe, bunch->extent, params->node_id);
		for (i = 0; i < node_cnt; i++) {
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
	    perf_start(&priv->perf_stat.lw_bw);
	    for (i = 0; i < node_cnt; i++) {
		chunk = priv->chunks[i];
		if (chunk->data >= 0) {
		    /* Read chunk from fabric */
		    rc = write_chunk(priv, i, stripe);
		    if (rc) return rc;
		}
	    }
	    rc = stripe_io_counter_wait(priv, CNTR_OP_W);
	    if (rc) return rc;
	    perf_add(&priv->perf_stat.lw_bw, params->chunk_sz*(unsigned int)data);
	}
	if (params->verbose)
	    printf("%d/%d Write FAM BW %.2f MiB/S\n",
		   rank, thread_id, perf_get_bw(&priv->perf_stat.lw_bw, uSec, MiB));
	break;

    case W_T_VERIFY:
	if (params->verbose) {
		printf("Verifying data in %lu stripes @%lu for extent %lu on node %d, chunks: ",
			bunch->stripes, bunch->phy_stripe, bunch->extent, params->node_id);
		for (i = 0; i < node_cnt; i++) {
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
	    perf_start(&priv->perf_stat.lr_bw);
	    for (i = 0; i < node_cnt; i++) {
		chunk = priv->chunks[i];
		if (chunk->data >= 0) {
		    /* Read chunk from fabric */
		    rc = read_chunk(priv, i, stripe);
		    if (rc) return rc;
		}
	    }
	    rc = stripe_io_counter_wait(priv, CNTR_OP_R);
	    if (rc) return rc;
	    perf_add(&priv->perf_stat.lr_bw, params->chunk_sz*(unsigned int)data);

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
		for (i = 0; i < node_cnt; i++) {
			chunk = priv->chunks[i];
			if (chunk->parity >= 0)
				printf("%d:P%d ", i, chunk->parity);
		}
		printf("on %lu stripes @%lu for extent %lu on node %d from chunks: ",
			bunch->stripes, bunch->phy_stripe, bunch->extent, params->node_id);
		for (i = 0; i < node_cnt; i++) {
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
	    perf_start(&priv->perf_stat.lr_bw);
	    for (i = 0; i < node_cnt; i++) {
		chunk = priv->chunks[i];
		if (chunk->data >= 0) {
		    /* Read chunk from fabric */
		    rc = read_chunk(priv, i, stripe);
		    if (rc) return rc;
		}
	    }
	    rc = stripe_io_counter_wait(priv, CNTR_OP_R);
	    if (rc) return rc;
	    perf_add(&priv->perf_stat.lr_bw, params->chunk_sz*(unsigned int)data);

            encode_stripe(priv);

	    perf_start(&priv->perf_stat.lw_bw);
	    for (i = 0; i < node_cnt; i++) {
		chunk = priv->chunks[i];
		if (chunk->parity >= 0) {
		    /* Write chunk to fabric */
		    rc = write_chunk(priv, i, stripe);
		    if (rc) return rc;
		}
	    }
	    rc = stripe_io_counter_wait(priv, CNTR_OP_W);
	    if (rc) return rc;
	    perf_add(&priv->perf_stat.lw_bw, params->chunk_sz*(unsigned int)params->parities);
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
		for (i = 0; i < node_cnt; i++) {
			chunk = priv->chunks[i];
			if (chunk->data >= 0 && chunk->data < params->recover)
				printf("%d:D%d ", i, chunk->data);
		}
		printf("on %lu stripes starting at %lu for extent %lu on node %d from: ",
			bunch->stripes, bunch->phy_stripe, bunch->extent, params->node_id);
		for (i = 0; i < node_cnt; i++) {
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
	    perf_start(&priv->perf_stat.lr_bw);
	    for (i = 0; i < node_cnt; i++) {
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
	    perf_add(&priv->perf_stat.lr_bw,
		params->chunk_sz * (unsigned int)(data - params->recover + params->parities));

	    /* Decode 'recover' data chunks */
            recover_stripe(priv);

	    perf_start(&priv->perf_stat.lw_bw);
	    for (i = 0; i < node_cnt; i++) {
		chunk = priv->chunks[i];
		if (chunk->data >= 0 && chunk->data < params->recover) {
		    /* Write recovered chunk to fabric */
		    rc = write_chunk(priv, i, stripe);
		    if (rc) return rc;
		}
	    }
	    rc = stripe_io_counter_wait(priv, CNTR_OP_W);
	    if (rc) return rc;
	    perf_add(&priv->perf_stat.lw_bw, params->chunk_sz*(unsigned int)params->recover);
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
    perf_stats_add_locked(&params->perf_stats, &priv->perf_stat, &params->pstats_lock);

    work_free(priv);
    return rc;
}

static void lf_client_free(LF_CL_t *cl)
{
	int j;

	if (cl->eq)
	    ON_FI_ERROR(fi_close(&cl->eq->fid), "close eq");
	if (cl->mr)
	    ON_FI_ERROR(fi_close(&cl->mr->fid), "close srv mr");

	for (j = 0; j < cl->size; j++) {
	    /* MR_LOCAL */
	    if (cl->local_mr)
		ON_FI_ERROR(fi_close(&cl->local_mr[j]->fid), "close mr");
	    /* scalable endpoint */
	    if (cl->tx_epp)
		ON_FI_ERROR(fi_close(&cl->tx_epp[j]->fid), "close tx ep");
	    if (cl->rx_epp && cl->rx_epp[j])
		ON_FI_ERROR(fi_close(&cl->rx_epp[j]->fid), "close rx ep");
	    if (cl->rcnts && cl->rcnts[j])
		ON_FI_ERROR(fi_close(&cl->rcnts[j]->fid), "close rcnt");
	    if (cl->wcnts)
		ON_FI_ERROR(fi_close(&cl->wcnts[j]->fid), "close wcnt");
	    if (cl->tx_cqq)
		ON_FI_ERROR(fi_close(&cl->tx_cqq[j]->fid), "close tx cq");
	    if (cl->rx_cqq && cl->rx_cqq[j])
		ON_FI_ERROR(fi_close(&cl->rx_cqq[j]->fid), "close rx cq");
	}
	free(cl->tx_epp);
	free(cl->rx_epp);
	free(cl->rcnts);
	free(cl->wcnts);
	free(cl->cq_affinity);
	free(cl->local_desc);
	free(cl->local_mr);

	/* scalable endpoint */
	if (cl->ep)
	    ON_FI_ERROR(fi_close(&cl->ep->fid), "close ep");

	/* non-scalable endpoint */
	if (cl->size == 0 && cl->rx_cqq)
		ON_FI_ERROR(fi_close(&cl->rx_cqq[0]->fid), "close rx cq 0");
	if (cl->rcnt)
		ON_FI_ERROR(fi_close(&cl->rcnt->fid), "close rcnt 0");
	free(cl->rx_cqq);
	free(cl->tx_cqq);

	ON_FI_ERROR(fi_close(&cl->av->fid), "close av");
	ON_FI_ERROR(fi_close(&cl->domain->fid), "close domain");
	ON_FI_ERROR(fi_close(&cl->fabric->fid), "close fabric");
	fi_freeinfo(cl->fi);

	free(cl->srv_addr);
	free(cl->tgt_srv_addr);
	free(cl);
}

static void lf_clients_free(LF_CL_t **all_clients, int count)
{
    int i;

    for (i = 0; i < count; i++)
	lf_client_free(all_clients[i]);

    free(all_clients);
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

static int lf_srv_init(LF_SRV_t *priv)
{
    N_PARAMS_t		*params = priv->params;
    LF_CL_t		*cl = priv->lf_client;

    struct fi_info      *hints, *fi;
    struct fid_fabric   *fabric;
    //struct fi_eq_attr   eq_attr;
    //struct fid_eq       *eq;
    struct fid_domain   *domain;
    struct fid_ep       *ep;
    struct fi_av_attr   av_attr;
    struct fid_av       *av;
    struct fi_cq_attr   cq_attr;
    struct fid_mr       *mr;
    struct fid_ep	**rx_epp = NULL;
    struct fid_cq	**rx_cqq;
    struct fi_rx_attr	rx_attr;
    struct fid_cntr     *rcnt = NULL;
    struct fi_cntr_attr cntr_attr;

    char                port[6], name[128];
    size_t              n, len;
    uint64_t            mr_key = 0;

    int			i, rx_ctx_n, my_node_id, *cq_affinity;
    const char		*pname;

    rx_ctx_n = params->lf_srv_rx_ctx;
    my_node_id = params->node_id;
    pname = params->nodelist[my_node_id];
    cq_affinity = cl->cq_affinity;
    sprintf(port, "%5d", cl->service);

    // Provider discovery
    hints = fi_allocinfo();
    hints->caps                 = FI_RMA;
#ifdef LF_TARGET_RMA_EVENT
    hints->caps                 |= FI_RMA_EVENT;
#endif
    if (rx_ctx_n)
	hints->caps		|= FI_NAMED_RX_CTX;
    hints->mode                 = FI_CONTEXT;

    if (params->lf_mr_flags.scalable)
	hints->domain_attr->mr_mode = FI_MR_SCALABLE;
    else if (params->lf_mr_flags.basic)
	hints->domain_attr->mr_mode = FI_MR_BASIC;
    else {
	if (params->lf_mr_flags.allocated)
	    hints->domain_attr->mr_mode |= FI_MR_ALLOCATED;
	if (params->lf_mr_flags.prov_key)
	    hints->domain_attr->mr_mode |= FI_MR_PROV_KEY;
	if (params->lf_mr_flags.virt_addr)
	    hints->domain_attr->mr_mode |= FI_MR_VIRT_ADDR;
    }
    if (params->lf_mr_flags.local)
	hints->domain_attr->mr_mode |= FI_MR_LOCAL;

    // hints->domain_attr->threading = FI_THREAD_ENDPOINT;
    hints->ep_attr->type        = FI_EP_RDM;
    free(hints->fabric_attr->prov_name);
    hints->fabric_attr->prov_name = strdup(params->prov_name);
    if (params->lf_domain) {
	free(hints->domain_attr->name);
	hints->domain_attr->name = strdup(params->lf_domain);
    }

    ON_FI_ERROR(fi_getinfo(FI_VERSION(1, 5), pname, port, FI_SOURCE, hints, &fi), "srv fi_getinfo failed");
    fi_freeinfo(hints);
    if (fi->next) {
	/* TODO: Add 'domain' option */
	fprintf(stderr, "Ambiguous target provider:%s in domains %s and %s\n",
		fi->fabric_attr->prov_name, fi->domain_attr->name, fi->next->domain_attr->name);
	return 1;
    }
    cl->fi = fi;

    /* Query provider capabilities */
    if (fi->domain_attr->mr_mode & FI_MR_LOCAL)
	params->lf_mr_flags.local = 1;
    if (fi->domain_attr->mr_mode & FI_MR_BASIC)
	params->lf_mr_flags.basic = 1;
    if (fi->domain_attr->mr_mode & FI_MR_PROV_KEY)
	params->lf_mr_flags.prov_key = 1;
    if (fi->domain_attr->mr_mode & FI_MR_VIRT_ADDR)
	params->lf_mr_flags.virt_addr = 1;
    if (fi->domain_attr->mr_mode & FI_MR_ALLOCATED)
	params->lf_mr_flags.allocated = 1;

    // Create fabric object
    ON_FI_ERROR(fi_fabric(fi->fabric_attr, &fabric, NULL), "srv fi_fabric failed");
    cl->fabric = fabric;

    // Create completion queue
    /*
    memset(&eq_attr, 0, sizeof(eq_attr));
    eq_attr.size = 64;
    eq_attr.wait_obj = FI_WAIT_UNSPEC;
    ON_FI_ERROR(fi_eq_open(fabric, &eq_attr, &eq, NULL), "srv fi_eq_open failed");
    cl->eq = eq;
    */
    cl->eq = NULL;

    // Create domain object
    ON_FI_ERROR(fi_domain(fabric, fi, &domain, NULL), "srv fi_domain failed");
    cl->domain = domain;

    // Create address vector bind to endpoint and event queue
    memset(&av_attr, 0, sizeof(av_attr));
    av_attr.type = FI_AV_MAP;
    av_attr.rx_ctx_bits = LFSRV_RCTX_BITS;
    av_attr.ep_per_node = (unsigned int)rx_ctx_n;
    ON_FI_ERROR(fi_av_open(domain, &av_attr, &av, NULL), "srv fi_av_open failed");
    cl->av = av;
    // if FI_EVENT
    // ON_FI_ERROR(fi_av_bind(av, (fid_t)eq, 0), "srv fi_av_bind failed");

    // Create endpoint
    if (rx_ctx_n) {
	//fi->caps = FI_RMA | FI_NAMED_RX_CTX;
	ON_FI_ERROR(fi_scalable_ep(domain, fi, &ep, NULL), "srv fi_scalable_ep failed");
	ON_FI_ERROR(fi_scalable_ep_bind(ep, &av->fid, 0), "srv fi_scalable_ep_bind failed");
    } else {
	//fi->caps = FI_RMA;
	ON_FI_ERROR(fi_endpoint(domain, fi, &ep, NULL), "srv fi_endpoint failed");
	ON_FI_ERROR(fi_ep_bind(ep, (fid_t)av, 0), "srv fi_ep_bind failed");
    }
    cl->ep = ep;

    // Create completion queue and bind to endpoint
    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.format = FI_CQ_FORMAT_TAGGED;
    cq_attr.size = 100;
    if (params->set_affinity)
	cq_attr.flags = FI_AFFINITY;

    cl->size = rx_ctx_n;

    /* Scalable endpoint: create 'rx_ctx_n' rx contexts on passive RMA side */
    rx_attr = *fi->rx_attr;
    rx_attr.caps = FI_RMA;
    rx_attr.comp_order = FI_ORDER_NONE;
    rx_attr.op_flags = 0;

    if (rx_ctx_n > 0) {
	rx_epp = (struct fid_ep **) malloc(rx_ctx_n * sizeof(void*));
	ASSERT(rx_epp)
	cl->rx_epp = rx_epp;
    }
    rx_cqq = (struct fid_cq **) malloc(((rx_ctx_n > 0)? rx_ctx_n:1)* sizeof(void*));
    ASSERT(rx_cqq);
    cl->rx_cqq = rx_cqq;
    if (params->cmd_trigger > 0) {
	memset(&cntr_attr, 0, sizeof(cntr_attr));
	ON_FI_ERROR(fi_cntr_open(domain, &cntr_attr, &rcnt, NULL), "srv fi_cntr_open failed");
	cl->rcnt = rcnt;
    }

    for (i = 0; i < rx_ctx_n; i++) {
	/* scalable endpoint */
	ON_FI_ERROR(fi_rx_context(ep, i, &rx_attr, &rx_epp[i], NULL), "srv fi_rx_context failed");

	if (params->set_affinity)
	    cq_attr.signaling_vector = cq_affinity[(priv->thread_id + 1 + i) % params->node_servers];
	ON_FI_ERROR(fi_cq_open(domain, &cq_attr, &rx_cqq[i], NULL),
		    "srv fi_cq_open failed");

	ON_FI_ERROR(fi_ep_bind(rx_epp[i], &rx_cqq[i]->fid, FI_SEND | FI_RECV | FI_SELECTIVE_COMPLETION),
		    "fi_ep_bind rx context failed");

	if (params->cmd_trigger > 0) {
	    // Bind counter to endpoint
	    ON_FI_ERROR(fi_ep_bind(rx_epp[i], &rcnt->fid, FI_REMOTE_READ|FI_REMOTE_WRITE),
			"srv cntr bind failed");
	}

	ON_FI_ERROR(fi_enable(rx_epp[i]),
		    "srv fi_enable rx_ep failed");
    }

    if (rx_ctx_n == 0) {
	/* non-scalable endpoint */
	ON_FI_ERROR(fi_cq_open(domain, &cq_attr, &rx_cqq[0], NULL),
		    "srv fi_cq_open failed");
	ON_FI_ERROR(fi_ep_bind(ep, &rx_cqq[0]->fid, FI_SEND | FI_RECV | FI_SELECTIVE_COMPLETION),
		    "srv fi_ep_bind failed");

	if (params->cmd_trigger > 0) {
	    ON_FI_ERROR(fi_ep_bind(ep, &rcnt->fid, FI_REMOTE_READ|FI_REMOTE_WRITE),  "srv cntr bind failed");
	}
    }

    // Create memory region
    if (!params->lf_mr_flags.prov_key)
	mr_key = node2lf_mr_pkey(my_node_id, params->node_servers, cl->partition);

    char **bufp, *buf;
    if (params->part_mreg == 0) {
	len = params->vmem_sz;
	bufp = &fam_buf;
    } else {
	len = priv->length;
	bufp = &buf;
	ON_ERROR(posix_memalign((void **)bufp, getpagesize(), len), "srv memory alloc failed");
	priv->virt_addr = buf;
    }
    ON_FI_ERROR( fi_mr_reg(domain, *bufp, len, FI_REMOTE_READ|FI_REMOTE_WRITE, 0, mr_key, 0, &mr, NULL),
		"srv fi_mr_reg failed");
    cl->mr = mr;
    if (params->lf_mr_flags.prov_key) {
	int tmo = 3; /* 3 sec */
	mr_key = fi_mr_key(mr);
	while (tmo-- && mr_key == FI_KEY_NOTAVAIL) {
	    mr_key = fi_mr_key(mr);
	    sleep(1);
	}
	if (mr_key == FI_KEY_NOTAVAIL) {
	    fprintf(stderr, "%d/%d: Memory registration has not completed, partition:%d\n",
		    my_node_id, priv->thread_id, cl->partition);
	    ON_FI_ERROR(FI_KEY_NOTAVAIL, "srv fi_mr_key failed");
	}
    }
    cl->mr_key = mr_key;
    printf("%d/%d: Registered %zuMB of memory on %s:%s (p%d) if:%s\n",
	my_node_id, priv->thread_id,
	len/1024/1024, pname, port, cl->partition, fi->domain_attr->name);

    // Enable endpoint
    ON_FI_ERROR(fi_enable(ep), "fi_enale failed");
    n = 128;
    ON_FI_ERROR(fi_getname((fid_t)ep, name, &n), "srv fi_getname failed");
    if (n >=128) {
        printf("name > 128 chars!\n");
        return 1;
    }
    name[n] = 0;
    if (params->verbose) {
        printf("%d/%d: server addr is %zu:\n", my_node_id, priv->thread_id, n);
        for (i = 0; i < (int)n; i++) 
            printf("%02x ", (unsigned char)name[i]);
	printf(" buf@%p basic:%d local:%d prov_key:%d virt_addr:%d allocated:%d mr_key:%lu\n",
		*bufp, params->lf_mr_flags.basic, params->lf_mr_flags.local,
		params->lf_mr_flags.prov_key, params->lf_mr_flags.virt_addr, params->lf_mr_flags.allocated,
		mr_key);
    }

#if 0
    // Setup completion queues
    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.format = FI_CQ_FORMAT_DATA;
    cq_attr.size = 64;
    ON_FI_ERROR(fi_cq_open(domain, &cq_attr, &rcq, NULL), "rcq open failed");
    ON_FI_ERROR(fi_cq_open(domain, &cq_attr, &wcq, NULL), "wcq open failed");
    ON_FI_ERROR(fi_ep_bind(ep, (fid_t)rcq, FI_REMOTE_READ), "rcq bind failed");
    ON_FI_ERROR(fi_ep_bind(ep, (fid_t)wcq, FI_REMOTE_WRITE), "wcq bind failed");
#endif
    return 0;
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
	err("srv fi_cntr_wait failed:%d", err);
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

