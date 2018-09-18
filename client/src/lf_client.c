#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <limits.h>
#include <ifaddrs.h>

#include <mpi.h>

#include "lf_client.h"
#include "unifycr-internal.h"

#define PR_BUF_SZ	12

static int rank, rank_size;

static int lf_client_init(LF_CL_t *lf_node_p, N_PARAMS_t *params);
static void lf_client_free(LF_CL_t *cl);


#define N_STRLIST_DELIM ","
static char** getstrlist(const char *buf, int *count)
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

static void nodelist_free(char **nodelist, int size) {
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

static uint64_t get_batch_stripes(uint64_t stripes, int servers) {
    uint64_t batch = stripes / (unsigned int)servers;
    return (batch == 0)? 1:batch;
}

static void usage(const char *name) {
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
	    "\t   --memreg basic|local|scalable\n"
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

int str2argv(char *str, char **argv, int argmax) {
    int argc = 0;
    char *tok, *p = str;

    while ((tok = strsep(&p, " \t")) && argc < argmax) {
        argv[argc++] = tok;
        DEBUG("tok[%d]=%s", argc - 1, tok);
    }

    argv[argc] = 0;
    return --argc;
}

int arg_parser(int argc, char **argv, N_PARAMS_t **params_p) {
    int			opt, opt_idx = 0;
    char		port[6], **nodelist = NULL;
    int			node_cnt = 0, recover = 0, verbose = 0;
    int			iters = -1, parities = -1, workers = -1, lf_port = -1;
    size_t		vmem_sz = 0, chunk_sz = 0, extent_sz = 0;
    uint64_t            transfer_len = 0; /* transfer [block] size */
    W_TYPE_t		cmd, cmdv[CMD_MAX];
    unsigned int	srv_extents = 0; 
    int			set_affinity = 0, lf_srv_rx_ctx = 0;
    int			lf_mr_scalable, lf_mr_local;
    uint64_t		*mr_prov_keys = NULL, *mr_virt_addrs = NULL;
    char		*lf_provider_name = NULL, *lf_domain = NULL, *memreg = NULL;
    N_PARAMS_t		*params = NULL;
    LF_CL_t		**lf_all_clients = NULL;
    int			cmdc, i, k, data, node_id, srv_cnt, rc;
    uint64_t		io_timeout = 0;
    uint64_t		phy_stripe, stripes, extents;
    char		**stripe_buf;	/* [0]: stripe buffer */


    ASSERT(sizeof(size_t) == 8);

    rc = 1; /* parser error */
    // MPI_Comm_size(MPI_COMM_WORLD, &rank_size);
    // MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    enum opt_long_ {
	OPT_PROVIDER = 1000,
	OPT_DOMAIN,
	OPT_RXCTX,
	OPT_SRV_EXTENTS,
	OPT_MEMREG,
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
		    goto _free;
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
            case '?':
            case 'h':
            default:
		usage(argv[0]);
		goto _free;
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
	    goto _free;
	}
	cmdv[cmdc++] = cmd;
    }
    if (cmdc == 0) {
	printf("No command given!\n");
	goto _free;
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
    lf_mr_local = strcasecmp(memreg, LF_MR_MODEL_LOCAL)? 0:1;
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
	    goto _free;
	}
	if ( extent_sz % chunk_sz != 0) {
	    fprintf(stderr, "Extent must be multiple of chunks\n");
	    goto _free;
	}
	if ( chunk_sz % transfer_len != 0) {
	    fprintf(stderr, "Chunk must be multiple of transfer blocks\n");
	    goto _free;
	}
	if ( (stripes*chunk_sz) != vmem_sz ) {
	    fprintf(stderr, "vmem_sz is not divisible by chunk_sz!\n");
	    goto _free;
	}
	if (data < parities) {
	    printf("Wrong number of data chunks:%d for %d parity chunks on %d nodes\n",
		data, parities, node_cnt);
	    goto _free;
	}
	if (recover < 0 || recover > parities) {
	    fprintf(stderr, "Wrong number of chunks to recover %d parities\n", parities);
	    goto _free;
	}
	if (!lf_mr_scalable && !lf_mr_local && strcasecmp(memreg, LF_MR_MODEL_BASIC)) {
	    fprintf(stderr, "Wrong LF memory registration type:%s (expect %s, %s or %s)\n",
		memreg, LF_MR_MODEL_BASIC, LF_MR_MODEL_LOCAL, LF_MR_MODEL_SCALABLE);
	    goto _free;
	}

	printf("Commands: ");
	for (i = 0; i < cmdc; i++)
	    printf("%s%s", (i>0)?",":"", cmd2str(cmdv[i]));
	printf("\n");

	printf("Nodelist: ");
	for (i = 0; i < node_cnt; i++)
	    printf("%s%s", (i>0)?",":"", nodelist[i]);
	printf("\n");

	printf("Chunk %dD+%dP=%d %zu bytes\n", data, parities, node_cnt, chunk_sz);
	printf("Number data chunk(s) to recover:%d (starting with chunk 0)\n", recover);
	printf("Extent %zu bytes\n", extent_sz);
	printf("VMEM %zu bytes in %d partition(s) per node\n", vmem_sz, srv_cnt);
	printf("Transfer block size %zu bytes\n", transfer_len);
	printf("libfabric port:%s mr:%s\n  number of workers:%d, srv rx ctx:%d\n  I/O timeout %lu ms\n",
	    port, lf_mr_scalable?LF_MR_MODEL_SCALABLE:(lf_mr_local?LF_MR_MODEL_LOCAL:LF_MR_MODEL_BASIC),
	    workers, lf_srv_rx_ctx, io_timeout);
	printf("Iterations: %d\n", iters);

	if (extents*extent_sz != vmem_sz*node_cnt) {
		fprintf(stderr, "Wrong VMEM:%lu, it must be a multiple of extent size (%lu)!\n",
			vmem_sz, extent_sz);
		goto _free;
	}
	if (exts % srv_extents) {
		fprintf(stderr, "Wrong srv_extents:%d, extents (%u) must be devisible by it.\n",
			srv_extents, exts);
			goto _free;
	}
	printf("Calculated:\n\tPhy extents per node %u, total:%lu\n"
		"\tStripes per extent:%lu, total:%ld\n",
		exts, extents, extent_sz/chunk_sz, stripes);
    }
    free(memreg);

    if (!lf_mr_scalable) {
	mr_prov_keys = (uint64_t *)malloc(srv_cnt*node_cnt*sizeof(uint64_t));
	mr_virt_addrs = (uint64_t *)malloc(srv_cnt*node_cnt*sizeof(uint64_t));
    }

    params = (N_PARAMS_t*)malloc(sizeof(N_PARAMS_t));
    params->nodelist = nodelist;
    params->vmem_sz = vmem_sz;
    params->chunk_sz = chunk_sz;
    params->extent_sz = extent_sz;
    params->node_cnt = node_cnt;
    /* TODO: Find my node in nodelist */
    params->node_id = node_id;
    params->parities = parities;
    params->recover = recover;
    params->w_thread_cnt = 1;
    params->transfer_sz = transfer_len;
    params->io_timeout_ms = io_timeout;
    params->lf_port = lf_port;
    params->prov_name = lf_provider_name;
    params->lf_domain = lf_domain;
    memset(&params->lf_mr_flags, 0, sizeof(LF_MR_MODE_t));
    params->lf_mr_flags.scalable = lf_mr_scalable;
    params->lf_mr_flags.local = lf_mr_local;
    params->verbose = verbose;
    params->set_affinity = set_affinity;
    params->lf_srv_rx_ctx = lf_srv_rx_ctx;
    params->srv_extents = srv_extents;
    params->node_servers = srv_cnt;
    params->part_sz = (off_t)vmem_sz / srv_cnt;
    params->mr_prov_keys = mr_prov_keys;
    params->mr_virt_addrs = mr_virt_addrs;

    //MPI_Barrier(MPI_COMM_WORLD);

    /* Pre-allocate stripe data buffer */
    stripe_buf = (char **)malloc(sizeof(void*));
    ASSERT(stripe_buf);
    int psize = getpagesize();
    /* Stripe I/O buffer */
    ON_ERROR(posix_memalign((void **)&stripe_buf[0], psize,
			    params->chunk_sz * params->node_cnt),
			    "chunk memory alloc failed");
    params->stripe_buf = stripe_buf;

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

	    /* Create tx contexts */
	    ON_ERROR( lf_client_init(cl, params), 
		     "Error in libfabric client init");
	    lf_all_clients[i*srv_cnt+part] = cl;

	}
    }
    if (rank == 0) {
	printf("LF initiator prov_key:%d local:%d virt_addr:%d\n",
		params->lf_mr_flags.prov_key, params->lf_mr_flags.local, params->lf_mr_flags.virt_addr);
    }

    if (params->set_affinity && rank == 0) {
	printf("Set CQ and worker affinity: ");
		printf("%d ", lf_all_clients[0]->cq_affinity[0]);
	printf("\n");
    } 

    //MPI_Barrier(MPI_COMM_WORLD);

    params->lf_clients = lf_all_clients;
    *params_p = params;
    return 0;

_free:
    nodelist_free(nodelist, node_cnt);
    return rc;
}

void free_lf_clients(N_PARAMS_t **params_p)
{
    N_PARAMS_t *params = *params_p;
    LF_CL_t **lf_all_clients;
    int i, count;

    if (params == NULL)
	return;

    lf_all_clients = params->lf_clients;
    count = params->node_cnt * params->node_servers;
    for (i = 0; i < count; i++)
	lf_client_free(lf_all_clients[i]);
    free(lf_all_clients);

    free(params->stripe_buf[0]);
    free(params->stripe_buf);
    nodelist_free(params->nodelist, params->node_cnt);
    free(params->prov_name);
    free(params->lf_domain);
    free(params->mr_prov_keys);
    free(params->mr_virt_addrs);
    free(params);
    *params_p = NULL;
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

#if 0
static inline char* pr_chunk(char *buf, int d, int p) {
	if (d >= 0)
		snprintf(buf, PR_BUF_SZ, "D%d", d);
	else if (p >= 0)
		snprintf(buf, PR_BUF_SZ, "P%d", p);
	else
		sprintf(buf, "???");
	return buf;
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
    int		j;

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

		/* Setup fabric for extent on each node */
		for (n = 0; n < node_cnt; n++) {
			priv->lf_clients[n] = all_clients[n*params->node_servers + partition];
			ASSERT(partition == priv->lf_clients[n]->partition);

			/* Allocate N_CHUNK_t and map chunk to extent */
			ON_ERROR( assign_map_chunk(&priv->chunks[n], params, e, partition, n),
				"Error allocating chunk");
		}

		/* Queue job */
		if (params->verbose) {
			printf("%s: add_work %s in extent %d for stripes %lu..%lu\n",
				params->nodelist[node_id], cmd2str(op), e, start, start+j_count-1);
		}
    		ON_ERROR( pool_add_work(pool, op, priv), "Error queueing work");
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
#endif

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
    int			node, partition_id, service;
    int			*cq_affinity = NULL;
    const char		*pname;
    int			i, rc;

    node = lf_node->node_id;
    partition_id = lf_node->partition;
    service = node2service(params->lf_port, node, partition_id);
    sprintf(port, "%5d", service);

    // Provider discovery
    hints = fi_allocinfo();
 //   hints->caps                 = FI_RMA | FI_RMA_EVENT;
    hints->caps                 = FI_RMA;
    if (params->lf_srv_rx_ctx)
	hints->caps		|= FI_NAMED_RX_CTX;
    hints->mode                 = FI_CONTEXT;
    if (params->lf_mr_flags.scalable)
	hints->domain_attr->mr_mode = FI_MR_SCALABLE;
    else if (params->lf_mr_flags.local)
	hints->domain_attr->mr_mode = FI_MR_LOCAL;
    else
	hints->domain_attr->mr_mode = FI_MR_BASIC;
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

    // Create fabric object
    ON_FI_ERROR(fi_fabric(fi->fabric_attr, &fabric, NULL), "fi_fabric failed");

    // Check support for scalable endpoint
    if (fi->domain_attr->max_ep_tx_ctx > 1) {
	size_t min_ctx =
		min(fi->domain_attr->tx_ctx_cnt, fi->domain_attr->rx_ctx_cnt);
    } else {
	fprintf(stderr, "Provider %s (in %s) doesn't support scalable endpoints\n",
		fi->fabric_attr->prov_name, pname);
	ON_ERROR(1, "lf_client_init failed");
    }

    // Create domain object
    ON_FI_ERROR(fi_domain(fabric, fi, &domain, NULL),
		"%d: cannot connect to node %d (p%d) port %d - fi_domain failed",
		rank, node, partition_id, service);
    if (params->verbose)
	printf("%d CL attached to node/part %d/%d on %s:%s\n", rank, node, partition_id, pname, port);

    // Create address vector bind to endpoint and event queue
    memset(&av_attr, 0, sizeof(av_attr));
    av_attr.type = FI_AV_MAP;
    av_attr.rx_ctx_bits = LFSRV_RCTX_BITS;
    av_attr.ep_per_node = 1;
    ON_FI_ERROR(fi_av_open(domain, &av_attr, &av, NULL), "fi_av_open failed");

    // Create endpoint
    fi->caps = FI_RMA;
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
	alloc_affinity(&cq_affinity, 1, node + 2);
	cq_attr.flags = FI_AFFINITY;
    }

    tx_attr = *fi->tx_attr;
    tx_attr.comp_order = FI_ORDER_NONE;
 //   tx_attr.op_flags = FI_COMPLETION;

    /* per worker --> */
    tx_epp = (struct fid_ep **) malloc(sizeof(void*));
    tx_cqq = (struct fid_cq **) malloc(sizeof(void*));
    ASSERT(tx_epp && tx_cqq);
    rcnts = (struct fid_cntr **) malloc(sizeof(void*));
    wcnts = (struct fid_cntr **) malloc(sizeof(void*));
    ASSERT(rcnts && wcnts);
    if (params->lf_mr_flags.local) {
	local_mr = (struct fid_mr **) malloc(sizeof(void*));
	ASSERT(local_mr);
    }
    local_desc = (void **) calloc(1, sizeof(void*));

    /* Register the local buffers */
    if (params->lf_mr_flags.local) {
	ON_FI_ERROR( fi_mr_reg(domain, params->stripe_buf[0], params->chunk_sz * params->node_cnt,
				FI_READ|FI_WRITE, 0, 0, FI_RMA_EVENT, &mr, NULL),
				"fi_mr_reg failed");
	local_mr[0] = mr;
	/* Wait until registration is completed */ 
	int tmo = 3; /* 3 sec */
	mr = local_mr[0];
	uint64_t mr_key = fi_mr_key(mr);
	while (tmo-- && mr_key == FI_KEY_NOTAVAIL) {
	    mr_key = fi_mr_key(mr);
	    sleep(1);
	}
	if (mr_key == FI_KEY_NOTAVAIL) {
	    fprintf(stderr, "%d/%d: Memory registration has not completed, partition:%d\n",
		    rank, node, partition_id);
	    ON_FI_ERROR(FI_KEY_NOTAVAIL, "srv fi_mr_key failed");
	}

	/* Get local descriptors */
	local_desc[i] = fi_mr_desc(local_mr[0]);
    }

    {
	if (params->lf_srv_rx_ctx) {
	    /* scalable endpoint */

	    // Create independent transmitt queues
	    ON_FI_ERROR(fi_tx_context(ep, 0, &tx_attr, &tx_epp[0], NULL), "fi_tx_context failed");
	} else {
	    /* non-scalable endpoint */
	    ON_FI_ERROR(fi_endpoint(domain, fi, &tx_epp[0], NULL),
			"%d: cannot create endpoint #%d for node %d (p%d) - fi_endpoint failed",
			rank, 0, node, partition_id);
	    ON_FI_ERROR(fi_ep_bind(tx_epp[0], &av->fid, 0), "fi_ep_bind failed");
	}

	// Create counters
	ON_FI_ERROR(fi_cntr_open(domain, &cntr_attr, &rcnts[0], NULL), "fi_cntr_open r failed");
	ON_FI_ERROR(fi_cntr_open(domain, &cntr_attr, &wcnts[0], NULL), "fi_cntr_open w failed");

#if 1
	// Create completion queues
	if (params->set_affinity)
	    cq_attr.signaling_vector = cq_affinity[0];

	ON_FI_ERROR(fi_cq_open(domain, &cq_attr, &tx_cqq[0], NULL), "fi_cq_open failed");

	// Bind completion queues to endpoint
	ON_FI_ERROR(fi_ep_bind(tx_epp[0], &tx_cqq[0]->fid, FI_RECV | FI_TRANSMIT | FI_SELECTIVE_COMPLETION),
		    "fi_ep_bind tx context failed");
#endif

	// Bind counters to endpoint
	ON_FI_ERROR(fi_ep_bind(tx_epp[0], &rcnts[0]->fid, FI_READ),  "fi_ep_bind r cnt failed");
	ON_FI_ERROR(fi_ep_bind(tx_epp[0], &wcnts[0]->fid, FI_WRITE),  "fi_ep_bind w cnt failed");

	ON_FI_ERROR(fi_enable(tx_epp[0]), "fi_enable tx_ep failed");
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

    tgt_srv_addr = (fi_addr_t *)malloc(sizeof(fi_addr_t));
    ASSERT(tgt_srv_addr);
    /* Convert endpoint address to target receive context */
	if (params->lf_srv_rx_ctx) {
	    tgt_srv_addr[0] = fi_rx_addr(*srv_addr, 0, LFSRV_RCTX_BITS);
	    ON_FI_ERROR( tgt_srv_addr[0] == FI_ADDR_NOTAVAIL, "FI_ADDR_NOTAVAIL");
	} else
	    tgt_srv_addr[0] = *srv_addr;

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
    lf_node->size = 1;
    if (!params->lf_mr_flags.prov_key)
	lf_node->mr_key = node2lf_mr_pkey(node, params->node_servers, partition_id);
    lf_node->cq_affinity = cq_affinity;
    lf_node->service = service;

    /* not used on active RMA side */
    lf_node->eq = NULL;
    lf_node->rx_epp = NULL;
    lf_node->rx_cqq = NULL;
    lf_node->mr = NULL;

    return 0;
}

#if 0
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

	printf("will write %d blocks of %lu bytes to %s chunk of stripe %lu on %s p%d @%ld\n",
		blocks, transfer_sz,
		pr_chunk(pr_buf, chunk->data, chunk->parity), stripe,
		params->nodelist[chunk_n], node->partition, off);
    }

    // Do RMA
    for (ii = 0; ii < blocks; ii++) {
	ON_FI_ERROR(fi_write(tx_ep, buf, transfer_sz, node->local_desc, *tgt_srv_addr, off,
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
	ON_FI_ERROR(fi_read(tx_ep, buf, transfer_sz, node->local_desc, *tgt_srv_addr, off,
			    node->mr_key, (void*)buf /* NULL */),
		    "fi_read failed");
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
	}
	break;

    default:
	return 1;
    }

    work_free(priv);
    return rc;
}
#endif

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

