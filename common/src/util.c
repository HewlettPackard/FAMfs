#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <limits.h>
#include <ifaddrs.h>

#include "famfs_env.h"
#include "famfs_error.h"
#include "famfs_lf_connect.h"


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
	if (nodelist) {
		for (int i = 0; i < size; i++)
			free(nodelist[i]);
		free(nodelist);
	}
}

int find_my_node(char* const* nodelist, int node_cnt, int silent) {
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

	if (idx < 0 && !silent)
		printf("Cannot find my node %s in the node list (-H)!\n",
			hostname?hostname:"?");
	free(hostname);
	return idx;
}

void alloc_affinity(int **affp, int size, int pos)
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

void ion_usage(const char *name) {
    printf("\nUsage:\n%s <mandatory options> [<more options>] <command> [<command>...]\n"
	   "\t-H |--hostlist <node name list>\n"
	   "\t-P |--parities <number of parity chunks in a stripe>\n"
	   "\t-R |--recover <number of data chunks to recover>\n"
	   "\t-M |--memory <virtual memory size>\n"
	   "\t-E |--extent <extent size>\n"
	   "\t-C |--chunk <chunk size>\n"
	   "\t-w |--workers <number of worker threads>\n"
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
	   "\t   --part_mreg <1|0> - 1(default): every partition registers own RMA buffer\n"
	   "\t   --memreg <basic|local|basic,local|scalable> (default:scalable)\n"
	   "\t-c --clients <node name list>\n"
	   "\t-a |--affinity\n"
	   "\t-v |--verbose\n"
	   "  Command is one of:\n"
	   "\tLOAD - populate data\n"
	   "\tENCODE\n"
	   "\tDECODE\n"
	   "\tVERIFY\n"
	   "\n",
	   name);
}

int arg_parser(int argc, char **argv, int be_verbose, int client_rank_size, N_PARAMS_t **params_p)
{
    int			opt, opt_idx = 0;
    char		port[6], **nodelist = NULL, **clientlist = NULL;
    int			node_cnt = 0, recover = 0, verbose = 0;
    int			cmd_trigger = 0, client_cnt = 0, part_mreg = 1;
    int			iters = -1, parities = -1, workers = -1, lf_port = -1;
    size_t		vmem_sz = 0, chunk_sz = 0, extent_sz = 0;
    uint64_t            transfer_len = 0; /* transfer [block] size */
    W_TYPE_t		cmd, cmdv[ION_CMD_MAX];
    unsigned int	srv_extents = 0;
    int			set_affinity = 0, lf_srv_rx_ctx = 0;
    int			lf_mr_scalable, lf_mr_local, lf_mr_basic, zhpe_support = 0;
    uint64_t		*mr_prov_keys = NULL, *mr_virt_addrs = NULL;
    char		*lf_provider_name = NULL, *lf_domain = NULL, *memreg = NULL;
    const char		*env_zhpe_backend = NULL;
    N_PARAMS_t		*params = NULL;
    int			cmdc, i, data, node_id, srv_cnt, rc;
    uint64_t		cmd_timeout, io_timeout = 0;
    uint64_t		stripes, extents;

    rc = 1; /* parser error */

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
	{"clients",	1, 0, 'c'},
	{"extent",	1, 0, 'E'},
	{"workers",	1, 0, 'w'},
	/* no short option */
	{"provider",	1, 0, OPT_PROVIDER},
	{"domain",	1, 0, OPT_DOMAIN},
	{"rxctx",	1, 0, OPT_RXCTX},
	{"srv_extents",	1, 0, OPT_SRV_EXTENTS},
	{"memreg",	1, 0, OPT_MEMREG},
	{"cmd_trigger",	0, 0, OPT_CMD_TRIGGER},
	{"part_mreg",	0, 0, OPT_PART_MREG},
	{0, 0, 0, 0}
    };

    optind = 0;
    while ((opt = getopt_long(argc, argv, "avhp:i:t:T:H:P:R:M:C:c:E:w:",
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
	    case 'c':
		clientlist = getstrlist(optarg, &client_cnt);
		if (!clientlist) {
		    printf("Client name list - bad delimiter!");
		    goto _free;
		}
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
	    case OPT_PART_MREG:
		part_mreg = atoi(optarg);
		break;
            case '?':
            case 'h':
            default:
		goto _free;
        }
    }

    /* Parse command */
    cmdc = 0;
    while (optind < argc) {
	if (cmdc >= ION_CMD_MAX) {
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
	    goto _free;
	}
	cmdv[cmdc++] = cmd;
    }
    if (cmdc == 0) {
	printf("No command given!\n");
	goto _free;
    }

    /* Sanity check */
    ON_ERROR( (node_cnt == 0), "Bad node count, please check -H [--hostlist]");

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
    if (!strcmp(lf_provider_name, "zhpe") && (env_zhpe_backend = getenv("ZHPE_BACKEND_LIBFABRIC_PROV")))
	if (!strcmp(env_zhpe_backend, "zhpe"))
	    zhpe_support = 1;
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

    /* Find my node */
    if (client_rank_size > 0) {
	node_id = find_my_node(clientlist, client_cnt, 0);
	ON_ERROR ((node_id < 0) && (client_cnt > client_rank_size),
		  "Bad node count %d > %d, please check -c [--clientlist]",
		  client_cnt, client_rank_size);
    } else {
        node_id = find_my_node(nodelist, node_cnt, 0);
	if (clientlist) {
	    /* Ignore clientlist */
	    nodelist_free(clientlist, client_cnt);
	    client_cnt = 0;
	    clientlist = NULL;
	    err("Ignore clientlist (-c) option on IO node %d of %d", node_id, node_cnt);
	}
    }
    ON_ERROR (node_id < 0, "Cannot find my node in the list (-%c)!", client_cnt?'c':'H');

    /* Sanity check */

    /* Default: srv_cnt=1 (single partition) */
    if (srv_extents == 0)
	srv_extents = vmem_sz/extent_sz;
    srv_cnt = vmem_sz/extent_sz/srv_extents;

    printf("Running on node:%d\n", node_id);

    if (be_verbose) {
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
	if (!lf_mr_scalable && !lf_mr_local && !lf_mr_basic) {
	    fprintf(stderr, "Wrong LF memory registration type:%s (expect %s, %s or/and %s)\n",
		memreg, LF_MR_MODEL_SCALABLE, LF_MR_MODEL_BASIC, LF_MR_MODEL_LOCAL);
	    goto _free;
	}
	if (cmd_trigger > cmdc) {
	    err("Wrong command trigger:%d - there is no such command!", cmd_trigger);
	    goto _free;
	}

	printf("Commands: ");
	for (i = 0; i < cmdc; i++)
	    printf("%s%s", (i>0)?",":"", cmd2str(cmdv[i]));
	printf("\n");
	if (cmd_trigger > 0) {
	    printf("\tthis command will be triggered by LF remote access: %s\n",
		cmd2str(cmdv[cmd_trigger-1]));
	}

	printf("Servers: ");
	for (i = 0; i < node_cnt; i++)
	    printf("%s%s", (i>0)?",":"", nodelist[i]);
	printf("\n");
	if (clientlist) {
	    printf("Clients: ");
	    for (i = 0; i < client_cnt; i++)
		printf("%s%s", (i>0)?",":"", clientlist[i]);
	    printf("\n");
	}

	printf("Chunk %dD+%dP=%d %zu bytes\n", data, parities, node_cnt, chunk_sz);
	printf("Number data chunk(s) to recover:%d (starting with chunk 0)\n", recover);
	if (recover || parities)
	    printf("  ISA-L uses %s\n", ISAL_CMD==ISAL_USE_AVX2?"AVX2":"SSE2");
	printf("Extent %zu bytes\n", extent_sz);
	printf("VMEM %zu bytes in %d partition(s) per node\n", vmem_sz, srv_cnt);
	printf("Transfer block size %zu bytes\n", transfer_len);
	printf("libfabric provider:%s/%s mr_mode:%s%s%s",
	       lf_provider_name, env_zhpe_backend?env_zhpe_backend:"?",
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
    params->cmdc = cmdc;
    memcpy(params->cmdv, cmdv, cmdc*sizeof(W_TYPE_t));
    params->nodelist = nodelist;
    params->vmem_sz = vmem_sz;
    params->chunk_sz = chunk_sz;
    params->extent_sz = extent_sz;
    params->node_cnt = node_cnt;
    params->clientlist = clientlist;
    params->client_cnt = clientlist? client_cnt : node_cnt;
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
	params->lf_mr_flags.prov_key = 0;
	params->lf_mr_flags.allocated = 1;
	params->lf_mr_flags.virt_addr = 0;
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
    params->lf_mr_flags.zhpe_support = zhpe_support;

    params->verbose = verbose;
    params->set_affinity = set_affinity;
    params->lf_srv_rx_ctx = lf_srv_rx_ctx;
    params->srv_extents = srv_extents;
    params->node_servers = srv_cnt;
    params->part_sz = (off_t)vmem_sz / srv_cnt;
    params->mr_prov_keys = mr_prov_keys;
    params->mr_virt_addrs = mr_virt_addrs;
    params->cmd_trigger = cmd_trigger;
    params->part_mreg = part_mreg;

    params->lf_clients = NULL;

    *params_p = params;
    return 0;

_free:
    nodelist_free(nodelist, node_cnt);
    nodelist_free(clientlist, client_cnt);
    return rc;
}

void free_lf_params(N_PARAMS_t **params_p)
{
    N_PARAMS_t *params = *params_p;
    LF_CL_t **lf_all_clients;
    int i, node_cnt;

    if (params == NULL)
	return;
    node_cnt = params->node_cnt;

    lf_all_clients = params->lf_clients;
    if (lf_all_clients) {
	int count = node_cnt * params->node_servers;

	lf_clients_free(lf_all_clients, count);
	params->lf_clients = NULL;
    }

    if (params->stripe_buf) {
	for (i = 0; i < params->w_thread_cnt; i++) {
	    if (params->lf_mr_flags.allocated)
		munlock(params->stripe_buf[i], params->chunk_sz * node_cnt);
	    free(params->stripe_buf[i]);
	}
	free(params->stripe_buf);
	params->stripe_buf = NULL;
    }

    nodelist_free(params->nodelist, node_cnt);
    nodelist_free(params->clientlist, params->client_cnt);
    free(params->prov_name);
    free(params->lf_domain);
    free(params->mr_prov_keys);
    free(params->mr_virt_addrs);
    free(params);
    *params_p = NULL;
}

