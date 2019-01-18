/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_rma.h>


#include "famfs_env.h"
#include "famfs_error.h"
#include "famfs_lf_connect.h"


int lf_client_init(LF_CL_t *lf_node, N_PARAMS_t *params)
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

    void		*fi_dest_addr;
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
    hints->caps			= FI_RMA;
#ifdef LF_TARGET_RMA_EVENT
    hints->caps			|= FI_RMA_EVENT;
#endif
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
    if (!strcmp(params->prov_name, "zhpe"))
	hints->domain_attr->data_progress = FI_PROGRESS_AUTO;
    hints->ep_attr->type        = FI_EP_RDM;
    free(hints->fabric_attr->prov_name);
    hints->fabric_attr->prov_name = strdup(params->prov_name);
    if (params->lf_domain) {
	free(hints->domain_attr->name);
	hints->domain_attr->name = strdup(params->lf_domain);
    }

    if (params->lf_fabric) {
	pname = params->lf_fabric;
    } else {
	char* const* nodelist = params->clientlist? params->clientlist : params->nodelist;

	if (params->lf_mr_flags.zhpe_support)
	    pname = nodelist[params->node_id];
	else
	    pname = nodelist[node];
    }
    rc = fi_getinfo(FI_VERSION(1, 5), pname, port, 0, hints, &fi);
    ON_FI_ERROR(rc, "LF client - fi_getinfo failed for FAM node %d (p%d) on %s:%s",
		    node, partition_id, pname, port);

    fi_freeinfo(hints);
    if (fi->next) {
	/* TODO: Add 'domain' option */
	ON_ERROR(1, "LF client failed - ambiguous provider:%s in domains %s and %s",
		    fi->fabric_attr->prov_name, fi->domain_attr->name, fi->next->domain_attr->name);
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

    // Check support for scalable endpoint
    if (fi->domain_attr->max_ep_tx_ctx > 1) {
	size_t min_ctx =
		min(fi->domain_attr->tx_ctx_cnt, fi->domain_attr->rx_ctx_cnt);
	ON_ERROR((unsigned int)thread_cnt > min_ctx,
		"Maximum number of requested contexts exceeds provider limitation");
    } else {
	err("Provider %s (in %s) doesn't support scalable endpoints",
		fi->fabric_attr->prov_name, pname);
	ON_ERROR(1, "lf_client_init failed");
    }

    if (lf_node->fabric == NULL) {
	// Create fabric object
	ON_FI_ERROR(fi_fabric(fi->fabric_attr, &fabric, NULL), "fi_fabric failed");

	// Create domain object
	ON_FI_ERROR(fi_domain(fabric, fi, &domain, NULL),
		    "LF client fi_domain failed for FAM node %d (p%d) port %d - fi_domain failed",
		    node, partition_id, service);
	lf_node->free_domain_fl = 1;

	// Create address vector bind to endpoint and event queue
	memset(&av_attr, 0, sizeof(av_attr));
	av_attr.type = FI_AV_MAP;
	//av_attr.type = FI_AV_UNSPEC;
	av_attr.rx_ctx_bits = LFSRV_RCTX_BITS;
	av_attr.ep_per_node = (unsigned int)thread_cnt;
	ON_FI_ERROR(fi_av_open(domain, &av_attr, &av, NULL), "fi_av_open failed");
    } else {
	fabric = lf_node->fabric;
	domain = lf_node->domain;
	av = lf_node->av;
	lf_node->free_domain_fl = 0;
    }
    fi_dest_addr = fi->dest_addr;

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
	if (lf_node->free_domain_fl) {
	    local_mr = (struct fid_mr **) malloc(thread_cnt * sizeof(void*));
	    ASSERT(local_mr);
	    for (i = 0; i < thread_cnt; i++) {
		ON_FI_ERROR( fi_mr_reg(domain, params->stripe_buf[i], params->chunk_sz * params->nchunks,
				       FI_READ|FI_WRITE, 0, i, 0, &mr, NULL),
			    "fi_mr_reg failed, key:%d", i);
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
		    ON_FI_ERROR(mr_key, "Memory registration has not completed, FAM node %d part:%d",
					node, partition_id);
		}
	    }
#endif
	    /* Get local descriptors */
	    for (i = 0; i < thread_cnt; i++)
		local_desc[i] = fi_mr_desc(local_mr[i]);
	} else {
	    /* Copy local descriptors */
	    memcpy(local_desc, lf_node->local_desc, thread_cnt * sizeof(void*));
	}
    }

    for (i = 0; i < thread_cnt; i++) {
	if (params->lf_srv_rx_ctx) {
	    /* scalable endpoint */

	    // Create independent transmitt queues
	    ON_FI_ERROR(fi_tx_context(ep, i, &tx_attr, &tx_epp[i], NULL), "fi_tx_context failed");
	} else {
	    /* non-scalable endpoint */
	    ON_FI_ERROR(fi_endpoint(domain, fi, &tx_epp[i], NULL),
			"Cannot create endpoint #%d for FAM node %d (p%d) - fi_endpoint failed",
			i, node, partition_id);
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
	// FI_RECV | FI_TRANSMIT | FI_SELECTIVE_COMPLETION
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

    // zhpe support
    if (params->lf_mr_flags.zhpe_support) {
	struct fi_zhpe_ext_ops_v1 *ext_ops;
	size_t sa_len;
	char url[16];
	unsigned long long fam_id = lf_node->fam_id;

	ON_FI_ERROR( fi_open_ops(&fabric->fid, FI_ZHPE_OPS_V1, 0, (void **)&ext_ops, NULL),
		"srv open_ops failed");
	// FAM lookup
	sprintf(url, "zhpe:///fam%4Lu", fam_id);
	ON_FI_ERROR( ext_ops->lookup(url, &fi_dest_addr, &sa_len), "fam:%4Lu lookup failed", fam_id);

	if (params->verbose)
	    printf("CL attached to FAM node %d(p%d) ID:fam%4Lu from %s\n",
		   node, partition_id, fam_id, pname);
    } else {
	if (params->verbose)
	    printf("CL attached to node %d(p%d) on %s:%s\n",
		   node, partition_id, pname, port);
    }

    // Perform address translation
    srv_addr = (fi_addr_t *)malloc(sizeof(fi_addr_t));
    ASSERT(srv_addr);
    if (1 != (i = fi_av_insert(av, fi_dest_addr, 1, srv_addr, 0, NULL))) {
	ioerr("fi_av_insert failed, returned %d", i);
	return 1;
    }
    fi_freeinfo(fi);

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
	lf_node->mr_key = params->lf_mr_flags.zhpe_support? FI_ZHPE_FAM_RKEY : \
			  node2lf_mr_pkey(node, params->node_servers, partition_id);
    lf_node->cq_affinity = cq_affinity;
    lf_node->service = service;

    /* used on passive RMA side */
    //lf_node->eq = NULL;
    lf_node->rx_epp = NULL;
    lf_node->rx_cqq = NULL;
    lf_node->mr = NULL;
    lf_node->rcnt = NULL;

    return 0;
}

void lf_client_free(LF_CL_t *cl)
{
	int j;

//	if (cl->eq)
//	    ON_FI_ERROR(fi_close(&cl->eq->fid), "close eq");
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

	if (cl->free_domain_fl) {
	    /* close the domain */
	    ON_FI_ERROR(fi_close(&cl->av->fid), "close av");
	    ON_FI_ERROR(fi_close(&cl->domain->fid), "close domain");
	    ON_FI_ERROR(fi_close(&cl->fabric->fid), "close fabric");
	}
	free(cl->srv_addr);
	free(cl->tgt_srv_addr);
	free(cl);
}

int lf_clients_init(N_PARAMS_t *params)
{
    LF_CL_t **lf_all_clients;
    size_t chunk_sz;
    char **stripe_buf;
    int psize, workers, fam_cnt, srv_cnt, nchunks, lf_client_idx;
    int verbose, my_node_id;
    int i, part, rc;

    /* Pre-allocate LF client worker's private data buffers */
    workers = params->w_thread_cnt;
    stripe_buf = (char **)malloc(workers * sizeof(void*));
    ASSERT(stripe_buf);
    psize = getpagesize();
    nchunks = params->nchunks;
    chunk_sz = params->chunk_sz;
    for (i = 0; i < workers; i++) {
	/* Stripe I/O buffer */
	ON_ERROR(posix_memalign((void **)&stripe_buf[i], psize,
				chunk_sz * nchunks),
		 "stripe buffer memory alloc failed");
	if (params->lf_mr_flags.allocated)
	    mlock(stripe_buf[i], chunk_sz * nchunks);
    }
    params->stripe_buf = stripe_buf;

    /* Allocate one LF_CL_t structure per FAM */
    fam_cnt = params->fam_cnt;
    srv_cnt = params->node_servers;
    lf_all_clients = (LF_CL_t **) calloc(fam_cnt * srv_cnt, sizeof(void*));
    ASSERT(lf_all_clients);
    params->lf_clients = lf_all_clients;

    /* Setup fabric for each node */
    my_node_id = params->node_id;
    for (i = 0; i < fam_cnt; i++) {
	for (part = 0; part < srv_cnt; part++) {
	    LF_CL_t *cl;
	    lf_client_idx = to_lf_client_id(i, srv_cnt, part);

	    cl = (LF_CL_t *) malloc(sizeof(LF_CL_t));
	    ASSERT(cl);
	    cl->node_id = i;
	    cl->partition = (unsigned int)part;
	    cl->fam_id = fam_id_by_index(params->fam_map, i);

	    if (params->lf_mr_flags.prov_key)
		cl->mr_key = params->mr_prov_keys[lf_client_idx];

	    /* FI_MR_VIRT_ADDR? */
	    if (params->lf_mr_flags.virt_addr) {
		if (params->part_mreg == 0)
		    cl->dst_virt_addr = (uint64_t) params->fam_buf;
		else
		    cl->dst_virt_addr = (uint64_t) params->mr_virt_addrs[lf_client_idx];
	    }

	    if (!params->fam_map || (i == 0 && part == 0)) {
		/* Join the fabric and domain */
		cl->fabric = NULL;
	    } else {
		LF_CL_t *fab = lf_all_clients[0];

		cl->fabric = fab->fabric;
		cl->domain = fab->domain;
		cl->av = fab->av;
		cl->local_desc = fab->local_desc;
	    }

	    /* Create tx contexts per working thread (w_thread_cnt) */
	    if ((rc = lf_client_init(cl, params))) {
		err("Error in libfabric client init for FAM module %d(p%d)",
		    i, part);
		free(cl);
		continue;
	    }

	    lf_all_clients[lf_client_idx] = cl;
	    if (params->verbose) {
		char * const *nodelist = params->clientlist? params->clientlist : params->nodelist;

		if (params->fam_map)
		    printf("%d CL attached to FAM module %d(p%d) mr_key:%lu\n",
			   my_node_id, i, part, cl->mr_key);
		else
		    printf("%d CL attached to node %d(p%d) on %s:%5d mr_key:%lu\n",
			   my_node_id, i, part, nodelist[i], cl->service, cl->mr_key);
	    }
	}
    }

    verbose = (my_node_id == 0);
    if (verbose) {
	printf("LF initiator scalable:%d local:%d basic:%d (prov_key:%d virt_addr:%d allocated:%d)\n",
		params->lf_mr_flags.scalable, params->lf_mr_flags.local, params->lf_mr_flags.basic,
		params->lf_mr_flags.prov_key, params->lf_mr_flags.virt_addr, params->lf_mr_flags.allocated);
    }

    if (params->set_affinity && verbose) {
	printf("Set CQ and worker affinity: ");
	for (i = 0; i < params->w_thread_cnt; i++)
		printf("%d ", lf_all_clients[0]->cq_affinity[i]);
	printf("\n");
    }

    return 0;
}

/*
 * Libfabric target
**/
int lf_srv_init(LF_SRV_t *priv)
{
    N_PARAMS_t		*params = priv->params;
    LF_CL_t		*cl = priv->lf_client;

    struct fi_info      *hints, *fi;
    struct fid_fabric   *fabric;
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
    const char		*pname, *fabname;

    rx_ctx_n = params->lf_srv_rx_ctx;
    my_node_id = params->node_id;
    pname = params->nodelist[my_node_id];
    fabname = params->lf_fabric? params->lf_fabric : pname;
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
    if (!strcmp(params->prov_name, "zhpe"))
	hints->domain_attr->data_progress = FI_PROGRESS_AUTO;
    hints->ep_attr->type        = FI_EP_RDM;
    free(hints->fabric_attr->prov_name);
    hints->fabric_attr->prov_name = strdup(params->prov_name);
    if (params->lf_domain) {
	free(hints->domain_attr->name);
	hints->domain_attr->name = strdup(params->lf_domain);
    }

    ON_FI_ERROR(fi_getinfo(FI_VERSION(1, 5), fabname, port, FI_SOURCE, hints, &fi),
		"srv fi_getinfo failed on %s for %s:%s in domain:%s",
		pname, fabname, port, hints->domain_attr->name);
    fi_freeinfo(hints);
    if (fi->next) {
	/* TODO: Add 'domain' option */
	err("Ambiguous target provider:%s in domains %s and %s",
		fi->fabric_attr->prov_name, fi->domain_attr->name, fi->next->domain_attr->name);
	return 1;
    }

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

    if (cl->fabric == NULL) {
	cl->free_domain_fl = 1;

	// Create fabric object
	ON_FI_ERROR(fi_fabric(fi->fabric_attr, &fabric, NULL), "srv fi_fabric failed");

	// Create domain object
	ON_FI_ERROR(fi_domain(fabric, fi, &domain, NULL), "srv fi_domain failed");

	// Create address vector bind to endpoint and event queue
	memset(&av_attr, 0, sizeof(av_attr));
	av_attr.type = FI_AV_MAP;
	av_attr.rx_ctx_bits = LFSRV_RCTX_BITS;
	av_attr.ep_per_node = (unsigned int)rx_ctx_n;
	ON_FI_ERROR(fi_av_open(domain, &av_attr, &av, NULL), "srv fi_av_open failed");
    } else {
	cl->free_domain_fl = 0;
	fabric = cl->fabric;
	domain = cl->domain;
	av = cl->av;
    }

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
    }
    rx_cqq = (struct fid_cq **) malloc(((rx_ctx_n > 0)? rx_ctx_n:1)* sizeof(void*));
    ASSERT(rx_cqq);
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
	mr_key = params->lf_mr_flags.zhpe_support? FI_ZHPE_FAM_RKEY : \
		 node2lf_mr_pkey(my_node_id, params->node_servers, cl->partition);

    void **bufp, *buf;
    if (params->part_mreg == 0) {
	len = params->vmem_sz;
	bufp = &params->fam_buf;
    } else {
	unsigned int page_size = getpagesize();
	size_t part_length = params->vmem_sz / params->node_servers;

	len = params->lf_mr_flags.zhpe_support? page_size : part_length;
	bufp = &buf;
	ON_ERROR(posix_memalign(bufp, page_size, len), "srv memory alloc failed");
    }
    ON_FI_ERROR( fi_mr_reg(domain, *bufp, len, FI_REMOTE_READ|FI_REMOTE_WRITE, 0, mr_key, 0, &mr, NULL),
		"srv fi_mr_reg failed");
    priv->virt_addr = *bufp;
    if (params->lf_mr_flags.prov_key) {
	int tmo = 3; /* 3 sec */
	mr_key = fi_mr_key(mr);
	while (tmo-- && mr_key == FI_KEY_NOTAVAIL) {
	    mr_key = fi_mr_key(mr);
	    sleep(1);
	}
	if (mr_key == FI_KEY_NOTAVAIL) {
	    err("%d/%d: Memory registration has not completed, partition:%d",
		    my_node_id, priv->thread_id, cl->partition);
	    ON_FI_ERROR(FI_KEY_NOTAVAIL, "srv fi_mr_key failed");
	}
    }

    // Enable endpoint
    ON_FI_ERROR(fi_enable(ep), "fi_enale failed");

    // zhpe support
    if (params->lf_mr_flags.zhpe_support) {
	struct fi_zhpe_ext_ops_v1 *ext_ops;
	size_t sa_len;
	void *fam_sa;
	char url[16];

	ON_FI_ERROR( fi_open_ops(&fabric->fid, FI_ZHPE_OPS_V1, 0, (void **)&ext_ops, NULL),
		"srv open_ops failed");
	sprintf(url, "zhpe:///fam%4Lu", cl->fam_id);
	ON_FI_ERROR( ext_ops->lookup(url, &fam_sa, &sa_len), "fam:%4Lu lookup failed", cl->fam_id);

	printf("%d/%d: Attached to %zuMB of FAM memory on %s:fam%4Lu if:%s\n",
	       my_node_id, priv->thread_id,
	       len/1024/1024, pname,
	       cl->fam_id, fi->domain_attr->name);
    } else {
	printf("%d/%d: Registered %zuMB of memory on %s:%s (p%d) if:%s\n",
	       my_node_id, priv->thread_id,
	       len/1024/1024, pname, port, cl->partition, fi->domain_attr->name);
    }
    fi_freeinfo(fi);
    fi = NULL;

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

    cl->fabric = fabric;
    cl->domain = domain;
    cl->av = av;
    cl->ep = ep;
    cl->rx_epp = rx_epp;
    cl->rx_cqq = rx_cqq;
    cl->mr = mr;
    cl->mr_key = mr_key;
    return 0;
}

int lf_servers_init(LF_SRV_t ***lf_servers_p, N_PARAMS_t *params, MPI_Comm mpi_comm)
{
    LF_SRV_t **lf_servers = NULL;
    int srv_cnt, node_id, lf_client_idx;
    int rank, size;
    int i, part, rc;

    MPI_Comm_rank(mpi_comm, &rank);
    MPI_Comm_size(mpi_comm, &size);
    node_id = params->node_id;
    srv_cnt = params->node_servers;
    if (size != srv_cnt) {
	err("%d: MPI error: communicator has %d nodes but the command has %d",
	    node_id, size, srv_cnt);
	rc = -1;
        goto _err;
    }

    if (params->part_mreg == 0) {
	if ((rc = posix_memalign(&params->fam_buf, getpagesize(),
			params->vmem_sz))) {
	    err("srv memory alloc failed");
	    goto _err;
	}
    }

    lf_servers = (LF_SRV_t **) malloc(srv_cnt*sizeof(void*));
    ASSERT(lf_servers);
    for (i = 0; i < srv_cnt; i++) {
	LF_SRV_t *srv;
	LF_CL_t *cl;

	srv = (LF_SRV_t *) malloc(sizeof(LF_SRV_t));
	ASSERT(srv);
	srv->params = params;
	srv->thread_id = i;
	//lf_servers[i]->length = part_length;
	//lf_servers[i]->virt_addr = NULL;

	cl = (LF_CL_t*) calloc(1, sizeof(LF_CL_t));
	ASSERT(cl);
	cl->partition = i;
	/* if (params->fam_map)
	    cl->fam_id = fam_id_by_index(params->fam_map, node_id); */
	cl->service = node2service(params->lf_port, node_id, i);
	if ( params->set_affinity)
	    alloc_affinity(&cl->cq_affinity, srv_cnt, i + 1);
	srv->lf_client = cl;

	rc = lf_srv_init(srv);
	if (rc) {
	    err("%d: Error starting FAM module %d(p%d) emulation!",
		rank, i, cl->partition);
	    free(cl);
	    free(srv);
	    goto _err;
	}

	lf_servers[i] = srv;
    }

#if 0
	if (priv->params->cmd_trigger > 0)
	    rc = lf_srv_trigger(priv);
#endif

    MPI_Barrier(mpi_comm);
    if (rank == 0) {
	printf("LF target scalable:%d local:%d basic:%d (prov_key:%d virt_addr:%d allocated:%d)\n",
		params->lf_mr_flags.scalable, params->lf_mr_flags.local, params->lf_mr_flags.basic,
		params->lf_mr_flags.prov_key, params->lf_mr_flags.virt_addr, params->lf_mr_flags.allocated);
    }

    /* Exchange keys */
    if (params->lf_mr_flags.prov_key) {
	size_t len = srv_cnt * sizeof(uint64_t);

	/* For each partition */
	for (part = 0; part < srv_cnt; part++) {
	    lf_client_idx = to_lf_client_id(node_id, srv_cnt, part);
	    params->mr_prov_keys[lf_client_idx] = lf_servers[part]->lf_client->mr_key;
	}
	if ((rc = MPI_Allgather(MPI_IN_PLACE, len, MPI_BYTE,
				params->mr_prov_keys, len, MPI_BYTE, mpi_comm))) {
	    err("MPI_Allgather failed");
	    goto _err;
	}
    }
    /* Exchange virtual addresses */
    if (params->lf_mr_flags.virt_addr) {
	size_t len = srv_cnt * sizeof(uint64_t);

	/* For each partition */
	for (part = 0; part < srv_cnt; part++) {
	    lf_client_idx = to_lf_client_id(node_id, srv_cnt, part);
	    params->mr_virt_addrs[lf_client_idx] = (uint64_t) lf_servers[part]->virt_addr;
	}
	if ((rc = MPI_Allgather(MPI_IN_PLACE, len, MPI_BYTE,
				params->mr_virt_addrs, len, MPI_BYTE, mpi_comm))) {
	    err("MPI_Allgather failed");
	    goto _err;
	}
    }

    *lf_servers_p = lf_servers;
    return 0;

_err:
    MPI_Abort(mpi_comm, rc);
    MPI_Finalize();
    if (rank == 0)
	exit(rc);
    sleep(10);
    /* Should not reach this */
    return -1;
}

void lf_srv_free(LF_SRV_t *srv) {
    LF_CL_t *cl = srv->lf_client;

    lf_client_free(cl);
    if (srv->params->part_mreg)
	free(srv->virt_addr);
    free(srv);
}

