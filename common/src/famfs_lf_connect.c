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

    pname = params->nodelist[node];
    rc = fi_getinfo(FI_VERSION(1, 5), pname, port, 0, hints, &fi);
    ON_FI_ERROR(rc, "LF fi_getinfo failed, client cannot connect to node:%d (p%d) on %s:%s",
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

    // Create fabric object
    ON_FI_ERROR(fi_fabric(fi->fabric_attr, &fabric, NULL), "fi_fabric failed");
    fi_dest_addr = fi->dest_addr;

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
		"LF client cannot connect to node %d (p%d) port %d - fi_domain failed",
		node, partition_id, service);
    if (params->verbose)
	printf("CL attached to node/part %d/%d on %s:%s\n", node, partition_id, pname, port);

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
    if (params->lf_mr_flags.local || params->lf_mr_flags.zhpe_support) {
	local_mr = (struct fid_mr **) malloc(thread_cnt * sizeof(void*));
	ASSERT(local_mr);
	for (i = 0; i < thread_cnt; i++) {
	    ON_FI_ERROR( fi_mr_reg(domain, params->stripe_buf[i], params->chunk_sz * params->node_cnt,
				   FI_READ|FI_WRITE, 0, i, 0, &mr, NULL),
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
		ON_FI_ERROR(mr_key, "Memory registration has not completed, node:%d part:%d",
				    node, partition_id);
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
			"Cannot create endpoint #%d for node %d (p%d) - fi_endpoint failed",
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
	unsigned long long fam_id = part2fam_id(node, params->node_servers, partition_id);

	ON_FI_ERROR( fi_open_ops(&fabric->fid, FI_ZHPE_OPS_V1, 0, (void **)&ext_ops, NULL),
		"srv open_ops failed");
	// FAM lookup
	sprintf(url, "zhpe:///fam%4Lu", fam_id);
	ON_FI_ERROR( ext_ops->lookup(url, &fi_dest_addr, &sa_len), "fam:%4Lu lookup failed", fam_id);
    }

    // Perform address translation
    srv_addr = (fi_addr_t *)malloc(sizeof(fi_addr_t));
    ASSERT(srv_addr);
    if (1 != (i = fi_av_insert(av, fi_dest_addr, 1, srv_addr, 0, NULL))) {
        err("ft_av_insert failed, returned %d\n", i);
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
	lf_node->mr_key = params->lf_mr_flags.zhpe_support? FI_ZHPE_FAM_RKEY : \
			  node2lf_mr_pkey(node, params->node_servers, partition_id);
    lf_node->cq_affinity = cq_affinity;
    lf_node->service = service;

    /* used on passive RMA side */
    lf_node->eq = NULL;
    lf_node->rx_epp = NULL;
    lf_node->rx_cqq = NULL;
    lf_node->mr = NULL;
    lf_node->rcnt = NULL;

    return 0;
}

void lf_client_free(LF_CL_t *cl)
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

