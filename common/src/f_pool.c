/*
 * Copyright (c) 2019-2020, HPE
 *
 * Written by: Dmitry Ivanov
 */

#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include "famfs_env.h"
#include "famfs_error.h"
#include "famfs_lf_connect.h"
#include "f_pool.h"


#if 0
/* Lookup pool device in pool->devlist by IO node index and FAM position in the node */
F_POOL_DEV_t *f_ionode_pos_to_pdev(F_POOL_t *p, int ion_idx, int idx)
{
    F_POOL_DEV_t *pdev;

    for_each_pool_dev(p, pdev) {
	if (pdev->ionode_idx == ion_idx && pdev->idx_in_ion == idx)
	    return pdev;
    }
    return NULL;
}
#endif

F_POOL_DEV_t *f_find_pdev_by_media_id(F_POOL_t *p, unsigned int media_id)
{
    uint16_t idx;

    if (media_id > p->info.pdev_max_idx)
	return NULL;

    idx = p->info.pdi_by_media[media_id];
    return (idx >= p->pool_devs)? NULL:&p->devlist[idx];
}

void lf_clients_free(F_POOL_t *p)
{
    if (p) {
	F_POOL_DEV_t *pdev;

	for_each_pool_dev(p, pdev)
	    f_conn_close(&pdev->dev->f);

	f_domain_close(&p->mynode.domain);
    }
}

/* Open fabric/domain; open connections to all pool devices */
int lf_clients_init(F_POOL_t *p)
{
    F_MYNODE_t *node = &p->mynode;
    LF_DOM_t *domain;
    LF_INFO_t *lf_info;
    F_POOL_DEV_t *pdev;
    const char *fab;
    unsigned int dev_count;
    int verbose, rc;

    verbose = p->verbose;
    lf_info = p->lf_info;
    assert( lf_info );

    if (p->mynode.domain == NULL) {
	/* Open fabric/domain */
	fab = p->ionodes->hostname;
	rc =  f_domain_open(&p->mynode.domain, lf_info, fab, LF_CLIENT);
	if (rc) {
	    err("faied open libfabric");
	    goto _err;
	}
    }
    domain = node->domain;
    dev_count = p->info.dev_count;
    assert( dev_count ); /* there should be at least one */

    /* Open endopoint for each pool device */
    for_each_pool_dev(p, pdev) {
	FAM_DEV_t *fdev = &pdev->dev->f;
	unsigned int media_id = pdev->pool_index;

	if (DevFailed(pdev->sha))
	    goto _cont;

	rc = f_conn_open(fdev, domain, lf_info, media_id, LF_CLIENT);
	if (rc) {
	    err("Failed to open libfabric connection to media id:%u @%s",
		pdev->pool_index, fdev->lf_name);
		goto _err;
	}

_cont:
	if (verbose) {
	    if (lf_info->opts.true_fam)
		printf("%s: CL %s FAM device %d znode:%s url:%s mr_key:%lu\n",
			node->hostname, fdev->ep?"attached to":"skip", media_id,
			fdev->zfm.znode, fdev->zfm.url, fdev->mr_key);
	    else
		printf("%s: CL %s media id:%u on %s:%s mr_key:%lu\n",
			node->hostname, fdev->ep?"attached to":"skip", media_id,
			fdev->lf_name, fdev->service, fdev->mr_key);
	}
    }

    if (verbose) {
	printf("LF initiator prov:%s scalable:%d local:%d basic:%d (prov_key:%d virt_addr:%d allocated:%d)\n",
		node->domain->fi->domain_attr->name,
		lf_info->mrreg.scalable, lf_info->mrreg.local, lf_info->mrreg.basic,
		lf_info->mrreg.prov_key, lf_info->mrreg.virt_addr, lf_info->mrreg.allocated);
    }
    return 0;

_err:
    err("failed to open fabric:%d (prov=%s) on %snode %s",
	rc, lf_info->provider, NodeIsIOnode(node)?"IO ":"", node->hostname);
    lf_clients_free(p);
    assert( rc < 0 );
    return rc;
}

void lf_servers_free(F_POOL_t *p)
{
    if (p->mynode.emul_devs) {
	F_POOL_DEV_t *pdev;

	for_each_emul_pdev(p, pdev)
	    f_conn_close(&pdev->dev->f);
    }
    f_domain_close(&p->mynode.emul_domain);
}

/* Open fabric/domain; open connections to all pool devices */
int lf_servers_init(F_POOL_t *p)
{
    F_MYNODE_t *node = &p->mynode;
    LF_DOM_t *domain;
    LF_INFO_t *lf_info;
    F_POOL_DEV_t *pdev;
    unsigned int dev_count;
    int verbose, rc;

    assert( NodeRunLFSrv(node) );
    verbose = p->verbose;
    lf_info = p->lf_info;
    assert( lf_info );
    dev_count = node->emul_devs;
    if (dev_count == 0)
	return 0;

    if (p->mynode.emul_domain == NULL) {
	/* Open fabric/domain */
	rc =  f_domain_open(&p->mynode.emul_domain, lf_info, node->hostname, LF_SERVER);
	if (rc) {
	    err("faied open libfabric");
	    goto _err;
	}
    }
    domain = node->emul_domain;
    /* Open endopoint for each emulated pool device */
    for_each_emul_pdev(p, pdev) {
	FAM_DEV_t *fdev = &pdev->dev->f;
	unsigned int media_id = pdev->pool_index;

	rc = f_conn_open(fdev, domain, lf_info, media_id, LF_SERVER);
	if (rc) {
	    err("Failed to open libfabric connection to znode:%s url:%s"
		" for emulated media id:%u",
		fdev->zfm.znode, fdev->zfm.url, media_id);
		goto _err;
	}

	if (verbose) {
	    printf("LF target for media id:%u on %s:%s mr_key:%lu\n",
		   media_id, fdev->lf_name, fdev->service, fdev->mr_key);
	}
    }

#if 0
    if (params->lf_mr_flags.prov_key) {
	/* For each partition */
	for (part = 0; part < srv_cnt; part++) {
	    lf_client_idx = node_id;
	    params->mr_prov_keys[lf_client_idx] = lf_servers[part]->lf_client->mr_key;
	}
    }
    if (params->lf_mr_flags.virt_addr) {
	/* For each partition */
	for (part = 0; part < srv_cnt; part++) {
	    lf_client_idx = node_id;
	    params->mr_virt_addrs[lf_client_idx] = (uint64_t) lf_servers[part]->virt_addr;
	}
    }
#endif
    if (verbose) {
	printf("LF target scalable:%d local:%d basic:%d (prov_key:%d virt_addr:%d allocated:%d)\n",
		lf_info->mrreg.scalable, lf_info->mrreg.local, lf_info->mrreg.basic,
		lf_info->mrreg.prov_key, lf_info->mrreg.virt_addr, lf_info->mrreg.allocated);
    }
    return 0;

_err:
    err("failed to open fabric device (prov=%s) on %snode %s, error:%d",
	lf_info->provider, NodeIsIOnode(node)?"IO ":"", node->hostname, rc);
    lf_servers_free(p);
    assert( rc < 0 );
    return rc;
}


