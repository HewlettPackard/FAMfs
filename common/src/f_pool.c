/*
 * (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor
 *   Boston, MA 02110-1301, USA.
 *
 * Written by: Dmitry Ivanov
 */

#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include "f_env.h"
#include "f_error.h"
#include "f_lf_connect.h"
#include "f_pool.h"


/* Convert pool device index in devlist[] to this device index in info.pdev_indexes[],
  i.e. reverse lookup in info.pdev_indexes[] */
int f_pdev_to_indexes(F_POOL_t *p, int pdev_idx) {
    F_POOL_INFO_t *info = &p->info;
    uint16_t *pd_idx = info->pdev_indexes;
    uint32_t i, dev_count = info->dev_count;

    if (!IN_RANGE(pdev_idx, 0, (int)(p->pool_devs-1)))
	return -1;

    for (i = 0; i < dev_count; i++, pd_idx++) {
	if (*pd_idx == pdev_idx)
	    return i;
    }
    return -1;
}

F_POOL_DEV_t *f_find_pdev_by_media_id(F_POOL_t *p, unsigned int media_id)
{
    uint16_t idx;

    if (media_id > p->info.pdev_max_idx)
	return NULL;

    idx = p->info.pdi_by_media[media_id];
    return (idx >= p->pool_devs)? NULL:&p->devlist[idx];
}

int lf_clients_free(F_POOL_t *p)
{
    int r, rc = 0;

    if (p) {
	F_POOL_DEV_t *pdev = NULL;

	if (p->devlist && p->info.pdev_indexes) {
	    for_each_pool_dev(p, pdev) {
	        if (pdev && pdev->dev) {
	            r = f_conn_close(&pdev->dev->f);
		    if (r && !rc)
			rc = r;
		}
	    }
	}
	if (rc)
	    return rc;

	rc = f_domain_close(&p->mynode.domain);
    }
    return rc;
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

    /* Enable per-domain endpoint */
    if (lf_info->single_ep) {
	rc = f_conn_enable(domain->ep, domain->fi);
	if (rc) {
	    err("faied ebable per-domain endpoint");
	    goto _err;
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

int lf_servers_free(F_POOL_t *p)
{
    int r, rc = 0;

    if (p->mynode.emul_devs) {
	F_POOL_DEV_t *pdev;

	for_each_emul_pdev(p, pdev) {
	    r = f_conn_close(&pdev->dev->f);
	    if (r && !rc)
		rc = r;
	}
    }
    if (rc)
	return rc;

    return f_domain_close(&p->mynode.emul_domain);
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

	/* create domain->ep; register MR for each fdev; enable EP */
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

    rc = f_conn_enable(domain->ep, domain->fi);
    if (rc) {
	err("faied ebable per-domain endpoint");
	goto _err;
    }

    char name[128];
    size_t n = sizeof(name);
    rc = fi_getname(&domain->ep->fid, name, &n);
    if (rc) {
	fi_err(rc, "fi_getname failed");
	goto _err;
    }
    if (n >=128) {
	err("name > 128 chars!");
	rc = -E2BIG;
	goto _err;
    }
    name[n] = 0;
    if (lf_info->verbosity >= 7) {
	printf("%s: server addr is %zu:\n", p->mynode.hostname, n);
	for (int i = 0; i < (int)n; i++)
	     printf("%02x ", (unsigned char)name[i]);
	printf("\n");
    }

    if (verbose) {
	printf("%s: LF target scalable:%d local:%d basic:%d (prov_key:%d virt_addr:%d allocated:%d)\n",
		p->mynode.hostname,
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


