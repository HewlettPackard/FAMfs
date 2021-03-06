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
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
//#include <numaif.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_rma.h>


#include "f_env.h"
#include "f_error.h"
#include "f_lf_connect.h"


static int lf_verbosity = 0;

int f_domain_close(LF_DOM_t **dom_p)
{
    LF_DOM_t *dom = *dom_p;
    int rc;

    if (!dom)
	return 0;

    if (dom->ep) {
	do {
	    if (!(rc = fi_close(&dom->ep->fid)))
		break;
	    sleep(1);
	} while (rc == -EAGAIN);
	if (rc) {
	    fi_err(rc, "close per-domain ep");
	    return rc;
	}
	dom->ep = NULL;
    }
    if (dom->cq) {
	do {
	    if (!(rc = fi_close(&dom->cq->fid)))
		break;
	    sleep(1);
	} while (rc == -EAGAIN);
	if (rc) {
	    fi_err(rc, "close single-ep cq");
	    return rc;
	}
	dom->cq = NULL;
    }
    if (dom->av) {
	do {
	    if (!(rc = fi_close(&dom->av->fid)))
		break;
	    sleep(1);
	} while (rc == -EAGAIN);
	if (rc) {
	    fi_err(rc, "close av");
	    return rc;
	}
	dom->av = NULL;
    }
    if (dom->domain) {
	do {
	    if (!(rc = fi_close(&dom->domain->fid)))
		break;
	    sleep(1);
	} while (rc == -EAGAIN);
	if (rc) {
	    fi_err(rc, "close domain");
	    return rc;
	}
	dom->domain = NULL;
    }
    if (dom->fabric) {
	do {
	    if (!(rc = fi_close(&dom->fabric->fid)))
		break;
	    sleep(1);
	} while (rc == -EAGAIN);
	if (rc) {
	    fi_err(rc, "close fabric");
	    return rc;
	}
	dom->fabric = NULL;
    }
    if (dom->fi) {
	fi_freeinfo(dom->fi);
	dom->fi = NULL;
    }
    free(dom);
    *dom_p = NULL;
    return 0;
}

int f_conn_close(FAM_DEV_t *d)
{
    int rc;

    if (!d)
	return 0;

    if (d->mr) {
	do {
	    if (!(rc = fi_close(&d->mr->fid)))
		break;
	    sleep(1);
	} while (rc == -EAGAIN);
	if (rc) {
	    fi_err(rc, "close mr");
	    return rc;
	}
    }
    d->mr = NULL;

    if (!d->ep_flags.per_dom && d->ep) {
	do {
	    if (!(rc = fi_close(&d->ep->fid)))
		break;
	    sleep(1);
	} while (rc == -EAGAIN);
	if (rc) {
	    fi_err(rc, "close ep");
	    return rc;
	}
    }
    d->ep = NULL;

    if (d->rcnt) {
	do {
	    if (!(rc = fi_close(&d->rcnt->fid)))
		break;
	    sleep(1);
	} while (rc == -EAGAIN);
	if (rc) {
	    fi_err(rc, "close rcnt");
	    return rc;
	}
    }
    d->rcnt = NULL;

    if (d->wcnt) {
	do {
	    if (!(rc = fi_close(&d->wcnt->fid)))
		break;
	    sleep(1);
	} while (rc == -EAGAIN);
	if (rc) {
	    fi_err(rc, "close wcnt");
	    return rc;
	}
    }
    d->wcnt = NULL;

    if (!d->ep_flags.per_dom && d->cq) {
	do {
	    if (!(rc = fi_close(&d->cq->fid)))
		break;
	    sleep(1);
	} while (rc == -EAGAIN);
	if (rc) {
	    fi_err(rc, "close cq");
	    return rc;
	}
    }
    d->cq = NULL;

    free(d->lf_name); d->lf_name = NULL;
    free(d->service); d->service = NULL;

    if (d->mr_buf) {
	munmap(d->mr_buf, d->mr_size);
	d->mr_buf = NULL;
    }
    return 0;
}

/* Open libfabric (info, fabric, domain and av). If lf_srv, setup for LF server. */
int f_domain_open(LF_DOM_t **dom_p, LF_INFO_t *info, const char *node,
    bool lf_srv)
{
    LF_DOM_t		*dom;
    struct fi_info      *hints, *fi;
    struct fi_av_attr   av_attr;
    char		port[6] = { 0 };
    uint64_t		flags;
    int			rc;

    lf_verbosity = info->verbosity;

    dom = (LF_DOM_t *) calloc(1, sizeof(LF_DOM_t));
    if (!dom) {
	rc = -ENOMEM;
	goto _err;
    }
    sprintf(port, "%5d", info->service);

    // Provider discovery
    hints = fi_allocinfo();
    hints->caps			= FI_RMA | FI_ATOMIC;
    //hints->caps		|= FI_RMA_EVENT; /* completion events on RMA target */
    //hints->caps		|= FI_NAMED_RX_CTX; /* SEP */
    hints->mode                 = FI_CONTEXT;

    if (info->mrreg.scalable)
	hints->domain_attr->mr_mode = FI_MR_SCALABLE;
    else if (info->mrreg.basic)
	hints->domain_attr->mr_mode = FI_MR_BASIC;
    else {
	if (info->mrreg.allocated)
	    hints->domain_attr->mr_mode |= FI_MR_ALLOCATED;
	if (info->mrreg.prov_key)
	    hints->domain_attr->mr_mode |= FI_MR_PROV_KEY;
	if (info->mrreg.virt_addr)
	    hints->domain_attr->mr_mode |= FI_MR_VIRT_ADDR;
    }
    if (info->mrreg.local)
	hints->domain_attr->mr_mode |= FI_MR_LOCAL;

    // hints->domain_attr->threading = FI_THREAD_ENDPOINT; /* FI_THREAD_FID */
    if (info->progress.progress_manual) {
	hints->domain_attr->data_progress =
		lf_srv? FI_PROGRESS_AUTO : FI_PROGRESS_MANUAL;
    } else if (info->progress.progress_auto)
	hints->domain_attr->data_progress = FI_PROGRESS_AUTO;

    hints->ep_attr->type        = FI_EP_RDM;
    //hints->addr_format = FI_SOCKADDR;

    free(hints->fabric_attr->prov_name);
    hints->fabric_attr->prov_name = strdup(info->provider);
    if (info->domain) {
	free(hints->domain_attr->name);
	hints->domain_attr->name = strdup(info->domain);
    }

    flags = lf_srv? FI_SOURCE : 0;
    rc = fi_getinfo(FI_VERSION(1, 5), node, port, flags, hints, &fi);
    if (rc) {
	fi_err(rc, "fi_getinfo failed");
	goto _err;
    }
    fi_freeinfo(hints);
    dom->fi = fi;

    if (fi->next) {
	err("libfabric failed - ambiguous provider:%s in domains %s and %s",
	    fi->fabric_attr->prov_name, fi->domain_attr->name,
	    fi->next->domain_attr->name);
	rc = -ENOTUNIQ;
	goto _err;
    }

    /* Query provider capabilities */
    if (fi->domain_attr->mr_mode & FI_MR_PROV_KEY)
	info->mrreg.prov_key = 1;
    if (fi->domain_attr->mr_mode & FI_MR_LOCAL)
	info->mrreg.local = 1;
    if (fi->domain_attr->mr_mode & FI_MR_VIRT_ADDR)
	info->mrreg.virt_addr = 1;
    if (fi->domain_attr->mr_mode & FI_MR_ALLOCATED)
	info->mrreg.allocated = 1;

    // Create fabric object
    rc = fi_fabric(fi->fabric_attr, &dom->fabric, NULL);
    if (rc) {
	fi_err(rc, "fi_fabric failed");
	goto _err;
    }

    // Create domain object
    rc = fi_domain(dom->fabric, fi, &dom->domain, NULL);
    if (rc) {
	fi_err(rc, "fi_domain failed");
	goto _err;
    }

    // Create address vector
    memset(&av_attr, 0, sizeof(av_attr));
    av_attr.type = FI_AV_TABLE;
    //av_attr.rx_ctx_bits = LFSRV_RCTX_BITS;

    rc = fi_av_open(dom->domain, &av_attr, &dom->av, NULL);
    if (rc) {
	fi_err(rc, "fi_av_open failed");
	goto _err;
    }

    *dom_p = dom;
    return 0;

_err:
    fi_err(rc, "libfabric %s - failed to open fabric on %s:%s",
	   (lf_srv? "server":"client"), node, port);
    (void)f_domain_close(&dom);
    return rc;
}

/* Open libfabric (info, fabric, domain and av).
 * lf_srv is LF_CLIENT (false) or LF_SERVER (true);
 * node: libfabric node name;
 * id: device id for mr_key calculation that is unique on node.
 */
int f_conn_open(FAM_DEV_t *fdev, LF_DOM_t *dom, LF_INFO_t *info,
    int id, bool lf_srv)
{
    F_ZFM_t *zfm = &fdev->zfm;
    struct fi_info      *fi;
    struct fid_fabric   *fabric;
    struct fid_domain   *domain;
    struct fid_av       *av;
    struct fi_cq_attr   cq_attr;
    struct fi_cntr_attr cntr_attr;
    struct fid_ep	*ep;
    struct fid_cq	*cq = NULL;
    fi_addr_t		srv_addr;
    struct fid_cntr	*rcnt = NULL, *wcnt = NULL;
    uint64_t		flags;
    const char		*node;
    char		port[6] = { 0 };
    int			service, i, rc;
    bool		single_ep = lf_srv || info->single_ep;

    assert( fdev ); /* device structure must be already allocated in config parser */
    assert( dom ); /* domain should be already open */

    fabric = dom->fabric;
    domain = dom->domain;
    fi = dom->fi;
    av = dom->av;

    service = info->service;
    sprintf(port, "%5d", service);
    fdev->service = strdup(port);
    node = fdev->lf_name;

    /* non-scalable endpoint */
    if (single_ep && dom->ep) {
	fdev->ep = ep = dom->ep;
    } else {
	rc = fi_endpoint(domain, fi, &ep, NULL);
	if (rc) {
	    fi_err(rc, "fi_endpoint failed");
	    goto _err;
	}
	fdev->ep = ep;

	rc = fi_ep_bind(ep, &av->fid, 0);
	if (rc) {
	    fi_err(rc, "fi_ep_bind failed");
	    goto _err;
	}
    }
    if (single_ep) {
	dom->ep = ep;
	fdev->ep_flags.per_dom = 1; /* FAM_DEV_t has a reference to LF_DOM_t::ep */
	if (lf_srv)
	    goto _cont;
    }

    // Create completion queue and bind to endpoint
    memset(&cq_attr, 0, sizeof(cq_attr));
    if (fdev->cq_affinity) {
	cq_attr.flags = FI_AFFINITY;
	cq_attr.signaling_vector = fdev->cq_affinity;
    }
    //flags = FI_RECV | FI_TRANSMIT; /* bind CQ flags */
    cq_attr.format = FI_CQ_FORMAT_CONTEXT;
    cq_attr.wait_obj = FI_WAIT_NONE;
    cq_attr.size = fi->tx_attr->size;
    if (info->opts.use_cq) {
	if (single_ep && dom->cq) {
	    fdev->cq = cq = dom->cq;
	} else {
	    /* TODO: Set CQ affinity: fdev->cq_affinity = cq_attr.signaling_vector = ... */
	    rc = fi_cq_open(domain, &cq_attr, &cq, NULL);
	    if (rc) {
		fi_err(rc, "fi_cq_open failed");
		goto _err;
	    }
	    fdev->cq = cq;
	    // Bind completion queues to endpoint
	    rc = fi_ep_bind(ep, &cq->fid, /* FI_SEND |*/FI_RECV | FI_TRANSMIT);
	    if (rc) {
		fi_err(rc, "fi_ep_bind CQ failed");
		goto _err;
	    }
	}
	if (single_ep)
	    dom->cq = cq;
    } else {
	assert( !single_ep ); /* Counter not supported */
	// Create counters
	memset(&cntr_attr, 0, sizeof(cntr_attr));
	cntr_attr.events = FI_CNTR_EVENTS_COMP;
	cntr_attr.wait_obj = FI_WAIT_FD;

	rc = fi_cntr_open(domain, &cntr_attr, &rcnt, NULL);
	if (rc) {
	    fi_err(rc, "fi_cntr_open (R) failed");
	    goto _err;
	}
	fdev->rcnt = rcnt;

	/* counter flags */
	//flags = FI_REMOTE_READ | FI_REMOTE_WRITE; /* passive side */
	rc = fi_cntr_open(domain, &cntr_attr, &wcnt, NULL);
	if (rc) {
	    fi_err(rc, "fi_cntr_open (W) failed");
	    goto _err;
	}
	fdev->wcnt = wcnt;

	// Bind counters to endpoint
	flags = FI_READ;
	rc = fi_ep_bind(ep, &rcnt->fid, flags);
	if (rc) {
	    fi_err(rc, "fi_ep_bind counter (R) failed");
	    goto _err;
	}

	rc = fi_ep_bind(ep, &wcnt->fid, FI_WRITE);
	if (rc) {
	    fi_err(rc, "fi_ep_bind counter (W) failed");
	    goto _err;
	}
    }
_cont:
    fdev->ep = ep;

    if (!info->opts.true_fam)
	fdev->mr_key = id;

    /* libfabric server? */
    if (lf_srv == LF_SERVER) {
	void *buf;

	assert( !info->opts.true_fam );

	/* TODO: set_mempolicy */
	/* Allocate local memory */
	buf = mmap(NULL, fdev->mr_size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (buf == MAP_FAILED) {
	    err("%d: Memory allocation/map failed for %s",
		id, node);
	    rc = -ENOMEM;
	    goto _err;
	}
	fdev->mr_buf = buf;

	rc = fi_mr_reg(domain, fdev->mr_buf, fdev->mr_size,
			FI_REMOTE_READ|FI_REMOTE_WRITE,
			0, fdev->mr_key, 0, &fdev->mr, NULL);
	if (rc) {
	    fi_err(rc, "fi_mr_reg (len=%zu, key=%lu) failed",
		   fdev->mr_size, fdev->mr_key);
	    goto _err;
	}

	if (info->mrreg.prov_key) {
	    fdev->mr_key = fi_mr_key(fdev->mr);
	    assert( fdev->mr_key != FI_KEY_NOTAVAIL );
	} else {
	    assert( fdev->mr_key == fi_mr_key(fdev->mr) );
	}
    } else {

	// zhpe support
	if (info->opts.true_fam) {
	    struct fi_zhpe_ext_ops_v1 *ext_ops;
	    void *fi_dest_addr;
	    size_t sa_len;

	    rc = fi_open_ops(&fabric->fid, FI_ZHPE_OPS_V1, 0, (void **)&ext_ops, NULL);
	    if (rc) {
		fi_err(rc, "zhpe open_ops failed");
		goto _err;
	    }

	    // FAM lookup
	    fi_dest_addr = NULL;
	    rc = ext_ops->lookup(zfm->url, &fi_dest_addr, &sa_len);
	    if (rc) {
		fi_err(rc, "fam:%s lookup failed", zfm->url);
		goto _err;
	    }

	    if (1 != (i = fi_av_insert(av, fi_dest_addr, 1, &srv_addr, 0, NULL))) {
		err("fi_av_insert failed, returned %d", i);
		rc = -ENXIO;
		goto _err;
	    }
	    DEBUG_LF(3, "CL attached to FAM device %d url:%s (%s)",
		     id, zfm->url, node);

	} else {
	    // Perform address translation
	    if (1 != (i = fi_av_insertsvc(av, node, port, &srv_addr, 0, NULL))) {
		err("fi_av_insertsvc failed, returned %d", i);
		rc = -ENXIO;
		goto _err;
	    }
	    DEBUG_LF(3, "CL attached to device %d on %s:%d",
		     id, node, service);

	}
	fdev->fi_addr = srv_addr;
    }

    if (!info->single_ep) {
	// Enable endpoint
	rc = fi_enable(ep);
	if (rc) {
	    fi_err(rc, "fi_enable EP failed on prov:%s fab:%s dom:%s id:%d",
		   fi->fabric_attr->prov_name, fi->fabric_attr->name,
		   fi->domain_attr->name, id);
	    goto _err;
	}
    }

    if (lf_srv) {
	DEBUG_LF(3, "%d: Emulated %zuMB FAM on %s:%d if:%s",
		 id, fdev->mr_size/1024/1024, node, service, fi->domain_attr->name);
    }

    return 0;

_err:
    fi_err(rc, "libfabric %s - failed to open connection to FAM id:%d on %s:%s",
	   lf_srv? "server":"client",
	   id, node, port);
    (void)f_conn_close(fdev);
    return rc;
}

int f_conn_enable(struct fid_ep *ep, struct fi_info *fi)
{
    int rc;

    // Enable endpoint
    rc = fi_enable(ep);
    if (rc) {
	fi_err(rc, "failed to enable per-domain enpoint, prov:%s fab:%s dom:%s",
	       fi->fabric_attr->prov_name, fi->fabric_attr->name,
	       fi->domain_attr->name);
    }
    return rc;
}

static ssize_t lf_cq_read(struct fid_cq *cq, struct fi_cq_tagged_entry *fi_cqe,
    ssize_t count, struct fi_cq_err_entry *fi_cqerr)
{
    ssize_t ret = 0, rc;
    struct fi_cq_err_entry err_entry;

    bzero(&err_entry, sizeof(err_entry));

    for (;;) {
        ret = fi_cq_read(cq, fi_cqe, count);
        if (ret >= 0)
            break;
        if (ret == -FI_EAGAIN) {
            ret = 0;
            break;
        }
        if (ret != -FI_EAVAIL) {
            FI_ERROR_LOG(ret, "fi_cq_read");
            break;
        }
        if (!fi_cqerr)
            fi_cqerr = &err_entry;
        rc = fi_cq_readerr(cq, fi_cqerr, 0);
        if (!rc)
            /* Possibly no error? If so, retry. */
            continue;
        if (rc > 0) {
            if (fi_cqerr == &err_entry) 
                ret = -fi_cqerr->err;
            FI_ERROR_LOG(ret, "cq error");
            break;
        }
        if (rc == -FI_EAGAIN)
            /* Possible no error? If so, retry. */
            continue;
        FI_ERROR_LOG(rc, "fi_cq_readerr");
        ret = rc;
        break;
    }

    return ret;
}

static ssize_t lf_completions(struct fid_cq *cq, ssize_t count,
    void (*cq_callback)(void *arg, void *cqe, int err), void *arg)
{
    ssize_t ret = 0, rc, len, i;
    struct fi_cq_tagged_entry cqe[1];
    struct fi_cq_err_entry cqerr;

    /* The verbs rdm code forces all entries to be tagged, but the msg
     * code dosn't support tagged. All I want is the context; so we
     * read a single entry; pass in a fi_cq_tagged; and pull the context
     * off the front. The entries are designed to be compatible, but
     * the API means that is not terribly useful.
     */

    /* If count specified, read up to count entries; if not, all available. */
    for (ret = 0; !count || ret < count;) {
        len = sizeof(cqe)/sizeof(cqe[0]);
        if (count) {
            rc = count - ret;
            if (len > rc)
                rc = len;
        }
        rc = lf_cq_read(cq, cqe, len, (cq_callback ? &cqerr : NULL));
        if (!rc)
            break;
        if (rc >= 0) {
            ret += rc;
            if (cq_callback) {
                for (i = 0; i < rc; i++)
                    cq_callback(arg, cqe + i, 0);
            }
            continue;
        }
        if (rc == -FI_EAGAIN)
            break;
        if (rc != -FI_EAVAIL || !cq_callback) {
            ret = rc;
            break;
        }
        cq_callback(arg, &cqerr, 1);
        ret++;
    }

    return ret;
}

ssize_t lf_check_progress(struct fid_cq *cq, ssize_t *cmp) {
    ssize_t ret = 0, rc;
    ssize_t count = *cmp;

    if (count < 0)
	return -FI_EAVAIL;

    rc = lf_completions(cq, count, NULL, NULL);
    if (rc >= 0) {
	if (count == 0)
	    *cmp += rc;
	else
	    *cmp -= rc;
    } else
	ret = rc;

    return ret;
}

