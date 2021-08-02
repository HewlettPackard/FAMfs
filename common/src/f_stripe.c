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

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>

#include "f_env.h"
#include "f_error.h"
#include "f_stripe.h"
#include "f_maps.h"
#include "f_stats.h"
#include "f_pool.h"
#include "f_layout.h"
#include "f_lf_connect.h"

/* If defined: limit send queue depth when CQ is used */
//#define IBV_SQ_WR_DEPTH 0 /* 1..8; 0 - sync I/O */


static N_STRIPE_t *alloc_fam_stripe(F_LAYOUT_t *lo)
{
    N_STRIPE_t *stripe;
    N_CHUNK_t *chunks;
    int nchunks;

    stripe = (N_STRIPE_t *) calloc(1, sizeof(N_STRIPE_t));
    if (stripe == NULL)
        return NULL;

    /* array of chunks */
    nchunks = lo->info.chunks;
    chunks = (N_CHUNK_t *) malloc(nchunks*sizeof(N_CHUNK_t));
    if (chunks == NULL)
        goto _free;
    stripe->chunks = chunks;
    stripe->d = lo->info.data_chunks;
    stripe->p = nchunks - stripe->d;
    stripe->chunk_sz = lo->info.chunk_sz;
    stripe->extent_stipes = lo->info.slab_stripes;
    stripe->stripe_0 = 1; /* trigger stripe mapping */
    return stripe;

_free:
    free_fam_stripe(stripe);
    return NULL;
}

/*
 * Map to physical stripe.
 * Set references to pool devices in stripe->chunks[] with D and P chunk order,
 * following Slab map for given layout 'lo' and [global] or [local] stripe 's'
 * depending on the global flag.
 * Allocate N_STRIPE_t on demand.
 * Return -1 if no slab in map or unmapped, -ENOMEM or 0 for success.
 **/
int f_map_fam_stripe(F_LAYOUT_t *lo, N_STRIPE_t **stripe_p, f_stripe_t s, bool global)
{
    N_STRIPE_t *stripe = *stripe_p;
    F_POOL_t *pool = lo->pool;
    F_LO_PART_t *lp = lo->lp;
    F_MAP_t *slabmap = global ? lo->slabmap : lp->slabmap;
    F_SLAB_ENTRY_t *se;
    F_EXTENT_ENTRY_t *ee;
    N_CHUNK_t *chunk;
    uint64_t stripe_0;
    int ext, parities, nchunks, stripe_in_ext;

    if (stripe == NULL) {
	stripe = alloc_fam_stripe(lo);
	if (stripe == NULL)
	    return -ENOMEM;
	stripe->stripe_0--; /* invalid stripe # */
	*stripe_p = stripe;
    }
    stripe->extent = s / stripe->extent_stipes;
    stripe_0 = stripe->extent * stripe->extent_stipes;
    stripe_in_ext = s - stripe_0;
    if (!global) stripe_0 = f_map_prt_to_global(lp->claimvec, stripe_0);
    parities = stripe->p;
    nchunks = stripe->d + parities;

    /* read Slab map */
    se = (F_SLAB_ENTRY_t *)f_map_get_p(slabmap, stripe->extent);
    if (se == NULL) {
	ERROR("%s: failed to get Slab map record for %lu in slab %u",
	      lo->info.name, s, stripe->extent);
	f_print_sm(stderr, slabmap, lo->info.chunks, lo->info.slab_stripes);
	return -1;
    }
    /* TODO: Move the assert below to EXTRA_CHECK */
    if (se->stripe_0 != stripe_0) ERROR("%s:%d:%s: Slab map record:%lu != s:%lu",
	pool->mynode.hostname, pool->dbg_rank, lo->info.name, se->stripe_0, stripe_0);
    ASSERT( se->stripe_0 == stripe_0 ); /* Slab map entry key */
    if (se->mapped == 0) {
	ERROR("%s:%d:%s: failed to get Slab map record:%lu - not mapped!",
	      pool->mynode.hostname, pool->dbg_rank, lo->info.name, stripe_0);
	f_print_sm(stderr, slabmap, lo->info.chunks, lo->info.slab_stripes);
	return -1;
    }

    ee = (F_EXTENT_ENTRY_t *)(se+1);
    chunk = stripe->chunks;
    for (ext = 0; ext < nchunks; ext++, ee++, chunk++) {
	int idx;
	unsigned int media_id = ee->media_id;

	memset(chunk, 0, sizeof(N_CHUNK_t));
	chunk->node = ext;
	map_stripe_chunk(chunk, stripe_in_ext, nchunks, parities);

	chunk->extent = ee->extent;

	/* device lookup in the layout... */
	F_POOLDEV_INDEX_t *pdi = f_find_pdi_by_media_id(lo, media_id);
	if (pdi == NULL) {
	    ERROR("failed to find device %u in layout %s for stripe %lu @%d",
		  media_id, lo->info.name, stripe_0, ext);
	    return -1;
	}
	/* ...and pool 'devlist' */
	F_POOL_DEV_t *pdev = f_pdi_to_pdev(pool, pdi);
	ASSERT( media_id == pdev->pool_index );
	idx = f_pdev_to_indexes(pool, pdev-pool->devlist);
	if (idx < 0) {
	    ERROR("layout %s device [%d] (id:%d) not found in pool, stripe %lu @%d",
		  lo->info.name, media_id, (int)(pdi-lo->devlist), stripe_0, ext);
	    return -1;
	}
	chunk->lf_client_idx = idx;
	/* set reference to pool device */
	chunk->pdev = pdev;

	/* libfabric remote addr */
	chunk->p_stripe0_off = (pdev->extent_start + chunk->extent)*pdev->extent_sz;
	FAM_DEV_t *fdev = &pdev->dev->f;
	chunk->p_stripe0_off += fdev->offset + fdev->virt_addr;
	if (!pool->lf_info->opts.use_cq) {
	    chunk->r_event = fi_cntr_read(fdev->rcnt);
	    chunk->w_event = fi_cntr_read(fdev->wcnt);
	}
    }
    stripe->stripe_0 = stripe_0;
    stripe->stripe_in_part = stripe_in_ext;

    return 0;
}

/* Map logical I/O (offset in stripe and length) to stripe's physical chunks */
void map_fam_chunks(N_STRIPE_t *stripe, char *buf,
		    off_t offset, size_t length,
		    void* (*lookup_mreg_fn)(const char *buf, size_t len, int nid))
{
    unsigned int d, k, nchunks = stripe->p + stripe->d;
    N_CHUNK_t *chunk;
    size_t chunk_sz = stripe->chunk_sz;
    char *usr_buf = buf;
    uint32_t off;

    off = offset % chunk_sz;
    k = offset/chunk_sz;
    for (d = 0; d < nchunks; d++) {
	FAM_DEV_t *fdev;

	/* chunk Dn then Pn */
	chunk = get_fam_chunk(stripe, d);
	if (d < k || chunk->data < 0) {
	    /* before stripe I/O start or parity chunk */
	    chunk->length = 0;
	    chunk->offset = 0;
	} else {
	    /* map data to chunk 'd' */
	    chunk->length = min(length, chunk_sz);
	    length -= chunk->length;
	    chunk->offset = off;
	    off = 0;
	    fdev = &chunk->pdev->dev->f;
	    if (lookup_mreg_fn)
		fdev->local_desc = lookup_mreg_fn(buf, chunk->length, chunk->lf_client_idx);
	    fdev->usr_buf = usr_buf;
	    usr_buf += chunk->length;
	}
    }
}

void free_fam_stripe(N_STRIPE_t *stripe) {
    if (stripe) {
	free(stripe->chunks);
	free(stripe);
    }
}

static inline ssize_t _fi_write(struct fid_ep *ep, void *buf, size_t len, void *desc,
    fi_addr_t dest_addr, uint64_t addr, uint64_t key, void *context)
{
    return fi_write(ep, buf, len, desc, dest_addr, addr, key, context);
}

/* Start I/O to stripe's data chunks */
int chunk_rma_start(N_STRIPE_t *stripe, int use_cq, int wr)
{
    N_CHUNK_t *chunk;
    F_POOL_DEV_t *pdev;
    FAM_DEV_t *fdev;
    f_stripe_t s;
    ssize_t (*fi_rma)(struct fid_ep*, void*, size_t, void*,
		      fi_addr_t, uint64_t, uint64_t, void*);
    fi_addr_t *tgt_srv_addr;
    struct fid_ep *tx_ep = NULL;
    struct fid_cq *tx_cq = NULL;
    void *local_desc, *buf;
    off_t off, chunk_offset;
    ssize_t wcnt;
    size_t chunk_sz;
    uint64_t *event;
    uint32_t len;
    unsigned int i, nchunks, media_id;
    int rc = 0;
    ALLOCA_CHUNK_PR_BUF(pr_buf);

    chunk_sz = stripe->chunk_sz;
    s = stripe->stripe_0 + stripe->stripe_in_part;
    fi_rma = wr? &_fi_write : &fi_read;

    nchunks = stripe->d + stripe->p;
    for (i = 0; i < nchunks; i++) {
	uint64_t cnt = 0;

	chunk = get_fam_chunk(stripe, i);
	len = chunk->length;
	if (len == 0)
	    continue;

	ASSERT(chunk->parity = -1); /* must be a data chunk */
	pdev = chunk->pdev;
	media_id = pdev->pool_index;
	chunk_offset = chunk->offset;
	ASSERT(chunk_offset + len <= (off_t)chunk_sz); /* aligned to chunk boundary */

	/* Do RMA synchronous write/read to/from fdev */
	fdev = &pdev->dev->f;
	tgt_srv_addr = &fdev->fi_addr;
	local_desc = fdev->local_desc;
	buf = fdev->usr_buf;
	tx_ep = fdev->ep;

	/* use lifabric CQ or counters */
	event = wr? &chunk->w_event : &chunk->r_event;
	if (use_cq) {
	    tx_cq = fdev->cq;
	/* } else {
	    struct fid_cntr *cntr = wr? fdev->wcnt : fdev->rcnt;
	    *event = fi_cntr_read(cntr); */
	}

	/* remote address */
	off = chunk_offset + 1ULL * stripe->stripe_in_part * chunk_sz;
	off += chunk->p_stripe0_off; /* +fdev->offset +fdev->virt_addr */

	DEBUG_LVL(7, "%s:%d: %s stripe %lu @%jd - %u/%u/%s "
		  "on device %u(@%lu) len:%u desc:%p off:0x%lx mr_key:%lu",
		  f_get_pool()->mynode.hostname, f_get_pool()->dbg_rank,
		  wr?"write":"read", s, chunk_offset,
		  stripe->extent, stripe->stripe_in_part,
		  pr_chunk(pr_buf, chunk->data, chunk->parity),
		  media_id, (unsigned long)*tgt_srv_addr,
		  len, local_desc, off, fdev->mr_key);

	do {
 ASSERT( ((uint64_t)buf) > 0x10000 );
	    rc = fi_rma(tx_ep, buf, len, local_desc,
			*tgt_srv_addr, off, fdev->mr_key, (void*)buf);
	    if (rc == 0) {
		(*event)++;
	    } else if (rc < 0 && rc != -FI_EAGAIN)
		break;

	    if (use_cq) {
		int ret;

#ifdef IBV_SQ_WR_DEPTH
		if (rc == 0 && *event <= IBV_SQ_WR_DEPTH + cnt)
#else
		if (rc == 0)
#endif
		    break;

		/* If we got FI_EAGAIN, check LF progress to free some slot(s) in send queue */
		do {
		    wcnt = 0;
		    ret = lf_check_progress(tx_cq, &wcnt);
		    if (ret < 0) {
			rc = ret;
			fi_err(rc, "lf_check_progress cnt:%ld error", wcnt);
			break;
		    }
		    if (wcnt)
			cnt += (unsigned)wcnt;
#ifdef IBV_SQ_WR_DEPTH
		} while (*event > IBV_SQ_WR_DEPTH + cnt);
#else
		} while (0);
#endif
	    }
	} while (rc == -FI_EAGAIN);

	fi_err(rc, "%s:%d: fi_%s failed on device %u error",
	       f_get_pool()->mynode.hostname, f_get_pool()->dbg_rank, wr?"write":"read", media_id);

	/* Some I/O already finished due to the limited send queue depth: cnt */
	ASSERT( cnt <= *event );
	*event -= cnt;
    }

    return rc;
}

/* Wait for I/O that has been started by chunk_rma_start() */
int chunk_rma_wait(N_STRIPE_t *stripe, int use_cq, int wr, uint64_t io_timeout_ms)
{
    N_CHUNK_t *chunk = NULL;
    F_POOL_DEV_t *pdev;
    FAM_DEV_t *fdev;
    f_stripe_t s;
    struct fid_cntr *cntr = NULL;
    struct fid_cq *tx_cq = NULL;
    ssize_t wcnt;
    uint64_t *event;
    unsigned int i, nchunks, media_id = 0, chunks_read = 0;
    uint32_t len = 0;
    int rc = 0;
    struct timespec start = now();
    ALLOCA_CHUNK_PR_BUF(pr_buf);

    s = stripe->stripe_0 + stripe->stripe_in_part;
    nchunks = stripe->d + stripe->p;

    for (i = 0; i < nchunks; i++) {
	chunk = get_fam_chunk(stripe, i);
	len = chunk->length;
	if (len == 0)
	    continue;

	event = wr? &chunk->w_event : &chunk->r_event;
	if (*event == 0)
	    continue;

	pdev = chunk->pdev;
	media_id = pdev->pool_index;
	fdev = &pdev->dev->f;

	/* use lifabric CQ or counters */
	if (use_cq) {
	    tx_cq = fdev->cq;
	    wcnt = *event;
	    /* TODO: Implement timeout */
	    do {
		rc = lf_check_progress(tx_cq, &wcnt);
	    } while (rc >= 0 && wcnt > 0);
	    if (rc == 0)
		*event = 0;
	} else {
	    cntr = wr? fdev->wcnt : fdev->rcnt;
	    rc = fi_cntr_wait(cntr, *event, io_timeout_ms);
	}

	if (rc == -FI_ETIMEDOUT) {
	    err("%s:%d: fi_%s timeout stripe %lu - %u/%u/%s on device %u len:%u",
		f_get_pool()->mynode.hostname, f_get_pool()->dbg_rank, wr?"write":"read",
		s, stripe->extent, stripe->stripe_in_part,
		pr_chunk(pr_buf, chunk->data, chunk->parity),
		media_id, len);
	    break;
#if 0
	} else if (rc == -FI_EAVAIL) { /* 259 */
	    err("FI_EAVAIL on %s", f_get_pool()->mynode.hostname);
	    break;
#endif
	} else if (rc) {
	    uint64_t count;
	    int err;

	    if (use_cq) {
		count = *event - (uint64_t)wcnt;
		err = errno;
	    } else {
		count = fi_cntr_read(cntr);
		err = (int)fi_cntr_readerr(cntr);
		/* reset counter error */
		int ret = fi_cntr_seterr(cntr, 0);
		if (ret)
		    err("failed to reset counter error!");
	    }
	    err("%s:%d: fi_%s stripe %lu has %lu error(s):%d/%d "
		    "- %u/%u/%s on device %u count:%lu/%lu",
		    f_get_pool()->mynode.hostname, f_get_pool()->dbg_rank, wr?"write":"read",
		    s, count, rc, err,
		    stripe->extent, stripe->stripe_in_part,
		    pr_chunk(pr_buf, chunk->data, chunk->parity),
		    media_id, count, *event);
	    break;
	}
	chunks_read++;
    }
    DEBUG_LVL(7, "%s:%d: %s completed %u chunks in stripe %lu - time:%lu",
	  f_get_pool()->mynode.hostname, f_get_pool()->dbg_rank,
	  wr?"write":"read", chunks_read, s, elapsed(&start));

    return rc;
}

