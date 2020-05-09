/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>

#include "famfs_env.h"
#include "famfs_error.h"
#include "fam_stripe.h"
#include "famfs_maps.h"
#include "f_pool.h"
#include "f_layout.h"
#include "famfs_lf_connect.h"


/*
 * Map stripe offset to FAM chunk.
 * Return the pointer to the corresponding N_CHUNK_t structure in stripe->chunks[]
 **/
N_CHUNK_t *get_fam_chunk(N_STRIPE_t *stripe, f_stripe_t s, uint64_t offset)
{
    N_CHUNK_t *chunk;
    unsigned int i, data, n, stripe_chunk;

    data = stripe->d;
    ASSERT( offset < data*stripe->chunk_sz);
    n = data + stripe->p;

    /* find chunk index by D# */
    stripe_chunk = offset / stripe->chunk_sz;
    chunk = stripe->chunks;
    for (i = 0; i < n; i++, chunk++) {
	if (chunk->data == stripe_chunk)
	    break;
    }
    ASSERT(i < n);
    return chunk;
}

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

/* Set references to pool devices in stripe->chunks[] and sort them by d+P */
int f_map_fam_stripe(F_LAYOUT_t *lo, N_STRIPE_t **stripe_p, f_stripe_t s)
{
    N_STRIPE_t *stripe = *stripe_p;
    F_POOL_t *pool = lo->pool;
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
    parities = stripe->p;
    nchunks = stripe->d + parities;
    stripe_in_ext = s - stripe_0;

    /* read Slab map */
    se = (F_SLAB_ENTRY_t *)f_map_get_p(lo->slabmap, stripe->extent);
    if (se == NULL) {
	ERROR("failed to get Slab map record for %lu in slab %u",
	      s, stripe->extent);
	return -1;
    }
    ASSERT( se->stripe_0 == stripe_0 ); /* Slab map entry key */
    if (se->mapped == 0) {
	ERROR("failed to get Slab map record:%lu - not mapped!", stripe_0);
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
    }
    stripe->stripe_0 = stripe_0;
    stripe->stripe_in_part = stripe_in_ext;

    return 0;
}

void free_fam_stripe(N_STRIPE_t *stripe) {
    free(stripe->chunks);
    free(stripe);
}

