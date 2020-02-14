/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#include <malloc.h>

#include "famfs_env.h"
#include "famfs_stripe.h"
#include "famfs_lf_connect.h"
#include "fam_stripe.h"


/*
 * Map stripe chunk's in stripe for given extent number.
 * Return node number, i.e. the chunk position in the stripe.
 **/
static void map_stripe_chunks(N_STRIPE_t *stripe, unsigned int extent)
{
    N_CHUNK_t *chunk;
    int chunk_n, chunks;
    int p, parities;

    parities = stripe->p;
    chunks = stripe->d + parities;

    /* Map each chunk in the stripe for this extent */
    chunk = stripe->chunks;
    for (chunk_n = 0; chunk_n < chunks; chunk_n++, chunk++) {
	chunk->node = chunk_n;
	map_stripe_chunk(chunk, extent, chunks, parities);

        chunk->lf_client_idx = chunk_n + stripe->media_id_0;
	chunk->r_event = 0;
	chunk->w_event = 0;
    }

    stripe->extent = extent;
}

/*
 * Map I/O node log chunk to FAM chunk;
 * Ensure the stripe is mapped to the extent;
 * Return the chunk index in the stripe and
 * the pointer to the corresponding N_CHUNK_t structure.
 **/
N_CHUNK_t *get_fam_chunk(uint64_t ionode_chunk_id, struct n_stripe_ *stripe, int *index)
{
    N_CHUNK_t *chunk;
    unsigned int i, data, size;
    unsigned int extent, total_extents, stripe_n, extent_stipes, stripe_chunk_id;
    uint64_t fam_chunk;

    /* Convert I/O node log physical chunk to FAM logical chunk */
    fam_chunk = ionode_chunk_id * stripe->node_size + (unsigned int)stripe->node_id;

    data = stripe->d;
    size = data + stripe->p;
    extent_stipes = stripe->extent_stipes;
    stripe_n = fam_chunk / data;
    stripe_chunk_id = fam_chunk - ((uint64_t)stripe_n * data);
    extent = stripe_n / extent_stipes;

    total_extents = stripe->srv_extents;
    if (extent >= total_extents)
	return NULL; /* ENOSPC */

    /* Is this stripe mapped? */
    if (stripe->extent != extent || index == NULL)
	map_stripe_chunks(stripe, extent);

    /* find chunk index by D# */
    chunk = stripe->chunks;
    for (i = 0; i < size; i++, chunk++) {
	if (chunk->data == stripe_chunk_id)
	    break;
    }
    ASSERT(i < size);

    /* Stripe # in the FAM module */
    stripe->stripe_in_part = stripe_n;

    if (index)
	*index = (int)i;
    return chunk;
}

void free_fam_stripe(N_STRIPE_t *stripe) {
    free(stripe->chunks);
    free(stripe);
}

