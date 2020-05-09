/*
 * Copyright (c) 2017-2020, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAM_STRIPE_H
#define FAM_STRIPE_H

#include <sys/types.h>
#include <stdint.h>

#include "famfs_error.h"
#include "famfs_stripe.h"

struct f_layout_;

/* FAM stripe API */

/*
 * Map stripe offset to FAM chunk.
 * Return the pointer to the corresponding N_CHUNK_t structure in stripe->chunks[]
 **/
static inline N_CHUNK_t *get_fam_chunk(N_STRIPE_t *stripe, uint64_t offset)
{
    N_CHUNK_t *chunk;
    unsigned int i, n, data;
    int stripe_chunk;

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

/* Map chunks to physical stripe; allocate N_STRIPE_t on demand. */
int f_map_fam_stripe(struct f_layout_ *lo, N_STRIPE_t **stripe_p, uint64_t s);
/* Free N_STRIPE_t memory */
void free_fam_stripe(N_STRIPE_t *stripe);

#endif /* FAM_STRIPE_H */
