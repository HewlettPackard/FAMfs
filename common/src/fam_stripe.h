/*
 * Copyright (c) 2017-2020, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAM_STRIPE_H
#define FAM_STRIPE_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#include "famfs_error.h"
#include "famfs_stripe.h"

struct f_layout_;

/* FAM stripe API */

/*
 * Map stripe offset to FAM chunk.
 * Return the pointer to the corresponding N_CHUNK_t structure in stripe->chunks[]
 **/
static inline N_CHUNK_t *get_fam_chunk(N_STRIPE_t *stripe, int stripe_chunk)
{
    N_CHUNK_t *chunk = stripe->chunks;
    int i, n, data;

    data = stripe->d;
    n = data + stripe->p;

    /* find chunk index by D# or (P# + data) */
    for (i = 0; i < n; i++, chunk++) {
	if (stripe_chunk < data) {
	    if (chunk->data == stripe_chunk)
		break;
	} else {
	    if (chunk->parity == (stripe_chunk - data))
		break;
	}
    }
    ASSERT(i < n);
    return chunk;
}

/* Map chunks to physical stripe; allocate N_STRIPE_t on demand. */
int f_map_fam_stripe(struct f_layout_ *lo, N_STRIPE_t **stripe_p, uint64_t s, bool global);
/* Free N_STRIPE_t memory */
void free_fam_stripe(N_STRIPE_t *stripe);
/* Map logical I/O to stripe's physical chunks */
void map_fam_chunks(N_STRIPE_t *stripe, char *buf, off_t offset, size_t length,
    void* (*lookup_mreg_fn)(const char *buf, size_t len, int nid));
/* Start I/O to stripe's data chunks; wr: 0-read, 1-write */
int chunk_rma_start(N_STRIPE_t *stripe, int use_cq, int wr);
/* Wait for I/O that has been started by chunk_rma_start() */
int chunk_rma_wait(N_STRIPE_t *stripe, int use_cq, int wr, uint64_t io_timeout_ms);

#endif /* FAM_STRIPE_H */

