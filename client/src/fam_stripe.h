/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAM_STRIPE_H
#define FAM_STRIPE_H

#include <sys/types.h>
#include <stdint.h>

#include "famfs_stripe.h"


/* FAM API */
N_CHUNK_t *get_fam_chunk(uint64_t ionode_chunk_id, struct n_stripe_ *stripe, int *dest_node_idx);
//void map_stripe_chunks(N_STRIPE_t *stripe, unsigned int extent);
void free_fam_stripe(N_STRIPE_t *stripe);

#endif /* FAM_STRIPE_H */
