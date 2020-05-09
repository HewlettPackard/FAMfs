/*
 * Copyright (c) 2017-2020, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAM_STRIPE_H
#define FAM_STRIPE_H

#include <sys/types.h>
#include <stdint.h>

#include "famfs_stripe.h"

#include "f_layout.h"


/* FAM stripe API */
N_CHUNK_t *get_fam_chunk(N_STRIPE_t *stripe, f_stripe_t s, uint64_t offset);
int f_map_fam_stripe(F_LAYOUT_t *lo, N_STRIPE_t **stripe_p, f_stripe_t s);
void free_fam_stripe(N_STRIPE_t *stripe);

#endif /* FAM_STRIPE_H */
