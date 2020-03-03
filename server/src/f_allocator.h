/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Yann Livis
 */

#ifndef F_ALLOCATOR_H
#define F_ALLOCATOR_H

/* Start/stop allocators routines */
int f_start_allocator_threads(void);
int f_stop_allocator_threads(void);

/* Stripe allocation API */
int f_get_stripe(F_LAYOUT_t *lo, f_stripe_t match_stripe, struct f_stripe_set *ss);
int f_put_stripe(F_LAYOUT_t *lo, struct f_stripe_set *ss);

#endif
