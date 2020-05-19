/*
 * Copyright (c) 2020, HPE
 *
 * Written by: Oleg Neverovitch, Yann Livis
 */

#ifndef F_ENCODE_RECOVERY_H
#define F_ENCODE_RECOVERY_H

struct ec_worker_data {
	F_LO_PART_t 		*lp;	/* layout partition pointer */
	struct f_stripe_set	ss;	/* stripe set, ss->stripes released by the worker thread */
};

/*
 * Recover a set of stripes worker function
 *
 * Params
 * 	cmd		command to execute
 * 	arg		pointer to the ec_worker_data struct, must be released by the worker
 * 			after all is processed
 * 	thread_id	assigned worker's thread id
 *
 * Returns
 * 	0		success
 * 	-EAGAIN		not enough resources to process cmd, resubmit this entry 
 * 	<>0		error
 */
int f_recover_stripes(F_WTYPE_t cmd, void *arg, int thread_id);

/*
 * Encode a set of stripes worker function
 *
 * Params
 * 	cmd		command to execute
 * 	arg		pointer to the ec_worker_data struct, must be released by the worker
 * 			after all is processed
 * 	thread_id	assigned worker's thread id
 *
 * Returns
 * 	0		success
 * 	-EAGAIN		not enough resources to process cmd, resubmit this entry 
 * 	<>0		error
 */
int f_encode_stripes(F_WTYPE_t cmd, void *arg, int thread_id);

/*
 * Verify a set of stripes worker function
 *
 * Params
 * 	cmd		command to execute
 * 	arg		pointer to the ec_worker_data struct, must be released by the worker
 * 			after all is processed
 * 	thread_id	assigned worker's thread id
 *
 * Returns
 * 	0		success
 * 	-EAGAIN		not enough resources to process cmd, resubmit this entry 
 * 	<>0		error
 */
int f_verify_stripes(F_WTYPE_t cmd, void *arg, int thread_id);

/*
 * Submit a set of committed stripes for EC encoding. Called from f_commit_stripe().
 * All stripe #s n the set are expected to be global and to belong to the local allocator partition.
 *
 * Params
 * 	lo		layout pointer
 * 	ss		Stripe set object, contains global stripes to be encoded
 *
 * Returns
 * 	0		success
 * 	<>0		error
 */
int f_submit_encode_stripes(F_LAYOUT_t *lo, struct f_stripe_set *ss);

#endif


