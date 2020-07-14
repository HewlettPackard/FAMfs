/*
 * Copyright (c) 2020, HPE
 *
 * Written by: Oleg Neverovitch, Yann Livis
 */

#ifndef F_ENCODE_RECOVERY_H
#define F_ENCODE_RECOVERY_H

#include <stdint.h>
#include <pthread.h>
#include "list.h"

struct ec_worker_data {
	F_LO_PART_t 		*lp;	/* layout partition pointer */
	struct f_stripe_set	ss;	/* stripe set, ss->stripes released by the worker thread */
};

typedef struct ec_worker_data F_EDR_WD_t; 


typedef enum {
    F_EDR_EMPTY,    // Use for preallocated RQs
    F_EDR_READ,     // lf_read
    F_EDR_CALC,     // parity calcualtors worker pool
    F_EDR_WRITE,    // lf_write
    F_EDR_DONE      // completed
} F_EDR_STATE_t;

struct f_edr_;
typedef int (*F_EDR_CB_t)(struct f_edr_ *rq, void *ctx);

//
// Encode-Decode Request
// While request is being processed, it does not belong to any Q
// lf_read/write will provide *Rq in cq context field
typedef struct f_edr_ {
    struct list_head        list;       // Request list links
    F_EDR_WD_t              wdata;      // Worker data: stripe set and lyaout
    F_EDR_STATE_t           state;      // Request state
    F_EDR_CB_t              completion; // Operation end callback
    ssize_t                 bsize;      // Buffer size
    char                    **bvec;     // Buffer vector of this request
    int                     nvec;       // Number of buffers in the vector
    int                     busy;       // Number of buffers in transition (under I/O or calculations)
                                        //  when this drops to 0, completion cb is called that will 
                                        //  presumably chnage request's state (and queue asignment)
    int                     status;     // General completion status
    int                     nerr;       // Number of errors (only if status != 0)

} F_EDR_t;

//
// EDR operations queue
// Need two: submitted requests and completed ones (an optional Q for pre-allocated RQs)
// New(Rq) or Get(Rq from PreQ) -> SubmitQ -> thread removes it from Sq and starts operation -> 
//   Rq completes -> CB -> CompletedQ -> another thread removes it from Cq -> CB -> etc.
typedef struct f_edr_opq_ {
    pthread_mutex_t     wlock;          // wake signal lock
    pthread_cond_t      wake;           // wake signal
    pthread_spinlock_t  qlock;          // queue ops spinlock 
    struct list_head    queue;          // queue head
    int                 size;           // queue current size
    int                 quit;           // quit flag
} F_EDR_OPQ_t;

/*
 * Submnit Encode/Decode/Recover(/Verify) Request
 *
 * Parmas
 *      lo              layout pointer
 *      ss              stripe set to encode/recover
 *      fvec            failed chunks bitmap, if == 0: encode parities according to layout
 *                          if == <all 1s>: verify stripes
 *      done_cb         callaback function to call when state becomes DONE (or NULL if not needed)A
 *
 *  Returns
 *      0               success
 *      <>0             error              
*/      
int f_edr_sumbit(F_LAYOUT_t *lo, struct f_stripe_set *ss, uint64_t *fvec, F_EDR_CB_t done_cb, void *ctx);


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


