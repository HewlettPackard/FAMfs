/*
 * Copyright (c) 2020, HPE
 *
 * Written by: Oleg Neverovitch, Yann Livis
 */

#ifndef F_ENCODE_RECOVERY_H
#define F_ENCODE_RECOVERY_H

#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>
#include <inttypes.h>
#include <rdma/fabric.h>

#include "famfs_env.h"
#include "famfs_ktypes.h"
#include "famfs_bitops.h"
#include "famfs_lfa.h"
#include "famfs_stripe.h"
#include "f_map.h"
#include "f_dict.h"
#include "f_wpool.h"
#include "list.h"

#define F_EDR_PAINI 16  // Initial preallocated request que size
#define F_EDR_PAMAX 64  // Max preallocated q size

#define TMO_1S 1000000L // 1 sec in usec

struct ec_worker_data {
	F_LO_PART_t 		*lp;	/* layout partition pointer */
	struct f_stripe_set	ss;	/* stripe set, ss->stripes released by the worker thread */
};

typedef struct ec_worker_data F_EDR_WD_t; 


typedef enum {
    F_EDR_FREE,     // Use for preallocated RQs
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
// I/O buffer is allocated "chunks first", i.e. if we allocated 16 8D+2P stripes with 1M chunk
// the memory layout is: <s0.c0*1M><s0.c1*1M>...<s0.c9*1M><s1.c0*1M>...<s15.c9*1M>
// This way any I/O can operate on a contigious buffer within the same device up to
// <max allocated stripes>*<chunk size> in length
typedef struct f_edr_ {
    struct list_head        list;       // Request list links
    struct f_stripe_set     *ss;        // Stripe set of this request
    F_LAYOUT_t              *lo;        //   and Layout it belongs to
    uint64_t                fvec;       // Bitmap of failed chunks
    F_EDR_WD_t              wdata;      // Worker data: stripe set and lyaout
    F_EDR_STATE_t           state;      // Request state
    F_EDR_CB_t              opend;      // Operation end callback
    F_EDR_CB_t              completion; // Request completion callback
    N_STRIPE_t              *sattr;     // FAM stripe attributes
    void                    *ctx;       // conext parameter for CB call
    int                     sall;       // Allocated number of stripes
    int                     scnt;       // Single IO "depth": stripes count to rd/wr at once
    int                     scur;       // Stripe being processed
    char                    *iobuf;     // Buffer for this request: sall*<c.size>*<c.cnt>
    struct fid_mr           *buf_mr;    // Operand buffer MR
    void                    *buf_dsc;   //    and its descriptor
    int                     nvec;       // Number of buffers in the vector
    int                     ready;      // All chunks submited
    atomic_t                busy;       // Number of buffers in transition (under I/O or calculations)
                                        //  when this drops to 0, completion cb is called that will 
                                        //  presumably chnage request's state (and queue asignment)
    int                     err;        // Last errno read from CQ
    int                     prov_err;   // Last provider-specific error from CQ
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
    pthread_t           tid;            // owner thread's id
    struct list_head    qhead;          // queue head
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
 *      done_cb         callaback function to call when state becomes DONE (or NULL if not needed)
 *      ctx             context for CB
 *
 *  Returns
 *      0               success
 *      <>0             error              
*/      
int f_edr_submit(F_LAYOUT_t *lo, struct f_stripe_set *ss, uint64_t *fvec, F_EDR_CB_t done_cb, void *ctx);


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

int f_edr_quit();
int f_edr_init();

#endif


