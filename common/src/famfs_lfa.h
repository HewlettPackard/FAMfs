/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAMFS_LF_CONNECT_H
#define FAMFS_LF_CONNECT_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_ext_zhpe.h>
#include <mpi.h>

#include "famfs_env.h"

#define F_LFA_MAXV  32                      // max size of atomic vector
#define F_LFA_MAXB  8                       // max number of atmoic blobs

//
// Atomic (data) Blob Descriptor
//
typedef struct f_lfa_abd_{

    struct f_lfa_desc_      *lfa;           // Backpointer to the LFA Descriptor of this blob
    uint64_t                flags;          // Status and mode flags

    uint64_t                key;            // This blob's protection key: same for in/out/local

    int                     ncnt;           // Number of remote nodes exporting this blob
    char                    **nlist;        // Node names list
    fi_addr_t               *trg_adr;       // Atomic ops target addresses vector (includig loclal)

    size_t                  bsize;          // Size of in/out/data buffers
    void                    *in_buf;        // Input buffer for all atomic ops, NULL if this is server-only
    struct fid_mr           *in_mr;         // Input buffer MR
    void                    *in_mr_dsc;     //    and its descriptor
    void                    *out_buf;       // Output buffer for _compare_ and _fetch_ ops, NULL if server-only
    struct fid              *out_mr;        // Output buffer MR
    void                    *out_mr_dsc;    //    and its descriptor
    void                    *srv_buf;       // Server buffer, NULL if this is client-only
    struct fid              *srv_mr;        // Server buffer MR
    void                    *srv_dsc;       //    and its descriptor

} F_LFA_ABD_t;

//
// Atomic ops descriptor
//
typedef struct f_lfa_desc_ {

    pthread_mutex_lock_t    lock;           // Big Bad Lock for RBD chain
    F_LFA_ABD_t             *blobs;         // Pointer to the firts blob descriptor in chain (NULL terminated)
    struct fid_ep           *ep;            // Libfabric endpoint for atomic TXs
    struct fid_cq           *cq;            // Completion queue for atomic ops

} F_LFA_DESC_t;

//
// Create atomic blob, open new endpoint, translate all addresses etc
//   In
//      fab     fabric object - must be initialized already
//      dom     domain object - see above
//   Out
//      plfa    address of a pointer to hold created LFA structure
//   Return
//      0       success
//    <>0       error, see errno/fi_errno
//
int f_lfa_create(struct fid_fabric *fab, struct fid_domain *dom, F_LFA_DESC_t **plfa);

//
// Register local buffers for remote atomic blob access
// To be called only by nodes that provide memory for atomic ops (servers)
//   In
//      lfa:        LFA descriptor
//      key:        protection key to be used for MR
//      bsize:      size of the memory buffer to be served out
//   Inout
//      pbuf:       address of a pointer to data buffer to be served out
//                  if *pbuf == NULL, memory will be allocated
//   Out
//      pbdb:       (new) blob desriptor pointer
//   Return
//      0           success
//      EEXISTS     a blob with this key already registered
//      EINVAL      input buffer exists and its size != bsize
//      <>0         error
//
int f_lfa_register(F_LFA_DESC_t *lfa, uint64_t key, size_t bsize, void **pbuf, F_LFA_ABD_t **pabd);

//
// Attach to remote atomic blob
// To be used by any and all nodes that performs atomic ops (clients). This list may or may
// not include servers. I.e. servers could be subset of clients
//   In
//      lfa:        LFA descriptor
//      key:        remote memory protection key
//      nlist:      list of remote nodes names to perform atomic ops on (servers)
//      bsize:      size of the input memory buffer
//   Inout
//      ibuf:       address of a pointer to input buffer
//                  if *ibuf == NULL, memory will be allocated
//   Out
//      pbdb:       (new) blob desriptor pointer
//   Return
//      0           success
//      EEXISTS     a blob with this key already attached
//      EINVAL      remote buffer exists and its size != bsize
//      <>0         error
//
int f_lfa_attach(F_LFA_DESC_t *lfa, uint64_t key, char **nlist, size_t bsize, void **ibuf, F_LFA_ABD_t **pabd);

//
// Detach from remote atomic blob
//  If free != 0, free all memory buffers 
//
int f_lfa_detach(F_LFA_ABD_t *abd, int free);

//
// Deregister local buffers and free all lf resources
//  If free != 0, free all memory buffers 
//
int f_lfa_deregister(F_LFA_ABD_t *abd, int free);

//
// Close evrything lf-related, free memory 
//
int f_lfa_destroy(F_LFA_DESC_t *lfa);

//
// Get an address of the operand in the atomic blob 
//  lfa: LFA header
//  off:   offset of the operand
// If off is outside of the blob, NULL is returned
//
int *f_lfa_getpw(F_LFA_ABD_t *abd, off_t off);
long *f_lfa_getpl(F_LFA_ABD_t *abd, off_t off);

//
// Get an index of the operand in the atomic blob 
//  abd:   blob descriptor
//  op_p:  address of the operand
// If op_p is outside of the blob, -1 is returned
//
int f_lfa_getiw(F_LFA_ABD_t *abd, int *op_p);
int f_lfa_getilw(F_LFA_ABD_t *abd, long *op_p);

//
// Atomic add(w|l), inc(w|l), dec(w|l), no result
//  abd:    blob descriptor
//  trg_ix: index of target node
//  off:   offset of the operand
//  val:    value to add
// Return:
//   0      - Success
//   !=0    - check errno and fi_errno
//
int f_lfa_addw(F_LFA_ABD_t *abd, int trg_ix, off_t off, int val);
int f_lfa_addl(F_LFA_ABD_t *abd, int trg_ix, off_t off, long val);
#define f_lfa_subw(l, t, i,v) f_lfa_addw(l, t, i, -(v))
#define f_lfa_subl(l, t, i,v) f_lfa_addl(l, t, i, -(v))
#define f_lfa_incw(l, t, i) f_lfa_addw(l, t, i, 1)
#define f_lfa_incl(l, t, i) f_lfa_addl(l, t, i, 1)
#define f_lfa_decw(l, t, i) f_lfa_addw(l, t, i, -1)
#define f_lfa_decl(l, t, i) f_lfa_addl(l, t, i, -1)

//
// Atomic put
//  abd:    blob descriptor
//  trg_ix: index of target node
//  size:   size (in bytes) to transfer
//  src:    data source pointer, NULL if abd's input buffer to be used directly
//          If src != NULL, the data will be memmove'ed to abd's buffer prior to
//          issuing fi_atomic call
//
int f_lfa_put(F_LFA_ABD_t *abd, int trg_ix, size_t size, void *src);

//
// Atomic get
//  abd:    blob descriptor
//  trg_ix: index of target node
//  size:   size (in bytes) to transfer
//  src:    target data buffer, NULL if abd's output buffer to be used directly
//          If trgc != NULL, the data will be memmove'ed from abd's buffer after
//          fi_atomic call completes
//
int f_lfa_get(F_LFA_ABD_t *abd, int trg_ix, size_t size, void *trg);

// Atmic add_and_fetch(w|l): add and fetch old (remote) value
//  abd:    blob descriptor
//  trg_ix: index of target node
//  off:   offset of the operand
//  val:    value to add
//  old:    pointer to the fetched value
int f_lfa_aafw(F_LFA_ABD_t *abd, int trg_ix, off_t off, int val, int *old);
int f_lfa_aafl(F_LFA_ABD_t *abd, int trg_ix, off_t off, long val, long *old);
#define f_lfa_safw(l, t, i, v, o) f_lfa_addw(l, t, i, -(v), o)
#define f_lfa_safl(l, t, i, v, o) f_lfa_addl(l, t, i, -(v), o)
#define f_lfa_iafw(l, t, i, v, o) f_lfa_addw(l, t, i, 1, o)
#define f_lfa_iafl(l, t, i, v, o) f_lfa_addl(l, t, i, 1, o)
#define f_lfa_dafw(l, t, i, v, o) f_lfa_addw(l, t, i, -1, o)
#define f_lfa_dafl(l, t ,i, v, o) f_lfa_addl(l, t, i, -1, o)

//
// Atomic compare_and_swap: compare expected value with remote, if equal set new else return remote value found
//  abd:    blob descriptor 
//  trg_ix: index of target node
//  off:    offset of the operand
//  exp:    value to check on remote side
//  val:    new value to set
//  rval:   pointer to the fetched value, only valid if EGAIN (see below)
// Return:
//  0       - success
//  EAGAIN  - remote compare failed, check *rval for the remote value
//  !=0     - check errno
//  
int f_lfa_casw(F_LFA_ABD_t *abd, int trg_ix, off_t off, int val, int exp, int *rval);
int f_lfa_casl(F_LFA_ABD_t *abd, int trg_ix, off_t off, long val, long exp, long *rval);

// 
// Atomic bit_find_clear_and_set: find first clear bit, starting from offset, and set it
// Note of for the efficiency sake, there's no 64-bit (long) variant of this function.
// We assume that wotking on words (32-bit) gives us less contention for a given place in memory
//  abd:    blob descriptor
//  trg_ix: index of target node
//  off:    offset of the 1st word of the bir field
//  boff:   intitial bit offset (hopefully it will be clear!)
//  bsize:  max number of bits to scan
// Return:
//  >= 0:     - offset of the found clear bit
//  -ENOSPACE - no free bits found
//  <0:       - uh-oh.... 
//
int f_lfa_bfcs(F_LFA_ABD_t *abd, int trg_ix, off_t off, int boff, int bsize);

// 
// Cluster-wide spinlock acquire
//  abd:    blob descriptor
//  trg_ix: index of target node
//  off:    offset of atomic long used for spinlock
// Return:
//  =  0:   - successfully acquired lock
//  != 0:   - check errno
//
int f_lfa_spinlock(F_LFA_ABD_t *abd, int trg_ix, off_t off);

// 
// Cluster-wide spinlock try-to=lock
//  abd:    blob descriptor
//  trg_ix: index of target node
//  off:    offset of atomic long used for spinlock
// Return:
//  = 0:     - successfully acquired lock
//  = EAGAIN - already lock by someone
//  != 0:    - check errno
//
int f_lfa_trylock(F_LFA_ABD_t *abd, int trg_ix, off_t off);

// 
// Cluster-wide spinlock release 
//  abd:    blob descriptor
//  trg_ix: index of target node
//  off:    offset of atomic long used for spinlock
// Return:
//  =  0:   - successfully released lock
//  != 0:   - check errno
//
int f_lfa_unlock(F_LFA_ABD_t *abd, int trg_ix, off_t off);

// 
// Server-side counters block & TOC create
//  abd:     blob descriptor
//  max_cnt: max number oc counters in the TOC
// Return:
//  =  0:   - success
//  != 0:   - check errno
//
int f_lfa_toc_register(F_LFA_ABD_t *abd, unsigned max_cnt);

// 
// Server-side counters block & TOC free
//  abd:     blob descriptor
// Return:
//  =  0:   - successfully acquired lock
//  != 0:   - check errno
//
int f_lfa_toc_deregister(F_LFA_ABD_t *abd);

// 
// Client-side counters block & TOC create
//  abd:     blob descriptor
// Return:
//  =  0:   - successfully acquired lock
//  != 0:   - check errno
//
int f_lfa_toc_attach(F_LFA_ABD_t *abd);

//
// Client-side counters block & TOC free
//  abd:     blob descriptor
// Return:
//  =  0:   - successfully acquired lock
//  != 0:   - check errno
//
int f_lfa_toc_detach(F_LFA_ABD_t *abd);

// 
// Client-side counters block & TOC: allocate new counter
// Returns an offset of newly allocated counter to be used in f_lfa_inc/dec etc
//  abd:     blob descriptor
//  trg_ix: index of target node
// Return:
//  = (off_t)-ENOSPACE: - no more free slots
//  = (off_t)-1:        - check errno
//  >=0:                - offset of the new counter
//
off_t f_lfa_toc_get(F_LFA_ABD_t *abd, int trg_ix);

//
// Client-side counters block & TOC: release the counter
//  abd:     blob descriptor
//  max_cnt: max number oc counters in the TOC
int f_lfa_toc_free(F_LFA_ABD_t *abd, int trg_ix, off_t off);

