/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAMFS_LFA_H
#define FAMFS_LFA_H

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
#include <rdma/fi_atomic.h>

//#include <mpi.h>

//#include "famfs_env.h"

#define F_LFA_MAX_AVB  1024                 // max size of atomic vector (bytes)
#define F_LFA_MAX_BLOB 8                    // max number of atmoic blobs
#define F_LFA_MAX_BIT  (F_LFA_MAX_AVB/sizeof(uint32_t)*8) // max bit field length
#define F_LFA_LK_BASE  100000

typedef uint64_t FI_UINT64_t;
typedef uint32_t FI_UINT32_t;

typedef struct f_lfa_slist_ {
    char    *name;
    char    *service;
    size_t  bsz;
    off_t   bof;
} F_LFA_SLIST_t;

//
// Atomic (data) Blob Descriptor
//
typedef struct f_lfa_abd_{

    struct {
        union {
            uint64_t            in64[F_LFA_MAX_AVB/sizeof(uint64_t)];
            uint32_t            in32[F_LFA_MAX_AVB/sizeof(uint32_t)];
        };
        union {
            uint64_t            out64[F_LFA_MAX_AVB/sizeof(uint64_t)];
            uint32_t            out32[F_LFA_MAX_AVB/sizeof(uint32_t)];
        };
    }                       ops;            // Atomic functions local operands
    uint64_t                ops_key;        // This blob's local protecion key
    struct fid_mr           *ops_mr;        // Operand buffer MR
    void                    *ops_mr_dsc;    //    and its descriptor

    struct f_lfa_desc_      *lfa;           // Backpointer to the LFA Descriptor of this blob
    struct f_lfa_abd_       *next;          // next blob in chain
    uint64_t                flags;          // Status and mode flags

    int                     nsrv;           // Number of remote nodes exporting this blob
    F_LFA_SLIST_t           *slist;         // Node names list
    fi_addr_t               *tadr;          // Atomic ops target addresses vector (includig loclal)

    void                    *srv_buf;       // Server buffer, NULL if this is client-only
    size_t                  srv_bsz;
    struct fid_mr           *srv_mr;        // Server buffer MR
    uint64_t                srv_key;        // Server key

    void                    *in_buf;        // Input buffer for all atomic ops, NULL if this is server-only
    size_t                  in_bsz;         // Size of in/out/data buffers
    struct fid_mr           *in_mr;         // Input buffer MR
    void                    *in_mr_dsc;     //    and its descriptor

} F_LFA_ABD_t;

//
// Atomic ops descriptor
//
typedef struct f_lfa_desc_ {

    pthread_mutex_t         lock;           // Big Bad Lock for ABD chain
    F_LFA_ABD_t             *blobs;         // Pointer to the firts blob descriptor in chain (NULL terminated)
    struct fid_fabric       *fab;           // Fabric (if created by f_lfa_mydom() call)
    struct fi_info          *fi;            // fi_getinfo output
    struct fid_ep           *ep;            // Libfabric endpoint for atomic TXs
    struct fid_domain       *dom;           // Domain
    struct fid_av           *av;            // AV 
    struct fid_cq           *cq;            // Completion Queue for atomic ops
    struct fi_cq_tagged_entry cqe;          // CQ entry

} F_LFA_DESC_t;

//
// Make LFA-specific fi domain on specified address (name) and port (svc)
//
F_LFA_DESC_t * f_lfa_mydom(struct fi_info *fi, char *my_name, char *my_svc);

//
// Create atomic blob, open new endpoint, translate all addresses etc
//   In
//      dom     domain object - see above
//      noav    if = 1, do not create AV
//      fi      fabric info obtained when domain was created
//   Out
//      plfa    address of a pointer to hold created LFA structure
//   Return
//      0       success
//    <>0       error, see errno/fi_errno
//
int f_lfa_create(struct fid_domain *dom, struct fid_av *av, struct fi_info *fi, F_LFA_DESC_t **plfa);

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
//      pabd:       (new) blob desriptor pointer
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
int f_lfa_attach(F_LFA_DESC_t *lfa, uint64_t key, F_LFA_SLIST_t *lst, int lcnt, size_t bsize, void **ibuf, F_LFA_ABD_t **pabd);

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
// Atomic add(w|l), inc(w|l), dec(w|l), no result
//   abd:    blob descriptor
//   trg_ix: index of target node
//   off:    offset of the operand
//   val:    value to add
// Return:
//   0      - Success
//   !=0    - check errno and fi_errno
//
int f_lfa_addl(F_LFA_ABD_t *abd, int trg_ix, off_t off, long val);
int f_lfa_addw(F_LFA_ABD_t *abd, int trg_ix, off_t off, int val);
#define f_lfa_subw(l, t, i,v) f_lfa_addw(l, t, i, -(v))
#define f_lfa_subl(l, t, i,v) f_lfa_addl(l, t, i, -(v))
#define f_lfa_incw(l, t, i)   f_lfa_addw(l, t, i, 1)
#define f_lfa_incl(l, t, i)   f_lfa_addl(l, t, i, 1)
#define f_lfa_decw(l, t, i)   f_lfa_addw(l, t, i, -1)
#define f_lfa_decl(l, t, i)   f_lfa_addl(l, t, i, -1)

//
// Atomic global-buffer mapped add(w|l), inc(w|l), dec(w|l), no result
//   abd:    blob descriptor
//   goff:   offset in the global buffer
//   val:    value to add
// Return:
//   -EINVAL - global offset is beyond all remote buffers
//   0       - Success
//   !=0     - check errno and fi_errno
// Side effects:
//   NONE: Local input buffer is NOT updated!
//
//   Note that this family of atomic calls does not update local buffer
//   It does not even require one to be allocated - this is purely remote
//   update operations (like for e.g. counters on a master node)
//
int f_lfa_gaddl(F_LFA_ABD_t *abd, off_t goff, long val);
int f_lfa_gaddw(F_LFA_ABD_t *abd, off_t goff, int val);
#define f_lfa_gsubw(l, g, v) f_lfa_gaddw(l, g, -(v))
#define f_lfa_gsubl(l, g, v) f_lfa_gaddl(l, g, -(v))
#define f_lfa_gincw(l, g)    f_lfa_gaddw(l, g, 1)
#define f_lfa_gincl(l, g)    f_lfa_gaddl(l, g, 1)
#define f_lfa_gdecw(l, g)    f_lfa_gaddw(l, g, -1)
#define f_lfa_gdecl(l, g)    f_lfa_gaddl(l, g, -1)


//
// Write atomic blob to server
//   abd:    blob descriptor
//   trg_ix: index of target node
//   size:   size (in bytes) to transfer
//   off:    offset from the beginning of server buffer
//
//   <src>:  data source pointer is in_buf registered in lfa_attach call, if noting 
//           was registered, -ENOMEM will be returnd
//
int f_lfa_put(F_LFA_ABD_t *abd, int trg_ix, off_t off, size_t size);

//
// Write atomic blob to server, using global-buffer offset
//   abd:    blob descriptor
//   size:   size (in bytes) to transfer
//   goff:   offset in global buffer
//
//   <src>:  data source pointer is in_buf registered in lfa_attach call, if noting 
//           was registered, -ENOMEM will be returnd
// NOTE:
//   <size> cannot span accross multiple servers' buffers, i.e. all data being transfered
//   must belong to the same server that posesses @goff offset in global buffer
//
int f_lfa_gput(F_LFA_ABD_t *abd, off_t goff, size_t size);

//
// Read atmomic blob from server
//   abd:    blob descriptor
//   trg_ix: index of target node
//   size:   size (in bytes) to transfer
//   off:    offset from the beginning of server buffer
//
//   <trg>:  data target pointer is in_buf registered in lfa_attach call, if noting
//           was registered, -ENOMEM will be returnd
int f_lfa_get(F_LFA_ABD_t *abd, int trg_ix, off_t off, size_t size);

//
// Read atmomic blob from server, using global-buffer offset
//   abd:    blob descriptor
//   size:   size (in bytes) to transfer
//   goff:   offset in global buffer
//
//   <trg>:  data target pointer is in_buf registered in lfa_attach call, if noting
//           was registered, -ENOMEM will be returnd
// NOTE:
//   <size> cannot span accross multiple servers' buffers, i.e. all data being transfered
//   must belong to the same server that posesses @goff offset in global buffer
//
int f_lfa_gget(F_LFA_ABD_t *abd, off_t goff, size_t size);

//
// Atomic add_and_fetch(w|l): fetch remote memmory and THEN add value to that remote location
//   abd:    blob descriptor
//   trg_ix: index of target node
//   off:    offset of the operand
//   val:    value to add
//   old:    adddress to put the "old" value, fetched from remote
//
int f_lfa_aafw(F_LFA_ABD_t *abd, int trg_ix, off_t off, int val, int *old);
int f_lfa_aafl(F_LFA_ABD_t *abd, int trg_ix, off_t off, long val, long *old);
#define f_lfa_safw(l, t, i, v, o) f_lfa_aafw(l, t, i, -(v), o)
#define f_lfa_safl(l, t, i, v, o) f_lfa_aafl(l, t, i, -(v), o)
#define f_lfa_iafw(l, t, i, v, o) f_lfa_aafw(l, t, i, 1, o)
#define f_lfa_iafl(l, t, i, v, o) f_lfa_aafl(l, t, i, 1, o)
#define f_lfa_dafw(l, t, i, v, o) f_lfa_aafw(l, t, i, -1, o)
#define f_lfa_dafl(l, t ,i, v, o) f_lfa_aafl(l, t, i, -1, o)

//
// Atomic global-buffer mapped add_and_fetch(w|l): fetch remote memmory, add value to that location
// and update local bufer to reflect that operation (if successfull)
//   abd:    blob descriptor
//   goff:   offset in the global buffer
//   val:    value to add
// Return:
//   -EINVAL - global offset is beyond all remote buffers or local buffer
//   0       - Success
//   !=0     - check errno and fi_errno
// Side effects:
//   Local input buffer IS updated if remote operation was successfull
//
//   Note that this family of atomic calls updates local buffer, so it has
//   to be allocated beforehand in lfa_attach() call. Uponn successfull completion
//   of fabric atomic operaation, input parameter's value will be added to value 
//   retrieved from fabric and result written into local buffer @goff. 
//   No update will be made if fi_atomic call failed.
//
int f_lfa_gaafw(F_LFA_ABD_t *abd, off_t goff, int val);
int f_lfa_gaafl(F_LFA_ABD_t *abd, off_t goff, long val);
#define f_lfa_gsafw(l, g, v) f_lfa_gaafw(l, g, -(v))
#define f_lfa_gsafl(l, g, v) f_lfa_gaafl(l, g, -(v))
#define f_lfa_giafw(l, g)    f_lfa_gaafw(l, g, 1)
#define f_lfa_giafl(l, g)    f_lfa_gaafl(l, g, 1)
#define f_lfa_gdafw(l, g)    f_lfa_gaafw(l, g, -1)
#define f_lfa_gdafl(l, g)    f_lfa_gaafl(l, g, -1)

//
// Atomic compare_and_swap: compare expected value with remote, if equal set new else return remote value found
//   abd:    blob descriptor 
//   trg_ix: index of target node
//   off:    offset of the operand
//   exp:    value to check on remote side
//   val:    new value to set
//   rval:   pointer to the fetched value, only valid if EGAIN (see below)
// Return:
//   0       - success
//   -EAGAIN - remote compare failed, check *rval for the remote value
//   !=0     - check errno
//  
int f_lfa_casw(F_LFA_ABD_t *abd, int trg_ix, off_t off, uint32_t val, uint32_t exp, uint32_t *rval);
int f_lfa_casl(F_LFA_ABD_t *abd, int trg_ix, off_t off, uint64_t val, uint64_t exp, uint64_t *rval);

//
// Atomic global-buffer mapped compare_and_swap: compare expected value with remote, if equal 
// set new else return remote value found
// Input:
//   abd:    blob descriptor 
//   goff:   offset in global buffer
//   val:    new value to set
// Implicit:
//   exp:    value to check for on remote side must be in local buffer @goff
// Return:
//   0       - success
//   -EINVAL - goff is beyond buffer size or local buffer is not allocated
//   -EAGAIN - remote compare failed, check *rval for the remote value
//   !=0     - check errno
// Side effects:
//   Local input buffer is updated @goff to the value retrieved from remote
//  
int f_lfa_gcasw(F_LFA_ABD_t *abd, off_t goff, uint32_t val);
int f_lfa_gcasl(F_LFA_ABD_t *abd, off_t goff, uint64_t val);

// 
// Atomic bit_clear_and_fetch: clear a bit and check if it was set
// Note of for the efficiency sake, there's no 64-bit (long) variant of this function.
// We assume that wotking on words (32-bit) gives us less contention for a given place in memory
//   abd:    blob descriptor
//   trg_ix: index of target node
//   off:    offset of the 1st word of the bit field
//   bnum:   bit to clear
// Return:
//   = 0:     - offset of the found clear bit
//   -EBUSY   - the desired bit was already clear
//   <0:      - uh-oh.... 
// 
int f_lfa_bcf(F_LFA_ABD_t *abd, int trg_ix, off_t off, int bnum);

// 
// Atomic global-buffer mapped bit_clear_and_fetch: clear a bit and check if it was set
// Note of for the efficiency sake, there's no 64-bit (long) variant of this function.
// We assume that wotking on words (32-bit) gives us less contention for a given place in memory
//   abd:    blob descriptor
//   goff:   global buffer offset of the 1st word of the bit field
//   bnum:   bit to clear
// Return:
//   = 0:     - offset of the found clear bit
//   -EINVAL - goff is beyond buffer size
//   -EBUSY   - the desired bit was already clear
//   <0:      - uh-oh.... 
// Side effects:
//   *IF* local buffer exists:
//      Local buffer @goff is updated with value retrieved from remote, even on -EBUSY
//   If local buffer wasn't allocated, no side effects
//
// 
int f_lfa_gbcf(F_LFA_ABD_t *abd, off_t goff, int bnum);

// Atomic bit_find_clear_and_set: find first clear bit, starting from offset, and set it
// Note of for the efficiency sake, there's no 64-bit (long) variant of this function.
// We assume that wotking on words (32-bit) gives us less contention for a given place in memory
//   abd:    blob descriptor
//   trg_ix: index of target node
//   off:    offset of the 1st word of the bit field
//   boff:   intitial bit offset (hopefully it will be clear!)
//   bsize:  max number of bits to scan
// Return:
//   >= 0:     - offset of the found clear bit
//   -ENOSPACE - no free bits found
//   <0:       - uh-oh.... 
//
int f_lfa_bfcs(F_LFA_ABD_t *abd, int trg_ix, off_t off, int boff, int bsize);

// 
// Atomic global-buffer mapped bit_find_clear_and_set: find first clear bit, 
// starting from offset, and set it
// Note of for the efficiency sake, there's no 64-bit (long) variant of this function.
// We assume that wotking on words (32-bit) gives us less contention for a given place in memory
//   abd:    blob descriptor
//   goff:   offset in global buffer of the 1st word of the bit field
//   boff:   intitial bit offset (hopefully it will be clear!)
//   bsize:  max number of bits to scan
// Implicit:
//   input buffer: local copy of bitmap being scanned in remote location @goff
// Return:
//   0       - success
//   -EINVAL - goff is beyond buffer size or local buffer is not allocated
//   -ENOSPACE - no free bits found
//   !=0     - check errno
// Side effects:
//   Local input buffer is updated, but only the words that were actually retrieved by 
//   fi_atomic operation that set the desired bit. So, if the very first attempt to set the 
//   bit was successfull, only a word containing it in local buffer will be (resonably)
//   up-to-date with remote
//
int f_lfa_gbfcs(F_LFA_ABD_t *abd, off_t goff, int boff, int bsize);


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

#endif
