#include <sched.h>
#include <unistd.h>
#include "famfs_lfa.h"
#include "famfs_bitops.h"

#define ON_FIERR(action, onerr, msg, ...)   \
    do {                                    \
        int64_t __err;                      \
        if ((__err = (action))) {           \
            fprintf(stderr, "lfa error @%s:%d" #msg ": %ld - %s\n", __FUNCTION__, __LINE__, ## __VA_ARGS__, \
                    __err, fi_strerror(abs(__err))); \
            onerr;                          \
        }                                   \
    } while (0);

#define LOG_FIERR(err, msg, ...)            \
    do {                                    \
        int64_t __err = (err);              \
        fprintf(stderr, "lfa error @%s:%d" #msg ": %ld - %s\n", __FUNCTION__, __LINE__, ## __VA_ARGS__, \
                    __err, fi_strerror(abs(__err))); \
    } while (0);

#define LOCK_LFA(a)\
    do {\
        int __err = pthread_mutex_lock(&a->lfa->lock);\
        if (__err) {\
            fprintf(stderr, "lfa lock @%s:%d error %d - %s\n", __FUNCTION__, __LINE__,\
                    __err, strerror(abs(__err)));\
            return -abs(__err);\
        }\
    } while(0);

#define UNLOCK_LFA(a)\
    do {\
        pthread_mutex_unlock(&a->lfa->lock);\
    } while (0);
    

static ssize_t _wait_cq(F_LFA_DESC_t *lfa) {

    ssize_t ret = 0, rc;
    struct fi_cq_err_entry err_entry;

    bzero(&err_entry, sizeof(err_entry));

    while (1) {
        ret = fi_cq_read(lfa->cq, &lfa->cqe, 1);
        if (ret > 0) {
            return 0;
        } else if (!ret || ret == -FI_EAGAIN) {
            sched_yield();
        } else if (ret == -FI_EAVAIL) {
            LOG_FIERR(ret, "fi_cq_read: error, more data available");
            break;
        } else {
            LOG_FIERR(ret, "fi_cq_read failed:");
            return ret;
        }
    }

    while (1) {
        rc = fi_cq_readerr(lfa->cq, &err_entry, 0);
        if (!rc || rc == -FI_EAGAIN) {
            /* Possibly no error? If so, retry. */
            sched_yield(); 
            continue;
        } else if (rc > 0) {
            ret = -err_entry.err;
            LOG_FIERR(ret, "cq error");
            return ret;
        }
        LOG_FIERR(rc, "fi_cq_readerr");
        return rc;
    }

    return 0;
}

/*
   Make LFA-specific fi domain on specified address (name) and port (svc)

*/
F_LFA_DESC_t *f_lfa_mydom(struct fi_info *fi, char *my_name, char *my_svc) {

    F_LFA_DESC_t *lfa = calloc(1, sizeof(F_LFA_DESC_t));
    if (!lfa)
        return NULL;

    struct fi_info *fo;
    struct fi_info *hints = fi_dupinfo(fi);

    hints->rx_attr->size = 0; /* W/A for zhpe */
    hints->domain_attr->data_progress = FI_PROGRESS_AUTO;

    ON_FIERR(fi_getinfo(FI_VERSION(1, 5), my_name, my_svc, FI_SOURCE, hints, &fo), 
             return NULL, "fi_getinfo failed");
    ON_FIERR(fi_fabric(fo->fabric_attr, &lfa->fab, NULL), return NULL, "fi_fabric err");
    ON_FIERR(fi_domain(lfa->fab, fo, &lfa->dom, NULL), return NULL, "fi_domain err");

    fi_freeinfo(hints);
    lfa->fi = fo; 
    lfa->do_clean = 1; // mark for clean up
    return lfa;
}

/*
   Create atomic blob, open new endpoint, translate all addresses etc
     In
        dom     domain object - see above
        noav    if = 1, do not create AV
        fi      fabric info obtained when domain was created
     Out
        plfa    address of a pointer to hold created LFA structure
                (if *plfa != NULL, the LFA was alredy created by f_lfa_mydom call)
     Return
        0       success
      <>0       error, see errno/fi_errno
*/
int f_lfa_create(struct fid_domain *dom, struct fid_av *av, struct fi_info *fi, F_LFA_DESC_t **plfa) {
    struct fi_cq_attr   cq_attr;
    struct fi_av_attr   av_attr;
    int rc = 0;
    F_LFA_DESC_t *lfa;

    if (*plfa) {
        lfa = *plfa;
    } else {
        lfa = calloc(1, sizeof(F_LFA_DESC_t));
        if (!lfa)
            return -ENOMEM;
        *plfa = lfa;
    }

    pthread_mutex_init(&lfa->lock, NULL);

    if (dom)
        lfa->dom = dom;
    if (fi)
        lfa->fi = fi;
    ON_FIERR(rc = fi_endpoint(lfa->dom, lfa->fi, &lfa->ep, NULL), goto _clean, "create ep");

    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.format = FI_CQ_FORMAT_CONTEXT;
    cq_attr.wait_obj = FI_WAIT_NONE;
    cq_attr.size = lfa->fi->tx_attr->size;
    ON_FIERR(rc = fi_cq_open(lfa->dom, &cq_attr, &lfa->cq, NULL), goto _clean1, "open cq");
    ON_FIERR(rc = fi_ep_bind(lfa->ep, &lfa->cq->fid, FI_RECV | FI_TRANSMIT), goto _clean2, "bind cq");

    if (!av) {
        memset(&av_attr, 0, sizeof(av_attr));
        av_attr.type = FI_AV_TABLE;
        ON_FIERR(rc = fi_av_open(lfa->dom, &av_attr, &lfa->av, NULL), goto _clean2, "av open");
    } else {
        lfa->av = av;
    }
    ON_FIERR(rc = fi_ep_bind(lfa->ep, &lfa->av->fid, 0), goto _clean2, "av bind");

    ON_FIERR(rc = fi_enable(lfa->ep), goto _clean2, "ep enable");

    return 0;

_clean2:

    if (lfa->cq)
        fi_close(&lfa->cq->fid);
    if (lfa->av)
        fi_close(&lfa->av->fid);

_clean1:
    if (lfa->ep)
        fi_close(&lfa->ep->fid);

_clean:
    free(lfa);
    *plfa = NULL;
    return rc;
}

/*
   Register local buffers for remote atomic blob access
   To be called only by nodes that provide memory for atomic ops (servers)
     In
        lfa:        LFA descriptor
        key:        protection key to be used for MR
        bsize:      size of the memory buffer to be served out
     Inout
        pbuf:       address of a pointer to data buffer to be served out
                    if *pbuf == NULL, memory will be allocated
     Out
        pabd:       (new) blob desriptor pointer
     Return
        0           success
        EEXISTS     a blob with this key already registered
        EINVAL      input buffer exists and its size != bsize
        <>0         error
*/
int f_lfa_register(F_LFA_DESC_t *lfa, uint64_t key, size_t bsize, void **pbuf, F_LFA_ABD_t **pabd) {
    F_LFA_ABD_t *abd;
    void *mem;
    int  rc = 0, f = 0;

    if (posix_memalign((void **)&abd, 4096, sizeof(F_LFA_ABD_t))) 
        return -ENOMEM;
    bzero(abd, sizeof(F_LFA_ABD_t));
    *pabd = abd;

    if (!*pbuf) {
        mem = calloc(1, bsize);
        if (!mem)
            return -ENOMEM;
        *pbuf = mem;
        f++;
    } else {
        mem = *pbuf;
    }
    abd->srv_bsz = bsize;
    abd->srv_buf = mem;
    abd->srv_key = key;

    ON_FIERR(rc = fi_mr_reg(lfa->dom, mem, bsize, FI_REMOTE_READ|FI_REMOTE_WRITE, 
                            0, key, 0, &abd->srv_mr, NULL), goto _clean, "mr reg");

    if ((rc = pthread_mutex_lock(&lfa->lock)))
        goto _clean;

    abd->next = lfa->blobs;
    lfa->blobs = abd;
    abd->lfa = lfa;
    pthread_mutex_unlock(&lfa->lock);

    return 0;

_clean:
    free(abd);
    *pabd = NULL;
    if (f) {
        free(mem);
        *pbuf = NULL;
    }
    return rc;
}

/*
   Attach to remote atomic blob
   To be used by any and all nodes that performs atomic ops (clients). This list may or may
   not include servers. I.e. servers could be subset of clients
     In
        lfa:        LFA descriptor
        key:        remote memory protection key
        nlist:      list of remote nodes names to perform atomic ops on (servers)
        bsize:      size of the input memory buffer
     Inout
        ibuf:       address of a pointer to input buffer
                    if *ibuf == NULL, memory will be allocated
     Out
        pbdb:       (new) blob desriptor pointer
     Return
        0           success
        EEXISTS     a blob with this key already attached
        EINVAL      remote buffer exists and its size != bsize
        <>0         error
*/
int f_lfa_attach(F_LFA_DESC_t *lfa, uint64_t key, F_LFA_SLIST_t *lst, int lcnt, size_t bsize, void **ibuf, F_LFA_ABD_t **pabd) {
    F_LFA_ABD_t *abd;
    void *mem;
    int  rc = 0, f = 0;

    if (posix_memalign((void **)&abd, 4096, sizeof(F_LFA_ABD_t))) 
        return -ENOMEM;
    bzero(abd, sizeof(F_LFA_ABD_t));
    *pabd = abd;

    if (ibuf && bsize) {
        if (!*ibuf) {
            mem = calloc(1, bsize);
            if (!mem)
                return -ENOMEM;
            *ibuf = mem;
            f++;
        } else {
            mem = *ibuf;
        }
    } else {
        mem = NULL;
        bsize = 0;
    }
    abd->in_bsz = bsize;
    abd->in_buf = mem;
    abd->srv_key = key;
    abd->ops_key = key + F_LFA_LK_BASE;
    ON_FIERR(rc = fi_mr_reg(lfa->dom, &abd->ops, sizeof(abd->ops), 
        FI_READ|FI_WRITE|FI_REMOTE_READ|FI_REMOTE_WRITE, 
        0, abd->ops_key, 0, &abd->ops_mr, NULL), goto _clean, "mr reg");

    abd->ops_mr_dsc = fi_mr_desc(abd->ops_mr);
    if (!abd->ops_mr_dsc) {
        LOG_FIERR(-FI_EBADFLAGS, "bad MR descriptor");
        return -FI_EBADFLAGS;
    }

    if (mem) {
        ON_FIERR(rc = fi_mr_reg(lfa->dom, mem, bsize, 
            FI_READ|FI_WRITE|FI_REMOTE_READ|FI_REMOTE_WRITE,
            0, F_LFA_LK_BASE + abd->ops_key, 0, &abd->in_mr, NULL), goto _clean, "mr reg");

        abd->in_mr_dsc = fi_mr_desc(abd->in_mr);
        if (!abd->in_mr_dsc) {
            LOG_FIERR(-FI_EBADFLAGS, "bad MR descriptor");
            return -FI_EBADFLAGS;
        }
    }
    abd->tadr = calloc(lcnt, sizeof(fi_addr_t));
    if (!abd->tadr) {
        rc = ENOMEM;
        goto _clean;
    }

    abd->nsrv = lcnt;
    abd->slist = calloc(1, sizeof(F_LFA_SLIST_t)*lcnt);
    off_t off = 0;
    for (int i = 0; i < lcnt; i++) {
        rc = fi_av_insertsvc(lfa->av, lst[i].name, lst[i].service, &abd->tadr[i], 0, NULL);
        ON_FIERR(rc == 1 ? 0 : rc, goto _clean, "av svc insert");
        abd->slist[i].name = strdup(lst[i].name);
        abd->slist[i].service = strdup(lst[i].service);
        abd->slist[i].bsz = lst[i].bsz;
        abd->slist[i].bof = off;
        off += lst[i].bsz;
    }

    if ((rc = pthread_mutex_lock(&lfa->lock)))
        goto _clean;

    abd->next = lfa->blobs;
    lfa->blobs = abd;
    abd->lfa = lfa;

    pthread_mutex_unlock(&lfa->lock);

    return 0;

_clean:
    if (abd->ops_mr)
        fi_close(&abd->ops_mr->fid);

    if (abd->in_mr)
        fi_close(&abd->in_mr->fid);

    if(abd->tadr)
        free(abd->tadr);

    free(abd);
    *pabd = NULL;
    if (f) {
        free(mem);
        *ibuf = NULL;
    }
    return rc;
}

static inline int find_my_off(off_t myoff, F_LFA_SLIST_t *slist, int num) {
    int i = 0, base = 0;

    while (num > 0) {
        i = base  + (num>>1);
        if (myoff == slist[i].bof)
            return i;
        else if (myoff > slist[i].bof) {
            if ((uint64_t)myoff < slist[i].bof + slist[i].bsz)
                break;
            base = i + 1;
            num--;
        }
        num >>= 1;
    }
    return (uint64_t)myoff >= slist[i].bof + slist[i].bsz ? -1 : i;
}

static inline ssize_t get_local_off(F_LFA_ABD_t *abd, off_t goff, int *trg_srv) {
    int srv = find_my_off(goff, abd->slist, abd->nsrv);
    if (srv < 0)
        return -1;

    *trg_srv = srv;
    return goff - abd->slist[srv].bof;
}


int f_lfa_gaddl(F_LFA_ABD_t *abd, off_t goff, long val) {
    int ix;
    ssize_t off = get_local_off(abd, goff, &ix);
    if (off < 0)
        return -EINVAL;
    return f_lfa_addl(abd, ix, off, val);
}

int f_lfa_gaddw(F_LFA_ABD_t *abd, off_t goff, int val) {
    int ix;
    ssize_t off = get_local_off(abd, goff, &ix);
    if (off < 0)
        return -EINVAL;
    return f_lfa_addw(abd, ix, off, val);
}

int f_lfa_gaafl(F_LFA_ABD_t *abd, off_t goff, long val) {
    int ix, rc;
    long old;
    ssize_t off = get_local_off(abd, goff, &ix);
    if (off < 0)
        return -EINVAL;
    if ((rc = f_lfa_aafl(abd, ix, off, val, &old)))
        return rc;
    if (abd->in_buf)
        ((long *)abd->in_buf)[goff/sizeof(long)] = old + val;
    return 0;
}

int f_lfa_gaafw(F_LFA_ABD_t *abd, off_t goff, int val) {
    int ix, rc;
    int old;
    ssize_t off = get_local_off(abd, goff, &ix);
    if (off < 0)
        return -EINVAL;
    if ((rc = f_lfa_aafw(abd, ix, off, val, &old)))
        return rc;
    if (abd->in_buf)
        ((int *)abd->in_buf)[goff/sizeof(int)] = old + val;
    return 0;
}

int f_lfa_aafw(F_LFA_ABD_t *abd, int trg_ix, off_t off, int val, int *old) {
    int rc;

    if (trg_ix >= abd->nsrv)
        return -EINVAL;

    LOCK_LFA(abd);

    abd->ops.in32[0] = val;
    rc = fi_fetch_atomic(
            abd->lfa->ep,
            &abd->ops.in32[0], 1, abd->ops_mr_dsc,
            &abd->ops.out32[0], abd->ops_mr_dsc,
            abd->tadr[trg_ix], off, abd->srv_key,
            FI_INT32, FI_SUM, NULL);
    if (rc) {
        UNLOCK_LFA(abd);
        LOG_FIERR(rc, "fetch_atomic(add)");
        return rc;
    }
    ON_FIERR(rc = _wait_cq(abd->lfa), UNLOCK_LFA(abd); return rc, "atomiq cq");
    if (old) 
        *old = abd->ops.out32[0];

    UNLOCK_LFA(abd);

    return 0;
}

int f_lfa_aafl(F_LFA_ABD_t *abd, int trg_ix, off_t off, long val, long *old) {
    int rc;

    if (trg_ix >= abd->nsrv)
        return -EINVAL;

    LOCK_LFA(abd);

    abd->ops.in64[0] = val;
    rc = fi_fetch_atomic(
            abd->lfa->ep,
            &abd->ops.in64[0], 1, abd->ops_mr_dsc,
            &abd->ops.out64[0], abd->ops_mr_dsc,
            abd->tadr[trg_ix], off, abd->srv_key,
            FI_INT64, FI_SUM, NULL);
    if (rc) {
        UNLOCK_LFA(abd);
        LOG_FIERR(rc, "fetch_atomic(add)");
        return rc;
    }
    ON_FIERR(rc = _wait_cq(abd->lfa), UNLOCK_LFA(abd); return rc, "atomiq cq");
    if (old) 
        *old = abd->ops.out64[0];

    UNLOCK_LFA(abd);

    return 0;
}

static int f_lfa_borfl(F_LFA_ABD_t *abd, int trg_ix, off_t off, long val, long *old) {
    int rc;

    if (trg_ix >= abd->nsrv)
        return -EINVAL;

    LOCK_LFA(abd);

    abd->ops.in64[0] = val;
    rc = fi_fetch_atomic(
            abd->lfa->ep,
            &abd->ops.in64[0], 1, abd->ops_mr_dsc,
            &abd->ops.out64[0], abd->ops_mr_dsc,
            abd->tadr[trg_ix], off, abd->srv_key,
            FI_INT64, FI_BOR, NULL);
    if (rc) {
        UNLOCK_LFA(abd);
        LOG_FIERR(rc, "fetch_atomic(add)");
        return rc;
    }
    ON_FIERR(rc = _wait_cq(abd->lfa), UNLOCK_LFA(abd); return rc, "atomiq cq");
    if (old) 
        *old = abd->ops.out64[0];

    UNLOCK_LFA(abd);

    return 0;
}

static int f_lfa_bandfl(F_LFA_ABD_t *abd, int trg_ix, off_t off, long val, long *old) {
    int rc;

    if (trg_ix >= abd->nsrv)
        return -EINVAL;

    LOCK_LFA(abd);

    abd->ops.in64[0] = val;
    rc = fi_fetch_atomic(
            abd->lfa->ep,
            &abd->ops.in64[0], 1, abd->ops_mr_dsc,
            &abd->ops.out64[0], abd->ops_mr_dsc,
            abd->tadr[trg_ix], off, abd->srv_key,
            FI_INT64, FI_BAND, NULL);
    if (rc) {
        UNLOCK_LFA(abd);
        LOG_FIERR(rc, "fetch_atomic(add)");
        return rc;
    }
    ON_FIERR(rc = _wait_cq(abd->lfa), UNLOCK_LFA(abd); return rc, "atomiq cq");
    if (old) 
        *old = abd->ops.out64[0];

    UNLOCK_LFA(abd);

    return 0;
}

int f_lfa_gborfl(F_LFA_ABD_t *abd, off_t goff, uint64_t val) {
    int ix, rc;
    long old;
    ssize_t off = get_local_off(abd, goff, &ix);
    if (off < 0)
        return -EINVAL;
    if ((rc = f_lfa_borfl(abd, ix, off, val, &old)))
        return rc;
    if (abd->in_buf)
        ((long *)abd->in_buf)[goff/sizeof(long)] = old | val;
    return 0;
}

int f_lfa_gbandfl(F_LFA_ABD_t *abd, off_t goff, uint64_t val) {
    int ix, rc;
    long old;
    ssize_t off = get_local_off(abd, goff, &ix);
    if (off < 0)
        return -EINVAL;
    if ((rc = f_lfa_bandfl(abd, ix, off, val, &old)))
        return rc;
    if (abd->in_buf)
        ((long *)abd->in_buf)[goff/sizeof(long)] = old & val;
    return 0;
}

int f_lfa_addw(F_LFA_ABD_t *abd, int trg_ix, off_t off, int val) {
    int rc;

    if (trg_ix >= abd->nsrv)
        return -EINVAL;

    LOCK_LFA(abd);

    abd->ops.in32[0] = val;
    rc = fi_atomic(
            abd->lfa->ep,
            &abd->ops.in32[0], 1, abd->ops_mr_dsc,
            abd->tadr[trg_ix], off, abd->srv_key,
            FI_INT32, FI_SUM, NULL);
    if (rc) {
        UNLOCK_LFA(abd);
        LOG_FIERR(rc, "fetch_atomic(add)");
        return rc;
    }
    ON_FIERR(rc = _wait_cq(abd->lfa), UNLOCK_LFA(abd); return rc, "atomiq cq");

    UNLOCK_LFA(abd); 
    return 0;
}

int f_lfa_addl(F_LFA_ABD_t *abd, int trg_ix, off_t off, long val) {
    int rc;

    if (trg_ix >= abd->nsrv)
        return -EINVAL;

    LOCK_LFA(abd);

    abd->ops.in64[0] = val;
    rc = fi_atomic(
            abd->lfa->ep,
            &abd->ops.in64[0], 1, abd->ops_mr_dsc,
            abd->tadr[trg_ix], off, abd->srv_key,
            FI_INT64, FI_SUM, NULL);
    if (rc) {
        UNLOCK_LFA(abd);
        LOG_FIERR(rc, "fetch_atomic(add)");
        return rc;
    }
    ON_FIERR(rc = _wait_cq(abd->lfa), UNLOCK_LFA(abd); return rc, "atomiq cq");

    UNLOCK_LFA(abd);

    return 0;
}

/*
   Atomic compare_and_swap: compare expected value with remote, if equal set new else return remote value found
    abd:    blob descriptor 
    trg_ix: index of target node
    off:    offset of the operand
    exp:    value to check on remote side
    val:    new value to set
    rval:   pointer to the fetched value, only valid if EAGAIN (see below)
   Return:
    0       - success
    -EAGAIN - remote compare failed, check *rval for the remote value
    !=0     - check errno
*/  
int f_lfa_casw(F_LFA_ABD_t *abd, int trg_ix, off_t off, uint32_t val, uint32_t exp, uint32_t *rval) {
    int rc;

    if (trg_ix >= abd->nsrv)
        return -EINVAL;

    LOCK_LFA(abd);

    abd->ops.in32[0] = val;
    abd->ops.in32[1] = exp;
    rc = fi_compare_atomic(
            abd->lfa->ep,
            &abd->ops.in32[0], 1, abd->ops_mr_dsc,
            &abd->ops.in32[1],  abd->ops_mr_dsc, 
            &abd->ops.out32[0], abd->ops_mr_dsc,
            abd->tadr[trg_ix], off, abd->srv_key,
            FI_INT32, FI_CSWAP, NULL);

    if (rc) {
        UNLOCK_LFA(abd);
        LOG_FIERR(rc, "fetch_compare_atomic");
        return rc;
    }
    ON_FIERR(rc = _wait_cq(abd->lfa), UNLOCK_LFA(abd); return rc, "atomiq cq");

    if (rval)
        *rval = abd->ops.out32[0];
    if (abd->ops.out32[0] != exp)
        rc = -EAGAIN;

    UNLOCK_LFA(abd);

    return rc;
}

int f_lfa_gcasw(F_LFA_ABD_t *abd, off_t goff, uint32_t val) {
    int ix, rc;
    uint32_t actual;

    if (!abd->in_buf)
        return -EINVAL;

    ssize_t off = get_local_off(abd, goff, &ix);
    if (off < 0)
        return -EINVAL;

    if ((rc = f_lfa_casw(abd, ix, off, val, ((uint32_t *)abd->in_buf)[goff/sizeof(uint32_t)], &actual)))
        return rc;

    ((uint32_t *)abd->in_buf)[goff/sizeof(uint32_t)] = actual;
    return rc;
}


int f_lfa_casl(F_LFA_ABD_t *abd, int trg_ix, off_t off, uint64_t val, uint64_t exp, uint64_t *rval) {
    int rc;

    if (trg_ix >= abd->nsrv)
        return -EINVAL;

    LOCK_LFA(abd);

    abd->ops.in64[0] = val;
    abd->ops.in64[1] = exp;
    rc = fi_compare_atomic(
            abd->lfa->ep,
            &abd->ops.in64[0], 1, abd->ops_mr_dsc,      // value to try to set @remote
            &abd->ops.in64[1],  abd->ops_mr_dsc,        // value we expect to see @remote
            &abd->ops.out64[0], abd->ops_mr_dsc,        // actual value retrieved from remote
            abd->tadr[trg_ix], off, abd->srv_key,
            FI_INT64, FI_CSWAP, NULL);

    if (rc) {
        UNLOCK_LFA(abd);
        LOG_FIERR(rc, "fetch_compare_atomic");
        return rc;
    }
    ON_FIERR(rc = _wait_cq(abd->lfa), UNLOCK_LFA(abd); return rc, "atomiq cq");

    if (rval)
        *rval = abd->ops.out64[0];
    if (abd->ops.out64[0] != exp)
        rc = -EAGAIN;

    UNLOCK_LFA(abd);

    return rc;
}

int f_lfa_gcasl(F_LFA_ABD_t *abd, off_t goff, uint64_t val) {
    int ix, rc;
    uint64_t actual;

    if (!abd->in_buf)
        return -EINVAL;

    ssize_t off = get_local_off(abd, goff, &ix);
    if (off < 0)
        return -EINVAL;

    if ((rc = f_lfa_casl(abd, ix, off, val, ((uint64_t *)abd->in_buf)[goff/sizeof(uint64_t)], &actual)))
        return rc;

    ((uint64_t *)abd->in_buf)[goff/sizeof(uint64_t)] = actual;
    return rc;
}

static int _lfa_bfcs(F_LFA_ABD_t *abd, int trg_ix, off_t off, int boff, int bsize) {
    int rc, wrap = 0;
    uint32_t bit = boff%32;
    off_t bw = boff/32;
    uint32_t bmask, bn = boff, bmax = bsize;

    while (bn < bmax) {
        if ((uint64_t)bw >= F_LFA_MAX_AVB/sizeof(uint32_t))
            return -EINVAL;

        abd->ops.in32[bw] = bmask = 1<<bit;
        rc = fi_fetch_atomic(
                abd->lfa->ep,
                &abd->ops.in32[bw], 1, abd->ops_mr_dsc,
                &abd->ops.out32[bw], abd->ops_mr_dsc,
                abd->tadr[trg_ix], off + bw*sizeof(uint32_t), abd->srv_key,
                FI_INT32, FI_BOR, NULL);
        if (rc) {
            LOG_FIERR(rc, "fetch_atomic(bor)");
            return rc;
        }
        ON_FIERR(rc = _wait_cq(abd->lfa), UNLOCK_LFA(abd); return rc, "atomiq cq");

        abd->ops.in32[bw] = abd->ops.out32[bw] | bmask; // update input buffer with latest global value
        if (abd->ops.out32[bw] & bmask) {
            // oops, somebody had already set this bit
            int clear = __builtin_ffs(~abd->ops.out32[bw]);
            if (!clear) {
                // no clear bits in this word, go to next
                bit = 0;
                bn = ++bw*32;
            } else {
                // found clear bit somewhere in current word
                bit = clear - 1;
                bn = bw*32 + bit;
            } 
        } else {
            // success, return bit number
            return bw*32 + bit;
        }
        if (bn >= bmax) {
            if (!wrap) {
                wrap++;
                bn = bit = bw = 0;
                bmax = boff;
            } else {
                break;
            }
        }
    }

    // oopsie, didn't fine any clear bits even afeter full wrap-around scan
    return -ENOSPC;
}


/* 
   Atomic bit_find_clear_and_set: find first clear bit, starting from offset, and set it
   Note of for the efficiency sake, there's no 64-bit (long) variant of this function.
   We assume that wotking on words (32-bit) gives us less contention for a given place in memory
    abd:    blob descriptor
    trg_ix: index of target node
    off:    offset of the 1st word of the bit field
    boff:   intitial bit offset (hopefully it will be clear!)
    bsize:  max number of bits to scan
   Return:
    >= 0:     - offset of the found clear bit
    -ENOSPACE - no free bits found
    <0:       - uh-oh.... 
*/
int f_lfa_bfcs(F_LFA_ABD_t *abd, int trg_ix, off_t off, int boff, int bsize) {
    int rc;

    if (boff >= bsize || trg_ix >= abd->nsrv || (unsigned)bsize > F_LFA_MAX_BIT)
        return -EINVAL;

    LOCK_LFA(abd);
    rc = _lfa_bfcs(abd, trg_ix, off, boff, bsize);
    UNLOCK_LFA(abd);

    return rc;
}

int f_lfa_gbfcs(F_LFA_ABD_t *abd, off_t goff, int boff, int bsize) {
    int rc, ix, bit;

    if (boff >= bsize || (unsigned)bsize > F_LFA_MAX_BIT || !abd->in_buf)
        return -EINVAL;

    // first try to find bit >= boff
    bit = find_next_zero_bit((uint64_t*)((char *)abd->in_buf + goff), bsize, boff);
    if (bit >= bsize) {
        // no luck in the tail, now chekck bits from 0 to boff
        bit = find_first_zero_bit((uint64_t *)((char *)abd->in_buf + goff), boff);
        if(bit >= bsize)
            return -ENOSPC;
    }

    ssize_t off = get_local_off(abd, goff, &ix);
    if (off < 0)
        return -EINVAL;

    LOCK_LFA(abd);

    // copy current state of bit map in local mirror 
    memcpy(abd->ops.in32, (char *)abd->in_buf + goff, bsize/8); 
    rc = _lfa_bfcs(abd, ix, off, bit, bsize);
    // get whatever global updates in
    memcpy((char *)abd->in_buf + goff, abd->ops.in32, bsize/8);

    UNLOCK_LFA(abd);

    return rc;
}

static int _lfa_bcf(F_LFA_ABD_t *abd, int trg_ix, off_t off, int bnum) {
    int rc = 0;
    uint32_t bit = bnum%32, bmask;
    off_t bw = bnum/32;

    if (trg_ix >= abd->nsrv)
        return -EINVAL;

    abd->ops.in32[0] = ~(bmask = 1<<bit);
    rc = fi_fetch_atomic(
            abd->lfa->ep,
            &abd->ops.in32[0], 1, abd->ops_mr_dsc,
            &abd->ops.out32[0], abd->ops_mr_dsc,
            abd->tadr[trg_ix], off + bw*sizeof(uint32_t), abd->srv_key,
            FI_INT32, FI_BAND, NULL);
    if (rc) {
        LOG_FIERR(rc, "fetch_atomic(band)");
        return rc;
    }
    ON_FIERR(rc = _wait_cq(abd->lfa), UNLOCK_LFA(abd); return rc, "atomiq cq");

    if (!(abd->ops.out32[0] & bmask))
        rc = -EBUSY;
    else 
        abd->ops.out32[0] &= ~bmask;


    return rc;
}

/* 
   Atomic bit_clear_and_fetch: clear a bit and check if it was set
   Note of for the efficiency sake, there's no 64-bit (long) variant of this function.
   We assume that wotking on words (32-bit) gives us less contention for a given place in memory
    abd:    blob descriptor
    trg_ix: index of target node
    off:    offset of the 1st word of the bit field
    bnum:   intitial bit offset
   Return:
    = 0:      - offset of the found clear bit
    -EBUSY    - the bit was alrready cleared
    <0:       - uh-oh.... 
*/
int f_lfa_bcf(F_LFA_ABD_t *abd, int trg_ix, off_t off, int bnum) {
    int rc;

    LOCK_LFA(abd);
    rc = _lfa_bcf(abd, trg_ix, off, bnum);
    UNLOCK_LFA(abd);

    return rc;
}

int f_lfa_gbcf(F_LFA_ABD_t *abd, off_t goff, int bnum) {
    int ix, rc;
    ssize_t off = get_local_off(abd, goff, &ix);
    if (off < 0)
        return -EINVAL;

    LOCK_LFA(abd);
    rc = _lfa_bcf(abd, ix, off, bnum);
    if (!rc || rc == -EBUSY)
        if (abd->in_buf)
            ((int *)abd->in_buf)[goff/sizeof(int)] = abd->ops.out32[0];
    UNLOCK_LFA(abd);

    return rc;
}

/*
   Detach from remote atomic blob
    If fm != 0, free all memory buffers 
*/
int f_lfa_detach(F_LFA_ABD_t *abd, int fm) {
    int rc = 0;

    if (!abd) 
        return -EINVAL;
   
    LOCK_LFA(abd);

    F_LFA_ABD_t **prev = &abd->lfa->blobs;
    for (F_LFA_ABD_t *cur = abd->lfa->blobs; cur && cur != abd; prev = &cur->next, cur = cur->next);
    *prev = abd->next;

    UNLOCK_LFA(abd);

    ON_FIERR(rc = fi_close(&abd->ops_mr->fid), return rc, "ops mr close");
    ON_FIERR(rc = fi_close(&abd->in_mr->fid), return rc, "ibuf mr close");

    for (int i = 0; i < abd->nsrv; i++) {
        free(abd->slist[i].name);
        free(abd->slist[i].service);
    }

    free(abd->tadr);
    free(abd->slist);
    if (fm)
        free(abd->in_buf);
    free(abd);

    return 0;
}

/*
   Deregister local buffers and free all lf resources
    If fm != 0, free all memory buffers 
*/
int f_lfa_deregister(F_LFA_ABD_t *abd, int fm) {
    int rc = 0;

    if (!abd) 
        return -EINVAL;
   
    LOCK_LFA(abd);

    F_LFA_ABD_t **prev = &abd->lfa->blobs;
    for (F_LFA_ABD_t *cur = abd->lfa->blobs; cur && cur != abd; prev = &cur->next, cur = cur->next);
    *prev = abd->next;

    UNLOCK_LFA(abd);

    ON_FIERR(rc = fi_close(&abd->srv_mr->fid), return rc, "srv mr close");

    if (fm)
        free(abd->srv_buf);
    free(abd);

    return 0;
}

#define FI_CLOSE(obj)\
do {\
    if (!(rc = fi_close(&((obj)->fid))))\
        break;\
    sleep(1);\
    if (!rt--)\
        break;\
} while(rc == -EAGAIN);\
if (rc) {\
    LOG_FIERR(rc, "closing "#obj);\
    return rc;\
}


/*
   Close evrything lf-related, free memory 
*/
int f_lfa_destroy(F_LFA_DESC_t *lfa) {
    int rc = 0, rt = 60;
    if (!lfa) 
        return -EINVAL;
    if (lfa->blobs) {
        LOG_FIERR(-EINVAL, "LFA blobs chain not empty");
        return -EINVAL;
    }
    FI_CLOSE(lfa->ep);
    FI_CLOSE(lfa->cq);

    if (lfa->do_clean) {
        FI_CLOSE(lfa->av);
        FI_CLOSE(lfa->dom);
        FI_CLOSE(lfa->fab);
    }
    fi_freeinfo(lfa->fi);
    free(lfa);

    return 0;
}

int f_lfa_put(F_LFA_ABD_t *abd, int trg_ix, off_t off, size_t size) {
    int rc;

    if (!abd->in_buf)
        return -ENOMEM;
    if (trg_ix >= abd->nsrv)
        return -EINVAL;


    LOCK_LFA(abd);

    rc = fi_write(
            abd->lfa->ep, abd->in_buf, size, abd->in_mr_dsc,
            abd->tadr[trg_ix], off, abd->srv_key, NULL);
    if (rc) {
        UNLOCK_LFA(abd);
        LOG_FIERR(rc, "rma write");
        return rc;
    }
    ON_FIERR(rc = _wait_cq(abd->lfa), UNLOCK_LFA(abd); return rc, "atomiq cq");

    UNLOCK_LFA(abd);
    return 0;
}

int f_lfa_gput(F_LFA_ABD_t *abd, off_t goff, size_t size) {
    int ix, rc = 0;
    ssize_t tx_sz, off = get_local_off(abd, goff, &ix);
    if (off < 0 || !abd->in_buf)
        return -EINVAL;
    for (; ix < abd->nsrv; ix++) {
        tx_sz = min(abd->slist[ix].bsz - off, size);
        ON_FIERR(rc = f_lfa_put(abd, ix, off, tx_sz), break, "lfa put %s\n", abd->slist[ix].name);
        size -= tx_sz;
        if (!size)
            break;
        off = 0;
        
    }
    return rc;
}

int f_lfa_get(F_LFA_ABD_t *abd, int trg_ix, off_t off, size_t size) {
    int rc; 

    if (!abd->in_buf)
        return -ENOMEM;
    if (trg_ix >= abd->nsrv)
        return -EINVAL;


    LOCK_LFA(abd);
    rc = fi_read(
            abd->lfa->ep, abd->in_buf, size, abd->in_mr_dsc,
            abd->tadr[trg_ix], off, abd->srv_key, NULL);
    if (rc) {
        UNLOCK_LFA(abd);
        LOG_FIERR(rc, "rma write");
        return rc;
    }
    ON_FIERR(rc = _wait_cq(abd->lfa), UNLOCK_LFA(abd); return rc, "atomiq cq");

    UNLOCK_LFA(abd);
    return 0;
}

int f_lfa_gget(F_LFA_ABD_t *abd, off_t goff, size_t size) {
    int ix, rc = 0;
    ssize_t tx_sz, off = get_local_off(abd, goff, &ix);
    if (off < 0 || !abd->in_buf)
        return -EINVAL;
    for (; ix < abd->nsrv; ix++) {
        tx_sz = min(abd->slist[ix].bsz - off, size);
        ON_FIERR(rc = f_lfa_get(abd, ix, off, tx_sz), break, "lfa get %s\n", abd->slist[ix].name);
        size -= tx_sz;
        if (!size)
            break;
        off = 0;
        
    }
    return rc;
}


