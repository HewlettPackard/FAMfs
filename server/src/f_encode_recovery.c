/*
 * Copyright (c) 2020, HPE
 *
 * Written by: Oleg Neverovitch, Yann Livis
 */
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "log.h"
#include "unifycr_debug.h"
#include "unifycr_const.h"
#include "famfs_env.h"
#include "famfs_error.h"
#include "famfs_maps.h"
#include "famfs_bitmap.h"
#include "f_map.h"
#include "f_pool.h"
#include "f_layout.h"
#include "f_wpool.h"
#include "famfs_lf_connect.h"
#include "f_layout_ctl.h"
#include "f_allocator.h"
#include "fam_stripe.h"
#include "f_ec.h"
#include "f_encode_recovery.h"
#include "f_recovery.h"


static F_EDR_OPQ_t  edr_wq;
static F_EDR_OPQ_t  edr_cq;
static F_EDR_OPQ_t  *free_s;
static F_EDR_OPQ_t  *free_m;
static F_EDR_OPQ_t  *free_l;

static atomic_t edr_io_total;

static int edr_quit = 0;

static inline void set_tmo(struct timespec *ts, uint64_t usec) {
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += (ts->tv_nsec + (unsigned long)usec*1000L)/1000000000L;
    ts->tv_nsec = (ts->tv_nsec + (unsigned long)usec*1000L)%1000000000L;
}

// make these global as they'll be needed by recovery thread
u8 **edr_encode_tables, **edr_rs_matrices;

//
// q     - queue to init
// lo    - layout this q belongs to
// qsize - number of elements
// scnt  - stripe count
//
static int init_edr_q(F_EDR_OPQ_t *q, F_LAYOUT_t *lo, int qsize, int scnt) {
    F_EDR_t *rq;

    INIT_LIST_HEAD(&q->qhead);
    q->quit = 0;
    ON_ERROR_RC(pthread_spin_init(&q->qlock, PTHREAD_PROCESS_PRIVATE), "spin");
    ON_ERROR_RC(pthread_mutex_init(&q->wlock, NULL), "mutex");
    ON_ERROR_RC(pthread_cond_init(&q->wake, NULL), "cond");

    if (!qsize)
        return 0;

    // create prealloc requests
    for (int j = 0; j < qsize; j++) {
        ON_NOMEM_RET(rq = calloc(1, sizeof(F_EDR_t)), "alloc rq");
        // need 64-byte alignment for AVX XOR to work!
        ON_ERROR_RC(posix_memalign((void *)&rq->iobuf, 4096, 
                    lo->info.chunks*lo->info.chunk_sz*scnt), "alloc buf");
        //rq->iobuf = calloc(scnt, lo->info.chunks*lo->info.chunk_sz);
        rq->lo = lo;
        rq->state = F_EDR_FREE;
        rq->sall = scnt;
        list_add_tail(&rq->list, &q->qhead);
    }
    q->size = qsize;

    return 0;
}

//
// Submit EDR libfabric I/O
// rq - request
// wr - wr (1) or read
//
static int edr_io_submit(F_EDR_t *rq, int wr) {
    int rc = 0;
    N_CHUNK_t *chunk;
    F_POOL_DEV_t *pdev;
    FAM_DEV_t *fdev;
    fi_addr_t *tgt_srv_addr;
    struct fid_ep *tx_ep = NULL;
    void *local_desc, *buf;
    unsigned int nchunks, media_id;
    off_t off;
    ALLOCA_CHUNK_PR_BUF(pr_buf);

    N_STRIPE_t *stripe = rq->sattr;
    size_t chunk_sz = stripe->chunk_sz;
    uint32_t len = chunk_sz*rq->scnt;

    nchunks = stripe->d + stripe->p;
    ASSERT(nchunks <= 64);
    rq->ready = 0;
    rq->state = wr ? F_EDR_WRITE : F_EDR_READ;
    int px = 0, dx = 0;
    for (int i = 0; i < nchunks; i++) {

	chunk = get_fam_chunk(stripe, i);
        if (rq->op == EDR_OP_ENC) {
            // encode: skip parity on read and data on write
            // remeber wich chunks are data and parity
            if (chunk->data >= 0)
                rq->dchnk[dx++] = i;
            else
                rq->pchnk[px++] = i;

            if ((chunk->data < 0 && !wr) || (chunk->data >= 0 && wr))
                continue;
        } else if (rq->op == EDR_OP_REC) {
            // recover: skip error chunks on read and good ones on write
            // remeber good chunk and failed ones (the latter go as 'parity')
            if (test_bit(i, &rq->fvec)) {
                rq->pchnk[px++] = i;
                if (!wr) continue; 
            } else {
                rq->dchnk[dx++] = i;
                if (wr) continue;
            }
        } else if (rq->op == EDR_OP_VFY) {
            if (chunk->data >= 0)
                rq->dchnk[dx++] = i;
            else
                rq->pchnk[px++] = i;
            if (wr)
                continue;   // verify: don't write and dont't skip
        } else {
            ASSERT(0);
        }

	pdev = chunk->pdev;
	media_id = pdev->pool_index;

	fdev = &pdev->dev->f;
	tgt_srv_addr = &fdev->fi_addr;
	local_desc = NULL; // FIXME
	buf = &rq->iobuf[i*len];
	tx_ep = fdev->ep;
        if (!tx_ep || DevFailed(pdev->sha)) {
            LOG(LOG_ERR, "%s[%d]: %s - stripe %lu, chunk %d: dev %u has failed or EP not setup",
                rq->lo->info.name, rq->lo->lp->part_num, EDR_PR_R(rq),
                rq->ss->stripes[rq->scur], i, media_id);
            rc = -EINVAL;
            break;
        } 

	// remote address
	off = 1ULL*stripe->stripe_in_part*chunk_sz + chunk->p_stripe0_off;

	LOG(LOG_DBG3,"%s: %s stripe:%lu - %u/%u/%s "
		  "on device %u(@%lu) len:%u desc:%p off:0x%16lx mr_key:%lu",
		  f_get_pool()->mynode.hostname,
		  wr?"write":"read",rq->ss->stripes[rq->scur],
		  stripe->extent, stripe->stripe_in_part,
		  pr_chunk(pr_buf, chunk->data, chunk->parity),
		  media_id, (unsigned long)*tgt_srv_addr,
		  len, local_desc, off, fdev->mr_key);

	do {
	    rc = wr ? fi_write(tx_ep, buf, len, local_desc, *tgt_srv_addr, off,
                               fdev->mr_key, (void*)rq) :
                      fi_read(tx_ep, buf, len, local_desc, *tgt_srv_addr, off,
                              fdev->mr_key, (void*)rq);

	    if (rc == 0) {
                atomic_inc(&rq->busy);
                atomic_inc(&edr_io_total);
                atomic_inc(&pdev->edr_io_cnt);
                break;
	    } else if (rc < 0 && rc != -FI_EAGAIN) {
                fi_err(rc, "%s: fi_%s failed on dev %u",
                       f_get_pool()->mynode.hostname, wr ? "write" : "read", media_id);
            }
            LOG(LOG_ERR, "fi_%s returned EAGAIN on dev %u", wr ? "write" : "read", media_id);
            usleep(1000);
	} while (rc == -FI_EAGAIN);
    }

    // all ios submitted, tell CQ thread to be ready
    rq->ready = 1;
    pthread_cond_signal(&edr_cq.wake);

    return rc;
}

//
// Start EDR read
//
static int edr_read(F_EDR_t *rq) {
    int rc = 0;
    int x = rq->scur;
    f_stripe_t s = rq->ss->stripes[x];
    F_LAYOUT_t *lo = rq->lo;

    LOG(LOG_DBG2, "stripe %lu (%d of %d)", s, x + 1, rq->ss->count);
    if (rq->op == EDR_OP_ENC || rq->op == EDR_OP_VFY) {
        if (!f_stripe_slab_healthy(lo, s)) {
            LOG(LOG_ERR, "%s[%d]: %s - stripe %lu, slab is degraded or failed", 
                    lo->info.name, lo->lp->part_num, EDR_PR_R(rq), s);
            goto _err;
        }
    }
    if (!rq->sattr || rq->sattr->stripe_0 + rq->sattr->stripe_in_part != s) {
        // map to physical stripe
        if ((rc = f_map_fam_stripe(lo, &rq->sattr, s, 0))) {
            LOG(LOG_ERR,"stripe:%lu in layout %s - mapping error:%d", s, lo->info.name, rc);
            goto _err;
        }
    }

    if ((rc = edr_io_submit(rq, 0))) {
        LOG(LOG_ERR,"stripe:%lu in layout %s - submit i/o error:%d", s, lo->info.name, rc);
        goto _err;
    }

    return 0;

_err:
    rq->err = rc;
    rq->nerr++;
    return rc;
}

static int vfy_read_done(F_EDR_t *rq, void *ctx) {
    return 0;
}

//
// Current stripe is written out
// Porcess next stripe in SS: if the last one is done, finish up
// and retire this request
//
static int edr_read_done(F_EDR_t *rq, void *ctx);
static int edr_write_done(F_EDR_t *rq, void *ctx) {
    int rc = 0;
    int x = rq->scur;
    f_stripe_t s = rq->ss->stripes[x], s0 = rq->ss->stripes[0];
    F_LAYOUT_t *lo = rq->lo;
    F_LO_PART_t *lp = rq->lo->lp;

    do {
        if (!rq->err) {
            if (rq->op == EDR_OP_ENC) {
                f_laminate_stripe(lp->layout, s);
                LOG(LOG_DBG3, "%s[%d]: stripe %lu laminated (%d of %d)",
                    lo->info.name, lp->part_num, s, x + 1, rq->ss->count);
            } else {
                LOG(LOG_DBG3, "%s[%d]: %d stripes recovered, s0=%lu, %d to go",
                    lo->info.name, lp->part_num, rq->scnt, s, rq->ss->count - x -1);
            }
        } else {
            LOG(LOG_DBG3, "%s[%d]: stripe %lu in error (%d of %d): %d",
                lo->info.name, lp->part_num, s, x + 1, rq->ss->count, rq->err);
        }

        rq->scur += rq->scnt;
        if (rq->scur >= rq->ss->count) {
            // last stripe in set done
            rq->status = rq->nerr ? -EIO : 0;

            // Mark the claim vector to be flushed
            if (rq->op == EDR_OP_ENC) 
                SetLPCVFlush(lp);

            if (rq->completion) {
                if (rq->completion(rq, rq->ctx)) {
                    LOG(LOG_ERR, "%s[%d]: %s done callback failed",
                        lo->info.name, lp->part_num, EDR_PR_R(rq));
                }
            } else {
                LOG(LOG_DBG, "%s[%d]: s0=%lu - %d stripes laminated, %d errors (no CB)",
                    lo->info.name, lp->part_num, s0, rq->ss->count - rq->nerr, rq->nerr);
            }

            // return request to free queue
            rq->state = F_EDR_FREE;
            rq->err = 0;
            rq->nerr = 0;
            rq->status = 0;

            pthread_spin_lock(&rq->myq->qlock);
            list_add_tail(&rq->list, &rq->myq->qhead);
            rq->myq->size++;
            pthread_spin_unlock(&rq->myq->qlock);

            // wake up any client(s) that could be waiting for ree RQ
            pthread_cond_broadcast(&rq->myq->wake);
            //pthread_cond_signal(&free_s[l].wake);
            LOG(LOG_DBG3, "%s[%d]: retiring rq to '%s' queue",
                lo->info.name, lp->part_num, EDR_PR_Q(rq->myq));

        } else {
            // repeat the whole process for the next stripe(s) in set
            atomic_set(&rq->busy, 0);
            rq->scnt = min(rq->sall, rq->ss->count - rq->scur);
            rq->err = 0;
            rq->next_call = edr_read_done;
            rc = edr_read(rq);
        }
    } while (rc);

    return 0;
}

//
// Encode/Decode EC calc is done, next step: write out parity
//
static int edr_calc_done(F_EDR_t *rq, void *ctx) {
    int rc = 0;

    rq->next_call = edr_write_done;

    LOG(LOG_DBG3, "stripe batch %lu[%d] (%d of %d): %s calc done", 
        rq->ss->stripes[rq->scur], rq->scnt, rq->scur + 1, rq->ss->count, EDR_PR_R(rq));
    if (!rq->err) {
        if ((rc = edr_io_submit(rq, 1))) {
            LOG(LOG_DBG3, "stripe batch %lu[%d] (%d of %d): %s wr submit err:%d", 
                rq->ss->stripes[rq->scur], rq->scnt, rq->scur + 1, rq->ss->count, 
                EDR_PR_R(rq), rc);
            goto _err;

        }
        // I/O submitted successfully, this is WP thread context so just retun
        // and wait for the completion event to be read from CQ
        return 0;
    }

_err:
    // current stripe is in error, no point in writing. invoke callback directly
    // (NOTE: this is WP thread context, but oh well...)
    if (rc)
        rq->err = rc;
    rq->nerr++;
    rq->next_call(rq, rq->ctx);
    return rc;
}

//
// Encode stripe: read done, start EC calculations
//
static int edr_read_done(F_EDR_t *rq, void *ctx) {
    F_LO_PART_t *lp = rq->lo->lp;
    int rc = 0;
    int cmd;
    int prio;

    if (rq->op == EDR_OP_ENC) {
        cmd = F_WT_ENCODE;
        prio = F_WP_NORMAL;
    } else {
        cmd = F_WT_DECODE;
        prio = F_WP_HIGH;
    }
    rq->next_call = edr_calc_done;

    LOG(LOG_DBG3, "stripe batch %lu[%d] (%d of %d): %s read done", 
        rq->ss->stripes[rq->scur], rq->scnt, rq->scur + 1, rq->ss->count, EDR_PR_R(rq));
    ASSERT(atomic_read(&rq->busy) == 0);

    rq->state = F_EDR_CALC;
    if ((rc = f_wpool_add_work(lp->wpool, cmd, prio, rq))) {
        LOG(LOG_ERR, "stripe batch %lu[%d] (%d of %d): %s calc failed:%d",
            rq->ss->stripes[rq->scur], rq->scnt, rq->scur + 1, rq->ss->count, EDR_PR_R(rq), rc);
        rq->nerr++;
        rq->err = rc;
        rq->next_call(rq, rq->ctx);
    }
    return 0;
}

//
// Begin request processing
//
static void start_rq(F_EDR_t *rq) {
    int rc = 0;

    atomic_set(&rq->busy, 0);
    rq->status = 0;
    rq->nerr = 0;
    rq->scur = 0;

    switch (rq->op) {
    case EDR_OP_ENC:
    case EDR_OP_REC:
        rq->next_call = edr_read_done;
        break;

    case EDR_OP_VFY:
        rq->next_call = vfy_read_done;
        break;

    default:
        ASSERT(0);
    }

    if ((rc = edr_read(rq))) {
        // error submitting read i/o, finsh this directly
        LOG(LOG_ERR, "read: %d, rq err:%d", rc, rq->status);
        edr_write_done(rq, rq->ctx);
    }
}

//
// Check libfabric completion queue for any I/O completions or errors
//
static int check_cq(struct fid_cq *cq, F_EDR_t **prq) {
    struct fi_cq_tagged_entry cqe;
    struct fi_cq_err_entry cer;
    ssize_t ret = 0, rc;
    F_EDR_t *rq = NULL;

    // read completio queue
    ret = fi_cq_read(cq, &cqe, 1);
    if (ret > 0) {
        LOG(LOG_DBG3, "got RQ @%p completion", cqe.op_context);
        // got one rq completed successfully
        rq = (F_EDR_t *)cqe.op_context;
        rq->err = rq->prov_err = 0;
        *prq = rq;
        return 0;
    } else if (!ret || ret == -FI_EAGAIN) {
        // nothing ready yet
        *prq = rq;
        return -EAGAIN;
    } else if (ret == -FI_EAVAIL) {
        // got error
        LOG(LOG_ERR, "fi_cq_read: error, more data available");
    } else {
        // cq read operation failed
        LOG(LOG_ERR, "fi_cq_read failed:%ld", ret);
        *prq = rq;
        return ret;
    }

    // try to figure out what failed
    bzero(&cer, sizeof(cer));
    while (1) {
        rc = fi_cq_readerr(cq, &cer, 0);
        if (!rc || rc == -FI_EAGAIN) {
            // Possibly no error? If so, retry
            sched_yield();
            continue;
        } else if (rc > 0) {
            // got one error entry
            LOG(LOG_ERR, "cq got error: %d/%d", cer.err, cer.prov_errno);
            ret = -cer.err;
            rq = (F_EDR_t *)cer.op_context;
            rq->err = ret;
            rq->prov_err = cer.prov_errno;
            *prq = rq;
            return ret;
        }
        LOG(LOG_ERR, "fi_cq_readerr failed: %ld", rc);
        return rc;
    }

    return 0;
}

//
// Advance request propgress
//
static void advance_rq(F_EDR_t *rq) {
    LOG(LOG_DBG3, "stripe %lu (%d of %d)", rq->ss->stripes[rq->scur], rq->scur + 1, rq->ss->count);
    if (rq->err) {
        rq->nerr++;
        LOG(LOG_ERR, "I/O error (%d/%d) on %s rq, s[%d]=%lu, ss cnt=%d, lid=%d",
            rq->err, rq->prov_err, EDR_PR_R(rq), rq->scur, rq->ss->stripes[rq->scur], 
            rq->ss->count, rq->lo->info.conf_id);
    }
    if (atomic_dec_and_test(&rq->busy)) {
        if (rq->ready || rq->err) {
            // all ops completed (some may had failed), see what's next
            rq->next_call(rq, rq->ctx);
        } else {
            // not all ops started yet, wait
        }
    }
}

//
// EDR request queue processing thread
//
static void *edr_wq_thread(void *arg) {
    F_EDR_OPQ_t *wq = (F_EDR_OPQ_t *)arg;
    struct timespec ts;
    F_EDR_t *rq;
    int rc;

    ASSERT(wq == &edr_wq);
    LOG(LOG_INFO, "EDR worker thread started");

    while (!edr_quit) {
        pthread_spin_lock(&wq->qlock);
        rq = list_first_entry_or_null(&wq->qhead, F_EDR_t, list);
        if (!rq) {
            pthread_spin_unlock(&wq->qlock);
            pthread_mutex_lock((&wq->wlock));
            set_tmo(&ts, 10*TMO_1S);
            rc = pthread_cond_timedwait(&wq->wake, &wq->wlock, &ts);
            pthread_mutex_unlock(&wq->wlock);
            if (rc) {
                if (rc == ETIMEDOUT) {
                    LOG(LOG_DBG, "wq tmo");
                    continue;
                } else {
                    LOG(LOG_ERR, "wq err:%d", rc);
                    continue;
                }
            }
        } else {
            list_del_init(&rq->list);
            wq->size--;
            pthread_spin_unlock(&wq->qlock);
            start_rq(rq);
        }
    }
    LOG(LOG_INFO, "EDR worker thread exiting");

    return NULL;
}


//
// EDR's libfabric completion queue thread
//
static void *edr_cq_thread(void *arg) {
    F_EDR_OPQ_t *cq = (F_EDR_OPQ_t *)arg;
    struct timespec ts;
    F_EDR_t *rq = NULL;
    F_POOL_DEV_t *pd;
    F_POOL_t *pool = f_get_pool();

    int rc;

    LOG(LOG_INFO, "EDR I/O completion thread started");
    while (!edr_quit) {
        // if no EDR I/O is outstanding, sleep
        if (!atomic_read(&edr_io_total)) {
            pthread_mutex_lock(&cq->wlock);
            set_tmo(&ts, 10*TMO_1S);
            rc = pthread_cond_timedwait(&cq->wake, &cq->wlock, &ts);
            pthread_mutex_unlock(&cq->wlock);
            if (rc) {
                pthread_mutex_unlock(&cq->wlock);
                if (rc == ETIMEDOUT) {
                    LOG(LOG_DBG, "cq tmo");
                    continue;
                } else {
                    LOG(LOG_ERR, "cq err:%d", rc);
                    continue;
                }
            }
        }

        // scan all pool devices for outstanding EDR I/Os
        for_each_pool_dev(pool, pd) {
            if (!atomic_read(&pd->edr_io_cnt))
                continue;   // no outstanding i/o on this one

            FAM_DEV_t *fdev = &pd->dev->f;
            struct fid_cq *cq = fdev->cq;

            // check progress
            if ((rc = check_cq(cq, &rq)) == -EAGAIN)
                continue;    // nothing yet, next device;

            if (!rq) {
                LOG(LOG_ERR, "error (%d) checking CQ on dev %u", rc, pd->pool_index);
                continue;
            } else {
                // update i/o counters and advance request
                atomic_dec(&edr_io_total);
                atomic_dec(&pd->edr_io_cnt);
                advance_rq(rq);
            }

        }
    }
    LOG(LOG_INFO, "EDR worker thread exiting");

    return NULL;
}

//
// Init EDR stuff, start threads etc.
//
int f_edr_init() {
    int             rc = 0;
    F_POOL_t        *pool = f_get_pool();
    pthread_attr_t  attr;

    ASSERT(pool);
    int N = pool->info.layouts_count;

    ON_ERROR_RC(pthread_attr_init(&attr), "attr init");
    ON_ERROR_RC(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE), "set attr");

    ON_ERROR_RC(init_edr_q(&edr_wq, NULL, 0, 0), "init wq");
    ON_ERROR_RC(init_edr_q(&edr_cq, NULL, 0, 0), "init cq");
    edr_wq.idy = EDR_WQ;
    edr_cq.idy = EDR_CQ;

    ON_NOMEM_RET(free_s = calloc(N, sizeof(F_EDR_OPQ_t)), "free S");
    ON_NOMEM_RET(free_m = calloc(N, sizeof(F_EDR_OPQ_t)), "free M");
    ON_NOMEM_RET(free_l = calloc(N, sizeof(F_EDR_OPQ_t)), "free L");

    ON_NOMEM_RET(edr_encode_tables = calloc(N, sizeof(u8 *)), "encode tables");
    ON_NOMEM_RET(edr_rs_matrices = calloc(N, sizeof(u8 *)), "R-S matricies");

    // for each layout
    for (int i = 0; i < N; i++) {
        F_LAYOUT_t *lo = f_get_layout(i);
        if (lo == NULL) {
            LOG(LOG_ERR, "get layout [%d] info", i);
            rc = ULFS_ERROR_NOENV;
            goto _out;
        }
        int k = lo->info.data_chunks;
        int p = lo->info.chunks - lo->info.data_chunks;
        if (!p)
            continue;   // no parity - no recovery

        ON_ERROR_RC(init_edr_q(&free_s[i], lo, EDR_SQ_SZ, EDR_SQ_SC), "free S");
        ON_ERROR_RC(init_edr_q(&free_m[i], lo, EDR_MQ_SZ, EDR_MQ_SC), "free M");
        ON_ERROR_RC(init_edr_q(&free_l[i], lo, EDR_LQ_SZ, EDR_LQ_SC), "free L");
        free_s[i].idy = EDR_SQ;
        free_m[i].idy = EDR_MQ;
        free_l[i].idy = EDR_LQ;

        if (!(edr_encode_tables[i] = make_encode_matrix(k, p, &edr_rs_matrices[i]))) {
            LOG(LOG_ERR, "making encode matrix for lo %d", i);
            return -EINVAL;
        }
    }

    ON_ERROR_RC(pthread_create(&edr_wq.tid, &attr, edr_wq_thread, &edr_wq), "wq thread create");
    ON_ERROR_RC(pthread_create(&edr_cq.tid, &attr, edr_cq_thread, &edr_cq), "cq thread create");
    atomic_set(&edr_io_total, 0);

_out:

    return rc;
}

static void free_q(F_EDR_OPQ_t *q) {
    F_EDR_t *rq = NULL, *next;

    list_for_each_entry_safe(rq, next, &q->qhead, list) {
        list_del(&rq->list);
        free(rq->iobuf);
        free(rq->sattr);
        ss_free(rq->ss);
    }
}

//
// Clean up everything EDR-related
//
int f_edr_quit() {
    F_POOL_t        *pool = f_get_pool();
    ASSERT(pool);
    int N = pool->info.layouts_count;

    edr_quit = 1;
    if (edr_io_total.counter) {
        LOG(LOG_WARN, "EDR I/O (%d) in progress, can't quit", edr_io_total.counter);
        return -EAGAIN;
    }
    if(pthread_join(edr_wq.tid, NULL))
        LOG(LOG_ERR, "worker thread");
    if(pthread_join(edr_cq.tid, NULL))
        LOG(LOG_ERR, "completion thread");

    for (int i = 0; i < N; i++) {
        F_LAYOUT_t *lo = f_get_layout(i);

        if (!(lo->info.chunks - lo->info.data_chunks))
            continue;   // no parity - no recovery

        if (f_wpool_wait_all_jobs_done(lo->lp->wpool, 10000))
            LOG(LOG_ERR, "wait all jobs failed");

        free_q(&free_s[i]);
        free_q(&free_m[i]);
        free_q(&free_l[i]);

        free(edr_encode_tables[i]);
        free(edr_rs_matrices[i]);
    }

    // drop anything that still seats in work q
    free_q(&edr_wq);
    free(edr_encode_tables);

    return 0;
}

int f_recover_stripes(F_WTYPE_t cmd, void *arg, int thread_id) {
    F_EDR_t *rq = (F_EDR_t *)arg;
    F_LO_PART_t *lp = rq->lo->lp;
    F_LAYOUT_t *lo = rq->lo;
    f_stripe_t s = rq->ss->stripes[rq->scur];
    F_RECOVERY_t *rctx = (F_RECOVERY_t *)rq->ctx;

    ASSERT(rctx);
    ASSERT(cmd == F_WT_DECODE);
    if (!rq->err) {
        int cs = lo->info.chunk_sz*rq->scnt;
        int nerr = bitmap_weight(&rq->fvec, sizeof(u64));
        int nd = lo->info.chunks - nerr;
        u8 *dvec[nd], *evec[nerr];

        ASSERT(nerr);

        LOG(LOG_DBG3, "%s[%d]-w%d: decoding %d stripes s0=%lu (%d of %d)",
            lo->info.name, lp->part_num, thread_id, rq->scnt, s, rq->scur + 1, rq->ss->count);
        for (int i = 0; i < nd; i++)
            dvec[i] = rq->iobuf + rq->dchnk[i]*cs;
        for (int i = 0; i < nerr; i++)
            evec[i] = rq->iobuf + rq->pchnk[i]*cs;

        decode_data(ISAL_CMD, cs, nd, nerr, rctx->decode_table, dvec, evec);

    } else {
        LOG(LOG_INFO, "%s[%d]-w%d: not decoding %d stripes s0=%lu (%d of %d), rq nerr=%d",
            lo->info.name, lp->part_num, thread_id, rq->scnt, s, rq->scur + 1, 
            rq->ss->count, rq->nerr);
    }

    // proceed to next step (edr_calc_done, presumably)
    rq->next_call(rq, rq->ctx);

    return 0;

}

int f_encode_stripes(F_WTYPE_t cmd, void *arg, int thread_id) {
    F_EDR_t *rq = (F_EDR_t *)arg;
    F_LO_PART_t *lp = rq->lo->lp;
    F_LAYOUT_t *lo = rq->lo;
    f_stripe_t s = rq->ss->stripes[rq->scur];

    ASSERT(cmd == F_WT_ENCODE);
    if (!rq->err) {
        int cs = lo->info.chunk_sz*rq->scnt;
        int nd = lo->info.data_chunks;
        int lx = lo->info.conf_id;
        int np = lo->info.chunks - nd;
        u8 *dvec[nd], *pvec[np];

        LOG(LOG_DBG3, "%s[%d]-w%d: encoding stripe %lu (%d of %d)",
            lo->info.name, lp->part_num, thread_id, s, rq->scur + 1, rq->ss->count);
        for (int i = 0; i < nd; i++)
            dvec[i] = rq->iobuf + rq->dchnk[i]*cs;
        for (int i = 0; i < np; i++)
            pvec[i] = rq->iobuf + rq->pchnk[i]*cs;

        encode_data(ISAL_CMD, cs, nd, np, edr_encode_tables[lx], dvec, pvec);

    } else {
        LOG(LOG_INFO, "%s[%d]-w%d: not encoding stripe %lu (%d of %d), rq error(s) %d",
            lo->info.name, lp->part_num, thread_id, s, rq->scur + 1, rq->ss->count, rq->nerr);
    }

    // proceed to next step
    rq->next_call(rq, rq->ctx);

    return 0;
}

int f_verify_stripes(F_WTYPE_t cmd, void *arg, int thread_id)
{
	ASSERT(cmd == F_WT_VERIFY);
	return 0;
}

struct ss_data {
	unsigned long		devmap[F_DEVMAP_SIZE];
	struct f_stripe_set 	ss;
};

//
// Encode batch completed callback
//
int encode_batch_done_cb(F_EDR_t *rq, void *ctx) {
	F_LAYOUT_t *lo = rq->lo;;
	F_LO_PART_t *lp = lo->lp;

        LOG(LOG_DBG, "%s[%d]: encode rq (s0=%lu, cnt=%d) completed, status %d, err=%d)", 
            lo->info.name, lp->part_num, rq->ss->stripes[0], rq->ss->count, rq->status, rq->nerr);

	ss_free(rq->ss);
	return 0;
}

/*
 * Submit a set of committed stripes for EC encoding.i Called from f_commit_stripe().
 * All stripe #s n the set are expected to be global and to belong to the local allocator partition.
 * Returns 0 or error
 */
int f_submit_encode_stripes(F_LAYOUT_t *lo, struct f_stripe_set *ss)
{
	F_LO_PART_t *lp = lo->lp;
	F_POOL_t *pool = lo->pool;
	struct ss_data *buckets;
	F_ITER_t *sm_it;
	int batch_size = min(ss->count, lp->w_thread_cnt);	// use all worker threads
	int n = 0, i = 0, j = 0, rc = 0;

	ASSERT(lp);

	/*
	 * Split the stripe set by the slab buckets devmaps
	 * to enable potential request merge
	 */
	buckets = calloc(lp->slab_count, sizeof(struct ss_data));
	ASSERT(buckets);
	sm_it = f_map_get_iter(lp->slabmap, F_NO_CONDITION, 0); // TODO: use sm_slab_mapped cond
	for_each_iter(sm_it) {
		f_slab_t slab = sm_it->entry;
		unsigned long devmap[F_DEVMAP_SIZE];
		struct ss_data *ssd = NULL;

		if (slab >= lp->slab_count) break;
		if (!slab_allocated(lp, slab)) continue;

		rc = f_get_slab_devmap(lp, slab, devmap);
		ASSERT(!rc && !bitmap_empty(devmap, pool->info.pdev_max_idx+1));

		for (i = 0; i < lp->slab_count; i++) {
			ssd = &buckets[i];
			if (bitmap_empty(ssd->devmap, pool->info.pdev_max_idx+1) ||
				bitmap_equal(ssd->devmap, devmap, pool->info.pdev_max_idx+1))
					break;
		}
		ASSERT(ssd);

		if (bitmap_empty(ssd->devmap, pool->info.pdev_max_idx+1)) {
			bitmap_copy(ssd->devmap, devmap, pool->info.pdev_max_idx+1);
			ssd->ss.count = 0;
			ssd->ss.stripes = NULL; /* defer allocation untill we find a matching stripe */
			n = i + 1;
		}
	}
	f_map_free_iter(sm_it);

	buckets = realloc(buckets, sizeof(struct ss_data) * n);
	ASSERT(buckets);

	for (i = 0; i < ss->count; i++) {
		struct ss_data *ssd = NULL;
		f_stripe_t stripe;
//		struct ec_worker_data *ecw_data;
		struct f_stripe_set *bss;
		f_slab_t slab;
		unsigned long devmap[F_DEVMAP_SIZE];

		/* Remap global stripe # to local */
		ASSERT(f_map_prt_my_global(lp->claimvec, ss->stripes[i]));
		stripe = f_map_prt_to_local(lp->claimvec, ss->stripes[i]);

		/* Get this stripe's bitmap to find the right bucket */
		slab = stripe_to_slab(lo, stripe);
		rc = f_get_slab_devmap(lp, slab, devmap);
		ASSERT(!rc && !bitmap_empty(devmap, pool->info.pdev_max_idx+1));

		/* Find the matching bucket in the buckets array */
		for (j = 0; j < n; j++) {
			ssd = &buckets[j];
			ASSERT(!bitmap_empty(ssd->devmap, pool->info.pdev_max_idx+1));
			if (bitmap_equal(ssd->devmap, devmap, pool->info.pdev_max_idx+1))
				break;
		}
		ASSERT(j < n && ssd);
		if (!ssd->ss.stripes) ssd->ss.stripes = calloc(batch_size, sizeof(f_stripe_t));
		ssd->ss.stripes[ssd->ss.count++] = stripe;
		if (ssd->ss.count < batch_size) continue;

		/* Exceeded the batch size, submit what we have so far */
/*		ecw_data = calloc(1, sizeof(struct ec_worker_data));
		ASSERT(ecw_data);
		ecw_data->lp = lp;
		ecw_data->ss.count = ssd->ss.count;
		ecw_data->ss.stripes = calloc(batch_size, sizeof(f_stripe_t));
		memcpy(ecw_data->ss.stripes, ssd->ss.stripes, ssd->ss.count * sizeof(f_stripe_t));
*/
		bss = ss_alloc(batch_size);
		ASSERT(bss);
		bss->count = ssd->ss.count;
		memcpy(bss->stripes, ssd->ss.stripes, ssd->ss.count * sizeof(f_stripe_t));

		LOG(LOG_DBG, "%s[%d]: submitting %d stripes (s0=%lu) for encoding (bucket 0x%lx)",
	            lo->info.name, lp->part_num, bss->count, bss->stripes[0], *(ssd->devmap));

//		rc += f_wpool_add_work(lp->wpool, F_WT_ENCODE, F_WP_NORMAL, ecw_data);
		rc = f_edr_submit(lo, bss, NULL, encode_batch_done_cb, NULL);
		if (rc) {
			LOG(LOG_ERR, "%s[%d]: failed to submit stripe set for encode, rc=%d",
				lo->info.name, lp->part_num, rc);
			ss_free(bss);
			break;
		}

		/* Reset the busket's stripe set */
		memset(ssd->ss.stripes, 0, ssd->ss.count * sizeof(f_stripe_t));
		ssd->ss.count = 0;
	}

	/* Now submit the rest of stripe sets for encoding */
	for (j = 0; j < n; j++) {
		struct ss_data *ssd = &buckets[j];
		struct f_stripe_set *bss;

		/* Skip empty buckets */
		if (!ssd->ss.count) continue;

		bss = ss_alloc(batch_size);
		ASSERT(bss);
		bss->count = ssd->ss.count;
		memcpy(bss->stripes, ssd->ss.stripes, ssd->ss.count * sizeof(f_stripe_t));

		LOG(LOG_DBG, "%s[%d]: submitting %d stripes (s0=%lu) for encoding (bucket 0x%lx)",
	            lo->info.name, lp->part_num, bss->count, bss->stripes[0], *(ssd->devmap));

		rc = f_edr_submit(lo, bss, NULL, encode_batch_done_cb, NULL);
		if (rc) {
			LOG(LOG_ERR, "%s[%d]: failed to submit stripe set for encode, rc=%d",
				lo->info.name, lp->part_num, rc);
			ss_free(bss);
			break;
		}

	}

/*
	rc = f_wpool_wait_queue_jobs_done(lp->wpool, F_WP_NORMAL, 500);
	if (rc) LOG(LOG_DBG2, "%s[%d]: error %d in f_wpool_wait_queue_jobs",
		lo->info.name, lp->part_num, rc);
*/
	return rc;
}

//
// Get a request from one of the free queues
//  *this_q - if not NULL, always use this q, returns the appropriate q otherwise
//  qix     - layout (and hence queue) index
//  cnt     - stripe count (size) of the request 
//  wait    - 1: will block and wait forevr for free RQ to become available
//            0: will return NULL/EAGAIN if nothing available
//           -1: will block and wait once, return NULL/ETIMEDOUT on first timeout 
//
static F_EDR_t *get_free_rq(F_EDR_OPQ_t **this_q, int qix, int cnt, int wait) {
    F_EDR_OPQ_t *q = NULL;
    F_EDR_t *rq = NULL;
    struct timespec ts;
    int rc = 0;

    if (*this_q) {
        q = *this_q;
    } else {
        if (cnt > EDR_MQ_SC) {
            // rq size L, try L free q first, them M, then S. If S is empty go back to L
            q = &free_l[qix];
            if (!q->size) {
                q = &free_m[qix];
                if (!q->size) {
                    q = &free_s[qix];
                    if (!q->size)
                        q = &free_l[qix];
                }
            }

        } else if (cnt > 1) {
            // rq size M, try M then S. If S is empty, go back to M, don't use L
            q = &free_m[qix];
            if (!q->size) {
                q = &free_s[qix];
                if (!q->size)
                    q = &free_m[qix];
            }
        } else {
            // rq size S, try S, if empty go to M, if empty go back to S. Never use L
            q = &free_s[qix];
            if (!q->size) {
                q = &free_m[qix];
                if (!q->size)
                    q = &free_s[qix];
            }
        }
        *this_q = q;
    }
    LOG(LOG_DBG3, "getting EDR rq(size=%d) from '%s' q[%d]\n", cnt, EDR_PR_Q(q), qix);

    do {
        // get a free request
        pthread_spin_lock(&q->qlock);
        if (!list_empty(&q->qhead)) {
            break;
        } else {
            pthread_spin_unlock(&q->qlock);
            if (wait) {
                // no free requestes, wait for one becoming available
                pthread_mutex_lock(&q->wlock);
                set_tmo(&ts, 10*TMO_1S);
                rc = pthread_cond_timedwait(&q->wake, &q->wlock, &ts);
                pthread_mutex_unlock(&q->wlock);
                if (rc) {
                    if (rc == ETIMEDOUT) {
                        LOG(LOG_ERR, "free q '%s' wait TMO, lo %d", EDR_PR_Q(q), qix);
                        if (wait < 0) wait = 0;
                        continue;
                    } else {
                        LOG(LOG_ERR, "free q '%s' wait err, lo %d:%d", EDR_PR_Q(q), qix, rc);
                        errno = rc;
                        return NULL;
                    }
                }
            } else {
                // no waiting
                errno = EAGAIN;
                return NULL;
            }
        }
    } while (1);

    // get first ra in free q
    rq = list_first_entry(&q->qhead, F_EDR_t, list);
    list_del_init(&rq->list);
    q->size--;
    pthread_spin_unlock(&q->qlock);
    rq->myq = q;    // remeber where to return this request

    return rq;
}

/*
 * Submit Encode/Decode/Recover(/Verify) Request
 *
 * Parmas
 *      lo              layout pointer
 *      ss              stripe set to encode/recover
 *      fvec            failed chunks bitmap, if == 0: encode parities according to layout
 *                          if == <all 1s>: verify stripes
 *      done_cb         callaback function to call when state becomes DONE (or NULL if not needed)
 *      ctx             CB's parameter
 *
 *  Returns
 *       0              success
 *      <0              error
*/
int f_edr_submit(F_LAYOUT_t *lo, struct f_stripe_set *ss, uint64_t *fvec, F_EDR_CB_t done_cb, void *ctx) {
    int l = lo->info.conf_id;
    F_EDR_OPQ_t *q = NULL;
    F_EDR_t *rq = NULL;

// FIXME
//return 0;

    if (!fvec) {
        // ENCODE

        // since we can encode only one stripe at a time (due to rotating parity)
        // we will set scur to 1, never mind the ss size
        if (!(rq = get_free_rq(&q, l, 1, 1)))
            return -errno;

        rq->fvec = 0;
        rq->scnt = 1;   // one stripe at a time
        rq->op = EDR_OP_ENC;

    } else if (*fvec == ~0UL) {
        // VERIFY
        return -EINVAL; // FIXME
    } else {
        if (*fvec == 0UL) {
            LOG(LOG_ERR, "layout [%d]: recover rq with empty fail vector", l);
            return -EINVAL;
        }
        // RECOVER

        // try to get as large request as we can, recover can do multiple stripes at a time
        if (!(rq = get_free_rq(&q, l, ss->count, -1)))
            return -errno;
        rq->fvec = *fvec;
        rq->scnt = min(rq->sall, ss->count);
        rq->op = EDR_OP_REC;

    }

    rq->ss = ss;
    rq->lo = lo;
    rq->scur = 0;
    rq->status = 0;
    rq->nerr = 0;
    rq->completion = done_cb;
    rq->ctx = ctx;

    // and onto work q
    pthread_spin_lock(&edr_wq.qlock);
    list_add_tail(&rq->list, &edr_wq.qhead);
    edr_wq.size++;
    pthread_spin_unlock(&edr_wq.qlock);
    pthread_cond_signal(&edr_wq.wake);

    //printf("EDR rq '%s' from '%s' Q submitted\n", EDR_PR_R(rq), EDR_PR_Q(rq->myq));

    return 0;
}
