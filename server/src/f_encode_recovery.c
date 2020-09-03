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
#include "f_encode_recovery.h"
#include "f_allocator.h"
#include "fam_stripe.h"
#include "f_ec.h"
#include <pthread.h>


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

static u8 **encode_tables, **rs_matrices;

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
        // remeber wich chunks are data and parity
        if (chunk->data >= 0)
            rq->dchnk[dx++] = i;
        else
            rq->pchnk[px++] = i;

        if (rq->fvec == 0) {
            if ((chunk->data < 0 && !wr) || (chunk->data >= 0 && wr))
                continue;   // encode: skip parity on read and data on write
        } else if (rq->fvec == ~0L) {
            if (wr)
                continue;   // verify: don't write and dont't skip
        } else {
            if ((test_bit(i, &rq->fvec) && !wr) || (!test_bit(i, &rq->fvec) && wr))
                continue;   // recover: skip error chunks on read and good ones on write
        }

	pdev = chunk->pdev;
	media_id = pdev->pool_index;

	fdev = &pdev->dev->f;
	tgt_srv_addr = &fdev->fi_addr;
	local_desc = NULL; // FIXME
	buf = &rq->iobuf[i*len];
	tx_ep = fdev->ep;

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
    if (!rq->sattr || rq->sattr->stripe_0 + rq->sattr->stripe_in_part != s) {
        // map to physical stripe
        if ((rc = f_map_fam_stripe(lo, &rq->sattr, s))) {
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


static int recover_read_done(F_EDR_t *rq, void *ctx) {
    return 0;
}

static int vfy_read_done(F_EDR_t *rq, void *ctx) {
    return 0;
}

//
// Current stripe is written out
// Porcess next stripe in SS: if the last one is doen, finish up
// this request
//
static int encode_read_done(F_EDR_t *rq, void *ctx);
static int encode_write_done(F_EDR_t *rq, void *ctx) {
    int rc = 0;
    int x = rq->scur;
    f_stripe_t s = rq->ss->stripes[x], s0 = rq->ss->stripes[0];
    F_LAYOUT_t *lo = rq->lo;
    F_LO_PART_t *lp = rq->lo->lp;

    do {
        if (!rq->err) {
            f_laminate_stripe(lp->layout, s);
            LOG(LOG_DBG3, "%s[%d]: stripe %lu laminated (%d of %d)",
                lo->info.name, lp->part_num, s, x + 1, rq->ss->count);
        } else {
            LOG(LOG_DBG3, "%s[%d]: stripe %lu in error (%d of %d): %d",
                lo->info.name, lp->part_num, s, x + 1, rq->ss->count, rq->err);
        }

        rq->scur++;
        if (rq->scur >= rq->ss->count) {
            // last stripe in set done
            int l = lo->info.conf_id;
            rq->status = rq->nerr ? -EIO : 0;

            // Mark the claim vector to be flushed
            SetLPCVFlush(lp);
            if (rq->completion)
                rq->completion(rq, rq->ctx);
            else 
                LOG(LOG_DBG, "%s[%d]: s0=%lu - %d stripes laminated, %d errors (no CB)",
                    lo->info.name, lp->part_num, s0, rq->ss->count - rq->nerr, rq->nerr);

            // return request to free queue
            rq->state = F_EDR_FREE;
            rq->err = 0;
            rq->nerr = 0;
            rq->status = 0;

            pthread_spin_lock(&free_s[l].qlock);
            list_add_tail(&rq->list, &free_s[l].qhead);
            free_s[l].size++;
            pthread_spin_unlock(&free_s[l].qlock);

            // wake up any client(s) that could be waiting for ree RQ
            pthread_cond_broadcast(&free_s[l].wake);
            //pthread_cond_signal(&free_s[l].wake);

        } else {
            // repeat the whole process for the next stripe in set
            atomic_set(&rq->busy, 0);
            rq->err = 0;
            rq->next_call = encode_read_done;
            rc = edr_read(rq);
        }
    } while (rc);

    return 0;
}

//
// Encode EC calc is done, next step: write out parity
//
static int encode_calc_done(F_EDR_t *rq, void *ctx) {
    int rc = 0;
    int x = rq->scur;
    f_stripe_t s = rq->ss->stripes[x];
    F_LAYOUT_t *lo = rq->lo;

    rq->next_call = encode_write_done;

    LOG(LOG_DBG3, "stripe %lu (%d of %d)", s, x + 1, rq->ss->count);
    if (!rq->err) {
        if ((rc = edr_io_submit(rq, 1))) {
            LOG(LOG_ERR,"stripe:%lu in layout %s - submit i/o error:%d", s, lo->info.name, rc);
            goto _err;

        }
        return 0;
    }

_err:
    // current stripe is in error, no point in writing. invoke callback directly
    // (NOTE: this is worker thread context, but oh well...)
    if (rc)
        rq->err = rc;
    rq->nerr++;
    rq->next_call(rq, rq->ctx);
    return rc;
}

//
// Encode stripe: read done, start EC calculations
//
static int encode_read_done(F_EDR_t *rq, void *ctx) {
    F_LO_PART_t *lp = rq->lo->lp;
    int rc = 0;

    LOG(LOG_DBG3, "stripe %lu (%d of %d)", rq->ss->stripes[rq->scur], rq->scur + 1, rq->ss->count);
    ASSERT(atomic_read(&rq->busy) == 0);
    rq->next_call = encode_calc_done;
    rq->state = F_EDR_CALC;
    if ((rc = f_wpool_add_work(lp->wpool, F_WT_ENCODE, F_WP_NORMAL, rq))) {
        LOG(LOG_ERR, "%s[%d]: failed to submit stripe set for encode, rc=%d",
            rq->lo->info.name, lp->part_num, rc);
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

    if (rq->fvec == 0) {
        rq->next_call = encode_read_done;
    } else if (rq->fvec == ~0UL) {
        rq->next_call = vfy_read_done;
    } else {
        rq->next_call = recover_read_done;
    }

    if ((rc = edr_read(rq))) {
        // error submitting read i/o, finsh this directly
        LOG(LOG_ERR, "read: %d, rq err:%d", rc, rq->status);
        encode_write_done(rq, rq->ctx);
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
        char *rn = rq->fvec == 0 ? "ENC" : (rq->fvec == ~0L ? "VFY" : "REC");
        rq->nerr++;
        LOG(LOG_ERR, "I/O error (%d/%d) on %s rq, str=%d, ss cnt=%d, lid=%d",
            rq->err, rq->prov_err, rn, rq->scur, rq->ss->count, rq->lo->info.conf_id);
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
    F_EDR_t *rq;
    F_POOL_DEV_t *pd;
    F_POOL_t *pool = f_get_pool();

    int rc;

    LOG(LOG_INFO, "EDR worker thread started");
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

    ON_NOMEM_RET(free_s = calloc(N, sizeof(F_EDR_OPQ_t)), "free S");
    ON_NOMEM_RET(free_m = calloc(N, sizeof(F_EDR_OPQ_t)), "free M");
    ON_NOMEM_RET(free_l = calloc(N, sizeof(F_EDR_OPQ_t)), "free L");

    ON_NOMEM_RET(encode_tables = calloc(N, sizeof(u8 *)), "encode tables");
    ON_NOMEM_RET(rs_matrices = calloc(N, sizeof(u8 *)), "R-S matricies");

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

        ON_ERROR_RC(init_edr_q(&free_s[i], lo, 64, 1), "free S");
        ON_ERROR_RC(init_edr_q(&free_m[i], lo, 8, 4), "free M");
        ON_ERROR_RC(init_edr_q(&free_l[i], lo, 1, 16), "free L");

        if (!(encode_tables[i] = make_encode_matrix(k, p, &rs_matrices[i]))) {
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

        free(encode_tables[i]);
        free(rs_matrices[i]);
    }

    // drop anything that still seats in work q
    free_q(&edr_wq);
    free(encode_tables);

    return 0;
}

int f_recover_stripes(F_WTYPE_t cmd, void *arg, int thread_id)
{
	struct ec_worker_data *ecw_data = (struct ec_worker_data *)arg;
	F_LO_PART_t *lp = ecw_data->lp;
	F_LAYOUT_t *lo = lp->layout;
	struct f_stripe_set *ss = &ecw_data->ss;
	int i, rc = 0;

	ASSERT(cmd == F_WT_DECODE);
	for (i = 0; i < ss->count; i++) {
		f_stripe_t s = ss->stripes[i];

		LOG(LOG_DBG3, "%s[%d]-w%d: recovering stripe %lu (%d of %d)",
			lo->info.name, lp->part_num, thread_id, s, i, ecw_data->ss.count);
		usleep(500);

		if (rc ) return -EAGAIN;
	}

	if (ss->stripes) free(ss->stripes);
	if (ecw_data) free(ecw_data);
	return 0;
}

#if 0
int f_encode_stripes(F_WTYPE_t cmd, void *arg, int thread_id)
{
	struct ec_worker_data *ecw_data = (struct ec_worker_data *)arg;
	F_LO_PART_t *lp = ecw_data->lp;
	F_LAYOUT_t *lo = lp->layout;
	struct f_stripe_set *ss = &ecw_data->ss;
	int i, rc = 0;

	ASSERT(cmd == F_WT_ENCODE);
	for (i = 0; i < ss->count; i++) {
		f_stripe_t s = ss->stripes[i];

		LOG(LOG_DBG3, "%s[%d]-w%d: encoding stripe %lu (%d of %d)",
			lo->info.name, lp->part_num, thread_id, s, i, ecw_data->ss.count);
		usleep(500);

		if (rc ) return -EAGAIN;

		f_laminate_stripe(lp->layout, s);
	}

	/* Mark the claim vector to be flushed */
	SetLPCVFlush(lp);

	if (ss->stripes) free(ss->stripes);
	if (ecw_data) free(ecw_data);
	return 0;
}
#endif
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

        encode_data(ISAL_CMD, cs, nd, np, encode_tables[lx], dvec, pvec);
        //encode_data(256, cs, nd, np, encode_tables[lx], dvec, pvec);

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
    struct timespec ts;
    int rc = 0;
    F_EDR_t *rq;

// FIXME
//return 0;

    if (!fvec) {
        // ENCODE
_encode:

        do {
            // get a free request
            pthread_spin_lock(&free_s[l].qlock);
            if (!list_empty(&free_s[l].qhead)) {
                break;
            } else {
                // no free requestes, wait for one becoming available
                pthread_spin_unlock(&free_s[l].qlock);
                pthread_mutex_lock(&free_s[l].wlock);
                set_tmo(&ts, 10*TMO_1S);
                pthread_cond_timedwait(&free_s[l].wake, &free_s[l].wlock, &ts);
                pthread_mutex_unlock(&free_s[l].wlock);
                if (rc) {
                    if (rc == ETIMEDOUT) {
                        LOG(LOG_ERR, "free 'S' wait TMO, lo %d", l);
                        continue;
                    } else {
                        LOG(LOG_ERR, "free 'S' wait err, lo %d:%d", l, rc);
                        return -rc;
                    }
                }
            }
        } while (1);

        // get it off free q
        rq = list_first_entry(&free_s[l].qhead, F_EDR_t, list);
        list_del_init(&rq->list);
        free_s[l].size--;
        pthread_spin_unlock(&free_s[l].qlock);

        rq->ss = ss;
        rq->lo = lo;
        rq->fvec = 0;
        rq->scur = 0;
        rq->scnt = 1;   // one stripe at a time
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

    } else if (*fvec == ~0UL) {
        // VERIFY
    } else {
        if (*fvec == 0UL)
            goto _encode;
        // RECOVER
    }

    return 0;
}
