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
#include <mpi.h>

#include "log.h"
#include "unifycr_debug.h"
#include "unifycr_const.h"
#include "f_env.h"
#include "f_error.h"
#include "f_maps.h"
#include "f_bitmap.h"
#include "f_map.h"
#include "f_pool.h"
#include "f_layout.h"
#include "f_wpool.h"
#include "f_lf_connect.h"
#include "f_layout_ctl.h"
#include "f_allocator.h"
#include "f_stripe.h"
#include "f_helper.h"
#include "f_ec.h"
#include "f_encode_recovery.h"
#include "f_recovery.h"


static F_EDR_OPQ_t  edr_wq;
static F_EDR_OPQ_t  edr_cq;
static F_EDR_OPQ_t  *free_s;
static F_EDR_OPQ_t  *free_m;
static F_EDR_OPQ_t  *free_l;

static F_EDR_BLQ_t  backlog;

static F_RNTFY_t    *rntfy;
pthread_mutex_t     ntfy_lock = PTHREAD_MUTEX_INITIALIZER;

static atomic_t edr_io_total;
static atomic_t *enc_ops;

static int edr_quit = 0;

static inline void set_tmo(struct timespec *ts, uint64_t usec) {
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += (ts->tv_nsec + (unsigned long)usec*1000L)/1000000000L;
    ts->tv_nsec = (ts->tv_nsec + (unsigned long)usec*1000L)%1000000000L;
}

static inline int chunk_role(F_LAYOUT_t *lo, f_stripe_t s, int ext) {
    int role;
    int soff = s - stripe_to_stripe0(lo, s);
    int chunks = lo->info.chunks;
    int parities = chunks - lo->info.data_chunks;

    role = (ext - soff)%chunks;
    role = (role < 0) ? (role + chunks) : role;
    if (role < parities)
        return -parities + role;  // -NPar ... -1, add +NPar to get P index
    else
        return role - parities;   // 0 ... NData, straight D index
}

static char* c2s(char *buf, F_LAYOUT_t *lo, f_stripe_t s, int ext) {
    int r = chunk_role(lo, s, ext);
    char type = 'D';
    if (r < 0) {
        type = 'P';
        r += lo->info.chunks - lo->info.data_chunks;
    }
    snprintf(buf, sizeof(long), "%c[%02d]", type, (char)r);
    return buf;
}

#define C2S(l, s, e) ({ long b;\
        c2s((char *)&b, l, s, e);\
        (char *)&b;\
        })

/*
static inline void map_stripe_chunk(N_CHUNK_t *chunk, int extent, int chunks, int parities)
{
	int p, chunk_n = chunk->node;

	p = (chunk_n - extent) % chunks;
	p = (p < 0)? (p + chunks) : p;
	if (p < parities) {
		chunk->parity = p;
		chunk->data = -1;
	} else {
		chunk->data = p - parities;
		ASSERT(chunk->data >= 0 && chunk->data < (chunks - parities));
		chunk->parity = -1;
	}
}
*/


// make these global as they'll be needed by recovery thread
u8 **edr_encode_tables, **edr_encode_matrices;

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

    if (!rq->sattr) {
        LOG(LOG_WARN, "%s:sattr is 0 for %crq %p, s[0]=%lu/%u, s[cur=%d]=%lu\n",
            f_get_pool()->mynode.hostname, wr?'w':'r', rq, rq->ss->stripes[0], 
            rq->ss->count, rq->scur,  rq->ss->stripes[rq->scur]);

        // map to physical stripe
        if ((rc = f_map_fam_stripe(rq->lo, &rq->sattr, rq->ss->stripes[rq->scur], 0))) {
            LOG(LOG_ERR,"stripe:%lu mapping error:%d", rq->ss->stripes[rq->scur], rc);
            return rc;
        }
    }

    N_STRIPE_t *stripe = rq->sattr;
    size_t chunk_sz = stripe->chunk_sz;
    uint32_t len = chunk_sz*rq->scnt;

    nchunks = stripe->d + stripe->p;
    BUGON(nchunks > 64, "nchunks=%d", nchunks);
    rq->ready = 0;
    rq->state = wr ? F_EDR_WRITE : F_EDR_READ;
    int px = 0, dx = 0;
    char c = '*';
    unsigned int failed_media[nchunks];
    int fcnt = 0;

    if (rq->op == EDR_OP_REC)
        for (int i = 0; i < nchunks; i++)
            if (test_bit(i, &rq->fvec)) 
                failed_media[fcnt++] = stripe->chunks[i].pdev->pool_index;

    BUGON(fcnt > stripe->p, "fcnt=%d", fcnt);   // max 'p' chunks may fail
    BUGON(rq->lo->info.data_chunks != stripe->d || 
          rq->lo->info.chunks - rq->lo->info.data_chunks != stripe->p, 
          "lo:%d/%d, str:%d/%d", rq->lo->info.chunks, rq->lo->info.data_chunks, stripe->d, stripe->p);

#if 0
    printf(">>> @%s:%s stripes:\n", f_get_pool()->mynode.hostname, wr?"write":"read");
    for (int i = 0; i < rq->scnt; i++) printf("    s[%d]=%lu\n", rq->scur + i, rq->ss->stripes[rq->scur + i]);
#endif

    atomic_set(&rq->busy, nchunks);
    for (int i = 0; i < nchunks && !rc; i++) {
        
        chunk = get_fam_chunk(stripe, i);
	pdev = chunk->pdev;
	media_id = pdev->pool_index;
	fdev = &pdev->dev->f;
	tgt_srv_addr = &fdev->fi_addr;

        if (rq->op == EDR_OP_ENC) {
            // encode: based on chunk's role (d/p), skip parity on read and data on write
            // remeber wich chunks are data and parity
            c = 'E';
            if (chunk->data >= 0) {
                rq->dchnk[dx++] = i;
            } else {
                rq->pchnk[px++] = i;
            }

            if ((chunk->data < 0 && !wr) || (chunk->data >= 0 && wr)) {
                atomic_dec(&rq->busy);
                continue;
            }
        } else if (rq->op == EDR_OP_REC) {
            // recover: based on chunk's device, skip error chunks on read and good ones on write
            // remeber good chunk and failed ones (the latter go as 'parity')
            c = 'R';
            int failed = 0;
            for (int j = 0; j < fcnt && !failed; j++) 
                if (media_id == failed_media[j])
                    failed = 1;
            if (failed) {
            //if (test_bit(i, &rq->fvec)) {
                rq->fd_f[px] = media_id;
                rq->pchnk[px++] = i;
                if (!wr) {
                    atomic_dec(&rq->busy);
                    continue;
                }
            } else {
                rq->fd_h[dx] = media_id;
                rq->dchnk[dx++] = i;
                if (wr || dx > stripe->d) { // skip WR or RD -> if more than we need for recovery
                //if (wr) { // skip WR
                    atomic_dec(&rq->busy);
                    continue;
                }
            }
        } else if (rq->op == EDR_OP_VFY) {
            c = 'V';
            if (chunk->data >= 0)
                rq->dchnk[dx++] = i;
            else
                rq->pchnk[px++] = i;
            if (wr) {
                atomic_dec(&rq->busy);
                continue;   // verify: don't write and dont't skip
            }
        } else {
            ASSERT(0);
        }

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

	LOG(LOG_DBG2,"%c-%s stripe:%lu[%d] - "
            "%u/%u/%s "
            "ext:%u->%s"
            "dev:%2u len:%u off:0x%lx @%2d",
            c, wr?"write":"read", rq->ss->stripes[rq->scur], i,
            stripe->extent, stripe->stripe_in_part, pr_chunk(pr_buf, chunk->data, chunk->parity), 
            chunk->node, C2S(rq->lo, rq->ss->stripes[rq->scur], chunk->node),
            media_id, len, off, i);
#if 0
        printf("*** @%s:%c-%s s=%lu c[%d]=%s -> %u %u@0x%lx [s_in_p*cs=%lx, s0_off=%lx]\n",
                f_get_pool()->mynode.hostname, c, wr?"write":"read", rq->ss->stripes[rq->scur], i,
                pr_chunk(pr_buf, chunk->data, chunk->parity), media_id, len, off,
                (unsigned long)stripe->stripe_in_part*chunk_sz, (unsigned long)chunk->p_stripe0_off);
#endif

	do {
	    rc = wr ? fi_write(tx_ep, buf, len, local_desc, *tgt_srv_addr, off,
                               fdev->mr_key, (void*)rq) :
                      fi_read(tx_ep, buf, len, local_desc, *tgt_srv_addr, off,
                              fdev->mr_key, (void*)rq);

	    if (!rc) {
                atomic_inc(&edr_io_total);
                atomic_inc(&pdev->edr_io_cnt);
                break;
	    } else if (rc != -FI_EAGAIN) {
                fi_err(rc, "%s: fi_%s failed on dev %u",
                       f_get_pool()->mynode.hostname, wr ? "write" : "read", media_id);
            } else {
                LOG(LOG_ERR, "fi_%s returned EAGAIN on dev %u", wr ? "write" : "read", media_id);
            }
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
    F_LO_PART_t *lp = lo->lp;

    LOG(LOG_DBG2, "stripe %lu (%d of %d)", s, x + 1, rq->ss->count);
    if (rq->op == EDR_OP_ENC || rq->op == EDR_OP_VFY) {
        if (!f_stripe_slab_healthy(lo, s)) {
            LOG(LOG_ERR, "%s[%d]: %s - stripe %lu, slab is degraded or failed", 
                    lo->info.name, lo->lp->part_num, EDR_PR_R(rq), s);
            goto _err;
        }
    }

    // Get stripe properties for the 1st stripe in the set
    // This will work because encoding goes stripe-by-stripe and next stripe
    // will be re-evaluated if needed and recovery doesn't care of any sequential 
    // stripe attributes: we are not rotating parity on recovery
    if (!rq->sattr || f_map_prt_to_local(lp->claimvec, rq->sattr->stripe_0) + 
				rq->sattr->stripe_in_part != s) {
        // map to physical stripe
        if ((rc = f_map_fam_stripe(lo, &rq->sattr, s, 0))) {
            LOG(LOG_ERR,"stripe:%lu in layout %s - mapping error:%d", s, lo->info.name, rc);
            goto _err;
        }
    }

    // Need to make sure that the stripe bunch is contigious, otherwise
    // recovery's bulk read/write will not work
    for (int i = 0; i < rq->scnt - 1; i++) {
        if (rq->ss->stripes[x + i + 1] != rq->ss->stripes[x + i] + 1) {
            rq->scnt = i + 1;
            break;
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
                LOG(LOG_DBG2, "%s[%d]: stripe %lu laminated (%d of %d)",
                    lo->info.name, lp->part_num, s, x + 1, rq->ss->count);
                f_laminate_stripe(lp->layout, s);
            } else {
                LOG(LOG_DBG2, "%s[%d]: %d stripes recovered, s0=%lu, %d to go",
                    lo->info.name, lp->part_num, rq->scnt, s, rq->ss->count - x -1);
            }
        } else {
            LOG(LOG_ERR, "%s[%d]: stripe %lu in error, not laminated (%d of %d): %d (%d)",
                lo->info.name, lp->part_num, s, x + 1, rq->ss->count, rq->err, rq->nerr);
        }

        rq->scur += rq->scnt;
        if (rq->scur >= rq->ss->count) {
            // last stripe in set done
            rq->status = rq->nerr ? -EIO : 0;

            // Mark the claim vector to be flushed & enc op finished
            if (rq->op == EDR_OP_ENC) { 
                SetLPCVFlush(lp);
                atomic_dec(&enc_ops[lo->info.conf_id]);
            }

            if (rq->completion) {
                if (rq->completion(rq, rq->ctx)) {
                    LOG(LOG_ERR, "%s[%d]: %s done callback failed",
                        lo->info.name, lp->part_num, EDR_PR_R(rq));
                }
            } else {
                LOG(LOG_DBG, "%s[%d]: s0=%lu - %d stripes laminated, %d errors (no CB)",
                    lo->info.name, lp->part_num, s0, rq->ss->count - rq->nerr, rq->nerr);
            }

            rq->err = 0;
            rq->nerr = 0;
            rq->status = 0;
            rq->state = F_EDR_FREE;
            free_fam_stripe(rq->sattr);
            rq->sattr = 0;

            // check for backlog
            pthread_spin_lock(&backlog.qlock);
            F_EDR_BLRQ_t *bl_rq = list_first_entry_or_null(&backlog.qhead, F_EDR_BLRQ_t, list);
            if (bl_rq) {
                list_del_init(&bl_rq->list);
                backlog.size--;
                pthread_spin_unlock(&backlog.qlock);
                rq->op = EDR_OP_ENC;       // only encode request can go to backlog
                rq->ss = bl_rq->ss;
                rq->lo = bl_rq->lo;
                rq->completion = bl_rq->done_cb;
                rq->ctx = bl_rq->ctx;
                rq->fvec = 0;
                rq->scnt = rq->smax = 1;   // always one stripe at a time
                rq->scur = 0;

                atomic_inc(&enc_ops[rq->lo->info.conf_id]);
                free(bl_rq);

                // add former backlog request to work queue 
                pthread_spin_lock(&edr_wq.qlock);
                list_add_tail(&rq->list, &edr_wq.qhead);
                edr_wq.size++;
                pthread_spin_unlock(&edr_wq.qlock);
                pthread_cond_signal(&edr_wq.wake);
                LOG(LOG_DBG2, "%s got rq off backlog, ss[0]=%lu cnt=%d", 
                    f_get_pool()->mynode.hostname, rq->ss->stripes[0], rq->ss->count);

                return 0;
            }
            pthread_spin_unlock(&backlog.qlock);


            // return request to free queue
            pthread_spin_lock(&rq->myq->qlock);
            list_add_tail(&rq->list, &rq->myq->qhead);
            rq->myq->size++;
            pthread_spin_unlock(&rq->myq->qlock);

            // wake up any client(s) that could be waiting for free RQ
            pthread_cond_broadcast(&rq->myq->wake);
            //pthread_cond_signal(&free_s[l].wake);
            LOG(LOG_DBG2, "%s[%d]: retiring rq to '%s' queue",
                lo->info.name, lp->part_num, EDR_PR_Q(rq->myq));

        } else {
            // repeat the whole process for the next stripe(s) in set
            atomic_set(&rq->busy, 0);
            rq->scnt = min(rq->smax, rq->ss->count - rq->scur);
            rq->err = 0;
            rq->next_call = edr_read_done;
            rc = edr_read(rq);
        }
    } while (rc);

    return rc;
}

//
// Encode/Decode EC calc is done, next step: write out parity
//
static int edr_calc_done(F_EDR_t *rq, void *ctx) {
    int rc = 0;
    uint64_t delay;

    rq->next_call = edr_write_done;

    LOG(LOG_DBG2, "stripe batch %lu[%d] (%d of %d): %s calc done", 
        rq->ss->stripes[rq->scur], rq->scnt, rq->scur + 1, rq->ss->count, EDR_PR_R(rq));
    if ((delay = (uint64_t)f_get_pool()->info.enc_bdelay)) usleep(delay);

    if (!rq->err) {
        if ((rc = edr_io_submit(rq, 1))) {
            LOG(LOG_DBG2, "stripe batch %lu[%d] (%d of %d): %s wr submit err:%d", 
                rq->ss->stripes[rq->scur], rq->scnt, rq->scur + 1, rq->ss->count, 
                EDR_PR_R(rq), rc);
            goto _err;

        }
        // I/O submitted successfully, this is WP thread context so just return
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
    int rc = 0, n = 0;
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

    //ASSERT(atomic_read(&rq->busy) == 0);
    if ((n = atomic_read(&rq->busy))) {
        LOG(LOG_ERR, "stripe batch %lu[%d] (%d of %d): %s Busy(%d) <>0, err=%d, nerr=%d",
            rq->ss->stripes[rq->scur], rq->scnt, rq->scur + 1, rq->ss->count, EDR_PR_R(rq),
            n, rq->err, rq->nerr);
        rq->nerr++;
        rq->err = -EINVAL;
    }

    if (rq->err) {
        rq->next_call(rq, rq->ctx);
    } else {
        rq->state = F_EDR_CALC;
        if ((rc = f_wpool_add_work(lp->wpool, cmd, prio, rq))) {
            LOG(LOG_ERR, "stripe batch %lu[%d] (%d of %d): %s calc failed:%d",
                rq->ss->stripes[rq->scur], rq->scnt, rq->scur + 1, rq->ss->count, 
                EDR_PR_R(rq), rc);
            rq->nerr++;
            rq->err = rc;
            rq->next_call(rq, rq->ctx);
        }
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
            rq->nerr++;
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
        LOG(LOG_ERR, "I/O error (%d/%d) on %s rq, s[%d]=%lu, ss cnt=%d, lid=%d",
            rq->err, rq->prov_err, EDR_PR_R(rq), rq->scur, rq->ss->stripes[rq->scur], 
            rq->ss->count, rq->lo->info.conf_id);
    }
    if (atomic_dec_and_test(&rq->busy)) {
        // all ops completed (some may had failed), see what's next
        LOG(LOG_DBG3, "stripe %lu (%d of %d) advancing", rq->ss->stripes[rq->scur], rq->scur + 1, rq->ss->count);
        rq->next_call(rq, rq->ctx);
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
            rq = NULL;

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

    ON_NOMEM_RET(enc_ops = calloc(N, sizeof(atomic_t)), "encode ops cnt");
    ON_NOMEM_RET(rntfy = calloc(N, sizeof(F_RNTFY_t)), "ranks notify");

    ON_NOMEM_RET(edr_encode_tables = calloc(N, sizeof(u8 *)), "encode tables");
    ON_NOMEM_RET(edr_encode_matrices = calloc(N, sizeof(u8 *)), "R-S matricies");


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

        // Create free requests queues (small (for encode), medium and large (for recovery))
        int qs = pool->info.enc_freeq_sz;
        ON_ERROR_RC(init_edr_q(&free_s[i], lo, qs, EDR_SQ_SC), "free S");
        LOG(LOG_INFO, "EDR 'S' free queue depth is set to %d, batch delay %dus", qs, pool->info.enc_bdelay);
        
        qs = pool->info.rec_freeq_sz;
        ON_ERROR_RC(init_edr_q(&free_l[i], lo, qs, EDR_LQ_SC), "free L");
        LOG(LOG_INFO, "EDR 'L' free queue depth is set to %d", qs);
        
        qs = max(min(pool->info.enc_freeq_sz/2, pool->info.rec_freeq_sz*2), 2);
        ON_ERROR_RC(init_edr_q(&free_m[i], lo, qs, EDR_MQ_SC), "free M");
        LOG(LOG_INFO, "EDR 'M' free queue depth is set to %d", qs);

        free_s[i].idy = EDR_SQ;
        free_m[i].idy = EDR_MQ;
        free_l[i].idy = EDR_LQ;
        atomic_set(&enc_ops[i], 0);


        rntfy[i].size = 64;
        rntfy[i].cnt = 0;
        rntfy[i].ranks = calloc(rntfy[i].size, sizeof(int));

        if (!(edr_encode_tables[i] = prep_encode(k, p, &edr_encode_matrices[i]))) {
            LOG(LOG_ERR, "making encode matrix for lo %d", i);
            return -EINVAL;
        }
    }

    // Create backlog encode requests queue
    INIT_LIST_HEAD(&backlog.qhead);
    backlog.size = 0;
    ON_ERROR_RC(pthread_spin_init(&backlog.qlock, PTHREAD_PROCESS_PRIVATE), "spin");

    ON_ERROR_RC(pthread_create(&edr_wq.tid, &attr, edr_wq_thread, &edr_wq), "wq thread create");
    ON_ERROR_RC(pthread_create(&edr_cq.tid, &attr, edr_cq_thread, &edr_cq), "cq thread create");
    atomic_set(&edr_io_total, 0);

_out:

    return rc;
}

//
// Add a client rank to notify list
// "Client" here means compute-node side of the server, i.e. helper/client arm
//
void f_edr_add_ntfy(F_LAYOUT_t *lo, int src_rank) {
    int l = lo->info.conf_id;
    int i;

    ASSERT(lo->info.chunks - lo->info.data_chunks);
    pthread_mutex_lock(&ntfy_lock);

    // see if we already have him
    for (i = 0; i < rntfy[l].cnt; i++)
        if (rntfy[l].ranks[i] == src_rank)
            goto _out;

    // extend the list as needed
    if (i == rntfy[l].size) {
        rntfy[l].size += rntfy[l].size;
        rntfy[l].ranks = realloc(rntfy[l].ranks, sizeof(int)*rntfy[l].size);
        ASSERT(rntfy[l].ranks);
    }

    rntfy[l].ranks[i] = src_rank;
    rntfy[l].cnt++;

_out:
    pthread_mutex_unlock(&ntfy_lock);
    return;
}

static void free_q(F_EDR_OPQ_t *q) {
    F_EDR_t *rq = NULL, *next;

    list_for_each_entry_safe(rq, next, &q->qhead, list) {
        list_del(&rq->list);
        free(rq->iobuf);
        if (rq->sattr) free_fam_stripe(rq->sattr);
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

        free(rntfy[i].ranks);

        free(edr_encode_tables[i]);
        free(edr_encode_matrices[i]);
    }

    // drop anything that still seats in work q
    free_q(&edr_wq);
    free(edr_encode_tables);
    free(enc_ops);
    free(rntfy);

    return 0;
}

#define pv(h, v, n, f) {\
    char b[1024];\
    int l = sprintf(b, "%s: \n", h);\
    for (int i = 0; i < n; i++) l += sprintf(&b[l], "%02d:" f "\n", i, v[i]);\
    LOG(LOG_DBG, "%s", b);\
}

static inline int cmp_u8(const void *a, const void *b) {
    return *(u8 *)a - *(u8 *)b;
}

#define ROL(a, n) do {\
    if (n > 0) {\
        __auto_type _swp_ = a[0];\
        for (int i = 0; i < n - 1; i++) a[i] = a[i +1];\
        a[n - 1] = _swp_;\
    }\
} while(0);

int f_recover_stripes(F_WTYPE_t cmd, void *arg, int thread_id) {
    F_EDR_t *rq = (F_EDR_t *)arg;
    F_LO_PART_t *lp = rq->lo->lp;
    F_LAYOUT_t *lo = rq->lo;
    f_stripe_t s = rq->ss->stripes[rq->scur];
    F_RECOVERY_t *rctx = (F_RECOVERY_t *)rq->ctx;
    int k = lo->info.data_chunks, m = lo->info.chunks, p = m - k;

    ASSERT(rctx);
    ASSERT(cmd == F_WT_DECODE);
    if (!rq->err) {
        int sz = lo->info.chunk_sz*rq->scnt;
        int nerr = bitmap_weight(&rq->fvec, sizeof(u64)*BITS_PER_BYTE);
        int lid = lo->info.conf_id;
        u8 *dvec[m], *rvec[nerr], eix[nerr], hdev[m], fdev[nerr];

        u8 *dc_tbl = alloca(k*p*32);

        ASSERT(nerr);
        memset(eix, 0, nerr);

        for (int i = 0; i < k; i++) {
            dvec[i] = rq->iobuf + rq->dchnk[i]*sz;
            hdev[i] = rq->fd_h[i];
            LOG(LOG_DBG2, "H[%02d] @ C%02d %p @%d", i, rq->dchnk[i], dvec[i], hdev[i]);
        }

        for (int i = 0; i < nerr; i++) {
            rvec[i] = rq->iobuf + rq->pchnk[i]*sz;
            fdev[i] = rq->fd_f[i];
            eix[i] = rq->pchnk[i];
            LOG(LOG_DBG2, "F[%02d] @ C%02d %p @%d", i, rq->pchnk[i], rvec[i], fdev[i]);
        }

        for (int si = 0; si < rq->scnt; si++) {
            LOG(LOG_DBG2, "%s[%d]-w%d: decoding stripe:%lu, fvec=0x%lx, nerr=%d",
                lo->info.name, lp->part_num, thread_id, s + si, rq->fvec, nerr);
/*
pv("hdev", hdev, k ,"%2d");
pv("fdev", fdev, nerr, "%2d");
pv("eix", eix, nerr, "%2d");
*/
            int cmd = p <= 2 ? ISAL_CMD : ISAL_USE_AVX2; // drop forced raid flag is p > 2
            if (p > 1) {
                if (prep_decode(k, m, nerr, eix, edr_encode_matrices[lid], dc_tbl, NULL)) {
                    LOG(LOG_ERR, "%s[%d]-w%d: can't produce decode tables", 
                        lo->info.name, lp->part_num, thread_id);
                    rq->err = 1;
                    rq->next_call(rq, rq->ctx);
                    return -EINVAL;
                }
            }

            decode_data(cmd, lo->info.chunk_sz, k, nerr, dc_tbl, dvec, rvec);
            /*
            u8 *swap = dvec[0] + lo->info.chunk_sz;
            for (int i = 0; i < k - 1; i++) dvec[i] = dvec[i + 1] + lo->info.chunk_sz;
            dvec[k - 1] = rvec[0] + lo->info.chunk_sz;
            for (int i = 0; i < nerr - 1; i++) rvec[i] = rvec[i + 1] + lo->info.chunk_sz;
            rvec[nerr - 1] = swap;
            */
            if (eix[0]) {
                ROL(dvec, k);
                ROL(hdev, k);
                /*
                u8 *swap = dvec[0] + lo->info.chunk_sz;
                for (int i = 0; i < k - 1; i++) dvec[i] = dvec[i + 1] + lo->info.chunk_sz;
                dvec[k - 1] = swap;

                u8 tmp = hdev[0];
                for (int i = 0; i < k - 1; i++) hdev[i] = hdev[i + 1];
                hdev[k - 1] = tmp;
                */
            } else {
                ROL(rvec, nerr);
                ROL(fdev, nerr);
                /*
                u8 *swap = rvec[0] + lo->info.chunk_sz;
                for (int i = 0; i < nerr - 1; i++) rvec[i] = rvec[i + 1] + lo->info.chunk_sz;
                rvec[nerr - 1] = swap;

                u8 tmp = fdev[0];
                for (int i = 0; i < nerr - 1; i++) fdev[i] = fdev[i + 1];
                fdev[nerr - 1] = tmp;
                */
            }
            for (int i = 0; i < nerr; i++) {
                if (!eix[i]) 
                    eix[i] = m - 1;
                else
                    eix[i]--;
            }
            qsort(eix, nerr, 1, cmp_u8);

            for (int i = 0; i < k; i++) dvec[i] += lo->info.chunk_sz;
            for (int i = 0; i < nerr; i++) rvec[i] += lo->info.chunk_sz;

        }
    } else {
        LOG(LOG_INFO, "%s[%d]-w%d: not decoding %d stripes s0=%lu (%d of %d), rq nerr=%d",
            lo->info.name, lp->part_num, thread_id, rq->scnt, s, rq->scur + 1, 
            rq->ss->count, rq->nerr);
    }

    // proceed to next step (edr_calc_done, presumably)
    rq->next_call(rq, rq->ctx);

    return 0;

}

int _f_recover_stripes(F_WTYPE_t cmd, void *arg, int thread_id) {
    F_EDR_t *rq = (F_EDR_t *)arg;
    F_LO_PART_t *lp = rq->lo->lp;
    F_LAYOUT_t *lo = rq->lo;
    f_stripe_t s = rq->ss->stripes[rq->scur];
    F_RECOVERY_t *rctx = (F_RECOVERY_t *)rq->ctx;
    int k = lo->info.data_chunks, m = lo->info.chunks, p = m - k;

    ASSERT(rctx);
    ASSERT(cmd == F_WT_DECODE);
    if (rq->err) {
        LOG(LOG_INFO, "%s[%d]-w%d: not decoding %d stripes s0=%lu (%d of %d), rq nerr=%d",
            lo->info.name, lp->part_num, thread_id, rq->scnt, s, rq->scur + 1, 
            rq->ss->count, rq->nerr);

        rq->next_call(rq, rq->ctx);
        return 0;
    }

    int sz = lo->info.chunk_sz*rq->scnt;
    int nerr = bitmap_weight(&rq->fvec, sizeof(u64)*BITS_PER_BYTE);
    int lid = lo->info.conf_id;
    u8 *dvec[m], *rvec[nerr];
    unsigned int media_id, failed_media[m];
    u8 *dc_tbl = alloca(k*p*32);
    int fcnt = 0;
    int dchnk[m], rchnk[p], rdev[m], ddev[m], hdev[m], fdev[nerr];
    u8 eix[m];

    ASSERT(nerr);

    for (int si = 0; si < rq->scnt; si++) {
        LOG(LOG_DBG2, "%s[%d]-w%d: decoding stripe:%lu, fvec=0x%lx, nerr=%d",
            lo->info.name, lp->part_num, thread_id, s + si, rq->fvec, nerr);
    
        f_map_fam_stripe(rq->lo, &rq->sattr, s + si, 0);
        N_STRIPE_t *stripe = rq->sattr;

        LOG(LOG_DBG2, "stripe=%lu", s + si);
        for (int i = 0; i < m; i++)
            if (test_bit(i, &rq->fvec))
                failed_media[fcnt++] = stripe->chunks[i].pdev->pool_index;

        for (int i = 0, px = 0, dx = 0; i < m; i++) {
            N_CHUNK_t *chunk = get_fam_chunk(stripe, i);
            F_POOL_DEV_t *pdev = chunk->pdev;
            media_id = pdev->pool_index;
            int failed = 0;
            for (int j = 0; j < fcnt && !failed; j++) 
                if (media_id == failed_media[j])
                    failed = 1;
            if (failed) {
                rdev[px] = media_id;
                fdev[px] = rq->fd_f[i];
                rchnk[px++] = i;
            } else {
                ddev[dx] = media_id;
                hdev[dx] = rq->fd_h[i];
                dchnk[dx++] = i;
            }
        }
        for (int i = 0; i < k; i++) {
            dvec[i] = rq->iobuf + dchnk[i]*sz + lo->info.chunk_sz*si;
            LOG(LOG_DBG2, "H[%02d] @ C%02d %p -> %02d", i, rq->dchnk[i], dvec[i], ddev[i]);
        }

        for (int i = 0; i < nerr; i++) {
            rvec[i] = rq->iobuf + rchnk[i]*sz + lo->info.chunk_sz*si;
            LOG(LOG_DBG2, "F[%02d] @ C%02d %p -> %02d", i, rq->pchnk[i], rvec[i], rdev[i]);
            eix[i] = rchnk[i];
        }
pv("hdev", hdev, k ,"%d");
pv("fdev", fdev, nerr, "%d");
pv("eix", eix, nerr, "%d");
        int cmd = p <= 2 ? ISAL_CMD : ISAL_USE_AVX2; // drop forced raid flag is p > 2
        if (p > 1) {
            if (prep_decode(k, m, nerr, eix, edr_encode_matrices[lid], dc_tbl, NULL)) {
                LOG(LOG_ERR, "%s[%d]-w%d: can't produce decode tables", lo->info.name, lp->part_num, thread_id);
                return -EINVAL;
            }
        }
        decode_data(cmd, lo->info.chunk_sz, k, nerr, dc_tbl, dvec, rvec);
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
        int sz = lo->info.chunk_sz*rq->scnt;
        int nd = lo->info.data_chunks;
        int lx = lo->info.conf_id;
        int np = lo->info.chunks - nd;
        u8 *dvec[nd], *pvec[np];

        LOG(LOG_DBG2, "%s[%d]-w%d: encoding stripe %lu (%d of %d)",
            lo->info.name, lp->part_num, thread_id, s, rq->scur + 1, rq->ss->count);
        for (int i = 0; i < nd; i++) {
            dvec[i] = rq->iobuf + rq->dchnk[i]*sz;
            LOG(LOG_DBG2, "D[%d] @ C%d", i, rq->dchnk[i]);
        }
        for (int i = 0; i < np; i++) {
            pvec[i] = rq->iobuf + rq->pchnk[i]*sz;
            LOG(LOG_DBG2, "P[%d] @ C%d", i, rq->pchnk[i]);
        }

        encode_data(ISAL_CMD, sz, nd, np, edr_encode_tables[lx], dvec, pvec);

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
	F_LAYOUT_t *lo = rq->lo;
	F_LO_PART_t *lp = lo->lp;
        int l = lo->info.conf_id;

        LOG(LOG_DBG, "%s[%d]: encode rq (s0=%lu, cnt=%d) completed, status %d, err=%d)", 
            lo->info.name, lp->part_num, rq->ss->stripes[0], rq->ss->count, rq->status, rq->nerr);

	ss_free(rq->ss);

        if (!atomic_read(&enc_ops[l])) {
            f_ah_ntfy_t msg = {.op = F_NTFY_EC_DONE, .lid = l};
            F_POOL_t *pool = lo->pool;
            int rc;
            F_RNTFY_t ntfy; 

            // no encoding ops in progress on this layout, at least for now
            // notify remote helpers
            pthread_mutex_lock(&ntfy_lock);
            ntfy.cnt = rntfy[l].cnt;
            ntfy.ranks = alloca(sizeof(int)*ntfy.cnt);
            memcpy(ntfy.ranks, rntfy[l].ranks, sizeof(int)*ntfy.cnt);
            rntfy[l].cnt = 0;
            pthread_mutex_unlock(&ntfy_lock);

            for (int i = 0; i < ntfy.cnt; i++) {
                LOG(LOG_DBG2, "%s[%d]: ENC done notify rank %d", 
                    lo->info.name, lp->part_num, ntfy.ranks[i]);

                rc = MPI_Send(&msg, sizeof(msg), MPI_BYTE, ntfy.ranks[i], 
                              F_TAG_NTFY, pool->helper_comm);
                if (rc != MPI_SUCCESS) {
                    LOG(LOG_ERR, "%s[%d]: MPI_Send error %d, ntfy %d", 
                        lo->info.name, lp->part_num, rc, ntfy.ranks[i]);
                    continue;
                }
            }
        }

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

		if (ss->stripes[i] == F_STRIPE_INVALID) continue;

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
//  wait    - wait for free rq mode, see .h
//
//  returns NULL if unable to get request, errno is set to:
//  EBUSY   - no free requests
//  EAGAIN  - no free, but put request into backlog
//  other   - something else went wrong
//
static F_EDR_t *get_free_rq(F_EDR_OPQ_t **this_q, int qix, int cnt, F_EDR_WM_t wait) {
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
    LOG(LOG_DBG2, "getting EDR rq(size=%d) from '%s' q[%d]\n", cnt, EDR_PR_Q(q), qix);

    int go = 1;
    do {
        // get a free request
        pthread_spin_lock(&q->qlock);
        if (!list_empty(&q->qhead)) {
            break;
        } else {
            pthread_spin_unlock(&q->qlock);
            if (wait == F_EDR_4EVER || wait == F_EDR_ONCE) {
                // no free requestes, wait for one becoming available
                pthread_mutex_lock(&q->wlock);
                set_tmo(&ts, 10*TMO_1S);
                rc = pthread_cond_timedwait(&q->wake, &q->wlock, &ts);
                pthread_mutex_unlock(&q->wlock);
                if (rc) {
                    if (rc == ETIMEDOUT) {
                        LOG(LOG_ERR, "free q '%s' wait TMO, lo %d", EDR_PR_Q(q), qix);
                        if (wait == F_EDR_ONCE) {
                            errno = EBUSY;
                            return NULL;
                        }
                    } else {
                        LOG(LOG_ERR, "free q '%s' wait err, lo %d:%d", EDR_PR_Q(q), qix, rc);
                        errno = rc;
                        return NULL;
                    }
                }
            } else if (wait == F_EDR_BACKLOG) {
                // no free requests, put this stripe set into backlog queue
                errno = EAGAIN;
                return NULL;
            } else {
                // no waiting
                errno = EBUSY;
                return NULL;
            }
        }
    } while (go);

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
 *      fvec            failed extents bitmap, bit #N set means extent #N in this slab failed
 *                          if fvec == 0: encode parities according to layout
 *                          if fvec == <all 1s>: verify stripes
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

    if (!(lo->info.chunks - lo->info.data_chunks)) {
        LOG(LOG_ERR, "EDR request for %s[%d] layout rejected:no P-chunks",
            lo->info.name, lo->lp->part_num);
        return -EINVAL;
    }
    LOG(LOG_DBG3, "EDR Rq: %d stripes, ss[0]=%lu\n", ss->count, ss->stripes[0]);

    if (!fvec) {
        // ENCODE

        if (!(rq = get_free_rq(&q, l, 1, F_EDR_BACKLOG))) {
            if (errno == EAGAIN) {
                // couldn't find any free requests, add to backog queue
                F_EDR_BLRQ_t *bl_rq = malloc(sizeof(F_EDR_BLRQ_t));
                ASSERT(bl_rq);
                bl_rq->lo = lo;
                bl_rq->ss = ss;
                bl_rq->done_cb = done_cb;
                bl_rq->ctx = ctx;
                pthread_spin_lock(&backlog.qlock);
                list_add_tail(&bl_rq->list, &backlog.qhead);
                pthread_spin_unlock(&backlog.qlock);
                LOG(LOG_DBG2, "%s putting rq in backlog, ss[0]=%lu cnt=%d", 
                    f_get_pool()->mynode.hostname, bl_rq->ss->stripes[0], bl_rq->ss->count);
                return 0;
            } else return -errno;
        }

        rq->fvec = 0;
        rq->scnt = rq->smax = 1;   // always one stripe at a time
        rq->op = EDR_OP_ENC;
        atomic_inc(&enc_ops[l]);

    } else if (*fvec == ~0UL) {
        // VERIFY
        return -EINVAL; //TODO
    } else {
        if (*fvec == 0UL) {
            LOG(LOG_ERR, "layout [%d]: recover rq with empty fail vector", l);
            return -EINVAL;
        }
        // RECOVER

        // try to get as large request as we can, recover can do multiple stripes at a time
        q = &free_l[l]; //FIXME
        if (!(rq = get_free_rq(&q, l, ss->count, F_EDR_4EVER)))
            return -errno;
        rq->fvec = *fvec;
        rq->scnt = 1;//min(rq->sall, ss->count); //FIXME
        rq->smax = 1;//rq->sall; //FIXME
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

    return 0;
}
