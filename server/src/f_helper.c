/*
 * (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor
 *   Boston, MA 02110-1301, USA.
 *
 * Written by: Oleg Neverovitch, Yann Livis
 */

#include <mpi.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <signal.h>

#include "f_global.h"
#include "unifycr_metadata.h"
#include "log.h"
#include "unifycr_debug.h"
#include "unifycr_const.h"
#include "unifycr_global.h"
#include "unifycr_cmd_handler.h"
#include "unifycr_service_manager.h"
#include "lf_client.h"
#include "f_env.h"
#include "f_error.h"
#include "f_maps.h"
#include "f_bitmap.h"
#include "f_rbq.h"
#include "f_pool.h"
#include "f_layout.h"
#include "f_map.h"
#include "f_allocator.h"
#include "mpi_utils.h"
#include "f_layout_ctl.h"
#include "f_encode_recovery.h"
#include "f_helper.h"

extern volatile int exit_flag;
extern pthread_spinlock_t cntfy_lock;
extern f_close_ntfy_t cntfy[MAX_NUM_CLIENTS];

static volatile int quit = 0;

static pthread_t al_thrd[F_CMDQ_MAX];
static pthread_t cm_thrd;
static pthread_t hs_athrd[F_CMDQ_MAX];
static pthread_t hs_cthrd;

static f_rbq_t   *alq[F_CMDQ_MAX];
static f_rbq_t   *cmq;

static void *stoker(void *arg);
static void *drainer(void *arg);
static void *alloc_srv(void *arg);
static void *commit_srv(void *arg);

int f_ah_init(F_POOL_t *pool) {
    F_LAYOUT_t *lo;
    int i, rc = 0;

    // Only for "pure" IONs
    if (NodeIsIOnode(&pool->mynode) && !NodeForceHelper(&pool->mynode)) {

        // start alloc srv threads
	i = 0;
	list_for_each_entry(lo, &pool->layouts, list) {
            if ((rc = pthread_create(&hs_athrd[i++], NULL, alloc_srv, lo))) {
                LOG(LOG_ERR, "helper alloc srv thread create failed on LO %s", lo->info.name);
                return rc;
            }
        }

        // start commit srv thread
        if ((rc = pthread_create(&hs_cthrd, NULL, commit_srv, pool))) {
            LOG(LOG_ERR, "helper commit srv thread create failed");
            return rc;
        }

        return 0;
    }

    // Only for "pure" CNs AND IONs, i.e. not in single-node enviro
    if (!NodeForceHelper(&pool->mynode)) {
	rc = f_set_ionode_ranks(pool);
	if (rc) {
            LOG(LOG_ERR, "error %s in f_set_ionode_ranks", strerror(rc));
            return rc;
	}
    }

    /* Init global slabmap and claim vector (f_map_init, f_map_register) in all layouts */
    rc = f_prepare_layouts_maps(pool, true);
    if (rc) {
	LOG(LOG_ERR, "error %d in prepare_layouts_maps", rc);
	return rc;
    }

    i = 0;
    list_for_each_entry(lo, &pool->layouts, list) {
        if ((rc = pthread_create(&al_thrd[i++], NULL, stoker, lo))) {
            LOG(LOG_ERR, "helper alloc thread create failed on LO %s", lo->info.name);
            return rc;
        }
    }

    if ((rc = pthread_create(&cm_thrd, NULL, drainer, pool))) {
        LOG(LOG_ERR, "helper str commit thread create failed");
        return rc;
    }

    /* wait until layout maps loaded */
    pthread_mutex_lock(&pool->event_lock);
    while (pool->event)
	pthread_cond_wait(&pool->event_cond, &pool->event_lock);
    pthread_mutex_unlock(&pool->event_lock);

    return 0;
}

/*
 * Helper commit server thread, runs only on real IONs
 * Provides MPI IPC with helper threads on CNs
 * This is the remote counterpart of CN's helper "drainer" thread
 * One for all layouts in config
 *
 */
static void *commit_srv(void *arg) {
    F_POOL_t *pool = (F_POOL_t *)arg;
    F_LAYOUT_t *lo;
    int msg_max = F_AH_MSG_SZ(F_MAX_IPC_ME);
    int rc = 0, msg_sz = 0;
    MPI_Status sts;
    f_ah_ipc_t *msg = malloc(msg_max);
    struct f_stripe_set ss = {.count = 0, .stripes = NULL};
    int N = pool->info.layouts_count;

    if (!msg) {
        LOG(LOG_ERR, "out of memory");
        return NULL;
    }

    while (!quit) {
        // wait for any commit or release message from CNs' helpers
        // commit thread uses TAG_BASE + layout_count
        rc = MPI_Recv(msg, msg_max, MPI_BYTE, MPI_ANY_SOURCE, 
                      F_TAG_BASE + N, pool->helper_comm, &sts);
        if (rc != MPI_SUCCESS || sts.MPI_ERROR != MPI_SUCCESS) {
            LOG(LOG_ERR, "MPI_Recv returnd error %d/sts=%d", rc, sts.MPI_ERROR);
            continue;
        }

        MPI_Get_count(&sts, MPI_BYTE, &msg_sz);
        LOG(LOG_DBG, "srv CT from %d: msg[%d].op=%d got %d stripes to commit to LO %d, s0=%lu", 
            sts.MPI_SOURCE, msg_sz, msg->cmd, msg->cnt, msg->lid, msg->str[0]);
        if (msg->cmd == F_AH_QUIT) {
            LOG(LOG_INFO, "srv CT: received QUIT command");
            break;
        }
        if (msg->cmd != F_AH_COMS && msg->cmd != F_AH_PUTS) {
            LOG(LOG_ERR, "srv CT: wrong command received: %d, LO %d", msg->cmd, msg->lid);
            continue;
        }
        ASSERT(F_TAG_BASE + N  == sts.MPI_TAG);
        ASSERT(msg_sz == F_AH_MSG_SZ(msg->cnt));

        ss.count = msg->cnt;
        ss.stripes = &msg->str[0];
        lo = f_get_layout(msg->lid);
        if (lo == NULL) {
            LOG(LOG_ERR, "get layout [%d] info\n", msg->lid);
            continue;
        }

        // if this is protected layout, add to notify list
        if (lo->info.chunks - lo->info.data_chunks)
            f_edr_add_ntfy(lo, sts.MPI_SOURCE);

        // commit or release stripes and continue, no respose required
        if (msg->cmd == F_AH_COMS) {
            rc = f_commit_stripe(lo, &ss);
        } else {
            rc = f_put_stripe(lo, &ss);
        }
        if (rc < 0)
            LOG(LOG_ERR, "%s[%d]: error %d in %s", lo->info.name, lo->lp->part_num, 
                rc, msg->cmd == F_AH_COMS ? "commit_stripe" : "put_stripe");

    }

    free(msg);
    return NULL;
}

/*
 * Helper allocation server thread, runs only on real IONs
 * Provides MPI IPC with helper threads on CNs
 * This is the remote counterpart of CN's helper "stoker" thread
 * One per each layout in config
 *
 */
static void *alloc_srv(void *arg) {
    struct f_stripe_set ss = {.count = 0, .stripes = NULL}; 
    F_LAYOUT_t *lo = (F_LAYOUT_t *)arg;
    F_POOL_t *pool = lo->pool;
    MPI_Status sts;
    MPI_Request mrq;
    f_ah_ipc_t msg, *rply = NULL;
    int rc = 0, msg_sz = 0, ss_cnt = 0, in_flight = 0;
    int lid = lo->info.conf_id;

    while (!quit) {
        // wait for any commit message from CNs' helpers
        // allocators use TAG_BASE + layout ID tag
        rc = MPI_Recv(&msg, sizeof(msg), MPI_BYTE, MPI_ANY_SOURCE, F_TAG_BASE + lid, 
                      pool->helper_comm, &sts);
        if (rc != MPI_SUCCESS || sts.MPI_ERROR != MPI_SUCCESS) {
            LOG(LOG_ERR, "MPI_Recv returnd error %d/sts=%d", rc, sts.MPI_ERROR);
            continue;
        }

        MPI_Get_count(&sts, MPI_BYTE, &msg_sz);
        LOG(LOG_DBG, "srv AT from %d: msg[%d].op=%d got req for %d stripes to alloc for LO %d", 
            sts.MPI_SOURCE, msg_sz, msg.cmd, msg.cnt, msg.lid);
        if (msg.cmd == F_AH_QUIT) {
            LOG(LOG_INFO, "srv AT: recevided QUIT command");
            break;
        }
        if (msg.cmd != F_AH_GETS) {
            LOG(LOG_ERR, "srv AT: wrong command received: %d, LO %d", msg.cmd, msg.lid);
            continue;
        }
        ASSERT(msg.lid + F_TAG_BASE == sts.MPI_TAG);
        ASSERT(msg_sz == sizeof(msg));
        if (lid != msg.lid) {
            LOG(LOG_ERR, "srv AT: wrong layout id: expected %d, got %d", lid, msg.lid);
            continue;
        }

        if (in_flight) {
            MPI_Wait(&mrq, MPI_STATUS_IGNORE);
            in_flight = 0;
        }

        F_AH_MSG_ALLOC(rply, msg.cnt, ss_cnt, ss);
        if (!rply) {
            LOG(LOG_FATAL, "out of memory");
            quit = 1;
            return NULL;
        }
        rply->cmd = F_AH_GETS;
        rply->lid = lid;

        // acquire stripes from allocator
        int rq_cnt = ss.count;
        if ((rc = f_get_stripe(lo, F_STRIPE_INVALID, &ss)) < 0) {
            LOG(LOG_ERR, "%s: error %d in f_get_stripe", lo->info.name, rc);
            rply->flag = rc;
        } else {
            LOG(LOG_DBG, "%s: allocated %d stripes", lo->info.name, rc);
            rply->flag = 0;
            ASSERT(rc == ss.count);
        }
        rply->cnt = ss.count;

        if (ss.count < rq_cnt)
            LOG(LOG_WARN, "srv AT: requested %d stripes, but only got %d\n", rq_cnt, ss.count);
        rc = MPI_Isend(rply, F_AH_MSG_SZ(ss.count), MPI_BYTE, sts.MPI_SOURCE, 
                       sts.MPI_TAG, pool->helper_comm, &mrq);
        if (rc != MPI_SUCCESS) {
            LOG(LOG_ERR, "MPI_Isend returnd error %d", rc);
            continue;
        }
        in_flight = 1;
/*
        rc = MPI_Send(rply, F_AH_MSG_SZ(ss.count), MPI_BYTE, sts.MPI_SOURCE, 
                       sts.MPI_TAG, pool->helper_comm);
        if (rc != MPI_SUCCESS) {
            LOG(LOG_ERR, "MPI_Send returnd error %d", rc);
            continue;
        }
*/

    }
    if (rply)
        free(rply);

    return NULL;
}

/*
 * Shutdown helper threads
 * On 'pure' ION, sends quit message via MPI to itself to wake any threads
 * sleeping on MPI_Recv.
 * On CN, just set the flag and wake those on water mark conditions 
 *
 */
int f_ah_shutdown(F_POOL_t *pool) {
    int rc = 0;
    int n = 0;

    // make'em all know we are finished
    quit = 1;

    if (NodeIsIOnode(&pool->mynode) && !NodeForceHelper(&pool->mynode)) {
        // running on "real" ION
        MPI_Request rq[pool->info.layouts_count];
        f_ah_ipc_t qm = {.cmd = F_AH_QUIT};
        int myself;

        MPI_Comm_rank(pool->helper_comm, &myself);
        for (int i = 0; i < pool->info.layouts_count; i++) {
            MPI_Isend(&qm, sizeof(qm), MPI_BYTE, myself, F_TAG_BASE + i, pool->helper_comm, &rq[i]);
            pthread_join(hs_athrd[i], NULL);
        }

        MPI_Isend(&qm, sizeof(qm), MPI_BYTE, myself, F_TAG_BASE + pool->info.layouts_count, pool->helper_comm, &rq[0]);
        pthread_join(hs_cthrd, NULL);

        return 0;
    }

    for (int i = 0; i < pool->info.layouts_count; i++) 
        f_rbq_wakewm(alq[i]);

    f_rbq_wakewm(cmq);

    for (int i = 0; i < pool->info.layouts_count; i++) {
        F_LAYOUT_t *lo = f_get_layout(i);
        if (lo == NULL) {
            LOG(LOG_ERR, "get layout [%d] info\n", i);
            continue;
        }
        pthread_join(al_thrd[i], NULL);

        n = 0;
        while (f_rbq_destroy(alq[i]) == -EAGAIN) {
            LOG(LOG_WARN, "refcnt not 0 on layout %d", i);
            sleep(5);
            if (++n > 6) {
                LOG(LOG_ERR, "helper thread %d is taking too long to exit", i);
                rc = ETIMEDOUT;
                break;
            }
        }
    }

    pthread_join(cm_thrd, NULL);

    n = 0;
    while (f_rbq_destroy(cmq) == -EAGAIN) {
        LOG(LOG_WARN, "refcnt not 0 commit queue");
        sleep(5);
        if (++n > 6) {
            LOG(LOG_ERR, "helper commit thread is taking too long to exit");
            rc = ETIMEDOUT;
            break;
        }
    }

    return rc;
}

/* Map load callback function data */
struct cb_data {
    F_LAYOUT_t 	*lo;
    int		loaded;
    int		err;
};

/*
 * Slab map load callback function. Called on each slab map PU load
 */
static void slabmap_load_cb(uint64_t e, void *arg, const F_PU_VAL_t *pu)
{
    struct cb_data *data = (struct cb_data *) arg;
    F_LAYOUT_t *lo = data->lo;
    F_POOL_t *pool = lo->pool;
    F_SLABMAP_ENTRY_t *sme;
    f_slab_t slab = e;
    unsigned int pu_entries = 1U << lo->slabmap->geometry.pu_factor;
    unsigned int e_sz = lo->slabmap->geometry.entry_sz;
    unsigned int i;

    for(i = 0; i < pu_entries; i++, slab++) {
        f_stripe_t s0 = slab_to_stripe0(lo, slab);;
        unsigned int n;

        sme = (F_SLABMAP_ENTRY_t *)&pu->se;
        if (!sme) {
            LOG(LOG_ERR, "%s: error on SM entry %u", lo->info.name, slab);
            data->err++;
        }

        if (!sme->slab_rec.mapped) continue;

        /* Check slab map entry CRC */
        if (f_crc4_sm_chk(&sme->slab_rec)) {
            LOG(LOG_ERR, "%s: slab %u CRC error", lo->info.name, slab);
            data->err++;
        }

        if (sme->slab_rec.stripe_0 != s0) {
            LOG(LOG_ERR, "%s: slab %u s0 mismatch", lo->info.name, slab);
            data->err++;
        }

        /* Process this slab map entry */
        for (n = 0;  n < lo->info.chunks; n++) {
            unsigned int dev_id = sme->extent_rec[n].media_id;
            F_POOL_DEV_t *pdev = f_find_pdev_by_media_id(pool, dev_id);
            F_POOLDEV_INDEX_t *pdi = f_find_pdi_by_media_id(lo, dev_id);
            
            if (!pdev) {
                LOG(LOG_ERR, "%s: slab %u ext %u invalid dev idx %u", 
                        lo->info.name, slab, n, dev_id);
                data->err++;
            }
            if (!pdi) {
                LOG(LOG_ERR, "%s: slab %u ext %u dev idx %u not in layout", 
                        lo->info.name, slab, n, dev_id);
                data->err++;
            }

            if (f_crc4_fast_chk(&sme->extent_rec[n], sizeof(F_EXTENT_ENTRY_t))) {
                LOG(LOG_ERR, "%s: slab %u ext %u CRC err", lo->info.name, slab, n);
                data->err++;
            }

            if (DevMissing(pdev->sha)) {
                LOG(LOG_INFO, "%s: missing dev in slab %u ext %u", 
                        lo->info.name, slab, n); 
            }

            /* All chunk extents have to be mapped */
            if (!sme->extent_rec[n].mapped) {
                LOG(LOG_ERR, "%s: slab %u ext %u not mapped", lo->info.name, slab, n);
                data->err++;
                continue;
            }
        }

        data->loaded++;

        LOG(LOG_DBG, "%s: slab %u loaded: %d errors", lo->info.name, slab, data->err);
        pu = (F_PU_VAL_t *) ((char*)pu + e_sz);
    }

}

/*
 * Load and verify global slab map (all partitions)
 *
 * Slab Map
 *
 * [F_SLAB_ENTRY_t 0][F_EXTENT_ENTRY_t 0][F_EXTENT_ENTRY_t 1]...[F_EXTENT_ENTRY_t N] [F_SLAB_ENTRY_t 1]...
 */
static int read_global_slabmap(F_LAYOUT_t *lo)
{
    struct cb_data cbdata;
    int rc;

    LOG(LOG_DBG, "%s: loading global slabmap", lo->info.name);

     rc = f_map_shm_attach(lo->slabmap, F_MAPMEM_SHARED_WR);
    if (rc) {
        LOG(LOG_ERR, "%s: error %d attaching to global slabmap", lo->info.name, rc);
        return rc;
    }

    /* FIXME: Add tag to MDHIM remote msg and move two lines... */
    F_POOL_t *pool = lo->pool;
    pthread_mutex_lock(&pool->event_lock);

    cbdata.lo = lo;
    cbdata.err = 0;
    cbdata.loaded = 0;
    rc = f_map_load_cb(lo->slabmap, slabmap_load_cb, (void *)&cbdata);
    if (rc || cbdata.err) {
        LOG(LOG_ERR, "%s: error %d loading global slabmap, %d load errors",
                lo->info.name, rc, cbdata.err);
        f_print_sm(dbg_stream, lo->slabmap, lo->info.chunks, lo->info.slab_stripes);
        return rc ? rc : cbdata.err;
    }

    /* signal pool event: layout maps are loaded */
    /* FIXME: ...here. */
//    F_POOL_t *pool = lo->pool;
//    pthread_mutex_lock(&pool->event_lock);
    if (pool->event)
	rc = (int) pool->event--;
    pthread_mutex_unlock(&pool->event_lock);
    if (rc)
	pthread_cond_signal(&pool->event_cond);

    LOG(LOG_DBG, "%s: %u slabs loaded: %d errors", lo->info.name, cbdata.loaded, cbdata.err);

    if (log_print_level > 0)
        f_print_sm(dbg_stream, lo->slabmap, lo->info.chunks, lo->info.slab_stripes);

    return 0;
}

/*
 * Shovel preallocated stripes, obtained from (remote) allocator into
 * ready-queue on compute node
 *
 */
static void *stoker(void *arg) {
    int dst = 0, rc = 0;
    useconds_t backoff = 0;

    F_LAYOUT_t *lo = (F_LAYOUT_t *)arg;
    F_POOL_t   *pool = lo->pool;

    char qname[MAX_RBQ_NAME];
    f_rbq_t    *salq;
    int depth = max(64, lo->info.sq_depth);
    int lwm = max(8, depth*lo->info.sq_lwm/100);

    struct f_stripe_set ss = {.count = 0, .stripes = NULL};
    F_MAP_KEYSET_u keyset = {.slabs = NULL};

    // create rbq
    sprintf(qname, "%s-%s", F_SALQ_NAME, lo->info.name);
    if ((rc = f_rbq_create(qname, sizeof(f_stripe_t), depth, &salq, 1))) {
        LOG(LOG_ERR, "%s: rbq %s create: %s", lo->info.name, qname, strerror(-rc));
        exit(rc);
    }

    alq[lo->info.conf_id] = salq;

    // set low water mark
    f_rbq_setlwm(salq, lwm);

    rcu_register_thread();

    MPI_Barrier(pool->helper_comm);

    if ((rc = read_global_slabmap(lo))) {
	LOG(LOG_ERR, "%s: slabmap load failed: %s", lo->info.name, strerror(-rc));
        goto _abort;
    }

    // rc = open_global_claimvec(lo);

    if (NodeForceHelper(&pool->mynode)) {
        F_LO_PART_t *lp = lo->lp;

        if (!lp->ready) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            // set timeout to 1 minute
            ts.tv_sec += (ts.tv_nsec + 60000000000L)/1000000000L;
            ts.tv_nsec = (ts.tv_nsec + 60000000000L)%1000000000L;

            pthread_mutex_lock(&lp->lock_ready);
            if ((rc = pthread_cond_timedwait(&lp->cond_ready, &lp->lock_ready, &ts))) {
                if (rc == -ETIMEDOUT) {
                    LOG(LOG_ERR, "%s: TMO waiting for alloc thread to be ready", lo->info.name);
                } else {
                    LOG(LOG_ERR, "%s: error waitng for allocator", lo->info.name);
                }
            } else {
                LOG(LOG_DBG, "%s: stocker thread is ready", lo->info.name);
            }
        }
    } else {
        dst = pool->mynode.my_ion;
    }

    LOG(LOG_DBG, "%s: helper alloc thread %s is up: qd=%d lwm=%d", lo->info.name, qname, depth, lwm);

    f_ah_ipc_t *arq = NULL;
    int cur_ss_sz = 0;
    while (!quit) {

        // wait until queue is sufficiently empty
        if (f_rbq_count(salq) < f_rbq_getlwm(salq)) {
            if ((rc = f_rbq_waitlwm(salq, F_SALQ_LWTMO)) == -ETIMEDOUT) {
                if (f_rbq_isfull(salq))
                    LOG(LOG_DBG, "%s: rbq %s: LW TMO\n", lo->info.name, qname);
            } else if (rc == -ECANCELED) {
                LOG(LOG_INFO, "%s: rbq %s wak-up signal", lo->info.name, qname);
            } else if (rc) {
                LOG(LOG_ERR, "%s: rbq %s wait lwm: %s", lo->info.name, qname, strerror(-rc));
            }

            if (quit) break;
        }

        // stuff stripes into the queue untill it's full
        int to_do = f_rbq_size(salq) - f_rbq_count(salq);
        while (to_do > 0) {
            int batch = min(to_do, F_MAX_IPC_ME);
            if (!batch) break;

            if (F_AH_MSG_ALLOC(arq, batch, cur_ss_sz, ss)) {
                if (keyset.slabs)
                    free(keyset.slabs);
                keyset.slabs = calloc(ss.count, sizeof(f_slab_t));
                if (!arq || !keyset.slabs) {
                    LOG(LOG_FATAL, "%s: helper ran out of memory", lo->info.name);
                    quit = 1;
                    goto _abort;
                }
            }

            // goto sleep if back off is required
            if (backoff) usleep(min(backoff, RBQ_TMO_1M));
            if (quit) break;

            if (NodeForceHelper(&pool->mynode)) {
                // Single-node config (testing enviro)
                if ((rc = f_get_stripe(lo, F_STRIPE_INVALID, &ss)) < 0) {
                    LOG(LOG_ERR, "%s: error %d in f_get_stripe", lo->info.name, rc);
                    if (rc == -ENOSPC) sleep(1); // FIXME
                    continue;
                } else {
                    LOG(LOG_DBG, "%s: allocated %d stripes", lo->info.name, rc);
                }

            } else {
                // MPI magic
                MPI_Status sts;
                int msg_sz;

                arq->cnt = ss.count;
                arq->cmd = F_AH_GETS;
                arq->flag = 0;
                arq->lid = lo->info.conf_id;
                // send request to remote allocator
                rc = MPI_Send(arq, sizeof(*arq), MPI_BYTE, dst,
                              F_TAG_BASE + lo->info.conf_id, pool->helper_comm);
                if (rc != MPI_SUCCESS) {
                    LOG(LOG_ERR, "MPI_Send returnd error %d", rc);
                    continue;
                }

                // wait for response
                rc = MPI_Recv(arq, F_AH_MSG_SZ(arq->cnt), MPI_BYTE, dst,
                              F_TAG_BASE + lo->info.conf_id, pool->helper_comm, &sts);
                if (rc != MPI_SUCCESS) {
                    LOG(LOG_ERR, "MPI_Recv returnd error %d", rc);
                    continue;
                }
                MPI_Get_count(&sts, MPI_BYTE, &msg_sz);
                LOG(LOG_DBG2, "LO:%d cln AT rsp from %d: msg[%d].op=%d asked %d stripes",
                    arq->lid, sts.MPI_SOURCE, msg_sz, arq->cmd, arq->cnt);
                if (arq->cmd == F_AH_QUIT) {
                    LOG(LOG_INFO, "cln AT: received QUIT command");
                    quit = 1;
                    break;
                }
                if (arq->cmd != F_AH_GETS) {
                    LOG(LOG_ERR, "LO:%d cln AT: wrong response received: %d",
                         arq->lid, arq->cmd);
                    continue;
                }
                ASSERT(arq->lid + F_TAG_BASE == sts.MPI_TAG);
                if (arq->flag) {
                    LOG(LOG_ERR, "LO:%d remote allocator %d returnd error %d",
                        arq->lid, dst, arq->flag);
                    if (arq->flag == -ENOSPC) backoff += 10*RBQ_TMO_1S;
                    continue;
                } else if (arq->cnt != ss.count) {
                    ASSERT(arq->cnt <= ss.count); // can't get more than i asked for
                    LOG(LOG_WARN, "LO:%d remote allocator returnd %d stripes, %d requested",
                        arq->lid, arq->cnt, ss.count);
                    ss.count = arq->cnt;
                    // adjust back off delay to reduce pressure on the allocator
                    backoff += backoff ? : RBQ_TMO_1S;
                } else {
                    // got everything we hoped for, reset back off delay
                    backoff = 0;
                }
            }
            to_do -= ss.count;

            int j, n = 0;
            keyset.count = 0;
            for (int i = 0; i < ss.count; i++) {
                // check slab map and update if missing that slab
                f_slab_t slab = stripe_to_slab(lo, ss.stripes[i]);
                F_SLABMAP_ENTRY_t *sme;
                for (j = 0; j < keyset.count; j++) {
                    if (keyset.slabs[j] == slab) break;
                }
                
                if (j == keyset.count) {
                    sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lo->slabmap, slab);
                    if (!sme || !sme->slab_rec.mapped) {
                        keyset.slabs[n] = slab;
                        keyset.count = ++n;
                        printf("added slab %u (s %lu) to update count %d\n", 
				slab, ss.stripes[i], keyset.count);
                    }
                }
            }
            if (keyset.count > 0) {
                LOG(LOG_DBG2, "%s: updating %d slabs", lo->info.name, n);
                if ((rc = f_slabmap_update(lo->slabmap, &keyset)))
                    LOG(LOG_ERR, "%s: error %d updating global slabmap", lo->info.name, rc);
                if (log_print_level > 0)
                    f_print_sm(dbg_stream, lo->slabmap, lo->info.chunks, lo->info.slab_stripes);
            }

	    /* Stock the queue */
            for (int i = 0; i < ss.count; i++) {
                long tmo = 0;
_retry:
                if ((rc = f_rbq_push(salq, &ss.stripes[i], tmo)) < 0) {
                    LOG(LOG_ERR, "%s: rbq %s push error: %s", lo->info.name, qname, strerror(rc = errno));
                    break;
                } else if (rc == -EAGAIN) {
                    // queue full?
                    // that should not have happened, but try to recover
                    LOG(LOG_ERR, "%s: rbq %s push failed: queue is full", lo->info.name, qname);
                    tmo += RBQ_TMO_1S;
                    goto _retry;
                }
            }
        } // something to_do

    } // loop until quit

    LOG(LOG_DBG, "%s: rbq %s rceived quit signal", lo->info.name, qname);

    // return all unused stripes back to allocator
    while (!f_rbq_isempty(salq)) {
        ss.count = f_rbq_count(salq);

        F_AH_MSG_ALLOC(arq, f_rbq_count(salq), cur_ss_sz, ss);
        if (!arq) {
            LOG(LOG_FATAL, "%s: helper ran out of memory", lo->info.name);
            quit = 1;
            goto _abort;
        }

        for (int i = 0; i < ss.count; i++) {
            if ((rc = f_rbq_pop(salq, &ss.stripes[i], 0)) < 0) {
                LOG(LOG_ERR, "%s: rbq %s pop error while cleaning up: %s", 
                        lo->info.name, qname, strerror(-rc));
                continue;
            } else if (rc == EAGAIN) {
                // empty, we are done
                ss.count = i;
                break;
            }
        }

        if (NodeForceHelper(&pool->mynode)) {
            // single-node config
            if ((rc = f_put_stripe(lo, &ss))) 
                LOG(LOG_ERR, "%s: error %d in f_put_stripe", lo->info.name, rc);
           
        } else {
            // MPI magic
            arq->cnt = ss.count;
            arq->cmd = F_AH_PUTS;
            arq->flag = 0;
            arq->lid = lo->info.conf_id;
            rc = MPI_Send(&arq, F_AH_MSG_SZ(ss.count), MPI_BYTE, dst, 
                     F_TAG_BASE + pool->info.layouts_count, pool->helper_comm);
            if (rc != MPI_SUCCESS)
                LOG(LOG_ERR, "MPI_Send returned error %d", rc);
        }
    }

_abort:
    if (arq)
        free(arq);
    if (keyset.slabs)
        free(keyset.slabs);

    if (lo->slabmap) f_map_exit(lo->slabmap);
    rcu_unregister_thread();
    f_rbq_destroy(salq);
    return NULL;
}

/*
 * Empty committed stripes queue and send them back to (remote) allocator
 * on ION, he'll know what to do with them
 *
 */
#if 0
static void *drainer(void *arg) {
    int rc = 0;
    char qname[MAX_RBQ_NAME];

    F_POOL_t    *pool = (F_POOL_t *)arg;
    f_rbq_t     *scmq;
    f_ah_scme_t scme;
    int hwm = pool->info.cq_hwm;
    int N = pool->info.layouts_count;
    F_LAYOUT_t  *lo[N];
    int dst = 0;
    int qdepth = 0;
    uint64_t tmo = pool->info.cq_hwm_tmo*RBQ_TMO_1S;

    if (!tmo) tmo = RBQ_TMO_1S/10;  // min tmo 100ms 

    for (int i = 0; i < N; i++) {
        if ((lo[i] = f_get_layout(i)) == NULL) {
            LOG(LOG_ERR, "get layout [%d] info\n", i);
            continue;
        } else {
            qdepth += lo[i]->info.sq_depth;
        }
    }

    // create rbq
    sprintf(qname, "%s-all", F_SCMQ_NAME);
    if ((rc = f_rbq_create(qname, sizeof(f_ah_scme_t), qdepth, &scmq, 1))) {
        LOG(LOG_ERR, "rbq %s create: %s", qname, strerror(-rc));
        exit(rc);
    }

    cmq = scmq;

    // set high water mark
    f_rbq_sethwm(scmq, qdepth*hwm/100);

    struct f_stripe_set ssa[N];
    int sss[N];
    f_ah_ipc_t *crq[N];
    int in_flight[N];
    MPI_Request mrq[N];


    bzero(in_flight, sizeof(in_flight));
    bzero(ssa, sizeof(ssa));
    bzero(sss, sizeof(sss));
    bzero(crq, sizeof(crq));

    for (int i = 0; i < N; i++) {
        F_AH_MSG_ALLOC(crq[i], hwm/N, sss[i], ssa[i]);
        if (crq[i] == NULL) {
            LOG(LOG_FATAL, "helper ran out of memory");
            goto _abort;
        }
        ssa[i].count = 0;
        crq[i]->cmd = F_AH_COMS;
        crq[i]->lid = i;
        crq[i]->flag = 0;
    }

    if (!NodeForceHelper(&pool->mynode))
        dst = pool->mynode.my_ion;

    LOG(LOG_DBG, "helper commit thread %s is up", qname);

    int do_more = 0;
    while (!quit) {
        if (!do_more) {
            // wait until queue is sufficiently full 
            if ((rc = f_rbq_waithwm(scmq, tmo)) == -ETIMEDOUT) {
                LOG(LOG_DBG3, "rbq %s: HW TMO\n", qname);
            } else if (rc == -ECANCELED) {
                if (!f_rbq_isempty(scmq))
                    LOG(LOG_INFO, "rbq %s: wake-up signal received", qname);
            } else if (rc) {
                LOG(LOG_ERR, "rbq %s wait hwm: %s", qname, strerror(-rc));
            }
        }
        if (quit)
            break;

        // read commit queue untill empty and send stripe (home)
        while (!f_rbq_isempty(scmq)) {
            if ((rc = f_rbq_pop(scmq, &scme, 0) == -EAGAIN)) {
                // empty, done
                break;
            } else if (rc < 0) {
                LOG(LOG_ERR, "rbq %s pop error: %s", qname, strerror(rc = errno));
                break;
            }
            int lid = scme.lid;
            if (lid >= N) {
                LOG(LOG_ERR, "bad layout id %d popped of queue %s", scme.lid, qname);
                continue;
            }

            // this stripe is marked for relase
            if (scme.flag) {
                F_AH_MSG(prq, 1) = F_AH_MSG_INIT(F_AH_PUTS, lid, 1);
                prq.str[0] = scme.str;
                struct f_stripe_set ss = {.count = 1, .stripes = &prq.str[0]};

                if (NodeForceHelper(&pool->mynode)) {
                    if ((rc = f_put_stripe(lo[lid], &ss)))
                        LOG(LOG_ERR, "%s: error %d in f_put_stripe", lo[lid]->info.name, rc);
                } else {
                    // MPI magic
                    if (in_flight[lid])
                        MPI_Wait(&mrq[lid], MPI_STATUS_IGNORE);
                    in_flight[lid] = 0;
                    rc = MPI_Isend(&prq, sizeof(prq), MPI_BYTE, dst, F_TAG_BASE + N, 
                                   pool->helper_comm, &mrq[lid]);
                    if (rc != MPI_SUCCESS) {
                        LOG(LOG_ERR, "MPI_Isend returnd error %d", rc);
                        continue;
                    }
                    in_flight[lid] = 1;
                }
                LOG(LOG_DBG, "%s: sent stripe %lu for release", lo[lid]->info.name, scme.str);
                continue;
            }

            if (lo[lid]->info.chunks - lo[lid]->info.data_chunks) {
                pthread_spin_lock(&cntfy_lock);
                set_bit(lid, &cntfy[scme.rank].edr_bm);
                pthread_spin_unlock(&cntfy_lock);
            }

            F_AH_MSG_APPEND(crq[lid], scme.str, sss[lid], ssa[lid]);
            if (crq[lid] == NULL) {
                LOG(LOG_FATAL, "helper ran out of memory");
                goto _abort;
            }

            // send them out if too many
            if (ssa[lid].count >= F_MAX_IPC_ME) {
                do_more++;
                break;
            }
        }
        if (f_rbq_isempty(scmq))
            do_more = 0;

        for (int i = 0; i <  N; i++) {
            if (ssa[i].count) {
                if (NodeForceHelper(&pool->mynode)) {
                    if ((rc = f_commit_stripe(lo[i], &ssa[i])) < 0)
                        LOG(LOG_ERR, "%s[%d]: error %d in f_commit_stripe", lo[i]->info.name, lo[i]->lp->part_num, rc);
                } else {
                    // MPI magic
                    if (in_flight[i])
                        MPI_Wait(&mrq[i], MPI_STATUS_IGNORE);
                    in_flight[i] = 0;
                    crq[i]->cnt = ssa[i].count;
                    crq[i]->flag = 0;
                    crq[i]->lid = i;
                    rc = MPI_Isend(crq[i], F_AH_MSG_SZ(ssa[i].count), MPI_BYTE, 
                                   dst, F_TAG_BASE + N, pool->helper_comm, &mrq[i]);
                    if (rc != MPI_SUCCESS) {
                        LOG(LOG_ERR, "MPI_Isend returnd error %d", rc);
                    } else {
                        in_flight[i] = 1;
                    }
                    LOG(LOG_DBG, "%s: sent %d stripes to commit, s0=%lu", lo[i]->info.name, crq[i]->cnt, crq[i]->str[0]); 

                }
                ssa[i].count = 0;
            }
        }
    }

_abort:

    for (int i = 0; i < pool->info.layouts_count; i++)
        if (crq[i])
            free(crq[i]);

    f_rbq_destroy(scmq);
    return NULL;
}
#endif

//
// Send helper (client) request batch to helper (server) on allocator node
// If request is already in flight, just wait for it's completion, do not resend
//
static int send_or_wait_helper_rq(f_ah_ipc_t *rq, int dst, u8 *flying, MPI_Request *mpi_rq, int sync, char *h) {
    F_POOL_t *pool = f_get_pool();
    int rc;

    if (NodeForceHelper(&pool->mynode)) {
        struct f_stripe_set ss;

        ss.count = rq->cnt;
        ss.stripes = alloca(sizeof(f_stripe_t)*rq->cnt);
        memcpy(ss.stripes, &rq->str[0], sizeof(f_stripe_t)*rq->cnt);

        if (rq->cmd == F_AH_COMS)
            rc = f_commit_stripe(f_get_layout(rq->lid), &ss);
        else
            rc = f_put_stripe(f_get_layout(rq->lid), &ss);

        if (rc) LOG(LOG_ERR, "f_%s_stripe returnd error %d", rq->cmd == F_AH_COMS ? "commit" : "put", rc);
        return rc;
    }

    if (*flying) {
        // MPI_Isend in progress
//printf("%s: wait for %d %s to complete, s0=%lu\n", h, rq->cnt, rq->cmd == F_AH_COMS ? "commits" : "releases", rq->str[0]);
        MPI_Wait(mpi_rq, MPI_STATUS_IGNORE);
        rq->cnt = 0;
        *flying  = 0;
        return 0;
    } else {
        // No MPI_Isend issued 
        if (sync) {
//printf("%s: sync send %d stripes to %s, s0=%lu\n", h, rq->cnt, rq->cmd == F_AH_COMS ? "commit" : "release", rq->str[0]);
            rc = MPI_Send(rq, F_AH_MSG_SZ(rq->cnt), MPI_BYTE, dst,
                          F_TAG_BASE + pool->info.layouts_count,
                          pool->helper_comm);
            rq->cnt = 0;
        } else {
//printf("%s: send %d stripes to %s, s0=%lu\n", h, rq->cnt, rq->cmd == F_AH_COMS ? "commit" : "release", rq->str[0]);
            *flying = 1;
            rc = MPI_Isend(rq, F_AH_MSG_SZ(rq->cnt), MPI_BYTE, dst,
                           F_TAG_BASE + pool->info.layouts_count,
                           pool->helper_comm, mpi_rq);
        }

        if (rc != MPI_SUCCESS) {
            LOG(LOG_ERR, "%s MPI_(I)send returnd error %d", h, rc);
            rq->cnt = 0;
            *flying  = 0;
            return rc;
        }
    }

    return 0;
}

static void *drainer(void *arg) {
    int rc = 0;
    char qname[MAX_RBQ_NAME];

    F_POOL_t    *pool = (F_POOL_t *)arg;
    f_rbq_t     *scmq;
    f_ah_scme_t scme;
    int hwm = pool->info.cq_hwm;
    int N = pool->info.layouts_count;
    F_LAYOUT_t  *lo[N];
    int dst = 0;
    int qdepth = 0;
    uint64_t tmo = pool->info.cq_hwm_tmo*RBQ_TMO_1S;

    if (!tmo) tmo = RBQ_TMO_1S/10;  // min tmo 100ms 

    for (int i = 0; i < N; i++) {
        if ((lo[i] = f_get_layout(i)) == NULL) {
            LOG(LOG_ERR, "get layout [%d] info\n", i);
            continue;
        } else {
            qdepth += lo[i]->info.sq_depth;
        }
    }

    // create rbq
    sprintf(qname, "%s-all", F_SCMQ_NAME);
    if ((rc = f_rbq_create(qname, sizeof(f_ah_scme_t), qdepth, &scmq, 1))) {
        LOG(LOG_ERR, "rbq %s create: %s", qname, strerror(-rc));
        exit(rc);
    }

    cmq = scmq;

    // set high water mark
    f_rbq_sethwm(scmq, qdepth*hwm/100);

    f_ah_ipc_t *crq[N], *rrq[N];
    u8 c_act[N], r_act[N];
    MPI_Request c_mrq[N], r_mrq[N];


    bzero(c_act, sizeof(c_act));
    bzero(r_act, sizeof(r_act));

    for (int i = 0; i < N; i++) {
        crq[i] = malloc(F_AH_MSG_SZ(F_MAX_IPC_ME));
        rrq[i] = malloc(F_AH_MSG_SZ(F_MAX_IPC_ME));
        if (crq[i] == NULL || rrq[i] == NULL) {
            LOG(LOG_FATAL, "helper ran out of memory");
            goto _abort;
        }
        crq[i]->cmd = F_AH_COMS;
        crq[i]->lid = i;
        crq[i]->flag = 0;

        rrq[i]->cmd = F_AH_PUTS;
        rrq[i]->lid = i;
        rrq[i]->flag = 1;

    }

    if (!NodeForceHelper(&pool->mynode))
        dst = pool->mynode.my_ion;

    char *h = pool->mynode.hostname;

    LOG(LOG_DBG, "%s helper commit thread %s is up", pool->mynode.hostname, qname);

    while (!quit) {
        // wait until queue is sufficiently full 
        if ((rc = f_rbq_waithwm(scmq, tmo)) == -ETIMEDOUT) {
            LOG(LOG_DBG3, "rbq %s: HW TMO\n", qname);
        } else if (rc == -ECANCELED) {
            if (!f_rbq_isempty(scmq))
                LOG(LOG_INFO, "rbq %s: wake-up signal received", qname);
        } else if (rc) {
            LOG(LOG_ERR, "rbq %s wait hwm: %s", qname, strerror(-rc));
        }
        if (quit) break;

        // read commit queue untill empty and send stripes home
        while (!f_rbq_isempty(scmq)) {
            if ((rc = f_rbq_pop(scmq, &scme, 0) == -EAGAIN)) {
                // input queue is empty, done
                break;
            } else if (rc < 0) {
                LOG(LOG_ERR, "rbq %s pop error: %s", qname, strerror(rc = errno));
                break;
            }
            int lid = scme.lid;
            if (lid >= N) {
                LOG(LOG_ERR, "bad layout id %d popped of queue %s", scme.lid, qname);
                continue;
            }
//printf(">>> %s: got rq from %d to %s stripe %lu\n", h, scme.rank, scme.flag ? "release" : "commit", scme.str);

            if (scme.flag) {
                // release request, see if we have any commits accumulated for this layout
                if (crq[lid]->cnt) {
                    if (send_or_wait_helper_rq(crq[lid], dst, &c_act[lid], &c_mrq[lid], 1, h)) {
                        LOG(LOG_ERR, "%s: failed to send %d/%lu stripes to commit to %d", 
                            pool->mynode.hostname, crq[lid]->cnt, crq[lid]->str[0], dst);
                    }
                }

                // keep adding to release batch, but first make sure we can use the buffer
                if (r_act[lid]) {
                    MPI_Wait(&r_mrq[lid], MPI_STATUS_IGNORE);
                    r_act[lid] = 0;
                    rrq[lid]->cnt = 0;
                }
                rrq[lid]->str[rrq[lid]->cnt++] = scme.str;

                if (rrq[lid]->cnt == F_MAX_IPC_ME) {
                    // reached max batch
                    if (send_or_wait_helper_rq(rrq[lid], dst, &r_act[lid], &r_mrq[lid], 0, h)) {
                        LOG(LOG_ERR, "%s: failed to send %d/%lu stripes to release to %d", 
                            pool->mynode.hostname, rrq[lid]->cnt, rrq[lid]->str[0], dst);
                    }
                }
            } else {
                // commit request, see if we have any releases accumulated for this layout
                if (rrq[lid]->cnt) {
                    if (send_or_wait_helper_rq(rrq[lid], dst, &r_act[lid], &r_mrq[lid], 1, h)) {
                        LOG(LOG_ERR, "%s: failed to send %d/%lu stripes to release to %d", 
                            pool->mynode.hostname, rrq[lid]->cnt, rrq[lid]->str[0], dst);
                    }
                }

                // keep adding to commit batch
                if (c_act[lid]) {
                    MPI_Wait(&c_mrq[lid], MPI_STATUS_IGNORE);
                    c_act[lid] = 0;
                    crq[lid]->cnt = 0;
                }
                crq[lid]->str[crq[lid]->cnt++] = scme.str;

                // if layout has parity, mark this client in EDR bitmap for close() delay
                if (lo[lid]->info.chunks - lo[lid]->info.data_chunks) {
                    pthread_spin_lock(&cntfy_lock);
                    set_bit(lid, &cntfy[scme.rank].edr_bm);
                    pthread_spin_unlock(&cntfy_lock);
                }

                if (crq[lid]->cnt == F_MAX_IPC_ME) {
                    if (send_or_wait_helper_rq(crq[lid], dst, &c_act[lid], &c_mrq[lid], 0, h)) {
                        LOG(LOG_ERR, "%s: failed to send %d/%lu stripes to commit to %d",
                            pool->mynode.hostname, crq[lid]->cnt, crq[lid]->str[0], dst);
                    }
                }
            }
        }

        // push all accumulated commits and releases out
        for (int i = 0; i < N; i++) {
            if (crq[i]->cnt && !c_act[i]) {
                if (send_or_wait_helper_rq(crq[i], dst, &c_act[i], &c_mrq[i], 0, h)) {
                    LOG(LOG_ERR, "%s: failed to send %d/%lu stripes to commit to %d",
                        pool->mynode.hostname, crq[i]->cnt, crq[i]->str[0], dst);
                }
            }
            if (rrq[i]->cnt && !r_act[i]) {
                if (send_or_wait_helper_rq(rrq[i], dst, &r_act[i], &r_mrq[i], 0, h)) {
                    LOG(LOG_ERR, "%s: failed to send %d/%lu stripes to release to %d", 
                        pool->mynode.hostname, rrq[i]->cnt, rrq[i]->str[0], dst);
                }
            }
        }
    }

_abort:

    for (int i = 0; i < pool->info.layouts_count; i++) {
        free(crq[i]);
        free(rrq[i]);
    }

    f_rbq_destroy(scmq);
    return NULL;
}


//
// -------------------- tear here -------------------
// Client part
//

#ifndef ERROR

#define ERROR(fmt, ...) \
do { \
        printf("famfs error: %s:%d: %s: " fmt "\n", \
               __FILE__, __LINE__, __func__, ## __VA_ARGS__); \
} while (0)

#endif

static f_rbq_t *calq[F_CMDQ_MAX];
static f_rbq_t *ccmq;

int f_ah_attach() {
    int rc = 0;
    char qname[MAX_RBQ_NAME];

    F_POOL_t    *pool = f_get_pool();

    for (int i = 0; i < pool->info.layouts_count; i++) {
        F_LAYOUT_t *lo = f_get_layout(i);
        if (lo == NULL) {
            ERROR("bad layout id: %d", i);
            return -EINVAL;
        }

        sprintf(qname, "%s-%s", F_SALQ_NAME, lo->info.name);
        if ((rc = f_rbq_open(qname, &calq[i]))) {
            ERROR("rbq %s open: %s", qname, strerror(rc = errno));
            return rc;
        }
    }
    sprintf(qname, "%s-all", F_SCMQ_NAME);
    if ((rc = f_rbq_open(qname, &ccmq))) {
        ERROR("rbq %s open: %s", qname, strerror(rc = errno));
        return rc;
    }

    return 0;
}

int f_ah_dettach() {
    F_POOL_t    *pool = f_get_pool();

    for (int i = 0; i < pool->info.layouts_count; i++) 
        f_rbq_close(calq[i]);

    f_rbq_close(ccmq);

    return 0;
}

int f_ah_get_stripe(F_LAYOUT_t *lo, f_stripe_t *str) {
    F_POOL_t    *pool = f_get_pool();
    int rc;

    if (str == NULL || lo->info.conf_id >= pool->info.layouts_count || lo->info.conf_id < 0) {
        ERROR("bad call parameteres");
        return -EINVAL;
    }
    
    int rt = 0;
    do {
        rc = f_rbq_pop(calq[lo->info.conf_id], str, 10*RBQ_TMO_1S);
    } while (rc == -ETIMEDOUT && ++rt < 3);

    if (rc == -ETIMEDOUT && f_rbq_isempty(calq[lo->info.conf_id])) {
        ERROR("looks like lo %s is out of space", lo->info.name);
        rc = -ENOSPC;
    } else if (rc) {
        ERROR("layout %s rbq error: %s", lo->info.name, strerror(-rc));
    }

    return rc;
}

static int _push_stripe(F_LAYOUT_t *lo, f_stripe_t str, int release) {
    F_POOL_t    *pool = f_get_pool();
    f_ah_scme_t scme;

    if (lo->info.conf_id >= pool->info.layouts_count || lo->info.conf_id < 0) {
        ERROR("bad call parameteres");
        return -EINVAL;
    }
    scme.lid = lo->info.conf_id;
    scme.str = str;
    scme.flag = release;
    scme.rank = 0;

    return f_rbq_push(ccmq, &scme, 10*RBQ_TMO_1S);

}

int f_ah_commit_stripe(F_LAYOUT_t *lo, f_stripe_t str) {
    return _push_stripe(lo, str, 0);
}

int f_ah_release_stripe(F_LAYOUT_t *lo, f_stripe_t str) {
    return _push_stripe(lo, str, 1);
}

void f_ah_flush() {
    f_rbq_wakewm(ccmq);
}

int f_test_helper(F_POOL_t *pool)
{
	int rc = f_ah_attach();
	if (rc) return rc;
	printf("attached\n");
        int cnt = 128;

    	while (!exit_flag && cnt--) {
		//int n = 0;
		for (int i = 0; i < pool->info.layouts_count; i++) {
			f_stripe_t s;
			F_LAYOUT_t *lo = f_get_layout(i);

			rc = f_ah_get_stripe(lo, &s);
			if (rc == -ETIMEDOUT) {
				sleep(1);
				continue;
			} else if (rc) goto _ret;

			usleep(100);

			rc = f_ah_commit_stripe(lo, s);
			if (rc) goto _ret;
		}
	}
_ret:
	printf("flushing commit queue\n");
	f_ah_flush();
	f_ah_dettach();
	return rc;
}
