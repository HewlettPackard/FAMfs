/*
 * Copyright (c) 2019, HPE
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

#include "famfs_global.h"
#include "unifycr_metadata.h"
#include "log.h"
#include "unifycr_debug.h"
#include "unifycr_const.h"
#include "unifycr_global.h"
#include "unifycr_cmd_handler.h"
#include "unifycr_service_manager.h"
//#include "unifycr_request_manager.h"
#include "famfs_env.h"
#include "famfs_error.h"
#include "famfs_maps.h"
#include "famfs_bitmap.h"
#include "lf_client.h"
#include "famfs_rbq.h"
#include "f_pool.h"
#include "f_layout.h"
#include "famfs_maps.h"
#include "f_map.h"
#include "f_allocator.h"
#include "mpi_utils.h"
#include "f_layout_ctl.h"
#include "f_helper.h"

extern volatile int exit_flag;

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
    int rc = 0;

    // Only for "pure" IONs
    if (f_host_is_ionode(NULL) && !NodeForceHelper(&pool->mynode)) {

        // start alloc srv threads
        for (int i = 0; i < pool->info.layouts_count; i++) {
            F_LAYOUT_t *lo = f_get_layout(i);
            if (lo == NULL) {
                LOG(LOG_ERR, "get layout [%d] info\n", i);
                continue;
            }

            if ((rc = pthread_create(&hs_athrd[i], NULL, alloc_srv, lo))) {
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

    for (int i = 0; i < pool->info.layouts_count; i++) {
        F_LAYOUT_t *lo = f_get_layout(i);
        if (lo == NULL) {
            LOG(LOG_ERR, "get layout [%d] info\n", i);
            return EIO;
        }

        lo->part_count = pool->ionode_count;
        if ((rc = pthread_create(&al_thrd[i], NULL, stoker, lo))) {
            LOG(LOG_ERR, "helper alloc thread create failed on LO %s", lo->info.name);
            return rc;
        }
    }
    
    if ((rc = pthread_create(&cm_thrd, NULL, drainer, pool))) {
        LOG(LOG_ERR, "helper str commit thread create failed");
        return rc;
    }

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
                      F_TAG_BASE + N, MPI_COMM_WORLD, &sts);
        if (rc != MPI_SUCCESS || sts.MPI_ERROR != MPI_SUCCESS) {
            LOG(LOG_ERR, "MPI_Recv returnd error %d/sts=%d", rc, sts.MPI_ERROR);
            continue;
        }

        MPI_Get_count(&sts, MPI_BYTE, &msg_sz);
        LOG(LOG_DBG, "srv CT from %d: msg[%d].op=%d got %d stripes to commit to LO %d", 
            sts.MPI_SOURCE, msg_sz, msg->cmd, msg->cnt, msg->lid);
        if (msg->cmd == F_AH_QUIT) {
            LOG(LOG_INFO, "srv CT: received QUIT command");
            break;
        }
        if (msg->cmd != F_AH_COMS && msg->cmd != F_AH_PUTS) {
            LOG(LOG_ERR, "srv CT: wrong command received: %d, LO %d", msg->cmd, msg->lid);
            continue;
        }
        ASSERT(msg_sz == F_AH_MSG_SZ(msg->cnt));

        ss.count = msg->cnt;
        ss.stripes = &msg->str[0];
        lo = f_get_layout(msg->lid);
        if (lo == NULL) {
            LOG(LOG_ERR, "get layout [%d] info\n", msg->lid);
            continue;
        }

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
    MPI_Status sts;
    MPI_Request mrq;
    f_ah_ipc_t msg, *rply = NULL;
    int rc = 0, msg_sz = 0, ss_cnt = 0, in_flight = 0;
    int lid = lo->info.conf_id;

    while (!quit) {
        // wait for any commit message from CNs' helpers
        // allocators use TAG_BASE + layout ID tag
        rc = MPI_Recv(&msg, sizeof(msg), MPI_BYTE, MPI_ANY_SOURCE, F_TAG_BASE + lid, 
                      MPI_COMM_WORLD, &sts);
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
        ASSERT(msg_sz == sizeof(msg));
        ASSERT(msg.lid + F_TAG_BASE == sts.MPI_TAG);
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
                       sts.MPI_TAG, MPI_COMM_WORLD, &mrq);
        if (rc != MPI_SUCCESS) {
            LOG(LOG_ERR, "MPI_Isend returnd error %d", rc);
            continue;
        }
        in_flight = 1;
/*
        rc = MPI_Send(rply, F_AH_MSG_SZ(ss.count), MPI_BYTE, sts.MPI_SOURCE, 
                       sts.MPI_TAG, MPI_COMM_WORLD);
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

    if (f_host_is_ionode(NULL) && !NodeForceHelper(&pool->mynode)) {
        // running on "real" ION
        MPI_Request rq[pool->info.layouts_count];
        f_ah_ipc_t qm = {.cmd = F_AH_QUIT};
        int myself;

        MPI_Comm_rank(MPI_COMM_WORLD, &myself);
        for (int i = 0; i < pool->info.layouts_count; i++) {
            MPI_Isend(&qm, sizeof(qm), MPI_BYTE, myself, F_TAG_BASE + i, MPI_COMM_WORLD, &rq[i]);
            pthread_join(hs_athrd[i], NULL);
        }

        MPI_Isend(&qm, sizeof(qm), MPI_BYTE, myself, F_TAG_BASE + pool->info.layouts_count, MPI_COMM_WORLD, &rq[0]);
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
    F_POOL_t *pool = lo->pool;
    struct cb_data cbdata;
    int part = NodeIsIOnode(&pool->mynode) ? pool->mynode.ionode_idx : 0;
    int e_sz, chunks, rc;

    LOG(LOG_DBG, "%s: loading global slabmap", lo->info.name);

    chunks = lo->info.chunks%2 +  lo->info.chunks; // Pad to the next even chunk 
    e_sz = sizeof(F_SLAB_ENTRY_t) + chunks*sizeof(F_EXTENT_ENTRY_t);
    lo->slabmap  = f_map_init(F_MAPTYPE_STRUCTURED, e_sz, 0, 0);
    if (!lo->slabmap) return -EINVAL;

    rc = f_map_init_prt(lo->slabmap, lo->part_count, part, 0, 1);
    if (rc) {
        LOG(LOG_ERR, "%s: error %d initializing global slabmap", lo->info.name, rc);
        return rc;
    }

    rc = f_map_register(lo->slabmap, lo->info.conf_id);
    if (rc) {
        LOG(LOG_ERR, "%s: error %d registering global slabmap", lo->info.name, rc);
        return rc;
    }

    rc = f_map_shm_attach(lo->slabmap, F_MAPMEM_SHARED_WR);
    if (rc) {
        LOG(LOG_ERR, "%s: error %d attaching to global slabmap", lo->info.name, rc);
        return rc;
    }

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

    LOG(LOG_DBG, "%s: %u slabs loaded: %d errors", lo->info.name, cbdata.loaded, cbdata.err);

    if (log_print_level > 0)
        f_print_sm(dbg_stream, lo->slabmap, lo->info.chunks, lo->info.slab_stripes);

    return rc;
}

/*
 * Open global claim vector (all partitions). Not used by the helper, done only to work around
 * the global index creation barrier. Hence, we do not load the claim vector here.
 */
static int open_global_claimvec(F_LAYOUT_t *lo)
{
    F_POOL_t *pool = lo->pool;
    int part = NodeIsIOnode(&pool->mynode) ? pool->mynode.ionode_idx : 0;
    int rc;

    LOG(LOG_DBG, "%s: opening global claim vector", lo->info.name);

    lo->claimvec  = f_map_init(F_MAPTYPE_BITMAP, 2, 0, 0);
    if (!lo->claimvec) return -EINVAL;

    rc = f_map_init_prt(lo->claimvec, lo->part_count, part, 0, 1);
    if (rc) {
        LOG(LOG_ERR, "%s: error %d initializing global claim vector", lo->info.name, rc);
        return rc;
    }

    rc = f_map_register(lo->claimvec, lo->info.conf_id);
    if (rc) {
        LOG(LOG_ERR, "%s: error %d registering global claim vector", lo->info.name, rc);
        return rc;
    }
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
    int depth = lo->info.sq_depth;
    int lwm = depth*lo->info.sq_lwm/100;

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

    if ((rc = read_global_slabmap(lo))) {
	LOG(LOG_ERR, "%s: slabmap load failed: %s", lo->info.name, strerror(-rc));
        goto _abort;
    }

    if ((rc = open_global_claimvec(lo))) {
	LOG(LOG_ERR, "%s: claim vector load failed: %s", lo->info.name, strerror(-rc));
        goto _abort;
    }

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

    LOG(LOG_DBG, "%s: helper alloc thread %s is up", lo->info.name, qname);

    f_ah_ipc_t *arq = NULL;
    int cur_ss_sz = 0;
    while (!quit) {

        // wait until queue is sufficiently empty
        if ((rc = f_rbq_waitlwm(salq, F_SALQ_LWTMO)) == -ETIMEDOUT) {
            if (f_rbq_isfull(salq))
                LOG(LOG_DBG, "%s: rbq %s: LW TMO\n", lo->info.name, qname);
        } else if (rc == -ECANCELED) {
            LOG(LOG_INFO, "%s: rbq %s wak-up signal", lo->info.name, qname);
        } else if (rc) {
            LOG(LOG_ERR, "%s: rbq %s wait lwm: %s", lo->info.name, qname, strerror(-rc));
        }
        if (quit)
            break;

        // stuff stripes into the queue untill it's full
        int to_do = f_rbq_size(salq) - f_rbq_count(salq);
        while (to_do) {
            int batch = min(f_rbq_size(salq) - f_rbq_count(salq), F_MAX_IPC_ME);
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
                              F_TAG_BASE + lo->info.conf_id, MPI_COMM_WORLD);
                if (rc != MPI_SUCCESS) {
                    LOG(LOG_ERR, "MPI_Send returnd error %d", rc);
                    continue;
                }

                // wait for response
                rc = MPI_Recv(arq, F_AH_MSG_SZ(arq->cnt), MPI_BYTE, dst, 
                              F_TAG_BASE + lo->info.conf_id, MPI_COMM_WORLD, &sts);
                if (rc != MPI_SUCCESS) {
                    LOG(LOG_ERR, "MPI_Recv returnd error %d", rc);
                    continue;
                }
                MPI_Get_count(&sts, MPI_BYTE, &msg_sz);
                LOG(LOG_DBG, "cln AT rsp from %d: msg[%d].op=%d got %d stripes for %d", 
                    sts.MPI_SOURCE, msg_sz, arq->cmd, arq->cnt, arq->lid);
                if (arq->cmd == F_AH_QUIT) {
                    LOG(LOG_INFO, "cln AT: received QUIT command");
                    quit = 1;
                    break;
                }
                if (arq->cmd != F_AH_GETS) {
                    LOG(LOG_ERR, "cln AT: wrong response received: %d, LO %d", arq->cmd, arq->lid);
                    continue;
                }
                ASSERT(arq->lid + F_TAG_BASE == sts.MPI_TAG);
                if (arq->flag) {
                    LOG(LOG_ERR, "remote allocator %d returnd error %d", dst, arq->flag);
                    if (arq->flag == -ENOSPC) backoff += 10*RBQ_TMO_1S;
                    continue;
                } else if (arq->cnt != ss.count) {
                    LOG(LOG_WARN, "remote allocator returnd %d stripes, %d requested", arq->cnt, ss.count);
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
                long tmo = 0;
                for (j = 0; j < keyset.count; j++) {
                    if (keyset.slabs[j] == slab) break;
                }
                
                if (j == keyset.count) {
                    sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lo->slabmap, slab);
                    if (!sme || !sme->slab_rec.mapped) {
                        keyset.slabs[n] = slab;
                        keyset.count = ++n;
                        printf("added slab %u (s %lu) to update count %d\n", slab, ss.stripes[i], keyset.count);
                    }
                }
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
            if (keyset.count > 0) {
                LOG(LOG_DBG2, "%s: updating %d slabs", lo->info.name, n);
                if ((rc = f_slabmap_update(lo->slabmap, &keyset)))
                    LOG(LOG_ERR, "%s: error %d updating global slabmap", lo->info.name, rc);
                if (log_print_level > 0)
                    f_print_sm(dbg_stream, lo->slabmap, lo->info.chunks, lo->info.slab_stripes);
            }
        }
            
    }

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
                     F_TAG_BASE + pool->info.layouts_count, MPI_COMM_WORLD);
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

    while (!quit) {
        // wait until queue is sufficiently full 
        if ((rc = f_rbq_waithwm(scmq, tmo)) == -ETIMEDOUT) {
            LOG(LOG_DBG, "rbq %s: HW TMO\n", qname);
        } else if (rc == -ECANCELED) {
            if (!f_rbq_isempty(scmq))
                LOG(LOG_INFO, "rbq %s: wake-up signal received", qname);
        } else if (rc) {
            LOG(LOG_ERR, "rbq %s wait hwm: %s", qname, strerror(-rc));
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
                                   MPI_COMM_WORLD, &mrq[lid]);
                    if (rc != MPI_SUCCESS) {
                        LOG(LOG_ERR, "MPI_Isend returnd error %d", rc);
                        continue;
                    }
                    in_flight[lid] = 1;
                }
                continue;
            }

            F_AH_MSG_APPEND(crq[lid], scme.str, sss[lid], ssa[lid]);
            if (crq[lid] == NULL) {
                LOG(LOG_FATAL, "helper ran out of memory");
                goto _abort;
            }

            // send them out if too many
            if (ssa[lid].count >= F_MAX_IPC_ME)
                break;
        }

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
                                   dst, F_TAG_BASE + N, MPI_COMM_WORLD, &mrq[i]);
                    if (rc != MPI_SUCCESS) {
                        LOG(LOG_ERR, "MPI_Isend returnd error %d", rc);
                    } else {
                        in_flight[i] = 1;
                    }

                }
                ssa[i].count = 0;
            }
        }
    }

_abort:

    for (int i = 0; i < pool->info.layouts_count; i++)
        if (ssa[i].stripes)
            free(ssa[i].stripes);

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

    	while (!exit_flag) {
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
