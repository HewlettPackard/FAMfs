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
#include "unifycr_request_manager.h"
#include "famfs_env.h"
#include "famfs_error.h"
#include "famfs_maps.h"
#include "lf_client.h"
#include "famfs_rbq.h"
#include "f_pool.h"
#include "f_layout.h"
#include "famfs_maps.h"
#include "f_allocator.h"
#include "mpi_utils.h"
#include "f_helper.h"

extern volatile int exit_flag;
volatile int quit = 0;

pthread_t al_thrd[F_CMDQ_MAX];
pthread_t cm_thrd;

f_rbq_t   *alq[F_CMDQ_MAX];
f_rbq_t   *cmq;

int f_ah_init(F_POOL_t *pool) {
    int rc = 0;

    if (f_host_is_ionode(NULL) && !NodeForceHelper(&pool->mynode)) {
        LOG(LOG_ERR, "attempt to start helper on ION");
        return EINVAL;
    }

    for (int i = 0; i < pool->info.layouts_count; i++) {
        F_LAYOUT_t *lo = f_get_layout(i);
        if (lo == NULL) {
            LOG(LOG_ERR, "get layout [%d] info\n", i);
            return EIO;
        }

        if ((rc = pthread_create(&al_thrd[i], NULL, f_ah_stoker, lo))) {
            LOG(LOG_ERR, "LO %s helper alloc thread create failed", lo->info.name);
            return rc;
        }
    }
    
    if ((rc = pthread_create(&cm_thrd, NULL, f_ah_drainer, pool))) {
        LOG(LOG_ERR, "helper str commit thread create failed");
        return rc;
    }

    return 0;
}

int f_ah_shutdown(F_POOL_t *pool) {
    int rc = 0;
    int n = 0;

    if (f_host_is_ionode(NULL) && !NodeForceHelper(&pool->mynode)) {
        LOG(LOG_ERR, "attempt to start helper on ION");
        return EINVAL;
    }

    quit = 1;
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
        while (f_rbq_destroy(alq[i]) == EAGAIN) {
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
    while (f_rbq_destroy(cmq) == EAGAIN) {
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

void *f_ah_stoker(void *arg) {
    int rc = 0;
    char qname[MAX_RBQ_NAME];

    f_rbq_t    *salq;
    F_LAYOUT_t *lo = (F_LAYOUT_t *)arg;
    F_POOL_t   *pool = lo->pool;

    struct f_stripe_set ss;

    // create rbq
    sprintf(qname, "%s-%s", F_SALQ_NAME, lo->info.name);
    if ((rc = f_rbq_create(qname, sizeof(f_stripe_t), F_MAX_SALQ, &salq, 1))) {
        LOG(LOG_ERR, "rbq %s create: %s", qname, strerror(rc = errno));
        exit(rc);
    }

    alq[lo->info.conf_id] = salq;

    // set low water mark
    f_rbq_setlwm(salq, f_rbq_size(salq)/100*F_SALQ_LWM);

    if (NodeForceHelper(&pool->mynode)) {
        F_LO_PART_t *lp = lo->lp;

        if (!lp->ready) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += (ts.tv_nsec + 60000000000L)/1000000000L;
            ts.tv_nsec = (ts.tv_nsec + 60000000000L)%1000000000L;

            pthread_mutex_lock(&lp->lock_ready);
            if ((rc = pthread_cond_timedwait(&lp->cond_ready, &lp->lock_ready, &ts))) {
                if (rc == ETIMEDOUT) {
                    LOG(LOG_ERR, "TMO waiting for alloc thread to be ready");
                } else {
                    LOG(LOG_ERR, "error waitng for allocator");
                }
            } else {
                LOG(LOG_DBG, "allocator thread is ready");
            }
        }
    } else {
        // TODO: MPI sync wait for allocators
    }

    LOG(LOG_DBG, "helper alloc thread %s is up", qname);

    while (!quit) {

        // wait until queue is sufficiently empty
        if ((rc = f_rbq_waitlwm(salq, F_SALQ_LWTMO)) == ETIMEDOUT) {
            LOG(LOG_DBG, "rbq %s: LW TMO\n", qname);
            continue;
        } else if (rc && rc != ECANCELED) {
            LOG(LOG_ERR, "rbq %s wait lwm: %s", qname, strerror(rc));
            continue;
        }
        if (quit)
            break;

        // stuff stripes into the queue untill it's full
        while (f_rbq_count(salq) < f_rbq_size(salq)) {
            if (NodeForceHelper(&pool->mynode)) {

                ss.count = f_rbq_size(salq) - f_rbq_count(salq);
                ss.stripes = calloc(ss.count, sizeof(f_stripe_t));
                if (ss.stripes == NULL) {
                    LOG(LOG_FATAL, "helper ran out of memory");
                    quit = 1;
                    return NULL;
                }

                if ((rc = f_get_stripe(lo, F_STRIPE_INVALID, &ss)) < 0) {
                    LOG(LOG_ERR, "%s[%d]: error %d in f_get_stripe", lo->info.name, lo->lp->part_num, rc);
                    continue;
                } else {
                    LOG(LOG_DBG, "%s[%d]: allocated %d stripes", lo->info.name, lo->lp->part_num, rc);
                }

                uint64_t tmo = 0;
                for (int i = 0; i < ss.count; i++) {
                    //f_slab_t slab = stripe_to_slab(lo, ss.stripes[i]);
                    // TODO: check slab map and update if missing this stripe

_retry:
                    if ((rc = f_rbq_push(salq, &ss.stripes[i], tmo)) < 0) {
                        LOG(LOG_ERR, "rbq %s push error: %s", qname, strerror(rc = errno));
                        break;
                    } else if (rc == EAGAIN) {
                        // queue full?
                        // that should not have happened, but try to recover
                        LOG(LOG_ERR, "rbq %s push failed: queue is full", qname);
                        tmo += RBQ_TMO_1S;
                        goto _retry;
                    }
                    tmo = 0;
                }
                free(ss.stripes);

            } else {
                // TODO: MPI magic
            }
        }
            
    }

    LOG(LOG_DBG, "rbq %s rceived quit signal", qname);

    // return all unused stripes back to allocator
    while (!f_rbq_isempty(salq)) {
        if (NodeForceHelper(&pool->mynode)) {
            ss.count = f_rbq_count(salq);
            ss.stripes = calloc(ss.count, sizeof(f_stripe_t));
            if (ss.stripes == NULL) {
                LOG(LOG_FATAL, "helper ran out of memory");
                goto _abort;
            }

            for (int i = 0; i < ss.count; i++) {
                if ((rc = f_rbq_pop(salq, &ss.stripes[i], 0)) < 0) {
                    LOG(LOG_ERR, "rbq %s pop error while cleaning up: %s", qname, strerror(rc = errno));
                    continue;
                } else if (rc == EAGAIN) {
                    // empty, we are done
                    ss.count = i;
                    break;
                }
            }
            if ((rc = f_put_stripe(lo, &ss))) 
                LOG(LOG_ERR, "%s[%d]: error %d in f_put_stripe", lo->info.name, lo->lp->part_num, rc);

            free(ss.stripes);
           
        } else {
            // TODO: MPI magic
        }
    }

_abort:

    return NULL;
}

void *f_ah_drainer(void *arg) {
    int rc = 0;
    char qname[MAX_RBQ_NAME];

    F_POOL_t    *pool = (F_POOL_t *)arg;
    f_rbq_t     *scmq;
    f_ah_scme_t scme;
    F_LAYOUT_t  *lo;

    // create rbq
    sprintf(qname, "%s-all", F_SCMQ_NAME);
    if ((rc = f_rbq_create(qname, sizeof(f_ah_scme_t), F_MAX_SCMQ, &scmq, 1))) {
        LOG(LOG_ERR, "rbq %s create: %s", qname, strerror(rc = errno));
        exit(rc);
    }

    cmq = scmq;

    // set high water mark
    f_rbq_sethwm(scmq, f_rbq_size(scmq)/100*F_SCMQ_HWM);

    struct f_stripe_set ssa[pool->info.layouts_count];
    int sss[pool->info.layouts_count];

    for (int i = 0; i < pool->info.layouts_count; i++) {
        sss[i] = f_rbq_gethwm(scmq)/pool->info.layouts_count;
        ssa[i].stripes = malloc(sizeof(f_stripe_t)*sss[i]);
        if (ssa[i].stripes == NULL) {
            LOG(LOG_FATAL, "helper ran out of memory");
            goto _abort;
        }
        ssa[i].count = 0;
    }

    LOG(LOG_DBG, "helper commit thread %s is up", qname);

    while (!quit) {
        // wait until queue is sufficiently full 
        if ((rc = f_rbq_waithwm(scmq, F_SCMQ_HWTMO)) == ETIMEDOUT) {
            LOG(LOG_DBG, "rbq %s: HW TMO\n", qname);
            continue;
        } else if (rc && rc != ECANCELED) {
            LOG(LOG_ERR, "rbq %s wait hwm: %s", qname, strerror(rc));
            continue;
        }
        if (quit)
            break;

        // read commit queue untill empty and send stripe (home)
        while (!f_rbq_isempty(scmq)) {
            if ((rc = f_rbq_pop(scmq, &scme, 0) == EAGAIN)) {
                // empty, done
                break;
            } else if (rc < 0) {
                LOG(LOG_ERR, "rbq %s pop error: %s", qname, strerror(rc = errno));
                break;
            }
            int lo_id = scme.lo_id;
            if (lo_id >= pool->info.layouts_count) {
                LOG(LOG_ERR, "bad layout id %d popped of queue %s", scme.lo_id, qname);
                continue;
            }
            if (sss[lo_id] <= ssa[lo_id].count) {
                sss[lo_id] += sss[lo_id];
                ssa[lo_id].stripes = realloc(ssa[lo_id].stripes, sss[lo_id]);
                if (ssa[lo_id].stripes == NULL) {
                    LOG(LOG_FATAL, "helper ran out of memory");
                    goto _abort;
                }
            }
            ssa[lo_id].stripes[ssa[lo_id].count] = scme.str;
            ssa[lo_id].count++;

            // send them out if too many
            if (ssa[lo_id].count > F_MAX_CMS_CNT)
                break;
        }

        for (int i = 0; i <  pool->info.layouts_count; i++) {
            if (ssa[i].count) {
                if ((lo = f_get_layout(i)) == NULL) {
                     LOG(LOG_ERR, "get layout [%d] info\n", i);
                     continue;
                }
                if ((rc = f_commit_stripe(lo, &ssa[i])) < 0)
                    LOG(LOG_ERR, "%s[%d]: error %d in f_commit_stripe", lo->info.name, lo->lp->part_num, rc);

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

    if (str == NULL || lo->info.conf_id >= pool->info.layouts_count || lo->info.conf_id < 0) {
        ERROR("bad call parameteres");
        return -EINVAL;
    }
    
    return f_rbq_pop(calq[lo->info.conf_id], str, RBQ_TMO_1S);

}

int f_ah_commit_stripe(F_LAYOUT_t *lo, f_stripe_t str) {
    F_POOL_t    *pool = f_get_pool();

    if (lo->info.conf_id >= pool->info.layouts_count || lo->info.conf_id < 0) {
        ERROR("bad call parameteres");
        return -EINVAL;
    }
    
    return f_rbq_push(ccmq, &str, 10*RBQ_TMO_1S);

}


