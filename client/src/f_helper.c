/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Oleg Neverovitch, Yann Livis
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>

#include "famfs_global.h"
#include "famfs_env.h"
#include "famfs_error.h"
#include "famfs_rbq.h"
#include "f_pool.h"
#include "f_layout.h"
#include "f_helper.h"


pthread_t al_thrd[F_CMDQ_MAX];
pthread_t cm_thrd;

f_rbq_t   *alq[F_CMDQ_MAX];
f_rbq_t   *cmq;

//
// Client part
//

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

int f_ah_detach() {
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

int f_ah_commit_stripe(F_LAYOUT_t *lo, f_stripe_t str) {
    F_POOL_t    *pool = f_get_pool();

    if (lo->info.conf_id >= pool->info.layouts_count || lo->info.conf_id < 0) {
        ERROR("bad call parameteres");
        return -EINVAL;
    }
    
    return f_rbq_push(ccmq, &str, 10*RBQ_TMO_1S);

}

void f_ah_flush() {
    f_rbq_wakewm(ccmq);
}
#if 0
int f_test_helper(F_POOL_t *pool)
{
	int rc = f_ah_attach();
	if (rc) return rc;
	printf("attached\n");

    	while (!exit_flag) {
		for (int i = 0; i < pool->info.layouts_count; i++) {
			f_stripe_t s;
			F_LAYOUT_t *lo = f_get_layout(i);
		
			rc = f_ah_get_stripe(lo, &s);
			if (rc == -ETIMEDOUT) {
				sleep(1);
				continue;
			} else if (rc) goto _ret;

			printf("got stripe %lu\n", s);

			usleep(100);

			rc = f_ah_commit_stripe(lo, s);
			if (rc) goto _ret;
			printf("committed stripe %lu\n", s);
		}
	}
_ret:
	f_ah_dettach();	
	return rc;
}
#endif

