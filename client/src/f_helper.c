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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>

#include "f_global.h"
#include "f_env.h"
#include "f_error.h"
#include "f_rbq.h"
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

    for (unsigned int i = 0; i < pool->info.layouts_count; i++) {
        F_LAYOUT_t *lo = f_get_layout(i);
        if (lo == NULL) {
            ERROR("bad layout id: %u", i);
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

    for (unsigned int i = 0; i < pool->info.layouts_count; i++)
        f_rbq_close(calq[i]);

    f_rbq_close(ccmq);

    return 0;
}

int f_ah_get_stripe(F_LAYOUT_t *lo, f_stripe_t *str) {
    F_POOL_t    *pool = f_get_pool();
    int rc;

    if (str == NULL || lo->info.conf_id >= pool->info.layouts_count) {
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

extern int local_rank_idx;
static int _push_stripe(F_LAYOUT_t *lo, f_stripe_t str, int release) {
    F_POOL_t    *pool = f_get_pool();
    f_ah_scme_t scme;

    if (lo->info.conf_id >= pool->info.layouts_count) {
        ERROR("bad call parameteres");
        return -EINVAL;
    }
    scme.lid = lo->info.conf_id;
    scme.str = str;
    scme.flag = release;
    scme.rank = local_rank_idx;

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

