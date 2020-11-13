/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef W_POOL_H
#define W_POOL_H

#include <stdint.h>
#include <pthread.h>
#include <limits.h>

#include "list.h"
#include "famfs_env.h"
#include "famfs_ktypes.h"

#define W_QUEUE_MAX_SIZE INT_MAX

typedef enum f_wtype_ {
	F_WT_LOAD = 0,
	F_WT_ENCODE,
	F_WT_DECODE,
	F_WT_VERIFY,
	F_WT_EXIT,
	F_WT_NONE,
} F_WTYPE_t;

static inline const char *f_wtype2str(F_WTYPE_t type)
{
        switch(type) {
        case F_WT_LOAD:  return "LOAD";
        case F_WT_ENCODE:return "ENCODE";
        case F_WT_DECODE:return "DECODE";
        case F_WT_VERIFY:return "VERIFY";
        default:        return "Unknown";
        }
}

typedef enum f_wpriority_ {
	F_WP_HIGH = 0,
	F_WP_NORMAL,
	F_WP_LOW,
	F_WP_NR,	/* # of priorities */
} F_WPRIO_t;

typedef struct f_work_ {
	struct list_head	list;
	enum f_wtype_		type;
	void			*params;
} F_WORK_t;
/*
typedef struct n_status_ {
	QUEUE		node;
	int		status;
} N_STATUS_t;
*/
typedef struct f_wthread_ {
	int			id;
	pthread_t		pthread;
	struct	f_wpool_	*wpool;
} F_WTHREAD_t;

typedef int (*f_wfunc_)(enum f_wtype_ type, void *params, int thread_id);

typedef struct f_wqueue_ {
	struct list_head	queue;
	pthread_spinlock_t	lock;
	int			size;
	f_wfunc_		w_fn;
	atomic_t		in_flight;
} F_WQUEUE_t;

typedef struct w_thread_stats_ {
	volatile int	alive;
	volatile int	job_queued;
	volatile int	job_done;
} W_THREAD_STATS_t;

typedef struct f_wpool_ {
	F_WTHREAD_t	**threads;
	pthread_cond_t	w_thread_cond;
	pthread_mutex_t	w_thread_lock;
	pthread_mutex_t	queue_lock;
	pthread_cond_t	queue_cond;
	atomic_t	qsize;
	atomic_t	in_flight;
	F_WQUEUE_t	queues[F_WP_NR];
	int		queue_max_size;
//	w_func_		w_fn;
	int		size;
	volatile int	shutdown;
	int		any_done_only;	/* 1: wait for all done only */
	pthread_spinlock_t	stats_lock;
	W_THREAD_STATS_t	stats;
} F_WPOOL_t;

F_WPOOL_t *f_wpool_init(int size, f_wfunc_ *work_func_array, int *affinity);
int f_wpool_add_work(F_WPOOL_t *wpool, F_WTYPE_t type, F_WPRIO_t prio, void *params);
int f_wpool_exit(F_WPOOL_t *wpool, int cancel);
int f_wpool_wait_all_jobs_done(F_WPOOL_t *wpool, uint64_t timeout_ms);
int f_wpool_wait_queue_jobs_done(F_WPOOL_t *wpool, F_WPRIO_t prio, uint64_t timeout_ms);
int f_wpool_wait_single_job_done(F_WPOOL_t *wpool, uint64_t timeout_ms);

#endif
