/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef W_POOL_H
#define W_POOL_H

#include <stdint.h>
#include <pthread.h>

#include "queue.h"
#include "famfs_env.h"

#define W_QUEUE_MAX_SIZE 128

typedef enum w_type_ {
	W_T_LOAD = 0,
	W_T_ENCODE,
	W_T_DECODE,
	W_T_VERIFY,
	W_T_EXIT,
	W_T_NONE,
} W_TYPE_t;

static inline const char *cmd2str(W_TYPE_t type)
{
        switch(type) {
        case W_T_LOAD:  return "LOAD";
        case W_T_ENCODE:return "ENCODE";
        case W_T_DECODE:return "DECODE";
        case W_T_VERIFY:return "VERIFY";
        default:        return "Unknown";
        }
}

typedef struct n_work_ {
	QUEUE		node;
	enum w_type_	type;
	void		*params;
} N_WORK_t;

typedef struct n_status_ {
	QUEUE		node;
	int		status;
} N_STATUS_t;

typedef struct w_thread_ {
	int	id;
	pthread_t	pthread;
	struct	w_pool_	*pool;
} W_THREAD_t;

typedef struct w_queue_ {
	QUEUE		queue;
	pthread_mutex_t	queue_lock;
	pthread_cond_t	queue_cond;
	int		size;
} W_QUEUE_t;

typedef int (*w_func_)(enum w_type_ type, void *params, int thread_id);

typedef struct w_thread_stats_ {
	volatile int	alive;
	volatile int	job_queued;
	volatile int	job_done;
} W_THREAD_STATS_t;

typedef struct w_pool_ {
	W_THREAD_t	**threads;
	pthread_cond_t	w_thread_cond;
	pthread_mutex_t	w_thread_lock;
	W_QUEUE_t	in_queue;
	W_QUEUE_t	out_queue;
	int		queue_max_size;
	w_func_		w_fn;
	int		size;
	volatile int	shutdown;
	int		any_done_only;	/* 1: wait for all done only */
	pthread_spinlock_t	stats_lock;
	W_THREAD_STATS_t	stats;
} W_POOL_t;

W_POOL_t* pool_init(int size, w_func_ work_func_p, int *affinity);
int pool_add_work(W_POOL_t* pool, enum w_type_ type, void *params);
int pool_exit(W_POOL_t* pool, int cancel);
int pool_wait_works_done(W_POOL_t* pool, uint64_t timeout_ms);
int pool_wait_single_work_done(W_POOL_t* pool, uint64_t timeout_ms);

#endif
