/*
 * Copyright (c) 2018, HPE
 *
 * Written by: Dmitry Ivanov
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include "f_error.h"
#include "w_pool.h"

#define timespecadd(t, inc)				\
	do {						\
		(t)->tv_sec += (inc)->tv_sec;		\
		(t)->tv_nsec += (inc)->tv_nsec;		\
		if ((t)->tv_nsec >= 1000000000U) {	\
			(t)->tv_sec++;			\
			(t)->tv_nsec -= 1000000000U;	\
		}					\
	} while (0)

static int pool_wait(W_POOL_t* pool);

static int thread_init(W_POOL_t *pool, W_THREAD_t **threads, int id, const cpu_set_t *cpuset);
static void* thread_run(W_THREAD_t *thread);
static void thread_free(W_THREAD_t *thread);

static void w_queue_init(W_QUEUE_t* q);
static void w_queue_free(W_QUEUE_t* q);


W_POOL_t* pool_init(int size, w_func_ work_func_p, int *affinity)
{
	W_POOL_t *pool;
	cpu_set_t *cpumask = NULL;
	int i;

	ASSERT(size > 0);

	if (affinity) {
		cpumask = (cpu_set_t *)malloc(sizeof(cpu_set_t));
		ON_ERROR(!cpumask, "OOM cpumask");
	}

	pool = (W_POOL_t *)malloc(sizeof(W_POOL_t));
	ON_ERROR(!pool, "OOM pool");
	pool->size = 0;
	pool->any_done_only = 0;
	pool->queue_max_size = W_QUEUE_MAX_SIZE;
	w_queue_init(&pool->in_queue);
	w_queue_init(&pool->out_queue);

	pool->threads = (W_THREAD_t **)malloc(size*sizeof(W_THREAD_t *));
	ON_ERROR(!pool->threads, "OOM threads");
	pool->shutdown = 0;
	memset(&pool->stats, 0, sizeof(pool->stats)); /* alive, job_queued, job_done = 0 */
	pool->w_fn = work_func_p;

	ON_ERROR( pthread_mutex_init(&pool->w_thread_lock, NULL), "mutex");
	ON_ERROR( pthread_cond_init(&pool->w_thread_cond, NULL), "cond");
	ON_ERROR( pthread_spin_init(&pool->stats_lock, PTHREAD_PROCESS_SHARED), "spin");

	for (i = 0; i < size; i++) {
		if (affinity) {
			int j, k = affinity[i];

			CPU_ZERO(cpumask);
			for (j=0;j<1;j++)
				CPU_SET(j+k, cpumask);
		}
		thread_init(pool, &pool->threads[i], i, cpumask);
	}
	free(cpumask);

	while (pool->stats.alive != size) {}

	return pool;
}

int pool_add_work(W_POOL_t* pool, W_TYPE_t type, void *params)
{
	N_WORK_t *work;
	W_QUEUE_t *q;
	int rc = 0;

	ASSERT(type < W_T_NONE);
	work = (N_WORK_t *)malloc(sizeof(N_WORK_t));
	if (!work) {
		err("OOM work");
		return -1;
	}
	work->type = type;
	work->params = params;
	QUEUE_INIT(&work->node);

	/* Add work to in_queue */
	pthread_mutex_lock(&pool->w_thread_lock);
	if (pool->shutdown && type != W_T_EXIT) {
		pthread_mutex_unlock(&pool->w_thread_lock);
		free(work);
		return -1;
	}
	pthread_mutex_unlock(&pool->w_thread_lock);

	q = &pool->in_queue;
	pthread_mutex_lock(&q->queue_lock);

	if (pool->in_queue.size < pool->queue_max_size) {
		/* TODO: Limit queue size */
		QUEUE_INSERT_TAIL(&q->queue, &work->node);
		q->size++;

		/* TODO: no need for another lock while accessing stats.job_xxx */
		pthread_spin_lock(&pool->stats_lock);
		pool->stats.job_queued++;
		pthread_spin_unlock(&pool->stats_lock);

		pthread_cond_signal(&q->queue_cond);
	} else {
		err("Queue full @%d", pool->queue_max_size);
		free(work);
		rc = -1;
	}
	pthread_mutex_unlock(&q->queue_lock);

	return rc;
}

/* Wait until all works done or return ETIMEDOUT */
int pool_wait_works_done(W_POOL_t* pool, uint64_t timeout_ms)
{
	struct timespec to, wait;
	int do_wait, rc = 0;

	/* ms to timespec */
	wait.tv_sec = timeout_ms / 1000;
	wait.tv_nsec = (timeout_ms % 1000U) * 1000000U;

	clock_gettime(CLOCK_REALTIME, &to);
	timespecadd(&to, &wait);

	pthread_mutex_lock(&pool->w_thread_lock);
		pthread_spin_lock(&pool->stats_lock);
		do_wait = (pool->stats.job_queued > pool->stats.job_done);
		pthread_spin_unlock(&pool->stats_lock);

	while (!pool->shutdown && do_wait && !rc) {
		rc = pthread_cond_timedwait(&pool->w_thread_cond, &pool->w_thread_lock, &to);
		pthread_spin_lock(&pool->stats_lock);
		do_wait = (pool->stats.job_queued > pool->stats.job_done);
		pthread_spin_unlock(&pool->stats_lock);
	}
	pthread_mutex_unlock(&pool->w_thread_lock);

	return rc;
}

/* Wait until first work done or return ETIMEDOUT */
int pool_wait_single_work_done(W_POOL_t* pool, uint64_t timeout_ms)
{
	struct timespec to, wait;
	int do_wait, rc = 0;

	/* ms to timespec */
	wait.tv_sec = timeout_ms / 1000;
	wait.tv_nsec = (timeout_ms % 1000U) * 1000000U;

	clock_gettime(CLOCK_REALTIME, &to);
	timespecadd(&to, &wait);

	pthread_mutex_lock(&pool->w_thread_lock);
		pthread_spin_lock(&pool->stats_lock);
		do_wait = ((pool->stats.job_queued - pool->size) >= pool->stats.job_done);
		pthread_spin_unlock(&pool->stats_lock);

	while (!pool->shutdown && do_wait && !rc) {
		rc = pthread_cond_timedwait(&pool->w_thread_cond, &pool->w_thread_lock, &to);
		pthread_spin_lock(&pool->stats_lock);
		do_wait = ((pool->stats.job_queued - pool->size) >= pool->stats.job_done);
		pthread_spin_unlock(&pool->stats_lock);
	}
	pthread_mutex_unlock(&pool->w_thread_lock);

	pool->any_done_only = 0;
	return rc;
}

static int pool_wait(W_POOL_t* pool)
{
	int i, size;
	int r, rc = 0;
	intptr_t rtn;

	size = pool->size;
	for (i = 0; i < size; i++) {
		r = pthread_join(pool->threads[i]->pthread, (void**)&rtn);
		if (r)
			err("pool pthread_join error %d - %m\n", r);
		if (rtn)
			err("worker error:%ld", rtn);
		if (rc == 0)
			rc = (int)rtn;
	}
	/* TODO: Process out_queue */

	return rc;
}

int pool_exit(W_POOL_t* pool, int cancel)
{
	volatile int size;
	int i;
	int rc;

	ASSERT(pool);

	/* Stop queueing */
	ON_ERROR( pthread_mutex_lock(&pool->w_thread_lock), "mutex_lock");
	if (pool->shutdown) {
		ON_ERROR( pthread_mutex_unlock(&pool->w_thread_lock), "mutex_unlock");

		err("Pool already stopped");
		return -1;
	}
	pool->shutdown = cancel;
	ON_ERROR( pthread_mutex_unlock(&pool->w_thread_lock), "mutex_unlock");

	ON_ERROR( pthread_spin_lock(&pool->stats_lock), "spin lock");
	size = pool->stats.alive;
	ON_ERROR( pthread_spin_unlock(&pool->stats_lock), "spin lock");

	/* Signal threads to exit */
	ASSERT(size<=pool->size);
	for (i = 0; i < size; i++)
		pool_add_work(pool, W_T_EXIT, NULL);
	rc = pool_wait(pool);

	for (i = 0; i < size; i++)
		thread_free(pool->threads[i]);
	free(pool->threads);

	/* TODO: Process out_queue */

	/* Destroy queues */
	w_queue_free(&pool->in_queue);
	w_queue_free(&pool->out_queue);

	free(pool);
	return rc;
}

static void w_queue_init(W_QUEUE_t* q)
{
	QUEUE_INIT(&q->queue);
	q->size = 0;
	ON_ERROR( pthread_mutex_init(&q->queue_lock, NULL), "mutex");
	ON_ERROR( pthread_cond_init(&q->queue_cond, NULL), "cond");
}

static void w_queue_free(W_QUEUE_t* queue)
{
	QUEUE	*q;
	N_WORK_t *work;

	while (queue->size > 0) {
		q = QUEUE_HEAD(&queue->queue);
		QUEUE_REMOVE(q);
		work = QUEUE_DATA(q, N_WORK_t, node);
		free(work);
		queue->size--;
	}
}

static int thread_init(W_POOL_t *pool, W_THREAD_t **threads, int id, const cpu_set_t *cpuset)
{
	pthread_attr_t	attr;
	W_THREAD_t	*threadp;

	ON_ERROR( pthread_attr_init(&attr), "pthread attr init");
	ON_ERROR( pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE), "pthread set attr");
	if (cpuset)
		ON_ERROR( pthread_attr_setaffinity_np(&attr, sizeof(*cpuset), cpuset),
			"pthread setaffinity");

	threadp = (W_THREAD_t *)malloc(sizeof(W_THREAD_t));
	if (!threadp) {
		err("OOM thread");
		return -1;
	}
	threadp->pool = pool;
	threadp->id = id;

	ON_ERROR( pthread_create(&threadp->pthread, &attr, (void *)thread_run, threadp),
		"Error creating pthread");
	ON_ERROR( pthread_attr_destroy(&attr), "pthread attr destroy");

	ON_ERROR( pthread_spin_lock(&pool->stats_lock), "spin lock");
	*threads = threadp;
	pool->size++;
	ON_ERROR( pthread_spin_unlock(&pool->stats_lock), "spin unlock");

	return 0;
}

static void thread_free(W_THREAD_t *thread)
{
	free(thread);
}

static void* thread_run(W_THREAD_t *thread)
{
	W_POOL_t *pool = thread->pool;
	W_QUEUE_t *in_queue;
	char name[16];
	intptr_t rc = 0;

	ASSERT(pool);
	sprintf(name, "w-thread-%d", thread->id);
	ON_ERROR( pthread_setname_np(thread->pthread, name), "setname");

	pthread_spin_lock(&pool->stats_lock);
	pool->stats.alive++;
	pthread_spin_unlock(&pool->stats_lock);

	in_queue = &pool->in_queue;
	while (!pool->shutdown) {
		N_WORK_t *w;
		W_TYPE_t cmd;
		QUEUE *q;
		int ret, signal_all_done;

		pthread_mutex_lock(&in_queue->queue_lock);
		while (in_queue->size == 0) {
			pthread_cond_wait(&in_queue->queue_cond, &in_queue->queue_lock);
		}
		q = QUEUE_HEAD(&in_queue->queue);
		QUEUE_REMOVE(q);
		in_queue->size--;
		pthread_mutex_unlock(&in_queue->queue_lock);

		w = QUEUE_DATA(q, N_WORK_t, node);
		cmd = w->type;
		if (pool->shutdown)
			goto _free;

		switch (cmd) {
		case W_T_LOAD:
		case W_T_VERIFY:
		case W_T_ENCODE:
		case W_T_DECODE:
			ret = pool->w_fn(cmd, w->params, thread->id);
			if (ret && !rc)
				rc = ret; /* report the first error */
			break;
		default:;
		}
_free:
		free(w);

		/* signal all works done */
		pthread_mutex_lock(&pool->w_thread_lock);
		pthread_spin_lock(&pool->stats_lock);
		signal_all_done = (pool->stats.job_queued == ++pool->stats.job_done);
		pthread_spin_unlock(&pool->stats_lock);
		pthread_mutex_unlock(&pool->w_thread_lock);
		if (pool->any_done_only || signal_all_done)
			pthread_cond_signal(&pool->w_thread_cond);

		if (cmd == W_T_EXIT)
			break;
	}

	pthread_spin_lock(&pool->stats_lock);
	pool->stats.alive--;
	pthread_spin_unlock(&pool->stats_lock);

	pthread_exit((void*)rc);
}

