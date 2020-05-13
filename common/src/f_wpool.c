/*
 * Copyright (c) 2018, HPE
 *
 * Written by: Dmitry Ivanov
 * Modified by: Yann Livis
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include "famfs_env.h" 
#include "famfs_error.h"
#include "f_wpool.h"

static int wpool_wait(F_WPOOL_t* wpool);

static int thread_init(F_WPOOL_t *wpool, F_WTHREAD_t **threads, int id, const cpu_set_t *cpuset);
static void* thread_run(F_WTHREAD_t *thread);
static void thread_free(F_WTHREAD_t *thread);

static void w_queue_init(F_WQUEUE_t* q);
static void w_queue_free(F_WQUEUE_t* q);


F_WPOOL_t *f_wpool_init(int size, f_wfunc_ *work_func_array, int *affinity)
{
	F_WPOOL_t *wpool;
	cpu_set_t *cpumask = NULL;
	F_WPRIO_t p;
	int i;

	ASSERT(size > 0);

	if (affinity) {
		cpumask = (cpu_set_t *)malloc(sizeof(cpu_set_t));
		ON_ERROR(!cpumask, "OOM cpumask");
	}

	wpool = (F_WPOOL_t *)malloc(sizeof(F_WPOOL_t));
	ON_ERROR(!wpool, "OOM pool");
	wpool->size = 0;
	wpool->any_done_only = 0;
	wpool->queue_max_size = W_QUEUE_MAX_SIZE;
	atomic_set(&wpool->qsize, 0);
	atomic_set(&wpool->in_flight, 0);

	for (p = F_WP_HIGH; p < F_WP_NR; p++) {
		F_WQUEUE_t *q = &wpool->queues[p];
		w_queue_init(q);
		q->w_fn = work_func_array[p];
	}

	wpool->threads = (F_WTHREAD_t **)malloc(size*sizeof(F_WTHREAD_t *));
	ON_ERROR(!wpool->threads, "OOM threads");
	wpool->shutdown = 0;
	memset(&wpool->stats, 0, sizeof(wpool->stats)); /* alive, job_queued, job_done = 0 */

	ON_ERROR( pthread_mutex_init(&wpool->w_thread_lock, NULL), "mutex");
	ON_ERROR( pthread_cond_init(&wpool->w_thread_cond, NULL), "cond");
	ON_ERROR( pthread_mutex_init(&wpool->queue_lock, NULL), "mutex");
	ON_ERROR( pthread_cond_init(&wpool->queue_cond, NULL), "cond");
	ON_ERROR( pthread_spin_init(&wpool->stats_lock, PTHREAD_PROCESS_SHARED), "spin");

	for (i = 0; i < size; i++) {
		if (affinity) {
			int j, k = affinity[i];

			CPU_ZERO(cpumask);
			for (j=0;j<1;j++)
				CPU_SET(j+k, cpumask);
		}
		thread_init(wpool, &wpool->threads[i], i, cpumask);
	}
	free(cpumask);

	while (wpool->stats.alive != size) {}

	return wpool;
}

int f_wpool_add_work(F_WPOOL_t *wpool, F_WTYPE_t type, F_WPRIO_t prio, void *params)
{
	F_WORK_t *work;
	F_WQUEUE_t *q;
	int rc = 0;

	ASSERT(type < F_WT_NONE);
	ASSERT(prio < F_WP_NR);

	work = (F_WORK_t *)malloc(sizeof(F_WORK_t));
	if (!work) {
		err("OOM work");
		return -1;
	}
	work->type = type;
	work->params = params;
	INIT_LIST_HEAD(&work->list);

	/* Add work to in_queue */
	pthread_mutex_lock(&wpool->w_thread_lock);
	if (wpool->shutdown && type != F_WT_EXIT) {
		pthread_mutex_unlock(&wpool->w_thread_lock);
		free(work);
		return -1;
	}
	pthread_mutex_unlock(&wpool->w_thread_lock);

	q = &wpool->queues[prio];

	if (atomic_read(&wpool->qsize) < wpool->queue_max_size) {
		pthread_spin_lock(&q->lock);
		list_add_tail(&work->list, &q->queue);
		q->size++;
		pthread_spin_unlock(&q->lock);

		atomic_inc(&wpool->qsize);
		atomic_inc(&wpool->in_flight);
		atomic_inc(&q->in_flight);

		/* TODO: no need for another lock while accessing stats.job_xxx */
		pthread_spin_lock(&wpool->stats_lock);
		wpool->stats.job_queued++;
		pthread_spin_unlock(&wpool->stats_lock);

		pthread_cond_signal(&wpool->queue_cond);
	} else {
		err("Queue full @%d", wpool->queue_max_size);
		free(work);
		rc = -1;
	}

	return rc;
}

/* Wait until all jobs done or return ETIMEDOUT */
int f_wpool_wait_all_jobs_done(F_WPOOL_t *wpool, uint64_t timeout_ms)
{
	struct timespec to, wait;
//	int do_wait;
	int rc = 0;

	/* ms to timespec */
	wait.tv_sec = timeout_ms / 1000;
	wait.tv_nsec = (timeout_ms % 1000U) * 1000000U;

	clock_gettime(CLOCK_REALTIME, &to);
	timespecadd(&to, &wait);

	pthread_mutex_lock(&wpool->w_thread_lock);
/*		pthread_spin_lock(&pool->stats_lock);
		do_wait = (pool->stats.job_queued > pool->stats.job_done);
		pthread_spin_unlock(&pool->stats_lock);

	while (!pool->shutdown && do_wait && !rc) {
*/
	while (!wpool->shutdown && atomic_read(&wpool->in_flight) && !rc) {
		rc = pthread_cond_timedwait(&wpool->w_thread_cond, &wpool->w_thread_lock, &to);
/*		pthread_spin_lock(&pool->stats_lock);
		do_wait = (pool->stats.job_queued > pool->stats.job_done);
		pthread_spin_unlock(&pool->stats_lock);
*/
	}
	pthread_mutex_unlock(&wpool->w_thread_lock);

	return rc;
}

/* Wait until a particular queue jobs done or return ETIMEDOUT */
int f_wpool_wait_queue_jobs_done(F_WPOOL_t *wpool, F_WPRIO_t prio, uint64_t timeout_ms)
{
	struct timespec to, wait;
	F_WQUEUE_t *q;
	int rc = 0;

	ASSERT(prio < F_WP_NR);
	q = &wpool->queues[prio];

	/* ms to timespec */
	wait.tv_sec = timeout_ms / 1000;
	wait.tv_nsec = (timeout_ms % 1000U) * 1000000U;

	clock_gettime(CLOCK_REALTIME, &to);
	timespecadd(&to, &wait);

	pthread_mutex_lock(&wpool->w_thread_lock);
	while (!wpool->shutdown && atomic_read(&q->in_flight) && !rc) {
		rc = pthread_cond_timedwait(&wpool->w_thread_cond, &wpool->w_thread_lock, &to);
	}
	pthread_mutex_unlock(&wpool->w_thread_lock);

	return rc;
}

/* Wait until first work done or return ETIMEDOUT */
int f_wpool_wait_single_job_done(F_WPOOL_t* pool, uint64_t timeout_ms)
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

static int wpool_wait(F_WPOOL_t* wpool)
{
	int i, size;
	int r, rc = 0;
	intptr_t rtn;

	size = wpool->size;
	for (i = 0; i < size; i++) {
		r = pthread_join(wpool->threads[i]->pthread, (void**)&rtn);
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

int f_wpool_exit(F_WPOOL_t* wpool, int cancel)
{
	volatile int size;
	F_WPRIO_t p;
	int i;
	int rc;

	ASSERT(wpool);

	/* Stop queueing */
	ON_ERROR( pthread_mutex_lock(&wpool->w_thread_lock), "mutex_lock");
	if (wpool->shutdown) {
		ON_ERROR( pthread_mutex_unlock(&wpool->w_thread_lock), "mutex_unlock");

		err("Pool already stopped");
		return -1;
	}
	wpool->shutdown = cancel;
	ON_ERROR( pthread_mutex_unlock(&wpool->w_thread_lock), "mutex_unlock");

	ON_ERROR( pthread_spin_lock(&wpool->stats_lock), "spin lock");
	size = wpool->stats.alive;
	ON_ERROR( pthread_spin_unlock(&wpool->stats_lock), "spin lock");

	/* Signal threads to exit */
	ASSERT(size<=wpool->size);
	for (i = 0; i < size; i++)
		f_wpool_add_work(wpool, F_WT_EXIT, F_WP_HIGH, NULL);
	rc = wpool_wait(wpool);

	for (i = 0; i < size; i++)
		thread_free(wpool->threads[i]);
	free(wpool->threads);

	/* TODO: Process out_queue */

	/* Destroy queues */
	for (p = F_WP_HIGH; p < F_WP_NR; p++) {
		F_WQUEUE_t *q = &wpool->queues[p];
		w_queue_free(q);
	}

	free(wpool);
	return rc;
}

static void w_queue_init(F_WQUEUE_t* q)
{
	INIT_LIST_HEAD(&q->queue);
	q->size = 0;
	atomic_set(&q->in_flight, 0);
	ON_ERROR( pthread_spin_init(&q->lock, PTHREAD_PROCESS_PRIVATE), "spin");
}

static void w_queue_free(F_WQUEUE_t* queue)
{
	F_WORK_t *work, *next;

	list_for_each_entry_safe(work, next, &queue->queue, list) {
		list_del_init(&work->list);
		free(work);
		queue->size--;
	}
	ASSERT(!queue->size);
}

static int thread_init(F_WPOOL_t *wpool, F_WTHREAD_t **threads, int id, const cpu_set_t *cpuset)
{
	pthread_attr_t	attr;
	F_WTHREAD_t	*threadp;

	ON_ERROR( pthread_attr_init(&attr), "pthread attr init");
	ON_ERROR( pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE), "pthread set attr");
	if (cpuset)
		ON_ERROR( pthread_attr_setaffinity_np(&attr, sizeof(*cpuset), cpuset),
			"pthread setaffinity");

	threadp = (F_WTHREAD_t *)malloc(sizeof(F_WTHREAD_t));
	if (!threadp) {
		err("OOM thread");
		return -1;
	}
	threadp->wpool = wpool;
	threadp->id = id;

	ON_ERROR( pthread_create(&threadp->pthread, &attr, (void *)thread_run, threadp),
		"Error creating pthread");
	ON_ERROR( pthread_attr_destroy(&attr), "pthread attr destroy");

	ON_ERROR( pthread_spin_lock(&wpool->stats_lock), "spin lock");
	*threads = threadp;
	wpool->size++;
	ON_ERROR( pthread_spin_unlock(&wpool->stats_lock), "spin unlock");

	return 0;
}

static void thread_free(F_WTHREAD_t *thread)
{
	free(thread);
}

static void* thread_run(F_WTHREAD_t *thread)
{
	F_WPOOL_t *wpool = thread->wpool;
	char name[16];
	intptr_t rc = 0;

	ASSERT(wpool);
	sprintf(name, "w-thread-%d", thread->id);
	ON_ERROR( pthread_setname_np(thread->pthread, name), "setname");

	pthread_spin_lock(&wpool->stats_lock);
	wpool->stats.alive++;
	pthread_spin_unlock(&wpool->stats_lock);

	while (!wpool->shutdown) {
		F_WORK_t *w = NULL;
		F_WTYPE_t cmd;
		F_WPRIO_t p;
		F_WQUEUE_t *q = NULL;
		int ret = 0, signal_all_done;

		pthread_mutex_lock(&wpool->queue_lock);
		while (atomic_read(&wpool->qsize) == 0) {
			pthread_cond_wait(&wpool->queue_cond, &wpool->queue_lock);
		}
		pthread_mutex_unlock(&wpool->queue_lock);

		for (p = F_WP_HIGH; p < F_WP_NR; p++) {
			q = &wpool->queues[p];
			pthread_spin_lock(&q->lock);
			if (list_empty(&q->queue)) {
				pthread_spin_unlock(&q->lock);
				continue;
			}
			w = list_first_entry(&q->queue, F_WORK_t, list);
			list_del_init(&w->list);
			q->size--;
			pthread_spin_unlock(&q->lock);
			atomic_dec(&wpool->qsize);
			break;
		}

		if (!w || p == F_WP_NR) continue;
		ASSERT(q);

		cmd = w->type;
		if (wpool->shutdown)
			goto _free;

		switch (cmd) {
		case F_WT_LOAD:
		case F_WT_VERIFY:
		case F_WT_ENCODE:
		case F_WT_DECODE:
			ret = q->w_fn(cmd, w->params, thread->id);
			if (ret && !rc)
				rc = ret; /* report the first error */
			break;
		default:;
		}

		if (ret == -EAGAIN) {
			/* Requeue the job */
			pthread_spin_lock(&q->lock);
			list_add_tail(&w->list, &q->queue);
			q->size++;
			pthread_spin_unlock(&q->lock);
			atomic_inc(&wpool->qsize);
			continue;
		} 
_free:
		free(w);

		/* signal all works done */
		atomic_dec(&wpool->in_flight);
		atomic_dec(&q->in_flight);
		pthread_mutex_lock(&wpool->w_thread_lock);
		pthread_spin_lock(&wpool->stats_lock);
		signal_all_done = (wpool->stats.job_queued == ++wpool->stats.job_done);
		pthread_spin_unlock(&wpool->stats_lock);
		pthread_mutex_unlock(&wpool->w_thread_lock);
		if (wpool->any_done_only || signal_all_done)
			pthread_cond_signal(&wpool->w_thread_cond);

		if (cmd == F_WT_EXIT)
			break;
	}

	pthread_spin_lock(&wpool->stats_lock);
	wpool->stats.alive--;
	pthread_spin_unlock(&wpool->stats_lock);

	pthread_exit((void*)rc);
}

