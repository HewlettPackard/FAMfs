#ifndef F_RBQ_H
#define F_RBQ_H

#define MAX_RBQ_NAME 32
#include <semaphore.h>

typedef struct {
    char                name[MAX_RBQ_NAME];
    uint64_t            in;
    uint64_t            out;
    uint64_t            qsize;
    uint64_t            esize;
    uint64_t            refc;
    pthread_mutex_t     lwmx;
    pthread_cond_t      lwmc;
    pthread_mutex_t     hwmx;
    pthread_cond_t      hwmc;
    int                 lwm;
    int                 hwm;
    int                 mapfd;
    int                 fill;
    char                a[0];
} f_rbq_hdr_t;

typedef struct {
    f_rbq_hdr_t     *rbq;
    sem_t           *isem;
    sem_t           *osem;
} f_rbq_t;

#define RBQ_TMO_4EVER -1L
#define RBQ_TMO_1S    1000000L
#define RBQ_TMO_1M    (60*RBQ_TMO_1S)
#define RBQ_NOWAIT    0

//
// Create ring buffer queue
//  name:   ring buffer global name
//  esize:  element size
//  ecnt:   number of slots in the buffer
//  qp:     address of a pointer to queue handle
//  flag:   if != 0 will force queue creation, destroying old structures if they exist
// Return:
//   0     - Success and qp points to the newly created queue
//  -errno - Check errno
int f_rbq_create(char *name, uint64_t esize, uint64_t ecnt, f_rbq_t **qp, int force);

//
// Open (presumably) existing queue
//  name:   name of the buffer queue
//  qp:     address of a pointer to the queue handle
// Return:
//  0       - Success
// -errno   - Check errno
//
int f_rbq_open(char *name, f_rbq_t **qp);

//
// Close rbq and free local memory resources
//
int f_rbq_close(f_rbq_t *q);

//
// Destroy both local and global memory structures, associated with this rbq
// If shared memory is still busy, it will be marked for deletion
//
int f_rbq_destroy(f_rbq_t *q); 

//
// Push an element onto the queue
//  q:      queue handle
//  e:      element to push
//  wait:   -1: wait forever, 0 - try to push, >0 sleep on full condition until timeout (in usec)
// Return:
//  0          - Success
//  -EAGAIN    - Queue is full and wait == 0
//  -ETIMEDOUT - Timeout waiting on queue not full condition
//  -errno     - check errno
int f_rbq_push(f_rbq_t *q, void *e, long wait);

//
// Pop an element from the queue
//  q:      queue handle
//  e:      element to push
//  wait:   -1: wait forever, 0 - try to pop, >0 sleep on empty condition until timeout (in usec)
// Return:
//  0          - Success
//  -EAGAIN    - Queue is empty and wait == 0
//  -ECANCELED - Somebody reset water marks
//  -ETIMEDOUT - Timeout waiting on queue not empty condition
//  -errno     - check errno
int f_rbq_pop(f_rbq_t *q, void *e, long wait);

//
// Sleep until low water mark is reached
// (LWM is define as "queue contains less or equal to LWM elements)
//  q:      queue handle
//  tmo:    timeout in usec
// Return:
//  0          - Success (low water mark reached)
//  -ETIMEDOUT - Timed out waiting
//  -ECANCELED - Somebody removed low water mark or signaled reset
//  -errno     - Check errno
int f_rbq_waitlwm(f_rbq_t *q, long tmo);

//
// Sleep until high water mark is reached
// (HWM is define as "queue contains more or equal to HWM elements)
//  q:      queue handle
//  tmo:    timeout in usec
// Return:
//  0          - Success (low water mark reached)
//  -ETIMEDOUT - Timed out waiting
//  -ECANCELED - Somebody removed high water mark or signaled reset
//  -errno     - Check errno
int f_rbq_waithwm(f_rbq_t *q, long tmo); 

//
// Returns queu size, i.e. number of slots in the ring buffer
//
static inline int f_rbq_size(f_rbq_t *q) {
    return q->rbq->qsize;
}

//
// Returns current number of occupied slots
//
static inline int f_rbq_count(f_rbq_t *q) {
    int v;
    sem_getvalue(q->osem, &v);
    return v;
}

//
// Returns 1 if queue is emptyl, 0 otherwise
//
static inline int f_rbq_isempty(f_rbq_t *q) {
    return f_rbq_count(q) == 0;
}

// Returns 1 if queue is full, 0 otherwise
static inline int f_rbq_isfull(f_rbq_t *q) {
    return f_rbq_count(q) == f_rbq_size(q);
}

// wake any and all threads slumbering on water mark wait
static inline void f_rbq_wakewm(f_rbq_t *q) {
    pthread_cond_broadcast(&q->rbq->lwmc);
    pthread_cond_broadcast(&q->rbq->hwmc);
}

//
// Set low water mark
//
static inline void f_rbq_setlwm(f_rbq_t *q, int low_water) {
    q->rbq->lwm = low_water;
    pthread_cond_broadcast(&q->rbq->lwmc);
}

//
// Set high water mark
//
static inline void f_rbq_sethwm(f_rbq_t *q, int high_water) {
    q->rbq->hwm = high_water;
    pthread_cond_broadcast(&q->rbq->hwmc);
}

//
// Reset both watermarks, signal to all waiting threads
//
static inline void f_rbq_resetwm(f_rbq_t *q) {
    f_rbq_setlwm(q, 0);
    f_rbq_sethwm(q, 0);
    f_rbq_wakewm(q);
}

static inline int f_rbq_getlwm(f_rbq_t *q) {
    return q->rbq->lwm;
}

static inline int f_rbq_gethwm(f_rbq_t *q) {
    return q->rbq->hwm;
}


#endif
