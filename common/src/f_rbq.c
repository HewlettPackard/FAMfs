#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h> /* For mode constants */
#include <fcntl.h> /* For O_* constants */ 
#include <string.h>
#include <sched.h>
#include <pthread.h>

#include "f_rbq.h"


int f_rbq_create(char *name, uint64_t esize, uint64_t ecnt, f_rbq_t **qp, int force) {
    int         fd;
    f_rbq_hdr_t *hp;
    size_t      size = (esize + sizeof(uint64_t))*ecnt + sizeof(f_rbq_hdr_t);
    char        sem_name[MAX_RBQ_NAME + 8];
    int         flags = O_RDWR | O_CREAT;

    if (strlen(name) > MAX_RBQ_NAME) {
        errno = EINVAL;
        return -errno;
    }

    if (!force)
        flags |= O_EXCL;

    if (-1 == (fd = shm_open(name, flags, 0777))) 
        return errno == EEXIST && !force ? -EEXIST : -1;

    if (-1 == ftruncate(fd, size))
        return -errno;

    if (NULL == (hp = mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_SHARED, fd, SEEK_SET))) 
        return -errno;

    bzero(hp, size);
    hp->qsize = ecnt;
    hp->esize = esize;
    hp->in = hp->out = 0;
    hp->mapfd = fd;
    if (NULL == (*qp = malloc(sizeof(f_rbq_t)))) {
        errno = ENOMEM;
        return -errno;
    }
    (*qp)->rbq = hp;
    
    snprintf(sem_name, sizeof(sem_name) - 1, "/%s:in", name);
    sem_unlink(sem_name);
    (*qp)->isem = sem_open(sem_name, O_CREAT | O_EXCL, 0666, ecnt);
    if ((*qp)->isem == SEM_FAILED) 
        return -errno;
    snprintf(sem_name, sizeof(sem_name) - 1, "/%s:out", name);
    sem_unlink(sem_name);
    (*qp)->osem = sem_open(sem_name, O_CREAT | O_EXCL, 0666, 0);
    if ((*qp)->osem == SEM_FAILED) 
        return -errno;

    hp->lwm = hp->hwm = -1;
    strcpy(hp->name, name);

    pthread_mutexattr_t mattr;
    pthread_mutexattr_init(&mattr);
    pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&hp->lwmx, &mattr);
    pthread_mutex_init(&hp->hwmx, &mattr);

    pthread_condattr_t cattr;
    pthread_condattr_init(&cattr);
    pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
    pthread_cond_init(&hp->lwmc, &cattr);
    pthread_cond_init(&hp->hwmc, &cattr);
    hp->refc = 1;

    return 0;
}

int f_rbq_open(char *name, f_rbq_t **qp) {
    int         fd;
    f_rbq_hdr_t *hp;
    char        sem_name[MAX_RBQ_NAME + 8];
    size_t      size;
    useconds_t  usec = 1000000;

    while (-1 == (fd = shm_open(name, O_RDWR, 0))) {
        if (errno != ENOENT)
            return -errno;
        usleep(usec);
        usec <<= 1;
        if (usec > 60*1000000)
            return -(errno = ENOENT);
    }

    if (NULL == (hp = mmap(NULL, sizeof(f_rbq_hdr_t), PROT_WRITE | PROT_READ, MAP_SHARED, fd, SEEK_SET))) 
        return -errno;

    size = (hp->esize + sizeof(uint64_t))*hp->qsize + sizeof(f_rbq_hdr_t);
    munmap(hp, sizeof(f_rbq_hdr_t));
    if (NULL == (hp = mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_SHARED, fd, SEEK_SET)))
        return -errno;

    if (NULL == (*qp = malloc(sizeof(f_rbq_t)))) {
        errno = ENOMEM;
        return -errno;
    }

    (*qp)->rbq = hp;
    snprintf(sem_name, sizeof(sem_name) - 1, "/%s:in", name);
    (*qp)->isem = sem_open(sem_name, 0);
    if ((*qp)->isem == SEM_FAILED)
        return -errno;
    snprintf(sem_name, sizeof(sem_name) - 1, "/%s:out", name);
    (*qp)->osem = sem_open(sem_name, 0);
    if ((*qp)->osem == SEM_FAILED)
        return -errno;

    __sync_fetch_and_add(&hp->refc, 1);
    return 0;
}

int f_rbq_close(f_rbq_t *q) {
    size_t size = (q->rbq->esize + sizeof(uint64_t))*q->rbq->qsize + sizeof(f_rbq_hdr_t);

    __sync_fetch_and_sub(&q->rbq->refc, 1);

    munmap(q->rbq, size);
    sem_close(q->isem);
    sem_close(q->osem);
    free(q);
    
    return 0;
}

int f_rbq_destroy(f_rbq_t *q) {
    char sem_name[MAX_RBQ_NAME + 8], name[MAX_RBQ_NAME];

    if (q->rbq->refc > 1)
        return -EAGAIN;

    strcpy(name, q->rbq->name);
    pthread_cond_destroy(&q->rbq->lwmc);
    pthread_cond_destroy(&q->rbq->hwmc);
    pthread_mutex_destroy(&q->rbq->lwmx);
    pthread_mutex_destroy(&q->rbq->lwmx);
    f_rbq_close(q);

    snprintf(sem_name, sizeof(sem_name) - 1, "/%s:in", name);
    sem_unlink(sem_name);
    snprintf(sem_name, sizeof(sem_name) - 1, "/%s:out", name);
    sem_unlink(sem_name);
    shm_unlink(name);

    return 0;
}

int f_rbq_push(f_rbq_t *q, void *e, long wait) {
    if (!wait) {
        if (-1 == sem_trywait(q->isem)) 
            return -errno;
    } else {
        if (wait == -1) {
            if (-1 == sem_wait(q->isem))
                return -errno;
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += (ts.tv_nsec + wait*1000L)/1000000000L;
            ts.tv_nsec = (ts.tv_nsec + wait*1000L)%1000000000L;
            if (-1 == sem_timedwait(q->isem, &ts)) 
                return -errno;
        }
    }
    uint64_t ix = __sync_fetch_and_add(&q->rbq->in, 1)%q->rbq->qsize;
    char *p = (char *)q->rbq + sizeof(f_rbq_hdr_t) + ix*(q->rbq->esize + sizeof(uint64_t));
    *(uint64_t *)p = 0UL;
    memcpy(p + sizeof(uint64_t), e, q->rbq->esize);

    asm volatile("" ::: "memory");

    *(uint64_t *)p = 1UL;
    int pre_post;
    sem_getvalue(q->osem, &pre_post);
    if (-1 == sem_post(q->osem))
        return -errno;
    if (q->rbq->hwm > 0 && f_rbq_count(q) >= q->rbq->hwm && pre_post < q->rbq->hwm)
        pthread_cond_broadcast(&q->rbq->hwmc);
    return 0;
} 

int f_rbq_pop(f_rbq_t *q, void *e, long wait) {
    if (!wait) {
        if (-1 == sem_trywait(q->osem)) 
            return -errno;
    } else {
        if (wait == -1) {
            if (-1 == sem_wait(q->osem))
                return -errno;
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += (ts.tv_nsec + wait*1000L)/1000000000L;
            ts.tv_nsec = (ts.tv_nsec + wait*1000L)%1000000000L;
            if (-1 == sem_timedwait(q->osem, &ts)) 
                return -errno;
        }
    }
    uint64_t ix = __sync_fetch_and_add(&q->rbq->out, 1)%q->rbq->qsize;
    char *p = (char *)q->rbq + sizeof(f_rbq_hdr_t) + ix*(q->rbq->esize + sizeof(uint64_t));
    while (!*(uint64_t *)p)
        sched_yield();

    *(uint64_t *)p = 0UL;
    memcpy(e, p + sizeof(uint64_t), q->rbq->esize);

    *(uint64_t *)p = 1UL;
    int pre_post;
    sem_getvalue(q->isem, &pre_post);
    if (-1 == sem_post(q->isem))
        return -errno;
    if (q->rbq->lwm > 0 && f_rbq_count(q) <= q->rbq->lwm && pre_post > q->rbq->lwm) 
        pthread_cond_broadcast(&q->rbq->lwmc);

    return 0;
}

int f_rbq_waitlwm(f_rbq_t *q, long tmo) {
    struct timespec ts;
    int s;

    if (q->rbq->lwm == -1)
        return -EINVAL;
    else if (!q->rbq->lwm || f_rbq_count(q) <= q->rbq->lwm)
        return 0;

    if (!tmo) 
        return -ETIMEDOUT;

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += (ts.tv_nsec + (unsigned long)tmo*1000L)/1000000000L;
    ts.tv_nsec = (ts.tv_nsec + (unsigned long)tmo*1000L)%1000000000L;
    if ((s = pthread_mutex_lock(&q->rbq->lwmx)))
        return -s;
    if ((s = pthread_cond_timedwait(&q->rbq->lwmc, &q->rbq->lwmx, &ts))) {
        pthread_mutex_unlock(&q->rbq->lwmx);
        return -s;
    }
    pthread_mutex_unlock(&q->rbq->lwmx);

    // check for alarm signal/WM reset
    if (!q->rbq->lwm || f_rbq_count(q) > q->rbq->lwm)
        return -ECANCELED;

    return 0;
}

int f_rbq_waithwm(f_rbq_t *q, long tmo) { 
    struct timespec ts;
    int s;

    if (q->rbq->hwm == -1)
        return -EINVAL;
    else if (!q->rbq->hwm || f_rbq_count(q) >= q->rbq->hwm)
        return 0;

    if (!tmo) 
        return -ETIMEDOUT;

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += (ts.tv_nsec + (unsigned long)tmo*1000L)/1000000000L;
    ts.tv_nsec = (ts.tv_nsec + (unsigned long)tmo*1000L)%1000000000L;
    if ((s = pthread_mutex_lock(&q->rbq->hwmx)))
        return -s;
    if ((s = pthread_cond_timedwait(&q->rbq->hwmc, &q->rbq->hwmx, &ts))) {
        pthread_mutex_unlock(&q->rbq->hwmx);
        return -s;
    }
    pthread_mutex_unlock(&q->rbq->hwmx);

    // check for alarm signal/WM reset
    if (!q->rbq->hwm || f_rbq_count(q) < q->rbq->hwm)
        return -ECANCELED;
    
    return 0;
}

#ifdef __F_RBQ_MAIN__

struct {
    int     code;
    union {
        struct {
            int     x;
            int     y;
        };
        struct {
            int     a;
            int     b;
        };
    };
} CMD;

int main(int argc, char *argv[]) {
    struct sigaction sa;
    struct timespec ts;
    int s;
    f_rbq_t *myq;
    char    ibuf[8] = {'a','b','c','d','e','f','g','h'};
    char    obuf[9];
    struct  {
        char    pfx[4];
        int     id;
    }       data = {{0, 0, 0, 0}, 0};
    int in, out, tmo, N;


    CMD.x=1;
    CMD.b=2;
    printf("s=%lu x=%d y=%d a=%d b=%d\n", sizeof(CMD), CMD.x, CMD.y, CMD.a, CMD.b);

    if (argc == 4) {
        tmo = atoi(argv[2])*1000000L;
        N = atoi(argv[3]);

        if (argv[1][0] == 'P') {

            if (f_rbq_open("cmd", &myq)) {
                printf("*** rbq open %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }
            printf("Producer opened cmd: %lu[%d] in=%d\n", myq->rbq->esize, f_rbq_size(myq), f_rbq_count(myq));

            strncpy(data.pfx, &argv[1][1], 3);
            for (int j = 0; j < N; j++) {
                data.id = j;
                if ((s = f_rbq_push(myq, &data, tmo))) {
                    printf("*** push %d %s\n", s, strerror(-s));
                    exit(EXIT_FAILURE);
                }
                printf("push %c[%d]\n", argv[1][1], j);
                if (f_rbq_count(myq) > 24) {
                    printf("sleep on LW\n");
                    if (s = f_rbq_waitlwm(myq, tmo))
                        printf("wait %s\n", strerror(-s));
                    else
                        printf("GOT UP\n");
                }
            }

            f_rbq_close(myq);
            exit(0);
        }
    } else {
        fprintf(stderr, "Usage: %s (C[onsumer]1|0)|(P[roducer]<ID>) <tmo (sec)> <cnt>\n", argv[0]);
        exit(EXIT_FAILURE);
    }


    int f = atoi(&argv[1][1]);
    if (!f)
        usleep(500000);
    if (s = f_rbq_create("cmd", sizeof(data), 32, &myq, f)) {
        if (s != -EEXIST) {
            printf("*** rbq create %s\n", strerror(-s));
            exit(EXIT_FAILURE);
        } else if (s = f_rbq_open("cmd", &myq)) {
            printf("*** rbq open %s\n", strerror(-s));
            exit(EXIT_FAILURE);
        }
        printf("Consumer opened cmd: %lu[%d] in=%d\n", myq->rbq->esize, f_rbq_size(myq), f_rbq_count(myq));
    } else {
        printf("Consumer created cmd\n");
        //f_rbq_setlwm(myq, 4);
        //f_rbq_sethwm(myq, 24);
    }

    printf("waiting for queue\n");
    //s = f_rbq_waithwm(myq, tmo);
    //printf("%s\n", strerror(s));


    obuf[8] = 0;
    for (int j = 0; j < N; j++) {
        //if (s = f_rbq_pop(myq, &data, tmo)) {
        if (s = f_rbq_pop(myq, &data, -1)) {
            if (s == -ETIMEDOUT) {
                printf("TMO\n");
                break;
            }
            printf("pop %d %s\n", s, strerror(-s));
            exit(EXIT_FAILURE);
        }
        printf("%c[%d]\n", data.pfx[0], data.id);
        usleep(50000);
    }

    if (f) {
        if (!f_rbq_isempty(myq))
            printf("cmd not empty:%d\n", f_rbq_count(myq));
        usleep(tmo);
        while (!f_rbq_isempty(myq)) {
            if ((s = f_rbq_pop(myq, &data, 0))) {
                if (s != -EAGAIN) {
                    printf("*** pop %d %s\n", s, strerror(-s));
                    exit(EXIT_FAILURE);
                } else {
                    printf("cmd empty\n");
                    break;
                }
            }
            printf("cleanup %c[%d]\n", data.pfx[0], data.id);
        }
        f_rbq_destroy(myq);
    } else
        f_rbq_close(myq);

    exit(0);
}
#endif
