/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef EC_PERF_H
#define EC_PERF_H

#include <sys/time.h>

#define CHUNK(m)    ((1024*m))
#define MMAX        64
#define PMAX        8
#define KMAX        (MMAX - PMAX)
#define WMAX        128

#define max(a,b)			\
    ({	__typeof__ (a) _a = (a);	\
	__typeof__ (b) _b = (b);	\
	_a > _b ? _a : _b; })	
#define min(a,b)			\
    ({	__typeof__ (a) _a = (a);	\
	__typeof__ (b) _b = (b);	\
	_a < _b ? _a : _b; })	
#define abs(a) (a < 0) ? (-a) : (a)

#define FORCE_RAID  256
#define HW_MASK     0xff

#define KiB (1024L)
#define MiB (KiB*1024L)
#define GiB (MiB*1024L)
#define TiB (GiB*1024L)

#define mSec (1000L)
#define uSec (mSec*1000L)

typedef unsigned char u8;
typedef unsigned long long int u64;

struct run_arg {
    int             s;
    int             k;
    int             p;
    int             n;
    int             hw;
    int             en;
    int             in;
    u8              *ev;
    pthread_mutex_t lock;
    pthread_cond_t  go;
    int             ready;
};

struct wrk_ctl {
    pthread_t       id;
    int             ix;
    double          enc_bw;
    double          dec_bw;
    pthread_attr_t  attr;
    struct run_arg  *par;
};

struct perf {
	struct timeval  start;
	struct timeval  stop;
        u64             elapsed;
        u64             data;
};

static inline void perf_init(struct perf *p) {
    p->elapsed = 0;
    p->data = 0;
}

static inline u64 perf_start(struct perf *p) {
	gettimeofday(&(p->start), 0);
        return (p->start.tv_sec*uSec + p->start.tv_usec);
}

static inline u64 perf_stop(struct perf *p) {
	gettimeofday(&(p->stop), 0);
        return (p->stop.tv_sec*uSec + p->stop.tv_usec);
}

static inline u64 perf_add(struct perf *p, u64 dsize) {
    p->elapsed += perf_stop(p) - (p->start.tv_sec*uSec + p->start.tv_usec);
    p->data += dsize;
    return p->elapsed;
}

static inline double perf_get_bw(struct perf *p, u64 tu, u64 bu) {
    return ((double)p->data/bu)/((double)p->elapsed/tu);
}

static inline double perf_bw(struct perf *p, long long dsize){
    u64 secs = p->stop.tv_sec - p->start.tv_sec;
    u64 usecs = secs * 1000000 + p->stop.tv_usec - p->start.tv_usec;
    double sec = ((double)usecs)/1000000.0;
    double mb = (double)dsize;

    return mb/sec;
}


#define vprintf(l, ...) if (VERBOSE >= l) printf(__VA_ARGS__)
#define dprintf(...) vprintf(3, __VA_ARGS__)

u8 *make_encode_matrix(int k, int p, u8 **pa);
u8 *make_decode_matrix(int k, int n, u8 *eix, u8 *a);
void encode_data(int how, int len, int ndata, int npar, u8 *enc_tbl, u8 **data, u8 **par);
void decode_data(int how, int len, int ndata, int nerr, u8 *dec_tbl, u8 **data, u8 **rst);

#endif
