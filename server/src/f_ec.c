/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
*/

#ifdef MAKE_MAIN
#define _GNU_SOURCE
#include <numa.h>
#include <sched.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include "erasure_code.h"
#include "raid.h"

#include "f_env.h"
#include "f_stats.h"
#include "f_ec.h"

#ifndef MMAX
#define MMAX        64
#define PMAX        8
#define KMAX        (MMAX - PMAX)
#define WMAX        128
#endif

//#define MAKE_MAIN
#ifdef MAKE_MAIN
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

#endif /* ifdef MAKE_MAIN */

static void print_a(u8 *a, int cols, int rows, char *h) {
    char s[1024];

    int l = sprintf(s, "*** %s[%d,%d]:\n", h, cols, rows);
    for (int i = 0; i < rows; i ++) {
        for (int j = 0; j < cols; j++) {
            l += sprintf(&s[l], "%02x,", a[i*cols + j]);
        }
        printf("%s\n", s);
        l = 0;
    }
}

u8 *prep_encode(int k, int p, u8 **pcauchy) {
    u8 *gf_tbl, *cauchy;
    int m = k + p;

    if (!(gf_tbl = malloc(k*p*32))) return NULL;
    bzero(gf_tbl, k*p*32);

    if (!(cauchy = malloc(m*k))) return NULL;
    bzero(cauchy, m*k);

    // Pick an encode matrix. A Cauchy matrix is a good choice as even
    // large k are always invertable keeping the recovery rule simple.
    gf_gen_cauchy1_matrix(cauchy, m, k);

    // Init gf tables from cauchy matrix
    ec_init_tables(k, p, &cauchy[k*k], gf_tbl);

    *pcauchy = cauchy;
    return gf_tbl;

}

int prep_decode(int k, int m, int nerr, u8 *elist, u8 *enc, u8* gf_tbl, u8 *dvec) {
    int i, j, p, r;
    int nsrcerr = 0;
    u8 s, tmp[m*k], inv[m*k], dec[m*k];
    u8 chnk_ev[MMAX];

    bzero(chnk_ev, MMAX);
    bzero(tmp, m*k);
    bzero(inv, m*k);
    bzero(dec, m*k);

    // Order the fragments in erasure for easier sorting
    for (i = 0; i < nerr; i++) {
        if (elist[i] < k)
            nsrcerr++;
        chnk_ev[elist[i]] = 1;
    }

    // Construct tmp (matrix that encoded remaining frags) by removing erased rows
    for (i = 0, r = 0; i < k; i++, r++) {
        while (chnk_ev[r])
            r++;
        for (j = 0; j < k; j++)
            tmp[k*i + j] = enc[k*r + j];
        if (dvec != NULL) 
            dvec[i] = r;
    }

    // Invert matrix to get recovery matrix
    if (gf_invert_matrix(tmp, inv, k) < 0)
        return -1;

    // Get decode matrix with only wanted recovery rows
    for (i = 0; i < nerr; i++) {
        if (elist[i] < k)	// A src err
            for (j = 0; j < k; j++)
                dec[k*i + j] = inv[k*elist[i] + j];
    }

    // For non-src (parity) erasures need to multiply encode matrix * invert
    for (p = 0; p < nerr; p++) {
        if (elist[p] >= k) {	// A parity err
            for (i = 0; i < k; i++) {
                s = 0;
                for (j = 0; j < k; j++)
                    s ^= gf_mul(inv[j*k + i], enc[k*elist[p] + j]);
                dec[k*p + i] = s;
            }
        }
    }
    ec_init_tables(k, nerr, dec, gf_tbl);

    return 0;

}

u8 *make_encode_matrix(int k, int p, u8 **pa) {
    u8 *ecm, *a;
    int m = k + p;

    if (!(ecm = malloc(k*m*32)))
        return NULL;
    bzero(ecm, k*m*32);

    if (!(a = malloc(KMAX*MMAX)))
        return 0;
    bzero(a, KMAX*MMAX);

    // Generate R-S codes matrix accoridng to chosen geometry
    gf_gen_rs_matrix(a, m, k);

    // Generate encode matrix
    ec_init_tables(k, p, &a[k*k], ecm);

    *pa = a;
    return ecm;
}

u8 *make_decode_matrix(int k, int n, u8 *eix, u8 *a) {
    u8 ev[k], b[MMAX*KMAX], c[MMAX*KMAX], d[MMAX*KMAX];
    u8 *dcm;
    int i, j, r;

    bzero(b, sizeof(b));
    bzero(c, sizeof(c));
    bzero(d, sizeof(d));

    if (!(dcm = malloc(k*(k + n)*32)))
        return NULL;

    memset(ev, 0, sizeof(ev));
    for (i = 0; i < n; i++) 
        ev[eix[i]] = 1;

    // Construct b by removing error rows
    for (i = 0, r = 0; i < k; i++, r++) {
        while (r < k && ev[r])
            r++;
        for (j = 0; j < k; j++)
            b[k*i + j] = a[k*r + j];
    }
    // Invert b -> d
    if (gf_invert_matrix(b, d, k) < 0) {
        print_a(b, k, k + n, "Ooops a");
        return 0;
    }

    // Construct c
    for (i = 0; i < n; i++)
        for (j = 0; j < k; j++)
            c[k*i + j] = d[k*eix[i] + j];

    // Generate decode matrix
    ec_init_tables(k, n, c, dcm);

    return dcm;
}

void encode_data(int how, int len, int ndata, int npar, u8 *enc_tbl, u8 **data, u8 **par) {
    int raid = how & ION_FORCE_RAID;
    int hw = how & ION_HW_MASK;

    if (!raid || npar > 2) {
        if (hw == 0)
            ec_encode_data_base(len, ndata, npar, enc_tbl, data, par);
        else if (hw == 1)
            ec_encode_data_sse(len, ndata, npar, enc_tbl, data, par);
        else if (hw == 2)
            ec_encode_data_avx(len, ndata, npar, enc_tbl, data, par);
        else if (hw == 3)
            ec_encode_data_avx2(len, ndata, npar, enc_tbl, data, par);
        else
            ec_encode_data(len, ndata, npar, enc_tbl, data, par);
    } else {
        // Special case for RAID-5 or RAID-6
        int  i;
        u8 *dp[ndata + npar];

        for (i = 0; i < ndata; i++)
            dp[i] = data[i];
        for ( ; i < ndata + npar; i++)
            dp[i] = par[i - ndata];

        if (npar == 1) {
            if (hw == 0)
                xor_gen_base(ndata + 1, len, (void **)dp);
            else if (hw == 1)
                xor_gen_sse(ndata + 1, len, (void **)dp);
            else if (hw == 2 || hw == 3)
                xor_gen_avx(ndata + 1, len, (void **)dp);
            else
                xor_gen(ndata + 1, len, (void **)dp);
        } else {
            if (hw == 0)
                pq_gen_base(ndata + 2, len, (void **)dp);
            else if (hw == 1)
                pq_gen_sse(ndata + 2, len, (void **)dp);
            else if (hw == 2)
                pq_gen_avx(ndata + 2, len, (void **)dp);
            else if (hw == 3)
                pq_gen_avx2(ndata + 2, len, (void **)dp);
            else
                pq_gen(ndata + 2, len, (void **)dp);
        }
    }
}

void decode_data(int how, int len, int ndata, int nerr, u8 *dec_tbl, u8 **data, u8 **rst) {
    int raid = how & ION_FORCE_RAID;
    int hw = how & ION_HW_MASK;

    // Recover data
    if (!raid || nerr > 1) {
        if (hw == 0)
            ec_encode_data_base(len, ndata, nerr, dec_tbl, data, rst);
        else if (hw == 1)
            ec_encode_data_sse (len, ndata, nerr, dec_tbl, data, rst);
        else if (hw == 2)
            ec_encode_data_avx (len, ndata, nerr, dec_tbl, data, rst);
        else if (hw == 3)
            ec_encode_data_avx2(len, ndata, nerr, dec_tbl, data, rst);
        else
            ec_encode_data(len, ndata, nerr, dec_tbl, data, rst);
    } else {
        // Special case for RAID-5 or RAID-6 with just one err
        u8 *dp[ndata + 1];
        int i;

        for (i = 0; i < ndata; i++)
           dp[i] = data[i];
        dp[ndata] = rst[0];

        if (hw == 0)
            xor_gen_base(ndata + 1, len, (void **)dp);
        else if (hw == 1)
            xor_gen_sse(ndata + 1, len, (void **)dp);
        else if (hw == 2 || hw == 3)
            xor_gen_avx(ndata + 1, len, (void **)dp);
        else
            xor_gen(ndata + 1, len, (void **)dp);
    }

}

#ifdef MAKE_MAIN

#define vprintf(l, ...) if (VERBOSE >= l) printf(__VA_ARGS__)
#define dprintf(...) vprintf(3, __VA_ARGS__)


int EXCEL = 0;
int RAID = 0;
int VERBOSE = 0;
int CAUCHY = 0;

u8 *ec_tbl, *dc_tbl, *a, *cauchy;
u8 src_err_ix[MMAX], src_err_list[MMAX];

static inline double ec_perf_bw(struct ec_perf *p, long long dsize) {
    ec_perf_stop(p);
    u64 secs = p->stop.tv_sec - p->start.tv_sec;
    u64 usecs = secs*1000000 + p->stop.tv_nsec/1000L - p->start.tv_nsec/1000L;
    double sec = ((double)usecs)/1000000.0;
    double mb = (double)dsize;

    return mb/sec;
}

int usage(void) {
    printf( "Usage: ec_perf [-v w<thrd> -a<isa> -k<data> -p<parity> -l<size> {-e<err>} -s{size}] [seed]\n"
        "  -h        Help\n"
        "  -v        Chatty, repeat for more\n"
        "  -r        Force RAID algo on 1P and 2P geometries\n"
        "  -x        Generate Excel-ready output (HT separated)\n"
        "  -w <val>  Start val threads in parallel (>0, <=64, =1)\n"
        "  -a <val>  Arcitechture: 0(basic), 1(sse), 2(avx), 3(avx2), 4(avx512), =255(auto)\n"
        "  -k <val>  Number of source chunks (>2, <63, =10)\n"
        "  -p <val>  Number of parity chunks (>=1, <=16, =4)\n"
        "  -l <val>  Chunk size, K/M suffixes accepted (>=64, <=16M, =1K)\n"
        "  -s <val>  Slab size, K/M/G suffixes accepted (>=k*s, =1G)\n"
        "  -i <val>  Average BW of val iterations (=1)\n"
        "  -e <val>  Force err on chunk index val, 0-based, can be repeated (=c[0]...c[p-1])\n"
        "  -C        Use Cauchy matrix\n");
    exit(0);
}

void *worker(void *you) {
    struct wrk_ctl *me = you;
    int i, j, rtest = 0, m, k, nerrs, r, p, s, hw, str_cnt, ii, iter = 0;
    void *buf;
    u8 *temp_buffs[MMAX], *buffs[MMAX], *dmem[MMAX], *tmem[MMAX], *recov[MMAX];
    struct ec_perf stat;

    k = me->par->k;
    p = me->par->p;
    s = me->par->s;
    hw = me->par->hw;
    nerrs = me->par->en;
    str_cnt = me->par->n;
    m = k + p;

    // Allocate data memory
    for (i = 0; i < m; i++) {
        if (posix_memalign(&buf, 64, s*str_cnt)) {
            printf("alloc error: Fail\n");
            return 0;
        }
        dmem[i] = buf;
    }
    // Allocate parity memory
    for (i = 0; i < p; i++) {
        if (posix_memalign(&buf, 64, s*str_cnt)) {
            printf("alloc error: Fail\n");
            return 0;
        }
        tmem[i] = buf;
        memset(buf, 0, s*str_cnt);
    }

    // Make (somewhat) random data
    for (i = 0; i < k; i++) {
        int rr = rand();
        for (j = 0; j < s*str_cnt; j += sizeof(u64)) {
            u64 *ptr = (u64*)&dmem[i][j];
            *ptr = (((u64)rr)<<(i%32)) + j;
        }
    }

    // Wait for a go
    pthread_mutex_lock(&me->par->lock);
    me->par->ready++;
    pthread_cond_wait(&me->par->go, &me->par->lock);
    pthread_mutex_unlock(&me->par->lock);

    // Start encode test
    ec_perf_start(&stat);
    for (iter = 0; iter < me->par->in; iter++) {
        for (rtest = 0; rtest < str_cnt; rtest++) {
            // Assign work buffers
            for (ii = 0; ii < m; ii++)
                buffs[ii] = dmem[ii] + rtest*s;

            encode_data(hw, s, k, p, ec_tbl, buffs, &buffs[k]);
        }
    }
    me->enc_bw = ec_perf_bw(&stat, (long long)s*m*rtest*iter);

    // Start decode test
    u8 dve[m];
    bzero(dve, m);
    ec_perf_start(&stat);
    if (CAUCHY) {
        if (prep_decode(k, m, nerrs, src_err_list, cauchy, dc_tbl, dve)) {
            printf("prep_decode failed\n");
            exit(1);
        } 
    }
    for (iter = 0; iter < me->par->in; iter++) {
        for (rtest = 0; rtest < str_cnt; rtest++) {
            // Assign input buffers
            for (ii = 0; ii < m; ii++)
                buffs[ii] = dmem[ii] + rtest*s;
            // Assign output buffers
            for (ii = 0; ii < nerrs; ii++)
                temp_buffs[ii] = tmem[ii] + rtest*s;

            if (!CAUCHY) {
                // Assign error recovery input buffer pointers
                for (i = 0, r = 0; i < k; i++, r++) {
                    while (src_err_ix[r])
                        r++;
                    recov[i] = buffs[r];
                }
                decode_data(hw, s, k, nerrs, dc_tbl, recov, temp_buffs);
            } else {
                for (i = 0; i < k; i++)
                    recov[i] = buffs[dve[i]];

                decode_data(hw, s, k, nerrs, dc_tbl, recov, temp_buffs);
            }


        }
    }
    me->dec_bw = ec_perf_bw(&stat, (long long)s*(k + nerrs)*rtest*iter);

    if (!CAUCHY) {
        for (rtest = 0; rtest < str_cnt; rtest++) {
            // Assign work buffers
            for (ii = 0; ii < m; ii++)
                buffs[ii] = dmem[ii] + rtest*s;
            for (ii = 0; ii < nerrs; ii++)
                temp_buffs[ii] = tmem[ii] + rtest*s;

            for (i = 0; i < nerrs; i++) {
                if (0 != memcmp(temp_buffs[i], buffs[src_err_list[i]], s)) {
                    printf("Fail error recovery (%d, %d, %d) @%d ", m, k, nerrs, rtest);
                    return 0;
                }
            }
        }
    } else {
        printf("check recovery of buffer {");
        for (i = 0; i < nerrs; i++) {
            printf(" %d", src_err_list[i]); 
            if (memcmp(temp_buffs[i], buffs[src_err_list[i]], s)) {
                printf(" Fail erasure recovery %d, frag %d\n", i, src_err_list[i]);
                return me;
            }
        }
        printf(" }\n");
    }

    return me;
}

int main(int argc, char *argv[]) {
    int i, m, k, nerrs, e, s = 1024, hw = 255, str_cnt, wcnt = 1, p, niter = 1;
    u8 err_list[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    char opt;
    struct run_arg args;
    struct wrk_ctl wrk[WMAX];
    double enc_bw = 0.0, dec_bw = 0.0;
    double enc_bw_max = 0.0, enc_bw_min = 1.0e20;
    double dec_bw_max = 0.0, dec_bw_min = 1.0e20;
    cpu_set_t cpum;
    u64  slab_sz = 1024*1024*1024L;
    char *sfx;

    // Pick test parameters
    k = 10;
    p = 4;
    nerrs = 0;

    while ((opt = getopt(argc, argv, "s:a:k:p:l:e:w:i:rhxvC")) != -1) {
        switch (opt) {
        case 'k':
            k = atoi(optarg);
            if (k > KMAX || k < 2)
                usage();
            break;
        case 'p':
            p = atoi(optarg);
            if (p < 1 || p > 16)
                usage();
            break;
        case 'l':
            s = strtol(optarg,  &sfx, 10);
            if (*sfx == 'K' || *sfx == 'k')
                s *= 1024;
            else if (*sfx == 'M' || *sfx == 'm')
                s *= 1024*1024;

            if (s <= 0 || s > 16*1024*1024)
                usage();
            break;
        case 'e':
            e = atoi(optarg);
            err_list[nerrs++] = e;
            if (nerrs > 16)
                usage();
            break;
        case 'a':
            hw = atoi(optarg);
            if (hw > 4 || hw < 0)
                hw = 255;
            break;
        case 'w':
            wcnt = atoi(optarg);
            if (wcnt < 1 || wcnt > 64)
                usage();
            break;
        case 'i':
            niter = atoi(optarg);
            if (niter < 1)
                usage();
            break;
        case 's':
            slab_sz = strtol(optarg,  &sfx, 10);
            if (*sfx == 'K' || *sfx == 'k')
                slab_sz *= 1024;
            else if (*sfx == 'M' || *sfx == 'm')
                slab_sz *= 1024*1024;
            else if (*sfx == 'G' || *sfx == 'g')
                slab_sz *= 1024*1024*1024L;
            if (!slab_sz)
                slab_sz = 1024*1024*1024L;
            break;
        case 'r':
            RAID++;
            break;
        case 'x':
            EXCEL++;
            break;
        case 'v':
            VERBOSE++;
            break;
        case 'C':
            CAUCHY++;
            break;
        case 'h':
        default:
            usage();
            break;
        }
    }
    m = k + p;
    if (!nerrs)
        nerrs = p;
    if (p > 2)
        RAID = 0;
    if (slab_sz < s*k) {
        printf("Slab size too small\n");
        usage();
    }
    str_cnt = slab_sz/(s*k);
    if (m > MMAX || k > KMAX || nerrs > p) {
        printf("Input test parameter error\n");
        usage();
    }
    if (argc > optind)
        srand(atoi(argv[optind]));

    if (RAID && p <= 2)
        hw |= ION_FORCE_RAID;


    args.k = k;
    args.p = p;
    args.s = s;
    args.hw = hw;
    args.in = niter;
    args.en = nerrs;
    args.ev = src_err_list;
    args.n  = str_cnt;
    pthread_mutex_init(&args.lock, NULL);
    pthread_cond_init(&args.go, NULL);
    args.ready = 0;


    for (i = 0; i < wcnt; i++) {
        pthread_attr_init(&wrk[i].attr);
        CPU_ZERO(&cpum);
        CPU_SET(i, &cpum);
        pthread_attr_setaffinity_np(&wrk[i].attr, sizeof(cpum), &cpum);
        wrk[i].par = &args;
        wrk[i].ix = i;
        if (pthread_create(&wrk[i].id, &wrk[i].attr, worker, &wrk[i])) {
            printf("Can't create wrk thread %d\n", i);
            exit(1);
        }
    }

    memcpy(src_err_list, err_list, nerrs);
    memset(src_err_ix, 0, MMAX);
    for (i = 0; i < nerrs; i++)
        src_err_ix[src_err_list[i]] = 1;

    if (!CAUCHY) {
        // Make encode matrix
        if (!(ec_tbl = make_encode_matrix(k, p, &a))) {
            printf("Can't generate encode table\n");
            exit(1);
        }

        // Skip RAID-5 and RAID-6 with single error (simple XOR recovery)
        if (!RAID || nerrs > 1) {
            // Do math magic to prepare error recovery matrix
            if (!(dc_tbl = make_decode_matrix(k, nerrs, src_err_list, a))) {
                printf("Can't generate decode table\n");
                exit(1);
            }
        }
    } else {
        if (!(ec_tbl = prep_encode(k, p, &cauchy))) {
            printf("Can't generate cauchy-based encode table\n");
            exit(1);
        }
        dc_tbl = malloc(k*p*32);
        bzero(dc_tbl, k*p*32);
    }

    do {
        pthread_mutex_lock(&args.lock);
        if (args.ready == wcnt)
            break;
        pthread_mutex_unlock(&args.lock);
        usleep(100);
    } while(1);

    dprintf("Sending a GO!\n");

    pthread_cond_broadcast(&args.go);
    pthread_mutex_unlock(&args.lock);

    for (i = 0; i < wcnt; i++) {
        void *rv;
        pthread_join(wrk[i].id, &rv);
        if (!rv)
            printf("Oops on thread %d\n", i);
        else
            dprintf("%d is OK, ebw=%.3f, dbw=%.3f\n", i, wrk[i].enc_bw, wrk[i].dec_bw);
        enc_bw += wrk[i].enc_bw;
        dec_bw += wrk[i].dec_bw;
        enc_bw_min = min(enc_bw_min, wrk[i].enc_bw);
        dec_bw_min = min(dec_bw_min, wrk[i].dec_bw);
        enc_bw_max = max(enc_bw_max, wrk[i].enc_bw);
        dec_bw_max = max(dec_bw_max, wrk[i].dec_bw);
    }
    vprintf(2, "Min BW per thread: enc %.3f MB/s, dec %.3f MB/s\n", enc_bw_min/MiB, dec_bw_min/MiB);
    vprintf(2, "Avg BW per thread: enc %.3f MB/s, dec %.3f MB/s\n", enc_bw/wcnt/MiB, dec_bw/wcnt/MiB);
    vprintf(2, "Max BW per thread: enc %.3f MB/s, dec %.3f MB/s\n", enc_bw_max/MiB, dec_bw_max/MiB);
    if (!EXCEL) {
        vprintf(1, "Test: %d*{[(%d+%d)x%dKi with %d err]*%d} --> ", wcnt, k, p, s, nerrs, str_cnt);
        printf("Ttl BW: enc %.3f MB/s, dec %.3f MB/s\n", enc_bw/MiB, dec_bw/MiB);
    } else {
        vprintf(1, "%d*{[(%d+%d)x%dKi with %d err]*%d}\t", wcnt, k, p, s, nerrs, str_cnt);
        printf("%.3f\t%.3f\t\n", enc_bw/MiB, dec_bw/MiB);
    }

}

#endif

