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
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef F_STATS_H
#define F_STATS_H

#include <pthread.h>
#include <stdint.h>
#include <sys/time.h>

#include "f_env.h"
#include "list.h"		/* Doubly linked list */


#define KiB (1024L)
#define MiB (KiB*1024L)
#define GiB (MiB*1024L)
#define TiB (GiB*1024L)

#define mSec (1000L)
#define uSec (mSec*1000L)

//#define FAMFS_STATS 1		/* Uncomment this line and export FAMFS_DO_STATS=1 to turn stats ON */
extern int do_lf_stats;

#if FAMFS_STATS

#define DUMP_STATS(name, sb) if (do_lf_stats) {\
    char *__ev = getenv("##name");\
    if (!__ev)\
        __ev = name;\
    /*printf("dumping %s\n", __ev);*/\
    pthread_mutex_lock(&sb.lck);\
    FILE *__fp = fopen(__ev, "a+");\
    if (__fp) {\
        fprintf(__fp, "%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n", \
                sb.bcnt, sb.ttl, sb.min, sb.max, \
                sb.cnt, sb.bmin, sb.bmax,\
                sb.ett, sb.emin, sb.emax);\
        fclose(__fp);\
    }\
    pthread_mutex_unlock(&sb.lck);\
}

#define INIT_STATS(name, sb) if (do_lf_stats) {\
    char *__ev = getenv("##name");\
    if (!__ev)\
        __ev = name;\
    bzero(&sb.all, sizeof(sb.all));\
}

#define UPDATE_STATS(sb, n, s, ts) if (do_lf_stats) {\
    uint64_t _n_ = (n), _s_ = (s);\
    uint64_t _e_ = elapsed(&(ts));\
    if (_n_) {\
        pthread_mutex_lock(&sb.lck);\
        sb.bcnt++;\
        sb.cnt += _n_;\
        sb.ttl += _s_;\
        if (_s_ < sb.min || !sb.min)\
           sb.min = _s_;\
        if (_s_ > sb.max)\
            sb.max = _s_;\
        if (_n_ < sb.bmin || !sb.bmin)\
            sb.bmin = _n_;\
        if (_n_ > sb.bmax)\
            sb.bmax = _n_;\
        pthread_mutex_unlock(&sb.lck);\
    }\
    if (_e_) {\
        sb.ett += _e_;\
        if (_e_ < sb.emin || !sb.emin)\
            sb.emin = _e_;\
        if (_e_ > sb.emax)\
            sb.emax = _e_;\
    }\
}

#define STATS_START(start) \
    struct timespec start;  \
    if (do_lf_stats)       \
        start = now();

#else

#define DUMP_STATS(name, sb) do {;} while (0);
#define INIT_STATS(name, sb) do {;} while (0);
#define UPDATE_STATS(sb, n, s, ts) do {;} while(0);
#define STATS_START(start) do {;} while(0);

#endif

typedef struct {
    pthread_mutex_t lck;
    union {
        struct {
            uint64_t        cnt;
            uint64_t        ttl;
            uint64_t        min;
            uint64_t        max;
            uint64_t        bcnt;
            uint64_t        bmin;
            uint64_t        bmax;
            uint64_t        ett;
            uint64_t        emin;
            uint64_t        emax;
        };
        uint64_t            all[10];
    };
} lfio_stats_t;

#define LF_WR_STATS_FN  "lf-writes.csv"
#define LF_RD_STATS_FN  "lf-reads.csv"
#define LF_MR_STATS_FN  "lf-mreg.csv"
#define MD_LG_STATS_FN  "md-lget.csv"
#define MD_FG_STATS_FN  "md-fget.csv"
#define MD_FP_STATS_FN  "md-fput.csv"
#define MD_AG_STATS_FN  "md-aget.csv"
#define MD_AP_STATS_FN  "md-aput.csv"
#define WR_MAP_STATS_FN "wr-map.csv"
#define WR_UPD_STATS_FN "wr-upd.csv"
#define WR_CMT_STATS_FN "wr-commit.csv"
#define FD_WR_STATS_FN  "fd-wr.csv"
#define FD_EXT_STATS_FN "fd-ext.csv"
#define FD_SYN_STATS_FN "fd-sync.csv"
#define TEST1_STATS_FN  "test1.csv"

extern lfio_stats_t        lf_wr_stat;  // libfaric write
extern lfio_stats_t        lf_rd_stat;  // libfaric read
extern lfio_stats_t        lf_mr_stat;  // libfaric local memory reg
extern lfio_stats_t        md_lg_stat;  // MDHIM file position get from local cache (on read)
extern lfio_stats_t        md_fg_stat;  // MDHIM file position get (CMD_MDGET)
extern lfio_stats_t        md_fp_stat;  // MDHIM file position put (MDRQ_FSYNC) (on fsync, close)
extern lfio_stats_t        md_ag_stat;  // MDHIM file attr get (MDRQ_FAMAT, MDRQ_GETFA)
extern lfio_stats_t        md_ap_stat;  // MDHIM file attr put (MDRQ_SETFA)
extern lfio_stats_t        wr_map_stat; // MD stripe/chunk mapping (on write)
extern lfio_stats_t        wr_upd_stat; // find file attr entry and update attr (on write)
extern lfio_stats_t        wr_cmt_stat; // commit stripe to Helper (on write)
extern lfio_stats_t        fd_wr_stat;  // fd_write()
extern lfio_stats_t        fd_ext_stat; // fid_extend()
extern lfio_stats_t        fd_syn_stat; // fid_sync()
extern lfio_stats_t        test1_stat;


// current time in timespec
static inline struct timespec now(void) {
    struct timespec tv_nsec;

    clock_gettime(CLOCK_MONOTONIC, &tv_nsec);
    return tv_nsec;
}

// elapsed time
static inline uint64_t elapsed(struct timespec *ts) {
    time_t sec;
    long usec;
    struct timespec tv = now();

    sec =  tv.tv_sec - ts->tv_sec;
    usec = (tv.tv_nsec - ts->tv_nsec)/1000;
    if (sec > 0 && usec < 0) {
        sec--;
        usec += 1000000L;
    }
    if (sec < 0 || (sec == 0 && usec < 0)) return 0;
    return (uint64_t)sec * 1000000UL + (uint64_t)usec;
}


/* Carbon simulator instruction stats */

#if (HAVE_FAM_SIM == 1)

#include <stddef.h>		/* offsetof(type,member) */

enum {
        FAMSIM_STATS_TEST,
        FAMSIM_STATS_SEND,
        FAMSIM_STATS_RECV,
        FAMSIM_STATS_FI_WR,
};

#endif /* HAVE_FAM_SIM == 1 */

enum {
        FAMSIM_STATS_STOPPED,
        FAMSIM_STATS_RUNNING,
        FAMSIM_STATS_PAUSED,
};

struct famsim_stat_ctx {
        int                     stats_id;
        char                    *stats_dir;
        char                    *stats_unique;
        struct list_head        stats_list;
        int                     fam_cnt; /* Pass FAM count to a client */
};

struct famsim_stats {
        struct list_head        item;
        struct famsim_stat_ctx  *stat_ctx;
        void                    *buf;
        uint64_t                buf_len;
        int                     fd;
        uint16_t                uid;
        uint8_t                 state;
};

extern struct famsim_stat_ctx *famsim_ctx;

#if (HAVE_FAM_SIM == 1)

#include <hpe_sim_api_linux64.h>

void famsim_stats_init(struct famsim_stat_ctx **ctx_p, const char *dir, const char *fn, int id);
struct famsim_stats * famsim_stats_create(struct famsim_stat_ctx *ctx, int uid);
struct famsim_stats * famsim_stats_find(struct famsim_stat_ctx *ctx, int uid);
void famsim_stats_start(struct famsim_stat_ctx *ctx, struct famsim_stats *stats);
void famsim_stats_stop(struct famsim_stats *stats, int do_write);
void famsim_stats_pause(struct famsim_stats *stats);
void famsim_stats_close(struct famsim_stats *stats);
void famsim_stats_free(struct famsim_stat_ctx *ctx);

#else

static inline void famsim_stats_init(struct famsim_stat_ctx **ctx_p, const char *dir, const char *fn, int id) \
    { (void)ctx_p; (void)dir; (void)fn; (void)id; }
#define famsim_stats_create(ctx, id) (NULL)
#define famsim_stats_find(ctx, id) (NULL)
static inline void famsim_stats_start(struct famsim_stat_ctx *ctx, struct famsim_stats *stats) \
    { (void)ctx; (void)stats; }
static inline void famsim_stats_stop(struct famsim_stats *stats, int do_write) \
    { (void)stats; (void)do_write; }
static inline void famsim_stats_pause(struct famsim_stats *stats) { (void)stats; }
static inline void famsim_stats_close(struct famsim_stats *stats) { (void)stats; }
static inline void famsim_stats_free(struct famsim_stat_ctx *ctx) { (void)ctx; }

#endif /* HAVE_FAM_SIM == 1 */

#endif  /* F_STATS_H */
