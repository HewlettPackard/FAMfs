//
// === libfabric stuff =============
//
#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>

#include <sys/time.h>

//
// === macro definitions ===========
//

#if 0
#define ON_ERROR(action, msg)               \
    do {                                    \
        int __err;                          \
        if ((__err = (action))) {           \
            printf("%s:%d%s: %d - %s\n", __FUNCTION__, __LINE__, msg, __err, fi_strerror(-__err)); \
            return (-ECANCELED);            \
        }                                   \
    } while (0);
#endif

#define CKPFS_STATS 1

#if CKPFS_STATS

#define DUMP_STATS(name, sb) if (do_lf_stats) {\
    char *__ev = getenv("##name");\
    if (!__ev)\
        __ev = name;\
    printf("dumping %s\n", __ev);\
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

#define UPDATE_STATS(sb, n, s, ts) if (do_lf_stats) {\
    int _n_ = (n), _s_ = (s);\
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

#else
#define DUMP_STATS(name, sb) do {;} while (0);
#define UPDATE_STATS(sb, n, s, ts) do {;} while(0);
#endif


#define SRV_MR_KEY 1

#define LF_WR_STATS_FN  "lf-writes.csv"
#define LF_RD_STATS_FN  "lf-reads.csv"
#define MD_FG_STATS_FN  "md-fget.csv"
#define MD_FP_STATS_FN  "md-fput.csv"
#define MD_AG_STATS_FN  "md-aget.csv"
#define MD_AP_STATS_FN  "md-aput.csv"

//
// === types =======================
//

typedef struct {
    pthread_mutex_t lck;
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
} lfio_stats_t;

//
// === globals =====================
//
#if 0
extern struct fi_info      *hints, *fi;
extern struct fid_fabric   *fabric;
extern struct fi_eq_attr   eq_attr;
extern struct fid_eq       *eq;
extern struct fid_domain   *domain;
extern struct fid_ep       *ep;
extern struct fi_av_attr   av_attr;
extern struct fid_av       *av;
extern struct fi_cq_attr   cq_attr;
extern struct fid_cq       *cq;
extern struct fid_mr       *mr;
extern struct fi_cntr_attr cntr_attr;
extern struct fid_cntr     *rcnt, *wcnt;
extern struct fi_context   wctx, rctx;
extern fi_addr_t           srv_addr;
#endif
extern size_t              mem_per_srv;
extern size_t              mem_per_cln;

extern lfio_stats_t        lf_wr_stat;  // libfaric write
extern lfio_stats_t        lf_rd_stat;  // libfaric read
extern lfio_stats_t        md_fg_stat;  // MDHIM file position get
extern lfio_stats_t        md_fp_stat;  // MDHIM file position put
extern lfio_stats_t        md_ag_stat;  // MDHIM file attr get
extern lfio_stats_t        md_ap_stat;  // MDHIM file attr put

extern FILE                *lf_stats_fp;
extern FILE                *md_stats_fp;

extern int                 do_lf_stats;

//
// === prototypes ==================
//

//int lf_connect(char *addr, char *srvc);

// current time in timespec
static inline struct timeval now(struct timeval *tvp) {
    struct timeval tv;
    gettimeofday(&tv, 0);
    if (tvp) *tvp = tv;
    return tv;
}

// elapsed time
static inline uint64_t elapsed(struct timeval *ts) {
    int64_t sec, usec;
    struct timeval tv = now(0);
    
    sec =  tv.tv_sec - ts->tv_sec;
    usec = tv.tv_usec - ts->tv_usec;
    if (sec > 0 && usec < 0) {
        sec--;
        usec += 1000000UL;
    }
    if (sec < 0 || (sec == 0 && usec < 0)) return 0;
    return sec * 1000000UL + usec;
}


// ---------------------------------
