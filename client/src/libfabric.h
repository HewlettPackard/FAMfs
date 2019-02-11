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

#define SRV_MR_KEY 1

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
