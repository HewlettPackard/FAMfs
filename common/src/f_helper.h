
#ifndef F_HELPER_H
#define F_HELPER_H

#define F_SALQ_NAME    "f_salq"
#define F_SCMQ_NAME    "f_scmq"

#define F_MAX_SALQ  256 //4096
#define F_MAX_SCMQ  256 //4096

#define F_SALQ_LWM  25
#define F_SCMQ_HWM  75

#define F_SALQ_LWTMO RBQ_TMO_1M
#define F_SCMQ_HWTMO RBQ_TMO_1M

#define F_MAX_CMS_CNT 4096

typedef struct _f_ah_scme {
    f_stripe_t  str;
    int         lo_id;
    int         flag;
} f_ah_scme_t;

struct f_pool_;
int  f_ah_init(struct f_pool_ *pool);
int  f_ah_shutdown(struct f_pool_ *pool);
void *f_ah_stoker(void *arg);
void *f_ah_drainer(void *arg);

int f_ah_attach();
int f_ah_detach();
struct f_layout_;
int f_ah_get_stripe(struct f_layout_ *lo, f_stripe_t *str);
int f_ah_commit_stripe(struct f_layout_ *lo, f_stripe_t str);
int f_ah_release_stripe(struct f_layout_ *lo, f_stripe_t str)'
void f_ah_flush();

#endif
