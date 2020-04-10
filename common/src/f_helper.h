
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
} f_ah_scme_t;

int  f_ah_init(F_POOL_t *pool);
int  f_ah_shutdown(F_POOL_t *pool);
void *f_ah_stoker(void *arg);
void *f_ah_drainer(void *arg);

int f_ah_attach();
int f_ah_detach();
int f_ah_get_stripe(F_LAYOUT_t *lo, f_stripe_t *str);
int f_ah_commit_stripe(F_LAYOUT_t *lo, f_stripe_t str);
void f_ah_flush();

#endif
