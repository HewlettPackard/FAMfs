
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

#define F_MAX_CMS_CNT 256 

#define F_TAG_BASE  666

typedef struct _f_ah_scme {
    f_stripe_t  str;
    int         lo_id;
    int         flag;
} f_ah_scme_t;

typedef enum {
    F_AH_GETS,
    F_AH_PUTS,
    F_AH_COMS,
    F_AH_QUIT
} f_ah_ipc_op_t;

typedef struct _f_ah_ipc {
    f_ah_ipc_op_t   cmd;
    int             flag;
    int             lo_id;
    int             cnt;
    f_stripe_t      str[0];
} f_ah_ipc_t;

struct f_pool_;
int  f_ah_init(struct f_pool_ *pool);
int  f_ah_shutdown(struct f_pool_ *pool);

struct f_layout_;
int f_ah_attach();
int f_ah_detach();
int f_ah_get_stripe(struct f_layout_ *lo, f_stripe_t *str);
int f_ah_release_stripe(struct f_layout_ *lo, f_stripe_t str);
int f_ah_commit_stripe(struct f_layout_ *lo, f_stripe_t str);
void f_ah_flush();

#endif
