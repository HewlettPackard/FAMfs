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
 * Written by: Oleg Neverovitch
 */

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

#define F_MAX_IPC_ME 1024 // max count of Message Elements to snd at once 

/* helper srv<->cln MPI tag base, individual layouts tags: <bas>+<id> */
#define F_TAG_BASE  (1U<<24) // 16777216: should not interfere with MDHIM CLIENT_RSP_TAG */
/* allocator->cln EDR done notification MPI tag */
#define F_TAG_NTFY  (F_TAG_BASE + F_LAYOUTS_MAX)

typedef struct _f_ah_scme {
    f_stripe_t  str;
    int         lid;
    int         flag;
    int         rank;
} f_ah_scme_t;

typedef enum {
    F_AH_GETS = 1,
    F_AH_PUTS,
    F_AH_COMS,
    F_AH_QUIT
} f_ah_ipc_op_t;

typedef struct _f_ah_ipc {
    f_ah_ipc_op_t   cmd;
    int             flag;
    int             lid;
    int             cnt;
    f_stripe_t      str[0];
} f_ah_ipc_t;

typedef struct _f_ah_ipci {
    f_ah_ipc_t      hdr;
    f_stripe_t      str;
} f_ah_ipci_t;

typedef enum {
    F_NTFY_EC_DONE = 1,
    F_NTFY_RC_DONE,
    F_NTFY_QUIT
} f_ntfy_op_t;

typedef struct _f_ah_ntfy_ {
    f_ntfy_op_t     op;
    int             lid;
} f_ah_ntfy_t;

#define F_AH_MSG(var, sz) struct {\
    f_ah_ipc_t      hdr;          \
    f_stripe_t      str[sz];      \
} var

#define F_AH_MSG_INIT(c,l,s) {.hdr.cmd = c, .hdr.lid = l, .hdr.cnt = s, .hdr.flag = 0, .str = {0}}
#define F_AH_MSG_SZ(n) (sizeof(f_ah_ipc_t) + (n)*sizeof(f_stripe_t))
#define F_AH_MSG_ALLOC(m,n,c,s) ({\
    int ext = 0;\
    __auto_type _new = (n);\
    __auto_type _cur = (c);\
    (s).count = _new;\
    if (_cur < _new) {\
        if (m) free(m);\
        m = malloc(F_AH_MSG_SZ(_new));\
        (c) = _new;\
        ext = 1;\
        if (m) (s).stripes = &m->str[0];\
    }\
    ext;\
})

#define F_AH_MSG_APPEND(m,e,c,s) ({\
    if (c <= (s).count) {\
        c += c;\
        m = realloc(m, F_AH_MSG_SZ(c));\
        if (m) (s).stripes = &m->str[0];\
    }\
    if (m) (s).stripes[(s).count] = (e);\
    (s).count++;\
})

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
