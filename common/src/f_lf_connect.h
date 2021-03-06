/*
 * (C) Copyright 2017-2020 Hewlett Packard Enterprise Development LP
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

#ifndef F_LF_CONNECT_H
#define F_LF_CONNECT_H

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_ext_zhpe.h>
#include <rdma/fi_errno.h>
#include <uuid/uuid.h>

#include "f_env.h"
#include "f_ktypes.h"
#include "f_bitops.h"
#include "f_zfm.h"
#include "f_error.h"


/* libfabric domain structure: that could be per device or per process */
typedef struct lf_dom_ {
	struct fid_fabric *fabric;
	struct fid_domain *domain;
	struct fi_info	*fi;
	struct fid_av	*av;
	struct fid_ep	*ep;		/* per-domain endpoint or NULL */
	struct fid_cq	*cq;		/* per-domain comlition queue or NULL */
} LF_DOM_t;

typedef struct fam_dev_ {
	char		*lf_name;	/* device node name */
	uint64_t	offset;		/* remote memory offset, bytes */
	F_ZFM_t		zfm;		/* GenZ fabric manager data */
	void		*usr_buf;	/* optional user buffer, reference */
	void		*local_desc;	/* local buffer descriptor */
	uint64_t	virt_addr;	/* address of remote memory to access or NULL */
	struct fid_mr	*mr;		/* memory region */
	struct fid_ep	*ep;		/* connected fabric endpoint: pointer of ref. */
	struct fid_cntr *rcnt;		/* completion and event counter for reads */
	struct fid_cntr	*wcnt;		/* completion and event counter for writes */
	struct fid_cq	*cq;		/* comlition queue bound to this endpoint or NULL */
	fi_addr_t	fi_addr;	/* index of fabric address returned by av_insert */
	char		*service;	/* remote port number */
	union {
	    uint64_t	pkey;		/* protection key associated with the remote memory */
	    uint64_t	mr_key;		/* memory region protection key for a local buffer */
	};
	size_t		mr_size;	/* memory region size, bytes */
	int		cq_affinity;	/* CQ affinity or zero */
	struct {
	    unsigned int    per_dom:1;	/* FAM_DEV_t::ep is a reference to per-domain EP */
	}		ep_flags;
	uint16_t	ionode_idx;	/* ionode index where device is located */

	/* FAM emulation only */
	void		*mr_buf;	/* local memory buffer or NULL */
} FAM_DEV_t;

typedef struct fam_bdev_ {
	dev_t		dev_mm;
	char		*path;
	int		fd;
} FAM_BDEV_t;

typedef struct f_dev_ {
    union {
	struct fam_dev_		f;
	struct fam_bdev_	b;
    };
} F_DEV_t;

typedef struct lf_mr_mode_ {
	unsigned int scalable:1;
	unsigned int basic:1;
	unsigned int local:1;
	unsigned int prov_key:1;
	unsigned int virt_addr:1;
	unsigned int allocated:1;
	unsigned int _f:26;
} __attribute__((packed)) LF_MR_MODE_t;

typedef struct lf_prg_mode_ {
	unsigned int progress_manual:1;
	unsigned int progress_auto:1;
	unsigned int _f:30;
} __attribute__((packed)) LF_PRG_MODE_t;

typedef struct lf_opts_ {
	unsigned int zhpe_support:1;
	unsigned int true_fam:1;
	unsigned int use_cq:1;		/* 1: use CQ, 0: use I/O completion counters */
	unsigned int _f:27;
} __attribute__((packed)) LF_OPTS_t;

typedef struct lf_info_ {
	char		*fabric;
	char		*domain;
	char		*provider;
	LF_MR_MODE_t	mrreg;
	LF_PRG_MODE_t	progress;
	LF_OPTS_t	opts;		/* libfabric connection options */
	uint64_t	io_timeout_ms;
	int		service;	/* libfabric service (port) - base */
	int		verbosity;	/* debug verbosity level, pool->verbose */
	int		single_ep;	/* 1: open single EP per domain */
} LF_INFO_t;


/* defined in f_lf_connect.c */
#define LF_CLIENT false	/* bool const for f_domain_open/f_conn_open: libfabric client */
#define LF_SERVER true	/* libfabric server */
int f_domain_open(LF_DOM_t **dom_p, LF_INFO_t *info, const char *node,
    bool is_srv);
int f_conn_open(FAM_DEV_t *fdev, LF_DOM_t *domain, LF_INFO_t *info,
    int media_id, bool is_srv);
int f_conn_enable(struct fid_ep *ep, struct fi_info *fi);
int f_domain_close(LF_DOM_t **domain_p);
int f_conn_close(FAM_DEV_t *d);
ssize_t lf_check_progress(struct fid_cq *cq, ssize_t *cmp);

#define FI_ERROR_LOG(err, msg, ...)       \
    do {                                  \
        int64_t __err = (int64_t)err;     \
        fprintf(stderr, #msg ": %ld - %s\n", ## __VA_ARGS__, __err, fi_strerror(-__err)); \
    } while (0);

#define ON_FI_ERROR(action, msg, ...)       \
    do {                                    \
        int64_t __err;                      \
        if ((__err = (action))) {           \
            fprintf(stderr, #msg ": %ld - %s\n", ## __VA_ARGS__, \
                    __err, fi_strerror(-__err)); \
            exit(1);                        \
        }                                   \
    } while (0);

#define ON_FI_ERR_RET(action, msg, ...)       \
    do {                                    \
        int64_t __err;                      \
        if ((__err = (action))) {           \
            fprintf(stderr, #msg ": %ld - %s\n", ## __VA_ARGS__, \
                    __err, fi_strerror(-__err)); \
            return -EINVAL;                 \
        }                                   \
    } while (0);

#define fi_err(rc, msg, ...)				\
    do {						\
	if (rc < 0) {					\
	    fprintf(stderr, "%s: " msg ": %d - %s\n",	\
		    __FUNCTION__, ## __VA_ARGS__,	\
		    (int)(rc), fi_strerror(-(int)(rc)));\
	} else if (rc > 0) {				\
	    fprintf(stderr, "%s: " msg ": %d - %m\n",	\
		    __FUNCTION__, ## __VA_ARGS__,	\
		    (int)(rc));				\
	}						\
    } while (0);

/* TODO: Move me to debug.h */
#define DEBUG_LF(lvl, fmt, ...) DEBUG_LVL_(lf_verbosity, lvl, fmt, ## __VA_ARGS__)

#endif /* F_LF_CONNECT_H */

