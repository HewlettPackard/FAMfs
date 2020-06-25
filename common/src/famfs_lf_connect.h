/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAMFS_LF_CONNECT_H
#define FAMFS_LF_CONNECT_H

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
#include <uuid/uuid.h>

#include "famfs_env.h"
#include "famfs_ktypes.h"
#include "famfs_bitops.h"
#include "famfs_zfm.h"


/* libfabric domain structure: that could be per device or per process */
typedef struct lf_dom_ {
	struct fid_fabric *fabric;
	struct fid_domain *domain;
	struct fi_info	*fi;
	struct fid_av	*av;
} LF_DOM_t;

typedef struct fam_dev_ {
	char		*lf_name;	/* device node name */
	uint64_t	offset;		/* remote memory offset, bytes */
	F_ZFM_t		zfm;		/* GenZ fabric manager data */
	void		*usr_buf;	/* optional user buffer, reference */
	void		*local_desc;	/* local buffer descriptor */
	uint64_t	virt_addr;	/* address of remote memory to access or NULL */
	struct fid_mr	*mr;		/* memory region */
	struct fid_ep	*ep;		/* connected fabric endpoint */
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
} LF_INFO_t;


/* defined in famfs_lf_connect.c */
#define LF_CLIENT false	/* bool const for f_domain_open/f_conn_open: libfabric client */
#define LF_SERVER true	/* libfabric server */
int f_domain_open(LF_DOM_t **dom_p, LF_INFO_t *info, const char *node,
    bool lf_srv);
int f_conn_open(FAM_DEV_t *fdev, LF_DOM_t *domain, LF_INFO_t *info,
    int media_id, bool lf_srv);
int f_domain_close(LF_DOM_t **domain_p);
int f_conn_close(FAM_DEV_t *d);

/* TODO: Move me to debug.h */
#define DEBUG_LF(lvl, fmt, ...) DEBUG_LVL_(lf_verbosity, lvl, fmt, ## __VA_ARGS__)

#endif /* FAMFS_LF_CONNECT_H */

