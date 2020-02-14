/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAMFS_LF_CQPROGRESS_H
#define FAMFS_LF_CQPROGRESS_H

#include <rdma/fi_domain.h>


/* Check CQ progress: defined in famfs_lf_connect.c */

ssize_t lf_check_progress(struct fid_cq *cq, ssize_t *cmp);

#endif /* FAMFS_LF_CQPROGRESS_H */

