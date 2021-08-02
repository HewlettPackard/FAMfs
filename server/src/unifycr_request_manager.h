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
 */

/*
 * Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 *
 * Copyright 2017, UT-Battelle, LLC.
 *
 * LLNL-CODE-741539
 * All rights reserved.
 *
 * This is the license for UnifyCR.
 * For details, see https://github.com/LLNL/UnifyCR.
 * Please read https://github.com/LLNL/UnifyCR/LICENSE for full license text.
 */

/*
 * Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * Copyright (c) 2017, Florida State University. Contributions from
 * the Computer Architecture and Systems Research Laboratory (CASTL)
 * at the Department of Computer Science.
 *
 * Written by: Teng Wang, Adam Moody, Weikuan Yu, Kento Sato, Kathryn Mohror
 * LLNL-CODE-728877. All rights reserved.
 *
 * This file is part of burstfs.
 * For details, see https://github.com/llnl/burstfs
 * Please read https://github.com/llnl/burstfs/LICENSE for full license text.
 */

#ifndef UNIFYCR_REQUEST_MANAGER_H
#define UNIFYCR_REQUEST_MANAGER_H
#include "unifycr_const.h"
#include "unifycr_global.h"
#include "arraylist.h"

struct shm_meta_t_; /* defined in famfs_global.h */

int f_rm_fetch_md(int cid, int rcnt);
int rm_fetch_md(int qid, int num);
void *rm_delegate_request_thread(void *arg);
int rm_read_remote_data(int qid, int num);
int rm_send_remote_requests(thrd_ctrl_t *thrd_ctrl,
                            int thrd_tag, long *tot_sz);
int rm_pack_send_requests(char *req_msg_buf,
                          send_msg_t *send_metas, int req_num,
                          long *tot_sz);
int compare_delegators(const void *a, const void *b);
int rm_pack_send_msg(int rank, char *send_msg_buf,
                     send_msg_t *send_metas, int meta_num,
                     long *tot_sz);
int rm_receive_remote_message(int app_id,
                              int qid, long tot_sz);
void print_recv_msg(int app_id,
                    int cli_id, int dbg_rank, int thrd_id, struct shm_meta_t_ *msg);
int rm_process_received_msg(int app_id, int qid,
                            char *recv_msg_buf, long *ptr_tot_sz);
void print_remote_del_reqs(int app_id, int cli_id,
                           int dbg_rank, del_req_stat_t *del_req_stat);
void print_send_msgs(send_msg_t *send_metas,
                     long msg_cnt, int dbg_rank);

#endif
