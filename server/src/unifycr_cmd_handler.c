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

#include <unistd.h>
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include "log.h"
#include "f_global.h"
#include "unifycr_global.h"
#include "unifycr_cmd_handler.h"
#include "unifycr_request_manager.h"
#include "unifycr_setup.h"
#include "unifycr_const.h"
#include "unifycr_sock.h"
#include "unifycr_metadata.h"
#include "f_rbq.h"
#include "f_pool.h"
#include "f_layout.h"
#include "f_helper.h"

extern f_rbq_t *rplyq[MAX_NUM_CLIENTS];
extern f_rbq_t *cmdq[F_CMDQ_MAX];
extern f_rbq_t *admq;
extern volatile int exit_flag;

pthread_spinlock_t cntfy_lock;
f_close_ntfy_t cntfy[MAX_NUM_CLIENTS];

/**
* handle client-side requests, including init, open, fsync,
* read, close, stat and unmount
*
* @param cmd_buf: received command from client
* @param sock_id: position in poll_set
* @return success/error code
*/
int delegator_handle_command(char *ptr_cmd, int sock_id, long db_max_recs_per_slice)
{

    /*init setup*/

    int rc = 0, ret_sz = 0;
    int cmd = *((int *)ptr_cmd);
    int num;
    long max_recs_per_slice = db_max_recs_per_slice;
    char *ptr_ack;

    LOG(LOG_DBG, "DLG command %x, masked %x\n", cmd, cmd & ~CMD_OPT_MASK);
    switch (cmd & ~CMD_OPT_MASK) {
    case COMM_SYNC_DEL:
        (void)0;
        ptr_ack = sock_get_ack_buf(sock_id);
        ret_sz = pack_ack_msg(ptr_ack, cmd, ACK_SUCCESS,
                              &local_rank_cnt, sizeof(int));
        rc = sock_ack_cli(sock_id, ret_sz);
        return rc;

    case COMM_MOUNT:
        fam_fs = cmd & CMD_OPT_FAMFS ? 1 : 0;
        if (fam_fs) {
            LOG(LOG_ERR, "FAMFS mount failed");
            return -1;
        }
        rc = sync_with_client(ptr_cmd, sock_id);

        ptr_ack = sock_get_ack_buf(sock_id);
        ret_sz = pack_ack_msg(ptr_ack, COMM_MOUNT, rc,
                              &max_recs_per_slice, sizeof(long));
#if 0
        *((int *)&ptr_ack[ret_sz]) = glb_rank;
        ret_sz += sizeof(int);
        *((int *)&ptr_ack[ret_sz]) = glb_size;
        ret_sz += sizeof(int);
#endif
        rc = sock_ack_cli(sock_id, ret_sz);
        return rc;

    case COMM_META:
        (void)0;
        int type = *((int *)ptr_cmd + 1);
        if (type == 1) {
            /*get file attribute*/
            f_fattr_t attr_val;
            rc = meta_process_attr_get(ptr_cmd,
                                       sock_id, &attr_val);

            ptr_ack = sock_get_ack_buf(sock_id);
            ret_sz = pack_ack_msg(ptr_ack, cmd, rc,
                                  &attr_val, sizeof(f_fattr_t));
            rc = sock_ack_cli(sock_id, ret_sz);

        }

        if (type == 2) {
            /*set file attribute*/
            rc = meta_process_attr_set(ptr_cmd, sock_id);

            ptr_ack = sock_get_ack_buf(sock_id);
            ret_sz = pack_ack_msg(ptr_ack, cmd, rc, NULL, 0);
            rc = sock_ack_cli(sock_id, ret_sz);
            /*ToDo: deliver the error code/success to client*/
        }

        if (type == 3) {
            /*synchronize both index and file attribute
             *metadata to the key-value store*/

            rc = meta_process_fsync(sock_id);

            /*ack the result*/
            ptr_ack = sock_get_ack_buf(sock_id);
            ret_sz = pack_ack_msg(ptr_ack, cmd, rc, NULL, 0);
            rc = sock_ack_cli(sock_id, ret_sz);
        }
        break;

    case COMM_READ:
        num = *(((int *)ptr_cmd) + 1);
        /* result is handled by the individual thread in
         * the request manager*/
        rc = rm_read_remote_data(sock_id, num);
        break;

    case COMM_MDGET:
        num = *(((int *)ptr_cmd) + 1);
        rc = rm_fetch_md(sock_id, num);
        if (rc) {
            LOG(LOG_ERR, "md_get err %d\n", rc);
        }
        rc = sock_notify_cli(sock_id, COMM_READ);
        if (rc != 0) {
            LOG(LOG_ERR, "sock notify failed\n");
            return rc;
        }
        break;

    case COMM_UNMOUNT:
        unifycr_broadcast_exit(sock_id);
        rc = ULFS_SUCCESS;
        break;

    case COMM_DIGEST:
        break;

    default:
        LOG(LOG_DBG, "rank:%d,Unsupported command %x\n",
            glb_rank, cmd);
        rc = -1;
        break;
    }
    return rc;
}

extern long max_recs_per_slice;

int f_srv_process_cmd(f_svcrq_t *pcmd, char *qn, int admin) {

    /*init setup*/

    int rc = 0;
    int cmd = pcmd->opcode;
    f_svcrply_t rply;
    char qname[MAX_RBQ_NAME];

    LOG(LOG_DBG, "svc command %x, masked %x\n", cmd, cmd & ~CMD_OPT_MASK);
    bzero(&rply, sizeof(rply));
    rply.ackcode = cmd;
    rply.more= 0;

    switch (cmd & ~CMD_OPT_MASK) {
    case CMD_SVCRQ:
        if (!admin) {
            LOG(LOG_ERR, "admin command (%d) on non-admin queue: %s", cmd, qn);
            return EINVAL;
        }
        if (rplyq[pcmd->cid]) {
            LOG(LOG_INFO, "reply queue %d was not properly closed", pcmd->cid);
            f_rbq_close(rplyq[pcmd->cid]);
        }
        sprintf(qname, "%s-%02d", F_RPLYQ_NAME, pcmd->cid); 
        if ((rc = f_rbq_open(qname, &rplyq[pcmd->cid]))) {
            LOG(LOG_ERR, "can't open client reply queue %s:%s", qname, strerror(-rc));
            return rc;
        }
        break;

    case CMD_MOUNT:
        if (!admin) {
            LOG(LOG_ERR, "admin command (%d) on non-admin queue: %s", cmd, qn);
            return EINVAL;
        }
        if (fam_fs == -1) {
            fam_fs = cmd & CMD_OPT_FAMFS ? 1 : 0;
        } else {
            if (fam_fs && !(cmd & CMD_OPT_FAMFS)) {
                LOG(LOG_ERR, "Attempt to mount FAMFS on non-FAMFS DB\n");
                return -1;
            } else if (!fam_fs && (cmd & CMD_OPT_FAMFS)) {
                LOG(LOG_ERR, "Attempt to mount not-FAM FS on FAMFS DB\n");
                return -1;
            }
        }
        rply.rc = f_setup_client(pcmd);
        //rply.max_rps = max_recs_per_slice;
        break;

    case CMD_META:
        if (pcmd->md_type == MDRQ_FAMAT) {
            if (!admin) {
                LOG(LOG_ERR, "FAM attr get cmd on non-admin queue: %s", qn);
                return EINVAL;
            }
            /*get FAM attribute*/
            fam_attr_val_t *pval = NULL;
            int n = 0;
            if (!(rply.rc = meta_famattr_get(pcmd->fam_id, &pval))) {
                for (int i = 0; i < pval->part_cnt; i++) {
                    rply.prt_atr[n++] = pval->part_attr[i];
                    if (n >= KA_PAIR_MAX) {
                        rply.cnt = n;
                        rply.more = pval->part_cnt - n;
                        if ((rc = f_rbq_push(rplyq[pcmd->cid], &rply, RBQ_TMO_1S))) {
                            LOG(LOG_ERR, "can't push partial reply onto q %d: %s\n", pcmd->cid, strerror(-rc));
                            free(pval);
                            return rc;
                        }
                        n = 0;
                    }
                }
            }
            rply.cnt = n;
            rply.more = 0;

            free(pval);
            break;
        }
        if (admin) {
            LOG(LOG_ERR, "non-admin command (%d) on admin queue: %s", cmd, qn);
            return EINVAL;
        }
        if (pcmd->md_type == MDRQ_GETFA) {
            /*get file attribute*/
            rply.rc = f_do_fattr_get(pcmd, &rply.fattr);
            break;
        }

        if (pcmd->md_type == MDRQ_SETFA) {
            /*set file attribute*/
            rply.rc = f_do_fattr_set(pcmd, &pcmd->fm_data);
            break;
        }

        if (pcmd->md_type == MDRQ_FSYNC) {
            /*synchronize both index and file attribute
             *metadata to the key-value store*/

            if (!(rply.rc = f_do_fsync(pcmd))) {
                //int me;
                //MPI_Comm_rank(pool->helper_comm, &me);
                F_LAYOUT_t *lo = f_get_layout(pcmd->fm_lid);
                ASSERT(lo);
                if (lo->info.chunks - lo->info.data_chunks) {
                    // mark this client as having written stuff to this layout
                    pthread_spin_lock(&cntfy_lock);
                    set_bit(pcmd->lid, &cntfy[pcmd->cid].sync_bm);
                    set_bit(pcmd->lid, &cntfy[pcmd->cid].edr_bm);
                    pthread_spin_unlock(&cntfy_lock);
                }
            }

            break;
        }

        break;

    case CMD_READ:
        LOG(LOG_ERR, "assisted read command is not supported");
        rply.rc = ENOSYS;
        break;

    case CMD_MDGET:
        if (admin) {
            LOG(LOG_ERR, "non-admin command (%d) on admin queue: %s", cmd, qn);
            return EINVAL;
        }
        if ((rply.rc = f_rm_fetch_md(pcmd->cid, pcmd->md_rcnt)))
            LOG(LOG_ERR, "md_get err %d\n", rc);
        break;

    case CMD_FCLOSE:
        if (admin) {
            LOG(LOG_ERR, "non-admin command (%d) on admin queue: %s", cmd, qn);
            return EINVAL;
        } else {
            F_LAYOUT_t *lo = f_get_layout(pcmd->lid);
            ASSERT(lo);

            int wait = 0;
            //int me;
            //MPI_Comm_rank(pool->helper_comm, &me);
            if (lo->info.chunks - lo->info.data_chunks) {
                // see if EDR is done for this client/layout
                pthread_spin_lock(&cntfy_lock);
                if (test_bit(pcmd->lid, &cntfy[pcmd->cid].sync_bm)) {
                    // if we saw fsync, see if EDR is also done
                    wait = test_bit(pcmd->lid, &cntfy[pcmd->cid].edr_bm);
                    if (wait) {
                        set_bit(pcmd->lid, &cntfy[pcmd->cid].wait_bm);
                        clear_bit(pcmd->lid, &cntfy[pcmd->cid].sync_bm);
                        clear_bit(pcmd->lid, &cntfy[pcmd->cid].edr_bm);
                    }
                }
                pthread_spin_unlock(&cntfy_lock);
            }
            if (wait) {
                return 0; // EDR still in progress, do not reply
            }
        }

        break;

    case CMD_UNMOUNT:
        if (!admin) {
            LOG(LOG_ERR, "admin command (%d) on non-admin queue: %s", cmd, qn);
            return EINVAL;
        }
        f_rbq_close(rplyq[pcmd->cid]);
        /* TODO clean up client thread resources */
        rplyq[pcmd->cid] = 0;
        return 0;

    case CMD_QUIT:
        return 0;

    case CMD_SHTDWN:
        if (!admin) {
            LOG(LOG_ERR, "admin command (%d) on non-admin queue: %s", cmd, qn);
            return EINVAL;
        }

        exit_flag = 1;
        return 0;

    case CMD_DIGEST:
    default:
        LOG(LOG_DBG, "client %d: Unsupported command %x\n", pcmd->cid, cmd);
        rply.rc = ENOSYS;
    }

    if ((rc = f_rbq_push(rplyq[pcmd->cid], &rply, RBQ_TMO_1S))) {
        LOG(LOG_ERR, "filed to post reply to client %d: %s", pcmd->cid, strerror(-rc));
    }
    return rc;
}

void *f_notify_thrd(void *arg) {
    int clients[MAX_NUM_CLIENTS], cnt = 0, rc = 0;
    f_ah_ntfy_t msg;
    F_POOL_t *pool = f_get_pool();
    MPI_Status sts;
    f_svcrply_t rply = {.rc = 0, .more = 0, .ackcode = CMD_FCLOSE};
    //int me;
    //MPI_Comm_rank(pool->helper_comm, &me);

    ASSERT(pool);

    while (1) {
        rc = MPI_Recv(&msg, sizeof(msg), MPI_BYTE, MPI_ANY_SOURCE,
                      F_TAG_NTFY, pool->helper_comm, &sts);
        if  (rc != MPI_SUCCESS || sts.MPI_ERROR != MPI_SUCCESS) {
            LOG(LOG_ERR, "MPI_Recv returnd error %d/sts=%d", rc, sts.MPI_ERROR);
            continue;
        }
        if (msg.op == F_NTFY_QUIT)
            break;
        ASSERT(msg.op == F_NTFY_EC_DONE);
        LOG(LOG_DBG, "Got EDR DONE on lid %d", msg.lid);

        for (int i = 0; i < MAX_NUM_CLIENTS; i++) {
            pthread_spin_lock(&cntfy_lock);
            if (test_bit(msg.lid, &cntfy[i].wait_bm)) {
                // client is waiting on close for EDR to finish
                clients[cnt++] = i;
                clear_bit(msg.lid, &cntfy[i].wait_bm);
            }
            // always clear edr bm 'cause edr is done regardless of wait list
            clear_bit(msg.lid, &cntfy[i].edr_bm);
            pthread_spin_unlock(&cntfy_lock);
        }

        for (int i = 0; i < cnt; i++) {
            LOG(LOG_DBG, "Sending CLOSE reply to rank %d, lid %d", clients[i], msg.lid);
            if ((rc = f_rbq_push(rplyq[clients[i]], &rply, RBQ_TMO_1S))) {
                LOG(LOG_ERR, "failed to post CLOSE reply to client %d: %s", clients[i], strerror(-rc));
            }
        }
        cnt = 0;
    }

    return NULL;
}

void *f_command_thrd(void *arg) {
    f_rbq_t     *myq = (f_rbq_t *)arg;
    f_svcrq_t    fcmd;
    int         rc;

    while (1) {
        if ((rc = f_rbq_pop(myq, &fcmd, 10*RBQ_TMO_1S))) {
            if (rc == -ETIMEDOUT) {
                LOG(LOG_DBG, "SRV: 10s, no command");
                if (exit_flag) {
                    LOG(LOG_INFO, "svc exit gflag set, exiting");
                    exit(0);
                }
                continue;
            } else {
                LOG(LOG_FATAL, "svc rbq pop failed: %s(%d)", strerror(-rc), rc);
                exit(1);
            }

        }
        if (exit_flag)
            return NULL;

        if ((rc = f_srv_process_cmd(&fcmd, myq->rbq->name, 0))) {
            LOG(LOG_FATAL, "%s", ULFS_str_errno(rc));
            exit(rc);
        }
    }
}

/**
* pack the message to be returned to the client.
* format: command type, error code, payload
* @param ptr_cmd: command buffer
* @param rc: error code
* @param val: payload
* @return success/error code
*/
int pack_ack_msg(char *ptr_cmd, int cmd, int rc, void *val,
                 int val_len)
{
    int ret_sz = 0;

    memcpy(ptr_cmd, &cmd, sizeof(int));
    ret_sz += sizeof(int);
    memcpy(ptr_cmd + sizeof(int), &rc, sizeof(int));
    ret_sz += sizeof(int);

    if (val != NULL) {
        memcpy(ptr_cmd + 2 * sizeof(int), val, val_len);
        ret_sz += val_len;
    }
    return ret_sz;
}

/**
* receive and store the client-side information,
* then attach to the client-side shared buffers.
*
* @param cmd_buf: received command from client
* @param sock_id: position in poll_set
* @return success/error code
*/
int sync_with_client(char *cmd_buf, int sock_id)
{
    int app_id = *((int *)(cmd_buf) + 1);
    int local_rank_idx = *((int *)(cmd_buf) + 2);
    int dbg_rank = *((int *)(cmd_buf) + 3);

    app_config_t *tmp_config;
    /*if this client is from a new application, then
     * initialize this application's information
     * */

    int rc;
    if (arraylist_get(app_config_list, app_id) == NULL) {
        int num_procs_per_node = *((int *)(cmd_buf) + 4);
        int req_buf_sz = *((int *)(cmd_buf) + 5);
        int recv_buf_sz = *((int *)(cmd_buf) + 6);
        long superblock_sz =
            *((long *)(cmd_buf +
                       7 * sizeof(int)));
        long meta_offset = *((long *)(cmd_buf + 7 * sizeof(int)
                                      + sizeof(long)));
        long meta_size = *((long *)(cmd_buf + 7 * sizeof(int)
                                    + 2 * sizeof(long)));

        long fmeta_offset = *((long *)(cmd_buf + 7 * sizeof(int)
                                       + 3 * sizeof(long)));
        long fmeta_size = *((long *)(cmd_buf + 7 * sizeof(int)
                                     + 4 * sizeof(long)));

        long data_offset = *((long *)(cmd_buf + 7 * sizeof(int)
                                      + 5 * sizeof(long)));
        long data_size = *((long *)(cmd_buf + 7 * sizeof(int)
                                    + 6 * sizeof(long)));

        int cursor = 7 * sizeof(int)
                     + 7 * sizeof(long);

        /*          LOG(LOG_DBG, "superblock_sz:%ld, num_procs_per_node:%ld,
                             req_buf_sz:%ld, data_size:%ld\n",
                            superblock_sz, num_procs_per_node, req_buf_sz, data_size); */
        tmp_config = (app_config_t *)malloc(sizeof(app_config_t));
        memcpy(tmp_config->external_spill_dir,
               cmd_buf + cursor, MAX_PATH_LEN);

        /*don't forget to free*/
        tmp_config->num_procs_per_node = num_procs_per_node;
        tmp_config->req_buf_sz = req_buf_sz;
        tmp_config->recv_buf_sz = recv_buf_sz;
        tmp_config->superblock_sz = superblock_sz;

        tmp_config->meta_offset = meta_offset;
        tmp_config->meta_size = meta_size;

        tmp_config->fmeta_offset = fmeta_offset;
        tmp_config->fmeta_size = fmeta_size;

        tmp_config->data_offset = data_offset;
        tmp_config->data_size = data_size;

        int i;
        for (i = 0; i < MAX_NUM_CLIENTS; i++) {
            tmp_config->client_ranks[i] = -1;
            tmp_config->shm_recv_bufs[i] = NULL;
            tmp_config->shm_req_bufs[i] = NULL;
            tmp_config->shm_superblocks[i] = NULL;
            tmp_config->shm_superblock_fds[i] = -1;
            tmp_config->shm_recv_fds[i] = -1;
            tmp_config->shm_req_fds[i] = -1;
            tmp_config->spill_log_fds[i] = -1;
            tmp_config->spill_index_log_fds[i] = -1;
        }

        rc = arraylist_insert(app_config_list, app_id, tmp_config);
        if (rc != 0) {
            return rc;
        }
    } else {
        tmp_config = (app_config_t *)arraylist_get(app_config_list,
                     app_id);
    }
    /* The following code attach a delegator thread
     * to this new connection */
    thrd_ctrl_t *thrd_ctrl =
        (thrd_ctrl_t *)malloc(sizeof(thrd_ctrl_t));
    memset(thrd_ctrl, 0, sizeof(thrd_ctrl_t));

    thrd_ctrl->exit_flag = 0;
    cli_signature_t *cli_signature =
        (cli_signature_t *)malloc(sizeof(cli_signature_t));
    cli_signature->app_id = app_id;
    cli_signature->sock_id = sock_id;
    rc = pthread_mutex_init(&(thrd_ctrl->thrd_lock), NULL);
    if (rc != 0) {
        return ULFS_ERROR_THRDINIT;
    }

    rc = pthread_cond_init(&(thrd_ctrl->thrd_cond), NULL);
    if (rc != 0) {
        return ULFS_ERROR_THRDINIT;
    }

    thrd_ctrl->del_req_set =
        (msg_meta_t *)malloc(sizeof(msg_meta_t));
    if (!thrd_ctrl->del_req_set) {
        return ULFS_ERROR_NOMEM;
    }
    memset(thrd_ctrl->del_req_set,
           0, sizeof(msg_meta_t));

    thrd_ctrl->del_req_stat =
        (del_req_stat_t *)malloc(sizeof(del_req_stat_t));
    if (!thrd_ctrl->del_req_stat) {
        return ULFS_ERROR_NOMEM;
    }
    memset(thrd_ctrl->del_req_stat, 0, sizeof(del_req_stat_t));

    thrd_ctrl->del_req_stat->req_stat =
        (per_del_stat_t *)malloc(sizeof(per_del_stat_t) * glb_size);
    if (!thrd_ctrl->del_req_stat->req_stat) {
        return ULFS_ERROR_NOMEM;
    }
    memset(thrd_ctrl->del_req_stat->req_stat,
           0, sizeof(per_del_stat_t) * glb_size);
    rc = arraylist_add(thrd_list, thrd_ctrl);
    if (rc != 0) {
        return rc;
    }

    tmp_config->thrd_idxs[sock_id] = arraylist_size(thrd_list) - 1;
    tmp_config->client_ranks[sock_id] = local_rank_idx;
    tmp_config->dbg_ranks[sock_id] = dbg_rank; /*add debug rank*/

    invert_sock_ids[sock_id] = app_id;

    rc = attach_to_shm(tmp_config, app_id, sock_id);
    if (rc != ULFS_SUCCESS) {
        return rc;
    }

    rc = open_log_file(tmp_config, app_id, sock_id);
    if (rc < 0) {
        return rc;
    }

    thrd_ctrl->has_waiting_delegator = 0;
    thrd_ctrl->has_waiting_dispatcher = 0;
    rc = pthread_create(&(thrd_ctrl->thrd), NULL, rm_delegate_request_thread,
                        cli_signature);
    if (rc != 0) {
        return  ULFS_ERROR_THRDINIT;
    }

    return rc;
}

int f_setup_client(f_svcrq_t *pcmd) {
    int app_id = pcmd->app_id;
    int local_rank_idx = pcmd->cid;
    int dbg_rank = pcmd->dbg_rnk;
    int qid = pcmd->cid;

    app_config_t *tmp_config;
    /*if this client is from a new application, then
     * initialize this application's information
     * */

    int rc;
    if (arraylist_get(app_config_list, app_id) == NULL) {
        int  num_procs_per_node = pcmd->num_prc;
        int  req_buf_sz         = pcmd->rqbf_sz;
        int  recv_buf_sz        = pcmd->rcbf_sz;
        long superblock_sz      = pcmd->sblk_sz;
        long meta_offset        = pcmd->meta_of;
        long meta_size          = pcmd->meta_sz;
        long fmeta_offset       = pcmd->fmet_of;
        long fmeta_size         = pcmd->fmet_sz;
        long data_offset        = pcmd->data_of;
        long data_size          = pcmd->data_sz;

        LOG(LOG_DBG, 
            "superblock_sz:%ld, num_procs_per_node:%d, req_buf_sz:%d, data_size:%ld\n", 
            superblock_sz, num_procs_per_node, req_buf_sz, data_size);

        tmp_config = (app_config_t *)malloc(sizeof(app_config_t));
        memcpy(tmp_config->external_spill_dir, pcmd->ext_dir, MAX_PATH_LEN);

        /*don't forget to free*/
        tmp_config->num_procs_per_node = num_procs_per_node;
        tmp_config->req_buf_sz = req_buf_sz;
        tmp_config->recv_buf_sz = recv_buf_sz;
        tmp_config->superblock_sz = superblock_sz;

        tmp_config->meta_offset = meta_offset;
        tmp_config->meta_size = meta_size;

        tmp_config->fmeta_offset = fmeta_offset;
        tmp_config->fmeta_size = fmeta_size;

        tmp_config->data_offset = data_offset;
        tmp_config->data_size = data_size;

        int i;
        for (i = 0; i < MAX_NUM_CLIENTS; i++) {
            tmp_config->client_ranks[i] = -1;
            tmp_config->shm_recv_bufs[i] = NULL;
            tmp_config->shm_req_bufs[i] = NULL;
            tmp_config->shm_superblocks[i] = NULL;
            tmp_config->shm_superblock_fds[i] = -1;
            tmp_config->shm_recv_fds[i] = -1;
            tmp_config->shm_req_fds[i] = -1;
            tmp_config->spill_log_fds[i] = -1;
            tmp_config->spill_index_log_fds[i] = -1;
        }

        rc = arraylist_insert(app_config_list, app_id, tmp_config);
        if (rc != 0) {
            return rc;
        }
    } else {
        tmp_config = (app_config_t *)arraylist_get(app_config_list,
                     app_id);
    }
#if 0
    /* The following code attach a delegator thread
     * to this new connection */
    thrd_ctrl_t *thrd_ctrl =
        (thrd_ctrl_t *)malloc(sizeof(thrd_ctrl_t));
    memset(thrd_ctrl, 0, sizeof(thrd_ctrl_t));

    thrd_ctrl->exit_flag = 0;
    cli_signature_t *cli_signature =
        (cli_signature_t *)malloc(sizeof(cli_signature_t));
    cli_signature->app_id = app_id;
    cli_signature->qid = qid;
    rc = pthread_mutex_init(&(thrd_ctrl->thrd_lock), NULL);
    if (rc != 0) {
        return ULFS_ERROR_THRDINIT;
    }

    rc = pthread_cond_init(&(thrd_ctrl->thrd_cond), NULL);
    if (rc != 0) {
        return ULFS_ERROR_THRDINIT;
    }

    thrd_ctrl->del_req_set =
        (msg_meta_t *)malloc(sizeof(msg_meta_t));
    if (!thrd_ctrl->del_req_set) {
        return ULFS_ERROR_NOMEM;
    }
    memset(thrd_ctrl->del_req_set,
           0, sizeof(msg_meta_t));

    thrd_ctrl->del_req_stat =
        (del_req_stat_t *)malloc(sizeof(del_req_stat_t));
    if (!thrd_ctrl->del_req_stat) {
        return ULFS_ERROR_NOMEM;
    }
    memset(thrd_ctrl->del_req_stat, 0, sizeof(del_req_stat_t));

    thrd_ctrl->del_req_stat->req_stat =
        (per_del_stat_t *)malloc(sizeof(per_del_stat_t) * glb_size);
    if (!thrd_ctrl->del_req_stat->req_stat) {
        return ULFS_ERROR_NOMEM;
    }
    memset(thrd_ctrl->del_req_stat->req_stat,
           0, sizeof(per_del_stat_t) * glb_size);
    rc = arraylist_add(thrd_list, thrd_ctrl);
    if (rc != 0) {
        return rc;
    }

    tmp_config->thrd_idxs[qid] = arraylist_size(thrd_list) - 1;
#endif
    tmp_config->client_ranks[qid] = local_rank_idx;
    tmp_config->dbg_ranks[qid] = dbg_rank; /*add debug rank*/

    invert_qids[qid] = app_id;

    rc = attach_to_shm(tmp_config, app_id, qid);
    if (rc != ULFS_SUCCESS) {
        return rc;
    }

    rc = open_log_file(tmp_config, app_id, qid);
    if (rc < 0) {
        return rc;
    }

#if 0
    thrd_ctrl->has_waiting_delegator = 0;
    thrd_ctrl->has_waiting_dispatcher = 0;
    rc = pthread_create(&(thrd_ctrl->thrd), NULL, rm_delegate_request_thread,
                        cli_signature);
    if (rc != 0) {
        return  ULFS_ERROR_THRDINIT;
    }
#endif

    return rc;
}


/**
* attach to the client-side shared memory
* @param app_config: application information
* @param app_id: the server-side
* @param qid: position in poll_set in unifycr_sock.h
* @return success/error code
*/
int attach_to_shm(app_config_t *app_config, int app_id, int qid)
{
    int ret = 0;
    char shm_name[GEN_STR_LEN] = {0};

    int client_side_id = app_config->client_ranks[qid];

    /* attach shared superblock,
     * a superblock is created by each
     * client to store the raw file data.
     * The overflowed data are spilled to
     * SSD.
     * */
    sprintf(shm_name, "%d-super-%d", app_id, client_side_id);
    int tmp_fd = shm_open(shm_name,
                          MMAP_OPEN_FLAG, MMAP_OPEN_MODE);
    if (-1 == (ret = tmp_fd)) {
        return ULFS_ERROR_SHMEM;
    }
    ret = ftruncate(tmp_fd, app_config->superblock_sz);
    if (-1 == ret) {
        return ULFS_ERROR_SHMEM;
    }
    app_config->shm_superblock_fds[client_side_id] = tmp_fd;

    strcpy(app_config->super_buf_name[client_side_id], shm_name);
    app_config->shm_superblocks[client_side_id] =
        mmap(NULL, app_config->superblock_sz, PROT_READ | PROT_WRITE,
             MAP_SHARED, tmp_fd, SEEK_SET);
    if (NULL == app_config->shm_superblocks[client_side_id]) {
        return ULFS_ERROR_SHMEM;
    }

    /* attach shared request buffer,
     * a request buffer is created by each
     * client to convey the client-side read
     * request to the delegator
     * */
    sprintf(shm_name, "%d-req-%d", app_id, client_side_id);
    tmp_fd = shm_open(shm_name, MMAP_OPEN_FLAG, MMAP_OPEN_MODE);
    if (-1 == (ret = tmp_fd)) {
        return ULFS_ERROR_SHMEM;
    }

    ret = ftruncate(tmp_fd, app_config->req_buf_sz);
    if (-1 == ret) {
        return ULFS_ERROR_SHMEM;
    }
    app_config->shm_req_fds[client_side_id] = tmp_fd;

    strcpy(app_config->req_buf_name[client_side_id], shm_name);
    app_config->shm_req_bufs[client_side_id] = mmap(NULL,
            app_config->req_buf_sz, PROT_READ | PROT_WRITE,
            MAP_SHARED, tmp_fd, SEEK_SET);
    if (NULL == app_config->shm_req_bufs[client_side_id]) {
        return ULFS_ERROR_SHMEM;
    }


    /* initialize shared receive buffer,
     * a request buffer is created by each
     * client for the delegator to
     * temporarily buffer the received
     * data for this client
     *
     * */
    sprintf(shm_name, "%d-recv-%d", app_id, client_side_id);

    tmp_fd = shm_open(shm_name, MMAP_OPEN_FLAG, MMAP_OPEN_MODE);
    if (-1 == (ret = tmp_fd)) {
        return ULFS_ERROR_SHMEM;
    }
    ret = ftruncate(tmp_fd, app_config->recv_buf_sz);
    if (-1 == ret) {
        return ULFS_ERROR_SHMEM;
    }
    app_config->shm_recv_fds[client_side_id] = tmp_fd;

    strcpy(app_config->recv_buf_name[client_side_id], shm_name);
    app_config->shm_recv_bufs[client_side_id] =
        mmap(NULL, app_config->recv_buf_sz, PROT_READ | PROT_WRITE,
             MAP_SHARED, tmp_fd, SEEK_SET);
    if (NULL == app_config->shm_recv_bufs[client_side_id]) {
        return ULFS_ERROR_SHMEM;
    }

    return ULFS_SUCCESS;

}


/**
* open spilled log file, spilled log file
* is created once the client-side shared superblock
* overflows.
* @param app_config: application information
* @param app_id: the server-side application id
* @param qid: position in poll_set in unifycr_sock.h
* @return success/error code
*/
int open_log_file(app_config_t *app_config,
                  int app_id, int qid)
{
    int client_side_id = app_config->client_ranks[qid];
    char path[GEN_STR_LEN] = {0};
    sprintf(path, "%s/spill_%d_%d.log",
            app_config->external_spill_dir, app_id, client_side_id);
    app_config->spill_log_fds[client_side_id] = open(path, O_RDONLY, 0666);
    /*  LOG(LOG_DBG, "openning log file %s, client_side_id:%d\n",
                path, client_side_id);
    */
    strcpy(app_config->spill_log_name[client_side_id], path);
    if (app_config->spill_log_fds[client_side_id] < 0) {
        printf("rank:%d, openning file %s failure\n", glb_rank, path);
        fflush(stdout);
        return ULFS_ERROR_FILE;
    }

    sprintf(path, "%s/spill_index_%d_%d.log",
            app_config->external_spill_dir, app_id, client_side_id);
    app_config->spill_index_log_fds[client_side_id] =
        open(path, O_RDONLY, 0666);
    /*
        LOG(LOG_DBG, "openning index log file %s, client_side_id:%d\n",
                path, client_side_id);
    */
    strcpy(app_config->spill_index_log_name[client_side_id], path);
    if (app_config->spill_index_log_fds[client_side_id] < 0) {
        printf("rank:%d, openning index file %s failure\n", glb_rank, path);
        fflush(stdout);
        return ULFS_ERROR_FILE;
    }

    return ULFS_SUCCESS;
}

/**
* broad cast the exit command to all other
* delegators in the job
* @return success/error code
*/
int unifycr_broadcast_exit(int sock_id)
{
    int exit_cmd = XFER_COMM_EXIT, rc = ULFS_SUCCESS;
    int i;
    for (i = 0; i < glb_size; i++) {
        MPI_Send(&exit_cmd, sizeof(int), MPI_CHAR,
                 i,
                 CLI_DATA_TAG, MPI_COMM_WORLD);
    }

    int cmd = CMD_UNMOUNT;

    char *ptr_ack = sock_get_ack_buf(sock_id);
    int ret_sz = pack_ack_msg(ptr_ack, cmd, rc, NULL, 0);
    rc = sock_ack_cli(sock_id, ret_sz);
    return rc;
}
