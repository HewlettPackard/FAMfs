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

#include <mpi.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <signal.h>

#include "famfs_global.h"
#include "unifycr_metadata.h"
#include "log.h"
#include "unifycr_debug.h"
#include "unifycr_sock.h"
#include "unifycr_init.h"
#include "unifycr_const.h"
#include "arraylist.h"
#include "unifycr_global.h"
#include "unifycr_cmd_handler.h"
#include "unifycr_service_manager.h"
#include "unifycr_request_manager.h"
#include "famfs_env.h"
#include "famfs_error.h"
#include "famfs_maps.h"
#include "lf_client.h"
#include "famfs_rbq.h"
#include "f_pool.h"
#include "f_layout.h"
#include "famfs_maps.h"
#include "f_allocator.h"
#include "mpi_utils.h"


int *local_rank_lst;
int local_rank_cnt;
int local_rank_idx;
int glb_rank, glb_size;
int fam_fs = -1;

arraylist_t *app_config_list;
pthread_t data_thrd;
arraylist_t *thrd_list;

int invert_qids[MAX_NUM_CLIENTS]; /*records app_id for each qid*/
int log_print_level = LOG_WARN;

unifycr_cfg_t server_cfg;
static LFS_CTX_t *lfs_ctx_p = NULL;

extern char *mds_vec;
extern int  num_mds;

f_rbq_t *rplyq[MAX_NUM_CLIENTS];
f_rbq_t *cmdq[F_CMDQ_MAX];
f_rbq_t *admq;
volatile int exit_flag = 0;

static int make_node_vec(char **vec_p, int wsize, int rank, int is_member) {
    int i, n = 0;
    char *vec;

    if (!(vec = malloc(wsize))) {
        LOG(LOG_ERR, "memory error");
        return -1;
    }
    memset(vec, 0, wsize);
    MPI_Barrier(MPI_COMM_WORLD);
    vec[rank] = (char) is_member;
    ON_ERROR(MPI_Allgather(MPI_IN_PLACE, 1, MPI_BYTE,
             vec, 1, MPI_BYTE, MPI_COMM_WORLD),
            "MPI_Allgather");
    for (i = 0; i < wsize; i++) {
        if (vec[i] < 0) {
            free(vec);
            return 0;
        } else if (vec[i]) {
            n++;
        }
    }
    if (rank == 0) {
        char buf[1024];
        int l = snprintf(buf, sizeof(buf), "MDS rank(s): ");
        for (i = 0; i < wsize; i++)
            if (vec[i])
                l += snprintf(&buf[l], sizeof(buf), "%d ", i);
        LOG(LOG_INFO, "%s\n", buf);
    }
    *vec_p = vec;
    return n;
}

volatile int sm_ready = 0;
extern int num_fds;
long max_recs_per_slice;

int main(int argc, char *argv[])
{
    F_POOL_t *pool;
    mdhim_options_t *db_opts = NULL;
    char dbg_fname[GEN_STR_LEN] = {0};
    int provided;
    int rc;
    bool daemon;
    long l;
    f_svcrq_t acmd;
    char qname[MAX_RBQ_NAME];
    pthread_t lo_thrd[F_CMDQ_MAX];

    rc = unifycr_config_init(&server_cfg, argc, argv);
    if (rc != 0)
	exit(1);

    rc = configurator_int_val(server_cfg.log_verbosity , &l);
    if (rc != 0)
	exit(1);
    log_print_level = (int)l;

    rc = configurator_bool_val(server_cfg.unifycr_daemonize, &daemon);
    if (rc != 0)
	exit(1);
    if (daemon)
	daemonize();

    rc = MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &provided);

    if (rc != MPI_SUCCESS)
        exit(1);

    rc = MPI_Comm_rank(MPI_COMM_WORLD, &glb_rank);
    if (rc != MPI_SUCCESS)
        exit(1);

    rc = MPI_Comm_size(MPI_COMM_WORLD, &glb_size);
    if (rc != MPI_SUCCESS)
        exit(1);

    rc = CountTasksPerNode(glb_rank, glb_size);
    if (rc < 0)
        exit(1);

    if ((rc = f_set_layouts_info(&server_cfg)) ||
	(rc = create_lfs_ctx(&lfs_ctx_p)))
    {
        printf("srv failed to load configuration: %d\n", rc);
        return rc;
    }
    pool = lfs_ctx_p->pool;
    /* DEBUG */
    if (log_print_level > 0 && glb_rank == 0) {
	unifycr_config_print(&server_cfg, NULL);
	printf("%s\n", pool->mynode.hostname);
	f_print_layouts();
	printf("\n");
    }

    /* Create MPI communicator for IO nodes */
    pool->zero_ion_rank = mpi_split_world(&pool->ionode_comm,
				NodeIsIOnode(&pool->mynode), 1,
				glb_rank, glb_size);
    assert( pool->zero_ion_rank >= 0 );

    local_rank_idx = find_rank_idx(glb_rank, local_rank_lst, local_rank_cnt);

    /* UNIFYCR_DEFAULT_LOG_FILE */
    if (server_cfg.log_file == NULL)
        exit(1);
    sprintf(dbg_fname, "%s-%d", server_cfg.log_file, glb_rank);

    rc = dbg_open(dbg_fname);
    if (rc != ULFS_SUCCESS)
        LOG(LOG_ERR, "%s", ULFS_str_errno(rc));

    rc = meta_init_conf(&server_cfg, &db_opts);
    if (rc != 0) {
        LOG(LOG_ERR, "%s", ULFS_str_errno(ULFS_ERROR_MDINIT));
        exit(1);
    }

    app_config_list = arraylist_create();
    if (app_config_list == NULL) {
        LOG(LOG_ERR, "%s", ULFS_str_errno(ULFS_ERROR_NOMEM));
        exit(1);
    }

    thrd_list = arraylist_create();
    if (thrd_list == NULL) {
        LOG(LOG_ERR, "%s", ULFS_str_errno(ULFS_ERROR_NOMEM));
        exit(1);
    }

    /* Create admin queue on all nodes */
    sprintf(qname, "%s-admin", F_CMDQ_NAME);
    if ((rc = f_rbq_create(qname, sizeof(f_svcrq_t), F_MAX_CMDQ, &admq, 1))) {
        LOG(LOG_ERR, "rbq %s create: %s", qname, strerror(rc = errno));
        exit(rc);
    }

    if (pool->info.layouts_count > F_CMDQ_MAX) {
        LOG(LOG_ERR, "too many layouts, not enough work queues");
        exit(1);
    }

    /* Create command queues and start layout threads only on compute nodes */
    bzero(rplyq, sizeof(rplyq));
    if (!f_host_is_ionode(NULL) || NodeForceHelper(&pool->mynode)) {

        bzero(lo_thrd, sizeof(lo_thrd));
        for (int i = 0; i < pool->info.layouts_count; i++) {
            F_LAYOUT_t *lo = f_get_layout(i);
            if (lo == NULL) {
                LOG(LOG_ERR, "get layout [%d] info\n", i);
                exit(1);
            }
            sprintf(qname, "%s-%s", F_CMDQ_NAME, lo->info.name);
            if ((rc = f_rbq_create(qname, sizeof(f_svcrq_t), F_MAX_CMDQ, &cmdq[i], 1))) {
                LOG(LOG_ERR, "rbq %s create: %s", qname, strerror(rc = errno));
                exit(rc);
            }
            LOG(LOG_INFO, "layout %d:%s queue %s created", i, lo->info.name, qname);
            if ((rc = pthread_create(&lo_thrd[i], NULL, f_command_thrd, cmdq[i]))) {
                LOG(LOG_ERR, "LO %s svc thread create failed", lo->info.name);
                exit(rc);
            }
        }
    }

    /* we DO NOT support multiple instances of famfs demon on one node */
    ASSERT(local_rank_idx == 0);

#if 0
    rc = sock_init_server(local_rank_idx);
    if (rc != 0) {
        LOG(LOG_ERR, "%s", ULFS_str_errno(ULFS_ERROR_SOCKET));
        exit(1);
    }
#endif

    if ((rc = make_node_vec(&mds_vec, glb_size, glb_rank,
			    NodeHasMDS(&pool->mynode))) > 0)
    {
        LOG(LOG_INFO, "MDS vector constructed with %d members\n", rc);
        num_mds = rc;
    } else if (rc < 0) {
        LOG(LOG_ERR, "Error obtaining MDS vector");
    } else {
        num_mds = 0;
    }


    /* Fork LF server process if FAM emulation is required */
    if (PoolFAMEmul(pool)) {
	rc = lfs_emulate_fams(glb_rank, glb_size, lfs_ctx_p);
	if (rc) {
	    LOG(LOG_ERR, "%d/%d: Failed to start FAM emulation: %d",
		glb_rank, glb_size, rc);
		exit(1);
	}
    }

    /*launch the service manager*/
    rc = pthread_create(&data_thrd, NULL, sm_service_reads, NULL);
    if (rc != 0) {
        LOG(LOG_ERR, "%s", ULFS_str_errno(ULFS_ERROR_THRDINIT));
        exit(1);
    }

/* f_rbq
    rc = sock_wait_cli_cmd();
    if (rc != ULFS_SUCCESS) {
        int ret = sock_handle_error(rc);
        if (ret != 0) {
            LOG(LOG_ERR, "%s",
                ULFS_str_errno(ret));
            exit(1);
        }
    } else {
        int qid = sock_get_id();
        if (qid != 0) {
            exit(1);
        }
    }
*/
    while (!sm_ready)
        usleep(10);

    /*wait for the service manager to connect to the
     *request manager so that they can exchange control
     *information*/
    if (log_print_level > 0) {
        printf("unifycrd is running\n");
    }

    rc = meta_init_store(db_opts);
    if (rc != 0) {
        LOG(LOG_ERR, "%s", ULFS_str_errno(ULFS_ERROR_MDINIT));
        exit(1);
    }
    max_recs_per_slice = db_opts->max_recs_per_slice;

    rc = meta_register_fam(lfs_ctx_p);
    if (rc != ULFS_SUCCESS) {
	LOG(LOG_ERR, "%s reg FAM", ULFS_str_errno(rc));
	exit(1);
    }

    MPI_Barrier(MPI_COMM_WORLD);
    {
        char fname[256];
        sprintf(fname, "/tmp/unifycrd.running.%d", getpid());
        int flag = open(fname, O_RDWR | O_CREAT, 0644);
        close(flag);
    }

    /* Start allocator threads on IO nodes only */
    if (NodeIsIOnode(&pool->mynode)) {
	rc = f_start_allocator_threads();
    	if (rc != ULFS_SUCCESS) {
	    LOG(LOG_WARN, "%s starting allocator threads", ULFS_str_errno(rc));
    	}
    }

    while (1) {
        if (exit_flag) {
            LOG(LOG_INFO, "exit flag set");
            break;
        }
        if ((rc = f_rbq_pop(admq, &acmd, RBQ_TMO_4EVER))) {
            LOG(LOG_FATAL, "svc rbq pop failed: %s(%d)", strerror(errno), rc);
            exit(1);
        }
        
        if ((rc = f_srv_process_cmd(&acmd, admq->rbq->name, 1))) {
            LOG(LOG_ERR, "%s", ULFS_str_errno(rc));
            continue;
        }
    }

#if 0
    while (1) {
        rc = sock_wait_cli_cmd();
        if (rc != ULFS_SUCCESS) {
            int qid = sock_get_error_id();
            if (qid == 1) {
                /* received exit command from the
                 * service manager
                 * thread.
                 * */
                unifycr_exit();
                break;
            }

            int ret = sock_handle_error(rc);
            if (ret != 0) {
                LOG(LOG_ERR, "%s",
                    ULFS_str_errno(ret));
                exit(1);
            }

        } else {
            int qid = sock_get_id();
            /*qid is 0 if it is a listening socket*/
            if (qid != 0) {
                char *cmd = sock_get_cmd_buf(qid);
                int cmd_rc = delegator_handle_command(cmd, qid,
						db_opts->max_recs_per_slice);
                if (cmd_rc != ULFS_SUCCESS) {
                    LOG(LOG_ERR, "%s",
                        ULFS_str_errno(cmd_rc));
                    return cmd_rc;
                }
            }
        }

    }
#endif

    unifycr_exit();

    MPI_Barrier(MPI_COMM_WORLD);
    MPI_Finalize();
    return 0;
}

/**
* count the number of delegators per node, and
* the rank of each delegator, the results are stored
* in local_rank_cnt and local_rank_lst.
* @param numTasks: number of processes in the communicator
* @return success/error code, local_rank_cnt and local_rank_lst.
*/
static int CountTasksPerNode(int rank, int numTasks)
{
    char       localhost[ULFS_MAX_FILENAME];
    char       hostname[ULFS_MAX_FILENAME];
    int        resultsLen = ULFS_MAX_FILENAME;

    MPI_Status status;
    int rc;

    rc = MPI_Get_processor_name(localhost, &resultsLen);
    if (rc != 0) {
        return -1;
    }

    int i;
    if (numTasks > 0) {
        if (rank == 0) {
            /* a container of (rank, host) mappings*/
            name_rank_pair_t *host_set =
                (name_rank_pair_t *)malloc(numTasks
                                           * sizeof(name_rank_pair_t));
            /* MPI_receive all hostnames, and compare to local hostname */
            for (i = 1; i < numTasks; i++) {
                rc = MPI_Recv(hostname, ULFS_MAX_FILENAME,
                              MPI_CHAR, MPI_ANY_SOURCE,
                              MPI_ANY_TAG,
                              MPI_COMM_WORLD, &status);

                if (rc != 0) {
                    return -1;
                }
                strcpy(host_set[i].hostname, hostname);
                host_set[i].rank = status.MPI_SOURCE;
            }
            strcpy(host_set[0].hostname, localhost);
            host_set[0].rank = 0;

            /*sort according to the hostname*/
            qsort(host_set, numTasks, sizeof(name_rank_pair_t),
                  compare_name_rank_pair);

            /* rank_cnt: records the number of processes on each node
             * rank_set: the list of ranks for each node
             * */
            int **rank_set = (int **)malloc(numTasks * sizeof(int *));
            int *rank_cnt = (int *)malloc(numTasks * sizeof(int));

            int cursor = 0, set_counter = 0;
            for (i = 1; i < numTasks; i++) {
                if (strcmp(host_set[i].hostname,
                           host_set[i - 1].hostname) == 0) {
                    /*do nothing*/
                } else {
                    // find a different rank, so switch to a new set
                    int j, k = 0;
                    rank_set[set_counter] =
                        (int *)malloc((i - cursor) * sizeof(int));
                    rank_cnt[set_counter] = i - cursor;
                    for (j = cursor; j <= i - 1; j++) {

                        rank_set[set_counter][k] =  host_set[j].rank;
                        k++;
                    }

                    set_counter++;
                    cursor = i;
                }

            }


            /*fill rank_cnt and rank_set entry for the last node*/
            int j = 0;

            rank_set[set_counter] =
                (int *)malloc((i - cursor) * sizeof(int));
            rank_cnt[set_counter] = numTasks - cursor;
            for (i = cursor; i <= numTasks - 1; i++) {
                rank_set[set_counter][j] = host_set[i].rank;
                j++;
            }
            set_counter++;

            /*broadcast the rank_cnt and rank_set information to each
             * rank*/
            int root_set_no = -1;
            for (i = 0; i < set_counter; i++) {
                for (j = 0; j < rank_cnt[i]; j++) {
                    if (rank_set[i][j] != 0) {
                        rc = MPI_Send(&rank_cnt[i], 1,
                                      MPI_INT, rank_set[i][j], 0, MPI_COMM_WORLD);
                        if (rc != 0) {
                            return -1;
                        }



                        /*send the local rank set to the corresponding rank*/
                        rc = MPI_Send(rank_set[i], rank_cnt[i],
                                      MPI_INT, rank_set[i][j], 0, MPI_COMM_WORLD);
                        if (rc != 0) {
                            return -1;
                        }
                    } else {
                        root_set_no = i;
                    }
                }
            }


            /* root process set its own local rank set and rank_cnt*/
            if (root_set_no >= 0) {
                local_rank_lst = malloc(rank_cnt[root_set_no] * sizeof(int));
                for (i = 0; i < rank_cnt[root_set_no]; i++)
                    local_rank_lst[i] = rank_set[root_set_no][i];
                local_rank_cnt = rank_cnt[root_set_no];
            }

            for (i = 0; i < set_counter; i++) {
                free(rank_set[i]);
            }
            free(rank_cnt);
            free(host_set);
            free(rank_set);

        } else {
            /* non-root process performs MPI_send to send
             * hostname to root node */
            rc = MPI_Send(localhost, ULFS_MAX_FILENAME, MPI_CHAR, 0, 0, MPI_COMM_WORLD);
            if (rc != 0) {
                return -1;
            }
            /*receive the local rank count */
            rc = MPI_Recv(&local_rank_cnt, 1, MPI_INT, 0,
                          0, MPI_COMM_WORLD, &status);
            if (rc != 0) {
                return -1;
            }

            /* receive the the local rank list */
            local_rank_lst = (int *)malloc(local_rank_cnt * sizeof(int));
            rc = MPI_Recv(local_rank_lst, local_rank_cnt, MPI_INT, 0,
                          0, MPI_COMM_WORLD, &status);
            if (rc != 0) {
                free(local_rank_lst);
                return -1;
            }

        }

        qsort(local_rank_lst, local_rank_cnt, sizeof(int),
              compare_int);

        // scatter ranks out
    } else {
        return -1;
    }

    return 0;
}

static int find_rank_idx(int my_rank,
                         int *local_rank_lst, int local_rank_cnt)
{
    int i;
    for (i = 0; i < local_rank_cnt; i++) {
        if (local_rank_lst[i] == my_rank) {
            return i;
        }
    }

    return -1;

}

static int compare_int(const void *a, const void *b)
{
    const int *ptr_a = a;
    const int *ptr_b = b;

    if (*ptr_a - *ptr_b > 0)
        return 1;

    if (*ptr_a - *ptr_b < 0)
        return -1;

    return 0;
}

static int compare_name_rank_pair(const void *a, const void *b)
{
    const name_rank_pair_t *pair_a = a;
    const name_rank_pair_t *pair_b = b;

    if (strcmp(pair_a->hostname, pair_b->hostname) > 0)
        return 1;

    if (strcmp(pair_a->hostname, pair_b->hostname) < 0)
        return -1;

    return 0;
}

static int unifycr_exit()
{
    int rc = ULFS_SUCCESS;

    /* notify the threads of request manager to exit*/
    int i, j;
    for (i = 0; i < arraylist_size(thrd_list); i++) {
        thrd_ctrl_t *tmp_ctrl =
            (thrd_ctrl_t *)arraylist_get(thrd_list, i);
        pthread_mutex_lock(&tmp_ctrl->thrd_lock);

        if (!tmp_ctrl->has_waiting_delegator) {
            tmp_ctrl->has_waiting_dispatcher = 1;
            pthread_cond_wait(&tmp_ctrl->thrd_cond, &tmp_ctrl->thrd_lock);
            tmp_ctrl->exit_flag = 1;
            tmp_ctrl->has_waiting_dispatcher = 0;
            free(tmp_ctrl->del_req_set);
            free(tmp_ctrl->del_req_stat->req_stat);
            free(tmp_ctrl->del_req_stat);
            pthread_cond_signal(&tmp_ctrl->thrd_cond);

        } else {
            tmp_ctrl->exit_flag = 1;

            free(tmp_ctrl->del_req_set);
            free(tmp_ctrl->del_req_stat->req_stat);
            free(tmp_ctrl->del_req_stat);

            pthread_cond_signal(&tmp_ctrl->thrd_cond);
        }
        pthread_mutex_unlock(&tmp_ctrl->thrd_lock);

        void *status;
        pthread_join(tmp_ctrl->thrd, &status);
    }

    arraylist_free(thrd_list);

    /* sanitize the shared memory and delete the log files
     * */
    int app_sz = arraylist_size(app_config_list);

    for (i = 0; i < app_sz; i++) {
        app_config_t *tmp_app_config =
            (app_config_t *)arraylist_get(app_config_list, i);

        for (j = 0; j < MAX_NUM_CLIENTS; j++) {
            if (tmp_app_config != NULL &&
                tmp_app_config->shm_req_fds[j] != -1) {
                shm_unlink(tmp_app_config->req_buf_name[j]);
            }

            if (tmp_app_config != NULL &&
                tmp_app_config->shm_recv_fds[j] != -1) {
                shm_unlink(tmp_app_config->recv_buf_name[j]);

            }

            if (tmp_app_config != NULL &&
                tmp_app_config->shm_superblock_fds[j] != -1) {
                shm_unlink(tmp_app_config->super_buf_name[j]);
            }

            if (tmp_app_config != NULL &&
                tmp_app_config->spill_log_fds[j] > 0) {
                close(tmp_app_config->spill_log_fds[j]);
                unlink(tmp_app_config->spill_log_name[j]);

            }

            if (tmp_app_config != NULL &&
                tmp_app_config->spill_index_log_fds[j] > 0) {
                close(tmp_app_config->spill_index_log_fds[j]);
                unlink(tmp_app_config->spill_index_log_name[j]);

            }
        }
    }

    exit_flag = 1;
    f_svcrq_t c = {.opcode = CMD_QUIT, .cid = 0};
    F_POOL_t *pool;
    pool = f_get_pool();
    for (int i = 0; i < pool->info.layouts_count; i++)
        if (cmdq[i])
            f_rbq_push(cmdq[i], &c, RBQ_TMO_1S);

    for (int i = 0; i < pool->info.layouts_count; i++)
        if (cmdq[i])
            if ((rc = f_rbq_destroy(cmdq[i]))) 
    

    for (int i = 0; i < MAX_NUM_CLIENTS; i++)
        if (rplyq[i])
            f_rbq_close(rplyq[i]);

    f_rbq_destroy(admq);

    if (NodeIsIOnode(&pool->mynode)) {
	f_stop_allocator_threads();
    }

    /* shutdown the metadata service */
    meta_sanitize(); /* mdhim_options_destroy(db_opts) */
    /* notify the service threads to exit*/

    /* destroy the sockets except for the ones
     * for acks*/
    sock_sanitize();

    /* Close FAM emulation fabric */
    free_lfs_ctx(&lfs_ctx_p);

    /* Free pool and all layout structures */
    f_free_layouts_info();

    /* Allocated at main(): free unifycr_cfg_t */
    unifycr_config_free(&server_cfg);

    return rc;
}

