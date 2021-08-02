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

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "unifycr_global.h"
#include "unifycr_sock.h"
#include "arraylist.h"
#include "unifycr_setup.h"
#include "unifycr_const.h"

int server_sockfd;
int num_fds = 0;

int thrd_pipe_fd[2] = {0};

struct pollfd poll_set[MAX_NUM_CLIENTS];
struct sockaddr_un server_address;
char cmd_buf[MAX_NUM_CLIENTS][GEN_STR_LEN];
char ack_buf[MAX_NUM_CLIENTS][GEN_STR_LEN];
int ack_msg[3] = {0};
int detached_qid = -1;
int cur_qid = -1;

/**
* initialize the listening socket on this delegator
* @return success/error code
*/
int sock_init_server(int local_rank_idx)
{
    int rc;

    char tmp_str[GEN_STR_LEN];

    sprintf(tmp_str, "%s%d", DEF_SOCK_PATH, local_rank_idx);
    server_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

    memset(&server_address, 0, sizeof(server_address));
    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, tmp_str);
    int server_len = sizeof(server_address);
    unlink(tmp_str);

    rc = bind(server_sockfd, (struct sockaddr *)&server_address,
              (socklen_t)server_len);
    if (rc != 0) {
        return -1;
    }
    chmod(tmp_str, 0777);

    rc = listen(server_sockfd, MAX_NUM_CLIENTS);
    if (rc != 0) {
        return -1;
    }

    int flag = fcntl(server_sockfd, F_GETFL);
    fcntl(server_sockfd, F_SETFL, flag | O_NONBLOCK);
    poll_set[0].fd = server_sockfd; //add
    poll_set[0].events = POLLIN | POLLHUP;
    poll_set[0].revents = 0;
    num_fds++;

    return 0;


}

int sock_add(int fd)
{
    if (num_fds == MAX_NUM_CLIENTS) {
        return -1;
    }
    int flag = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flag | O_NONBLOCK);
    poll_set[num_fds].fd = fd;
    poll_set[num_fds].events = POLLIN | POLLHUP;
    poll_set[num_fds].revents = 0;
    num_fds++;
    return 0;
}

void sock_reset()
{
    int i;

    for (i = 0; i < num_fds; i++) {
        poll_set[i].events = POLLIN | POLLPRI;
        poll_set[i].revents = 0;
    }
}

int sock_remove(int idx)
{
    /* in this case, we simply disable the disconnected
     * file descriptor. */
    poll_set[idx].fd = -1;
    return 0;
}

/*
 * send command to the client to let the client digest the
 * data in the shared receive buffer
 * @param: qid: socket index in poll_set
 * @param: cmd: command type
 *
 * */
int sock_notify_cli(int qid, int cmd)
{
    memcpy(ack_buf[qid], &cmd, sizeof(int));
    int rc = write(poll_set[qid].fd,
                   ack_buf[qid], sizeof(ack_buf[qid]));

    if (rc < 0) {
        return ULFS_ERROR_WRITE;
    }
    return ULFS_SUCCESS;
}


/*
 * wait for the client-side command
 * */

int sock_wait_cli_cmd()
{
    int rc, i;

    sock_reset();
    rc = poll(poll_set, num_fds, -1);
    if (rc <= 0) {
        return ULFS_ERROR_TIMEOUT;
    } else {
        for (i = 0; i < num_fds; i++) {
            if (poll_set[i].fd != -1 && poll_set[i].revents != 0) {
                if (i == 0 && poll_set[i].revents == POLLIN) {
                    int client_len = sizeof(struct sockaddr_un);

                    struct sockaddr_un client_address;
                    int client_sockfd = accept(server_sockfd,
                                               (struct sockaddr *)&client_address,
                                               (socklen_t *)&client_len);
                    rc = sock_add(client_sockfd);
                    if (rc < 0) {
                        return ULFS_SOCKETFD_EXCEED;
                    } else {
                        cur_qid = i;
                        return ULFS_SUCCESS;
                    }
                } else if (i != 0 && poll_set[i].revents == POLLIN) {
                    int bytes_read = read(poll_set[i].fd,
                                          cmd_buf[i], GEN_STR_LEN);
                    if (bytes_read == 0) {
                        sock_remove(i);
                        detached_qid = i;
                        return ULFS_SOCK_DISCONNECT;
                    }
                    cur_qid = i;
                    return ULFS_SUCCESS;
                } else {
                    if (i == 0) {
                        return ULFS_SOCK_LISTEN;
                    } else {
                        detached_qid = i;
                        if (i != 0 && poll_set[i].revents == POLLHUP) {
                            sock_remove(i);
                            return ULFS_SOCK_DISCONNECT;
                        } else {
                            sock_remove(i);
                            return ULFS_SOCK_OTHER;

                        }
                    }
                }
            }
        }
    }

    return ULFS_SUCCESS;

}

int sock_ack_cli(int qid, int ret_sz)
{
    int rc = write(poll_set[qid].fd,
                   ack_buf[qid], ret_sz);
    if (rc < 0) {
        return ULFS_SOCK_OTHER;
    }
    return ULFS_SUCCESS;
}

int sock_handle_error(int sock_error_no)
{
    return ULFS_SUCCESS;
}

int sock_get_error_id()
{
    return detached_qid;
}

char *sock_get_cmd_buf(int qid)
{
    return cmd_buf[qid];
}

char *sock_get_ack_buf(int qid)
{
    return (char *)ack_buf[qid];
}

int sock_get_id()
{
    return cur_qid;
}

int sock_sanitize()
{
    int i;
    for (i = 0; i < num_fds; i++) {
        if (poll_set[i].fd > 0) {
            close(poll_set[i].fd);
        }
    }

    char tmp_str[GEN_STR_LEN] = {0};
    sprintf(tmp_str, "%s%d", DEF_SOCK_PATH, local_rank_idx);
    unlink(tmp_str);
    return 0;
}
