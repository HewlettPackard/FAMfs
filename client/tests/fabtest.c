/*
 * Copyright (C) 2017-2018 Hewlett Packard Enterprise Development LP.
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <zhpeq_util_fab.h>

#include <rdma/fi_ext_zhpe.h>

#include <mpi.h>

struct args {
    uint64_t            nfams;
    uint64_t            fam_size;
    uint64_t            step_size;
    char                **nodes;
    char                **ports;
    int                 do_warm_up;
    int			use_fam;
};

struct stuff {
    const struct args   *args;
    struct fab_dom      fab_dom;
    struct fab_conn     fab_conn;
    bool                allocated;
};

static void stuff_free(struct stuff *stuff)
{
    if (!stuff)
        return;

    fab_conn_free(&stuff->fab_conn);
    fab_dom_free(&stuff->fab_dom);

    if (stuff->allocated)
        free(stuff);
}

static ssize_t do_progress(struct fid_cq *cq, size_t *cmp)
{
    ssize_t             ret = 0;
    ssize_t             rc;

    /* Check both tx and rx sides to make progress.
     * FIXME: Should rx be necessary for one-sided?
     */
    rc = fab_completions(cq, 0, NULL, NULL);
    if (rc >= 0)
        *cmp += rc;
    else
        ret = rc;

    return ret;
}


static int do_fam(const struct args *args, int rank, int cnt)
{
    int                 ret = -FI_ENOMEM;
    struct stuff        conn = {
            .args = args,
    };
    struct fab_dom      *fab_dom = &conn.fab_dom;
    struct fab_conn     *fab_conn = &conn.fab_conn;
    void                **fam_sa = NULL;
    fi_addr_t           *fam_addr = NULL;
    char                *url = NULL;
    size_t              tx_op = 0;
    size_t              tx_cmp = 0;
    size_t              sa_len;
    struct fi_zhpe_ext_ops_v1 *ext_ops;
    size_t              i;
    size_t              off, chunk_sz = args->fam_size/args->nfams;
    uint64_t            *v;
    //size_t              exp;
    struct fi_info      *fi;
    int                 rc;
    struct timeval      ts_beg, ts_end;
    double              tx_time, tx_bw, max_time, min_time, agg_bw, max_bw, min_bw;

    fam_sa = calloc(args->nfams, sizeof(*fam_sa));
    fam_addr = calloc(args->nfams, sizeof(*fam_addr));
    if (!fam_sa || !fam_addr)
        goto done;
    fab_dom_init(fab_dom);
    fab_conn_init(fab_dom, fab_conn);

    ret = fab_dom_setup(NULL, NULL, true, "zhpe", NULL, FI_EP_RDM, fab_dom);
    if (ret < 0)
        goto done;
    ret = fab_ep_setup(fab_conn, NULL, 0, 0);
    if (ret < 0)
        goto done;
    ret = fab_mrmem_alloc(fab_conn, &fab_conn->mrmem, chunk_sz*args->nfams, 0);
    if (ret < 0)
        goto done;
    v = (void *)fab_conn->mrmem.mem;


    if (!args->nodes || args->use_fam) {
        /* This is where it gets new. */
        ret = fi_open_ops(&fab_dom->fabric->fid, FI_ZHPE_OPS_V1, 0,
                          (void **)&ext_ops, NULL);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "fi_open_ops", FI_ZHPE_OPS_V1, ret);
            goto done;
        }
    }
    for (i = 0; i < args->nfams; i++) {
        if (!args->nodes) {
            if (zhpeu_asprintf(&url, "zhpe:///fam%Lu", (ullong)i) == -1) {
                ret = -FI_ENOMEM;
                goto done;
            }
            ret = ext_ops->lookup(url, &fam_sa[i], &sa_len);
            if (ret < 0) {
                print_func_err(__func__, __LINE__, "ext_ops.lookup", url, ret);
                goto done;
            }
            free(url);
            url = NULL;
	} else if (args->use_fam) {
            if (zhpeu_asprintf(&url, "zhpe:///%s", args->nodes[i]) < 0) {
                ret = -FI_ENOMEM;
                goto done;
            }
            ret = ext_ops->lookup(url, &fam_sa[i], &sa_len);
            if (ret < 0) {
                print_func_err(__func__, __LINE__, "ext_ops.lookup", url, ret);
                goto done;
            }
            free(url);
            url = NULL;
        } else {
            struct fi_info  *hints, *info;

            hints = fi_allocinfo();
            hints->caps = (FI_RMA | FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE);
            hints->mode = (FI_LOCAL_MR | FI_RX_CQ_DATA | FI_CONTEXT | FI_CONTEXT2);
            hints->domain_attr->mr_mode = FI_MR_BASIC;
            hints->addr_format = FI_SOCKADDR;
            hints->domain_attr->data_progress = FI_PROGRESS_MANUAL;
            ret = fi_getinfo(FAB_FIVERSION, args->nodes[i], args->ports[i], 0, hints, &fi);
            if (ret < 0) {
                print_func_fi_err(__func__, __LINE__, "fi_getinfo", "", ret);
                goto done;
            }
            for (info = fi; info; info = info->next) {
                if (!info->fabric_attr || !info->fabric_attr->prov_name || 
                        strcmp(info->fabric_attr->prov_name, "zhpe"))
                    continue;
                if (info->dest_addr) {
                    //printf("@%s dest addr[%ld]: %lx\n", args->nodes[i], i, *(unsigned long *)fi->dest_addr);
                    break;
                }
            }
            if (!info) {
                printf("@%s dest addr[%ld] not found\n", args->nodes[i], i);
                fi_freeinfo(fi);
                fi_freeinfo(hints);
                goto done;
            }  else {
                fam_sa[i] = info->dest_addr;
            }
            fi_freeinfo(hints);
        }
        ret = fi_av_insert(fab_dom->av, fam_sa[i], 1,  &fam_addr[i], 0, NULL);
        if (ret != 1) {
            print_err("%s,%u:fi_av_insert() returned %d\n",
                      __func__, __LINE__, ret);
            ret = -FI_EINVAL;
            goto done;
        }
        fi_freeinfo(fi);
    }

    int wup = args->do_warm_up;
    do {
        if (!wup) {
            if (rank == 0)
                printf("Writing...\n");
            MPI_Barrier(MPI_COMM_WORLD);
            gettimeofday(&ts_beg, NULL);
        } else if (rank == 0)
            printf("Warming up...\n");

        for (off = 0; off < chunk_sz; off += args->step_size) {
            for (i = 0; i < args->nfams; i++) {
                for (;;) {
                    char *bufp = (char *)v + chunk_sz*i + off;
                    ret = fi_write(fab_conn->ep, bufp, args->step_size,
                                   fi_mr_desc(fab_conn->mrmem.mr), fam_addr[i],
                                   rank*chunk_sz + off, args->use_fam ? 0 : i + 1 /* FI_ZHPE_FAM_RKEY */, NULL);
                    if (ret >= 0)
                        break;
                    if (ret != -FI_EAGAIN) {
                        print_func_err(__func__, __LINE__, "fi_write", "", ret);
                        goto done;
                    }
                    if ((rc = do_progress(fab_conn->tx_cq, &tx_cmp)) < 0) {
                        print_func_err(__func__, __LINE__, "do_progress(w)", "", rc);
                        goto done;
                    }
                }
                tx_op++;
                while (tx_cmp != tx_op) 
                    if ((rc = do_progress(fab_conn->tx_cq, &tx_cmp)) < 0) {
                        print_func_err(__func__, __LINE__, "do_progress(w)", "", rc);
                        goto done;
                    }
            }
        }
    } while (wup--);
    gettimeofday(&ts_end, NULL);
    
    MPI_Barrier(MPI_COMM_WORLD);
    tx_time = (1000000.0*(ts_end.tv_sec - ts_beg.tv_sec) + ts_end.tv_usec - ts_beg.tv_usec)/1000000.0;
    tx_bw = (double)args->fam_size/1048576.0/tx_time;
    MPI_Reduce(&tx_time, &max_time, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);
    MPI_Reduce(&tx_time, &min_time, 1, MPI_DOUBLE, MPI_MIN, 0, MPI_COMM_WORLD);
    MPI_Reduce(&tx_bw, &agg_bw, 1, MPI_DOUBLE, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(&tx_bw, &max_bw, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);
    MPI_Reduce(&tx_bw, &min_bw, 1, MPI_DOUBLE, MPI_MIN, 0, MPI_COMM_WORLD);
    tx_bw =(double)args->fam_size*cnt/1048576.0/max_time;
    if (rank == 0)
        printf("Write: Real BW %.3lfMiB/s, Agg BW %.3lfMiB/s\n    Max time %.3lfs, Min time %.3lfs\n    Min BW %.3lfMiB/s Max BW %.3lfMiB/s\n",
                tx_bw, agg_bw, max_time, min_time, min_bw, max_bw);

    if (rank == 0)
        printf("Reading...\n");
    MPI_Barrier(MPI_COMM_WORLD);
    gettimeofday(&ts_beg, NULL);

    for (off = 0; off < chunk_sz; off += args->step_size) {
        for (i = 0; i < args->nfams; i++) {
            for (;;) {
                char *bufp = (char *)v + chunk_sz*i + off;
                ret = fi_read(fab_conn->ep, bufp, args->step_size,
                              fi_mr_desc(fab_conn->mrmem.mr), fam_addr[i],
                              rank*chunk_sz + off, args->use_fam ? 0 : i + 1 /* FI_ZHPE_FAM_RKEY */, NULL);
                if (ret >= 0)
                    break;
                if (ret != -FI_EAGAIN) {
                    print_func_err(__func__, __LINE__, "fi_read", "", ret);
                    goto done;
                }
                if ((rc = do_progress(fab_conn->tx_cq, &tx_cmp)) < 0) {
                    print_func_err(__func__, __LINE__, "do_progress(r)", "", rc);
                    goto done;
                }
            }
            tx_op++;
            while (tx_cmp != tx_op)
                if ((rc = do_progress(fab_conn->tx_cq, &tx_cmp)) < 0) {
                    print_func_err(__func__, __LINE__, "do_progress(r)", "", rc);
                    goto done;
                }
        }
    }
    gettimeofday(&ts_end, NULL);

    MPI_Barrier(MPI_COMM_WORLD);
    tx_time = (1000000.0*(ts_end.tv_sec - ts_beg.tv_sec) + ts_end.tv_usec - ts_beg.tv_usec)/1000000.0;
    tx_bw = (double)args->fam_size/1048576.0/tx_time;
    MPI_Reduce(&tx_time, &max_time, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);
    MPI_Reduce(&tx_time, &min_time, 1, MPI_DOUBLE, MPI_MIN, 0, MPI_COMM_WORLD);
    MPI_Reduce(&tx_bw, &agg_bw, 1, MPI_DOUBLE, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(&tx_bw, &max_bw, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);
    MPI_Reduce(&tx_bw, &min_bw, 1, MPI_DOUBLE, MPI_MIN, 0, MPI_COMM_WORLD);
    tx_bw =(double)args->fam_size*cnt/1048576.0/max_time;
    if (rank == 0)
        printf("Read:  Real BW %.3lfMiB, Agg BW %.3lfMiB/s\n    Max time %.3lfs, Min time %.3lfs\n    Min BW %.3lfMiB/s Max BW %.3lfMiB/s\n",
                tx_bw, agg_bw, max_time, min_time, min_bw, max_bw);

done:
    if (fam_sa) {
        if (!args->nodes)
            for (i = 0; i < args->nfams; i++)
                free(fam_sa[i]);
        free(fam_sa);
    }
    free(fam_addr);
    free(url);
    stuff_free(&conn);

    return ret;
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "*** Usage:\n  %s <fams> <buf-size> <io-size>\n"
        "<fams>\n  - number of fams\n\t OR\n"
        "  - comma-separated list of servers and ports, beginning with '@'\n"
        "    for e.g. \"@node1:10001,node2:10002\"\n"
        "<buf-size>\n  - size of i/o buffer per process\n"
        "  - if prefixed with 'w' or 'W', does warmup cycle for the whole buffer\n"
        "Write <buf-size>/<fams> bytes to each fam (server) with <io-size> chunks then read it back.\n"
        "Sizes may be postfixed with [kmgtKMGT] to specify the base units.\n"
        "Lower case is base 10; upper case is base 2.\n\n",
        appname);

    exit(help ? 0 : 255);
}
static inline int str2argv(char *str, char **argv, char **sufv, int argmax) {
    int argc = 0;
    char *tok, *p = str;

    while ((tok = strsep(&p, ",;")) && argc < argmax) {
        while (*tok == ',' || *tok == ';')
            tok++;
        if (*tok) {
            char *s = strchr(tok, ':');
            if (s) {
                sufv[argc] = s + 1;
                *s = 0;
            } else {
                sufv[argc] = "50000";
            }    
            argv[argc++] = tok;
        }
    }

    argv[argc] = 0;
    return argc;
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = { 0 };
    int                 init, provided, my_rank, rank_cnt;
    char                *p2;


    zhpeq_util_init(argv[0], LOG_INFO, false);

    if (argc != 4)
        usage(true);

    MPI_Initialized(&init);
    if (!init) 
        if (MPI_SUCCESS != MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &provided)) {
            printf("MPI_Init_thread failed\n");
            exit(1);
        }

    if (MPI_SUCCESS != MPI_Comm_size(MPI_COMM_WORLD, &rank_cnt)) {
        printf("MPI_Comm_size failed\n");
        exit(1);
    }

    if (MPI_SUCCESS != MPI_Comm_rank(MPI_COMM_WORLD, &my_rank)) {
        printf("MPI_Comm_rank failed\n");
        exit(1);
    }

    if ((args.use_fam = (argv[1][0] == '*')) || argv[1][0] == '@') {
        args.nodes = calloc(64, sizeof(char *));
        args.ports = calloc(64, sizeof(char *));
        args.nfams = str2argv(&argv[1][1], args.nodes, args.ports, 64);
printf("use_fam=%d, nfam=%ld, node[0]=%s\n", args.use_fam, args.nfams, args.nodes[0]);
    } else if (parse_kb_uint64_t(__func__, __LINE__, "nfams",
                argv[1], &args.nfams, 0, 0, SIZE_MAX, 0) < 0)
        usage(false);

    if (argv[2][0] == 'w' || argv[2][0] == 'W') {
        p2 = &argv[2][1];
        args.do_warm_up = 1;
    } else {
        p2 = argv[2];
        args.do_warm_up = 0;
    }

    if (parse_kb_uint64_t(__func__, __LINE__, "fam-size",
                          p2, &args.fam_size, 0, 1,
                          SIZE_MAX, PARSE_KB | PARSE_KIB) ||
        parse_kb_uint64_t(__func__, __LINE__, "step-size",
                          argv[3], &args.step_size, 0, 1,
                          SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
        usage(false);
printf("fam_size=%ld, step_size=%ld\n", args.fam_size, args.step_size);

    if (do_fam(&args, my_rank, rank_cnt) < 0)
        goto done;

    ret = 0;
 done:

    MPI_Finalize();
    return ret;
}
