/*
 * Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * Copyright (c) 2017, Florida State University. Contributions from
 * the Computer Architecture and Systems Research Laboratory (CASTL)
 * at the Department of Computer Science.
 * Written by
 *      Teng Wang tw15g@my.fsu.edu
 *      Adam Moody moody20@llnl.gov
 *      Weikuan Yu wyu3@fsu.edu
 *      Kento Sato kento@llnl.gov
 *      Kathryn Mohror. kathryn@llnl.gov
 *      LLNL-CODE-728877.
 * All rights reserved.
 *
 * This file is part of BurstFS For details, see https://github.com/llnl/burstfs.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 * Copyright (c) 2013, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * code Written by
 *   Raghunath Rajachandrasekar <rajachan@cse.ohio-state.edu>
 *   Kathryn Mohror <kathryn@llnl.gov>
 *   Adam Moody <moody20@llnl.gov>
 * All rights reserved.
 * This file is part of CRUISE.
 * For details, see https://github.com/hpc/cruise
 * Please also read this file COPYRIGHT
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <mpi.h>
#include <sys/time.h>
#include <aio.h>
#include "unifycr.h"

#define GEN_STR_LEN 1024

//#define RUN_SV_ON_IO_NODE

struct timeval read_start, read_end;
double read_time = 0;

struct timeval write_start, write_end;
double write_time = 0;

struct timeval meta_start, meta_end;
double meta_time = 0;

typedef struct {
  int fid;
  long offset;
  long length;
  char *buf;

}read_req_t;

int main(int argc, char *argv[]) {

        printf("start test_pwrite\n");
        static const char * opts = "b:s:t:f:p:u:M:D:S:";
        char tmpfname[GEN_STR_LEN], fname[GEN_STR_LEN];
        long blk_sz, seg_num, tran_sz, num_reqs;
        int pat, c, rank_num, rank, direction, fd, \
                to_unmount = 0;
        int mount_burstfs = 1, direct_io = 0, sequential_io = 0;
        int rc = 0, provided = -1;
        size_t segsz;
        int n, initialized = 0;
        void *ion_base = NULL;

        /* initialize MPI, if necessary */
        rc = MPI_Initialized(&initialized);
        if (rc != MPI_SUCCESS) {
                exit(1);
        }
        if (!initialized) {
                rc = MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &provided);
        } else {
                rc = MPI_Query_thread(&provided);
        }
        if (rc != MPI_SUCCESS) {
                printf("MPI_Init failure\n");
                exit(1);
        }

        //MPI_Init(&argc, &argv);
        MPI_Comm_size(MPI_COMM_WORLD, &rank_num);
        MPI_Comm_rank(MPI_COMM_WORLD, &rank);

#define ULFS_MAX_FILENAME 128
        char hostname[ULFS_MAX_FILENAME] = {0};
        gethostname(hostname, ULFS_MAX_FILENAME);
        printf("Client node:%d/%d on %s\n", rank, rank_num, hostname);

        while((c = getopt(argc, argv, opts)) != -1){

                switch (c)  {
                        case 'b': /*size of block*/
                           blk_sz = atol(optarg); break;
                        case 's': /*number of blocks each process writes*/
                           seg_num = atol(optarg); break;
                        case 't': /*size of each write*/
                           tran_sz = atol(optarg); break;
                        case 'f':
                           strcpy(fname, optarg); break;
                        case 'p':
                           pat = atoi(optarg); break; /* 0: N-1 segment/strided, 1: N-N*/
                        case 'u':
                           to_unmount = atoi(optarg); break; /*0: not unmount after finish 1: unmount*/
                        case 'M':
                           mount_burstfs = atoi(optarg); break; /* 0: Don't mount burstfs */
                        case 'D':
                           direct_io = atoi(optarg); break; /* 1: Open with O_DIRECT */
                        case 'S':
                           sequential_io = atoi(optarg); break; /* 1: Write/read blocks sequentially */
                }
        }
        if (!rank)
                printf(" %s, %s, %s I/O, block size:%ld segment:%ld\n",
                        (pat)? "N-N" : ((seg_num > 1)? "strided":"segmented"),
                        (direct_io)? "direct":"buffered",
                        (sequential_io)? "sequential":"randomized",
                        tran_sz, blk_sz);

        if (mount_burstfs) {
                printf("mount burstfs\n");
                /* fs type: UNIFYCR_LOG */
                unifycr_mount("/tmp/mnt", rank, rank_num, 0, 1);
        } else
                to_unmount = 0;

        char *buf;
        if (direct_io)
                posix_memalign((void**)&buf, getpagesize(), tran_sz);
        else
                buf = malloc (tran_sz);
        if (buf == NULL)
                exit(1);;
        memset(buf, 0, tran_sz);

        MPI_Barrier(MPI_COMM_WORLD);

        if (pat == 1) {
                sprintf(tmpfname, "%s%d", fname, rank);
        } else {
                sprintf(tmpfname, "%s", fname);
        }

        printf("open file: %s\n", tmpfname);

        int flags = O_RDWR | O_CREAT;
        if (direct_io)
                flags |= O_DIRECT;
        fd = open(tmpfname, flags, S_IRUSR | S_IWUSR);
        if (fd < 0) {
                printf("open file failure: %m\n");
                fflush(stdout);
                exit(1);
        }
        /* if (direct_io)
                fsync(fd); */

        printf("write to file\n");

        gettimeofday(&write_start, NULL);
        long i, j, offset;
        for (i = 0; i < seg_num; i++) {
                long jj;
                for (jj = 0; jj < blk_sz/tran_sz; jj++) {
                        if (sequential_io) {
                                j = jj;
                        } else {
                                j = (blk_sz/tran_sz - 1) - 2*jj; /* reverse */
                                if (j < 0)
                                        j += (blk_sz/tran_sz - 1);
                        }
                        if (pat == 0)
                                offset = i * rank_num * blk_sz +\
                                        rank * blk_sz + j * tran_sz;
                        else if (pat == 1)
                                offset = i * blk_sz + j * tran_sz;

            int k;
            for (k = 0; k < tran_sz/sizeof(unsigned long); k++) {
                unsigned long *p = &(((unsigned long*)buf)[k]);
                *p = offset;
            }

                        rc = pwrite(fd, buf, tran_sz, offset);
                        if (rc < 0) {
                                printf("write failure\n");
                                fflush(stdout);
                                exit(1);
                        }
                }
        }

        printf("sync file\n");

        gettimeofday(&meta_start, NULL);
        fsync(fd);
        gettimeofday(&meta_end, NULL);
        meta_time += 1000000 * (meta_end.tv_sec - meta_start.tv_sec)\
                        + meta_end.tv_usec - meta_start.tv_usec;
        meta_time /= 1000000;
        gettimeofday(&write_end, NULL);
        write_time+=1000000 * (write_end.tv_sec - write_start.tv_sec)\
                        + write_end.tv_usec - write_start.tv_usec;
        write_time = write_time/1000000;

        printf("close file\n");

        close(fd);
        MPI_Barrier(MPI_COMM_WORLD);

        double write_bw = (double)blk_sz\
                        * seg_num / 1048576 /write_time;
        double agg_write_bw;
        MPI_Reduce(&write_bw, &agg_write_bw, 1, MPI_DOUBLE,\
                        MPI_SUM, 0, MPI_COMM_WORLD);

        double max_write_time;
        MPI_Reduce(&write_time, &max_write_time, 1, MPI_DOUBLE,\
                        MPI_MAX, 0, MPI_COMM_WORLD);

        double min_write_bw;
        min_write_bw=(double)blk_sz\
                        * seg_num * rank_num / 1048576 / max_write_time;

        if (rank == 0) {
                        printf("Aggregate Write BW is %lfMB/s, Min Write BW is %lfMB/s\n",\
                                        agg_write_bw, min_write_bw);
                        fflush(stdout);
        }
        free(buf);
        MPI_Barrier(MPI_COMM_WORLD);


        /* Read test */
        num_reqs = blk_sz*seg_num/tran_sz;
        char *read_buf; /*read buffer*/
        if (direct_io)
                posix_memalign((void**)&read_buf, getpagesize(), blk_sz);
        else
                read_buf = malloc(blk_sz);

        if (pat == 1) {
                sprintf(tmpfname, "%s%d", fname, rank);
        } else {
                sprintf(tmpfname, "%s", fname);
        }
        MPI_Barrier(MPI_COMM_WORLD);

        if (direct_io)
                flags = O_RDWR | O_DIRECT;
        else
                flags = O_RDONLY;
        fd = open(tmpfname, flags, S_IRUSR | S_IWUSR);
        if (fd < 0) {
                printf("open file failure\n");
                fflush(stdout);
                exit(1);
        }


        gettimeofday(&read_start, NULL);

        long cursor, e = 0;
        for (i = 0; i < seg_num; i++) {
                cursor = 0;
                long jjj;
                for (jjj = 0; jjj < blk_sz/tran_sz; jjj++) {
                        if (sequential_io) {
                                j = jjj;
                        } else {
                                j = (blk_sz/tran_sz - 1) - 2*jjj; /* reverse */
                                if (j < 0)
                                        j += (blk_sz/tran_sz - 1);
                        }
                        if (pat == 0)
                                offset = i * rank_num * blk_sz +\
                                        rank * blk_sz + j * tran_sz;
                        else if (pat == 1)
                                offset = i * blk_sz + j * tran_sz;
                        cursor = j * tran_sz;
                        rc = pread(fd, read_buf + cursor, tran_sz, offset);
                        if (rc < 0) {
                                printf("read failure\n");
                                fflush(stdout);
                                exit(1);
                        }

                        int k;
                        for (k = 0; k < tran_sz/sizeof(unsigned long); k++) {
                                unsigned long *p = &(((unsigned long*)(read_buf + cursor))[k]);

                                if (*p != offset) {
                                        e++;
#if 0
                                        printf("DATA MISMATCH, expected %u, got %u @%u\n", offset, *p, k*8);

                                        int ii, jj;
                                        for (ii = 0; ii < 16; ii++) {
                                                printf("### %02d: ", ii);
                                                for (jj = 0; jj < 8; jj++) {
                                                        printf("[%02x] ",
                                                            (unsigned char)*(read_buf + cursor + ii*8 + jj));
                                                }
                                        printf("\n");
                                        }
                                        break;
#endif
                                }
                        }
                }
        }
        if (e) {
                printf("%ld data verification errors\n", e);
        } else {
                printf("Success!!!\n");
        }
        gettimeofday(&read_end, NULL);
        read_time = (read_end.tv_sec - read_start.tv_sec)*1000000 \
                + read_end.tv_usec - read_start.tv_usec;
        read_time = read_time/1000000;

        close(fd);
        MPI_Barrier(MPI_COMM_WORLD);

        if (to_unmount) {
                if (rank == 0) {
                        unifycr_unmount();
			printf("burstfs unmounted\n");
		}
        }

        free(read_buf);

        double read_bw = (double)blk_sz * seg_num / 1048576 / read_time;
        double agg_read_bw;

        double max_read_time, min_read_bw;
        MPI_Reduce(&read_bw, &agg_read_bw, 1, MPI_DOUBLE, MPI_SUM, 0, MPI_COMM_WORLD);
        MPI_Reduce(&read_time, &max_read_time, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);

        min_read_bw=(double)blk_sz*seg_num*rank_num/1048576/max_read_time;
        if (rank == 0) {
                printf("Aggregate Read BW is %lfMB/s,\
                    Min Read BW is %lf\n", \
                    agg_read_bw,  min_read_bw);
                fflush(stdout);
        }

        if (!initialized) {
                MPI_Finalize();
        }

        /* Stop Servers */
        exit(0);
}
