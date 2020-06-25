/*
 * Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * Copyright (c) 2017, Florida State University. Contributions from
 * the Computer Architecture and Systems Research Laboratory (CASTL)
 * at the Department of Computer Science.
 * Written by
 * 	Teng Wang tw15g@my.fsu.edu
 * 	Adam Moody moody20@llnl.gov
 * 	Weikuan Yu wyu3@fsu.edu
 * 	Kento Sato kento@llnl.gov
 * 	Kathryn Mohror. kathryn@llnl.gov
 * 	LLNL-CODE-728877.
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
#include <string.h>
#include <fcntl.h>
#include <mpi.h>
#include <sys/time.h>
#include <aio.h>
#include <sys/mman.h>

#include <unifycr.h>

#include "famfs_stats.h"


//#define FAMFS_EXPLICIT_LO	/* Uncomment to set LAYOUT explicitly in path */
#define MOUNT_POINT	"/tmp/mnt"
#ifdef FAMFS_EXPLICIT_LO
#define LAYOUT		"1D:1M"
#endif

#define GEN_STR_LEN 1024

#define print0(...) if (rank == 0 && vmax == 0) {printf(__VA_ARGS__);}
#define printv(...) if (vmax > 0) {printf(__VA_ARGS__);}
#define getv(s) _getval(NULL, (s), 0)

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

    static const char * opts = "b:s:t:f:p:u:M:m:dD:S:w:r:i:v:W:GRC:VU";
    char tmpfname[GEN_STR_LEN+11], fname[GEN_STR_LEN];
    char mount_point[GEN_STR_LEN] = { 0 };
    long blk_sz = 0, seg_num = 1, tran_sz = 1024*1024, read_sz = 0;
    //long num_reqs;
    int pat = 0, c, rank_num, rank, fd, \
            to_unmount = 0;
    int mount_burstfs = 1, direct_io = 0, sequential_io = 0, write_only = 0;
    int shutdown = 0;
    int initialized, provided, rrc = MPI_SUCCESS;
    int gbuf = 0, mreg = 0;
    off_t ini_off = 0;
    void *rid;
    int vmax = 0;
    int vfy = 0;
    ssize_t ret, warmup = 0;
    struct famsim_stats *famsim_stats_send, *famsim_stats_recv;
    int carbon_stats = 0; /* Only on Carbon: CPU instruction stats */
    int fam_cnt = 0; /* Number of FAMs */
    int unifycr_fs = 0;

    //MPI_Init(&argc, &argv);
    MPI_Initialized(&initialized);
    if (!initialized) {
        rrc = MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &provided);
    }

    if (rrc != MPI_SUCCESS) {
        printf("MPI_Init_thread failed\n");
        exit(1);
    }

    rrc = MPI_Comm_size(MPI_COMM_WORLD, &rank_num);
    if (rrc != MPI_SUCCESS) {
        printf("MPI_Comm_size failed\n");
        exit(1);
    }

    rrc = MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    if (rrc != MPI_SUCCESS) {
        printf("MPI_Comm_rank failed\n");
        exit(1);
    }
    print0("startng test_prw\n");

#define ULFS_MAX_FILENAME 128
    char hostname[ULFS_MAX_FILENAME] = {0};
    gethostname(hostname, ULFS_MAX_FILENAME);
    printv("%s: Rank=%u, Rank num=%u\n", hostname, rank, rank_num);

    while((c = getopt(argc, argv, opts)) != -1) {
        switch (c)  {
            case 'b': /*size of block*/
               blk_sz = getv(optarg); break;
            case 's': /*number of blocks each process writes*/
               seg_num = getv(optarg); break;
            case 't': /*size of each write*/
               tran_sz = getv(optarg); break;
            case 'r': /*size of each read*/
               read_sz= getv(optarg); break;
            case 'f':
               strcpy(fname, optarg); break;
            case 'p':
               pat = atoi(optarg); break; /* 0: N-1 segment/strided, 1: N-N*/
            case 'u':
               to_unmount = atoi(optarg); break; /*0: not unmount after finish 1: unmount*/
            case 'M':
               mount_burstfs = atoi(optarg); break; /* 0: Don't mount burstfs */
            case 'm':
               strcpy(mount_point, optarg); break;
            case 'd':
               shutdown++; break; /* call fs shutdown() on exit (after unmount) */
            case 'D':
               direct_io = atoi(optarg); break; /* 1: Open with O_DIRECT */
            case 'S':
               sequential_io = atoi(optarg); break; /* 1: Write/read blocks sequentially */
            case 'w':
               write_only = atoi(optarg); break;
            case 'v':
               vmax = atoi(optarg); break;
            case 'G':
               gbuf++; break;
            case 'R':
               mreg++; break;
            case 'i':
               ini_off = getv(optarg); break;   /* 1st write initial offset: simulate unaligned writes */
            case 'W':
               warmup = getv(optarg); break;
            case 'C':
               carbon_stats = atoi(optarg); break; /* 1: Enable stats */
            case 'V':
               vfy++; break;
            case 'U':
               unifycr_fs = 1; break; /* 0: FAMFS, 1: UNIFYCR_LOG */
        }
    }
    if (read_sz == 0)
        read_sz = tran_sz;
    if (blk_sz == 0)
        blk_sz = tran_sz;

    /* choose fs type: UNIFYCR_LOG or FAMFS */
    fs_type_t fs = unifycr_fs?UNIFYCR_LOG:FAMFS;
    if (!fs_supported(fs)) {
        printf(" fs type %d not supported - check configuration file!\n", fs);
        exit(1);
    }

    if (rank == 0) printf(" %s, %s, %s I/O, %s block size:%ldW/%ldR segment:%ld hdr off=%lu\n",
        (pat)? "N-N" : ((seg_num > 1)? "strided":"segmented"),
        (direct_io)? "direct":"buffered",
        (sequential_io)? "sequential":"randomized",
        (write_only)? "W":"W/R",
        tran_sz, read_sz, blk_sz, ini_off);

    famsim_stats_init(&famsim_ctx, carbon_stats?"/tmp":NULL, "famsim", rank);
    if (carbon_stats != 0) {
        if (rank == 0 ) {
            printf("   Carbon stats %sabled\n", famsim_ctx?"en":"dis");
#if (HAVE_FAM_SIM == 0)
            printf("   FAMfs was configured without --with-fam-sim option!\n");
#endif
        }
    }
    famsim_stats_send = famsim_stats_create(famsim_ctx, FAMSIM_STATS_SEND);
    famsim_stats_recv = famsim_stats_create(famsim_ctx, FAMSIM_STATS_RECV);

    int rc = 0;
    if (mount_burstfs) {

        /* mount point is given as a part of file name? */
        char *p = strstr(fname, "::");
        if (p) {
            strcpy(tmpfname, fname);
            p = strrchr(tmpfname, '/');
            if (!p) {
                print0("Bad file name!\n");
                exit(1);
            }
            *p = 0;
            strcpy(mount_point, tmpfname);

        } else if (!*mount_point) {
            /* use defaults */
            sprintf(tmpfname, "%s", MOUNT_POINT);
#ifdef FAMFS_EXPLICIT_LO
            if (fs == FAMFS)
                sprintf(tmpfname, "%s::%s", LAYOUT, MOUNT_POINT);
#endif
            strcpy(mount_point, tmpfname);
        } else
            strcpy(tmpfname, mount_point);
        /* insert layout prefix to file name */
        if (p == NULL && fs == FAMFS) {
            p = strstr(tmpfname, "::");
            if (p) {
                strcpy(p+2, fname);
                strcpy(fname, tmpfname);
            }
        }

        print0("mount unifycr at %s\n", mount_point);
        rc = unifycr_mount(mount_point, rank, rank_num, 0, fs);
        if (rc) {
            fprintf(stderr, "mount (fs:%d) error:%d - %m\n", fs, rc);
            exit(1);
        }
        if (famsim_ctx)
            fam_cnt = famsim_ctx->fam_cnt;
    } else
        to_unmount = 0;

    /* Add layout name if FAMFS */
    print0("File name is %s\n", fname);

    char *buf;
    size_t len;
    if (gbuf) {
        len = blk_sz*seg_num;
        buf = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    } else {
        len = max(tran_sz, read_sz);
        rc = posix_memalign((void**)&buf, getpagesize(), max(len,1024*1024));
        if (rc) {
            printf("posix_memalign error:%d - %m\n", rc);
            exit(1);
        }
    }

    if (buf == NULL || buf == MAP_FAILED) {
        printf("[%02d] can't allocate %luMiB of  memory\n", rank, len/1024/1024);
        exit(1);
    }
    memset(buf, 0, max(tran_sz, read_sz));

    if (warmup) {
        print0("warming up...\n");
        printv("%02d warming up\n", rank);
        sprintf(tmpfname, "%s-%d.warmup", fname, rank);
        fd = open(tmpfname, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            printf("%02d warm-up file %s open failure\n", rank, fname);
            exit(1);
        }
        while (warmup > 0) {
            off_t off = 0;
            ssize_t l = pwrite(fd, buf, 1024*1024, off);

            if (l < 0) {
                printf("%02d warm-up file %s write error\n", rank, fname);
                exit(1);
            }
            warmup -= l;
            off += l;
        }
        close(fd);
    }

    if (mreg) {
       rc = famfs_buf_reg(buf, len, &rid);
       if (rc) {
           printf("%02d buf register error %d\n", rank, rc);
           exit(1);
       }
    }

    MPI_Barrier(MPI_COMM_WORLD);

    if (pat == 1) {
        sprintf(tmpfname, "%s%d", fname, rank);
    } else {
        sprintf(tmpfname, "%s", fname);
    }

    print0("opening files\n");

    int flags = O_RDWR | O_CREAT | O_TRUNC;
    if (direct_io)
        flags |= O_DIRECT;
    fd = open(tmpfname, flags, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        printf("%02d open file %s failure\n", rank, tmpfname);
        fflush(stdout);
        return -1;
    }
    if (direct_io)
        fsync(fd);

    long i, j;
    unsigned long offset, lw_off = 0, *p;
    char *bufp = buf;
    offset = 0;

    print0("writing...\n");
    printv("%02d writing\n", rank);
    gettimeofday(&write_start, NULL);

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
                offset = i*rank_num*blk_sz + rank*blk_sz + j*tran_sz;
            else if (pat == 1)
                offset = i*blk_sz + j*tran_sz;

            int k;
            lw_off = 0;

            if (gbuf)
                bufp = buf + i*blk_sz + j*tran_sz;

            for (k = 0; vfy && k < tran_sz/sizeof(unsigned long); k++) {
                if (gbuf)
                    p = &(((unsigned long *)bufp)[k]);
                else
                    p = &(((unsigned long*)buf)[k]);

                //*p = offset + k;
                *p = offset + lw_off*sizeof(long);
                lw_off++;
            }

            famsim_stats_start(famsim_ctx, famsim_stats_send);

            ssize_t bcount = pwrite(fd, bufp, tran_sz, offset);

            /* TODO: Ensure tran_sz equals to the chunk size */
            if (i==0 && jj<(fam_cnt/rank_num))
                famsim_stats_stop(famsim_stats_send, 1);
            else
                famsim_stats_pause(famsim_stats_send);

            if (bcount < 0) {
                printf("%02d write failure - %m\n", rank);
                fflush(stdout);
                exit(1);
            } else if (bcount != tran_sz) {
                printf("%02d write failure - %zd bytes written\n", rank, bcount);
                fflush(stdout);
                exit(1);
            }
        }
    }

    printv("%02d syncing\n", rank);

    gettimeofday(&meta_start, NULL);
    fsync(fd);
    gettimeofday(&meta_end, NULL);
    meta_time += 1000000*(meta_end.tv_sec - meta_start.tv_sec) + 
        meta_end.tv_usec - meta_start.tv_usec;
    meta_time /= 1000000;
    gettimeofday(&write_end, NULL);
    write_time += 1000000*(write_end.tv_sec - write_start.tv_sec) + 
        write_end.tv_usec - write_start.tv_usec;
    write_time = write_time/1000000;


    close(fd);
    if (direct_io) {
        MPI_Barrier(MPI_COMM_WORLD);
        printf("%s: drop_caches\n", hostname);
        rc = system("echo 1 > /proc/sys/vm/drop_caches");
        if (rc) {
            printf("Faied to drop caches:%d - %m\n", rc);
            exit(1);
        }
    }
    MPI_Barrier(MPI_COMM_WORLD);
    print0("closed files\n");


    double write_bw = (double)blk_sz*seg_num/1048576/write_time;
    double agg_write_bw;
    MPI_Reduce(&write_bw, &agg_write_bw, 1, MPI_DOUBLE, MPI_SUM, 0, MPI_COMM_WORLD);

    double max_write_time;
    MPI_Reduce(&write_time, &max_write_time, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);

    double min_write_bw;
    min_write_bw=(double)blk_sz*seg_num*rank_num/1048576/ max_write_time;

    double agg_write_time;
    MPI_Reduce(&write_time, &agg_write_time,  1, MPI_DOUBLE, MPI_SUM, 0, MPI_COMM_WORLD);

    double agg_meta_time;
    MPI_Reduce(&meta_time, &agg_meta_time,  1, MPI_DOUBLE, MPI_SUM, 0, MPI_COMM_WORLD);

    double max_meta_time;
    MPI_Reduce(&meta_time, &max_meta_time, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);

    /* write out FAM simulator stats */
    famsim_stats_stop(famsim_stats_send, 1);

    if (rank == 0) {
        printf("### Aggregate Write BW is %.3lf MiB/s, Min Write BW is %.3lf MiB/s\n",
                agg_write_bw, min_write_bw);
        printf("Per-process write time %lf sec, sync time %lf sec, Max %lf sec\n",
                (agg_write_time-agg_meta_time)/rank_num, agg_meta_time/rank_num, max_meta_time);
        fflush(stdout);
    }

    MPI_Barrier(MPI_COMM_WORLD);
    if (write_only) {
        MPI_Finalize();
        exit(0);
    }

    //num_reqs = blk_sz*seg_num/tran_sz;
    //char *read_buf = malloc(blk_sz * seg_num); /*read buffer*/
    //char *read_buf; /*read buffer*/
    /*
    if (direct_io)
            posix_memalign((void**)&read_buf, getpagesize(), blk_sz);
    else
            read_buf = malloc(blk_sz);

    */

    if (pat == 1) {
        sprintf(tmpfname, "%s%d", fname, rank);
    }	else {
        sprintf(tmpfname, "%s", fname);
    }
    MPI_Barrier(MPI_COMM_WORLD);

    if (direct_io)
        flags = O_RDWR | O_DIRECT;
    else
        flags = O_RDONLY;

    print0("open for read\n");

    fd = open(tmpfname, flags, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        printf("%02d open file '%s' failure - %m\n", rank, tmpfname);
        fflush(stdout);
        return -1;
    }
    if (direct_io)
        fsync(fd);

    gettimeofday(&read_start, NULL);

    print0("reading...\n");
    printv("%02d reading\n", rank);

    long vcnt, e = 0;
    //long cursor;
    offset = 0;
    for (i = 0; i < seg_num; i++) {
        //cursor = 0;
        long jj;
        for (jj = 0; jj < blk_sz/read_sz; jj++) {
            if (sequential_io) {
                j = jj;
            } else {
                j = (blk_sz/read_sz - 1) - 2*jj; /* reverse */
                if (j < 0)
                    j += (blk_sz/read_sz - 1);
            }
            if (pat == 0)
                offset = i*rank_num*blk_sz + rank*blk_sz + j*read_sz;
            else if (pat == 1)
                offset = i*blk_sz + j*read_sz;

            //cursor = j * read_sz;
            //rc = pread(fd, read_buf + cursor, read_sz, offset);

            int k;
            lw_off = 0;

            if (gbuf)
                bufp = buf + i*blk_sz + j*read_sz;

            famsim_stats_start(famsim_ctx, famsim_stats_recv);
            ret = pread(fd, bufp, read_sz, offset);
            famsim_stats_pause(famsim_stats_recv);
            if (ret < 0) {
                printf("%02d read failure - %m\n", rank);
                fflush(stdout);
                exit(1);
            } else if (ret != read_sz) {
                printf("%02d read failure, %zd bytes read\n", rank, ret);
                fflush(stdout);
                exit(1);
            }

            vcnt = 0;
            for (k = 0; vfy && k < read_sz/sizeof(unsigned long); k++) {
                //unsigned long *p = &(((unsigned long*)(read_buf + cursor))[k]);

                if (gbuf)
                    p = &(((unsigned long *)bufp)[k]);
                else
                    p = &(((unsigned long*)buf)[k]);

                if (*p != offset + (lw_off*sizeof(long))) {
                    e++;
                    if (vcnt < vmax) {
                        printf("DATA MISMATCH @%lu, expected %lu, got %lu [%u]\n", offset, offset + (lw_off*sizeof(long)), *p, k*8);
                        vcnt++;
                    }
#if 0
                    int ii, jj;
                    for (ii = 0; ii < 16; ii++) {
                        printf("### %02d: ", ii);
                        for (jj = 0; jj < 8; jj++) {
                            //printf("[%02x] ", (unsigned char)*(read_buf + cursor + ii*8 + jj));
                            printf("[%02x] ", (unsigned char)*(buf + ii*8 + jj));
                        }
                        printf("\n");
                    }
                    break;
#endif
                }
                lw_off++;
            }
        }
    }

    if (e)
        printf("%02d: %ld data verification errors\n", rank, e);
    else 
        printv("%02d success\n", rank);

    gettimeofday(&read_end, NULL);
    read_time = (read_end.tv_sec - read_start.tv_sec)*1000000 + read_end.tv_usec - read_start.tv_usec;
    read_time = read_time/1000000;

    close(fd);
    MPI_Barrier(MPI_COMM_WORLD);

    /* write out FAM simulator stats */
    famsim_stats_stop(famsim_stats_recv, 1);

    if (mreg)
        famfs_buf_unreg(rid);

    //free(read_buf);
    if (gbuf)
        munmap(buf, len);
    else
        free(buf);

    double read_bw = (double)blk_sz*seg_num/1048576/read_time;
    double agg_read_bw;

    double max_read_time, min_read_bw;
    MPI_Reduce(&read_bw, &agg_read_bw, 1, MPI_DOUBLE, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(&read_time, &max_read_time, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);

    min_read_bw=(double)blk_sz*seg_num*rank_num/1048576/max_read_time;
    if (rank == 0) {
        printf("### Aggregate Read BW is %.3lf MiB/s, Min Read BW is %.3lf\n", agg_read_bw,  min_read_bw);
        fflush(stdout);
    }

    if (rank == 0) {
	if (to_unmount)
	    if ((rc = unifycr_unmount()))
		fprintf(stderr, "error on FS unmount: %d\n", rc);
	if (shutdown)
	    if ((rc = unifycr_shutdown()))
		fprintf(stderr, "error on FS shutdown: %d\n", rc);
    }

    famsim_stats_free(famsim_ctx);

    MPI_Finalize();
    exit(rc);
}
