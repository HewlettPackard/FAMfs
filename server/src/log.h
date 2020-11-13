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

#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/time.h>

#include "famfs_ktypes.h" // time_get_ts, timespec_sub macros

extern FILE *dbg_stream;
extern int glb_rank;

typedef enum {
    LOG_FATAL = 1,
    LOG_ERR   = 2,
    LOG_WARN  = 3,
    LOG_INFO  = 4,
    LOG_DBG   = 5,
    LOG_DBG2  = 6,
    LOG_DBG3  = 7
} loglevel;

char timestamp[256];
time_t ltime;

// add and change all
struct tm *ttime;
struct timespec logstart, logend;

double mlogtm;

extern int log_print_level;
#define gettid() syscall(__NR_gettid)
#define LOG(level, ...) \
                if(level <= log_print_level) { \
                    time_get_ts(&logstart); \
                    ltime = time(NULL); \
                    ttime = localtime(&ltime); \
                    strftime(timestamp, sizeof(timestamp), \
                            "%Y-%m-%dT%H:%M:", ttime); \
                    fprintf(dbg_stream,"logtime:%lf rank [%d] [%s%02lu.%03lu] [%ld] [%s:%d] [%s] ", \
                                mlogtm/1000000, glb_rank, timestamp, \
                                (uint64_t)logstart.tv_sec%60, (uint64_t)logstart.tv_nsec/1000000, \
                                gettid(), __FILE__, __LINE__, __FUNCTION__); \
                    fprintf(dbg_stream, __VA_ARGS__); \
                    fprintf(dbg_stream, "\n"); \
                    fflush(dbg_stream); \
                    time_get_ts(&logend); \
                    timespec_sub(&logend, &logstart); \
                    mlogtm += (uint64_t)logend.tv_sec * 1000000UL + (uint64_t)logend.tv_nsec / 1000; \
                }
#define IF_LOG(level)	if (level <= log_print_level)

#endif /* LOG_H */
