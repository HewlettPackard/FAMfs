/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAMFS_ERROR_H
#define FAMFS_ERROR_H

#include <stdio.h>
#include <stdlib.h>

#include <rdma/fi_errno.h>

#define ON_FI_ERROR(action, msg, ...)       \
    do {                                    \
        int64_t __err;                      \
        if ((__err = (action))) {           \
            fprintf(stderr, #msg ": %ld - %s\n", ## __VA_ARGS__, \
                    __err, fi_strerror(-__err)); \
            exit(1);                        \
        }                                   \
    } while (0);

#define ON_ERROR(action, msg, ...)          \
    do {                                    \
        int __err;                          \
        if ((__err = (action))) {           \
            fprintf(stderr, #msg ": %d - %m\n", ## __VA_ARGS__, __err); \
            exit(1);                        \
        }                                   \
    } while (0);

#define    ASSERT(x)                    \
    do {                                \
        if (!(x))    {                  \
            fprintf(stderr, "%s:%s(%d) " #x "\n", __FILE__, __FUNCTION__, __LINE__); \
            exit(1);                    \
        }                               \
    } while (0);

#define ON_FI_ERR_RET(action, msg, ...)       \
    do {                                    \
        int64_t __err;                      \
        if ((__err = (action))) {           \
            fprintf(stderr, #msg ": %ld - %s\n", ## __VA_ARGS__, \
                    __err, fi_strerror(-__err)); \
            return -EINVAL;                 \
        }                                   \
    } while (0);

#define err(str, ...) fprintf(stderr, #str "\n", ## __VA_ARGS__)
#define ioerr(str, ...) fprintf(stderr, "%s: " #str " - %m\n", __FUNCTION__, ## __VA_ARGS__)


#endif /* ifndef FAMFS_ERROR_H */

