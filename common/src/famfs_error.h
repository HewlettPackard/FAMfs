/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAMFS_ERROR_H
#define FAMFS_ERROR_H

#include <stdio.h>
#include <stdlib.h>


/* TODO: Move me to debug.h */
#define DEBUG_LVL_(verbosity, lvl, fmt, ...) \
do { \
    if ((verbosity) >= (lvl)) \
        printf("famfs: %s:%d: %s: " fmt "\n", \
               __FILE__, __LINE__, __func__, ## __VA_ARGS__); \
} while (0)

#define ERROR(fmt, ...) \
    do {								\
	fprintf(stderr, "famfs error: %s:%d: %s: " fmt "\n",	\
		__FILE__, __LINE__, __func__, ## __VA_ARGS__);	\
    } while (0)

#define ON_ERROR(action, msg, ...)          \
    do {                                    \
        int __err;                          \
        if ((__err = (action))) {           \
            fprintf(stderr, #msg ": %d - %m\n", ## __VA_ARGS__, __err); \
            exit(1);                        \
        }                                   \
    } while (0);

#define ON_ERROR_RET(action, msg, ...)      \
    do {                                    \
        int __err;                          \
        if ((__err = (action))) {           \
            fprintf(stderr, #msg ": %d - %m\n", ## __VA_ARGS__, __err); \
            return;                         \
        }                                   \
    } while (0);

#define ON_ERROR_RV(action, ret_val, msg, ...) \
    do {                                       \
        int __err;                             \
        if ((__err = (action))) {              \
            fprintf(stderr, #msg ": %d - %m\n", ## __VA_ARGS__, __err); \
            return (ret_val);                  \
        }                                      \
    } while (0);

#define    ASSERT(x)                    \
    do {                                \
        if (!(x))    {                  \
            fprintf(stderr, "ASSERT failed %s:%s(%d) " #x "\n", __FILE__, __FUNCTION__, __LINE__); \
            exit(1);                    \
        }                               \
    } while (0);

#define err(str, ...) fprintf(stderr, str "\n", ## __VA_ARGS__)
#define ioerr(str, ...) fprintf(stderr, "%s: " str " - %m\n", __FUNCTION__, ## __VA_ARGS__)

#endif /* ifndef FAMFS_ERROR_H */

