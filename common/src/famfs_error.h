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
#ifndef DEBUG
#define DEBUG(fmt, ...)                          \
    do {                                         \
        printf("%s:%d: %s: " fmt "\n",           \
                __FILE__, __LINE__,              \
                __func__, ## __VA_ARGS__);       \
    } while (0)
#endif

#define DEBUG_LVL_(verbosity, lvl, fmt, ...)     \
do {                                             \
    if ((verbosity) >= (lvl))                    \
        DEBUG(fmt, ## __VA_ARGS__);              \
} while (0)

#ifndef ERROR
#define ERROR(fmt, ...)                          \
    do {                                         \
        fprintf(stderr, "famfs error: %s:%d: %s: " fmt "\n",   \
		__FILE__, __LINE__, __func__, ## __VA_ARGS__); \
    } while (0)
#endif

#define _op_exit(arg)   exit(arg)
#define _op_return(arg) return(arg)
#define _op_ret(arg)    return
#define _op_retabs(arg) return(-abs(arg))

#define ON_ERROR_(action, op, arg, msg, ...)     \
    do {                                         \
        int __err;                               \
        if ((__err = (action))) {                \
            ERROR(#msg ": %d - %m",              \
                  ##__VA_ARGS__, __err);         \
            op(arg);                             \
        }                                        \
    } while (0);

#define ON_ERROR(action, msg, ...)               \
    ON_ERROR_(action, _op_exit, 1, msg, ## __VA_ARGS__)

#define ON_ERROR_RET(action, msg, ...)           \
    ON_ERROR_(action, _op_ret, , msg, ## __VA_ARGS__)

#define ON_ERROR_RV(action, ret_val, msg, ...)   \
    ON_ERROR_(action, _op_return, ret_val, msg, ## __VA_ARGS__)

#define ON_ERROR_RC(action, msg, ...)            \
    ON_ERROR_(action, _op_retabs,  (int)(action), msg, ## __VA_ARGS__)

#define ON_NOMEM_RET(action, msg, ...)           \
    ON_ERROR_(!(action), _op_return, -ENOMEM, msg, ## __VA_ARGS__)


#define    ASSERT(x)                             \
    do {                                         \
        if (!(x))    {                           \
            fprintf(stderr, "ASSERT failed %s:%s(%d) " #x "\n", \
              __FILE__, __FUNCTION__, __LINE__); \
            exit(1);                             \
        }                                        \
    } while (0);

#define err(str, ...) fprintf(stderr, str "\n", ## __VA_ARGS__)
#define ioerr(str, ...) fprintf(stderr, "%s: " str " - %m\n", __FUNCTION__, ## __VA_ARGS__)

#endif /* ifndef FAMFS_ERROR_H */

