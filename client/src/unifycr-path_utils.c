/*
 * Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 *
 *
 * This is the license for UnifyCR.
 * For details, see https://github.com/LLNL/UnifyCR.
 * Please read https://github.com/LLNL/UnifyCR/LICENSE for full license text.
 */

#define _GNU_SOURCE
#include "unifycr-runtime-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "unifycr-internal.h"

char *normalized_path(const char *path, char *buf, size_t buf_sz)
{
    size_t i, j, k;
    const char *p = path;

    i = 0;
    while (*p != '\0') {
        /* token */
        if (*p == '/') {
            p++;
            /* remove "./" */
            if (*p == '.') {
		if (*(p+1) == '\0')
                    break;
                else if (*(p+1) == '/')
                    p += 2;
            }
            /* repeated slahes in a path are equivalent to a single slash */
            while (*p == '/')
                p++;
            /* don't copy the final slash */
            if (*p == '\0')
                break;
            if (i >= buf_sz)
                goto _enametoolong;
            buf[i++] = '/';
        } else {
            if (i >= buf_sz)
                goto _enametoolong;
            buf[i++] = *p++;
        }
    }
    /* terminate the normalized string */
    buf[i] = '\0';

    /* deal with .. */
    p = path;
    i = 0;
    j = 0;
    k = 0;

    /* parse the entire string */
    /* this snippet is borrowed from path.c */
    do {
        /* token */
        if (buf[i] == '/' || buf[i] == '\0') {
            /* ".." element found? */
            if ((i - j) == 2 && !strncmp (buf + j, "..", 2)) {
                /* check whether the pathname is empty? */
                if (k == 0) {
                    buf[k++] = '.';
                    buf[k++] = '.';

                    /* append a slash if necessary */
                    if (buf[i] == '/')
                        buf[k++] = '/';
                } else if (k > 1) {
                    /* search the path for the previous slash */
                    for (j = 1; j < k; j++) {
                        if (buf[k - j - 1] == '/')
                            break;
                    }

                    /* slash separator found? */
                    if (j < k) {
                        if (!strncmp (buf + k - j, "..", 2)) {
                            buf[k++] = '.';
                            buf[k++] = '.';
                        } else {
                            k = k - j - 1;
                        }

                        /* append a slash if necessary */
                        if (k == 0 && buf[0] == '/')
                            buf[k++] = '/';
                        else if (buf[i] == '/')
                            buf[k++] = '/';
                    }
                    /* no slash separator found? */
                    else {
                        if (k == 3 && !strncmp (buf, "..", 2)) {
                            buf[k++] = '.';
                            buf[k++] = '.';

                            /* append a slash if necessary */
                            if (buf[i] == '/')
                                buf[k++] = '/';
                        } else if (buf[i] == '\0') {
                            k = 0;
                            buf[k++] = '.';
                        } else if (buf[i] == '/' && buf[i + 1] == '\0') {
                            k = 0;
                            buf[k++] = '.';
                            buf[k++] = '/';
                        } else {
                            k = 0;
                        }
                    }
                }
            } else {
                /* copy directory name */
                memmove (buf + k, buf + j, i - j);
                /* advance write pointer */
                k += i - j;

                /* append a slash if necessary */
                if (buf[i] == '/')
                    buf[k++] = '/';
            }

            /* move to the next token */
            while (buf[i] == '/')
                i++;
            j = i;
        }
        else if (k == 0) {
            while (buf[i] == '.' || buf[i] == '/') {
                 j++,i++;
            }
        }
    } while (buf[i++] != '\0');

    /* properly terminate the string with a NULL character */
    buf[k] = '\0';
    return buf;

_enametoolong:
    errno = ENAMETOOLONG;
    return NULL;
}
