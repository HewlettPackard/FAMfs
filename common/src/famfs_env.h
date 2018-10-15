/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAMFS_ENV_H
#define FAMFS_ENV_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

static inline size_t _getval(char *name, char *v, size_t df) {
    size_t  val = 0;
    char    *evv, *last;

    if (v) 
        evv = v;
    else
        evv = getenv(name);
    if (evv) {
        val = strtod(evv, &last);
        if (*last) {
            switch (*last) {
            case 'k':
            case 'K':
                val *= 1024;
                break;
            case 'm':
            case 'M':
                val *= 1024*1024;
                break;
            case 'g':
            case 'G':
                val *= 1024*1024*1024L;
                break;
            }
        }
	return val;
    }
    return df;
}

#define getval(name, vstr) _getval("" #name "", vstr, name)

static inline char *_getstr(char *name, char *dfl) {
    char *str =  getenv(name);
    return str ? str : strdup(dfl);
}

#define getstr(name) _getstr("" #name "", name)

static inline const char *str_tk(const char *buf, const char *accept)
{
	const char *p;
	size_t l;

	p = strpbrk(buf, accept);
	if (!p) {
		if ((l = strlen(buf)))
			p = buf + l;
	}
	return p;
}

#define N_XFER_SZ	1*1024*1024L 
#define LFCLN_ITER	1
#define LFSRV_PORT	50666
#define LF_PROV_NAME	"sockets"
#define LFSRV_BUF_SZ	32*1024*1024*1024L
#define	N_PARITY	1
#define N_CHUNK_SZ	1*1024*1024L
#define N_WRK_COUNT	1
#define N_EXTENT_SZ	1*1024*1024*1024L
#define CMD_MAX		16
#define	IO_TIMEOUT_MS	30*1000 /* single I/O execution timeout, 30 sec */
#define LFSRV_RCTX_BITS 8	/* LF SRV: max number of rx contexts, bits */
#define LFSRV_START_TMO 15000	/* the timeout for start all LF servers */

/* default configuration command line */
#define LFS_COMMAND     "x -H 127.0.0.1 -P0 --memreg scalable --provider sockets --part_mreg ENCODE"
#define LFS_MAXARGS     64

#define LF_MR_MODEL_SCALABLE	"scalable"
#define LF_MR_MODEL_LOCAL	"local"	/* BASIC and FI_Mr_LOCAL */
#define LF_MR_MODEL_BASIC	"basic" /* FI_MR_ALLOCATED [| FI_MR_PROV_KEY | FI_MR_VIRT_ADDR - not now] */
//#define LF_MR_MODEL	LF_MR_MODEL_BASIC /* Default: local memory registration */
#define LF_MR_MODEL	LF_MR_MODEL_SCALABLE /* Default: local memory registration */

//#define LF_TARGET_RMA_EVENT	/* Require generation of completion events when target of RMA and/or atomics */

#endif /* FAMFS_ENV_H */
