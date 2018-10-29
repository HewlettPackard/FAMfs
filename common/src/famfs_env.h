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

#ifndef min
#define min(a,b)			\
    ({	__typeof__ (a) _a = (a);	\
	__typeof__ (b) _b = (b);	\
	_a < _b ? _a : _b; })
#endif /* min */

#ifndef max
#define max(a,b)			\
    ({	__typeof__ (a) _a = (a);	\
	__typeof__ (b) _b = (b);	\
	_a > _b ? _a : _b; })
#endif /* max */

typedef enum w_type_ {
	W_T_LOAD = 0,
	W_T_ENCODE,
	W_T_DECODE,
	W_T_VERIFY,
	W_T_EXIT,
	W_T_NONE,
} W_TYPE_t;


/* defined in util.c */
char** getstrlist(const char *buf, int *count);
int find_my_node(char* const* nodelist, int node_cnt, int silent);
void nodelist_free(char **nodelist, int size);
void alloc_affinity(int **affp, int size, int pos);
void ion_usage(const char *name);


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

static inline int str2argv(char *str, char **argv, int argmax) {
    int argc = 0;
    char *tok, *p = str;

    while ((tok = strsep(&p, " \t")) && argc < argmax) {
        argv[argc++] = tok;
        //DEBUG("tok[%d]=%s", argc - 1, tok);
    }

    argv[argc] = 0;
    return argc;
}

static inline const char *cmd2str(W_TYPE_t type)
{
        switch(type) {
        case W_T_LOAD:  return "LOAD";
        case W_T_ENCODE:return "ENCODE";
        case W_T_DECODE:return "DECODE";
        case W_T_VERIFY:return "VERIFY";
        default:        return "Unknown";
        }
}

/*
 * Defaults and constants
 * common for IONODE and clients
 */

#define ISAL_USE_AVX2	259
#define ISAL_USE_SSE2	257
#if (HAVE_CPU_FEATURE_AVX2 == 1)
# define ISAL_CMD ISAL_USE_AVX2
#else
# define ISAL_CMD ISAL_USE_SSE2
#endif

#define N_XFER_SZ	1*1024*1024L
#define LFCLN_ITER	1
#define LFSRV_PORT	50666
#define LF_PROV_NAME	"sockets"
#define LFSRV_BUF_SZ	32*1024*1024*1024L
#define	N_PARITY	1
#define N_CHUNK_SZ	1*1024*1024L
#define N_WRK_COUNT	1
#define N_EXTENT_SZ	1*1024*1024*1024L
#define ION_CMD_MAX	16	/* maximum number of commands */
#define	IO_TIMEOUT_MS	30*1000 /* single I/O execution timeout, 30 sec */
#define LFSRV_RCTX_BITS 8	/* LF SRV: max number of rx contexts, bits */
#define LFSRV_START_TMO 15000	/* the timeout for start all LF servers */

/* default configuration command line */
#define LFS_COMMAND     "x -H 127.0.0.1 -c 127.0.0.1 -P0 --memreg scalable --provider sockets ENCODE"
#define LFS_MAXARGS     64
#define LFS_MAXCLIENTS	64

#define LF_MR_MODEL_SCALABLE	"scalable"
#define LF_MR_MODEL_LOCAL	"local"	/* FI_Mr_LOCAL */
#define LF_MR_MODEL_BASIC	"basic"
/* Default: scalable memory registration */
//#define LF_MR_MODEL	LF_MR_MODEL_BASIC
#define LF_MR_MODEL	LF_MR_MODEL_SCALABLE

#define MR_MODEL_BASIC_SYM    /* Don't set FI_MR_BASIC but (FI_MR_ALLOCATED, FI_MR_PROV_KEY, FI_MR_VIRT_ADDR) */

/*
 * Defaults and constants
 * IONODE
 */

#define ION_FORCE_RAID	256
#define ION_HW_MASK	0xff
#define LF_TARGET_RMA_EVENT	/* Require generation of completion events when target of RMA and/or atomics */

#endif /* FAMFS_ENV_H */
