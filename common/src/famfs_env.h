/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAMFS_ENV_H
#define FAMFS_ENV_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "config.h"


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

#define	IN_RANGE(v, mn, mx)	((v)>=(mn) && (v)<=(mx))/* [mn, mx] */
#define	IS_POWER2(v)		(!(((v)-1) & (v)))	/* is the value a power of 2? */
#define	DIV_CEIL(x, y)		(((x)+(y)-1)/(y))	/* divide and round up */
#define	ROUND_UP(x, y)		((((x)+(y)-1)/(y))*(y))	/* round up */
#define	ROUND_DOWN(n, sz)	(((n)/(sz)) * (sz))	/* floor */
#define TYPE_ALINGMENT(t)	offsetof(struct { unsigned char x; t test; }, test)

#ifndef container_of	/* defined in rdma/fabric.h */
#define container_of(ptr, type, member)	({					\
		const __typeof__( ((type *) NULL)->member ) *__mptr = (ptr);	\
		(type *)( (char *)__mptr - offsetof(type,member) );})
#endif /* container_of */

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
char *f_get_myhostname(void);
int f_find_node(char* const* nodelist, int node_cnt, const char *hostname);
int find_my_node(char* const* nodelist, int node_cnt, char **hostname);
void nodelist_free(char **nodelist, int size);
//int is_module_loaded(const char *name);
void alloc_affinity(int **affp, int size, int pos);
void ion_usage(const char *name);
void daemonize(void);
int f_parse_moniker(const char *moniker, int *data, int *parity,
    int *mirrors, size_t *chunk_size);


static inline size_t _getval(char *name, char *v, size_t df) {
    size_t  val = 0;
    char    *evv = NULL, *last;

    if (v)
        evv = v;
    else if(name)
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
        /* Ignore empty arg */
        while (*tok == ' ' || *tok == '\t')
            tok++;
        if (*tok)
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
 * Configurator: Default Values
 */
#define KIB 1024
#define MIB 1048576
#define GIB 1073741824

/* Metadata/MDHIM */
#define META_DEFAULT_DB_PATH /l/ssd/
#define META_DEFAULT_DB_NAME unifycr_db
#define META_DEFAULT_SERVER_RATIO 1
#define META_DEFAULT_RANGE_SZ MIB

/* Pool and layout defaults */
#define FAMFS_PDEVS_UUID_DEF	"00000000-0000-4000-8000-000000000000"
#define UNIFYCR_EXTENT_SIZE	(1 * GIB)
#define UNIFYCR_EXTENT0_OFFSET	0
#define UNIFYCR_ION_COUNT	1
#define UNIFYCR_LAYOUTS_COUNT	1
#define LAYOUT0_NAME		"1D:1M"

/* Limits: slab, stripe, device and layout */
#define F_DEVICES_MAX		4096	/* Maximum number of FAMs, divisible by 8 */
#define F_STRIPE_DISK_COUNT	F_DEVICES_MAX /* Max number of disks per stripe */
#define FVAR_MONIKER_MAX	14	/* Max moniker string lemgth */
#define F_CHUNK_SIZE_MIN	(4*KIB)	/* Minimum chunk size - 4K */
#define F_CHUNK_SIZE_MAX	(16*MIB)
#define F_LAYOUTS_MAX		1024	/* Maximum number of layouts, for config & maps */
#define F_IONODES_MAX		1024	/* Maximum number of IO nodes */

#define F_UUID_BUF_SIZE		(37)	/* Print buffer size for UUID */

/* Client */
#define UNIFYCR_INDEX_BUF_SIZE (20 * MIB)
#define UNIFYCR_FATTR_BUF_SIZE MIB

#define UNIFYCR_CHUNK_BITS 24
#define UNIFYCR_CHUNK_MEM 0
#define UNIFYCR_SPILLOVER_SIZE (KIB * MIB)
#define UNIFYCR_MOUNT_POINT /famfs

#define UNIFYCR_MAX_FILES        ( 128 )

#define UNIFYCR_SHMEM_REQ_SIZE 1024*1024*8*16 + 131072
#define UNIFYCR_SHMEM_RECV_SIZE 1024*1024 + 131072

/* Server */
#define UNIFYCR_DEFAULT_LOG_FILE famfs.log

#define MAX_META_PER_SEND 524288
#define ULFS_MAX_FILENAME 128
#define MAX_PATH_LEN 100
#define MAX_NUM_CLIENTS 64 /*number of application processes each server node takes charge of*/
#define RECV_BUF_CNT 1
#define RECV_BUF_LEN 1048576+131072
#define REQ_BUF_LEN 8*16*1048576+4096+131072

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
#define	N_PARITY	0
#define N_CHUNK_SZ	1*1024*1024L
#define N_WRK_COUNT	1
#define N_EXTENT_SZ	1*1024*1024*1024L
#define ION_CMD_MAX	16	/* maximum number of commands */
#define	IO_TIMEOUT_MS	30*1000 /* single I/O execution timeout, 30 sec */
#define LFSRV_RCTX_BITS 8	/* LF SRV: max number of rx contexts, bits */
//#define LFSRV_START_TMO 15000	/* the timeout for start all LF servers */

#define ZHPE_MODULE_NAME "zhpe"	/* libfabric provider's backend driver name */
#define UMMUNOTIFY_MODULE_NAME "ummunotify"
#define ZHPE_URL_TLT	"zhpe:///ion" /* zhpe url template */

/* default configuration command line */
#define LFS_COMMAND     "x -H 127.0.0.1 -c 127.0.0.1 -M 16M -E 8M -P0 --memreg scalable --provider sockets ENCODE"
#define LFS_MAXARGS     64
#define LFS_MAXCLIENTS	128	/* Max number of LF clients */

#define FAMFS_PROGRESS_AUTO	"default" /* "default", "manual" or "auto" */
#define LF_MR_MODEL_SCALABLE	"scalable"
#define LF_MR_MODEL_LOCAL	"local"	/* FI_MR_LOCAL */
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


#endif /* FAMFS_ENV_H */
