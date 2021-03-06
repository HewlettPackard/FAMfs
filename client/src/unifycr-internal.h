/*
 * (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor
 *   Boston, MA 02110-1301, USA.
 */

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

/*
 * Copyright (c) 2013, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * code Written by
 *   Raghunath Rajachandrasekar <rajachan@cse.ohio-state.edu>
 *   Kathryn Mohror <kathryn@llnl.gov>
 *   Adam Moody <moody20@llnl.gov>
 * All rights reserved.
 * This file is part of CRUISE.
 * For details, see https://github.com/hpc/cruise
 * Please also read this file LICENSE.CRUISE
 */

#ifndef UNIFYCR_INTERNAL_H
#define UNIFYCR_INTERNAL_H

/* this is overkill to include all of these here, but just to get things working... */
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <search.h>
#include <assert.h>
#include <libgen.h>
#include <limits.h>

#include "utlist.h"
#include "uthash.h"

#include "f_global.h"
#include "f_configurator.h"


/* TODO: Move common defs to another file ---> */

/* eventually could decouple these so there could be
 * more or less file descriptors than files, but for
 * now they're the same
 */
#define UNIFYCR_MAX_FILEDESCS    ( UNIFYCR_MAX_FILES )
#define UNIFYCR_STREAM_BUFSIZE   ( 1 * 1024 * 1024 )
#define UNIFYCR_SUPERBLOCK_KEY   ( 4321 )

// const for unifycr
#define SOCKET_PATH "/tmp/unifycr_server_sock"
#define UNIFYCR_MAX_SPLIT_CNT 1048576
#define UNIFYCR_MAX_READ_CNT 1048576

/* <--- */

/* -------------------------------
 * Defines and types
 * ------------------------------- */
extern int unifycr_debug_level;
extern int dbg_rank;

#define DEBUG(fmt, ...) \
do { \
    if (unifycr_debug_level > 0) \
        printf("[%d]: %s:%d: %s: " fmt "\n", \
               dbg_rank, __FILE__, __LINE__, __func__, ## __VA_ARGS__); \
} while (0)

#define DEBUG_LVL(lvl, fmt, ...) DEBUG_LVL_(unifycr_debug_level, lvl, fmt, ## __VA_ARGS__)

#define ERROR(fmt, ...)                                        \
    do {                                                       \
	fprintf(stderr, "[%d]: error in %s:%d: %s: " fmt "\n", \
                dbg_rank, __FILE__, __LINE__, __func__,        \
                ## __VA_ARGS__);                               \
    } while (0)

/* define a macro to capture function name, file name, and line number
 * along with user-defined string */
#define UNIFYCR_UNSUPPORTED(fmt, args...) \
      unifycr_unsupported(__func__, __FILE__, __LINE__, fmt, ##args)

#ifdef UNIFYCR_GOTCHA

/* gotcha fills in address of original/real function
 * and we need to declare function prototype for each
 * wrapper */
#define UNIFYCR_DECL(name,ret,args) \
      extern ret(*__real_ ## name)args;  \
      ret __wrap_ ## name args;

/* define each DECL function in a .c file */
#define UNIFYCR_DEF(name,ret,args) \
      ret(*__real_ ## name)args = NULL;

/* we define our wrapper function as __wrap_<iofunc> instead of <iofunc> */
#define UNIFYCR_WRAP(name) __wrap_ ## name

/* gotcha maps the <iofunc> call to __real_<iofunc>() */
#define UNIFYCR_REAL(name) __real_ ## name

/* no need to look up the address of the real function (gotcha does that) */
#define MAP_OR_FAIL(func)

#elif UNIFYCR_PRELOAD

/* ===================================================================
 * Using LD_PRELOAD to intercept
 * ===================================================================
 * we need to use the same function names the application is calling,
 * and we then invoke the real library function after looking it up with
 * dlsym */

/* we need the dlsym function */
#define __USE_GNU
#include <dlfcn.h>
#include <stdlib.h>

/* define a static variable called __real_open to record address of
 * real open call and initialize it to NULL */
#define UNIFYCR_DECL(name,ret,args) \
      static ret (*__real_ ## name)args = NULL;

/* our open wrapper assumes the name of open() */
#define UNIFYCR_WRAP(name) name

/* the address of the real open call is stored in __real_open variable */
#define UNIFYCR_REAL(name) __real_ ## name

/* if __real_open is still NULL, call dlsym to lookup address of real
 * function and record it */
#define MAP_OR_FAIL(func) \
        if (!(__real_ ## func)) \
        { \
            __real_ ## func = dlsym(RTLD_NEXT, #func); \
            if(!(__real_ ## func)) { \
               fprintf(stderr, "UNIFYCR failed to map symbol: %s\n", #func); \
               exit(1); \
           } \
        }
#else

/* ===================================================================
 * Using ld -wrap option to intercept
 * ===================================================================
 * the linker will convert application calls from open --> __wrap_open,
 * so we define all of our functions as the __wrap variant and then
 * to call the real library, we call __real_open */

/* we don't need a variable to record the address of the real function,
 * just declare the existence of __real_open so the compiler knows the
 * prototype of this function (linker will provide it) */
#define UNIFYCR_DECL(name,ret,args) \
      extern ret __real_ ## name args;  \

/* we define our wrapper function as __wrap_open instead of open */
#define UNIFYCR_WRAP(name) __wrap_ ## name

/* the linker maps the open call to __real_open() */
#define UNIFYCR_REAL(name) __real_ ## name

/* no need to look up the address of the real function */
#define MAP_OR_FAIL(func)

#endif

#define UNIFYCR_SUCCESS     0
#define UNIFYCR_FAILURE    -1
#define UNIFYCR_ERR_NOSPC  -2
#define UNIFYCR_ERR_IO     -3
#define UNIFYCR_ERR_NAMETOOLONG -4
#define UNIFYCR_ERR_NOENT  -5
#define UNIFYCR_ERR_EXIST  -6
#define UNIFYCR_ERR_NOTDIR -7
#define UNIFYCR_ERR_NFILE  -8
#define UNIFYCR_ERR_INVAL  -9
#define UNIFYCR_ERR_OVERFLOW -10
#define UNIFYCR_ERR_FBIG   -11
#define UNIFYCR_ERR_BADF   -12
#define UNIFYCR_ERR_ISDIR  -13
#define UNIFYCR_ERR_NOMEM  -14

#ifndef HAVE_OFF64_T
typedef int64_t off64_t;
#endif

/* structure to represent file descriptors */
typedef struct {
    off_t pos;   /* current file pointer */
    int   read;  /* whether file is opened for read */
    int   write; /* whether file is opened for write */

    int   fid;   /* local file id associated with fd */
} unifycr_fd_t;

enum unifycr_stream_orientation {
    UNIFYCR_STREAM_ORIENTATION_NULL = 0,
    UNIFYCR_STREAM_ORIENTATION_BYTE,
    UNIFYCR_STREAM_ORIENTATION_WIDE,
};

/* structure to represent FILE* streams */
typedef struct {
    int    err;      /* stream error indicator flag */
    int    eof;      /* stream end-of-file indicator flag */
    int    fd;       /* file descriptor associated with stream */
    int    append;   /* whether file is opened in append mode */
    int    orient;   /* stream orientation, UNIFYCR_STREAM_ORIENTATION_{NULL,BYTE,WIDE} */

    void  *buf;      /* pointer to buffer */
    int    buffree;  /* whether we need to free buffer */
    int    buftype;  /* _IOFBF fully buffered, _IOLBF line buffered, _IONBF unbuffered */
    size_t bufsize;  /* size of buffer in bytes */
    off_t  bufpos;   /* byte offset in file corresponding to start of buffer */
    size_t buflen;   /* number of bytes active in buffer */
    size_t bufdirty; /* whether data in buffer needs to be flushed */

    unsigned char *ubuf; /* ungetc buffer (we store bytes from end) */
    size_t ubufsize;     /* size of ungetc buffer in bytes */
    size_t ubuflen;      /* number of active bytes in buffer */

    unsigned char *_p; /* pointer to character in buffer */
    size_t         _r; /* number of bytes left at pointer */
} unifycr_stream_t;

/* TODO: make this an enum */
#define FILE_STORAGE_NULL        0
#define FILE_STORAGE_FIXED_CHUNK 1
#define FILE_STORAGE_LOGIO       2

/* TODO: make this an enum */
#define CHUNK_LOCATION_NULL      0
#define CHUNK_LOCATION_MEMFS     1
#define CHUNK_LOCATION_SPILLOVER 2


struct unifycr_filemeta_t_;

/* path to fid lookup struct */
typedef struct {
    int in_use; /* flag incidating whether slot is in use */
    const char filename[UNIFYCR_MAX_FILENAME];
    /* full path and name of file */
} unifycr_filename_t;

/*unifycr structures*/
typedef struct read_req_t_ {
    /* --> this substructure must match shm_meta_t */
    int fid;            /* client fid then FAMfs global fid */
    int lid;            /* layout id */
    long offset;
    long length;
    /* <-- */
    char *buf;
} read_req_t;

typedef struct {
    off_t *ptr_num_entries;
    md_index_t *index_entry;
} unifycr_index_buf_t;

typedef struct {
    off_t *ptr_num_entries;
    f_fattr_t *meta_entry;
} unifycr_fattr_buf_t;

typedef struct {
    md_index_t idxes[UNIFYCR_MAX_SPLIT_CNT];
    int count;
} index_set_t;

typedef struct {
    read_req_t read_reqs[UNIFYCR_MAX_READ_CNT];
    int count;
} read_req_set_t;

/* --------------------------------------
 * sysio/stdio interface: UNIFYCR or FAMFS
 * --------------------------------------- */
typedef int (*f_fid_open) (const char *path, int flags, mode_t mode,
    int *outfid, off_t *outpos);
typedef int (*f_fid_close) (int fid);
typedef int (*f_fid_extend) (int fid, off_t length);
typedef int (*f_fid_shrink) (int fid, off_t length);
typedef int (*f_fid_write) (int fid, off_t pos, const void *buf, size_t count);
typedef off_t (*f_fid_size) (int fid);
/* truncate file id to given length, frees resources if length is
 * less than size and allocates and zero-fills new bytes if length
 * is more than size */
typedef int (*f_fid_truncate) (int fid, off_t length);
/* delete a file id and free data management resource for file */
typedef int (*f_fid_unlink) (int fid);

typedef int (*f_fd_logreadlist) (read_req_t *read_req, int count);
typedef int (*f_fd_fsync) (int fd);

typedef struct f_fd_iface_ {
    f_fid_open		fid_open;
    f_fid_close		fid_close;
    f_fid_extend	fid_extend;
    f_fid_shrink	fid_shrink;
    f_fid_write		fid_write;
    f_fid_size		fid_size;
    f_fid_truncate	fid_truncate;
    f_fid_unlink	fid_unlink;
    /* direct wrapper fn used in unifycr-sysio.c */
    f_fd_logreadlist	fd_logreadlist;
    f_fd_fsync		fd_fsync;
} F_FD_IFACE_t;
/* --------------------------------------- */

read_req_set_t read_req_set;
read_req_set_t tmp_read_req_set;
index_set_t tmp_index_set;

//extern int *local_rank_lst;
//extern int local_rank_cnt;
extern int local_rank_idx;
//extern int local_del_cnt;
extern int client_sockfd;
extern struct pollfd cmd_fd;
extern long shm_req_size;
extern long shm_recv_size;
extern char *shm_recvbuf;
extern char *shm_reqbuf;
extern int fs_type;
extern char cmd_buf[GEN_STR_LEN];
extern char ack_msg[3];
extern unifycr_fattr_buf_t unifycr_fattrs;
extern unifycr_index_buf_t unifycr_indices;
extern int my_srv_rank;

extern int glb_superblock_size;
extern int reqbuf_fd;
extern int recvbuf_fd;
extern int superblock_fd;
extern long unifycr_key_slice_range;

extern F_FD_IFACE_t *fd_iface;


/* -------------------------------
 * Global varaible declarations
 * ------------------------------- */

/*definition for unifycr*/
#define UNIFYCR_CLI_TIME_OUT 5000

typedef enum {
    COMM_MOUNT,
    COMM_META,
    COMM_READ,
    COMM_UNMOUNT,
    COMM_DIGEST,
    COMM_SYNC_DEL,
    COMM_MDGET,
} cmd_lst_t;

typedef enum {
    ACK_SUCCESS,
    ACK_FAIL,
} ack_status_t;

/* keep track of what we've initialized */
extern int unifycr_initialized;

/* list of file names */
extern unifycr_filename_t *unifycr_filelist;

/* mount directory */
extern char  *unifycr_mount_prefix;
extern size_t unifycr_mount_prefixlen;

/* array of file descriptors */
extern unifycr_fd_t unifycr_fds[UNIFYCR_MAX_FILEDESCS];
extern rlim_t unifycr_fd_limit;

/* array of file streams */
extern unifycr_stream_t unifycr_streams[UNIFYCR_MAX_FILEDESCS];

extern int unifycr_use_memfs;
extern int unifycr_use_spillover;

extern int    unifycr_max_files;  /* maximum number of files to store */
extern size_t
unifycr_chunk_mem;  /* number of bytes in memory to be used for chunk storage */
extern int    unifycr_chunk_bits; /* we set chunk size = 2^unifycr_chunk_bits */
extern size_t  unifycr_chunk_size; /* chunk size in bytes */
extern off_t
unifycr_chunk_mask; /* mask applied to logical offset to determine physical offset within chunk */
extern long
unifycr_max_chunks; /* maximum number of chunks that fit in memory */

extern void *free_chunk_stack;
extern void *free_spillchunk_stack;
extern char *unifycr_chunks;
int unifycr_spilloverblock;


/* -------------------------------
 * Common functions
 * ------------------------------- */

/* single function to route all unsupported wrapper calls through */
int unifycr_unsupported(const char *fn_name, const char *file, int line,
                        const char *fmt, ...);

/* returns 1 if two input parameters will overflow their type when
 * added together */
int unifycr_would_overflow_offt(off_t a, off_t b);

/* returns 1 if two input parameters will overflow their type when
 * added together */
int unifycr_would_overflow_long(long a, long b);

/* given an input mode, mask it with umask and return, can specify
 * an input mode==0 to specify all read/write bits */
mode_t unifycr_getmode(mode_t perms);

int unifycr_stack_lock();

int unifycr_stack_unlock();

/* normalize full path of a file or directory */
char *posix_normalized_path(const char *path, char *buf, size_t buf_sz);
char *normalized_path(const char *path, char *buf, size_t buf_sz);

/* sets flag if the path is a special path */
int unifycr_intercept_path(const char *path);

/* given an fd, return 1 if we should intercept this file, 0 otherwise,
 * convert fd to new fd value if needed */
int unifycr_intercept_fd(int *fd);

/* given a FILE*, returns 1 if we should intercept this file,
 * 0 otherwise */
int unifycr_intercept_stream(FILE *stream);

/* given a path, return the file id */
int unifycr_get_fid_from_path(const char *path);
int unifycr_get_fid_from_norm_path(const char *norm_path);

/* given a file descriptor, return the file id */
int unifycr_get_fid_from_fd(int fd);

/* initialze file descriptor structure corresponding to fd value */
void unifycr_fd_init(int fd);

/* given a file descriptor, calculate MD5 hash and return gfid */
int unifycr_get_global_fid(const char *path, int *gfid);

/* lookup in filedesc array for gfid, return local fid or -1 */
int famfs_fid_from_gfid(int gfid);

/* return address of file descriptor structure or NULL if fd is out
 * of range */
unifycr_fd_t *unifycr_get_filedesc_from_fd(int fd);

/* given a file id, return a pointer to the meta data,
 * otherwise return NULL */
struct unifycr_filemeta_t_ *unifycr_get_meta_from_fid(int fid);

/* insert file attribute to attributed share memory buffer */
int ins_file_meta(unifycr_fattr_buf_t *ptr_f_meta_log,
                  f_fattr_t *ins_fattr);

/* given an UNIFYCR error code, return corresponding errno code */
int unifycr_err_map_to_errno(int rc);

/* checks to see if fid is a directory
 * returns 1 for yes
 * returns 0 for no */
int unifycr_fid_is_dir(int fid);

/* checks to see if a directory is empty
 * assumes that check for is_dir has already been made
 * only checks for full path matches, does not check relative paths,
 * e.g. ../dirname will not work
 * returns 1 for yes it is empty
 * returns 0 for no */
int unifycr_fid_is_dir_empty(const char *path);

unsigned long unifycr_fid_is_dir_used(int fid, unsigned long* max_files);
int unifycr_report_storage(int fid, size_t *total, size_t *free);

/* fill in limited amount of stat information */
int unifycr_fid_stat(int fid, struct stat *buf);

/* allocate a file id slot for a new file
 * return the fid or -1 on error */
int unifycr_fid_alloc();

/* return the file id back to the free pool */
int unifycr_fid_free(int fid);

/* add a new file and initialize metadata
 * returns the new fid, or negative value on error */
//int unifycr_fid_create_file(const char *path, int loid);

/* add a new directory and initialize metadata
 * returns the new fid, or a negative value on error */
int unifycr_fid_create_directory(const char *path);

/* read count bytes from file starting from pos and store into buf,
 * all bytes are assumed to exist, so checks on file size should be
 * done before calling this routine */
int unifycr_fid_read(int fid, off_t pos, void *buf, size_t count);

/* given a file id, write zero bytes to region of specified offset
 * and length, assumes space is already reserved */
int unifycr_fid_write_zero(int fid, off_t pos, off_t count);

/*functions used in UnifyCR*/
int unifycr_coalesce_read_reqs(read_req_t *read_req, int count,
                               read_req_set_t *tmp_read_req_set, long unifycr_key_slice_range,
                               read_req_set_t *read_req_set);
int unifycr_match_received_ack(read_req_t *read_req, int count,
                               read_req_t *match_req);
int unifycr_locate_req(read_req_t *read_req, int count,
                       read_req_t *match_req);

int compare_fattr(const void *a, const void *b);

#endif /* UNIFYCR_INTERNAL_H */
