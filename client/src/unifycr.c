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

#define _GNU_SOURCE
#include <sched.h>
#include "unifycr-runtime-config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
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
#include <pthread.h>
#include <mpi.h>
#include <openssl/md5.h>
//#define __USE_GNU


#ifdef ENABLE_NUMA_POLICY
#include <numa.h>
#endif

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sched.h>

#include "unifycr-internal.h"

#ifdef MACHINE_BGQ
/* BG/Q to get personality and persistent memory */
#include <sys/mman.h>
#include <hwi/include/common/uci.h>
#include <firmware/include/personality.h>
#include <spi/include/kernel/memory.h>
#include "mpi.h"
#include <mpix.h>
#endif /* MACHINE_BGQ */

#ifdef UNIFYCR_GOTCHA
#include "gotcha/gotcha_types.h"
#include "gotcha/gotcha.h"
#include "gotcha_map_unifycr_list.h"
#endif

int local_rank_idx = 0;

#ifndef HAVE_OFF64_T
typedef int64_t off64_t;
#endif

static int unifycr_fpos_enabled   = 1;  /* whether we can use fgetpos/fsetpos */
/*
 * unifycr variable:
 * */

fs_type_t fs_type = UNIFYCRFS;
unifycr_index_buf_t unifycr_indices;
unifycr_fattr_buf_t unifycr_fattrs;
static size_t
unifycr_index_buf_size;   /* size of metadata log for log-structured io*/
static size_t unifycr_fattr_buf_size;
unsigned long
unifycr_max_index_entries; /*max number of metadata entries for log-structured write*/
unsigned int unifycr_max_fattr_entries;
int glb_superblock_size;
int unifycr_spillmetablock;

int *local_rank_lst = NULL;
int local_rank_cnt = 0;

int local_del_cnt = 0;
int client_sockfd;
struct pollfd cmd_fd;
long shm_req_size = UNIFYCR_DEF_REQ_SIZE;
long shm_recv_size = UNIFYCR_DEF_RECV_SIZE;
char *shm_recvbuf;
char *shm_reqbuf;
char cmd_buf[GEN_STR_LEN] = {0};
char ack_msg[3] = {0};

int dbg_rank;
int app_id;
int glb_size;
int reqbuf_fd = -1;
int recvbuf_fd = -1;
int superblock_fd = -1;
long unifycr_key_slice_range;


int unifycr_use_logio = 0;
int unifycr_use_memfs      = 1;
int unifycr_use_spillover = 1;

static int unifycr_use_single_shm = 0;
static int unifycr_page_size      = 0;

static off_t unifycr_max_offt;
static off_t unifycr_min_offt;
static off_t unifycr_max_long;
static off_t unifycr_min_long;

/* TODO: moved these to fixed file */
int dbgrank;
int    unifycr_max_files;  /* maximum number of files to store */
size_t unifycr_chunk_mem;  /* number of bytes in memory to be used for chunk storage */
int    unifycr_chunk_bits; /* we set chunk size = 2^unifycr_chunk_bits */
off_t  unifycr_chunk_size; /* chunk size in bytes */
off_t  unifycr_chunk_mask; /* mask applied to logical offset to determine physical offset within chunk */
long    unifycr_max_chunks; /* maximum number of chunks that fit in memory */

static size_t
unifycr_spillover_size;  /* number of bytes in spillover to be used for chunk storage */
long    unifycr_spillover_max_chunks; /* maximum number of chunks that fit in spillover storage */



#ifdef ENABLE_NUMA_POLICY
static char unifycr_numa_policy[10];
static int unifycr_numa_bank = -1;
#endif

extern pthread_mutex_t unifycr_stack_mutex;

/* keep track of what we've initialized */
int unifycr_initialized = 0;

/* global persistent memory block (metadata + data) */
void *unifycr_superblock = NULL;
static void *free_fid_stack = NULL;
void *free_chunk_stack = NULL;
void *free_spillchunk_stack = NULL;
unifycr_filename_t *unifycr_filelist    = NULL;
static unifycr_filemeta_t *unifycr_filemetas   = NULL;
static unifycr_chunkmeta_t *unifycr_chunkmetas = NULL;

char *unifycr_chunks = NULL;
int unifycr_spilloverblock = 0;
int unifycr_spillmetablock = 0; /*used for log-structured i/o*/

/* array of file descriptors */
unifycr_fd_t unifycr_fds[UNIFYCR_MAX_FILEDESCS];
rlim_t unifycr_fd_limit;

/* array of file streams */
unifycr_stream_t unifycr_streams[UNIFYCR_MAX_FILEDESCS];

/* mount point information */
char  *unifycr_mount_prefix = NULL;
size_t unifycr_mount_prefixlen = 0;
static key_t  unifycr_mount_shmget_key = 0;

/* mutex to lock stack operations */
pthread_mutex_t unifycr_stack_mutex = PTHREAD_MUTEX_INITIALIZER;

/* path of external storage's mount point*/

char external_data_dir[1024] = {0};
char external_meta_dir[1024] = {0};

/* single function to route all unsupported wrapper calls through */
int unifycr_vunsupported(
    const char *fn_name,
    const char *file,
    int line,
    const char *fmt,
    va_list args)
{
    /* print a message about where in the UNIFYCR code we are */
    printf("UNSUPPORTED: %s() at %s:%d: ", fn_name, file, line);

    /* print string with more info about call, e.g., param values */
    va_list args2;
    va_copy(args2, args);
    vprintf(fmt, args2);
    va_end(args2);

    /* TODO: optionally abort */

    return UNIFYCR_SUCCESS;
}

/* single function to route all unsupported wrapper calls through */
int unifycr_unsupported(
    const char *fn_name,
    const char *file,
    int line,
    const char *fmt,
    ...)
{
    /* print string with more info about call, e.g., param values */
    va_list args;
    va_start(args, fmt);
    int rc = unifycr_vunsupported(fn_name, file, line, fmt, args);
    va_end(args);
    return rc;
}

/* given an UNIFYCR error code, return corresponding errno code */
int unifycr_err_map_to_errno(int rc)
{
    switch (rc) {
    case UNIFYCR_SUCCESS:
        return 0;
    case UNIFYCR_FAILURE:
        return EIO;
    case UNIFYCR_ERR_NOSPC:
        return ENOSPC;
    case UNIFYCR_ERR_IO:
        return EIO;
    case UNIFYCR_ERR_NAMETOOLONG:
        return ENAMETOOLONG;
    case UNIFYCR_ERR_NOENT:
        return ENOENT;
    case UNIFYCR_ERR_EXIST:
        return EEXIST;
    case UNIFYCR_ERR_NOTDIR:
        return ENOTDIR;
    case UNIFYCR_ERR_NFILE:
        return ENFILE;
    case UNIFYCR_ERR_INVAL:
        return EINVAL;
    case UNIFYCR_ERR_OVERFLOW:
        return EOVERFLOW;
    case UNIFYCR_ERR_FBIG:
        return EFBIG;
    case UNIFYCR_ERR_BADF:
        return EBADF;
    case UNIFYCR_ERR_ISDIR:
        return EISDIR;
    case UNIFYCR_ERR_NOMEM:
        return ENOMEM;
    }
    return EIO;
}

/* given an errno error code, return corresponding UnifyCR error code */
int unifycr_errno_map_to_err(int rc)
{
    switch (rc) {
    case 0:
        return UNIFYCR_SUCCESS;
    case ENOSPC:
        return UNIFYCR_ERR_NOSPC;
    case EIO:
        return UNIFYCR_ERR_IO;
    case ENAMETOOLONG:
        return UNIFYCR_ERR_NAMETOOLONG;
    case ENOENT:
        return UNIFYCR_ERR_NOENT;
    case EEXIST:
        return UNIFYCR_ERR_EXIST;
    case ENOTDIR:
        return UNIFYCR_ERR_NOTDIR;
    case ENFILE:
        return UNIFYCR_ERR_NFILE;
    case EINVAL:
        return UNIFYCR_ERR_INVAL;
    case EOVERFLOW:
        return UNIFYCR_ERR_OVERFLOW;
    case EFBIG:
        return UNIFYCR_ERR_FBIG;
    case EBADF:
        return UNIFYCR_ERR_BADF;
    case EISDIR:
        return UNIFYCR_ERR_ISDIR;
    case ENOMEM:
        return UNIFYCR_ERR_NOMEM;
    }
    return UNIFYCR_FAILURE;
}

/* returns 1 if two input parameters will overflow their type when
 * added together */
inline int unifycr_would_overflow_offt(off_t a, off_t b)
{
    /* if both parameters are positive, they could overflow when
     * added together */
    if (a > 0 && b > 0) {
        /* if the distance between a and max is greater than or equal to
         * b, then we could add a and b and still not exceed max */
        if (unifycr_max_offt - a >= b) {
            return 0;
        }
        return 1;
    }

    /* if both parameters are negative, they could underflow when
     * added together */
    if (a < 0 && b < 0) {
        /* if the distance between min and a is less than or equal to
         * b, then we could add a and b and still not exceed min */
        if (unifycr_min_offt - a <= b) {
            return 0;
        }
        return 1;
    }

    /* if a and b are mixed signs or at least one of them is 0,
     * then adding them together will produce a result closer to 0
     * or at least no further away than either value already is*/
    return 0;
}

/* returns 1 if two input parameters will overflow their type when
 * added together */
inline int unifycr_would_overflow_long(long a, long b)
{
    /* if both parameters are positive, they could overflow when
     * added together */
    if (a > 0 && b > 0) {
        /* if the distance between a and max is greater than or equal to
         * b, then we could add a and b and still not exceed max */
        if (unifycr_max_long - a >= b) {
            return 0;
        }
        return 1;
    }

    /* if both parameters are negative, they could underflow when
     * added together */
    if (a < 0 && b < 0) {
        /* if the distance between min and a is less than or equal to
         * b, then we could add a and b and still not exceed min */
        if (unifycr_min_long - a <= b) {
            return 0;
        }
        return 1;
    }

    /* if a and b are mixed signs or at least one of them is 0,
     * then adding them together will produce a result closer to 0
     * or at least no further away than either value already is*/
    return 0;
}

/* given an input mode, mask it with umask and return, can specify
 * an input mode==0 to specify all read/write bits */
mode_t unifycr_getmode(mode_t perms)
{
    /* perms == 0 is shorthand for all read and write bits */
    if (perms == 0) {
        perms = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
    }

    /* get current user mask */
    mode_t mask = umask(0);
    umask(mask);

    /* mask off bits from desired permissions */
    mode_t ret = perms & ~mask & 0777;
    return ret;
}

inline int unifycr_stack_lock()
{
    if (unifycr_use_single_shm) {
        return pthread_mutex_lock(&unifycr_stack_mutex);
    }
    return 0;
}

inline int unifycr_stack_unlock()
{
    if (unifycr_use_single_shm) {
        return pthread_mutex_unlock(&unifycr_stack_mutex);
    }
    return 0;
}

/* sets flag if the path is a special path */
inline int unifycr_intercept_path(const char *path)
{
    /* don't intecept anything until we're initialized */
    if (! unifycr_initialized) {
        return 0;
    }

    /* if the path starts with our mount point, intercept it */
    if (strncmp(path, unifycr_mount_prefix, unifycr_mount_prefixlen) == 0) {
        return 1;
    }
    return 0;
}

/* given an fd, return 1 if we should intercept this file, 0 otherwise,
 * convert fd to new fd value if needed */
inline int unifycr_intercept_fd(int *fd)
{
    int oldfd = *fd;

    /* don't intecept anything until we're initialized */
    if (! unifycr_initialized) {
        return 0;
    }

    if (oldfd < unifycr_fd_limit) {
        /* this fd is a real system fd, so leave it as is */
        return 0;
    } else if (oldfd < 0) {
        /* this is an invalid fd, so we should not intercept it */
        return 0;
    } else {
        /* this is an fd we generated and returned to the user,
         * so intercept the call and shift the fd */
        int newfd = oldfd - unifycr_fd_limit;
        *fd = newfd;
        debug("Changing fd from exposed %d to internal %d\n", oldfd, newfd);
        return 1;
    }
}

/* given an fd, return 1 if we should intercept this file, 0 otherwise,
 * convert fd to new fd value if needed */
inline int unifycr_intercept_stream(FILE *stream)
{
    /* don't intecept anything until we're initialized */
    if (! unifycr_initialized) {
        return 0;
    }

    /* check whether this pointer lies within range of our
     * file stream array */
    unifycr_stream_t *ptr   = (unifycr_stream_t *) stream;
    unifycr_stream_t *start = &(unifycr_streams[0]);
    unifycr_stream_t *end   = &(unifycr_streams[UNIFYCR_MAX_FILEDESCS]);
    if (ptr >= start && ptr < end) {
        return 1;
    }

    return 0;
}

/* given a path, return the file id */
inline int unifycr_get_fid_from_path(const char *path)
{
    int i = 0;
    while (i < unifycr_max_files) {
        if (unifycr_filelist[i].in_use &&
            strcmp((void *)&unifycr_filelist[i].filename, path) == 0) {
            debug("File found: unifycr_filelist[%d].filename = %s\n",
                  i, (char *)&unifycr_filelist[i].filename
                 );
            return i;
        }
        i++;
    }

    /* couldn't find specified path */
    return -1;
}

/* given a file descriptor, return the file id */
inline int unifycr_get_fid_from_fd(int fd)
{
    /* check that file descriptor is within range */
    if (fd < 0 || fd >= UNIFYCR_MAX_FILEDESCS) {
        return -1;
    }

    /* right now, the file descriptor is equal to the file id */
    return fd;
}

/* return address of file descriptor structure or NULL if fd is out
 * of range */
inline unifycr_fd_t *unifycr_get_filedesc_from_fd(int fd)
{
    if (fd >= 0 && fd < UNIFYCR_MAX_FILEDESCS) {
        unifycr_fd_t *filedesc = &(unifycr_fds[fd]);
        return filedesc;
    }
    return NULL;
}

/* given a file id, return a pointer to the meta data,
 * otherwise return NULL */
unifycr_filemeta_t *unifycr_get_meta_from_fid(int fid)
{
    /* check that the file id is within range of our array */
    if (fid >= 0 && fid < unifycr_max_files) {
        /* get a pointer to the file meta data structure */
        unifycr_filemeta_t *meta = &unifycr_filemetas[fid];
        return meta;
    }
    return NULL;
}

/* ---------------------------------------
 * Operations on file storage
 * --------------------------------------- */

/* allocate and initialize data management resource for file */
static int unifycr_fid_store_alloc(int fid)
{
    /* get meta data for this file */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);

    if (fs_type == UNIFYCR_LOG) {
        meta->storage = FILE_STORAGE_LOGIO;
    } else if (unifycr_use_memfs || unifycr_use_spillover) {
        /* we used fixed-size chunk storage for memfs and spillover */
        meta->storage = FILE_STORAGE_FIXED_CHUNK;
    }


    return UNIFYCR_SUCCESS;
}

/* free data management resource for file */
static int unifycr_fid_store_free(int fid)
{
    /* get meta data for this file */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);

    return UNIFYCR_SUCCESS;
}

/* ---------------------------------------
 * Operations on file ids
 * --------------------------------------- */

/* checks to see if fid is a directory
 * returns 1 for yes
 * returns 0 for no */
int unifycr_fid_is_dir(int fid)
{
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    if (meta) {
        /* found a file with that id, return value of directory flag */
        int rc = meta->is_dir;
        return rc;
    } else {
        /* if it doesn't exist, then it's not a directory? */
        return 0;
    }
}

/* checks to see if a directory is empty
 * assumes that check for is_dir has already been made
 * only checks for full path matches, does not check relative paths,
 * e.g. ../dirname will not work
 * returns 1 for yes it is empty
 * returns 0 for no */
int unifycr_fid_is_dir_empty(const char *path)
{
    int i = 0;
    while (i < unifycr_max_files) {
        if (unifycr_filelist[i].in_use) {
            /* if the file starts with the path, it is inside of that directory
             * also check to make sure that it's not the directory entry itself */
            char *strptr = strstr(path, unifycr_filelist[i].filename);
            if (strptr == unifycr_filelist[i].filename
                && strcmp(path, unifycr_filelist[i].filename)) {
                debug("File found: unifycr_filelist[%d].filename = %s\n",
                      i, (char *)&unifycr_filelist[i].filename
                     );
                return 0;
            }
        }
        ++i;
    }

    /* couldn't find any files with this prefix, dir must be empty */
    return 1;
}

/* return current size of given file id */
off_t unifycr_fid_size(int fid)
{
    /* get meta data for this file */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    return meta->size;
}

/* fill in limited amount of stat information */
int unifycr_fid_stat(int fid, struct stat *buf)
{
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    if (meta == NULL) {
        return -1;
    }

    /* initialize all the values */
    buf->st_dev = 0;     /* ID of device containing file */
    buf->st_ino = 0;     /* inode number */
    buf->st_mode = 0;    /* protection */
    buf->st_nlink = 0;   /* number of hard links */
    buf->st_uid = 0;     /* user ID of owner */
    buf->st_gid = 0;     /* group ID of owner */
    buf->st_rdev = 0;    /* device ID (if special file) */
    buf->st_size = 0;    /* total size, in bytes */
    buf->st_blksize = 0; /* blocksize for file system I/O */
    buf->st_blocks = 0;  /* number of 512B blocks allocated */
    buf->st_atime = 0;   /* time of last access */
    buf->st_mtime = 0;   /* time of last modification */
    buf->st_ctime = 0;   /* time of last status change */

    /* set the file size */
    buf->st_size = meta->size;

    /* specify whether item is a file or directory */
    if (unifycr_fid_is_dir(fid)) {
        buf->st_mode |= S_IFDIR;
    } else {
        buf->st_mode |= S_IFREG;
    }

    return 0;
}

/* allocate a file id slot for a new file
 * return the fid or -1 on error */
int unifycr_fid_alloc()
{
    unifycr_stack_lock();
    int fid = unifycr_stack_pop(free_fid_stack);
    unifycr_stack_unlock();
    debug("unifycr_stack_pop() gave %d\n", fid);
    if (fid < 0) {
        /* need to create a new file, but we can't */
        debug("unifycr_stack_pop() failed (%d)\n", fid);
        return -1;
    }
    return fid;
}

/* return the file id back to the free pool */
int unifycr_fid_free(int fid)
{
    unifycr_stack_lock();
    unifycr_stack_push(free_fid_stack, fid);
    unifycr_stack_unlock();
    return UNIFYCR_SUCCESS;
}

/* add a new file and initialize metadata
 * returns the new fid, or negative value on error */
int unifycr_fid_create_file(const char *path)
{
    int fid = unifycr_fid_alloc();
    if (fid < 0)  {
        /* was there an error? if so, return it */
        errno = ENOSPC;
        return fid;
    }

    /* mark this slot as in use and copy the filename */
    unifycr_filelist[fid].in_use = 1;
    /* TODO: check path length to see if it is < 128 bytes
     * and return appropriate error if it is greater
     */
    strcpy((void *)&unifycr_filelist[fid].filename, path);
    debug("Filename %s got unifycr fd %d\n", unifycr_filelist[fid].filename, fid);

    /* initialize meta data */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    meta->size    = 0;
    meta->chunks  = 0;
    meta->is_dir  = 0;
    meta->real_size = 0;
    meta->storage = FILE_STORAGE_NULL;
    meta->flock_status = UNLOCKED;
    /* PTHREAD_PROCESS_SHARED allows Process-Shared Synchronization*/
    pthread_spin_init(&meta->fspinlock, PTHREAD_PROCESS_SHARED);

    return fid;
}

/* add a new directory and initialize metadata
 * returns the new fid, or a negative value on error */
int unifycr_fid_create_directory(const char *path)
{
    /* set everything we do for a file... */
    int fid = unifycr_fid_create_file(path);
    if (fid < 0) {
        /* was there an error? if so, return it */
        errno = ENOSPC;
        return fid;
    }

    /* ...and a little more */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    meta->is_dir = 1;
    return fid;
}

/* read count bytes from file starting from pos and store into buf,
 * all bytes are assumed to exist, so checks on file size should be
 * done before calling this routine */
int unifycr_fid_read(int fid, off_t pos, void *buf, size_t count)
{
    int rc;

    /* short-circuit a 0-byte read */
    if (count == 0) {
        return UNIFYCR_SUCCESS;
    }

    /* get meta for this file id */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);

    /* determine storage type to read file data */
    if (meta->storage == FILE_STORAGE_FIXED_CHUNK) {
        /* file stored in fixed-size chunks */
        rc = unifycr_fid_store_fixed_read(fid, meta, pos, buf, count);
    } else {
        /* unknown storage type */
        rc = UNIFYCR_ERR_IO;
    }

    return rc;
}

/* write count bytes from buf into file starting at offset pos,
 * all bytes are assumed to be allocated to file, so file should
 * be extended before calling this routine */
int unifycr_fid_write(int fid, off_t pos, const void *buf, size_t count)
{
    int rc;

    /* short-circuit a 0-byte write */
    if (count == 0) {
        return UNIFYCR_SUCCESS;
    }

    /* get meta for this file id */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);

    /* determine storage type to write file data */
    if (meta->storage == FILE_STORAGE_FIXED_CHUNK ||
        meta->storage == FILE_STORAGE_LOGIO) {
        /* file stored in fixed-size chunks */
        rc = unifycr_fid_store_fixed_write(fid, meta, pos, buf, count);
    } else {
        /* unknown storage type */
        rc = UNIFYCR_ERR_IO;
    }

    return rc;
}

/* given a file id, write zero bytes to region of specified offset
 * and length, assumes space is already reserved */
int unifycr_fid_write_zero(int fid, off_t pos, off_t count)
{
    int rc = UNIFYCR_SUCCESS;

    /* allocate an aligned chunk of memory */
    size_t buf_size = 1024 * 1024;
    void *buf = (void *) malloc(buf_size);
    if (buf == NULL) {
        return UNIFYCR_ERR_IO;
    }

    /* set values in this buffer to zero */
    memset(buf, 0, buf_size);

    /* write zeros to file */
    off_t written = 0;
    off_t curpos = pos;
    while (written < count) {
        /* compute number of bytes to write on this iteration */
        size_t num = buf_size;
        off_t remaining = count - written;
        if (remaining < (off_t) buf_size) {
            num = (size_t) remaining;
        }

        /* write data to file */
        int write_rc = unifycr_fid_write(fid, curpos, buf, num);
        if (write_rc != UNIFYCR_SUCCESS) {
            rc = UNIFYCR_ERR_IO;
            break;
        }

        /* update the number of bytes written */
        curpos  += (off_t) num;
        written += (off_t) num;
    }

    /* free the buffer */
    free(buf);

    return rc;
}

/* increase size of file if length is greater than current size,
 * and allocate additional chunks as needed to reserve space for
 * length bytes */
int unifycr_fid_extend(int fid, off_t length)
{
    int rc;

    /* get meta data for this file */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);

    /* determine file storage type */
    if (meta->storage == FILE_STORAGE_FIXED_CHUNK |
        meta->storage == FILE_STORAGE_LOGIO) {
        /* file stored in fixed-size chunks */
        rc = unifycr_fid_store_fixed_extend(fid, meta, length);
    } else {
        /* unknown storage type */
        rc = UNIFYCR_ERR_IO;
    }

    /* TODO: move this statement elsewhere */
    /* increase file size up to length */
    if (meta->storage == FILE_STORAGE_FIXED_CHUNK)
        if (length > meta->size) {
            meta->size = length;
        }

    return rc;
}

/* if length is less than reserved space, give back space down to length */
int unifycr_fid_shrink(int fid, off_t length)
{
    int rc;

    /* get meta data for this file */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);

    /* determine file storage type */
    if (meta->storage == FILE_STORAGE_FIXED_CHUNK) {
        /* file stored in fixed-size chunks */
        rc = unifycr_fid_store_fixed_shrink(fid, meta, length);
    } else {
        /* unknown storage type */
        rc = UNIFYCR_ERR_IO;
    }

    return rc;
}

/* truncate file id to given length, frees resources if length is
 * less than size and allocates and zero-fills new bytes if length
 * is more than size */
int unifycr_fid_truncate(int fid, off_t length)
{
    /* get meta data for this file */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);

    /* get current size of file */
    off_t size = meta->size;

    /* drop data if length is less than current size,
     * allocate new space and zero fill it if bigger */
    if (length < size) {
        /* determine the number of chunks to leave after truncating */
        int shrink_rc = unifycr_fid_shrink(fid, length);
        if (shrink_rc != UNIFYCR_SUCCESS) {
            return shrink_rc;
        }
    } else if (length > size) {
        /* file size has been extended, allocate space */
        int extend_rc = unifycr_fid_extend(fid, length);
        if (extend_rc != UNIFYCR_SUCCESS) {
            return UNIFYCR_ERR_NOSPC;
        }

        /* write zero values to new bytes */
        off_t gap_size = length - size;
        int zero_rc = unifycr_fid_write_zero(fid, size, gap_size);
        if (zero_rc != UNIFYCR_SUCCESS) {
            return UNIFYCR_ERR_IO;
        }
    }

    /* set the new size */
    meta->size = length;

    return UNIFYCR_SUCCESS;
}

/*
 * hash a path to gfid
 * @param path: file path
 * return: error code, gfid
 * */
static int unifycr_get_global_fid(const char *path, int *gfid)
{
    MD5_CTX ctx;

    unsigned char md[16];
    memset(md, 0, 16);

    int i;
    MD5_Init(&ctx);
    MD5_Update(&ctx, path, strlen(path));
    MD5_Final(md, &ctx);

    *gfid = *((int *)md);
    return UNIFYCR_SUCCESS;
}

/*
 * send global file metadata to the delegator,
 * which puts it to the key-value store
 * @param gfid: global file id
 * @return: error code
 * */
static int set_global_file_meta(unifycr_fattr_t *f_meta)
{
    int cmd = COMM_META;
    int flag = 2;
    memcpy(cmd_buf, &cmd, sizeof(int));
    memcpy(cmd_buf + sizeof(int), &flag, sizeof(int));
    memcpy(cmd_buf + sizeof(int) + sizeof(int),
           f_meta, sizeof(unifycr_fattr_t));

    int rc = __real_write(client_sockfd, cmd_buf, sizeof(cmd_buf));
    if (rc != 0) {
        int bytes_read = 0;
        cmd_fd.events = POLLIN | POLLPRI;
        cmd_fd.revents = 0;

        rc = poll(&cmd_fd, 1, -1);

        if (rc == 0) {
            /* encounter timeout*/
            return -1;
        } else {
            if (rc > 0) {
                if (cmd_fd.revents != 0) {
                    if (cmd_fd.revents == POLLIN) {
                        bytes_read = __real_read(client_sockfd,
                                                 cmd_buf, sizeof(cmd_buf));
                        if (bytes_read == 0) {
                            /*remote connection is closed*/
                            return -1;
                        } else {
                            if (*((int *)cmd_buf) != COMM_META || *((int *)cmd_buf + 1)
                                != ACK_SUCCESS) {
                                /*encounter delegator-side error*/
                                return -1;
                            } else {
                                /*success*/
                            }
                        }
                    } else {
                        /*encounter connection error*/
                        return -1;
                    }
                } else {
                    /*file descriptor is negative*/
                    return -1;
                }
            } else {
                /* encounter error*/
                return -1;
            }
        }
    } else {
        /*write error*/
        return -1;
    }

    return UNIFYCR_SUCCESS;
}

/*
 * get global file metadata from the delegator,
 * which retrieves the data from key-value store
 * @param gfid: global file id
 * @return: error code
 * @return: file_meta that point to the structure of
 * the retrieved metadata
 * */
static int get_global_file_meta(int gfid, unifycr_fattr_t **file_meta)
{
    /* format value length, payload 1, payload 2*/
    int cmd = COMM_META;

    int flag = 1;
    memcpy(cmd_buf, &cmd, sizeof(int));
    memcpy(cmd_buf + sizeof(int), &flag, sizeof(int));
    memcpy(cmd_buf + sizeof(int) + sizeof(int),
           &gfid, sizeof(int));

    int rc = __real_write(client_sockfd, cmd_buf, sizeof(cmd_buf));
    if (rc != 0) {
        int bytes_read = 0;
        cmd_fd.events = POLLIN | POLLPRI;
        cmd_fd.revents = 0;

        rc = poll(&cmd_fd, 1, -1);

        if (rc == 0) {
            /* encounter timeout*/
            return -1;
        } else {
            if (rc > 0) {
                if (cmd_fd.revents != 0) {
                    if (cmd_fd.revents == POLLIN) {
                        bytes_read = __real_read(client_sockfd,
                                                 cmd_buf, sizeof(cmd_buf));
                        if (bytes_read == 0) {
                            /*remote connection is closed*/
                            return -1;
                        } else {
                            if (*((int *)cmd_buf) != COMM_META || *((int *)cmd_buf + 1)
                                != ACK_SUCCESS) {
                                *file_meta = NULL;
                                return -1;
                            } else {
                                /*success*/

                            }
                        }
                    } else {
                        /*encounter connection error*/
                        return -1;
                    }
                } else {
                    /*file descriptor is negative*/
                    return -1;
                }
            } else {
                /* encounter error*/
                return -1;
            }
        }
    } else {
        /*write error*/
        return -1;
    }

    *file_meta = (unifycr_fattr_t *)malloc(sizeof(unifycr_fattr_t));
    memcpy(*file_meta, cmd_buf + 2 * sizeof(int), sizeof(unifycr_fattr_t));
    return UNIFYCR_SUCCESS;
}
/*
 * insert file attribute to attributed share memory buffer
 * */

static int ins_file_meta(unifycr_fattr_buf_t *ptr_f_meta_log,
                         unifycr_fattr_t *ins_fattr)
{
    int meta_cnt = *(ptr_f_meta_log->ptr_num_entries), i;
    unifycr_fattr_t *meta_entry = ptr_f_meta_log->meta_entry;

    for (i = 0; i < meta_cnt - 1; i++) {
        if (meta_entry[i].fid > ins_fattr->fid) {
            break;
        }
    }

    if (i == meta_cnt) {
        meta_entry[meta_cnt] = *ins_fattr;
        (*ptr_f_meta_log->ptr_num_entries)++;
        return 0;
    }

    int ins_pos = i;
    for (i = meta_cnt - 1; i >= ins_pos; i--) {
        meta_entry[i + 1] = meta_entry[i];
    }
    (*ptr_f_meta_log->ptr_num_entries)++;
    meta_entry[ins_pos] = *ins_fattr;
    return 0;

}

/* opens a new file id with specified path, access flags, and permissions,
 * fills outfid with file id and outpos with position for current file pointer,
 * returns UNIFYCR error code */
int unifycr_fid_open(const char *path, int flags, mode_t mode, int *outfid,
                     off_t *outpos)
{
    /* check that path is short enough */
    size_t pathlen = strlen(path) + 1;
    if (pathlen > UNIFYCR_MAX_FILENAME) {
        return UNIFYCR_ERR_NAMETOOLONG;
    }

    /* assume that we'll place the file pointer at the start of the file */
    off_t pos = 0;

    /* check whether this file already exists */
    int fid = unifycr_get_fid_from_path(path);
    debug("unifycr_get_fid_from_path() gave %d\n", fid);

    int gfid = -1, rc = 0;
    if (fs_type == UNIFYCR_LOG) {
        if (fid < 0) {
            rc = unifycr_get_global_fid(path, &gfid);
            if (rc != UNIFYCR_SUCCESS) {
                debug("Failed to generate fid for file %s\n", path);
                return UNIFYCR_ERR_IO;
            }

            gfid = abs(gfid);

            unifycr_fattr_t *ptr_meta = NULL;
            rc = get_global_file_meta(gfid, &ptr_meta);
            if (ptr_meta == NULL) {
                fid = -1;
            } else {
                /* other process has created this file, but its
                 * attribute is not cached locally,
                 * allocate a file id slot for this existing file */
                fid = unifycr_fid_create_file(path);
                if (fid < 0) {
                    debug("Failed to create new file %s\n", path);
                    return UNIFYCR_ERR_NFILE;
                }

                /* initialize the storage for the file */
                int store_rc = unifycr_fid_store_alloc(fid);
                if (store_rc != UNIFYCR_SUCCESS) {
                    debug("Failed to create storage for file %s\n", path);
                    return UNIFYCR_ERR_IO;
                }
                /* initialize the global metadata
                 * */
                unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
                meta->real_size = ptr_meta->file_attr.st_size;
                ptr_meta->fid = fid;
                ptr_meta->gfid = gfid;

                ins_file_meta(&unifycr_fattrs,
                              ptr_meta);
                free(ptr_meta);
            }
        } else {

        }
    }

    if (fid < 0) {
        /* file does not exist */
        /* create file if O_CREAT is set */
        if (flags & O_CREAT) {
            debug("Couldn't find entry for %s in UNIFYCR\n", path);
            debug("unifycr_superblock = %p; free_fid_stack = %p; free_chunk_stack = %p; unifycr_filelist = %p; chunks = %p\n",
                  unifycr_superblock, free_fid_stack, free_chunk_stack, unifycr_filelist,
                  unifycr_chunks
                 );

            /* allocate a file id slot for this new file */
            fid = unifycr_fid_create_file(path);
            if (fid < 0) {
                debug("Failed to create new file %s\n", path);
                return UNIFYCR_ERR_NFILE;
            }

            /* initialize the storage for the file */
            int store_rc = unifycr_fid_store_alloc(fid);
            if (store_rc != UNIFYCR_SUCCESS) {
                debug("Failed to create storage for file %s\n", path);
                return UNIFYCR_ERR_IO;
            }

            if (fs_type == UNIFYCR_LOG) {
                /*create a file and send its attribute to key-value store*/
                unifycr_fattr_t *new_fmeta =
                    (unifycr_fattr_t *)malloc(sizeof(unifycr_fattr_t));
                strcpy(new_fmeta->filename, path);
                new_fmeta->fid = fid;
                new_fmeta->gfid = gfid;

                set_global_file_meta(new_fmeta);
                ins_file_meta(&unifycr_fattrs,
                              new_fmeta);
                free(new_fmeta);

            }
        } else {
            /* ERROR: trying to open a file that does not exist without O_CREATE */
            debug("Couldn't find entry for %s in UNIFYCR\n", path);
            return UNIFYCR_ERR_NOENT;
        }
    } else {
        /* file already exists */

        /* if O_CREAT and O_EXCL are set, this is an error */
        if ((flags & O_CREAT) && (flags & O_EXCL)) {
            /* ERROR: trying to open a file that exists with O_CREATE and O_EXCL */
            return UNIFYCR_ERR_EXIST;
        }

        /* if O_DIRECTORY is set and fid is not a directory, error */
        if ((flags & O_DIRECTORY) && !unifycr_fid_is_dir(fid)) {
            return UNIFYCR_ERR_NOTDIR;
        }

        /* if O_DIRECTORY is not set and fid is a directory, error */
        if (!(flags & O_DIRECTORY) && unifycr_fid_is_dir(fid)) {
            return UNIFYCR_ERR_NOTDIR;
        }

        /* if O_TRUNC is set with RDWR or WRONLY, need to truncate file */
        if ((flags & O_TRUNC) && (flags & (O_RDWR | O_WRONLY))) {
            unifycr_fid_truncate(fid, 0);
        }

        /* if O_APPEND is set, we need to place file pointer at end of file */
        if (flags & O_APPEND) {
            unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
            pos = meta->size;
        }
    }

    /* TODO: allocate a free file descriptor and associate it with fid */
    /* set in_use flag and file pointer */
    *outfid = fid;
    *outpos = pos;
    debug("UNIFYCR_open generated fd %d for file %s\n", fid, path);

    /* don't conflict with active system fds that range from 0 - (fd_limit) */
    return UNIFYCR_SUCCESS;
}

int unifycr_fid_close(int fid)
{
    /* TODO: clear any held locks */

    /* nothing to do here, just a place holder */
    return UNIFYCR_SUCCESS;
}

/* delete a file id and return file its resources to free pools */
int unifycr_fid_unlink(int fid)
{
    /* return data to free pools */
    unifycr_fid_truncate(fid, 0);

    /* finalize the storage we're using for this file */
    unifycr_fid_store_free(fid);

    /* set this file id as not in use */
    unifycr_filelist[fid].in_use = 0;

    /* add this id back to the free stack */
    unifycr_fid_free(fid);

    return UNIFYCR_SUCCESS;
}

/* ---------------------------------------
 * Operations to mount file system
 * --------------------------------------- */

/* initialize our global pointers into the given superblock */
static void *unifycr_init_pointers(void *superblock)
{
    char *ptr = (char *)superblock;

    /* jump over header (right now just a uint32_t to record
     * magic value of 0xdeadbeef if initialized */
    ptr += sizeof(uint32_t);

    /* stack to manage free file ids */
    free_fid_stack = ptr;
    ptr += unifycr_stack_bytes(unifycr_max_files);

    /* record list of file names */
    unifycr_filelist = (unifycr_filename_t *)ptr;
    ptr += unifycr_max_files * sizeof(unifycr_filename_t);

    /* array of file meta data structures */
    unifycr_filemetas = (unifycr_filemeta_t *)ptr;
    ptr += unifycr_max_files * sizeof(unifycr_filemeta_t);

    /* array of chunk meta data strucutres for each file */
    unifycr_chunkmetas = (unifycr_chunkmeta_t *)ptr;
    ptr += unifycr_max_files * unifycr_max_chunks * sizeof(unifycr_chunkmeta_t);

    if (unifycr_use_spillover)
        ptr += unifycr_max_files * unifycr_spillover_max_chunks *
               sizeof(unifycr_chunkmeta_t);

    /* stack to manage free memory data chunks */
    free_chunk_stack = ptr;
    ptr += unifycr_stack_bytes(unifycr_max_chunks);

    if (unifycr_use_spillover) {
        /* stack to manage free spill-over data chunks */
        free_spillchunk_stack = ptr;
        ptr += unifycr_stack_bytes(unifycr_spillover_max_chunks);
    }

    /* Only set this up if we're using memfs */
    if (unifycr_use_memfs) {
        /* round ptr up to start of next page */
        unsigned long long ull_ptr  = (unsigned long long)ptr;
        unsigned long long ull_page = (unsigned long long)unifycr_page_size;
        unsigned long long num_pages = ull_ptr / ull_page;
        if (ull_ptr > num_pages * ull_page)
            ptr = (char *)((num_pages + 1) * ull_page);

        /* pointer to start of memory data chunks */
        unifycr_chunks = ptr;
        ptr += unifycr_max_chunks * unifycr_chunk_size;
    } else {
        unifycr_chunks = NULL;
    }

    /* pointer to the log-structured metadata structures*/
    if (fs_type == UNIFYCR_LOG) {
        unifycr_indices.ptr_num_entries = (off_t *)ptr;

        ptr += unifycr_page_size;
        unifycr_indices.index_entry = (unifycr_index_t *)ptr;


        /*data structures  to record the global metadata*/
        ptr += unifycr_max_index_entries * sizeof(unifycr_index_t);
        unifycr_fattrs.ptr_num_entries = (off_t *)ptr;
        ptr += unifycr_page_size;
        unifycr_fattrs.meta_entry = (unifycr_fattr_t *)ptr;
    }
    return ptr;
}

/* initialize data structures for first use */
static int unifycr_init_structures()
{
    int i;
    for (i = 0; i < unifycr_max_files; i++) {
        /* indicate that file id is not in use by setting flag to 0 */
        unifycr_filelist[i].in_use = 0;

        /* set pointer to array of chunkmeta data structures */
        unifycr_filemeta_t *filemeta = &unifycr_filemetas[i];

        unifycr_chunkmeta_t *chunkmetas;
        if (!unifycr_use_spillover) {
            chunkmetas = &(unifycr_chunkmetas[unifycr_max_chunks * i]);
        } else
            chunkmetas = &(unifycr_chunkmetas[(unifycr_max_chunks +
                                               unifycr_spillover_max_chunks) * i]);
        filemeta->chunk_meta = chunkmetas;
    }

    unifycr_stack_init(free_fid_stack, unifycr_max_files);

    unifycr_stack_init(free_chunk_stack, unifycr_max_chunks);

    if (unifycr_use_spillover) {
        unifycr_stack_init(free_spillchunk_stack, unifycr_spillover_max_chunks);
    }

    if (fs_type == UNIFYCR_LOG) {
        *(unifycr_indices.ptr_num_entries) = 0;
        *(unifycr_fattrs.ptr_num_entries) = 0;
    }
    debug("Meta-stacks initialized!\n");

    return UNIFYCR_SUCCESS;
}

static int unifycr_get_spillblock(size_t size, const char *path)
{
    void *scr_spillblock = NULL;
    int spillblock_fd;

    mode_t perms = unifycr_getmode(0);

    //MAP_OR_FAIL(open);
    spillblock_fd = __real_open(path, O_RDWR | O_CREAT | O_EXCL, perms);
    if (spillblock_fd < 0) {

        if (errno == EEXIST) {
            /* spillover block exists; attach and return */
            spillblock_fd = __real_open(path, O_RDWR);
        } else {
            perror("open() in unifycr_get_spillblock() failed");
            return -1;
        }
    } else {
        /* new spillover block created */
        /* TODO: align to SSD block size*/

        /*temp*/
        off_t rc = __real_lseek(spillblock_fd, size, SEEK_SET);
        if (rc < 0) {
            perror("lseek failed");
        }
    }

    return spillblock_fd;
}

/* create superblock of specified size and name, or attach to existing
 * block if available */
static void *unifycr_superblock_shmget(size_t size, key_t key)
{
    void *scr_shmblock = NULL;
    int scr_shmblock_shmid;

    debug("Key for superblock = %x\n", key);
    if (fs_type != UNIFYCR_LOG) {
#ifdef ENABLE_NUMA_POLICY
        /* if user requested to use 1 shm/process along with NUMA optimizations */
        if (key != IPC_PRIVATE) {
            numa_exit_on_error = 1;
            /* check to see if NUMA control capability is available */
            if (numa_available() >= 0) {
                int max_numa_nodes = numa_max_node() + 1;
                debug("Max. number of NUMA nodes = %d\n", max_numa_nodes);
                int num_cores = sysconf(_SC_NPROCESSORS_CONF);
                int my_core, i, pref_numa_bank = -1;

                /* scan through the CPU set to see which core the current process is bound to */
                /* TODO: can alternatively read from the proc filesystem (/proc/self*) */
                cpu_set_t myset;
                CPU_ZERO(&myset);
                sched_getaffinity(0, sizeof(myset), &myset);
                for (i = 0; i < num_cores; i++) {
                    if (CPU_ISSET(i, &myset)) {
                        my_core = i;
                    }
                }
                if (my_core < 0) {
                    debug("Not able to get current core affinity\n");
                    return NULL;
                }
                debug("Process running on core %d\n", my_core);

                /* find out which NUMA bank this core belongs to */
                // numa_preferred doesn't work as needed, returns 0 always. placeholder only.
                pref_numa_bank = numa_preferred();
                debug("Preferred NUMA bank for core %d is %d\n", my_core, pref_numa_bank);

                /* create/attach to respective shmblock*/
                scr_shmblock_shmid = shmget((key + pref_numa_bank), size,
                                            IPC_CREAT | IPC_EXCL | S_IRWXU);

            } else {
                debug("NUMA support unavailable!\n");
                return NULL;
            }
        } else {
            /* each process has its own block. use one of the other NUMA policies (unifycr_numa_policy) instead */
            scr_shmblock_shmid = shmget(key, size, IPC_CREAT | IPC_EXCL | S_IRWXU);
        }
#else
        /* when NUMA optimizations are turned off, just let the kernel allocate pages as it desires */
        /* TODO: Add Huge-Pages support */
        scr_shmblock_shmid = shmget(key, size, IPC_CREAT | IPC_EXCL | S_IRWXU);
#endif

        if (scr_shmblock_shmid < 0) {
            if (errno == EEXIST) {
                /* superblock already exists, attach to it */
                scr_shmblock_shmid = shmget(key, size, 0);
                scr_shmblock = shmat(scr_shmblock_shmid, NULL, 0);
                if (scr_shmblock < 0) {
                    perror("shmat() failed");
                    return NULL;
                }
                debug("Superblock exists at %p!\n", scr_shmblock);

                /* init our global variables to point to spots in superblock */
                unifycr_init_pointers(scr_shmblock);

            } else {
                perror("shmget() failed");
                return NULL;
            }
        } else {
            /* brand new superblock created, attach to it */
            scr_shmblock = shmat(scr_shmblock_shmid, NULL, 0);
            if (scr_shmblock == (void *) - 1) {
                perror("shmat() failed");
            }
            debug("Superblock created at %p!\n", scr_shmblock);


#ifdef ENABLE_NUMA_POLICY
            /* set NUMA policy for scr_shmblock */
            if (unifycr_numa_bank >= 0) {
                /* specifically allocate pages from user-set bank */
                numa_tonode_memory(scr_shmblock, size, unifycr_numa_bank);
            } else if (strcmp(unifycr_numa_policy, "interleaved") == 0) {
                /* interleave the shared-memory segment
                 * across all memory banks when all process share 1-superblock */
                debug("Interleaving superblock across all memory banks\n");
                numa_interleave_memory(scr_shmblock, size, numa_all_nodes_ptr);
            } else if (strcmp(unifycr_numa_policy, "local") == 0) {
                /* each process has its own superblock, let it be allocated from
                 * the closest memory bank */
                debug("Assigning memory from closest bank\n");
                numa_setlocal_memory(scr_shmblock, size);
            }
#endif
            /* init our global variables to point to spots in superblock */
            unifycr_init_pointers(scr_shmblock);
            /* initialize data structures within block */
            unifycr_init_structures();

        }
    } else {
        /* Use mmap to allocated share memory for UnifyCR*/
        int ret = -1;
        int fd = -1;
        char shm_name[GEN_STR_LEN] = {0};
        sprintf(shm_name, "%d-super-%d", app_id, key);
        superblock_fd = shm_open(shm_name, MMAP_OPEN_FLAG, MMAP_OPEN_MODE);
        if (-1 == (ret = superblock_fd)) {
            return NULL;
        }

        ret = ftruncate(superblock_fd, size);
        if (-1 == ret) {
            return NULL;
        }

        scr_shmblock = mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_SHARED,
                            superblock_fd, SEEK_SET);
        if (NULL == scr_shmblock) {
            return NULL;
        }
        /* init our global variables to point to spots in superblock */
        if (scr_shmblock != NULL) {
            unifycr_init_pointers(scr_shmblock);
            unifycr_init_structures();
        }
    }
    return scr_shmblock;
}

#ifdef MACHINE_BGQ
static void *unifycr_superblock_bgq(size_t size, const char *name)
{
    /* BGQ allocates memory in units of 1MB */
    unsigned long block_size = 1024 * 1024;

    /* round request up to integer number of blocks */
    unsigned long num_blocks = (unsigned long)size / block_size;
    if (block_size * num_blocks < size) {
        num_blocks++;
    }
    unsigned long size_1MB = num_blocks * block_size;

    /* open file in persistent memory */
    int fd = persist_open((char *)name, O_RDWR, 0600);
    if (fd < 0) {
        perror("unable to open persistent memory file");
        return NULL;
    }

    /* truncate file to correct size */
    int rc = ftruncate(fd, (off_t)size_1MB);
    if (rc < 0) {
        perror("ftruncate of persistent memory region failed");
        close(fd);
        return NULL;
    }

    /* mmap file */
    void *shmptr = mmap(NULL, (size_t)size_1MB, PROT_READ | PROT_WRITE, MAP_SHARED,
                        fd, 0);
    if (shmptr == MAP_FAILED) {
        perror("mmap of shared memory region failed");
        close(fd);
        return NULL;
    }

    /* close persistent memory file */
    close(fd);

    /* init our global variables to point to spots in superblock */
    unifycr_init_pointers(shmptr);

    /* initialize data structures within block if we haven't already */
    uint32_t *header = (uint32_t *) shmptr;
    uint32_t magic = *header;
    if (magic != 0xdeadbeef) {
        unifycr_init_structures();
        *header = 0xdeadbeef;
    }

    return shmptr;
}
#endif /* MACHINE_BGQ */

/* converts string like 10mb to unsigned long long integer value of 10*1024*1024 */
static int unifycr_abtoull(char *str, unsigned long long *val)
{
    /* check that we have a string */
    if (str == NULL) {
        debug("scr_abtoull: Can't convert NULL string to bytes @ %s:%d",
              __FILE__, __LINE__
             );
        return UNIFYCR_FAILURE;
    }

    /* check that we have a value to write to */
    if (val == NULL) {
        debug("scr_abtoull: NULL address to store value @ %s:%d",
              __FILE__, __LINE__
             );
        return UNIFYCR_FAILURE;
    }

    /* pull the floating point portion of our byte string off */
    errno = 0;
    char *next = NULL;
    double num = strtod(str, &next);
    if (errno != 0) {
        debug("scr_abtoull: Invalid double: %s @ %s:%d",
              str, __FILE__, __LINE__
             );
        return UNIFYCR_FAILURE;
    }

    /* now extract any units, e.g. KB MB GB, etc */
    unsigned long long units = 1;
    if (*next != '\0') {
        switch (*next) {
        case 'k':
        case 'K':
            units = 1024;
            break;
        case 'm':
        case 'M':
            units = 1024 * 1024;
            break;
        case 'g':
        case 'G':
            units = 1024 * 1024 * 1024;
            break;
        default:
            debug("scr_abtoull: Unexpected byte string %s @ %s:%d",
                  str, __FILE__, __LINE__
                 );
            return UNIFYCR_FAILURE;
        }

        next++;

        /* handle optional b or B character, e.g. in 10KB */
        if (*next == 'b' || *next == 'B') {
            next++;
        }

        /* check that we've hit the end of the string */
        if (*next != 0) {
            debug("scr_abtoull: Unexpected byte string: %s @ %s:%d",
                  str, __FILE__, __LINE__
                 );
            return UNIFYCR_FAILURE;
        }
    }

    /* check that we got a positive value */
    if (num < 0) {
        debug("scr_abtoull: Byte string must be positive: %s @ %s:%d",
              str, __FILE__, __LINE__
             );
        return UNIFYCR_FAILURE;
    }

    /* multiply by our units and set out return value */
    *val = (unsigned long long)(num * (double) units);

    return UNIFYCR_SUCCESS;
}

static int unifycr_init(int rank)
{
    if (! unifycr_initialized) {

#ifdef UNIFYCR_GOTCHA
        enum gotcha_error_t result;

        result = gotcha_wrap(wrap_unifycr_list, GOTCHA_NFUNCS, "unifycr");
        if (result != GOTCHA_SUCCESS) {
            debug("gotcha_wrap returned %d\n", (int) result);
        }

        int i;
        for (i = 0; i < GOTCHA_NFUNCS; i++) {
            if (*(void **)(wrap_unifycr_list[i].function_address_pointer) == 0) {
                printf("This function name failed to be wrapped: %s\n",
                       wrap_unifycr_list[i].name);
            }
        }
#endif
        char *env;
        unsigned long long bytes;

        /* as a hack to support fgetpos/fsetpos, we store the value of
         * a void* in an fpos_t so check that there's room and at least
         * print a message if this won't work */
        if (sizeof(fpos_t) < sizeof(void *)) {
            fprintf(stderr, "ERROR: fgetpos/fsetpos will not work correctly.\n");
            unifycr_fpos_enabled = 0;
        }

        /* look up page size for buffer alignment */
        unifycr_page_size = getpagesize();

        /* compute min and max off_t values */
        unsigned long long bits;
        bits = sizeof(off_t) * 8;
        unifycr_max_offt = (off_t)((1ULL << (bits - 1ULL)) - 1ULL);
        unifycr_min_offt = (off_t)(-(1ULL << (bits - 1ULL)));

        /* compute min and max long values */
        unifycr_max_long = LONG_MAX;
        unifycr_min_long = LONG_MIN;

        /* will we use spillover to store the files? */
        unifycr_use_spillover = 0;

        env = getenv("UNIFYCR_USE_SPILLOVER");
        if (env) {
            int val = atoi(env);
            if (val != 0) {
                unifycr_use_spillover = 1;
            }
        }

        debug("are we using spillover? %d\n", unifycr_use_spillover);

        /* determine max number of files to store in file system */
        unifycr_max_files = UNIFYCR_MAX_FILES;
        env = getenv("UNIFYCR_MAX_FILES");
        if (env) {
            int val = atoi(env);
            unifycr_max_files = val;
        }

        /* determine number of bits for chunk size */
        unifycr_chunk_bits = UNIFYCR_CHUNK_BITS;
        env = getenv("UNIFYCR_CHUNK_BITS");
        if (env) {
            int val = atoi(env);
            unifycr_chunk_bits = val;
        }

        /* determine maximum number of bytes of memory for chunk storage */
        unifycr_chunk_mem = UNIFYCR_CHUNK_MEM;
        env = getenv("UNIFYCR_CHUNK_MEM");
        if (env) {
            unifycr_abtoull(env, &bytes);
            unifycr_chunk_mem = (size_t) bytes;
        }

        /* set chunk size, set chunk offset mask, and set total number
         * of chunks */
        unifycr_chunk_size = 1 << unifycr_chunk_bits;
        unifycr_chunk_mask = unifycr_chunk_size - 1;
        unifycr_max_chunks = unifycr_chunk_mem >> unifycr_chunk_bits;

        /* determine maximum number of bytes of spillover for chunk storage */
        unifycr_spillover_size = UNIFYCR_SPILLOVER_SIZE;
        env = getenv("UNIFYCR_SPILLOVER_SIZE");
        if (env) {
            unifycr_abtoull(env, &bytes);
            unifycr_spillover_size = (size_t) bytes;
        }

        /* set number of chunks in spillover device */
        unifycr_spillover_max_chunks = unifycr_spillover_size >> unifycr_chunk_bits;

        if (fs_type == UNIFYCR_LOG) {
            unifycr_index_buf_size = UNIFYCR_INDEX_BUF_SIZE;
            env = getenv("UNIFYCR_INDEX_BUF_SIZE");
            if (env) {
                unifycr_abtoull(env, &bytes);
                unifycr_index_buf_size = (size_t) bytes;
            }
            unifycr_max_index_entries =
                unifycr_index_buf_size / sizeof(unifycr_index_t);

            unifycr_fattr_buf_size = UNIFYCR_FATTR_BUF_SIZE;
            env = getenv("UNIFYCR_ATTR_BUF_SIZE");
            if (env) {
                unifycr_abtoull(env, &bytes);
                unifycr_fattr_buf_size = (size_t) bytes;
            }
            unifycr_max_fattr_entries =
                unifycr_fattr_buf_size / sizeof(unifycr_fattr_t);

        }




#ifdef ENABLE_NUMA_POLICY
        env = getenv("UNIFYCR_NUMA_POLICY");
        if (env) {
            sprintf(unifycr_numa_policy, env);
            debug("NUMA policy used: %s\n", unifycr_numa_policy);
        } else {
            sprintf(unifycr_numa_policy, "default");
        }

        env = getenv("UNIFYCR_USE_NUMA_BANK");
        if (env) {
            int val = atoi(env);
            if (val >= 0) {
                unifycr_numa_bank = val;
            } else {
                fprintf(stderr, "Incorrect NUMA bank specified in UNIFYCR_USE_NUMA_BANK."
                        "Proceeding with default allocation policy!\n");
            }
        }

#endif

        /* record the max fd for the system */
        /* RLIMIT_NOFILE specifies a value one greater than the maximum
         * file descriptor number that can be opened by this process */
        struct rlimit *r_limit = malloc(sizeof(r_limit));
        if (r_limit == NULL) {
            perror("failed to allocate memory for call to getrlimit");
            return UNIFYCR_FAILURE;
        }
        if (getrlimit(RLIMIT_NOFILE, r_limit) < 0) {
            perror("rlimit failed");
            free(r_limit);
            return UNIFYCR_FAILURE;
        }
        unifycr_fd_limit = r_limit->rlim_cur;
        free(r_limit);
        debug("FD limit for system = %ld\n", unifycr_fd_limit);

        /* determine the size of the superblock */
        /* generous allocation for chunk map (one file can take entire space)*/
        size_t superblock_size = 0;
        superblock_size += sizeof(
                               uint32_t); /* header: single uint32_t to hold 0xdeadbeef number of initialization */
        superblock_size += unifycr_stack_bytes(
                               unifycr_max_files);         /* free file id stack */
        superblock_size += unifycr_max_files * sizeof(
                               unifycr_filename_t); /* file name struct array */
        superblock_size += unifycr_max_files * sizeof(
                               unifycr_filemeta_t); /* file meta data struct array */
        superblock_size += unifycr_max_files * unifycr_max_chunks * sizeof(
                               unifycr_chunkmeta_t);
        /* chunk meta data struct array for each file */
        if (unifycr_use_spillover) {
            superblock_size += unifycr_max_files * unifycr_spillover_max_chunks * sizeof(
                                   unifycr_chunkmeta_t);
        }
        superblock_size += unifycr_stack_bytes(
                               unifycr_max_chunks);        /* free chunk stack */
        if (unifycr_use_memfs) {
            superblock_size += unifycr_page_size +
                               (unifycr_max_chunks * unifycr_chunk_size);         /* memory chunks */
        }
        if (unifycr_use_spillover) {
            superblock_size +=
                unifycr_stack_bytes(
                    unifycr_spillover_max_chunks);     /* free spill over chunk stack */
        }

        /*unifycr: add the index and attribute region size of unifycr*/
        if (fs_type == UNIFYCR_LOG) {
            superblock_size += unifycr_max_index_entries
                               * sizeof(unifycr_index_t) + unifycr_page_size;
            superblock_size += unifycr_max_fattr_entries
                               * sizeof(unifycr_fattr_t) + unifycr_page_size;
            glb_superblock_size = superblock_size;
        }

        /* get a superblock of persistent memory and initialize our
         * global variables for this block */
#ifdef MACHINE_BGQ
        char bgqname[100];
        snprintf(bgqname, sizeof(bgqname), "memory_rank_%d", rank);
        unifycr_superblock = unifycr_superblock_bgq(superblock_size, bgqname);
#else /* MACHINE_BGQ */
        unifycr_superblock = unifycr_superblock_shmget(superblock_size,
                             unifycr_mount_shmget_key);
#endif /* MACHINE_BGQ */
        if (unifycr_superblock == NULL) {
            debug("unifycr_superblock_shmget() failed\n");
            return UNIFYCR_FAILURE;
        }
        char spillfile_prefix[100];

        env = getenv("UNIFYCR_EXTERNAL_DATA_DIR");
        if (env) {
            strcpy(external_data_dir, env);
        } else {
            strcpy(external_data_dir, EXTERNAL_DATA_DIR);
        }

        sprintf(spillfile_prefix, "%s/spill_%d_%d.log",
                external_data_dir, app_id, local_rank_idx);

        /* initialize spillover store */
        if (unifycr_use_spillover) {
            size_t spillover_size = unifycr_max_chunks * unifycr_chunk_size;
            unifycr_spilloverblock = unifycr_get_spillblock(spillover_size,
                                     spillfile_prefix);

            if (unifycr_spilloverblock < 0) {
                debug("unifycr_get_spillblock() failed!\n");
                return UNIFYCR_FAILURE;
            }
        }

        env = getenv("UNIFYCR_EXTERNAL_META_DIR");
        if (env) {
            strcpy(external_meta_dir, env);
        } else {
            strcpy(external_meta_dir, EXTERNAL_META_DIR);
        }

        /*ToDo: add the spillover feature for the index metadata*/
        sprintf(spillfile_prefix, "%s/spill_index_%d_%d.log",
                external_meta_dir, app_id, local_rank_idx);
        if (fs_type == UNIFYCR_LOG) {
            unifycr_spillmetablock =
                unifycr_get_spillblock(unifycr_index_buf_size, spillfile_prefix);
            if (unifycr_spillmetablock < 0) {
                debug("unifycr_get_spillmetablock failed!\n");
                return UNIFYCR_FAILURE;
            }
        }

        /* remember that we've now initialized the library */
        unifycr_initialized = 1;
    }
    return UNIFYCR_SUCCESS;
}

/* ---------------------------------------
 * APIs exposed to external libraries
 * --------------------------------------- */


/**
* mount a file system at a given prefix
* subtype: 0-> log-based file system;
* 1->striping based file system, not implemented yet.
* @param prefix: directory prefix
* @param size: the number of ranks
* @param l_app_id: application ID
* @return success/error code
*/
int unifycr_mount(const char prefix[], int rank, size_t size,
                  int l_app_id, int subtype)
{
    switch (subtype) {
    case UNIFYCRFS:
        fs_type = UNIFYCRFS;
        break;
    case UNIFYCR_LOG:
        fs_type = UNIFYCR_LOG;
        break;
    case UNIFYCR_STRIPE:
        fs_type = UNIFYCR_STRIPE;
        break;
    default:
        fs_type = UNIFYCR_LOG;
        break;
    }

    dbg_rank = rank;
    app_id = l_app_id;
    return unifycrfs_mount(prefix, size, rank);
}

/**
* unmount the mounted file system, triggered
* by the root process of an application
* ToDo: add the support for more operations
* beyond terminating the servers. E.g.
* data flush for persistence.
* @return success/error code
*/
int unifycr_unmount()
{
    if (fs_type == UNIFYCR_LOG) {
        int cmd = COMM_UNMOUNT;
        char cmd_buf[GEN_STR_LEN] = {0};
        memcpy(cmd_buf, &cmd, sizeof(int));

        int res = __real_write(cmd_fd.fd, cmd_buf, sizeof(cmd_buf));
        if (res != 0) {
            int bytes_read = 0;
            int rc;
            cmd_fd.events = POLLIN | POLLPRI;
            cmd_fd.revents = 0;

            rc = poll(&cmd_fd, 1, -1);
            if (rc == 0) {

            } else {
                if (rc > 0) {
                    if (cmd_fd.revents != 0) {
                        if (cmd_fd.revents == POLLIN) {
                            bytes_read = __real_read(cmd_fd.fd, cmd_buf,
                                                     sizeof(cmd_buf));
                            if (bytes_read == 0) {
                                return UNIFYCR_FAILURE;
                            } else {
                                if (*((int *)cmd_buf) != COMM_UNMOUNT
                                    || *((int *)cmd_buf + 1)
                                    != ACK_SUCCESS) {
                                    return UNIFYCR_FAILURE;
                                }
                                return UNIFYCR_SUCCESS;
                            }
                        } else {
                        }
                    } else {
                    }
                } else {

                }
            }
        } else {
            return UNIFYCR_FAILURE;
        }
    }

    return UNIFYCR_FAILURE;
}

/* mount memfs at some prefix location */
int unifycrfs_mount(const char prefix[], size_t size, int rank)
{
    unifycr_mount_prefix = strdup(prefix);
    unifycr_mount_prefixlen = strlen(unifycr_mount_prefix);

    /* KMM commented out because we're just using a single rank, so use PRIVATE
     * downside, can't attach to this in another srun (PRIVATE, that is) */
    //unifycr_mount_shmget_key = UNIFYCR_SUPERBLOCK_KEY + rank;

    char *env = getenv("UNIFYCR_USE_SINGLE_SHM");
    if (env) {
        int val = atoi(env);
        if (val != 0) {
            unifycr_use_single_shm = 1;
        }
    }

    if (unifycr_use_single_shm) {
        unifycr_mount_shmget_key = UNIFYCR_SUPERBLOCK_KEY + rank;
    } else {
        unifycr_mount_shmget_key = IPC_PRIVATE;
    }

    if (fs_type == UNIFYCR_LOG || fs_type == UNIFYCR_STRIPE) {
        int rc = CountTasksPerNode(rank, size);
        if (rc < 0) {
            debug("rank:%d, cannot get the local rank list.", dbg_rank);
            return -1;
        }

        local_rank_idx = find_rank_idx(rank,
                                       local_rank_lst, local_rank_cnt);

        /* unifycr_mount_shmget_key marks the start of
         * the superblock shared memory of each rank
         * each process has three types of shared memory:
         * request memory, recv memory and superblock
         * memory. We set unifycr_mount_shmget_key in
         * this way to avoid different ranks conflicting
         * on the same name in shm_open.
         * */
        unifycr_mount_shmget_key = local_rank_idx;

    }

    /* initialize our library */
    unifycr_init(rank);

    if (fs_type == UNIFYCR_LOG || fs_type == UNIFYCR_STRIPE) {
        char host_name[UNIFYCR_MAX_FILENAME] = {0};
        int rc = gethostname(host_name, UNIFYCR_MAX_FILENAME);
        if (rc != 0) {
            debug("rank:%d, fail to get the host name.", dbg_rank);
            return UNIFYCR_FAILURE;
        }

        /* get the number of collocated delegators*/
        if (local_rank_idx == 0) {
            rc = unifycr_init_socket(0, 1, 1);
            if (rc < 0) {
                return -1;
            }

            local_del_cnt = get_del_cnt();
            if (local_del_cnt > 0) {
                int i;
                for (i = 0; i < local_rank_cnt; i++) {
                    if (local_rank_lst[i] != rank) {
                        int rc = MPI_Send(&local_del_cnt, 1,
                                          MPI_INT, local_rank_lst[i], 0, MPI_COMM_WORLD);
                    }
                }
            } else {
                debug("rank:%d, fail to get the delegator count.", dbg_rank);
                return -1;
            }

        } else {
            MPI_Status status;
            int rc = MPI_Recv(&local_del_cnt, 1, MPI_INT, local_rank_lst[0],
                              0, MPI_COMM_WORLD, &status);
            if (local_del_cnt < 0 || rc < 0) {
                debug("rank:%d, fail to initialize socket.", dbg_rank);
                return UNIFYCR_FAILURE;
                return -1;
            } else  {
                int rc = unifycr_init_socket(local_rank_idx,
                                             local_rank_cnt, local_del_cnt);
                if (rc < 0) {
                    debug("rank:%d, fail to initialize socket.", dbg_rank);
                    return UNIFYCR_FAILURE;
                    return -1;
                }
            }
        }

        /*connect to server-side delegators*/

        rc = unifycr_init_req_shm(local_rank_idx, app_id);
        if (rc < 0) {
            debug("rank:%d, fail to init shared request memory.", dbg_rank);
            return UNIFYCR_FAILURE;
        }

        rc = unifycr_init_recv_shm(local_rank_idx, app_id);
        if (rc < 0) {
            debug("rank:%d, fail to init shared receive memory.", dbg_rank);
            return UNIFYCR_FAILURE;
        }

        rc = unifycr_sync_to_del();
        if (rc < 0) {
            debug("rank:%d, fail to convey information to the delegator.", dbg_rank);
            return UNIFYCR_FAILURE;
        }

    }
    /* add mount point as a new directory in the file list */
    if (unifycr_get_fid_from_path(prefix) >= 0) {
        /* we can't mount this location, because it already exists */
        errno = EEXIST;
        return -1;
    } else {
        /* claim an entry in our file list */
        int fid = unifycr_fid_create_directory(prefix);
        if (fid < 0) {
            /* if there was an error, return it */
            return fid;
        }
    }

    return 0;
}

/**
* transfer the client-side context information
* to the corresponding delegator on the
* server side.
*/
static int unifycr_sync_to_del()
{
    int rc = -1;

    int cmd = COMM_MOUNT;

    int superblock_start = UNIFYCR_SUPERBLOCK_KEY;
    int num_procs_per_node = local_rank_cnt;
    int req_buf_sz = shm_req_size;
    int recv_buf_sz = shm_recv_size;
    long superblock_sz = glb_superblock_size;

    long meta_offset =
        (void *)unifycr_indices.ptr_num_entries
        - unifycr_superblock;
    long meta_size = unifycr_max_index_entries
                     * sizeof(unifycr_index_t);

    long fmeta_offset =
        (void *)unifycr_fattrs.ptr_num_entries
        - unifycr_superblock;

    long fmeta_size = unifycr_max_fattr_entries *
                      sizeof(unifycr_fattr_t);

    long data_offset =
        (void *)unifycr_chunks - unifycr_superblock;
    long data_size = (long)unifycr_max_chunks * unifycr_chunk_size;

    char external_spill_dir[UNIFYCR_MAX_FILENAME] = {0};
    strcpy(external_spill_dir, external_data_dir);

    /* copy the client-side information to the command
     * buffer, and then send to the delegator. The delegator
     * will attach to the client-side shared memory, and open
     * the spill log file based on these information*/
    memcpy(cmd_buf, &cmd, sizeof(int));
    memcpy(cmd_buf + sizeof(int), &app_id, sizeof(int));
    memcpy(cmd_buf + 2 * sizeof(int),
           &local_rank_idx, sizeof(int));
    memcpy(cmd_buf + 3 * sizeof(int),
           &dbg_rank, sizeof(int)); /*add debug info*/
    memcpy(cmd_buf + 4 * sizeof(int), &num_procs_per_node, sizeof(int));
    memcpy(cmd_buf + 5 * sizeof(int), &req_buf_sz, sizeof(int));
    memcpy(cmd_buf + 6 * sizeof(int), &recv_buf_sz, sizeof(int));

    memcpy(cmd_buf + 7 * sizeof(int), &superblock_sz, sizeof(long));
    memcpy(cmd_buf + 7 * sizeof(int) + sizeof(long),
           &meta_offset, sizeof(long));
    memcpy(cmd_buf + 7 * sizeof(int) + 2 * sizeof(long),
           &meta_size, sizeof(long));

    memcpy(cmd_buf + 7 * sizeof(int) + 3 * sizeof(long),
           &fmeta_offset, sizeof(long));
    memcpy(cmd_buf + 7 * sizeof(int) + 4 * sizeof(long),
           &fmeta_size, sizeof(long));

    memcpy(cmd_buf + 7 * sizeof(int) + 5 * sizeof(long),
           &data_offset, sizeof(long));
    memcpy(cmd_buf + 7 * sizeof(int) + 6 * sizeof(long),
           &data_size, sizeof(long));

    memcpy(cmd_buf + 7 * sizeof(int) + 7 * sizeof(long),
           external_spill_dir, UNIFYCR_MAX_FILENAME); /*adjust to add debug info*/

    int res = __real_write(client_sockfd,
                           cmd_buf, sizeof(cmd_buf));
    if (res != 0) {
        int bytes_read = 0;
        int rc = -1;
        cmd_fd.events = POLLIN | POLLPRI;
        cmd_fd.revents = 0;

        rc = poll(&cmd_fd, 1, -1);
        if (rc == 0) {
            /* encounter timeout*/
            return -1;
        } else {
            if (rc > 0) {
                if (cmd_fd.revents != 0) {
                    if (cmd_fd.revents == POLLIN) {
                        bytes_read = __real_read(client_sockfd, cmd_buf,
                                                 sizeof(cmd_buf));
                        if (bytes_read == 0) {
                            /*remote connection is closed*/
                            return -1;
                        } else {
                            if (*((int *)cmd_buf) != COMM_MOUNT || *((int *)cmd_buf + 1)
                                != ACK_SUCCESS) {
                                /*encounter delegator-side error*/
                                return rc;
                            } else {
                                unifycr_key_slice_range =
                                    *((long *)(cmd_buf + 2 * sizeof(int)));
                                /*success*/

                            }
                        }
                    } else {
                        /*encounter connection error*/
                        return -1;
                    }
                } else {
                    /*file descriptor is negative*/
                    return -1;
                }
            } else {
                /* encounter error*/
                return -1;
            }
        }
    } else {
        /*write error*/
        return -1;
    }

    return 0;
}

/**
* Initialize the shared recv memory buffer
* to receive data from the delegators
*/
static int unifycr_init_recv_shm(int local_rank_idx, int app_id)
{
    int rc = -1;

    char *env = getenv("SHM_RECV_SIZE");
    if (env) {
        shm_recv_size = atol(env);
    }

    char shm_name[GEN_STR_LEN] = {0};
    sprintf(shm_name, "%d-recv-%d", app_id, local_rank_idx);

    recvbuf_fd = shm_open(shm_name, MMAP_OPEN_FLAG, MMAP_OPEN_MODE);
    if (-1 == (rc = recvbuf_fd)) {
        return UNIFYCR_FAILURE;
    }

    rc = ftruncate(recvbuf_fd, shm_recv_size);
    if (-1 == rc) {
        return UNIFYCR_FAILURE;
    }

    shm_recvbuf = mmap(NULL, shm_recv_size, PROT_WRITE | PROT_READ,
                       MAP_SHARED, recvbuf_fd, SEEK_SET);
    if (NULL == shm_recvbuf) {
        return UNIFYCR_FAILURE;
    }

    *((int *)shm_recvbuf) = app_id + 3;
    return 0;
}

/**
* Initialize the shared request memory, which
* is used to buffer the list of read requests
* to be transferred to the delegator on the
* server side.
* @param local_rank_idx: local process id
* @param app_id: which application this
*  process is from
* @return success/error code
*/
static int unifycr_init_req_shm(int local_rank_idx, int app_id)
{
    int rc = -1;

    /* initialize request buffer size*/
    char *env = getenv("SHM_REQ_SIZE");
    if (env) {
        shm_req_size = atol(env);
    }

    char shm_name[GEN_STR_LEN] = {0};
    sprintf(shm_name, "%d-req-%d", app_id, local_rank_idx);
    reqbuf_fd = shm_open(shm_name, MMAP_OPEN_FLAG, MMAP_OPEN_MODE);
    if (-1 == (rc = reqbuf_fd)) {
        return UNIFYCR_FAILURE;
    }

    rc = ftruncate(reqbuf_fd, shm_req_size);
    if (-1 == rc) {
        return UNIFYCR_FAILURE;
    }


    shm_reqbuf = mmap(NULL, shm_req_size, PROT_WRITE | PROT_READ,
                      MAP_SHARED, reqbuf_fd, SEEK_SET);
    if (NULL == shm_reqbuf) {
        return UNIFYCR_FAILURE;
    }

    return 0;
}

/**
* get the number of delegators on the
* same node from the first delegator
* on the server side
*/
static int get_del_cnt()
{
    int cmd = COMM_SYNC_DEL;
    memcpy(cmd_buf, &cmd, sizeof(int));

    int res = __real_write(client_sockfd,
                           cmd_buf, sizeof(cmd_buf));
    if (res != 0) {
        int bytes_read = 0;
        int rc = -1;
        cmd_fd.events = POLLIN | POLLPRI;
        cmd_fd.revents = 0;

        rc = poll(&cmd_fd, 1, -1);
        if (rc == 0) {
            /* encounter timeout*/
            return -1;
        } else {
            if (rc > 0) {
                if (cmd_fd.revents != 0) {
                    if (cmd_fd.revents == POLLIN) {
                        bytes_read = __real_read(client_sockfd, cmd_buf,
                                                 sizeof(cmd_buf));
                        if (bytes_read == 0) {
                            /*remote connection is closed*/
                            return -1;
                        } else {
                            if (*((int *)cmd_buf) != COMM_SYNC_DEL || *((int *)cmd_buf + 1)
                                != ACK_SUCCESS) {
                                /*encounter delegator-side error*/
                                return rc;
                            } else {
                                /*success*/
                            }
                        }
                    } else {
                        /*encounter connection error*/
                        return -1;
                    }
                } else {
                    /*file descriptor is negative*/
                    return -1;
                }
            } else {
                /* encounter error*/
                return -1;
            }
        }
    } else {
        /*write error*/
        return -1;
    }


    return *(int *)(cmd_buf + 2 * sizeof(int));

}

/**
* initialize the client-side socket
* used to communicate with the server-side
* delegators. Each client is serviced by
* one delegator.
* @param proc_id: local process id
* @param l_num_procs_per_node: number
* of ranks on each compute node
* @param l_num_del_per_node: number of server-side
* delegators on the same node
* @return success/error code
*/

static int unifycr_init_socket(int proc_id, int l_num_procs_per_node,
                               int l_num_del_per_node)
{
    int rc = -1;

    int len;
    int result;

    client_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_sockfd < 0) {
        return -1;
    }

    struct sockaddr_un serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    char tmp_path[GEN_STR_LEN] = {0};


    int nprocs_per_del;
    if (l_num_procs_per_node % l_num_del_per_node == 0) {
        nprocs_per_del = l_num_procs_per_node / l_num_del_per_node;
    } else {
        nprocs_per_del = l_num_procs_per_node / l_num_del_per_node + 1;
    }

    /*which delegator I belong to*/
    sprintf(tmp_path, "%s%d", SOCKET_PATH,
            proc_id / nprocs_per_del);

    strcpy(serv_addr.sun_path, tmp_path);
    len = sizeof(serv_addr);
    result = connect(client_sockfd, (struct sockaddr *)&serv_addr, len);

    /* exit with error if connection is not successful */
    if (result == -1) {
        rc = -1;
        return rc;
    }

    int flag = fcntl(client_sockfd, F_GETFL);
    fcntl(client_sockfd, F_SETFL, flag | O_NONBLOCK);
    cmd_fd.fd = client_sockfd;
    cmd_fd.events = POLLIN | POLLHUP;
    cmd_fd.revents = 0;

    return 0;

}

int compare_fattr(const void *a, const void *b)
{
    const unifycr_fattr_t *ptr_a = a;
    const unifycr_fattr_t *ptr_b = b;

    if (ptr_a->fid > ptr_b->fid)
        return 1;

    if (ptr_a->fid < ptr_b->fid)
        return -1;

    return 0;
}

static int compare_int(const void *a, const void *b)
{
    const int *ptr_a = a;
    const int *ptr_b = b;

    if (*ptr_a - *ptr_b > 0)
        return 1;

    if (*ptr_a - *ptr_b < 0)
        return -1;

    return 0;
}

static int compare_name_rank_pair(const void *a, const void *b)
{
    const name_rank_pair_t *pair_a = a;
    const name_rank_pair_t *pair_b = b;

    if (strcmp(pair_a->hostname, pair_b->hostname) > 0)
        return 1;

    if (strcmp(pair_a->hostname, pair_b->hostname) < 0)
        return -1;

    return 0;
}

/**
* find the local index of a given rank among all ranks
* collocated on the same node
* @param local_rank_lst: a list of local ranks
* @param local_rank_cnt: number of local ranks
* @return index of rank in local_rank_lst
*/
static int find_rank_idx(int rank,
                         int *local_rank_lst, int local_rank_cnt)
{
    int i;
    for (i = 0; i < local_rank_cnt; i++) {
        if (local_rank_lst[i] == rank) {
            return i;
        }
    }

    return -1;

}


/**
* calculate the number of ranks per node,
*
* @param numTasks: number of tasks in the application
* @return success/error code
* @return local_rank_lst: a list of local ranks
* @return local_rank_cnt: number of local ranks
*/
static int CountTasksPerNode(int rank, int numTasks)
{
    char       hostname[UNIFYCR_MAX_FILENAME],
               localhost[UNIFYCR_MAX_FILENAME];
    int        count               = 1,
               resultsLen          = 30,
               i;

    MPI_Status status;
    int rc;

    rc = MPI_Get_processor_name(localhost, &resultsLen);
    if (rc != 0) {
        debug("failed to get the processor's name");
    }



    if (numTasks > 0) {
        if (rank == 0) {
            /* a container of (rank, host) mappings*/
            name_rank_pair_t *host_set =
                (name_rank_pair_t *)malloc(numTasks
                                           * sizeof(name_rank_pair_t));
            /* MPI_receive all hostnames, and compare to local hostname */
            /* ToDo: handle the case when the length of hostname is larger
             * than 30*/
            for (i = 1; i < numTasks; i++) {
                rc = MPI_Recv(hostname, UNIFYCR_MAX_FILENAME,
                              MPI_CHAR, MPI_ANY_SOURCE,
                              MPI_ANY_TAG, MPI_COMM_WORLD,
                              &status);

                if (rc != 0) {
                    debug("cannot receive hostnames");
                    return -1;
                }
                strcpy(host_set[i].hostname, hostname);
                host_set[i].rank = status.MPI_SOURCE;
            }
            strcpy(host_set[0].hostname, localhost);
            host_set[0].rank = 0;

            /*sort according to the hostname*/
            qsort(host_set, numTasks, sizeof(name_rank_pair_t),
                  compare_name_rank_pair);

            /* rank_cnt: records the number of processes on each node
             * rank_set: the list of ranks for each node
             * */
            int **rank_set = (int **)malloc(numTasks * sizeof(int *));
            int *rank_cnt = (int *)malloc(numTasks * sizeof(int));

            int cursor = 0, set_counter = 0;
            for (i = 1; i < numTasks; i++) {
                if (strcmp(host_set[i].hostname,
                           host_set[i - 1].hostname) == 0) {
                    /*do nothing*/
                } else {
                    // find a different rank, so switch to a new set
                    int j, k = 0;
                    rank_set[set_counter] =
                        (int *)malloc((i - cursor) * sizeof(int));
                    rank_cnt[set_counter] = i - cursor;
                    for (j = cursor; j <= i - 1; j++) {

                        rank_set[set_counter][k] =  host_set[j].rank;
                        k++;
                    }

                    set_counter++;
                    cursor = i;
                }

            }


            /*fill rank_cnt and rank_set entry for the last node*/
            int j = 0;

            rank_set[set_counter] =
                (int *)malloc((i - cursor) * sizeof(int));
            rank_cnt[set_counter] = numTasks - cursor;
            /*
            printf("cursor is %d\n", cursor); fflush(stdout);
            */
            for (i = cursor; i <= numTasks - 1; i++) {
                rank_set[set_counter][j] = host_set[i].rank;
                j++;
            }
            set_counter++;

            /*broadcast the rank_cnt and rank_set information to each
             * rank*/
            int root_set_no;
            for (i = 0; i < set_counter; i++) {
                for (j = 0; j < rank_cnt[i]; j++) {
                    if (rank_set[i][j] != 0) {
                        /*
                        printf("i is %d, j is %d\n", i, j); fflush(stdout);
                        printf("rank:%d, 1sending to %d, rank_cnt[%d] is %d\n", rank,
                                rank_set[i][j], i, rank_cnt[i]); fflush(stdout);
                                */
                        rc = MPI_Send(&rank_cnt[i], 1,
                                      MPI_INT, rank_set[i][j], 0, MPI_COMM_WORLD);
                        if (rc != 0) {
                            debug("cannot send local rank cnt");
                            return -1;
                        }



                        /*send the local rank set to the corresponding rank*/
                        rc = MPI_Send(rank_set[i], rank_cnt[i],
                                      MPI_INT, rank_set[i][j], 0, MPI_COMM_WORLD);
                        /*
                        printf("rank:%d, 2sending to %d, rank_cnt[%d] is %d\n", rank,
                                rank_set[i][j], i, rank_cnt[i]); fflush(stdout);*/
                        if (rc != 0) {
                            debug("cannot send local rank list");
                            return -1;
                        }
                    } else {
                        root_set_no = i;
                    }
                }
            }


            /* root process set its own local rank set and rank_cnt*/
            local_rank_lst = (int *)malloc(rank_cnt[root_set_no] * sizeof(int));
            for (i = 0; i < rank_cnt[root_set_no]; i++) {
                local_rank_lst[i] = rank_set[root_set_no][i];
            }
            local_rank_cnt = rank_cnt[root_set_no];

            for (i = 0; i < set_counter; i++) {
                free(rank_set[i]);
            }
            free(rank_cnt);
            free(host_set);
            free(rank_set);

        } else {
            /* non-root process performs MPI_send to send
             * hostname to root node */
            rc = MPI_Send(localhost, UNIFYCR_MAX_FILENAME,
                          MPI_CHAR, 0, 0, MPI_COMM_WORLD);
            if (rc != 0) {
                debug("cannot send host name");
                return -1;
            }
            /*receive the local rank count */
            rc = MPI_Recv(&local_rank_cnt, 1, MPI_INT, 0,
                          0, MPI_COMM_WORLD, &status);
            if (rc != 0) {
                debug("cannot receive local rank cnt");
                return -1;
            }

            /* receive the the local rank list */
            local_rank_lst = (int *)malloc(local_rank_cnt * sizeof(int));
            rc = MPI_Recv(local_rank_lst, local_rank_cnt, MPI_INT, 0,
                          0, MPI_COMM_WORLD, &status);
            if (rc != 0) {
                free(local_rank_lst);
                debug("cannot receive local rank list");
                return -1;
            }

        }

        qsort(local_rank_lst, local_rank_cnt, sizeof(int),
              compare_int);

        // scatter ranks out
    } else {
        debug("number of tasks is smaller than 0");
        return -1;
    }

    return 0;
}

/* get information about the chunk data region
 * for external async libraries to register during their init */
size_t unifycr_get_data_region(void **ptr)
{
    *ptr = unifycr_chunks;
    return unifycr_chunk_mem;
}

/* get a list of chunks for a given file (useful for RDMA, etc.) */
chunk_list_t *unifycr_get_chunk_list(char *path)
{
    return NULL;
}

/* debug function to print list of chunks constituting a file
 * and to test above function*/
void unifycr_print_chunk_list(char *path)
{
}
