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

#include "unifycr-runtime-config.h"
#include <stdio.h>
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
#include <aio.h>
#define __USE_GNU
#include <pthread.h>

#include "unifycr-sysio.h"
#include "unifycr-internal.h"
#include "unifycr-fixed.h"
#include "unifycr-sysio.h"
#include "unifycr.h" /* fs_type_t */

#include "famfs.h"
#include "f_stats.h"
#include "f_env.h"
#include "f_error.h"
#include "f_global.h"
#include "f_rbq.h"

//
// === libfabric stuff =============
//

#include "lf_client.h"

//
// =================================
//

/* -------------------
 * define external variables
 * --------------------*/
extern int unifycr_spilloverblock;
extern int unifycr_use_spillover;
extern int dbgrank;

extern f_rbq_t *adminq;
extern f_rbq_t *rplyq;
extern f_rbq_t *lo_cq[F_CMDQ_MAX];


/* ---------------------------------------
 * POSIX wrappers: paths
 * --------------------------------------- */

int UNIFYCR_WRAP(access)(const char *path, int mode)
{
    /* determine whether we should intercept this path */
    if (unifycr_intercept_path(path)) {
        /* check if path exists */
        if (unifycr_get_fid_from_path(path) < 0) {
            DEBUG("access: unifycr_get_id_from path failed, returning -1, %s\n",
                  path);
            /* ENOENT */
            return -1;
        }

        /* currently a no-op */
        DEBUG("access: path intercepted, returning 0, %s\n", path);
        return 0;
    } else {
        DEBUG("access: calling MAP_OR_FAIL, %s\n", path);
        MAP_OR_FAIL(access);
        int ret = UNIFYCR_REAL(access)(path, mode);
        DEBUG("access: returning __real_access %d,%s\n", ret, path);
        return ret;
    }
}

int UNIFYCR_WRAP(mkdir)(const char *path, mode_t mode)
{
    /* Support for directories is very limited at this time
     * mkdir simply puts an entry into the filelist for the
     * requested directory (assuming it does not exist)
     * It doesn't check to see if parent directory exists */
    int fid;

    /* determine whether we should intercept this path */
    if (unifycr_intercept_path(path)) {
        /* check if it already exists */
        if (unifycr_get_fid_from_path(path) >= 0) {
            errno = EEXIST;
            return -1;
        }

        /* add directory to file list */
        fid = unifycr_fid_create_directory(path);
    } else {
        MAP_OR_FAIL(mkdir);
        fid = UNIFYCR_REAL(mkdir)(path, mode);
    }
    /* errno is set on error */
    return (fid < 0)? -1:0;
}

int UNIFYCR_WRAP(rmdir)(const char *path)
{
    int ret;

    /* determine whether we should intercept this path */
    if (unifycr_intercept_path(path)) {
        /* check if the mount point itself is being deleted */
        if (! strcmp(path, unifycr_mount_prefix)) {
            errno = EBUSY;
            return -1;
        }

        /* check if path exists */
        int fid = unifycr_get_fid_from_path(path);
        if (fid < 0) {
            /* ENOENT */
            return -1;
        }

        /* is it a directory? */
        if (! unifycr_fid_is_dir(fid)) {
            errno = ENOTDIR;
            return -1;
        }

        /* is it empty? */
        if (! unifycr_fid_is_dir_empty(path)) {
            errno = ENOTEMPTY;
            return -1;
        }

        /* remove the directory from the file list */
        ret = fd_iface->fid_unlink(fid);
    } else {
        MAP_OR_FAIL(rmdir);
        ret = UNIFYCR_REAL(rmdir)(path);
    }
    return (ret < 0)? -1:0;
}

int UNIFYCR_WRAP(rename)(const char *oldpath, const char *newpath)
{
    /* TODO: allow oldpath / newpath to split across memfs and normal
     * linux fs, which means we'll need to do a read / write */

    /* check whether the old path is in our file system */
    if (unifycr_intercept_path(oldpath)) {
        /* for now, we can only rename within our file system */
        if (! unifycr_intercept_path(newpath)) {
            /* ERROR: can't yet rename across file systems */
            errno = EXDEV;
            return -1;
        }

        /* verify that we really have a file by the old name */
        int fid = unifycr_get_fid_from_path(oldpath);
        DEBUG("orig file in position %d\n", fid);
        if (fid < 0) {
            /* ERROR: oldname does not exist */
            DEBUG("Couldn't find entry for %s in UNIFYCR\n", oldpath);
            /* ENOENT */
            return -1;
        }

        /* verify that we don't already have a file by the new name */
        if (unifycr_get_fid_from_path(newpath) < 0) {
            /* check that new name is within bounds */
            size_t newpathlen = strlen(newpath) + 1;
            if (newpathlen > UNIFYCR_MAX_FILENAME) {
                errno = ENAMETOOLONG;
                return -1;
            }

            /* finally overwrite the old name with the new name */
            DEBUG("Changing %s to %s\n",
                  (char *)&unifycr_filelist[fid].filename, newpath);
            strcpy((void *)&unifycr_filelist[fid].filename, newpath);
        } else {
            /* ERROR: new name already exists */
            DEBUG("File %s exists\n", newpath);
            errno = EEXIST;
            return -1;
        }
        return 0;
    } else {
        /* for now, we can only rename within our file system */
        if (unifycr_intercept_path(newpath)) {
            /* ERROR: can't yet rename across file systems */
            errno = EXDEV;
            return -1;
        }

        /* both files are normal linux files, delegate to system call */
        MAP_OR_FAIL(rename);
        int ret = UNIFYCR_REAL(rename)(oldpath, newpath);
        return ret;
    }
}

int UNIFYCR_WRAP(truncate)(const char *path, off_t length)
{
    /* determine whether we should intercept this path or not */
    if (unifycr_intercept_path(path)) {
        /* lookup the fd for the path */
        int fid = unifycr_get_fid_from_path(path);
        if (fid < 0) {
            /* ERROR: file does not exist */
            DEBUG("Couldn't find entry for %s in UNIFYCR\n", path);
            /* ENOENT */
            return -1;
        }

        /* truncate the file */
        int rc = fd_iface->fid_truncate(fid, length);
        if (rc != UNIFYCR_SUCCESS) {
            DEBUG("fid_truncate failed for %s in UNIFYCR\n", path);
            errno = EIO;
            return -1;
        }

        return 0;
    } else {
        MAP_OR_FAIL(truncate);
        int ret = UNIFYCR_REAL(truncate)(path, length);
        return ret;
    }
}

int UNIFYCR_WRAP(unlink)(const char *path)
{
    /* determine whether we should intercept this path or not */
    if (unifycr_intercept_path(path)) {
        /* get file id for path name */
        int fid = unifycr_get_fid_from_path(path);
        if (fid < 0) {
            /* ERROR: file does not exist */
            DEBUG("Couldn't find entry for %s in UNIFYCR\n", path);
            /* ENOENT */
            return -1;
        }

        /* check that it's not a directory */
        if (unifycr_fid_is_dir(fid)) {
            /* ERROR: is a directory */
            DEBUG("Attempting to unlink a directory %s in UNIFYCR\n", path);
            errno = EISDIR;
            return -1;
        }

        /* delete the file */
        fd_iface->fid_unlink(fid);

        return 0;
    } else {
        MAP_OR_FAIL(unlink);
        int ret = UNIFYCR_REAL(unlink)(path);
        return ret;
    }
}

int UNIFYCR_WRAP(remove)(const char *path)
{
    /* determine whether we should intercept this path or not */
    if (unifycr_intercept_path(path)) {
        /* get file id for path name */
        int fid = unifycr_get_fid_from_path(path);
        if (fid < 0) {
            /* ERROR: file does not exist */
            DEBUG("Couldn't find entry for %s in UNIFYCR\n", path);
            /* ENOENT */
            return -1;
        }

        /* check that it's not a directory */
        if (unifycr_fid_is_dir(fid)) {
            /* TODO: shall be equivalent to rmdir(path) */
            /* ERROR: is a directory */
            DEBUG("Attempting to remove a directory %s in UNIFYCR\n", path);
            errno = EISDIR;
            return -1;
        }

        /* shall be equivalent to unlink(path) */
        /* delete the file */
        fd_iface->fid_unlink(fid);

        return 0;
    } else {
        MAP_OR_FAIL(remove);
        int ret = UNIFYCR_REAL(remove)(path);
        return ret;
    }
}

int UNIFYCR_WRAP(stat)(const char *path, struct stat *buf)
{
    DEBUG("stat was called for %s....\n", path);
    if (unifycr_intercept_path(path)) {
        int fid = unifycr_get_fid_from_path(path);
        if (fid < 0) {
            /* ENOENT */
            return -1;
        }

        unifycr_fid_stat(fid, buf);

        return 0;
    } else {
        MAP_OR_FAIL(stat);
        int ret = UNIFYCR_REAL(stat)(path, buf);
        return ret;
    }
}

int UNIFYCR_WRAP(__xstat)(int vers, const char *path, struct stat *buf)
{
    DEBUG("xstat was called for %s....\n", path);
    if (unifycr_intercept_path(path)) {
        /* get file id for path */
        int fid = unifycr_get_fid_from_path(path);
        if (fid < 0) {
            /* file doesn't exist */
            /* ENOENT */
            return -1;
        }

        /* get meta data for this file */
        unifycr_fid_stat(fid, buf);

        return 0;
    } else {
        MAP_OR_FAIL(__xstat);
        int ret = UNIFYCR_REAL(__xstat)(vers, path, buf);
        return ret;
    }
}

int UNIFYCR_WRAP(__lxstat)(int vers, const char *path, struct stat *buf)
{
    /* check whether we should intercept this path */
    if (unifycr_intercept_path(path)) {
        /* ERROR: fn not yet supported */
        fprintf(stderr, "Function not yet supported @ %s:%d\n", __FILE__, __LINE__);
        errno = ENOENT;
        return -1;
    } else {
        MAP_OR_FAIL(__lxstat);
        int ret = UNIFYCR_REAL(__lxstat)(vers, path, buf);
        return ret;
    }
}

#define UNIFYCR_OPT_TRSF_BZ (1024*1024)
int UNIFYCR_WRAP(statfs)(const char *path, struct statfs *buf)
{
    /* check whether we should intercept this path */
    if (unifycr_intercept_path(path)) {
        if (strcmp(path, unifycr_mount_prefix) && !unifycr_use_spillover) {
            /* ERROR: fn not yet supported */
            fprintf(stderr, "Function not yet supported @ %s:%d path:%s\n", __FILE__, __LINE__, path);
            errno = ENOSYS;
            return -1;
        }
        /* check if path exists */
        int fid = unifycr_get_fid_from_path(path);
        if (fid < 0) {
            /* ENOENT */
            return -1;
        }
        /* is it a directory? */
        if (! unifycr_fid_is_dir(fid)) {
            errno = ENOTDIR;
            return -1;
        }

        struct statfs *stats = (struct statfs *)buf;
        memset(stats, 0, sizeof(struct statfs));
        stats->f_bsize = UNIFYCR_OPT_TRSF_BZ;
        /* total fs size */
        size_t total, free;
        int ret = unifycr_report_storage(fid, &total, &free);
        if (ret) {
            errno = ENOENT;
            return -1;
        }
        stats->f_blocks = total / stats->f_bsize;
        stats->f_bfree = free / stats->f_bsize;
        /* inodes */
        unsigned long maxfiles;
        unsigned long nfiles = unifycr_fid_is_dir_used(fid, &maxfiles);
        stats->f_files = maxfiles;
        stats->f_ffree = stats->f_files - nfiles;
        return 0;
    } else {
        MAP_OR_FAIL(statfs);
        int ret = UNIFYCR_REAL(statfs)(path, buf);
        return ret;
    }
}

char *UNIFYCR_WRAP(__realpath_chk)(const char* path, char* buf, size_t size)
{
    /* determine whether we should intercept this path or not */
    if (unifycr_intercept_path(path) && size >= PATH_MAX) {
        /* get file id for path name */
        int fid = unifycr_get_fid_from_path(path);
        if (fid < 0) {
            /* ERROR: file does not exist */
            DEBUG("Couldn't find entry for %s in UNIFYCR\n", path);
            /* ENOENT */
            return NULL;
        }
        return normalized_path(path, buf, size);
    } else {
        /* if size < PATH_MAX, log "buffer underflow" error and abort */
        MAP_OR_FAIL(__realpath_chk);
        char *ret = UNIFYCR_REAL(__realpath_chk)(path, buf, size);
        return ret;
    }
}

char *UNIFYCR_WRAP(realpath)(const char* path, char* buf)
{
    /* determine whether we should intercept this path or not */
    if (unifycr_intercept_path(path)) {
        /* get file id for path name */
        int fid = unifycr_get_fid_from_path(path);
        if (fid < 0) {
            /* ERROR: file does not exist */
            DEBUG("Couldn't find entry for %s in UNIFYCR\n", path);
            /* ENOENT */
            return NULL;
        }
        return normalized_path(path, buf, PATH_MAX);
    } else {
        MAP_OR_FAIL(realpath);
        char *ret = UNIFYCR_REAL(realpath)(path, buf);
        return ret;
    }
}

/* ---------------------------------------
 * POSIX wrappers: file descriptors
 * --------------------------------------- */

/* read count bytes info buf from file starting at offset pos,
 * returns number of bytes actually read in retcount,
 * retcount will be less than count only if an error occurs
 * or end of file is reached */
int unifycr_fd_read(int fd, off_t pos, void *buf, size_t count,
                    size_t *retcount)
{
    /* get the file id for this file descriptor */
    int fid = unifycr_get_fid_from_fd(fd);
    if (fid < 0) {
        return UNIFYCR_ERR_BADF;
    }

    /* it's an error to read from a directory */
    if (unifycr_fid_is_dir(fid)) {
        /* TODO: note that read/pread can return this, but not fread */
        return UNIFYCR_ERR_ISDIR;
    }

    /* check that file descriptor is open for read */
    unifycr_fd_t *filedesc = unifycr_get_filedesc_from_fd(fd);
    if (! filedesc->read) {
        return UNIFYCR_ERR_BADF;
    }

    /* TODO: is it safe to assume that off_t is bigger than size_t? */
    /* check that we don't overflow the file length */
    if (unifycr_would_overflow_offt(pos, (off_t) count)) {
        return UNIFYCR_ERR_OVERFLOW;
    }

    /* TODO: check that file is open for reading */

    /* check that we don't try to read past the end of the file */
    off_t lastread = pos + (off_t) count;
    off_t filesize = fd_iface->fid_size(fid);
    if (filesize < lastread) {
        /* adjust count so we don't read past end of file */
        if (filesize > pos) {
            /* read all bytes until end of file */
            count = (size_t)(filesize - pos);
        } else {
            /* pos is already at or past the end of the file */
            count = 0;
        }
    }

    /* record number of bytes that we'll actually read */
    *retcount = count;

    /* if we don't read any bytes, return success */
    if (count == 0) {
        return UNIFYCR_SUCCESS;
    }

    /* read data from file */
    int read_rc = unifycr_fid_read(fid, pos, buf, count);
    return read_rc;
}

/* write count bytes from buf into file starting at offset pos,
 * allocates new bytes and updates file size as necessary,
 * fills any gaps with zeros */
int unifycr_fd_write(int fd, off_t pos, const void *buf, size_t count)
{
    STATS_START(start);

    /* get the file id for this file descriptor */
    int fid = unifycr_get_fid_from_fd(fd);
    if (fid < 0) {
        return UNIFYCR_ERR_BADF;
    }

    /* it's an error to write to a directory */
    if (unifycr_fid_is_dir(fid)) {
        DEBUG("attempt to write to directory\n");
        return UNIFYCR_ERR_INVAL;
    }

    /* check that file descriptor is open for write */
    unifycr_fd_t *filedesc = unifycr_get_filedesc_from_fd(fd);
    if (! filedesc->write) {
        DEBUG("file is not open for write\n");
        return UNIFYCR_ERR_BADF;
    }

    /* TODO: is it safe to assume that off_t is bigger than size_t? */
    /* check that our write won't overflow the length */
    if (unifycr_would_overflow_offt(pos, (off_t) count)) {
        /* TODO: want to return EFBIG here for streams */
        return UNIFYCR_ERR_OVERFLOW;
    }

    /* TODO: check that file is open for writing */

    /* get current file size before extending the file */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    off_t filesize = fd_iface->fid_size(fid);
    off_t newpos;

    if (meta->storage == FILE_STORAGE_FIXED_CHUNK) {
        /* extend file size and allocate chunks if needed */
        newpos = pos + (off_t) count;
        int extend_rc = fd_iface->fid_extend(fid, newpos);
        if (extend_rc != UNIFYCR_SUCCESS) {
            return extend_rc;
        }

        /* fill any new bytes between old size and pos with zero values */
        if (filesize < pos) {
            off_t gap_size = pos - filesize;
            int zero_rc = unifycr_fid_write_zero(fid, filesize, gap_size);
            if (zero_rc != UNIFYCR_SUCCESS) {
                return zero_rc;
            }
        }
    }

    else if (meta->storage == FILE_STORAGE_LOGIO) {
        newpos = filesize + (off_t)count;
        int extend_rc = fd_iface->fid_extend(fid, newpos);
        if (extend_rc != UNIFYCR_SUCCESS) {
            return extend_rc;
        }
    } else {
        return UNIFYCR_ERR_IO;
    }

    /* finally write specified data to file */
    int write_rc = fd_iface->fid_write(fid, pos, buf, count);

    if (meta->storage == FILE_STORAGE_LOGIO) {
        unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
        if (write_rc == 0) {
            meta->size = newpos;
            if (pos + count > (long unsigned int)meta->real_size)
                meta->real_size = pos + count;
        }
    }

    UPDATE_STATS(fd_wr_stat, 1, count, start);

    return write_rc;
}

int UNIFYCR_WRAP(creat)(const char *path, mode_t mode)
{
    /* equivalent to open(path, O_WRONLY|O_CREAT|O_TRUNC, mode) */

    /* check whether we should intercept this path */
    if (unifycr_intercept_path(path)) {
        /* TODO: handle relative paths using current working directory */

        /* create the file */
        int fid;
        off_t pos;
        int rc = fd_iface->fid_open(path, O_WRONLY | O_CREAT | O_TRUNC, mode, &fid, &pos);
        if (rc != UNIFYCR_SUCCESS) {
            return -1;
        }

        /* TODO: allocate a free file descriptor and associate it with fid */
        /* set in_use flag and file pointer, flags include O_WRONLY */
        unifycr_fd_t *filedesc = &(unifycr_fds[fid]);
        filedesc->fid   = fid;
        filedesc->pos   = pos;
        filedesc->read  = 0;
        filedesc->write = 1;
        DEBUG("UNIFYCR_open generated fd %d for file %s\n", fid, path);

        /* don't conflict with active system fds that range from 0 - (fd_limit) */
        int ret = fid + unifycr_fd_limit;
        return ret;
    } else {
        MAP_OR_FAIL(creat);
        int ret = UNIFYCR_REAL(creat)(path, mode);
        return ret ;
    }
}

int UNIFYCR_WRAP(creat64)(const char *path, mode_t mode)
{
    /* check whether we should intercept this path */
    if (unifycr_intercept_path(path)) {
        /* ERROR: fn not yet supported */
        fprintf(stderr, "Function not yet supported @ %s:%d\n", __FILE__, __LINE__);
        return -1;
    } else {
        MAP_OR_FAIL(creat64);
        int ret = UNIFYCR_REAL(creat64)(path, mode);
        return ret;
    }
}

int UNIFYCR_WRAP(open)(const char *path, int flags, ...)
{
    int ret;
    /* if O_CREAT is set, we should also have some mode flags */
    int mode = 0;
    if (flags & O_CREAT) {
        va_list arg;
        va_start(arg, flags);
        mode = va_arg(arg, int);
        va_end(arg);
    }
    /* determine whether we should intercept this path */
    if (unifycr_intercept_path(path)) {
        /* TODO: handle relative paths using current working directory */

        /* create the file */
        int fid;
        off_t pos;
        int rc = fd_iface->fid_open(path, flags, mode, &fid, &pos);
        if (rc != UNIFYCR_SUCCESS) {
            return -1;
        }

        /* TODO: allocate a free file descriptor and associate it with fid */
        /* set in_use flag and file pointer */
        unifycr_fd_t *filedesc = &(unifycr_fds[fid]);
        filedesc->fid   = fid;
        filedesc->pos   = pos;
        filedesc->read  = ((flags & O_RDONLY) == O_RDONLY)
                          || ((flags & O_RDWR) == O_RDWR);
        filedesc->write = ((flags & O_WRONLY) == O_WRONLY)
                          || ((flags & O_RDWR) == O_RDWR);
        DEBUG("UNIFYCR_open generated fd %d for file %s r/w=%d/%d\n", fid, path, filedesc->read, filedesc->write);

        /* don't conflict with active system fds that range from 0 - (fd_limit) */
        ret = fid + unifycr_fd_limit;

        INIT_STATS(LF_RD_STATS_FN, lf_rd_stat);
        INIT_STATS(LF_WR_STATS_FN, lf_wr_stat);
        INIT_STATS(FD_SYN_STATS_FN, fd_syn_stat);
        INIT_STATS(FD_EXT_STATS_FN, fd_ext_stat);
        INIT_STATS(FD_WR_STATS_FN, fd_wr_stat);
        INIT_STATS(WR_MAP_STATS_FN, wr_map_stat);
        INIT_STATS(WR_UPD_STATS_FN, wr_upd_stat);
        INIT_STATS(WR_CMT_STATS_FN, wr_cmt_stat);
        INIT_STATS(MD_LG_STATS_FN, md_lg_stat);
        INIT_STATS(MD_FP_STATS_FN, md_fp_stat);
        INIT_STATS(MD_FG_STATS_FN, md_fg_stat);
        INIT_STATS(MD_AP_STATS_FN, md_ap_stat);
        INIT_STATS(MD_AG_STATS_FN, md_ag_stat);
        INIT_STATS(TEST1_STATS_FN, test1_stat);

        return ret;
    } else {
        MAP_OR_FAIL(open);
        if (flags & O_CREAT) {
            ret = UNIFYCR_REAL(open)(path, flags, mode);
        } else {
            ret = UNIFYCR_REAL(open)(path, flags);
        }
        return ret;
    }
}

int UNIFYCR_WRAP(__open_2)(const char *path, int flags)
{
    return UNIFYCR_WRAP(open)(path, flags);
}

int UNIFYCR_WRAP(open64)(const char *path, int flags, ...)
{
    int ret;

    /* if O_CREAT is set, we should also have some mode flags */
    int mode = 0;
    if (flags & O_CREAT) {
        va_list arg;
        va_start(arg, flags);
        mode = va_arg(arg, int);
        va_end(arg);
    }

    /* check whether we should intercept this path */
    if (unifycr_intercept_path(path)) {
        /* ERROR: fn not yet supported */
        fprintf(stderr, "Function not yet supported @ %s:%d\n", __FILE__, __LINE__);
        return -1;
    } else {
        MAP_OR_FAIL(open64);
        if (flags & O_CREAT) {
            ret = UNIFYCR_REAL(open64)(path, flags, mode);
        } else {
            ret = UNIFYCR_REAL(open64)(path, flags);
        }
    }

    return ret;
}

off_t UNIFYCR_WRAP(lseek)(int fd, off_t offset, int whence)
{
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* TODO: check that fd is actually in use */

        /* get the file id for this file descriptor */
        int fid = unifycr_get_fid_from_fd(fd);

        /* check that file descriptor is good */
        unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
        if (meta == NULL) {
            /* bad file descriptor */
            errno = EBADF;
            return (off_t) (-1);
        }

        /* get file descriptor for fd */
        unifycr_fd_t *filedesc = unifycr_get_filedesc_from_fd(fd);

        /* get current file position */
        off_t current_pos = filedesc->pos;

        /* compute final file position */
        DEBUG("seeking from %ld\n", current_pos);
        switch (whence) {
        case SEEK_SET:
            /* seek to offset */
            current_pos = offset;
            break;
        case SEEK_CUR:
            /* seek to current position + offset */
            current_pos += offset;
            break;
        case SEEK_END:
            /* seek to EOF + offset */
            //current_pos = meta->size + offset;
            current_pos = fd_iface->fid_size(fid) + offset;
            break;
        default:
            errno = EINVAL;
            return (off_t) (-1);
        }
        DEBUG("seeking to %ld\n", current_pos);

        /* set and return final file position */
        filedesc->pos = current_pos;
        return current_pos;
    } else {
        MAP_OR_FAIL(lseek);
        off_t ret = UNIFYCR_REAL(lseek)(fd, offset, whence);
        return ret;
    }
}

off64_t UNIFYCR_WRAP(lseek64)(int fd, off64_t offset, int whence)
{
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* ERROR: fn not yet supported */
        fprintf(stderr, "Function not yet supported @ %s:%d\n", __FILE__, __LINE__);
        errno = EBADF;
        return (off64_t) (-1);
    } else {
        MAP_OR_FAIL(lseek64);
        off64_t ret = UNIFYCR_REAL(lseek64)(fd, offset, whence);
        return ret;
    }
}

int UNIFYCR_WRAP(posix_fadvise)(int fd, off_t offset, off_t len, int advice)
{
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* check that the file descriptor is valid */
        int fid = unifycr_get_fid_from_fd(fd);
        if (fid < 0) {
            errno = EBADF;
            return errno;
        }

        /* process advice from caller */
        switch (advice) {
        case POSIX_FADV_NORMAL:
        case POSIX_FADV_SEQUENTIAL:
        /* can use this hint for a better compression strategy */
        case POSIX_FADV_RANDOM:
        case POSIX_FADV_NOREUSE:
        case POSIX_FADV_WILLNEED:
        /* with the spill-over case, we can use this hint to
         * to better manage the in-memory parts of a file. On
         * getting this advice, move the chunks that are on the
         * spill-over device to the in-memory portion
         */
        case POSIX_FADV_DONTNEED:
            /* similar to the previous case, but move contents from memory
             * to the spill-over device instead.
             */

            /* ERROR: fn not yet supported */
            fprintf(stderr, "Function not yet supported @ %s:%d\n", __FILE__, __LINE__);
            break;
        default:
            /* this function returns the errno itself, not -1 */
            errno = EINVAL;
            return errno;
        }

        /* just a hint so return success even if we don't do anything */
        return 0;
    } else {
        MAP_OR_FAIL(posix_fadvise);
        int ret = UNIFYCR_REAL(posix_fadvise)(fd, offset, len, advice);
        return ret;
    }
}

ssize_t UNIFYCR_WRAP(read)(int fd, void *buf, size_t count)
{
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* get pointer to file descriptor structure */
        unifycr_fd_t *filedesc = unifycr_get_filedesc_from_fd(fd);
        if (filedesc == NULL) {
            /* ERROR: invalid file descriptor */
            errno = EBADF;
            return (ssize_t) (-1);
        }

        /* read data from file */
        size_t retcount;

        if (fs_type == UNIFYCR_LOG || fs_type == FAMFS) {
            read_req_t tmp_req;
            tmp_req.buf = buf;
            tmp_req.fid = fd + unifycr_fd_limit;
            tmp_req.length = count;
            tmp_req.offset = filedesc->pos;
            tmp_req.lid = unifycr_get_meta_from_fid(fd)->loid;

            int ret = fd_iface->fd_logreadlist(&tmp_req, 1);
            if (!ret) {
                retcount = count;
            } else {
                retcount = 0;
            }
        } else {
            int read_rc = unifycr_fd_read(fd, filedesc->pos, buf, count, &retcount);
            if (read_rc != UNIFYCR_SUCCESS) {
                errno = unifycr_err_map_to_errno(read_rc);
                return (ssize_t) (-1);
            }

        }
        /* update position */
        filedesc->pos += (off_t) retcount;
        /* return number of bytes read */
        return (ssize_t) retcount;
    } else {
        MAP_OR_FAIL(read);
        ssize_t ret = UNIFYCR_REAL(read)(fd, buf, count);
        return ret;
    }
}

/* TODO: find right place to msync spillover mapping */
ssize_t UNIFYCR_WRAP(write)(int fd, const void *buf, size_t count)
{
    ssize_t ret;

    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* get pointer to file descriptor structure */
        unifycr_fd_t *filedesc = unifycr_get_filedesc_from_fd(fd);
        if (filedesc == NULL) {
            /* ERROR: invalid file descriptor */
            errno = EBADF;
            return (ssize_t) (-1);
        }

        /* write data to file */
        int write_rc = unifycr_fd_write(fd, filedesc->pos, buf, count);
        if (write_rc != UNIFYCR_SUCCESS) {
            errno = unifycr_err_map_to_errno(write_rc);
            return (ssize_t) (-1);
        }
        ret = count;

        /* update file position */
        filedesc->pos += ret;

    } else {
        MAP_OR_FAIL(write);
        ret = UNIFYCR_REAL(write)(fd, buf, count);
    }

    return ret;
}

ssize_t UNIFYCR_WRAP(readv)(int fd, const struct iovec *iov, int iovcnt)
{
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* ERROR: fn not yet supported */
        fprintf(stderr, "Function not yet supported @ %s:%d\n", __FILE__, __LINE__);
        errno = EBADF;
        return -1;
    } else {
        MAP_OR_FAIL(readv);
        ssize_t ret = UNIFYCR_REAL(readv)(fd, iov, iovcnt);
        return ret;
    }
}

ssize_t UNIFYCR_WRAP(writev)(int fd, const struct iovec *iov, int iovcnt)
{
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* ERROR: fn not yet supported */
        fprintf(stderr, "Function not yet supported @ %s:%d\n", __FILE__, __LINE__);
        errno = EBADF;
        return -1;
    } else {
        MAP_OR_FAIL(writev);
        ssize_t ret = UNIFYCR_REAL(writev)(fd, iov, iovcnt);
        return ret;
    }
}

int UNIFYCR_WRAP(lio_listio)(int mode __attribute__((unused)),
                             struct aiocb *const aiocb_list[],
                             int nitems,
                             struct sigevent *sevp __attribute__((unused)))
{

    int ret = 0, i;
    read_req_t *glb_read_reqs = malloc(nitems * sizeof(read_req_t));

    for (i = 0; i < nitems; i++) {
        if (aiocb_list[i]->aio_lio_opcode != LIO_READ) {
            //does not support write operation currently
            return -1;
        }
        int fid = aiocb_list[i]->aio_fildes + unifycr_fd_limit;
        glb_read_reqs[i].fid = fid;
        glb_read_reqs[i].buf = (char *)aiocb_list[i]->aio_buf;
        glb_read_reqs[i].length = aiocb_list[i]->aio_nbytes;
        glb_read_reqs[i].offset = aiocb_list[i]->aio_offset;
        glb_read_reqs[i].lid = 0; /* TODO: check fd and get lid from meta */
    }

    ret = fd_iface->fd_logreadlist(glb_read_reqs, nitems);
    free(glb_read_reqs);
    return ret;
}

static int compare_read_req(const void *a, const void *b)
{
    const read_req_t *ptr_a = a;
    const read_req_t *ptr_b = b;

    if (ptr_a->fid - ptr_b->fid > 0)
        return 1;

    if (ptr_a->fid - ptr_b->fid < 0)
        return -1;

    if (ptr_a->offset - ptr_b->offset > 0)
        return 1;

    if (ptr_a->offset - ptr_b->offset < 0)
        return -1;

    return 0;
}

int unifycr_locate_req(read_req_t *read_req, int count,
                       read_req_t *match_req)
{
    if (count == 0) {
        return -1;
    }

    if (count == 1) {
        return 0;
    }

    if (count == 2) {
        if (compare_read_req(match_req, &read_req[1]) < 0) {
            return 0;
        }

        return 1;
    }

    int left = 0;
    int right = count - 1;
    int mid = (left + right) / 2;

    int found = 0;
    while (left + 1 < right) {
        if (compare_read_req(match_req, &read_req[mid]) == 0) {
            found = 1;
            break;
        }

        if (compare_read_req(match_req, &read_req[mid]) > 0) {
            left = mid;
        }

        if (compare_read_req(match_req, &read_req[mid]) < 0) {
            right = mid;
        }

        mid = (left + right) / 2;

    }

    if (found == 1) {
        return mid;
    }

    if (compare_read_req(match_req, &read_req[left]) < 0) {
        if (left == 0) {
            return 0;
        }
        return left - 1;
    } else {
        if (compare_read_req(match_req, &read_req[right]) < 0) {
            return right - 1;
        } else {
            return right;
        }
    }

}

/*
 * given an read request, split it into multiple indices whose range is equal or smaller
 * than slice_range size
 * @param cur_read_req: the read request to split
 * @param slice_range: the slice size of the key-value store
 * @return read_req_set: the set of split read requests
 * */
static int unifycr_split_read_requests(read_req_t *cur_read_req,
                                read_req_set_t *read_req_set,
                                long slice_range)
{
    long cur_read_start = cur_read_req->offset;
    long cur_read_end = cur_read_req->offset + cur_read_req->length - 1;

    long cur_slice_start = cur_read_req->offset / slice_range * slice_range;
    long cur_slice_end = cur_slice_start + slice_range - 1;

    read_req_set->count = 0;

    if (cur_read_end <= cur_slice_end) {
        /*
        cur_slice_start                                  cur_slice_end
                         cur_read_start     cur_read_end

        */
        read_req_set->read_reqs[read_req_set->count]= *cur_read_req;
        read_req_set->count++;
    } else {
        /*
        cur_slice_start                     cur_slice_endnext_slice_start                   next_slice_end
                         cur_read_start                                     cur_read_end

        */
        read_req_set->read_reqs[read_req_set->count] = *cur_read_req;
        read_req_set->read_reqs[read_req_set->count].length =
            cur_slice_end - cur_read_start + 1;
        read_req_set->count++;

        cur_slice_start = cur_slice_end + 1;
        cur_slice_end = cur_slice_start + slice_range - 1;

        while (1) {
            if (cur_read_end <= cur_slice_end)
                break;

            read_req_set->read_reqs[read_req_set->count].lid = cur_read_req->lid;
            read_req_set->read_reqs[read_req_set->count].fid = cur_read_req->fid;
            read_req_set->read_reqs[read_req_set->count].offset = cur_slice_start;
            read_req_set->read_reqs[read_req_set->count].length = slice_range;

            cur_slice_start = cur_slice_end + 1;
            cur_slice_end = cur_slice_start + slice_range - 1;
            read_req_set->count++;

        }

        read_req_set->read_reqs[read_req_set->count].lid = cur_read_req->lid;
        read_req_set->read_reqs[read_req_set->count].fid = cur_read_req->fid;
        read_req_set->read_reqs[read_req_set->count].offset = cur_slice_start;
        read_req_set->read_reqs[read_req_set->count].length = cur_read_end - cur_slice_start + 1;
        read_req_set->count++;
    }

    return 0;
}

/*
 * coalesce contiguous read requests and
 * split the read requests whose size is larger than
 * unifycr_key_slice_range into the ones smaller
 * than unifycr_key_slice range
 * @param read_req: a list of read requests
 * @param count: number of read requests
 * @param tmp_read_req_set: a temporary read requests buffer
 * to hold the intermediate result
 * @param unifycr_key_slice_range: slice size of distributed
 * key-value store
 * @return read_req_set: the coalesced read requests
 *
 * */
int unifycr_coalesce_read_reqs(read_req_t *read_req, int count,
                               read_req_set_t *tmp_read_req_set, long unifycr_key_slice_range,
                               read_req_set_t *read_req_set)
{

    read_req_set->count = 0;
    tmp_read_req_set->count = 0;

    int cursor = 0;
    int i, j;
    for (i = 0; i < count; i++) {
        j = 0;
        unifycr_split_read_requests(&read_req[i], tmp_read_req_set,
                                    unifycr_key_slice_range);
        if (cursor != 0) {
            if (read_req_set->read_reqs[cursor - 1].lid == tmp_read_req_set->read_reqs[0].lid &&
                read_req_set->read_reqs[cursor - 1].fid == tmp_read_req_set->read_reqs[0].fid) {
                if (read_req_set->read_reqs[cursor - 1].offset +
                    read_req_set->read_reqs[cursor - 1].length
                    == tmp_read_req_set->read_reqs[0].offset) {
                    /*
                     * if not within the same slice, then don't coalesce
                     *
                     * */
                    if (read_req_set->read_reqs[cursor - 1].offset/unifycr_key_slice_range 
                        == tmp_read_req_set->read_reqs[0].offset/unifycr_key_slice_range) {
                        
                        read_req_set->read_reqs[cursor - 1].length += 
                            tmp_read_req_set->read_reqs[0].length;
                        j++;
                    }

                }
            }
        }

        for (; j < tmp_read_req_set->count; j++) {
            read_req_set->read_reqs[cursor] = tmp_read_req_set->read_reqs[j];
            read_req_set->count++;
            cursor++;
        }

    }

    return 0;
}

/*
 * match the received read_requests with the
 * client's read requests
 * @param read_req: a list of read requests
 * @param count: number of read requests
 * @param match_req: received read request to match
 * @return error code
 *
 * */

int unifycr_match_received_ack(read_req_t *read_req, int count,
                               read_req_t *match_req)
{

    read_req_t match_start = *match_req;
    read_req_t match_end = *match_req;
    read_req_t tmp_req_start, tmp_req_end;
    match_end.offset += match_end.length - 1;
    char *src = match_req->buf + sizeof(shm_meta_t);

    int start_pos = unifycr_locate_req(read_req, count, &match_start);
    int end_pos = unifycr_locate_req(read_req, count, &match_end);

    if (start_pos == -1) {
        return -1;
    }

    /*s: start of match_req, e: end of match_req*/
    if (start_pos == 0) {
        if (compare_read_req(&match_start, &read_req[0]) < 0) {
            /*
             *                      ************    ***********         *************
             *                  s
             * */
            return -1;
        }
    }

    tmp_req_start = read_req[start_pos];
    tmp_req_end = read_req[start_pos];
    tmp_req_end.offset += tmp_req_end.length - 1;

    /*              tmp_s       tmp_e
     *              *****************           *************
     *                     s  e
     * */
    if (compare_read_req(&match_start, &tmp_req_start) >= 0 &&
        compare_read_req(&match_end, &tmp_req_end) <= 0) {


        int copy_offset = match_start.offset - tmp_req_start.offset;
        memcpy(tmp_req_start.buf + copy_offset, src,
               match_req->length);

        return 0;
    }

    /*  tmp_s       tmp_e   req_s   req_endreq_s    req_endreq_s            req_e
     *  *************************************************************************
     *          s                                                       e
     * */


    read_req_t tmp_start_req_start, tmp_start_req_end,
               tmp_end_req_start, tmp_end_req_end;

    tmp_start_req_start = read_req[start_pos];
    tmp_start_req_end = read_req[start_pos];
    tmp_start_req_end.offset += tmp_start_req_end.length - 1;

    tmp_end_req_start = read_req[end_pos];
    tmp_end_req_end = read_req[end_pos];
    tmp_end_req_end.offset += tmp_end_req_end.length - 1;


    if (compare_read_req(&match_start, &tmp_start_req_start) >= 0 &&
        compare_read_req(&match_end, &tmp_end_req_end) <= 0) {

        /*read requests are noncontiguous, so we returned more
         * data, error*/
        int i;
        for (i = start_pos + 1; i <= end_pos; i++) {
            if (read_req[i - 1].offset + read_req[i - 1].length != read_req[i].offset) {
                return -1;
            }
        }

        /*read requests are contiguous, so we fill all req buffers in the
         * middle*/
        long copy_offset = match_start.offset - tmp_start_req_start.offset;
        long copy_length = tmp_start_req_end.offset - match_start.offset + 1;
        memcpy(tmp_start_req_start.buf + copy_offset, src, copy_length);


        long cursor = copy_length;
        for (i = start_pos + 1; i < end_pos; i++) {
            memcpy(read_req[i].buf, src + cursor, read_req[i].length);

            cursor += read_req[i].length;
        }

        copy_offset = 0;
        copy_length = match_end.offset - tmp_end_req_start.offset + 1;
        memcpy(tmp_end_req_start.buf + copy_offset, src, copy_length);

        return 0;
    }

    return -1;

}

/*
 * get data for a list of read requests from the
 * delegator
 * @param read_req: a list of read requests
 * @param count: number of read requests
 * @return error code
 *
 * */
int unifycr_fd_logreadlist(read_req_t *read_req, int count)
{
    int i, tot_sz = 0, num = 0;
    int *ptr_size = NULL, *ptr_num = NULL;
    int rc = UNIFYCR_SUCCESS;

    /*
     * Todo: When the number of read requests exceed the
     * request buffer, split list io into multiple bulk
     * sends and transfer in bulks
     * */

    /*convert local fid to global fid*/
    f_fattr_t tmp_meta_entry;
    f_fattr_t *ptr_meta_entry;
    for (i = 0; i < count; i++) {
        read_req[i].lid = 0;
        read_req[i].fid -= unifycr_fd_limit;
        tmp_meta_entry.fid = read_req[i].fid;

        ptr_meta_entry = (f_fattr_t *)bsearch(&tmp_meta_entry,
                         unifycr_fattrs.meta_entry, *unifycr_fattrs.ptr_num_entries,
                         sizeof(f_fattr_t), compare_fattr);
        if (ptr_meta_entry != NULL) {
            read_req[i].fid = ptr_meta_entry->gfid;
        }
    }

    qsort(read_req, count, sizeof(read_req_t), compare_read_req);

    /*coalesce the contiguous read requests*/
    unifycr_coalesce_read_reqs(read_req, count,
                               &tmp_read_req_set, unifycr_key_slice_range,
                               &read_req_set);


    shm_meta_t *tmp_sh_meta = (shm_meta_t *)shm_reqbuf;

    int cmd = COMM_READ;
    memcpy(cmd_buf, &cmd, sizeof(int));
    memcpy(cmd_buf + sizeof(int), &(read_req_set.count), sizeof(int));

    *((int *)shm_recvbuf) = 0;
    *((int *)shm_recvbuf + 1) = 0;

    for (i = 0; i < read_req_set.count; i++) {
        tot_sz += read_req_set.read_reqs[i].length;

        memcpy(tmp_sh_meta++, &read_req_set.read_reqs[i], sizeof(shm_meta_t));
        /*
        tmp_sh_meta->src_fid = read_req_set.read_reqs[i].fid;
        tmp_sh_meta->offset = read_req_set.read_reqs[i].offset;
        tmp_sh_meta->length = read_req_set.read_reqs[i].length;

        memcpy(shm_reqbuf + i * sizeof(shm_meta_t),
               tmp_sh_meta, sizeof(shm_meta_t));
        */
    }
    __real_write(cmd_fd.fd, cmd_buf, sizeof(cmd_buf));

    /*
     * ToDo: Exception handling when some of the requests
     * are missed
     * */
    while (tot_sz > 0) {
        cmd_fd.events = POLLIN | POLLPRI;
        cmd_fd.revents = 0;

        rc = poll(&cmd_fd, 1, -1);
        if (rc == 0) {
            /*time out event*/
            DEBUG("MD/read TMO: poll %d rq:\n", read_req_set.count);
            for (i = 0; i < read_req_set.count; i++) {
                DEBUG("fid %d: %ld(%ld)\n", read_req_set.read_reqs[i].fid,\
                      read_req_set.read_reqs[i].offset, read_req_set.read_reqs[i].length);
            }
        } else if (rc > 0) {
            read_req_t tmp_read_req;
            shm_meta_t *tmp_req;

            if (cmd_fd.revents != 0) {
                if (cmd_fd.revents == POLLIN) {
                    int sh_cursor = 0;
                    ssize_t bytes_read = __real_read(cmd_fd.fd, cmd_buf, sizeof(cmd_buf));
                    if (bytes_read == -1)
                        return -1;

                    ptr_size = (int *)shm_recvbuf;
                    num = *((int *)shm_recvbuf + 1); /*The first int spared out for size*/
                    ptr_num = (int *)((char *)shm_recvbuf + sizeof(int));

                    int j;
                    for (j = 0; j < num; j++) {
                        tmp_req = (shm_meta_t *)(shm_recvbuf
                                                 + 2 * sizeof(int) + sh_cursor);

                        sh_cursor += sizeof(shm_meta_t);
                        *ptr_size -= sizeof(shm_meta_t);

                        tmp_read_req.lid = 0;
                        tmp_read_req.fid = tmp_req->src_fid;
                        tmp_read_req.offset = tmp_req->offset;
                        tmp_read_req.length = tmp_req->length;
                        tmp_read_req.buf = shm_recvbuf + 2 * sizeof(int) + sh_cursor;

                        rc = unifycr_match_received_ack(read_req,
                                                        count, &tmp_read_req);
                        if (rc == 0) {
                            sh_cursor += tmp_req->length;
                            tot_sz -= tmp_req->length;
                            *ptr_size -= tmp_req->length;
                            (*ptr_num)--;
                        } else {
                            rc = -1;
                            return rc;
                        }
                    }
                } else {

                }
            }

        } else {

        }
    }

    return rc;
}

ssize_t UNIFYCR_WRAP(pread)(int fd, void *buf, size_t count, off_t offset)
{
    /* equivalent to read(), except that it shall read from a given
     * position in the file without changing the file pointer */

    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* get pointer to file descriptor structure */
        unifycr_fd_t *filedesc = unifycr_get_filedesc_from_fd(fd);
        if (filedesc == NULL) {
            /* ERROR: invalid file descriptor */
            errno = EBADF;
            return (ssize_t) (-1);
        }

        size_t retcount;
        if (fs_type == UNIFYCR_LOG || fs_type == FAMFS) {
            read_req_t tmp_req;
            tmp_req.buf = buf;
            tmp_req.fid = fd + unifycr_fd_limit;
            tmp_req.length = count;
            tmp_req.offset = offset;
            tmp_req.lid = unifycr_get_meta_from_fid(fd)->loid;
            int read_rc =  fd_iface->fd_logreadlist(&tmp_req, 1);

            if (read_rc == 0) {
                return count;
            } else {
                return 0;
            }
        } else {
            int read_rc = unifycr_fd_read(fd, offset, buf, count, &retcount);
            if (read_rc != UNIFYCR_SUCCESS) {
                errno = unifycr_err_map_to_errno(read_rc);
                return (ssize_t) (-1);
            }
        }
        /* return number of bytes read */
        return (ssize_t) retcount;
    } else {
        MAP_OR_FAIL(pread);
        ssize_t ret = UNIFYCR_REAL(pread)(fd, buf, count, offset);
        return ret;
    }
}

ssize_t UNIFYCR_WRAP(pread64)(int fd, void *buf, size_t count, off64_t offset)
{
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* ERROR: fn not yet supported */
        fprintf(stderr, "Function not yet supported @ %s:%d\n", __FILE__, __LINE__);
        errno = EBADF;
        return -1;
    } else {
        MAP_OR_FAIL(pread64);
        ssize_t ret = UNIFYCR_REAL(pread64)(fd, buf, count, offset);
        return ret;
    }
}

ssize_t UNIFYCR_WRAP(pwrite)(int fd, const void *buf, size_t count,
                             off_t offset)
{
    /* equivalent to write(), except that it writes into a given
     * position without changing the file pointer */
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* get pointer to file descriptor structure */
        unifycr_fd_t *filedesc = unifycr_get_filedesc_from_fd(fd);
        if (filedesc == NULL) {
            /* ERROR: invalid file descriptor */
            errno = EBADF;
            return (ssize_t) (-1);
        }

        /* write data to file */
        int write_rc = unifycr_fd_write(fd, offset, buf, count);
        if (write_rc != UNIFYCR_SUCCESS) {
            errno = unifycr_err_map_to_errno(write_rc);
            return (ssize_t) (-1);
        }

        /* return number of bytes read */
        return (ssize_t) count;
    } else {
        MAP_OR_FAIL(pwrite);
        ssize_t ret = UNIFYCR_REAL(pwrite)(fd, buf, count, offset);
        return ret;
    }
}

ssize_t UNIFYCR_WRAP(pwrite64)(int fd, const void *buf, size_t count,
                               off64_t offset)
{
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* ERROR: fn not yet supported */
        return -1;
    } else {
        MAP_OR_FAIL(pwrite64);
        ssize_t ret = UNIFYCR_REAL(pwrite64)(fd, buf, count, offset);
        return ret;
    }
}

int UNIFYCR_WRAP(ftruncate)(int fd, off_t length)
{
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* get the file id for this file descriptor */
        int fid = unifycr_get_fid_from_fd(fd);
        if (fid < 0) {
            /* ERROR: invalid file descriptor */
            errno = EBADF;
            return -1;
        }

        /* check that file descriptor is open for write */
        unifycr_fd_t *filedesc = unifycr_get_filedesc_from_fd(fd);
        if (! filedesc->write) {
            errno = EBADF;
            return -1;
        }

        /* truncate the file */
        int rc = fd_iface->fid_truncate(fid, length);
        if (rc != UNIFYCR_SUCCESS) {
            errno = EIO;
            return -1;
        }

        return 0;
    } else {
        MAP_OR_FAIL(ftruncate);
        int ret = UNIFYCR_REAL(ftruncate)(fd, length);
        return ret;
    }
}

int unifycr_fsync(int fd __attribute__((unused)))
{
    if (!*unifycr_indices.ptr_num_entries)
        return 0;

    STATS_START(start);

    if (unifycr_use_spillover)
        if (__real_fsync(unifycr_spilloverblock))
            return -1; /* EIO */

    if (fs_type == UNIFYCR_LOG) {
        /*put indices to key-value store*/
        int cmd = COMM_META;
        memcpy(cmd_buf, &cmd, sizeof(int));
        int flag = 3;
        memcpy(cmd_buf + sizeof(int), &flag, sizeof(int));
        int res = __real_write(client_sockfd, cmd_buf, sizeof(cmd_buf));

        if (res != 0) {
            int rc;
            cmd_fd.events = POLLIN | POLLPRI;
            cmd_fd.revents = 0;
             rc = poll(&cmd_fd, 1, -1);
            if (rc == 0) {
                /*time out event*/
            } else if (rc > 0) {
                if (cmd_fd.revents != 0) {
                    if (cmd_fd.revents == POLLIN) {
                        int bytes_read = 0;
                        bytes_read = __real_read(client_sockfd,
                                                 cmd_buf, sizeof(cmd_buf));
                        if (bytes_read == 0) {
                            return -1;
                        } else {
                            /**/
                            if (*((int *)cmd_buf) != COMM_META ||
                                *((int *)cmd_buf + 1) != ACK_SUCCESS) {
                                return -1;
                            } else {

                            }
                        }
                    } else {
                        return -1;
                    }
                }

            } else {
                return -1;
            }
        }
        UPDATE_STATS(md_fp_stat, *unifycr_indices.ptr_num_entries, *unifycr_indices.ptr_num_entries*sizeof(md_index_t), start);
        *unifycr_indices.ptr_num_entries = 0;
        //*unifycr_fattrs.ptr_num_entries = 0;

        /* TODO: if using spill over we may have some fsyncing to do */
    }
    return 0;
}

int UNIFYCR_WRAP(fsync)(int fd)
{
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* get the file id for this file descriptor */
        int fid = unifycr_get_fid_from_fd(fd);
        if (fid < 0) {
            errno = EBADF;
            return -1;
        }

        /* transfer ("flush") all modified in-core data to backend device */
        return fd_iface->fd_fsync(fd);

    } else {
        MAP_OR_FAIL(fsync);
        int ret = UNIFYCR_REAL(fsync)(fd);
        return ret;
    }
}

int UNIFYCR_WRAP(fdatasync)(int fd)
{
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* ERROR: fn not yet supported */
        fprintf(stderr, "Function not yet supported @ %s:%d\n", __FILE__, __LINE__);
        errno = EBADF;
        return -1;
    } else {
        MAP_OR_FAIL(fdatasync);
        int ret = UNIFYCR_REAL(fdatasync)(fd);
        return ret;
    }
}

int UNIFYCR_WRAP(flock)(int fd, int operation)
{
    int ret;

    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        // KMM I removed the locking code because it was causing
        // hangs
        /*
          -- currently handling the blocking variants only
          switch (operation)
          {
              case LOCK_EX:
                  DEBUG("locking file %d..\n", fid);
                  ret = pthread_spin_lock(&meta->fspinlock);
                  if ( ret ) {
                      perror("pthread_spin_lock() failed");
                      return -1;
                  }
                  meta->flock_status = EX_LOCKED;
                  break;
              case LOCK_SH:
                  -- not needed for CR; will not be supported,
                  --  update flock_status anyway
                  meta->flock_status = SH_LOCKED;
                  break;
              case LOCK_UN:
                  ret = pthread_spin_unlock(&meta->fspinlock);
                  DEBUG("unlocking file %d..\n", fid);
                  meta->flock_status = UNLOCKED;
                  break;
              default:
                  errno = EINVAL;
                  return -1;
          }
         */

        return 0;
    } else {
        MAP_OR_FAIL(flock);
        ret = UNIFYCR_REAL(flock)(fd, operation);
        return ret;
    }
}

/* TODO: handle different flags */
void *UNIFYCR_WRAP(mmap)(void *addr, size_t length, int prot, int flags,
                         int fd, off_t offset)
{
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* get the file id for this file descriptor */
        int fid = unifycr_get_fid_from_fd(fd);
        if (fid < 0) {
            errno = EBADF;
            return MAP_FAILED;
        }

        /* TODO: handle addr properly based on flags */

        /* allocate memory required to mmap the data if addr is NULL;
         * using posix_memalign instead of malloc to align mmap'ed area
         * to page size */
        if (! addr) {
            int ret = posix_memalign(&addr, sysconf(_SC_PAGE_SIZE), length);
            if (ret) {
                /* posix_memalign does not set errno */
                if (ret == EINVAL) {
                    errno = EINVAL;
                    return MAP_FAILED;
                }

                if (ret == ENOMEM) {
                    errno = ENOMEM;
                    return MAP_FAILED;
                }
            }
        }

        if (fs_type == FAMFS) {
            fprintf(stderr, "Function not yet supported @ %s:%d\n", __FILE__, __LINE__);
            errno = ENOSYS;
            return MAP_FAILED;
        }

        /* TODO: do we need to extend file if offset+length goes past current end? */

        /* check that we don't copy past the end of the file */
        off_t last_byte = offset + length;
        off_t file_size = fd_iface->fid_size(fid);
        if (last_byte > file_size) {
            /* trying to copy past the end of the file, so
             * adjust the total amount to be copied */
            length = (size_t)(file_size - offset);
        }

        /* read data from file */
        int rc = unifycr_fid_read(fid, offset, addr, length);
        if (rc != UNIFYCR_SUCCESS) {
            /* TODO: need to free memory in this case? */
            errno = ENOMEM;
            return MAP_FAILED;
        }

        return addr;
    } else {
        MAP_OR_FAIL(mmap);
        void *ret = UNIFYCR_REAL(mmap)(addr, length, prot, flags, fd, offset);
        return ret;
    }
}

int UNIFYCR_WRAP(munmap)(void *addr, size_t length)
{
    MAP_OR_FAIL(munmap)
    return UNIFYCR_REAL(munmap)(addr, length);
    fprintf(stderr, "Function not yet supported @ %s:%d\n", __FILE__, __LINE__);
    errno = ENOSYS;
    return ENODEV;
}

int UNIFYCR_WRAP(msync)(void *addr __attribute__((unused)),
    size_t length __attribute__((unused)),
    int flags __attribute__((unused)))
{
    /* TODO: need to keep track of all the mmaps that are linked to
     * a given file before this function can be implemented*/
    fprintf(stderr, "Function not yet supported @ %s:%d\n", __FILE__, __LINE__);
    errno = ENOSYS;
    return ENOMEM;
}

void *UNIFYCR_WRAP(mmap64)(void *addr, size_t length, int prot, int flags,
                           int fd, off64_t offset)
{
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* ERROR: fn not yet supported */
        fprintf(stderr, "Function not yet supported @ %s:%d\n", __FILE__, __LINE__);
        errno = ENOSYS;
        return MAP_FAILED;
    } else {
        MAP_OR_FAIL(mmap64);
        void *ret = UNIFYCR_REAL(mmap64)(addr, length, prot, flags, fd, offset);
        return ret;
    }
}

int UNIFYCR_WRAP(__fxstat)(int vers, int fd, struct stat *buf)
{
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        /* ERROR: fn not yet supported */
        fprintf(stderr, "Function not yet supported @ %s:%d\n", __FILE__, __LINE__);
        errno = EBADF;
        return -1;
    } else {
        MAP_OR_FAIL(__fxstat);
        int ret = UNIFYCR_REAL(__fxstat)(vers, fd, buf);
        return ret;
    }
}

int UNIFYCR_WRAP(close)(int fd)
{
    /* check whether we should intercept this file descriptor */
    if (unifycr_intercept_fd(&fd)) {
        int rc;

        DEBUG("closing fd %d\n", fd);

        /* TODO: what to do if underlying file has been deleted? */

        /* check that fd is actually in use */
        int fid = unifycr_get_fid_from_fd(fd);
        if (fid < 0) {
            errno = EBADF;
            return -1;
        }

        /* transfer ("flush") all modified in-core data to backend device */

        rc = fd_iface->fd_fsync(fd);
        if (rc) {
            DEBUG("ERROR %d syncing fd:%d - %m", rc, fd);
            errno = EIO;
            return -1;
        }

        /* close the file id */
        int close_rc = fd_iface->fid_close(fid);
        if (close_rc != UNIFYCR_SUCCESS) {
            errno = EIO;
            return -1;
        }

        /* reinitialize file descriptor to indicate that
         * it is no longer associated with a file,
         * not technically needed but may help catch bugs */
        unifycr_fd_init(fd);

        DUMP_STATS(LF_RD_STATS_FN, lf_rd_stat);
        DUMP_STATS(LF_WR_STATS_FN, lf_wr_stat);
        DUMP_STATS(FD_SYN_STATS_FN, fd_syn_stat);
        DUMP_STATS(FD_EXT_STATS_FN, fd_ext_stat);
        DUMP_STATS(FD_WR_STATS_FN, fd_wr_stat);
        DUMP_STATS(WR_MAP_STATS_FN, wr_map_stat);
        DUMP_STATS(WR_UPD_STATS_FN, wr_upd_stat);
        DUMP_STATS(WR_CMT_STATS_FN, wr_cmt_stat);
        DUMP_STATS(MD_LG_STATS_FN, md_lg_stat);
        DUMP_STATS(MD_FP_STATS_FN, md_fp_stat);
        DUMP_STATS(MD_FG_STATS_FN, md_fg_stat);
        DUMP_STATS(MD_AP_STATS_FN, md_ap_stat);
        DUMP_STATS(MD_AG_STATS_FN, md_ag_stat);
        DUMP_STATS(TEST1_STATS_FN, test1_stat);

        /* TODO: free file descriptor */

        return rc;
    } else {
        MAP_OR_FAIL(close);
        int ret = UNIFYCR_REAL(close)(fd);
        return ret;
    }
}
