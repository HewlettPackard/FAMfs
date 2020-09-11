/*
 * Copyright (c) 2020, HPE
 *
 * Written by: Dmitry Ivanov
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


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <search.h>
#include <pthread.h>

#include "unifycr-runtime-config.h"
#include "unifycr-internal.h"
#include "unifycr-fixed.h"
#include "unifycr-stack.h"
#include "unifycr-sysio.h"
#include "unifycr.h" /* fs_type_t */

#include "famfs.h"
#include "famfs_env.h"
#include "famfs_error.h"
#include "famfs_global.h"
#include "famfs_stats.h"
#include "fam_stripe.h"
#include "lf_client.h"
#include "famfs_rbq.h"
#include "famfs_bitmap.h"
#include "famfs_maps.h" /* DEBUG_LVL macro */
#include "f_map.h"
#include "f_pool.h"
#include "f_layout.h"
#include "f_helper.h"
#include "famfs_rbq.h"


/*
 * unifycr variable:
 * */
extern long unifycr_spillover_max_chunks;
extern void *unifycr_superblock;
extern unifycr_cfg_t client_cfg;
extern int local_rank_cnt;
extern unifycr_filename_t *unifycr_filelist;
extern unsigned long unifycr_max_index_entries;
extern unsigned int unifycr_max_fattr_entries;
extern char external_data_dir[1024];
extern char external_meta_dir[1024];
extern int app_id;


/* FAM */
LFS_CTX_t *lfs_ctx = NULL;
f_rbq_t *adminq;
f_rbq_t *rplyq;
f_rbq_t *lo_cq[F_CMDQ_MAX];

/* TODO: Remove me! */
static int allow_merge = 0; /* disabled until we come up with liniaresation algo */

static int f_stripe_write(int fid, long pos, unifycr_filemeta_t *meta,
    const void *buf, size_t count, F_LAYOUT_t *lo);

//
// ===========================================
//

static int layout_of_path(const char *path, char *ln){
    char lo_name[FVAR_MONIKER_MAX];
    F_LAYOUT_t *lo;
    int id;

    bzero(lo_name, sizeof(lo_name));
    const char *fpath = strstr(path, "::");
    if (fpath) {
        strncpy(lo_name, path, min(fpath - path, FVAR_MONIKER_MAX));
        if (!(lo = f_get_layout_by_name(lo_name)))
            return -1;
        id = lo->info.conf_id;
    } else {
        lo = f_get_layout(0);
        id = 0;
    }
    if (ln)
        strcpy(ln, lo->info.name);
    return id;
}

/* sets flag if the path is a special path */
const char *famfs_intercept_path(const char *path)
{
    /* if the path starts with our mount point, intercept it */
    const char *fpath = strstr(path, "::");
    if (fpath) {
        char lo_name[FVAR_MONIKER_MAX+1];
        size_t len = (size_t)(fpath - path);
        strncpy(lo_name, path, FVAR_MONIKER_MAX);
        if (len > FVAR_MONIKER_MAX)
            len = FVAR_MONIKER_MAX;
        lo_name[len] = '\0';
        F_LAYOUT_t *lo = f_get_layout_by_name(lo_name);
        if (!lo) {
            DEBUG("layout not found '%s'", lo_name);
            return NULL;
        }
        fpath += 2;
    } else {
        fpath = path;
    }
    return fpath;
}

/* ---------------------------------------
 * Operations on FAM storage
 * --------------------------------------- */

/* total, free data in FS */
int famfs_report_storage(int fid, size_t *total, size_t *free)
{
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    if (!meta)
        return UNIFYCR_FAILURE;
    F_LAYOUT_t *lo = f_get_layout(meta->loid);
    if (lo == NULL)
        return UNIFYCR_FAILURE;

    size_t stripe_sz = lo->info.stripe_sz; /* one stripe data size */
    /* TODO: Have Helper to scan SM&CV */
    *total = unifycr_spillover_max_chunks * stripe_sz; /* *glb_size */
    /* TODO; Gather spillover free blocks globally */
    *free = (unifycr_spillover_max_chunks - meta->ttl_stripes) * stripe_sz;
    return UNIFYCR_SUCCESS;
}

/* ---------------------------------------
 * Operations on write stripe cache
 * --------------------------------------- */

/* allocate a new stripe for the specified file and logical stripe id */
static int famfs_stripe_alloc(F_LAYOUT_t *lo, unifycr_filemeta_t *meta, int id)
{
    f_stripe_t s;
    int rc;

    /* get pointer to chunk meta data */
    unifycr_chunkmeta_t *stripe = &(meta->chunk_meta[id]);

    /* allocate a chunk and record its location */
    if ((rc = f_ah_get_stripe(lo, &s))) {
        if (rc == -ENOSPC) {
            DEBUG("layout (%d) out of space", meta->loid);
            return UNIFYCR_ERR_NOSPC;
        }
        DEBUG("layout (%d) getting stripe error:%d", meta->loid, rc);
        return UNIFYCR_FAILURE;
    }
    meta->ttl_stripes++;
    DEBUG_LVL(6, "layout %s (%d) get stripe %lu",
                 lo->info.name, meta->loid, s);

    /* got one from spill over */
    stripe->id = s;
    stripe->flags = 0;
    stripe->f.in_use = 1;
    stripe->data_w = 0;

    return UNIFYCR_SUCCESS;
}

/* drop stripe from write stripe cache */
static int famfs_stripe_free(int fid, unifycr_filemeta_t *meta, int id,
    F_LAYOUT_t *lo)
{
    int rc;

    /* get pointer to chunk meta data */
    unifycr_chunkmeta_t *stripe = &(meta->chunk_meta[id]);

    /* get physical id of chunk */
    f_stripe_t s = stripe->id;
    DEBUG_LVL(7, "free stripe %ld (logical id %d) fl:%x", s, id, stripe->flags);

    /* release stripe; check uncommited stripe */

    if (!stripe->f.in_use) {
        ERROR("free unallocated stripe %lu in layout %s",
              s, lo->info.name);
        ASSERT(0);
    }

    if (!stripe->f.committed) {
        if ((rc = f_ah_release_stripe(lo, s))) {
            ERROR("failed to release stripe %lu in layout %s, error:%d",
                  s, lo->info.name, rc);
            return UNIFYCR_FAILURE;
        }
        meta->ttl_stripes--;

        DEBUG_LVL(6, "fid:%d lid:%d - stripe %lu released",
                  fid, meta->loid, s);
    }
    stripe->flags = 0;
    stripe->data_w = 0;

    return UNIFYCR_SUCCESS;
}

static int trim_stripe_cache(int fid, F_LAYOUT_t *lo, unifycr_filemeta_t *meta, unsigned int n)
{
    int rc = 0;
    while (meta->stripes > n) {
        meta->stripes--;
        if ((rc = famfs_stripe_free(fid, meta, meta->stripes, lo)))
            break;
    }
    return rc;
}

static int invalidate_stripe_cache(int fid, F_LAYOUT_t *lo, unifycr_filemeta_t *meta) {
    int rc;
    if ((rc = trim_stripe_cache(fid, lo, meta, 0)))
        return rc;
    ASSERT( meta->stripes == 0 );
    meta->stripe_idx = 0;
    return 0;
}

/* ---------------------------------------
 * File creation
 * --------------------------------------- */

/* add a new file and initialize metadata
 * returns the new fid, or negative value on error */
int famfs_fid_create_file(const char *path, const char *fpath, int loid)
{
    if (loid < 0) {
        loid = layout_of_path(path, 0);
        if (loid < 0) {
            ERROR("layout doesn't exist: %s", path);
            errno = ENOENT;
            return -1;
        }
    }

    int fid = unifycr_fid_alloc();
    if (fid < 0)  {
        /* TODO: Return unifycr_max_files error: ENFILE */
        errno = ENOSPC;
        return fid;
    }

    /* mark this slot as in use and copy the filename */
    unifycr_filelist[fid].in_use = 1;
    /* TODO: check path length to see if it is < 128 bytes
     * and return appropriate error if it is greater
     */
    strcpy((void *)&unifycr_filelist[fid].filename, fpath);

    /* add fid to the layout's array of open file IDs */
    F_LAYOUT_t *lo = f_get_layout(loid);
    set_bit(fid%BITS_PER_LONG, f_map_new_p(lo->file_ids, fid));

    DEBUG("Filename %s got famfs fd %d in layout %s",
          unifycr_filelist[fid].filename, fid, lo->info.name);

    /* initialize meta data */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    meta->size    = 0;
    meta->is_dir  = 0;
    meta->real_size = 0;
    meta->storage = FILE_STORAGE_NULL;
    meta->flock_status = UNLOCKED;
    meta->loid = loid;
    meta->stripes  = 0;
    meta->ttl_stripes  = 0; /* TODO: Make it persistent file attr */
    meta->stripe_idx  = 0;
    /* PTHREAD_PROCESS_SHARED allows Process-Shared Synchronization*/
    pthread_spin_init(&meta->fspinlock, PTHREAD_PROCESS_SHARED);

    return fid;
}

/*
 * send global file metadata to the delegator,
 * which puts it to the key-value store
 * @param gfid: global file id
 * @return: error code
 * */
static int f_create_file_global(f_fattr_t *f_meta)
{
    int rc;

    STATS_START(start);

    f_svcrply_t r;
    f_svcrq_t c = {
        .opcode = CMD_META,
        .cid = local_rank_idx,
        .md_type = MDRQ_SETFA,
        .fm_data = *f_meta
    };

    f_rbq_t *cq = lo_cq[f_meta->loid];
    ASSERT(cq);

    if ((rc = f_rbq_push(cq, &c, 10*RBQ_TMO_1S))) {
        ERROR("can't push 'create file' command onto layout %d queue: %s", f_meta->loid, strerror(-rc));
        return rc;
    }

    if ((rc = f_rbq_pop(rplyq, &r, 30*RBQ_TMO_1S))) {
        ERROR("couldn't get response for 'create file' from layout %d queue: %s", f_meta->loid, strerror(-rc));
        return rc;
    }

    UPDATE_STATS(md_ap_stat, 1, 1, start);

    return r.rc;
}

/*
 * get global file metadata from the delegator,
 * which retrieves the data from key-value store
 * @param gfid: global file id
 * @return: error code
 * @return: file_meta that point to the structure of
 * the retrieved metadata
 * */
static int f_find_file_global(int gfid, int loid, f_fattr_t **file_meta) {
    int rc;

    STATS_START(start);

    f_svcrply_t r;
    f_svcrq_t c = {
        .opcode = CMD_META,
        .cid = local_rank_idx,
        .md_type = MDRQ_GETFA,
        .fm_gfid = gfid};

    f_rbq_t *cq = lo_cq[loid];
    ASSERT(cq);

    if ((rc = f_rbq_push(cq, &c, 10*RBQ_TMO_1S))) {
        ERROR("can't push 'find file' command onto layout %d queue: %s", loid, strerror(-rc));
        return rc;
    }

    if ((rc = f_rbq_pop(rplyq, &r, 30000*RBQ_TMO_1S))) {
        ERROR("couldn't get response for 'find file' from layout %d queue: %s", loid, strerror(-rc));
        return rc;
    }
    if (r.rc) {
        DEBUG("layout %d global file id %d not found in DB - error:%d", loid, gfid, r.rc);
        *file_meta = NULL;
        return ENOENT;
    }

    *file_meta = (f_fattr_t *)malloc(sizeof(f_fattr_t));
    **file_meta = r.fattr;

    UPDATE_STATS(md_ag_stat, 1, 1, start);

    return 0;
}

int get_global_fam_meta(int fam_id, fam_attr_val_t **fam_meta)
{
    int rc;
    f_svcrq_t c = {
        .opcode = CMD_META,
        .cid = local_rank_idx,
        .md_type = MDRQ_FAMAT,
        .fam_id = fam_id
    };
    f_svcrply_t r;

    STATS_START(start);

    if ((rc = f_rbq_push(adminq, &c, RBQ_TMO_1S*10))) {
        ERROR("couldn't push fam attr get admin q: %s (%d)\n", strerror(-rc), rc);
        return rc;
    }
    *fam_meta = NULL;

    int n = 0, j = 0;
    do {
        if ((rc = f_rbq_pop(rplyq, &r, RBQ_TMO_1S*30))) {
            if (*fam_meta)
                free(*fam_meta);
            ERROR("error getting FAM %d attr: %s (%d)", fam_id, strerror(-rc), rc);
            return rc;
        }

        if (!*fam_meta) {
            n = r.cnt + r.more;
            *fam_meta = (fam_attr_val_t *)malloc(fam_attr_val_sz(n));
            (*fam_meta)->part_cnt = n;
        }

        for (int i = 0; i < r.cnt; i++)
            (*fam_meta)->part_attr[j++]  = r.prt_atr[i];

    } while (j < n);

    UPDATE_STATS(md_ag_stat, 1, j, start);

    return UNIFYCR_SUCCESS;
}

static inline off_t get_stripe_offset_wr(unifycr_filemeta_t *meta)
{
    ASSERT( meta->stripe_idx < meta->stripes );
    uint64_t stripe_id = meta->stripe_idx; /* logical stripe id to write to */
    unifycr_chunkmeta_t *stripe = &(meta->chunk_meta[stripe_id]);
    return stripe->data_w;
}

static inline off_t get_stripe_wr_cache_size(unifycr_filemeta_t *meta, size_t stripe_sz)
{
    off_t maxsize = 0;
    if (meta->stripes > meta->stripe_idx) {
        maxsize = (meta->stripes - meta->stripe_idx)*stripe_sz;
        maxsize -= meta->chunk_meta[meta->stripe_idx].data_w;
    }
    return maxsize;
}

/* ---------------------------------------
 * Operations on file ids
 * --------------------------------------- */

/* return current size of given file id */
static off_t famfs_fid_size(int fid)
{
    /* get meta data for this file */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    return meta->real_size;
}

/* increase size of file if length is greater than current size,
 * and allocate additional chunks as needed to reserve space for
 * file growing upto length bytes */
static int famfs_fid_extend(int fid, off_t length)
{
#if FAMFS_STATS
    int st_str = 0;

    STATS_START(start);
#endif

    /* get meta data for this file */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    ASSERT( meta );
    ASSERT( meta->storage == FILE_STORAGE_LOGIO );
    if (length <= meta->real_size) /* <= famfs_fid_size ? */
        return UNIFYCR_SUCCESS;

    F_LAYOUT_t *lo = f_get_layout(meta->loid);
    if (lo == NULL) {
        DEBUG("fid:%d error: layout id:%d not found!",
              fid, meta->loid);
        return UNIFYCR_ERR_IO;
    }
    size_t stripe_sz = lo->info.stripe_sz;

    DEBUG_LVL(5, "fid %d lid %d extend from %jd to %jd",
              fid, meta->loid, meta->real_size, length);

    /* determine whether we need to allocate more stripes */
    off_t maxsize = get_stripe_wr_cache_size(meta, stripe_sz);
    length -= meta->real_size; /* subtract famfs_fid_size */
    if (length > maxsize) {
        /* compute number of additional bytes we need */
        off_t additional = length - maxsize;
        while (additional > 0) {
            /* TODO: Remove me! */
            /* check that we don't overrun max number of chunks for file */
            if (meta->stripes == unifycr_max_chunks + unifycr_spillover_max_chunks) {
                return UNIFYCR_ERR_NOSPC;
            }
            /* allocate a new stripe */
            int rc = famfs_stripe_alloc(lo, meta, meta->stripes);
            if (rc != UNIFYCR_SUCCESS) {
                DEBUG("failed to allocate chunk");
                return UNIFYCR_ERR_NOSPC;
            }

            /* increase chunk count and subtract bytes from the number we need */
            meta->stripes++;
            additional -= stripe_sz;
#if FAMFS_STATS
            st_str++;
#endif
        }
        DEBUG_LVL(6, "fid %d lid %d extended from %ld to %ld",
                  fid, meta->loid, maxsize, get_stripe_wr_cache_size(meta, stripe_sz));

        UPDATE_STATS(fd_ext_stat, 1, st_str, start);
    }

    return UNIFYCR_SUCCESS;
}

/* if length is less than reserved space, give back space down to length */
static int famfs_fid_shrink(int fid, off_t length)
{
    /* get meta data for this file */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    ASSERT( meta );
    ASSERT( meta->storage == FILE_STORAGE_LOGIO );
    F_LAYOUT_t *lo = f_get_layout(meta->loid);
    if (lo == NULL) {
        DEBUG("fid:%d error: layout id:%d not found!",
              fid, meta->loid);
        return UNIFYCR_ERR_IO;
    }

    DEBUG_LVL(5, "fid %d lid %d shrink to %jd",
              fid, meta->loid, length);

    /* determine the number of chunks to leave after truncating */
    off_t num_chunks = 0;
    size_t stripe_sz = lo->info.stripe_sz;
    if (length > 0) {
        num_chunks = DIV_CEIL(length, stripe_sz);
    }

    return trim_stripe_cache(fid, lo, meta, num_chunks);
}

/* truncate file id to given length, frees resources if length is
 * less than size and allocates and zero-fills new bytes if length
 * is more than size */
static int famfs_fid_truncate(int fid, off_t length)
{
    /* get meta data for this file */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);

    /* get current size of file */
    off_t size = meta->real_size; /* famfs_fid_size */

    /* drop data if length is less than current size,
     * allocate new space and zero fill it if bigger */
    if (length < size) {
        /* determine the number of chunks to leave after truncating */
        int shrink_rc = famfs_fid_shrink(fid, length);
        if (shrink_rc != UNIFYCR_SUCCESS) {
            return shrink_rc;
        }
    } else if (length > size) {
        /* file size has been extended, allocate space */
        int extend_rc = famfs_fid_extend(fid, length);
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
    meta->real_size = length;

    return UNIFYCR_SUCCESS;
}

/* write count bytes from buf into file starting at offset pos,
 * all bytes are assumed to be allocated to file, so file should
 * be extended before calling this routine */
static int famfs_fid_write(int fid, off_t pos, const void *buf, size_t count)
{
    int rc;

    /* short-circuit a 0-byte write */
    if (count == 0) {
        return UNIFYCR_SUCCESS;
    }

    /* get meta for this file id */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    ASSERT( meta );
    ASSERT( meta->storage == FILE_STORAGE_LOGIO );
    F_LAYOUT_t *lo = f_get_layout(meta->loid);
    if (lo == NULL) {
        DEBUG("fid:%d error: layout id:%d not found!",
              fid, meta->loid);
        return UNIFYCR_ERR_IO;
    }

    /* TODO: Add memory region cache for libfabric and translate 'buf' to local descriptor */

    /* get position within current stripe */
    off_t stripe_offset = get_stripe_offset_wr(meta);

    /* determine how many bytes remain in the current chunk */
    size_t stripe_sz = lo->info.stripe_sz;
    size_t remaining = stripe_sz - stripe_offset;
    if (count <= remaining) {
        /* all bytes for this write fit within the current chunk */
        rc = f_stripe_write(fid, pos, meta, buf, count, lo);
        if (rc)
            goto _err;

    } else {
        /* otherwise, fill up the remainder of the current chunk */
        char *ptr = (char *) buf;
        rc = f_stripe_write(fid, pos, meta, (void *)ptr, remaining, lo);
        if (rc)
            goto _err;

        ptr += remaining;
        pos += remaining;

        /* then write the rest of the bytes starting from beginning
         * of chunks */
        size_t processed = remaining;
        while (processed < count && rc == UNIFYCR_SUCCESS) {

            /* compute size to write to this chunk */
            size_t num = count - processed;
            if (num > stripe_sz) {
                num = stripe_sz;
            }

            /* write data */
            rc = f_stripe_write(fid, pos, meta, (void *)ptr, num, lo);
            if (rc)
                goto _err;

            ptr += num;
            pos += num;

            /* update number of bytes processed */
            processed += num;
        }
    }

_err:
    if (rc) {
        DEBUG("write error in layout %d, fid:%d pos:%ld len:%zu rem:%zu",
              meta->loid, fid, pos, count, remaining);
        return rc; /* UNIFYCR_FAILURE */
    }
    return UNIFYCR_SUCCESS;
}

/* opens a new file id with specified path, access flags, and permissions,
 * fills outfid with file id and outpos with position for current file pointer,
 * returns UNIFYCR error code */
static int famfs_fid_open(const char *path, int flags,
    mode_t mode __attribute__((unused)),
    int *outfid, off_t *outpos)
{
    int loid;
    char *norm_path, buf[PATH_MAX];
    char lo_name[FVAR_MONIKER_MAX];

    norm_path = normalized_path(path, buf, PATH_MAX);
    if (norm_path == NULL) {
        errno = unifycr_err_map_to_errno(UNIFYCR_ERR_NAMETOOLONG);
        return -1; /* ENAMETOOLONG */
    }
    if (strcmp(path, norm_path))
        DEBUG("normalize path:'%s' to '%s'", path, norm_path);

    /* check that path is short enough */
    size_t pathlen = strlen(norm_path) + 1;
    if (pathlen > UNIFYCR_MAX_FILENAME) {
        errno = unifycr_err_map_to_errno(UNIFYCR_ERR_NAMETOOLONG);
        return -1;
    }
    if ((loid = layout_of_path(path, lo_name)) < 0) {
        ERROR("non-exisitng layout %s secified: %s", lo_name, norm_path);
        errno = unifycr_err_map_to_errno(UNIFYCR_ERR_NOENT);
        return -1;
    }

    /* assume that we'll place the file pointer at the start of the file */
    off_t pos = 0;

    /* check whether this file already exists */
    int fid = unifycr_get_fid_from_norm_path(norm_path);
    DEBUG_LVL(7, "unifycr_get_fid_from_path() gave %d", fid);

    int gfid = -1, rc = 0;
    if (fid < 0) {
        rc = unifycr_get_global_fid(norm_path, &gfid);
        if (rc != UNIFYCR_SUCCESS) {
            DEBUG_LVL(2, "Failed to generate fid for file %s", norm_path);
            errno = unifycr_err_map_to_errno(UNIFYCR_ERR_IO);
            return -1;
        }

        gfid = abs(gfid);

        f_fattr_t *ptr_meta = NULL;
        //rc = get_global_file_meta(gfid, &ptr_meta);
        if (f_find_file_global(gfid, loid, &ptr_meta)) {
            // file not found in global DB
            fid = -1;
        } else if (ptr_meta->loid != loid) {
            // found the file, but in the wrong layout
            ERROR("file %s exists in different layout globally: got %d, expected %d",
                  norm_path, ptr_meta->loid, loid);
            free(ptr_meta);
            errno = unifycr_err_map_to_errno(UNIFYCR_ERR_NOENT);
            return -1;
        } else {
            /* other process has created this file, but its
             * attribute is not cached locally,
             * allocate a file id slot for this existing file */
            fid = famfs_fid_create_file(path, norm_path, loid);
            if (fid < 0) {
                DEBUG("Failed to create new file %s", norm_path);
                errno = unifycr_err_map_to_errno(UNIFYCR_ERR_NFILE);
                return -1;
            }

            /* initialize the storage for the file */

            /* initialize the global metadata
             * */
            unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
            meta->storage = FILE_STORAGE_LOGIO;
            meta->real_size = ptr_meta->file_attr.st_size;
            meta->loid = loid;
            /* cache attributes locally */
            ptr_meta->fid = fid;
            ptr_meta->gfid = gfid;
            ptr_meta->loid = loid;

            ins_file_meta(&unifycr_fattrs, ptr_meta);
            free(ptr_meta);
        }
    }

    if (fid < 0) {
        /* file does not exist */
        /* create file if O_CREAT is set */
        if (flags & O_CREAT) {
            DEBUG("Couldn't find entry for %s in FAMFS", norm_path);
            DEBUG("unifycr_superblock = %p;"
                  "free_chunk_stack = %p; unifycr_filelist = %p;"
                  "chunks = %p", unifycr_superblock,
                  free_chunk_stack, unifycr_filelist, unifycr_chunks);

            /* allocate a file id slot for this new file */
            fid = famfs_fid_create_file(path, norm_path, loid);
            if (fid < 0) {
                DEBUG("Failed to create new file %s", norm_path);
                errno = unifycr_err_map_to_errno(UNIFYCR_ERR_NFILE);
                return -1;
            }

            /* initialize the storage for the file */
            unifycr_get_meta_from_fid(fid)->storage = FILE_STORAGE_LOGIO;

            /*create a file and send its attribute to key-value store*/
            f_fattr_t *new_fmeta = (f_fattr_t *)malloc(sizeof(f_fattr_t));
            strcpy(new_fmeta->filename, norm_path);
            new_fmeta->fid = fid;
            new_fmeta->gfid = gfid;
            new_fmeta->loid = loid;
            if ((rc = f_create_file_global(new_fmeta)))
                return rc;
            ins_file_meta(&unifycr_fattrs, new_fmeta);
            free(new_fmeta);

        } else {
            /* ERROR: trying to open a file that does not exist without O_CREATE */
            DEBUG("Couldn't find entry for %s in FAMFS", norm_path);
            errno = unifycr_err_map_to_errno(UNIFYCR_ERR_NOENT);
            return -1;
        }
    } else {
        /* file already exists */

        /* if O_CREAT and O_EXCL are set, this is an error */
        if ((flags & O_CREAT) && (flags & O_EXCL)) {
            /* ERROR: trying to open a file that exists with O_CREATE and O_EXCL */
            errno = unifycr_err_map_to_errno(UNIFYCR_ERR_EXIST);
            return -1;
        }

        /* if O_DIRECTORY is set and fid is not a directory, error */
        /* if O_DIRECTORY is not set and fid is a directory, error */
        if (!(flags & O_DIRECTORY) != !unifycr_fid_is_dir(fid)) {
            errno = unifycr_err_map_to_errno(UNIFYCR_ERR_NOTDIR);
            return -1;
        }

        /* if O_TRUNC is set with RDWR or WRONLY, need to truncate file */
        if ((flags & O_TRUNC) && (flags & (O_RDWR | O_WRONLY))) {
            famfs_fid_truncate(fid, 0);
        }

        /* if O_APPEND is set, we need to place file pointer at end of file */
        if (flags & O_APPEND) {
            //unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
            //pos = meta->size;
            pos = famfs_fid_size(fid);
        }
    }

    /* TODO: allocate a free file descriptor and associate it with fid */
    /* set in_use flag and file pointer */
    *outfid = fid;
    *outpos = pos;
    DEBUG_LVL(6, "FAMFS_open generated fd %d for file %s", fid, norm_path);

    /* don't conflict with active system fds that range from 0 - (fd_limit) */
    return UNIFYCR_SUCCESS;
}

static int famfs_fid_close(int fid)
{
    int rc;
    unsigned int i;

    /* TODO: clear any held locks */

    /* remove fid from the layout's array of open file IDs */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);

    F_LAYOUT_t *lo = f_get_layout(meta->loid);
    clear_bit(fid%BITS_PER_LONG, f_map_new_p(lo->file_ids, fid));

    /* uncommited stripe? */
    unifycr_chunkmeta_t *stripe = meta->chunk_meta;
    for (i = 0; i < meta->stripes; i++, stripe++) {
	f_stripe_t s = stripe->id;

	if (stripe->f.in_use == 0 || stripe->f.committed == 1)
	    continue;

	if (stripe->data_w == 0) {
	    if ((rc = f_ah_release_stripe(lo, s))) {
		ERROR("fid:%d in layout %s - failed to release stripe %lu on close, error:%d",
		      fid, lo->info.name, s, rc);
		return UNIFYCR_FAILURE;
	    }
	    meta->ttl_stripes--;
	    DEBUG_LVL(6, "fid:%d lid:%d - release stripe %lu on close",
		      fid, meta->loid, s);
	} else {
	    ASSERT( stripe->data_w == lo->info.stripe_sz ); 
	    if ((rc = f_ah_commit_stripe(lo, s))) {
		ERROR("fid:%d in layout %s - failed to commit stripe %lu on close, error:%d",
		      fid, lo->info.name, s, rc);
		return UNIFYCR_FAILURE;
	    }
	}
	stripe->flags = 0;
    }

    if (invalidate_stripe_cache(fid, lo, meta)) {
	ERROR("fid:%d in layout %s - failed to drop %u stripes on close",
	      fid, lo->info.name, meta->stripes);
	return UNIFYCR_FAILURE;
    }
    return UNIFYCR_SUCCESS;
}

#if 0
/* delete a file id and return file its resources to free pools */
int unifycr_fid_unlink(int fid)
{
    /* return data to free pools */
    famfs_fid_truncate(fid, 0);

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
    char *ptr = (char *) superblock;

    /* jump over header (right now just a uint32_t to record
     * magic value of 0xdeadbeef if initialized */
    ptr += sizeof(uint32_t);

    /* stack to manage free file ids */
    free_fid_stack = ptr;
    ptr += unifycr_stack_bytes(unifycr_max_files);

    /* record list of file names */
    unifycr_filelist = (unifycr_filename_t *) ptr;
    ptr += unifycr_max_files * sizeof(unifycr_filename_t);

    /* array of file meta data structures */
    unifycr_filemetas = (unifycr_filemeta_t *) ptr;
    ptr += unifycr_max_files * sizeof(unifycr_filemeta_t);

    /* array of chunk meta data strucutres for each file */
    unifycr_chunkmetas = (unifycr_chunkmeta_t *) ptr;
    ptr += unifycr_max_files * unifycr_max_chunks * sizeof(unifycr_chunkmeta_t);

    if (unifycr_use_spillover) {
        ptr += unifycr_max_files * unifycr_spillover_max_chunks * sizeof(
                   unifycr_chunkmeta_t);
    }
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
        unsigned long long ull_ptr  = (unsigned long long) ptr;
        unsigned long long ull_page = (unsigned long long) unifycr_page_size;
        unsigned long long num_pages = ull_ptr / ull_page;
        if (ull_ptr > num_pages * ull_page) {
            ptr = (char *)((num_pages + 1) * ull_page);
        }

        /* pointer to start of memory data chunks */
        unifycr_chunks = ptr;
        ptr += unifycr_max_chunks * unifycr_chunk_size;
    } else {
        unifycr_chunks = NULL;
    }

    /* pointer to the log-structured metadata structures*/
    if ((fs_type == UNIFYCR_LOG) || (fs_type == FAMFS)) {
        unifycr_indices.ptr_num_entries = (long *)ptr;

        ptr += unifycr_page_size;
        unifycr_indices.index_entry = (md_index_t *)ptr;


        /*data structures  to record the global metadata*/
        ptr += unifycr_max_index_entries * sizeof(md_index_t);
        unifycr_fattrs.ptr_num_entries = (long *)ptr;
        ptr += unifycr_page_size;
        unifycr_fattrs.meta_entry = (f_fattr_t *)ptr;
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

    if (fs_type == UNIFYCR_LOG || fs_type == FAMFS) {
        *(unifycr_indices.ptr_num_entries) = 0;
        *(unifycr_fattrs.ptr_num_entries) = 0;
    }
    DEBUG("Meta-stacks initialized!");

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

    DEBUG("Key for superblock = %x", key);

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
    return scr_shmblock;
}
#endif

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
int famfs_mount(const char prefix[] __attribute__((unused)),
    size_t size __attribute__((unused)),
    int rank)
{
    F_POOL_t *pool;
    int rc;

    ASSERT(fs_type == FAMFS);   // For now
    /* TODO we'll need to get rid of all the other suff eventually */

    if ((rc = f_set_layouts_info(&client_cfg))) {
	printf("failed to get layout info: %d\n", rc);
	return rc;
    }
    pool = f_get_pool();
    ASSERT(pool); /* f_set_layouts_info must fail if no pool */
    ASSERT(rank==dbg_rank);
    pool->dbg_rank = rank; /* use application's rank for the log and error messages */

    /* DEBUG */
    if (pool->verbose && rank == 0) {
	unifycr_config_print(&client_cfg, NULL);
	printf("\n"); f_print_layouts(); printf("\n");
    }


    if ((rc = lfs_connect(&lfs_ctx))) {
    	printf("lf-connect failed on mount: %d\n", rc);
	(void)f_free_layouts_info();
	return rc;
    }

    return 0;
}

static int famfs_client_exit(unifycr_cfg_t *cfg, LFS_CTX_t **lfs_ctx_p)
{
    int rc;

    /* close libfabric devices */
    free_lfc_ctx(lfs_ctx_p);

    /* close the pool */
    rc = f_free_layouts_info();

    /* free configurator structure */
    unifycr_config_free(cfg);

    return rc;
}

/**
* unmount the mounted file system, triggered
* by the root process of an application
* ToDo: add the support for more operations
* beyond terminating the servers. E.g.
* data flush for persistence.
* @return success/error code
*/
int famfs_shutdown() {
    ASSERT(fs_type == FAMFS);

    f_svcrq_t    c = {.opcode = CMD_SHTDWN, .cid = local_rank_idx};

    if (f_rbq_push(adminq, &c, RBQ_TMO_1S)) {
        ERROR("couldn't push UNMOUNT command to svr");
    }
#if 0
    f_rbq_destroy(rplyq);
    f_rbq_close(adminq);
    for (int i = 0; i < pool->info.layouts_count; i++) {
        if (lo_cq[i]) {
            int rc;
            if ((rc = f_rbq_close(lo_cq[i]))) {
                ERROR("error closing queue of %d: %d", i, rc);
            }
        }
    }

    rc = famfs_client_exit(&client_cfg, &lfs_ctx);
#endif
    return 0;
}

int famfs_unmount() {
    ASSERT(fs_type == FAMFS);

    f_svcrq_t    c = {.opcode = CMD_UNMOUNT, .cid = local_rank_idx};
    int rc;

    F_POOL_t *pool;
    pool = f_get_pool();
    if ((rc = f_rbq_push(adminq, &c, RBQ_TMO_1S))) {
        ERROR("couldn't push UNMOUNT command to srv");
	goto _err;
    }
    f_rbq_destroy(rplyq);
    f_rbq_close(adminq);
    for (unsigned int i = 0; i < pool->info.layouts_count; i++) {
        if (lo_cq[i]) {
            if ((rc = f_rbq_close(lo_cq[i]))) {
                ERROR("on closing queue of %u", i);
		goto _err;
            }
        }
    }

    if ((rc = famfs_client_exit(&client_cfg, &lfs_ctx))) {
	ERROR("on closing libfabric");
	goto _err;
    }
    return UNIFYCR_SUCCESS;

_err:
    ERROR("on unmount:%d", rc);
    return UNIFYCR_FAILURE;
}

/**
* transfer the client-side context information
* to the corresponding delegator on the
* server side.
*/
int f_server_sync() {
    ASSERT(fs_type == FAMFS);

    f_svcrq_t    c;
    f_svcrply_t   r;

    int rc = -1;
    int num_procs_per_node = local_rank_cnt;
    int req_buf_sz = shm_req_size;
    int recv_buf_sz = shm_recv_size;
    long superblock_sz = glb_superblock_size;

    long meta_offset =
        (void *)unifycr_indices.ptr_num_entries
        - unifycr_superblock;
    long meta_size = unifycr_max_index_entries
                     * sizeof(md_index_t);

    long fmeta_offset =
        (void *)unifycr_fattrs.ptr_num_entries
        - unifycr_superblock;

    long fmeta_size = unifycr_max_fattr_entries *
                      sizeof(f_fattr_t);

    long data_offset =
        (void *)unifycr_chunks - unifycr_superblock;
    //long data_size = (long)unifycr_max_chunks * unifycr_chunk_size;
    long data_size = 0;

    char external_spill_dir[UNIFYCR_MAX_FILENAME] = {0};
    strcpy(external_spill_dir, external_data_dir);

    /* copy the client-side information to the command
     * buffer, and then send to the delegator. The delegator
     * will attach to the client-side shared memory, and open
     * the spill log file based on these information*/
    c.opcode = CMD_MOUNT | CMD_OPT_FAMFS;
    c.app_id = app_id;
    c.cid = local_rank_idx;
    c.dbg_rnk = dbg_rank;
    c.num_prc = num_procs_per_node;
    c.rqbf_sz = req_buf_sz;
    c.rcbf_sz = recv_buf_sz;
    c.sblk_sz = superblock_sz;
    c.meta_of = meta_offset;
    c.meta_sz = meta_size;
    c.fmet_of = fmeta_offset;
    c.fmet_sz = fmeta_size;
    c.data_of = data_offset;
    c.data_sz = data_size;
    strncpy(c.ext_dir, external_spill_dir, F_MAX_FNM);

    if ((rc = f_rbq_push(adminq, &c, 10*RBQ_TMO_1S))) {
        ERROR("rank couldn't send MOUNT command: %s(%d)", strerror(-rc), rc);
        return -1;
    }

    if ((rc = f_rbq_pop(rplyq, &r, 30*RBQ_TMO_1S))) {
        ERROR("rank couldn't mount FAMfs: %s(%d)", strerror(-rc), rc);
        return -1;
    }

    if (r.rc) {
        ERROR("rank FAMfs mount error: %d", r.rc);
        return -1;
    }
    return 0;
}

/* TODO: Make me static! */
int f_srv_connect()
{
    int         rc;
    char        qname[MAX_RBQ_NAME];
    F_POOL_t    *pool = f_get_pool();
    f_svcrq_t   c = {.opcode = CMD_SVCRQ, .cid = local_rank_idx};
    f_svcrply_t r;

    ASSERT(pool);

    sprintf(qname, "%s-%02d", F_RPLYQ_NAME, local_rank_idx);
    if ((rc = f_rbq_create(qname, sizeof(f_svcrply_t), F_MAX_RPLYQ, &rplyq, 1))) {
        ERROR("failed to create reply queue: %s(%d)", strerror(-rc), rc);
        return rc;
    }

    sprintf(qname, "%s-admin", F_CMDQ_NAME);
    if ((rc = f_rbq_open(qname, &adminq))) {
        ERROR("failed to open admin queue: %s(%d)", strerror(-rc), rc);
        return rc;
    }

    if ((rc = f_rbq_push(adminq, &c, RBQ_TMO_1S))) {
        ERROR("failed to send command: %s(%d)", strerror(-rc), rc);
        return rc;
    }


    if ((rc = f_rbq_pop(rplyq, &r, 10*RBQ_TMO_1S))) {
        ERROR("failed to get reply: %s(%d)", strerror(-rc), rc);
        return rc;
    }
    if (r.ackcode != c.opcode || r.rc != 0) {
        ERROR("bad reply: opcode=%d, rc=%d", r.ackcode, r.rc);
        return -1;
    }
    bzero(lo_cq, sizeof(lo_cq));
    for (unsigned int i = 0; i < pool->info.layouts_count; i++) {
        F_LAYOUT_t *lo = f_get_layout(i);
        if (lo == NULL) {
            ERROR("get layout [%u] info", i);
            return -1;
        }
        sprintf(qname, "%s-%s", F_CMDQ_NAME, lo->info.name);
        if ((rc = f_rbq_open(qname, &lo_cq[i]))) {
            ERROR("can't open LO %s command queue: %s(%d)",
                  lo->info.name, strerror(-rc), rc);
            return -1;
        }
    }

    return 0;
}

#if 0
/*
 * given an index, split it into multiple indices whose range is equal or smaller
 * than slice_range size
 * @param cur_idx: the index to split
 * @param slice_range: the slice size of the key-value store
 * @return index_set: the set of split indices
 * */
int unifycr_split_index(md_index_t *cur_idx, index_set_t *index_set,
                        long slice_range)
{

    long cur_idx_start = cur_idx->file_pos;
    long cur_idx_end = cur_idx->file_pos + cur_idx->length - 1;

    long cur_slice_start = cur_idx->file_pos / slice_range * slice_range;
    long cur_slice_end = cur_slice_start + slice_range - 1;


    index_set->count = 0;

//    long cur_mem_pos = cur_idx->mem_pos;
    if (cur_idx_end <= cur_slice_end) {
        /*
        cur_slice_start                                  cur_slice_end
                         cur_idx_start      cur_idx_end

        */
        index_set->idxes[index_set->count] = *cur_idx;
        index_set->count++;

    } else {
        /*
        cur_slice_start                     cur_slice_endnext_slice_start                   next_slice_end
                         cur_idx_start                                      cur_idx_end

        */
        index_set->idxes[index_set->count] = *cur_idx;
        index_set->idxes[index_set->count].length =
            cur_slice_end - cur_idx_start + 1;

//        cur_mem_pos += index_set->idxes[index_set->count].length;

        cur_slice_start = cur_slice_end + 1;
        cur_slice_end = cur_slice_start + slice_range - 1;
        index_set->count++;

        while (1) {
            if (cur_idx_end <= cur_slice_end) {
                break;
            }

            index_set->idxes[index_set->count].fid = cur_idx->fid;
            index_set->idxes[index_set->count].file_pos = cur_slice_start;
            index_set->idxes[index_set->count].length = slice_range;
//            index_set->idxes[index_set->count].mem_pos = cur_mem_pos;
            if (fs_type == FAMFS) {
		/*
                index_set->idxes[index_set->count].nid = cur_idx->nid;
                index_set->idxes[index_set->count].cid = cur_idx->cid;
		*/
                index_set->idxes[index_set->count].sid = cur_idx->sid;
            }
//            cur_mem_pos += index_set->idxes[index_set->count].length;

            cur_slice_start = cur_slice_end + 1;
            cur_slice_end = cur_slice_start + slice_range - 1;
            index_set->count++;

        }

        index_set->idxes[index_set->count].fid = cur_idx->fid;
        index_set->idxes[index_set->count].file_pos = cur_slice_start;
        index_set->idxes[index_set->count].length = cur_idx_end - cur_slice_start + 1;
//        index_set->idxes[index_set->count].mem_pos = cur_mem_pos;
        if (fs_type == FAMFS) {
	    /*
            index_set->idxes[index_set->count].nid = cur_idx->nid;
            index_set->idxes[index_set->count].cid = cur_idx->cid;
	    */
            index_set->idxes[index_set->count].sid = cur_idx->sid;
        }

        index_set->count++;
    }

    return 0;
}
#endif

famfs_mr_list_t known_mrs = {0, NULL};

#define FAMFS_MR_AU 8
#define LMR_BASE_KEY 1000000
#define LMR_PID_SHIFT 8

int famfs_buf_reg(char *buf, size_t len, void **rid) {
    F_POOL_t *pool = lfs_ctx->pool;
    LF_INFO_t *lf_info = pool->lf_info;
    F_POOL_DEV_t *pdev;
    unsigned int i;

    ASSERT( fs_type == FAMFS );
    STATS_START(start);

    // if local registration is not enabled, do nothing
    if (!lf_info->mrreg.local)
        return 0;

    if (!known_mrs.cnt) {
        known_mrs.regs = (lf_mreg_t *)calloc(FAMFS_MR_AU, sizeof(lf_mreg_t));
        if (!known_mrs.regs) {
            err("memory alloc failure");
            return -ENOMEM;
        }
        known_mrs.cnt = FAMFS_MR_AU;
        i = 0;
    } else {
        for (i = 0; i < known_mrs.cnt; i++)
            if (!known_mrs.regs[i].buf)
                break;
        if (i == known_mrs.cnt) {
            known_mrs.regs = (lf_mreg_t *)realloc(known_mrs.regs,
                                                  known_mrs.cnt*sizeof(lf_mreg_t));
            if (!known_mrs.regs) {
                err("memory realloc failure");
                return -ENOMEM;
            }
            bzero(&known_mrs.regs[i], sizeof(lf_mreg_t)*FAMFS_MR_AU);
            known_mrs.cnt += FAMFS_MR_AU;
        }
    }
    //unsigned long my_key = LMR_BASE_KEY + par->node_id*10000 + local_rank_idx*100 + i;
    unsigned long my_key = LMR_BASE_KEY + (getpid() << LMR_PID_SHIFT) + i;
    int n = pool->info.dev_count;
    known_mrs.regs[i].mreg = (struct fid_mr **)calloc(n, sizeof(struct fid_mr *));
    known_mrs.regs[i].desc = (void **)calloc(n, sizeof(void *));
    known_mrs.regs[i].buf = buf;
    known_mrs.regs[i].len = len;

    for_each_pool_dev(pool, pdev) {
	/* return -EINVAL if any error */
	ON_FI_ERR_RET(fi_mr_reg(pool->mynode.domain->domain, buf, len, FI_READ | FI_WRITE,
				0, my_key, 0, &known_mrs.regs[i].mreg[_i], NULL),
		      "cln fi_mr_reg key:%lu buf:%p failed", my_key, buf);
        known_mrs.regs[i].desc[_i] = fi_mr_desc(known_mrs.regs[i].mreg[_i]);
    }

    if (rid)
        *rid = (void *)&known_mrs.regs[i];

    UPDATE_STATS(lf_mr_stat, 1, 1, start);
    return 0;
}

int famfs_buf_unreg(void *rid) {
    F_POOL_t *pool = lfs_ctx->pool;
    LF_INFO_t *lf_info = pool->lf_info;
    F_POOL_DEV_t *pdev;

    if (!lf_info->mrreg.local)
        return 0;

    lf_mreg_t *mr = (lf_mreg_t *)rid;
    for_each_pool_dev(pool, pdev)
        ON_FI_ERR_RET(fi_close(&mr->mreg[_i]->fid), "cln fi_close failed");

    free(mr->mreg);
    free(mr->desc);
    mr->buf = 0;
    mr->len = 0;

    return 0;
}

static void *lookup_mreg(const char *buf, size_t len, int nid) {
    F_POOL_t *pool = lfs_ctx->pool;
    LF_INFO_t *lf_info = pool->lf_info;
    unsigned int i;

    if (!lf_info->mrreg.local)
        return NULL;

    for (i = 0; i < known_mrs.cnt; i++)
        if (buf >= known_mrs.regs[i].buf &&
            buf + len <= known_mrs.regs[i].buf + known_mrs.regs[i].len)
            break;

    return i == known_mrs.cnt ? NULL : known_mrs.regs[i].desc[nid];
}

static int lf_write(F_LAYOUT_t *lo, char *buf, size_t len,
    f_stripe_t stripe_phy_id, off_t stripe_offset)
{
    F_POOL_t *pool = lfs_ctx->pool;
    N_STRIPE_t *fam_stripe;
    LF_INFO_t *lf_info = pool->lf_info;
    struct famsim_stats *stats_fi_wr;
    int rc = 0;

    /* new physical stripe? */
    STATS_START(start_m);
    if (!lo->fam_stripe ||
	lo->fam_stripe->stripe_0 + lo->fam_stripe->stripe_in_part != stripe_phy_id)
    {
	/* map to physical stripe */
	if ((rc = f_map_fam_stripe(lo, &lo->fam_stripe, stripe_phy_id, 1))) {
	    DEBUG("%s: stripe %lu in layout %s - mapping error:%d",
		  pool->mynode.hostname, stripe_phy_id, lo->info.name, rc);
	    errno = EIO;
	    return UNIFYCR_FAILURE;
	}
    }
    fam_stripe = lo->fam_stripe;

    /* map data to physical chunks */
    map_fam_chunks(fam_stripe, buf, stripe_offset, len, &lookup_mreg);

    UPDATE_STATS(wr_map_stat, 1, 1, start_m);
    STATS_START(start);

    stats_fi_wr = lfs_ctx->famsim_stats_fi_wr;
    famsim_stats_start(famsim_ctx, stats_fi_wr);

    /* start lf write to chunk(s) */
    if ((rc = chunk_rma_start(fam_stripe, lf_info->opts.use_cq?1:0, 1)))
    {
	DEBUG("%s: stripe %lu in layout %s off/len=%lu/%lu write error:%d",
	      pool->mynode.hostname, stripe_phy_id, lo->info.name,
	      stripe_offset, len, rc);
	errno = EIO;
	return UNIFYCR_FAILURE;
    }

    /* wait for I/O end */
    rc = chunk_rma_wait(fam_stripe, lf_info->opts.use_cq?1:0, 1,
			lf_info->io_timeout_ms);
    if (rc) {
	DEBUG("%s: stripe %lu in layout %s off/len=%lu/%lu write error:%d",
	      pool->mynode.hostname, stripe_phy_id, lo->info.name,
	      stripe_offset, len, rc);
	errno = EIO;
	return UNIFYCR_FAILURE;
    }

    /* stats */
    UPDATE_STATS(lf_wr_stat, 1, len, start);

    if (fam_stripe->extent == 0 && fam_stripe->stripe_in_part == 0)
	famsim_stats_stop(stats_fi_wr, 1);
    else
	famsim_stats_pause(stats_fi_wr);

    return UNIFYCR_SUCCESS;
}

static int lf_read(F_LAYOUT_t *lo, char *buf, size_t len,
    off_t stripe_offset, f_stripe_t s)
{
    F_POOL_t *pool = lfs_ctx->pool;
    N_STRIPE_t *fam_stripe;
    LF_INFO_t *lf_info = pool->lf_info;
    //struct famsim_stats *stats_fi_rd;
    int rc = 0;

    DEBUG_LVL(5, "%s: read %zu bytes @%lu from stripe %lu",
              lfs_ctx->pool->mynode.hostname, len, stripe_offset, s);

    /* new physical stripe? */
    if (!lo->fam_stripe ||
        lo->fam_stripe->stripe_0 + lo->fam_stripe->stripe_in_part != s)
    {
        /* map to physical stripe */
        if ((rc = f_map_fam_stripe(lo, &lo->fam_stripe, s, 1))) {
            DEBUG("%s: stripe %lu in layout %s - read mapping error:%d",
                  pool->mynode.hostname, s, lo->info.name, rc);
            errno = EIO;
            return UNIFYCR_FAILURE;
        }
    }
    fam_stripe = lo->fam_stripe;

    /* map data to physical chunks */
    map_fam_chunks(fam_stripe, buf, stripe_offset, len, &lookup_mreg);

    //stats_fi_rd = lfs_ctx->famsim_stats_fi_rd;
    STATS_START(start);
    //famsim_stats_start(famsim_ctx, stats_fi_rd);

    /* start lf read to chunk(s) */
    if ((rc = chunk_rma_start(fam_stripe, lf_info->opts.use_cq?1:0, 0)))
    {
	DEBUG_LVL(2, "%s: stripe %lu in layout %s off/len=%lu/%lu read error:%d",
		  pool->mynode.hostname, s, lo->info.name, stripe_offset, len, rc);
	errno = EIO;
	return UNIFYCR_FAILURE;
    }

    /* wait for I/O end */
    rc = chunk_rma_wait(fam_stripe, lf_info->opts.use_cq?1:0, 0,
			lf_info->io_timeout_ms);
    if (rc) {
	DEBUG_LVL(2, "%s: stripe %lu in layout %s off/len=%lu/%lu read error:%d",
		  pool->mynode.hostname, s, lo->info.name, stripe_offset, len, rc);
	errno = EIO;
	return UNIFYCR_FAILURE;
    }

    /* stats */
    UPDATE_STATS(lf_rd_stat, 1, len, start);
    /*
    if (fam_stripe->extent == 0 && fam_stripe->stripe_in_part == 0)
        famsim_stats_stop(stats_fi_rd, 1);
    else
        famsim_stats_pause(stats_fi_rd);
    */

    return UNIFYCR_SUCCESS;
}

/* read data from specified chunk id, chunk offset, and count into user buffer,
 * count should fit within chunk starting from specified offset */
static int f_stripe_write(
    int fid,
    long pos,                 /* write offset inside the file */
    unifycr_filemeta_t *meta, /* pointer to file meta data */
    const void *buf,          /* buffer holding data to be written */
    size_t count,             /* number of bytes to write */
    F_LAYOUT_t *lo)           /* layout structure pointer for this fid */
{
    long key_slice_range;
    int i;

    /* get chunk meta data */
    ASSERT( meta->stripe_idx < meta->stripes );
    uint64_t stripe_id = meta->stripe_idx; /* logical stripe id to write to */
    unifycr_chunkmeta_t *stripe = &(meta->chunk_meta[stripe_id]);
    /* logical offset within chunk to write to */
    off_t stripe_offset = get_stripe_offset_wr(meta);
    ASSERT( stripe->f.in_use == 1 ); /* got allocated stripe from Helper */

    key_slice_range = lo->info.stripe_sz;
    f_stripe_t s = stripe->id; /* global stripe number */

    DEBUG_LVL(5, "%s: write %zu bytes @%ld (logical %lu) to stripe %lu @%lu",
              lfs_ctx->pool->mynode.hostname, count, pos, stripe_id, s, stripe_offset);

    int rc = lf_write(lo, (char *)buf, count, s, stripe_offset);
    if (rc) {
        int ret;
        /* Release or commit the stripe because of I/O failure */
        if (stripe->data_w) {
            if ((ret = f_ah_commit_stripe(lo, s)))
                ERROR("fid:%d in layout %s - error %d committing stripe %lu",
                      fid, lo->info.name, ret, s);
        } else {
            if ((ret = f_ah_release_stripe(lo, s)))
                ERROR("fid:%d in layout %s - error %d releasing stripe %lu",
                      fid, lo->info.name, ret, s);
            meta->ttl_stripes--;
        }
        /* Print the real error code */
        ioerr("lf-write failed: %d", rc);
        /* Report ENOSPC or EIO */
        if (rc != UNIFYCR_ERR_NOSPC)
            rc = UNIFYCR_FAILURE;
        return rc;
    }
    stripe->data_w += count;

    /* Commit full stipe */
    if (stripe->data_w >= key_slice_range) {
        ASSERT( stripe->data_w == key_slice_range );
        ASSERT( stripe->f.in_use == 1 );
        ASSERT( stripe->f.committed == 0 );

        STATS_START(start_cmt);

        if ((rc = f_ah_commit_stripe(lo, s))) {
            ERROR("fid:%d in layout %s - failed committing stripe %lu, error:%d",
                  fid, lo->info.name, s, rc);
            return UNIFYCR_FAILURE;
        }
        DEBUG_LVL(6, "fid:%d lid %d commit full stripe %lu",
                  fid, meta->loid, s);
        stripe->f.committed = 1;

        /* get pointer to start of next stripe */
        meta->stripe_idx++;

        UPDATE_STATS(wr_cmt_stat, 1, count, start_cmt);
    }

    /* find the corresponding file attr entry and update attr*/
    STATS_START(start);
    md_index_t cur_idx;
    f_fattr_t tmp_meta_entry;
    tmp_meta_entry.fid = fid;
    f_fattr_t *ptr_meta_entry
        = (f_fattr_t *)bsearch(&tmp_meta_entry,
                                     unifycr_fattrs.meta_entry, *unifycr_fattrs.ptr_num_entries,
                                     sizeof(f_fattr_t), compare_fattr);
    if (ptr_meta_entry !=  NULL) {
        ptr_meta_entry->file_attr.st_size = pos + count;
    }
    cur_idx.fid = ptr_meta_entry->gfid;
    cur_idx.file_pos = pos;
    cur_idx.length = count;
    cur_idx.mem_pos = stripe_offset;
    cur_idx.sid = s;
    cur_idx.loid = meta->loid;

    /*split the write requests larger than key_slice_range into
     * the ones smaller than key_slice_range
     * */
    unifycr_split_index(&cur_idx, &tmp_index_set,
                        key_slice_range);
    i = 0;
    if (*(unifycr_indices.ptr_num_entries) + tmp_index_set.count
        < (long)unifycr_max_index_entries) {
        /*coalesce contiguous indices*/

        if (*unifycr_indices.ptr_num_entries >= 1) {
            md_index_t *ptr_last_idx = &unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries - 1];
            if (ptr_last_idx->loid == tmp_index_set.idxes[0].loid &&
                ptr_last_idx->fid == tmp_index_set.idxes[0].fid &&
                ptr_last_idx->sid == tmp_index_set.idxes[0].sid &&
                ptr_last_idx->file_pos + (ssize_t)ptr_last_idx->length
                == tmp_index_set.idxes[0].file_pos) {
                if (ptr_last_idx->file_pos / key_slice_range
                    == tmp_index_set.idxes[0].file_pos / key_slice_range) {
                    ptr_last_idx->length  += tmp_index_set.idxes[0].length;
                    i++;
                }
            }
        }
        for (; i < tmp_index_set.count; i++) {
            unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries].file_pos =
                tmp_index_set.idxes[i].file_pos;
            unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries].mem_pos =
                tmp_index_set.idxes[i].mem_pos;
            unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries].length =
                tmp_index_set.idxes[i].length;

            unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries].loid
                = tmp_index_set.idxes[i].loid;
            unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries].fid
                = tmp_index_set.idxes[i].fid;
            unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries].sid =
                tmp_index_set.idxes[i].sid;
            (*unifycr_indices.ptr_num_entries)++;
        }

    } else {
        /*Todo:page out existing metadata buffer to disk*/
    }
    UPDATE_STATS(wr_upd_stat, 1, tmp_index_set.count, start);

    return UNIFYCR_SUCCESS;
}

static int cmp_md(const void *ap, const void *bp) {
    md_index_t *mda = (md_index_t *)ap, *mdb = (md_index_t *)bp;

    if (mda->loid > mdb->loid)
        return 1;
    else if (mda->loid < mdb->loid)
        return -1;
    if (mda->fid > mdb->fid)
        return 1;
    else if (mda->fid < mdb->fid)
        return -1;
    if (mda->sid > mdb->sid)
        return 1;
    else if (mda->sid < mdb->sid)
        return -1;
    if (mda->file_pos > mdb->file_pos)
        return 1;
    else if (mda->file_pos < mdb->file_pos)
        return -1;
    return 0;
}

static inline int same_stripe(md_index_t *a,  md_index_t *b) {
    return (a->loid == b->loid && a->fid == b->fid && a->sid == b->sid);
}

void famfs_merge_md() {
    md_index_t *mdp = unifycr_indices.index_entry;
    off_t     *nrp = unifycr_indices.ptr_num_entries;

    if (*nrp <= 1)
        return;

    // first, or MD by file id and offset in it
    off_t i, j = 0, n = *nrp;
    qsort(mdp, n, sizeof(md_index_t), cmp_md);

    // merge sequential requests within same stripe
    for (i = 1; i < n; i++) {
        md_index_t *a = &mdp[j], *b =  &mdp[i];
        if (same_stripe(a, b) &&
            b->file_pos == a->file_pos + (ssize_t)a->length)
        {
            a->length += b->length;
            b->length = 0;
        } else {
            j++;
        }
    }

    // now compress MD to get rid of 0 length records
    for (i = 0, j = 0; i < n; i++) {
        if (mdp[j].length == 0) {
            if (mdp[i].length == 0)
                continue;
            mdp[j] = mdp[i];
        }
        j++;
    }
    if (j < i)
        *nrp = j;
}

static ssize_t match_rq_and_read(F_LAYOUT_t *lo, read_req_t *rq, int rq_cnt,
    int lid, fsmd_kv_t *md, int md_cnt, size_t ttl)
{
    int i, rc;
    for (i = 0; i < rq_cnt; i++) {
        off_t fam_off;
        size_t fam_len;
        off_t rq_b = rq[i].offset;
        off_t rq_e = rq_b + rq[i].length;
        char *bufp;
        int j;

        for (j = 0; j < md_cnt; j++) {
            off_t md_b = md[j].k.offset;
            off_t md_e = md[j].k.offset + md[j].v.len;

	    DEBUG_LVL(7, "match md[%d] K lo=%d fid=%d @%lu V s=%lu len=%lu @%lu,"
			 " rq[%d] fid=%d len=%lu @%lu, ttl:%zu",
		      j, md[j].k.pk.loid, md[j].k.pk.fid, md[j].k.offset,
		      md[j].v.stripe, md[j].v.len, md[j].v.addr,
		      i, rq[i].fid, rq[i].length, rq[i].offset, ttl);

            fam_off = fam_len = 0;
            if (md[j].k.pk.loid != lid || md[j].k.pk.fid != rq[i].fid)
                continue;

            if (rq_b >= md_b && rq_b < md_e) {
                // [MD_b ... (rq_b ... MD_e] ... rq_e)
                // [MD_b ... (rq_b ... rq_e) ... MD_e]
                fam_off = md[j].v.addr + (rq_b - md_b);
                fam_len = min(md_e, rq_e) - rq_b;
                bufp = rq[i].buf;
            } else if (rq_e > md_b && rq_b <= md_b) {
                // (rq_b ... [MD_b ... rq_e) ... MD_e]
                // (rq_b ... [MD_b ... MD_e] ... rq_e)
                fam_off = md[j].v.addr;
                fam_len = min(rq_e, md_e) - md_b;
                bufp = rq[i].buf + (md_b - rq_b);
            } else {
                // not our chunk
                continue;
            }

            if (fam_len) {
		fam_len = min(fam_len, ttl);

                DEBUG_LVL(6, "lo %d fid %d read %lu bytes from stripe %lu @%lu to %lu",
			  lid, rq[i].fid,
			  fam_len, md[j].v.stripe, fam_off, bufp - rq[i].buf);

                if ((rc = lf_read(lo, bufp, fam_len, fam_off, md[j].v.stripe)))
                {
                    ioerr("lf_read failed ret:%d", rc);
                    return (ssize_t)rc;
                }
                ttl -= fam_len;
		if (ttl == 0)
		    return 0;
            }
        }
    }
    return ttl;
}

#define DEBUG_RC 1
#ifdef DEBUG_RC
static uint64_t c_hit=0;
static uint64_t c_miss=0;
#endif

int famfs_fd_logreadlist(read_req_t *read_req, int count)
{
    shm_meta_t *md_rq;
    read_req_t *rq_ptr;
    f_fattr_t tmp_meta_entry;
    f_fattr_t *ptr_meta_entry;
    long tot_sz = 0;
    int i, j, rq_cnt;
    int rc = UNIFYCR_SUCCESS;

    if (!count)
        return 0;

    STATS_START(start_l);

    /*convert local fid to global fid*/
    int lid = read_req[0].lid;
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(lid);
    ASSERT( meta );
    F_LAYOUT_t *lo = f_get_layout(meta->loid);
    if (lo == NULL) {
        DEBUG_LVL(2, "%s: fid:%d error: layout id:%d not found!",
                  f_get_pool()->mynode.hostname, lid, meta->loid);
        errno = EIO;
        return -1;
    }
    for (i = 0; i < count; i++) {
        if (read_req[0].lid != lid) {
            DEBUG_LVL(2, "read rqs on different layouts, expected %d, got %d",
                      read_req[0].lid, lid);
            errno = EIO;
            return -1;
        }

        read_req[i].fid -= unifycr_fd_limit;
        tmp_meta_entry.fid = read_req[i].fid;

        ptr_meta_entry = (f_fattr_t *)bsearch(&tmp_meta_entry,
                         unifycr_fattrs.meta_entry, *unifycr_fattrs.ptr_num_entries,
                         sizeof(f_fattr_t), compare_fattr);
        if (ptr_meta_entry != NULL) {
            read_req[i].fid = ptr_meta_entry->gfid;
        } else {
            DEBUG_LVL(2, "file %d has no gfid %d record in DB",
                      read_req[i].fid, ptr_meta_entry->gfid);
            errno = EBADF;
            return -1;
        }

        tot_sz += read_req[i].length;
    }
#if defined(DEBUG_RC) | defined(FAMFS_STATS)
    long ttl = tot_sz;
#endif

    qsort(read_req, count, sizeof(read_req_t), compare_read_req);

    DEBUG_LVL(6, "lid:%d read %d request(s):", 
	      lid, count);
    for (i = 0; i < count; i++) {
        DEBUG_LVL(6, "  [%d] fid=%d off/len=%ld/%ld",
		  i, read_req[i].fid, read_req[i].offset, read_req[i].length);
    }

    size_t stripe_sz = lo->info.stripe_sz;
#if 0
    if (key_slice_range % stripe_sz) {
        // If some brain-dead individual created a FS with key range slice not multiples of
        // chunk size, split reads that cross slice boundary
        // *** NOTE: this is REALLY stupid and should be discouraged in SOP
        split_reads_by_slice(read_req, count, &read_req_set);
        rq_cnt = read_req_set.count;
    }
#endif
        rq_cnt = count;
    rq_ptr = read_req_set.read_reqs;
#if 0
     memcpy(rq_ptr, read_req, sizeof(read_req_t)*(unsigned)count);
#else
    /*coalesce the contiguous read requests*/
    unifycr_coalesce_read_reqs(read_req, count,
                               &tmp_read_req_set, stripe_sz,
                               &read_req_set);
    rq_cnt = read_req_set.count;
#endif

    fsmd_kv_t  *md_ptr = (fsmd_kv_t *)(shm_recvbuf + sizeof(int));
    int *rc_ptr = (int *)shm_recvbuf;
    if (*rc_ptr) {
        // Have prev MD in cache, see if anything matches
        tot_sz = match_rq_and_read(lo, read_req, count, lid,
                                   md_ptr, *rc_ptr, tot_sz);
        if (tot_sz < 0) {
            printf("lf_read error\n");
            return (int)tot_sz;
        }

#ifdef DEBUG_RC
	if (tot_sz < ttl)
	    DEBUG_LVL(7, "hit:%lu sz:%ld of %lu",
		      ++c_hit, tot_sz, ttl);
#endif

        if (!tot_sz)
            return 0;
    }

    md_rq = (shm_meta_t *)(shm_reqbuf);
    long prev_offset = -1;
    int prev_fid = -1;
    for (i = 0, j = 0; i < rq_cnt; i++) {
        long offset;

        /* request the whole stripe */
        while ((rq_ptr[i].offset % stripe_sz) + rq_ptr[i].length > stripe_sz) {
            offset = ROUND_DOWN(rq_ptr[i].offset, stripe_sz);
            /* if rq matches a new stripe, add a new md_rq */
            if (rq_ptr[i].fid != prev_fid || offset != prev_offset) {
                md_rq[j].loid = lid;
                md_rq[j].src_fid = prev_fid = rq_ptr[i].fid;
                md_rq[j].length = stripe_sz;
                md_rq[j].offset  = offset;
                j++;
            }
            /* go to next stripe */
            offset += stripe_sz;
            offset -= rq_ptr[i].offset;
            rq_ptr[i].length -= offset;
            rq_ptr[i].offset += offset;
        }
        offset = ROUND_DOWN(rq_ptr[i].offset, stripe_sz);
        /* skip the same stripe */
        if (rq_ptr[i].fid == prev_fid && offset == prev_offset)
            continue;

        md_rq[j].loid = lid;
        md_rq[j].src_fid = prev_fid = rq_ptr[i].fid;
        //md_rq[j].length  = stripe_sz - (rq_ptr[i].offset % stripe_sz);
        md_rq[j].length = stripe_sz;
        //md_rq[j].offset  = rq_ptr[i].offset;
        md_rq[j].offset  = offset;
        j++;
    }
    rq_cnt = j;

    UPDATE_STATS(md_lg_stat, count, ttl, start_l);

    f_svcrq_t c = {
       .opcode  = CMD_MDGET,
       .cid     = local_rank_idx,
       .md_rcnt = rq_cnt
    };
    f_svcrply_t r;

    STATS_START(start);

    DEBUG_LVL(6, "MD/read: loid:%d poll %d rq:", lid, rq_cnt);
    for (i = 0; i < rq_cnt; i++) {
        DEBUG_LVL(7, "  [%d] fid=%d off/len=%ld/%ld",
		  i, md_rq[i].src_fid, md_rq[i].offset, md_rq[i].length);
    }

    f_rbq_t *cq = lo_cq[lid];
    ASSERT(cq);
    struct timespec md_start = now();
    if ((rc = f_rbq_push(cq, &c, RBQ_TMO_1S))) {
        ERROR("%s: can't push MD_GET cmd, layout %d: %s(%d)", 
	    f_get_pool()->mynode.hostname, lid, strerror(-rc), rc);
        return -EIO;
    }
    if ((rc = f_rbq_pop(rplyq, &r, 30*RBQ_TMO_1S))) {
        ERROR("can't get reply to MD_GET from layout %d: %s(%d)", lid, strerror(-rc), rc);
        return -EIO;
    }
    if (r.rc) {
        ERROR("%s: error retrieving file MD: %d", f_get_pool()->mynode.hostname, r.rc);
        return -EIO;
    }
    UPDATE_STATS(md_fg_stat, *rc_ptr, *rc_ptr*sizeof(fsmd_kv_t), start);

#ifdef DEBUG_RC
    DEBUG_LVL(7, "miss:%lu sz:%ld of %ld, MD records found:%d time:%lu",
              ++c_miss, tot_sz, ttl, *rc_ptr, elapsed(&md_start));
#endif

    tot_sz = match_rq_and_read(lo, read_req, count, lid,
                               md_ptr, *rc_ptr, tot_sz);
    if (tot_sz < 0) {
        printf("lf_read error\n");
        return (int)tot_sz;
    }

    if (tot_sz) {
        printf("residual length not 0: %ld\n", tot_sz);
        return -ENODATA;
    }

    return 0;
}

static int famfs_fd_fsync(int fd) {
    int rc;
    f_svcrply_t r;
    f_svcrq_t c = {
        .opcode = CMD_META,
        .cid = local_rank_idx,
        .md_type = MDRQ_FSYNC
    };

    if (!*unifycr_indices.ptr_num_entries)
        return 0;

#ifdef FAMFS_STATS
    int md_cnt=0;
    STATS_START(start_m);
#endif

    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fd);
    ASSERT(meta);

    F_LAYOUT_t *lo = f_get_layout(meta->loid);
    ASSERT(lo);

    /* uncommited stripe? */
    unifycr_chunkmeta_t *stripe = meta->chunk_meta;
    for (unsigned int i = 0; i < meta->stripes; i++, stripe++) {
	f_stripe_t s = stripe->id;

	if (stripe->data_w == 0 || stripe->f.committed)
	    continue;

	if (!stripe->f.in_use) {
	    ERROR("fid:%d in layout %s - unallocated stripe %lu",
		  fd, lo->info.name, s);
	    goto io_err;
	}
        if ((rc = f_ah_commit_stripe(lo, s))) {
            ERROR("fid:%d in layout %s - error %d committed stripe %lu",
                  fd, lo->info.name, rc, s);
            goto io_err;
        }
#ifdef FAMFS_STATS
        md_cnt++;
#endif
        DEBUG_LVL(6, "fid:%d lid:%d commit stripe %lu",
                  fd, meta->loid, s);
        stripe->f.committed = 1;
    }

    if ((rc = invalidate_stripe_cache(fd, lo, meta))) {
        ERROR("fid:%d in layout %s - failed to drop %u stripes", fd, lo->info.name, meta->stripes);
        goto io_err;
    }

    if (allow_merge)
        famfs_merge_md();

    STATS_START(start);

    f_rbq_t *cq = lo_cq[meta->loid];
    ASSERT(cq);

    if ((rc = f_rbq_push(cq, &c, 10*RBQ_TMO_1S))) {
        ERROR("can't push fsync command onto layout %d queue: %s", meta->loid, strerror(-rc));
        return rc;
    }

    if ((rc = f_rbq_pop(rplyq, &r, 30*RBQ_TMO_1S))) {
        ERROR("couldn't get response for fsync from layout %d queue: %s", meta->loid, strerror(-rc));
        return rc;
    }

    *unifycr_indices.ptr_num_entries = 0;
    //*unifycr_fattrs.ptr_num_entries = 0;

    UPDATE_STATS(md_fp_stat, *unifycr_indices.ptr_num_entries, *unifycr_indices.ptr_num_entries, start);
    UPDATE_STATS(fd_syn_stat, *unifycr_indices.ptr_num_entries, *unifycr_indices.ptr_num_entries*sizeof(md_index_t), start_m);

    return r.rc;

io_err:
    errno = EIO;
    return -1;
}

/* sysio/stdio interface to UNIFYCR or FAMFS filesystem */
static F_FD_IFACE_t f_fd_iface = {
    .fid_open		= &famfs_fid_open,
    .fid_close          = &famfs_fid_close,
    .fid_extend		= &famfs_fid_extend,
    .fid_shrink		= &famfs_fid_shrink,
    .fid_write		= &famfs_fid_write,
    .fid_size		= &famfs_fid_size,
    .fid_truncate	= &famfs_fid_truncate,
    /* read fn used in unifycr-sysio.c */
    .fd_logreadlist	= &famfs_fd_logreadlist,
    .fd_fsync		= &famfs_fd_fsync,
};
F_FD_IFACE_t *famfs_fd_iface = &f_fd_iface;

