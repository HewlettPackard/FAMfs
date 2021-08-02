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
#include "f_env.h"
#include "f_error.h"
#include "f_global.h"
#include "f_stats.h"
#include "f_stripe.h"
#include "lf_client.h"
#include "f_rbq.h"
#include "f_bitmap.h"
#include "f_maps.h" /* DEBUG_LVL macro */
#include "f_map.h"
#include "f_pool.h"
#include "f_layout.h"
#include "f_helper.h"
#include "f_rbq.h"
#include "seg_tree.h"
#include "f_ja.h"


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
extern F_POOL_t *pool;
LFS_CTX_t *lfs_ctx = NULL;
f_rbq_t *adminq;
f_rbq_t *rplyq;
f_rbq_t *lo_cq[F_CMDQ_MAX];

bool famfs_local_extents; /* enable tracking of local extents (write cache config option) */
static unsigned long shm_recv_max; /* max number of records in mdhim receive buffer in SHM */


static int f_stripe_write(int fid, long pos, unifycr_filemeta_t *meta,
    const void *buf, size_t count, F_LAYOUT_t *lo);


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
    DEBUG_LVL(6, "layout %s lid:%d get stripe %lu",
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

    DEBUG_LVL(7, "free logical id %d stripe %lu", id, s);

    /* release stripe; check uncommited stripe */

    if (!stripe->f.in_use) {
        ERROR("free unallocated stripe %lu in layout %s fl:%x",
              s, lo->info.name, stripe->flags);
        ASSERT(0);
    }

    if (!stripe->f.committed) {

	DEBUG_LVL(6, "fid:%d lid:%d release stripe %lu",
		  fid, meta->loid, s);

        if ((rc = f_ah_release_stripe(lo, s))) {
            ERROR("failed to release stripe %lu in layout %s, error:%d",
                  s, lo->info.name, rc);
            return UNIFYCR_FAILURE;
        }
        meta->ttl_stripes--;
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
 * Operations on client write index
 * --------------------------------------- */

/*
 * Clear all entries in the log index.  This only clears the metadata,
 * not the data itself.
 */
static void clear_index(void)
{
    *unifycr_indices.ptr_num_entries = 0;
}

/* add metadata (write indexes) to meta->extents tree;
 * keep record of committed stripes */
static void cache_write_indexes(unifycr_filemeta_t* meta)
{
    /* get pointer to index buffer */
    md_index_t* indexes = unifycr_indices.index_entry;
    long i, num_entries = *unifycr_indices.ptr_num_entries;

    if (PoolReleaseCS(pool)) {
	for (i = 0; i < num_entries; i++) {
	    f_ja_add(meta->committed_stripes, indexes[i].sid);
	}
	rcu_quiescent_state();
    }

    if (PoolWCache(pool)) {
        seg_tree_wrlock(&meta->extents);

        /* Add each write metadata to seg_tree ... */
        for (i = 0; i < num_entries; i++) {
            off_t file_pos = indexes[i].file_pos;

            /* add metadata for a single write to meta->extents tree */
            seg_tree_add(&meta->extents,
                         file_pos,
                         file_pos + indexes[i].length - 1,
                         indexes[i].mem_pos,
                         indexes[i].sid);
        }
        seg_tree_unlock(&meta->extents);
    }
}

static int client_sync_md(unifycr_filemeta_t *meta, int fsync_tmo) {
    int rc;
    f_svcrply_t r;
    f_svcrq_t c = {
        .opcode = CMD_META,
        .cid = local_rank_idx,
        .md_type = MDRQ_FSYNC
    };

    ASSERT( *unifycr_indices.ptr_num_entries > 0 );

    STATS_START(start);

    f_rbq_t *cq = lo_cq[meta->loid];
    ASSERT(cq);
    c.fm_lid = meta->loid;

    /* make Helper to send metadata to RS */
    if ((rc = f_rbq_push(cq, &c, 10*RBQ_TMO_1S))) {
        ERROR("can't push fsync command onto layout %d queue: %s", meta->loid, strerror(-rc));
        return rc;
    }

    /* cache write indexes: populate meta->extents tree and committed_stripes */
    cache_write_indexes(meta);

    /* wait for RS acknowledgement */
    if ((rc = f_rbq_pop(rplyq, &r, fsync_tmo*RBQ_TMO_1S))) {
        ERROR("couldn't get RS response for syncing metadata in %d s, lid: %d queue: %s",
              fsync_tmo, meta->loid, strerror(-rc));
        return rc;
    }

    UPDATE_STATS(md_fp_stat, *unifycr_indices.ptr_num_entries, *unifycr_indices.ptr_num_entries, start);

    return r.rc;
}

/*
 * Sync all the write extents for the target file(s) to the server.
 * The target_fid identifies a specific file, or all files (-1).
 * Clears the metadata index afterwards.
 *
 * Returns 0 on success, nonzero otherwise.
 */
static int famfs_sync(int target_fid)
{
    int fsync_tmo = pool->info.fsync_tmo;
    int ret = UNIFYCR_SUCCESS;

    /* For each open file descriptor .. */
    for (int i = 0; i < unifycr_max_files; i++) {
        /* get file id for each file descriptor */
        int fid = unifycr_fds[i].fid;
        if (-1 == fid) {
            /* file descriptor is not currently in use */
            continue;
        }

        /* is this the target file? */
        if ((target_fid != -1) && (fid != target_fid)) {
            continue;
        }

        unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
        if ((NULL == meta) || (meta->fid != fid)) {
            ERROR("missing filemeta for fid=%d", fid);
            ret = UNIFYCR_FAILURE;
            goto _cont;
        }

        if (meta->needs_sync) {

            /* if there are no index entries, we've got nothing to sync */
            if (*unifycr_indices.ptr_num_entries == 0) {
                meta->needs_sync = 0;
                goto _cont;
            }

            STATS_START(start);

            F_LAYOUT_t *lo = f_get_layout(meta->loid);
            ASSERT(lo);
            size_t key_slice_range = lo->info.stripe_sz;

            /* uncommited stripe? */
            unifycr_chunkmeta_t *stripe = meta->chunk_meta;
            for (unsigned int n = 0; n < meta->stripes; n++, stripe++) {
                f_stripe_t s = stripe->id;

                if (stripe->data_w == 0 || stripe->f.committed)
                    continue;

                if (!stripe->f.in_use) {
                    ERROR("fid:%d in layout %s - unallocated stripe %lu",
                          fid, lo->info.name, s);
                    goto io_err;
                }

                /* forced fsync: commit full stripes only */
                if ((target_fid == -1) && stripe->data_w < key_slice_range)
                    continue;

                if ((ret = f_ah_commit_stripe(lo, s))) {
                    ERROR("fid:%d in layout %s - error %d committed stripe %lu",
                          fid, lo->info.name, ret, s);
                    goto io_err;
                }
                stripe->f.committed = 1;

                DEBUG_LVL(6, "fid:%d lid:%d commit %s stripe %lu",
                          fid, meta->loid,
                          (stripe->data_w < lo->info.stripe_sz)?"partial":"", s);
            }

            if ((target_fid != -1) && (ret = invalidate_stripe_cache(fid, lo, meta)))
            {
                ERROR("fid:%d in layout %s - failed to drop %u stripes",
                      fid, lo->info.name, meta->stripes);
                goto io_err;
            }

            UPDATE_STATS(fd_syn_stat, *unifycr_indices.ptr_num_entries,
                         *unifycr_indices.ptr_num_entries, start);

            /* tell the server to grab our new extents */
            ret = client_sync_md(meta, fsync_tmo);
            if (ret != UNIFYCR_SUCCESS) {
                /* something went wrong when trying to flush extents */
                ERROR("failed to flush write index to server for gfid=%d",
                       meta->gfid);
                goto io_err;
            }
            meta->needs_sync = 0;

            /* flushed, clear buffer and refresh number of entries
             * and number remaining */
            clear_index();
        }

        /* break out of loop when targeting a specific file */
_cont:
        if (fid == target_fid) {
            break;
        }
    }
    return ret;

io_err:
    errno = EIO;
    return ret;
}


//
/// ===========================================
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
    meta->size         = 0;
    meta->is_dir       = 0;
    meta->real_size    = 0;
    meta->storage      = FILE_STORAGE_NULL;
    meta->flock_status = UNLOCKED;
    meta->stripes      = 0;
    meta->ttl_stripes  = 0; /* TODO: Make ttl_stripes persistent file attr */
    meta->stripe_idx   = 0;
    meta->fid          = fid;
    meta->gfid         = 0; /* TODO: Generate gfid here */
    meta->loid         = loid;
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

    if ((rc = f_rbq_pop(rplyq, &r, 30*RBQ_TMO_1S))) {
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

static int fid_store_alloc(int fid) {
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    if ((meta != NULL) && (meta->fid == fid)) {
        meta->storage = FILE_STORAGE_LOGIO;

        /* Initialize our segment tree to track extents for all writes
         * by this process, can be used to read back local data */
        if (famfs_local_extents) {
            int rc = seg_tree_init(&meta->extents);
            if (rc != 0)
                return rc;
        }

        if (PoolReleaseCS(pool))
	    meta->committed_stripes = f_new_ja(64);
        else
            meta->committed_stripes = NULL;

        return UNIFYCR_SUCCESS;
    }
    return UNIFYCR_FAILURE;
}

/* free data management resource for file */
static int fid_store_free(int fid) {
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    if ((meta != NULL) && (meta->fid == fid)) {
        meta->storage = FILE_STORAGE_NULL;

        /* Free our extent seg_tree */
        if (famfs_local_extents)
            seg_tree_destroy(&meta->extents);

        if (PoolReleaseCS(pool)) {
            int ret;
            if ((ret = f_ja_destroy(meta->committed_stripes))) {
                ERROR("fid:%d - error %d", fid, ret);
                return UNIFYCR_FAILURE;
            }
	    meta->committed_stripes = NULL;
        }
        return UNIFYCR_SUCCESS;
    }
    return UNIFYCR_FAILURE;
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
        ERROR("fid:%d error: layout id:%d not found!",
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

    int rc = trim_stripe_cache(fid, lo, meta, num_chunks);
    if (rc != UNIFYCR_SUCCESS) {
        ERROR("fid:%d error shrinking layout id:%d to %ld",
              fid, meta->loid, length);
        return UNIFYCR_ERR_IO;
    }

    /* if truncated to zero, free all stripes and drop write cache */
    /* FIXME: truncate to the arbitrary size */
    if (num_chunks == 0) {
	if (PoolReleaseCS(pool)) {
	    F_JUDY_t *ja_cs = meta->committed_stripes;
	    int ret;
	    uint64_t s;
	    struct cds_ja_node *node;

	    //ja_for_each_entry(meta->committed_stripes, n, s) {
	    rcu_read_lock();
	    cds_ja_for_each_key_rcu(ja_cs, s, node) {
		F_JA_NODE_t *n;

		ret = cds_ja_del(ja_cs, s, node);
		if (ret) {
		    rcu_read_unlock();
		    ERROR("fid:%d in layout %s - error %d releasing stripe %lu",
			  fid, lo->info.name, ret, s);
		    return UNIFYCR_ERR_IO;
		}
		n = container_of(node, F_JA_NODE_t, node);
		s = n->entry;
		f_ja_node_free(n);
		rcu_read_unlock();

		DEBUG_LVL(6, "fid:%d lid:%d release stripe %lu",
			  fid, meta->loid, s);

		if ((ret = f_ah_release_stripe(lo, s))) {
		    ERROR("fid:%d in layout %s - error %d releasing stripe %lu",
			  fid, lo->info.name, ret, s);
		    return UNIFYCR_ERR_IO;
		}
		meta->ttl_stripes--;
		rcu_read_lock();
	    }
	    rcu_read_unlock();
	    rcu_quiescent_state();
	}

	if (PoolWCache(pool))
	    seg_tree_clear(&meta->extents);
    }

    return rc; 
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

    DEBUG_LVL(5, "fid %d lid %d truncate %jd -> %jd",
              fid, meta->loid, size, length);

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
        /* hash a path to gfid */
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
            if (fid_store_alloc(fid))
                return UNIFYCR_FAILURE;

            /* initialize the global metadata */
            unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
            meta->real_size = ptr_meta->file_attr.st_size;
            meta->gfid = gfid;

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
            if (fid_store_alloc(fid))
                return UNIFYCR_FAILURE;

            /* initialize the global metadata */
            unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
            meta->gfid = gfid;

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

	if (stripe->data_w > 0) {
	    if ((rc = f_ah_commit_stripe(lo, s))) {
		ERROR("fid:%d in layout %s - failed to commit stripe %lu on close, error:%d",
		      fid, lo->info.name, s, rc);
		return UNIFYCR_FAILURE;
	    }
	    stripe->f.committed = 1;
	    DEBUG_LVL(6, "fid:%d lid:%d - commit %s stripe %lu on close",
		      fid, meta->loid,
		      (stripe->data_w < lo->info.stripe_sz)?"partial":"", s);
	}
    }

    if (invalidate_stripe_cache(fid, lo, meta)) {
	ERROR("fid:%d in layout %s - failed to drop %u stripes on close",
	      fid, lo->info.name, meta->stripes);
	return UNIFYCR_FAILURE;
    }

    if ((lo->info.chunks - lo->info.data_chunks) && PoolEncWaitOnClose(pool)) {
        f_svcrq_t   c = {.opcode = CMD_FCLOSE, .cid = local_rank_idx, .fid = fid, .lid = meta->loid};
        f_svcrply_t r;
        int lid = meta->loid;
        f_rbq_t *cq = lo_cq[lid];

        if ((rc = f_rbq_push(cq, &c, RBQ_TMO_1S))) {
            ERROR("%s: can't push FCLOSE cmd, layout %d: %s(%d)",
                  f_get_pool()->mynode.hostname, lid, strerror(-rc), rc);
            return UNIFYCR_FAILURE;
        }

        int n = 0;
        do {
            rc = f_rbq_pop(rplyq, &r, RBQ_TMO_1M);
            if (++n > 3) break;
        } while (rc == -ETIMEDOUT);

        if (rc) {
            ERROR("%s: FCLOSE %s, layout %d: %s(%d)",
                  f_get_pool()->mynode.hostname, rc == -ETIMEDOUT ? "timed-out" : "failed", 
                  lid, strerror(-rc), rc);
            return UNIFYCR_FAILURE;
        }
    }

    return UNIFYCR_SUCCESS;
}

/* delete a file id and return file its resources to free pools */
static int famfs_fid_unlink(int fid)
{
    /* return data to free pools */
    famfs_fid_truncate(fid, 0);

    /* finalize the storage we're using for this file */
    int rc = fid_store_free(fid);
    if (rc != UNIFYCR_SUCCESS)
        return rc;

    /* set this file id as not in use */
    unifycr_filelist[fid].in_use = 0;

    /* add this id back to the free stack */
    unifycr_fid_free(fid);

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
int famfs_mount(const char prefix[] __attribute__((unused)),
    size_t size __attribute__((unused)),
    int rank)
{
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
    /* enable tracking of local ranges on write and/or on read */
    famfs_local_extents = PoolWCache(pool) || PoolRCache(pool);
    /* metadata receive buffer size: max KV index */
    shm_recv_max = shm_recv_size/sizeof(fsmd_kv_t);
    ASSERT( shm_recv_max>0 );
    shm_recv_max--;

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
    f_svcrq_t   c = {.opcode = CMD_SVCRQ, .cid = local_rank_idx};
    f_svcrply_t r;

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

famfs_mr_list_t known_mrs = {0, NULL};

#define FAMFS_MR_AU 8
#define LMR_BASE_KEY 1000000
#define LMR_PID_SHIFT 8

int famfs_buf_reg(char *buf, size_t len, void **rid) {
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
    N_STRIPE_t *fam_stripe;
    LF_INFO_t *lf_info = pool->lf_info;
    //struct famsim_stats *stats_fi_rd;
    int rc = 0;

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
    size_t key_slice_range;

    /* get chunk meta data */
    ASSERT( meta->stripe_idx < meta->stripes );
    uint64_t stripe_id = meta->stripe_idx; /* logical stripe id to write to */
    unifycr_chunkmeta_t *stripe = &(meta->chunk_meta[stripe_id]);
    /* logical offset within chunk to write to */
    off_t stripe_offset = get_stripe_offset_wr(meta);
    ASSERT( stripe->f.in_use == 1 ); /* got allocated stripe from Helper */

    key_slice_range = lo->info.stripe_sz;
    f_stripe_t s = stripe->id; /* global stripe number */

    DEBUG_LVL(5, "%s: write to stripe %lu @%lu %zu bytes pos %ld (logical %lu)",
              lfs_ctx->pool->mynode.hostname, s, stripe_offset, count, pos, stripe_id);

    ASSERT( stripe_offset + count <= key_slice_range );

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

    /* Commit full stripe */
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

    STATS_START(start);

    md_index_t *cur = &tmp_index_set.idxes[0];
    tmp_index_set.count = 1;
    cur->fid      = meta->gfid;
    cur->loid     = meta->loid;
    cur->file_pos = pos;
    cur->length   = count;
    cur->mem_pos  = stripe_offset;
    cur->sid      = s;

    /*split the write requests larger than key_slice_range into
     * the ones smaller than key_slice_range
     * */
    if (pos % key_slice_range + count > key_slice_range) {
        size_t new_len = pos % key_slice_range + count - key_slice_range;
        md_index_t * snd = cur+1;
        cur->length   -= new_len;
        snd->file_pos  = cur->length + pos;
        snd->mem_pos   = cur->length + stripe_offset;
        snd->length    = new_len;
        snd->loid = meta->loid;
        snd->fid  = meta->gfid;
        snd->sid  = s;
        tmp_index_set.count++;
    }

    int i = 0;
    if (*(unifycr_indices.ptr_num_entries) + tmp_index_set.count
        >= (long)unifycr_max_index_entries)
    {
        /* force MD sync */
        meta->needs_sync = 1;
        famfs_sync(-1);
        /* TODO: Implement fsync in background */
        DEBUG_LVL(3, "Warning: Insufficient MD buffer size may affect the performance!");
    }
    ASSERT( *(unifycr_indices.ptr_num_entries) + tmp_index_set.count
           < (long)unifycr_max_index_entries );

    /*coalesce contiguous indices*/

    if (*unifycr_indices.ptr_num_entries >= 1) {
        md_index_t *ptr_last_idx = &unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries - 1];

        if (ptr_last_idx->sid == cur->sid &&
            ptr_last_idx->fid == cur->fid &&
            ptr_last_idx->loid == cur->loid)
        {
            off_t prev_e = ptr_last_idx->file_pos + (ssize_t)ptr_last_idx->length;

            if (prev_e == cur->file_pos) {
                off_t slice_b = (ptr_last_idx->file_pos / key_slice_range + 1) * key_slice_range;
                off_t cur_e = prev_e + (ssize_t)cur->length;

                /* if new range end is in the next slice */
                if (cur_e > slice_b) {
                    off_t adj = slice_b - prev_e;

                    /* extend former range upto slice boundary */  
                    ptr_last_idx->length += adj;
                    ASSERT( ptr_last_idx->length < key_slice_range );

                    /* adjust new range to the slice boundary */
                    cur->file_pos = slice_b;
                    cur->mem_pos += adj;
                    cur->length -= adj;
                    ASSERT( cur->length < key_slice_range );

                } else {
                    /* both in the same slice, coalesce */
                    ptr_last_idx->length += cur->length;
                    ASSERT( ptr_last_idx->length <= key_slice_range );
                    i++;
                }
            }
        }
    }
    for (; i < tmp_index_set.count; i++) {
        unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries] = tmp_index_set.idxes[i];
        (*unifycr_indices.ptr_num_entries)++;
    }

    /* find the corresponding file attr entry and update attr*/
    f_fattr_t tmp_meta_entry;
    tmp_meta_entry.fid = fid;
    f_fattr_t *ptr_meta_entry = (f_fattr_t *)bsearch(&tmp_meta_entry,
                                         unifycr_fattrs.meta_entry,
                                         *unifycr_fattrs.ptr_num_entries,
                                         sizeof(f_fattr_t), compare_fattr);
    if (ptr_meta_entry !=  NULL)
        ptr_meta_entry->file_attr.st_size = pos + count;

    meta->needs_sync = 1;

    UPDATE_STATS(wr_upd_stat, 1, 1, start);

    return rc;
}

static int compare_read_req(const void *a, const void *b)
{
    const read_req_t *ptr_a = a;
    const read_req_t *ptr_b = b;

    if (ptr_a->lid - ptr_b->lid > 0)
        return 1;

    if (ptr_a->lid - ptr_b->lid < 0)
        return -1;

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

/*
 * given an read request, split it into multiple indices whose range is equal or smaller
 * than slice_range size
 * @param cur_read_req: the read request to split
 * @param slice_range: the slice size of the key-value store
 * @return read_req_set: the set of split read requests
 * */
static void famfs_split_read_requests(read_req_t *cur_read_req,
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
        read_req_set->read_reqs[0]= *cur_read_req;
        read_req_set->count++;
    } else {
        /*
        cur_slice_start                     cur_slice_endnext_slice_start                   next_slice_end
                         cur_read_start                                     cur_read_end

        */
        read_req_set->read_reqs[0] = *cur_read_req;
        read_req_set->read_reqs[0].length =
            cur_slice_end - cur_read_start + 1;
        char *buf = cur_read_req->buf + read_req_set->read_reqs[0].length;
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
            read_req_set->read_reqs[read_req_set->count].buf = buf;

            cur_slice_start = cur_slice_end + 1;
            cur_slice_end = cur_slice_start + slice_range - 1;
            buf += slice_range;
            read_req_set->count++;

        }

        read_req_set->read_reqs[read_req_set->count].lid = cur_read_req->lid;
        read_req_set->read_reqs[read_req_set->count].fid = cur_read_req->fid;
        read_req_set->read_reqs[read_req_set->count].offset = cur_slice_start;
        read_req_set->read_reqs[read_req_set->count].length = cur_read_end - cur_slice_start + 1;
        read_req_set->read_reqs[read_req_set->count].buf = buf;
        read_req_set->count++;
    }
}

static inline void md_cache_copy_item(fsmd_kv_t *md, int *pos, struct seg_tree_node *n, int lid, int fid)
{
    int i = *pos;
    ASSERT( IN_RANGE(i, 0, (int)shm_recv_max) ); 
    md[i].k.pk.loid = lid;
    md[i].k.pk.fid = fid;
    md[i].k.offset = n->start;
    md[i].v.len = n->end - n->start + 1;
    md[i].v.stripe = n->stripe;
    md[i].v.addr = n->ptr;

    /* do not duplicate */
    if (i == 0 || memcmp(&md[i-1], &md[i], sizeof(fsmd_kv_t)))
        (*pos)++;
}

/* reset and fill md-> array of fsmd_kv_t with cached metadata which fit given read requests */
static void md_cache_fetch(struct seg_tree *extents, read_req_t *rq, int rq_cnt,
    fsmd_kv_t *md, int *md_cnt_p)
{
    int i, j, k;
    int md_cnt = 0;

    seg_tree_rdlock(extents);

    for (i = 0; i < rq_cnt; i++) {
        off_t rq_b = rq[i].offset;
        size_t rq_len = rq[i].length;
        size_t rq_e = rq_b + rq_len;

        int lid = rq[i].lid;
        int fid = rq[i].fid;

        size_t expected_start = rq_b;
        bool have_in_cache = 1;
        k = md_cnt; /* md index */

        /* iterate over extents we have for this file,
         * and check that there are no holes in coverage,
         * we search for a starting extent using a range
         * of just the very first byte that we need */
         struct seg_tree_node* first = seg_tree_find_nolock(extents, rq_b, rq_b);
         struct seg_tree_node* next = first;
         while (next != NULL && next->start < rq_e) {
             if (expected_start >= next->start) {
                 /* this extent has the next byte we expect,
                  * bump up to the first byte past the end
                  * of this extent */
                 expected_start = next->end + 1;
                 /* avoid duplicate */
                 md_cache_copy_item(md, &k, next, lid, fid);
            } else {
                 /* there is a gap between extents so we're missing
                  * some bytes */
                 have_in_cache = 0;
                 break;
            }

            /* get the next element in the tree */
            next = seg_tree_iter(extents, next);
        }

        /* check that we account for the full request
         * up until the last byte */
        if (expected_start < rq_e) {
            /* missing some bytes at the end of the request */
            have_in_cache = 0;
        }

        /* we can't fully satisfy the request */
        if (!have_in_cache)
            continue;

        if (unifycr_debug_level >= 7) {
            for (j = md_cnt; j < k; j++) {
                ASSERT( lid == md[j].k.pk.loid );
                ASSERT( fid == md[j].k.pk.fid );
                if (j == md_cnt) {
                    DEBUG_LVL(7, "fetch md[%d] K lo=%d fid=%d @%lu V s=%lu len=%lu @%lu"
                                 " for rq[%d] off/len=%zu/%lu",
                              j, lid, fid, md[j].k.offset,
                              md[j].v.stripe, md[j].v.len, md[j].v.addr,
                              i, rq[i].offset, rq_len);
                } else {
                    DEBUG_LVL(7, "fetch md[%d] K lo=%d fid=%d @%lu V s=%lu len=%lu @%lu"
                                 " for rq[%d]",
                              j, lid, fid, md[j].k.offset,
                              md[j].v.stripe, md[j].v.len, md[j].v.addr,
                              i);
                }
            }
        }

        /* copy the metadata */
        md_cnt = k;
    }

    seg_tree_unlock(extents);

    *md_cnt_p = md_cnt;
}

/* add md-> array[md_cnt] of fsmd_kv_t to per-file segment tree */
static void md_cache_add(fsmd_kv_t *md, int md_cnt)
{
    unifycr_filemeta_t *meta = NULL;
    int i;
    int gfid = -1, fid = -1, lid = -1;

    for (i = 0; i < md_cnt; i++) {
	if (gfid != md[i].k.pk.fid) {
	    gfid = md[i].k.pk.fid;
	    fid = famfs_fid_from_gfid(gfid);

	    if (lid != md[i].k.pk.loid) {

		if (meta != NULL)
		    seg_tree_unlock(&meta->extents);

		meta = unifycr_get_meta_from_fid(fid);
		if (meta == NULL) {
		    ERROR("%s: layout id %d gfid %d - metadata not found @%lu",
			  pool->mynode.hostname, md[i].k.pk.loid, gfid, md[i].k.offset);
		    continue;
		}
		lid = md[i].k.pk.loid;

		seg_tree_wrlock(&meta->extents);
	    }
	}

        /* add metadata for a single write to meta->extents tree */
	unsigned long file_pos = md[i].k.offset;
	unsigned long length = md[i].v.len;
        seg_tree_add(&meta->extents,
                     file_pos,
                     file_pos + length - 1,
                     md[i].v.addr,
                     md[i].v.stripe);
    }

    if (meta != NULL)
	seg_tree_unlock(&meta->extents);
}

/*
 * Match read requests rq[*rq_cnt_p] to metadata md[md_cnt], read FAM and return
 * unmatched requests in rq.
 */
static ssize_t match_rq_and_read(F_LAYOUT_t *lo, read_req_t *rq, int *rq_cnt_p,
    fsmd_kv_t *md, int md_cnt, size_t ttl, int force_read)
{
    md_index_t *cur = tmp_index_set.idxes; /* temporary storage for rq[i] matches, [n] */ 
    size_t nread = 0;
    int lid = lo->info.conf_id;
    int rq_cnt = *rq_cnt_p;
    int i, j, k, n, rc;

    /* i -> IN rq[i], k -> OUT rq[k] */
    for (i = k = 0; i < rq_cnt && ttl > 0; i++) {
        off_t fam_off;
        size_t fam_len, rq_len = rq[i].length;
        off_t rq_b = rq[i].offset;
        off_t rq_e = rq_b + rq_len;
        char *bufp;
        uint64_t s;

        DEBUG_LVL(7, "rq[%d] %s fid=%d off/len=%zu/%lu buf=%p",
		  i, force_read?"F":"",
                  rq[i].fid, rq[i].offset, rq_len, rq[i].buf);

        /* j -> md[j], n -> cur[n] */
        nread = 0;
        tmp_index_set.count = n = 0;
        for (j = 0; j < md_cnt && ttl > 0; j++) {
            s          = md[j].v.stripe;
            off_t md_b = md[j].k.offset;
            off_t md_e = md[j].k.offset + md[j].v.len;

	    DEBUG_LVL(7, "  md[%d] K lo=%d fid=%d @%lu V s=%lu len=%lu @%lu,"
			 " ttl:%zu",
		      j, md[j].k.pk.loid, md[j].k.pk.fid, md[j].k.offset,
		      s, md[j].v.len, md[j].v.addr,
		      ttl);

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
                ASSERT( fam_len <= rq_len );
                fam_len = min(fam_len, ttl);
                nread += fam_len;

                DEBUG_LVL(6, "rq[%d] match [%d] %lu bytes @%lu to buf @%lu, rem: %zu",
                          i, j, fam_len, fam_off, bufp-rq[i].buf, nread);

                // forced segment read
                if (force_read) {
                    DEBUG_LVL(5, "%s: read from stripe %lu seg @%lu %zu bytes to pos %ld",
                              lfs_ctx->pool->mynode.hostname, s,
                              fam_off, fam_len, rq_b+bufp-rq[i].buf);

                    if ((rc = lf_read(lo, bufp, fam_len, fam_off, s)))
                    {
                        ioerr("lf_read failed ret:%d", rc);
                        return (ssize_t)rc;
                    }
                    ttl -= fam_len;

                } else {
                    // store segment metadata in temp array
                    // cur->loid = lid;
                    // cur->fid = rq[i].fid;
                    cur[n].file_pos = bufp - rq[i].buf;
                    cur[n].mem_pos  = fam_off;
                    cur[n].length   = fam_len;
                    cur[n].sid      = s;
                    n++;
                }
            }
        }

        /* evict rq which is fully served */
        if (nread != rq_len) {
            if (k < i)
                memcpy(&rq[k], &rq[i], sizeof(read_req_t));
            k++;
        } else {
            if (!force_read) {
                // read all segments of rq[i]
                for (j = 0; j < n && ttl > 0; j++) {
                    bufp    = cur[j].file_pos + rq[i].buf;
                    s       = cur[j].sid;
                    fam_off = cur[j].mem_pos;
                    fam_len = cur[j].length;

                    DEBUG_LVL(5, "%s: read from stripe %lu seg:%d @%lu %zu bytes to pos %ld",
                              lfs_ctx->pool->mynode.hostname, s, j,
                              fam_off, fam_len, rq_b+cur[j].file_pos);

                    if ((rc = lf_read(lo, bufp, fam_len, fam_off, s)))
                    {
                        ioerr("lf_read failed ret:%d", rc);
                        return (ssize_t)rc;
                    }
                    ttl -= fam_len;
                    if (ttl == 0)
                        break;
                }
            }
            DEBUG_LVL(7, "rq[%d] fullfilled", i);
        }
    }

    if (ttl == 0 && i < rq_cnt) {
        ERROR("%s: read premature end, %d request(s) not served, lid:%d fid:%d nread:%zu",
              lfs_ctx->pool->mynode.hostname, rq_cnt-i, lid, rq[i].fid, nread);
        *rq_cnt_p = 0;
        errno = EIO;
        return -1;
    }

    *rq_cnt_p = k;

    return ttl;
}

#define DEBUG_RC 1
#ifdef DEBUG_RC
static uint64_t c_hit=0;
static uint64_t c_miss=0;
#endif

int famfs_fd_logreadlist(read_req_t *read_req, int count)
{
    unifycr_filemeta_t *meta;
    shm_meta_t *md_rq;
    read_req_t *rq_ptr;
    long tot_sz = 0;
    int i, rq_cnt;
    int rc = UNIFYCR_SUCCESS;

    if (!count)
        return 0;

    STATS_START(start_l);

    /* TODO: Add support for multiple layout read */
    F_LAYOUT_t *lo = NULL;
    meta = NULL;
    int fid = -1, lid = -1;

    for (i = 0; i < count; i++) {
        fid = read_req[i].fid - unifycr_fd_limit;
        /*convert local fid to global fid*/
        meta = unifycr_get_meta_from_fid(fid);
        if (meta == NULL) {
            ERROR("%s: fid %d not found!", pool->mynode.hostname, fid);
            errno = EBADF;
            return -1;
        }
        lid = read_req[i].lid;
        ASSERT( lid == meta->loid );
        lo = f_get_layout(lid);
        if (lo == NULL) {
            DEBUG_LVL(2, "%s: fid:%d error: layout id:%d not found!",
                      pool->mynode.hostname, fid, lid);
            errno = EIO;
            return -1;
        }
        read_req[i].fid = meta->gfid;

        tot_sz += read_req[i].length;
    }
#if defined(DEBUG_RC) | defined(FAMFS_STATS)
    long ttl = tot_sz;
#endif

    qsort(read_req, count, sizeof(read_req_t), compare_read_req);

    for (i = 0; i < count; i++) {
        DEBUG_LVL(6, "rq[%d] (%d) lid=%d fid=%d off/len=%ld/%ld buf=%p",
                  i, count, lid, read_req[i].fid,
                  read_req[i].offset, read_req[i].length, read_req[i].buf);
    }

    /* split request so it may overlap one RS boundary at most */
    size_t stripe_sz = lo->info.stripe_sz;
    famfs_split_read_requests(read_req, &read_req_set, stripe_sz);

    /* read request array */
    rq_ptr = read_req_set.read_reqs;
    count = read_req_set.count;

    /* md request array (SHM) */
    fsmd_kv_t  *md_ptr = (fsmd_kv_t *)(shm_recvbuf + sizeof(int));
    int *md_cnt = (int *)shm_recvbuf;

    /* TODO: process read rq per-file */
    /* fill md_ptr-> array of fsmd_kv_t with suitable md from cache */
    if (famfs_local_extents)
        md_cache_fetch(&meta->extents, rq_ptr, count,
                       md_ptr, md_cnt);

    if (*md_cnt) {
        // Have prev MD in cache, see if anything matches
        tot_sz = match_rq_and_read(lo, rq_ptr, &read_req_set.count,
                                   md_ptr, *md_cnt, tot_sz, 0);
        if (tot_sz < 0) {
            printf("lf_read error\n");
            return (int)tot_sz;
        }

#ifdef DEBUG_RC
	if (tot_sz < ttl)
	    DEBUG_LVL(7, "hit:%lu %d of %d reqs, remaining sz:%ld of %lu",
		      ++c_hit, (count - read_req_set.count), count,
		      tot_sz, ttl);
#endif

        if (!tot_sz)
            return 0;
    }

    md_rq = (shm_meta_t *)(shm_reqbuf);
    rq_cnt = read_req_set.count;
    for (i = 0; i < rq_cnt; i++)
        memcpy(&md_rq[i], &rq_ptr[i], sizeof(shm_meta_t));
    *md_cnt = rq_cnt;

    UPDATE_STATS(md_lg_stat, count, ttl, start_l);

    f_svcrq_t c = {
       .opcode  = CMD_MDGET,
       .cid     = local_rank_idx,
       .md_rcnt = rq_cnt
    };
    f_svcrply_t r;

    STATS_START(start);

    DEBUG_LVL(6, "read MD loid:%d %d Rqs:", lid, rq_cnt);
    for (i = 0; i < rq_cnt; i++) {
        DEBUG_LVL(7, "  [%d] fid=%d off/len=%ld/%ld",
		  i, md_rq[i].src_fid, md_rq[i].offset, md_rq[i].length);
    }

    f_rbq_t *cq = lo_cq[lid];
    ASSERT(cq);
    struct timespec md_start = now();
    if ((rc = f_rbq_push(cq, &c, RBQ_TMO_1S))) {
        ERROR("%s: can't push MD_GET cmd, layout %d: %s(%d)", 
              pool->mynode.hostname, lid, strerror(-rc), rc);
        return -EIO;
    }

    /* TODO: Add requrst ranges tree and fill gaps only */
    // fill user buffer with zeros
    for (i = 0; i < rq_cnt; i++)
        memset(rq_ptr[i].buf, 0, rq_ptr[i].length);

    if ((rc = f_rbq_pop(rplyq, &r, 30*RBQ_TMO_1S))) {
        ERROR("can't get reply to MD_GET from layout %d: %s(%d)", lid, strerror(-rc), rc);
        return -EIO;
    }
    if (r.rc) {
        ERROR("%s: error retrieving file MD: %d", pool->mynode.hostname, r.rc);
        return -EIO;
    }

    /* md read cache: add md_ptr-> array of fsmd_kv_t to per-file segment tree */
    if (PoolRCache(pool))
        md_cache_add(md_ptr, *md_cnt);

    UPDATE_STATS(md_fg_stat, *md_cnt, *md_cnt*sizeof(fsmd_kv_t), start);

#ifdef DEBUG_RC
    DEBUG_LVL(7, "miss:%lu sz:%ld of %ld, MD records found:%d for %d reqs, time:%lu",
	      ++c_miss,
	      tot_sz, ttl, *md_cnt, rq_cnt, elapsed(&md_start));
#endif

    // see if anything matches
    tot_sz = match_rq_and_read(lo, rq_ptr, &read_req_set.count,
                               md_ptr, *md_cnt, tot_sz, 1);
    if (tot_sz < 0) {
        printf("lf_read error\n");
        return (int)tot_sz;
    }
    if (tot_sz) {
        DEBUG_LVL(7, "residual length: %ld\n", tot_sz);
    }

    return 0;
}

static int famfs_fd_fsync(int fid) {
    int ret = UNIFYCR_SUCCESS;

    /* sync any writes to disk */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    ASSERT( meta != NULL );

    if (meta->needs_sync) {
        /* sync data with server */
        ret = famfs_sync(fid);
        /* invalidate last metadata in read path */
        *((int *)shm_recvbuf) = 0;
    }

    return ret;
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
    .fid_unlink		= &famfs_fid_unlink,
    /* read fn used in unifycr-sysio.c */
    .fd_logreadlist	= &famfs_fd_logreadlist,
    .fd_fsync		= &famfs_fd_fsync,
};
F_FD_IFACE_t *famfs_fd_iface = &f_fd_iface;

