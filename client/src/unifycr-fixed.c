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
#define __USE_GNU
#include <pthread.h>

#include "famfs_global.h"
#include "unifycr-internal.h"

extern int dbgrank;
extern unifycr_index_buf_t unifycr_indices;
extern unifycr_fattr_buf_t unifycr_fattrs;
extern void *unifycr_superblock;
extern unsigned long unifycr_max_index_entries;
extern int unifycr_spillover_max_chunks;

#include "famfs_stats.h"
#include "famfs_env.h"
#include "fam_stripe.h"
#include "lf_client.h"

/* FAM */
extern LFS_CTX_t *lfs_ctx;

//static uint64_t wevents = 1;

//
// =================================
//

/* given a file id and logical chunk id, return pointer to meta data
 * for specified chunk, return NULL if not found */
static unifycr_chunkmeta_t *unifycr_get_chunkmeta(int fid, int cid)
{
    /* lookup file meta data for specified file id */
    unifycr_filemeta_t *meta = unifycr_get_meta_from_fid(fid);
    if (meta != NULL) {
        /* now lookup chunk meta data for specified chunk id */
        if (cid >= 0 && cid < unifycr_max_chunks) {
            unifycr_chunkmeta_t *chunk_meta = &(meta->chunk_meta[cid]);
            return chunk_meta;
        }
    }

    /* failed to find file or chunk id is out of range */
    return (unifycr_chunkmeta_t *)NULL;
}

/* ---------------------------------------
 * Operations on file chunks
 * --------------------------------------- */

/* given a logical chunk id and an offset within that chunk, return the pointer
 * to the memory location corresponding to that location */
static inline void *unifycr_compute_chunk_buf(
    const unifycr_filemeta_t *meta,
    int logical_id,
    off_t logical_offset)
{
    /* get pointer to chunk meta */
    const unifycr_chunkmeta_t *chunk_meta = &(meta->chunk_meta[logical_id]);

    /* identify physical chunk id */
    int physical_id = chunk_meta->id;

    /* compute the start of the chunk */
    char *start = NULL;
    if (physical_id < unifycr_max_chunks) {
        start = unifycr_chunks + ((long)physical_id << unifycr_chunk_bits);
    } else {
        /* chunk is in spill over */
        DEBUG("wrong chunk ID\n");
        return NULL;
    }

    /* now add offset */
    char *buf = start + logical_offset;
    return (void *)buf;
}

static inline int physical_chunk_id(const unifycr_filemeta_t *meta, int logical_id)
{
    return meta->chunk_meta[logical_id].id;
}

/* given a chunk id and an offset within that chunk, return the offset
 * in the spillover file corresponding to that location */
static inline off_t unifycr_compute_spill_offset(
    const unifycr_filemeta_t *meta,
    int logical_id,
    off_t logical_offset)
{
    /* get pointer to chunk meta */
    const unifycr_chunkmeta_t *chunk_meta = &(meta->chunk_meta[logical_id]);

    /* identify physical chunk id */
    int physical_id = chunk_meta->id;
    /* compute start of chunk in spill over device */
    off_t start = 0;
    if (physical_id < unifycr_max_chunks) {
        DEBUG("wrong spill-chunk ID\n");
        return -1;
    } else {
        /* compute buffer loc within spillover device chunk */
        /* account for the unifycr_max_chunks added to identify location when
         * grabbing this chunk */
        start = ((long)(physical_id - unifycr_max_chunks) << unifycr_chunk_bits);
    }
    off_t buf = start + logical_offset;
    return buf;
}

/* allocate a new chunk for the specified file and logical chunk id */
static int unifycr_chunk_alloc(int fid, unifycr_filemeta_t *meta, int chunk_id)
{
    /* get pointer to chunk meta data */
    unifycr_chunkmeta_t *chunk_meta = &(meta->chunk_meta[chunk_id]);
    /* allocate a chunk and record its location */
    if (unifycr_use_memfs) {
        /* allocate a new chunk from memory */
        unifycr_stack_lock();
        int id = unifycr_stack_pop(free_chunk_stack);
        unifycr_stack_unlock();

        /* if we got one return, otherwise try spill over */
        if (id >= 0) {
            /* got a chunk from memory */
            chunk_meta->location = CHUNK_LOCATION_MEMFS;
            chunk_meta->id = id;
        } else if (unifycr_use_spillover) {
            /* shm segment out of space, grab a block from spill-over device */

            DEBUG("getting blocks from spill-over device\n");
            /* TODO: missing lock calls? */
            /* add unifycr_max_chunks to identify chunk location */
            unifycr_stack_lock();
            id = unifycr_stack_pop(free_spillchunk_stack) + unifycr_max_chunks;
            unifycr_stack_unlock();
            if (id < unifycr_max_chunks) {
                DEBUG("spill-over device out of space (%d)\n", id);
                return UNIFYCR_ERR_NOSPC;
            }

            /* got one from spill over */
            chunk_meta->location = CHUNK_LOCATION_SPILLOVER;
            chunk_meta->id = id;
        } else {
            /* spill over isn't available, so we're out of space */
            DEBUG("memfs out of space (%d)\n", id);
            return UNIFYCR_ERR_NOSPC;
        }
    } else if (unifycr_use_spillover) {
        /* memory file system is not enabled, but spill over is */

        /* shm segment out of space, grab a block from spill-over device */
        DEBUG("getting blocks from spill-over device\n");

        /* TODO: missing lock calls? */
        /* add unifycr_max_chunks to identify chunk location */
        unifycr_stack_lock();
        int id = unifycr_stack_pop(free_spillchunk_stack) + unifycr_max_chunks;
        unifycr_stack_unlock();
        if (id < unifycr_max_chunks) {
            DEBUG("spill-over device out of space (%d)\n", id);
            return UNIFYCR_ERR_NOSPC;
        }

        /* got one from spill over */
        chunk_meta->location = CHUNK_LOCATION_SPILLOVER;
        chunk_meta->id = id;
    } else {
        /* don't know how to allocate chunk */
        chunk_meta->location = CHUNK_LOCATION_NULL;
        return UNIFYCR_ERR_IO;
    }

    return UNIFYCR_SUCCESS;
}

static int unifycr_chunk_free(int fid, unifycr_filemeta_t *meta, int chunk_id)
{
    /* get pointer to chunk meta data */
    unifycr_chunkmeta_t *chunk_meta = &(meta->chunk_meta[chunk_id]);

    /* get physical id of chunk */
    int id = chunk_meta->id;
    DEBUG("free chunk %d from location %d\n", id, chunk_meta->location);

    /* determine location of chunk */
    if (chunk_meta->location == CHUNK_LOCATION_MEMFS) {
        unifycr_stack_lock();
        unifycr_stack_push(free_chunk_stack, id);
        unifycr_stack_unlock();
    } else if (chunk_meta->location == CHUNK_LOCATION_SPILLOVER) {
        /* TODO: free spill over chunk */
    } else {
        /* unkwown chunk location */
        DEBUG("unknown chunk location %d\n", chunk_meta->location);
        return UNIFYCR_ERR_IO;
    }

    /* update location of chunk */
    chunk_meta->location = CHUNK_LOCATION_NULL;

    return UNIFYCR_SUCCESS;
}

/* read data from specified chunk id, chunk offset, and count into user buffer,
 * count should fit within chunk starting from specified offset */
static int unifycr_chunk_read(
    unifycr_filemeta_t *meta, /* pointer to file meta data */
    int chunk_id,            /* logical chunk id to read data from */
    off_t chunk_offset,      /* logical offset within chunk to read from */
    void *buf,               /* buffer to store data to */
    size_t count)            /* number of bytes to read */
{
    /* get chunk meta data */
    unifycr_chunkmeta_t *chunk_meta = &(meta->chunk_meta[chunk_id]);

    /* determine location of chunk */
    if (chunk_meta->location == CHUNK_LOCATION_MEMFS) {
        /* just need a memcpy to read data */
        void *chunk_buf = unifycr_compute_chunk_buf(meta, chunk_id, chunk_offset);
        memcpy(buf, chunk_buf, count);
    } else if (chunk_meta->location == CHUNK_LOCATION_SPILLOVER) {
        /* spill over to a file, so read from file descriptor */
        //MAP_OR_FAIL(pread);
        off_t spill_offset = unifycr_compute_spill_offset(meta, chunk_id, chunk_offset);
        ssize_t rc = pread(unifycr_spilloverblock, buf, count, spill_offset);
        /* TODO: check return code for errors */
        if (rc < 0)
            return errno;
    } else {
        /* unknown chunk type */
        DEBUG("unknown chunk type in read\n");
        return UNIFYCR_ERR_IO;
    }

    /* assume read was successful if we get to here */
    return UNIFYCR_SUCCESS;
}

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

    long cur_mem_pos = cur_idx->mem_pos;
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

        cur_mem_pos += index_set->idxes[index_set->count].length;

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
            index_set->idxes[index_set->count].mem_pos = cur_mem_pos;
            if (fs_type == FAMFS) {
                index_set->idxes[index_set->count].nid = cur_idx->nid;
                index_set->idxes[index_set->count].cid = cur_idx->cid;
            }
            cur_mem_pos += index_set->idxes[index_set->count].length;

            cur_slice_start = cur_slice_end + 1;
            cur_slice_end = cur_slice_start + slice_range - 1;
            index_set->count++;

        }

        index_set->idxes[index_set->count].fid = cur_idx->fid;
        index_set->idxes[index_set->count].file_pos = cur_slice_start;
        index_set->idxes[index_set->count].length = cur_idx_end - cur_slice_start + 1;
        index_set->idxes[index_set->count].mem_pos = cur_mem_pos;
        if (fs_type == FAMFS) {
            index_set->idxes[index_set->count].nid = cur_idx->nid;
            index_set->idxes[index_set->count].cid = cur_idx->cid;
        }

        index_set->count++;
    }

    return 0;
}

famfs_mr_list_t known_mrs = {0, NULL};

#define FAMFS_MR_AU 8
#define LMR_BASE_KEY 1000000

int famfs_buf_reg(char *buf, size_t len, void **rid) {
    struct fid_mr *mr;
    N_PARAMS_t *pr = lfs_ctx->lfs_params;
    LF_CL_t    *me = pr->lf_clients[pr->node_id];
    int i;

    if (fs_type != FAMFS)
        return -EINVAL;

    // if local registration is not enabled, do nothing
    if (!pr->lf_mr_flags.local) 
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
            known_mrs.regs = (lf_mreg_t *)realloc(known_mrs.regs, known_mrs.cnt*sizeof(lf_mreg_t));
            if (!known_mrs.regs) {
                err("memory realloc failure");
                return -ENOMEM;
            }
            bzero(&known_mrs.regs[i], sizeof(lf_mreg_t)*FAMFS_MR_AU);
            known_mrs.cnt += FAMFS_MR_AU;
        }
    }
    unsigned long my_key = LMR_BASE_KEY + me->node_id*10000 + local_rank_idx*100 + i;
    ON_FI_ERR_RET(fi_mr_reg(me->domain, buf, len, FI_REMOTE_READ | FI_REMOTE_WRITE, 0, my_key, 0, &known_mrs.regs[i].mreg, NULL), "cln fi_mr_reg failed");

    known_mrs.regs[i].buf = buf;
    known_mrs.regs[i].len = len;
    known_mrs.regs[i].desc = fi_mr_desc(known_mrs.regs[i].mreg);
    *rid = (void *)&known_mrs.regs[i];

    return 0;
}

int famfs_buf_unreg(void *rid) {
    N_PARAMS_t *pr = lfs_ctx->lfs_params;

    if (!pr->lf_mr_flags.local)
        return 0;

    lf_mreg_t *mr = (lf_mreg_t *)rid;
    ON_FI_ERR_RET(fi_close(&mr->mreg->fid), "cln fi_close failed");
    mr->buf = 0;
    mr->len = 0;

    return 0;
}

static void *lookup_mreg(char *buf, size_t len) {
    N_PARAMS_t *pr = lfs_ctx->lfs_params;
    int i; 

    if (!pr->lf_mr_flags.local)
        return NULL;

    for (i = 0; i < known_mrs.cnt; i++) 
        if (buf >= known_mrs.regs[i].buf && buf + len <= known_mrs.regs[i].buf + known_mrs.regs[i].len) 
            break;

    return i == known_mrs.cnt ? NULL : known_mrs.regs[i].desc;
}

struct fid_ep   *saved_ep;
fi_addr_t       *saved_adr;
off_t           saved_off;

int lf_write(char *buf, size_t len,  int chunk_phy_id, off_t chunk_offset, int *trg_ni, off_t *trg_off)
{
    N_PARAMS_t *lfs_params = lfs_ctx->lfs_params;
    N_STRIPE_t *fam_stripe = lfs_ctx->fam_stripe;
    char *const *nodelist = lfs_params->clientlist? lfs_params->clientlist : lfs_params->nodelist;
    N_CHUNK_t *chunk;
    LF_CL_t *node;
    struct famsim_stats *stats_fi_wr;
    struct fid_cntr *cntr;
    fi_addr_t *tgt_srv_addr;
    struct fid_ep *tx_ep;
    //size_t transfer_sz;
    off_t off;
    //int i, blocks;
    int dst_node, rc;
    ALLOCA_CHUNK_PR_BUF(pr_buf);

    /* to FAM chunk */
    chunk = get_fam_chunk(chunk_phy_id, fam_stripe, &dst_node);
    if (chunk == NULL) {
	DEBUG("%d chunk:%d - ENOSPC\n", lfs_params->node_id, chunk_phy_id);
	errno = ENOSPC;
	return UNIFYCR_ERR_NOSPC;
    }
    ASSERT(chunk->lf_client_idx < lfs_params->fam_cnt * lfs_params->node_servers);
    node = lfs_params->lf_clients[chunk->lf_client_idx];

    /* Do RMA synchronous write */
    cntr = node->wcnts[0];
    tgt_srv_addr = &node->tgt_srv_addr[0];
    tx_ep =  node->tx_epp[0];
    chunk->w_event = fi_cntr_read(cntr);
    //transfer_sz = params->transfer_sz;
    //int blocks = len / transfer_sz;
    ASSERT(chunk_offset + len <= unifycr_chunk_size);
    ASSERT(dst_node == node->node_id);
    ASSERT(dst_node < lfs_params->fam_cnt);
    if (trg_ni)
        *trg_ni = dst_node;
    off = chunk_offset + 1ULL * fam_stripe->stripe_in_part * lfs_params->chunk_sz;
    if (trg_off)
        *trg_off = off;

    stats_fi_wr = lfs_ctx->famsim_stats_fi_wr;
    STATS_START(start);

    //for (i = 0; i < blocks; i++) {
    DEBUG("%d: write chunk:%d @%jd to %u/%u/%s(@%lu) on FAM module %d(p%d) len:%zu desc:%p off:%jd mr_key:%lu",
        lfs_params->node_id, chunk_phy_id, chunk_offset,
        fam_stripe->extent, fam_stripe->stripe_in_part, pr_chunk(pr_buf, chunk->data, chunk->parity), (unsigned long)*tgt_srv_addr,
        dst_node, node->partition,
        len, node->local_desc[0], off, node->mr_key);

    famsim_stats_start(famsim_ctx, stats_fi_wr);

    ON_FI_ERROR(
        fi_write(tx_ep, buf, len, lookup_mreg(buf, len), 
            *tgt_srv_addr, off, node->mr_key, (void*)buf),
        "%d (%s): fi_write failed on FAM module %d(p%d)", 
        lfs_params->node_id, nodelist[lfs_params->node_id],
        dst_node, fam_stripe->partition);

    if (chunk_phy_id==0)
        famsim_stats_stop(stats_fi_wr, 1);
    else
        famsim_stats_pause(stats_fi_wr);

	//off += transfer_sz;
	//buf += transfer_sz;
	chunk->w_event++;
    //}

    rc = fi_cntr_wait(cntr, chunk->w_event, lfs_params->io_timeout_ms);
    if (rc == -FI_ETIMEDOUT) {
        err("%d (%s): lf_write timeout chunk:%d to %u/%u/%s on FAM module %d(p%d) len:%zu off:%jd",
	    lfs_params->node_id, nodelist[lfs_params->node_id], chunk_phy_id,
	    fam_stripe->extent, fam_stripe->stripe_in_part, pr_chunk(pr_buf, chunk->data, chunk->parity),
	    dst_node, node->partition, len, off);
    } else if (rc) {
	err("%d (%s): lf_write chunk:%d has %lu error(s):%d to %u/%u/%s on FAM module %d(p%d) cnt:%lu/%lu",
		lfs_params->node_id, nodelist[lfs_params->node_id], chunk_phy_id,
		fi_cntr_readerr(cntr), rc,
		fam_stripe->extent, fam_stripe->stripe_in_part, pr_chunk(pr_buf, chunk->data, chunk->parity),
		dst_node, node->partition,
		fi_cntr_read(cntr), chunk->w_event);
	ON_FI_ERROR(fi_cntr_seterr(cntr, 0), "failed to reset counter error!");
    }

#if 0
    {
        char *vfy = malloc(len);
        cntr = node->rcnts[0];
        chunk->r_event = fi_cntr_read(cntr);
        printf("rcnt=%d\n", chunk->r_event);
    
        int s = fi_read(tx_ep, vfy, len, node->local_desc[0], *tgt_srv_addr, off, node->mr_key, (void*)vfy /* NULL */);
        if (s) {
            printf("vfy failed: %d\n", s);
            free(vfy);
            return s;
        }
        chunk->r_event++;
        printf("wait for rcnt=%d\n", chunk->r_event);
        s = fi_cntr_wait(cntr, chunk->r_event, lfs_params->io_timeout_ms);
        if (s) {
            printf("vfy ctr failed: %d\n", s);
            free(vfy);
            return s;
        }
        printf("=== read *vfy[0]=%lx\n", *(unsigned long *)vfy);
        printf("=== read *vfy[1]=%lx\n", *((unsigned long *)vfy + 1));
        free(vfy);
        saved_ep = tx_ep;
        saved_adr = tgt_srv_addr;
        saved_off = off;
    }
#endif

    UPDATE_STATS(lf_wr_stat, 1, len, start);

    return rc;
}

int lf_fam_read(char *buf, size_t len, off_t fam_off, int nid, unsigned long cid)
{
    N_PARAMS_t *lfs_params = lfs_ctx->lfs_params;
    N_STRIPE_t *fam_stripe = lfs_ctx->fam_stripe;
    //char *const *nodelist = lfs_params->clientlist? lfs_params->clientlist : lfs_params->nodelist;
    N_CHUNK_t *chunk;
    LF_CL_t *node;
    struct fid_cntr *cntr;
    fi_addr_t *tgt_srv_addr;
    struct fid_ep *tx_ep;
    //size_t transfer_sz;
    //int i, blocks;
    int src_node, rc;
    ALLOCA_CHUNK_PR_BUF(pr_buf);

    /* to FAM chunk */
    
    chunk = get_fam_chunk(cid, fam_stripe, &src_node);
    if (chunk == NULL) {
	DEBUG("%d chunk:%jd - ENOSPC\n", lfs_params->node_id, cid);
	errno = ENOSPC;
	return UNIFYCR_ERR_NOSPC;
    }
   
    node = lfs_params->lf_clients[nid];
    ASSERT(src_node == node->node_id);
    ASSERT(src_node == nid);

    /* Do RMA synchronous read */
    cntr = node->rcnts[0];
    tgt_srv_addr = &node->tgt_srv_addr[0];
    tx_ep =  node->tx_epp[0];
    chunk->r_event = fi_cntr_read(cntr);
    //transfer_sz = params->transfer_sz;
    //int blocks = len / transfer_sz;
    /*
    ASSERT(chunk_offset + len <= unifycr_chunk_size);
    ASSERT(dst_node < lfs_params->fam_cnt);
    */

    STATS_START(start);

    off_t coff = fam_off - 1ULL*fam_stripe->stripe_in_part*lfs_params->chunk_sz; 
    DEBUG("%d: read chunk:%jd @%lu to %u/%u/%s(@%lu) on FAM module %d(p%d) len:%zu desc:%p off:%jd mr_key:%lu",
	  lfs_params->node_id, cid, coff,
	  fam_stripe->extent, fam_stripe->stripe_in_part, pr_chunk(pr_buf, chunk->data, chunk->parity), (unsigned long)*tgt_srv_addr,
	  src_node, node->partition,
	  len, node->local_desc[0], fam_off, node->mr_key);

    ON_FI_ERROR(
        fi_read(tx_ep, buf, len, lookup_mreg(buf, len), 
            *tgt_srv_addr, fam_off, node->mr_key, (void*)buf),
        "%d: fi_read failed on FAM module %d(p%d)", lfs_params->node_id, src_node, fam_stripe->partition);

    chunk->r_event++;
    rc = fi_cntr_wait(cntr, chunk->r_event, lfs_params->io_timeout_ms);
    if (rc == -FI_ETIMEDOUT) {
        err("%d: lf_read timeout chunk:%jd to %u/%u/%s on FAM module %d(p%d) len:%zu off:%jd",
	    lfs_params->node_id, cid,
	    fam_stripe->extent, fam_stripe->stripe_in_part, pr_chunk(pr_buf, chunk->data, chunk->parity),
	    src_node, node->partition, len, fam_off);
    } else if (rc) {
	err("%d: lf_read chunk:%jd has %lu error(s):%d to %u/%u/%s on FAM module %d(p%d) cnt:%lu/%lu",
		lfs_params->node_id, cid,
		fi_cntr_readerr(cntr), rc,
		fam_stripe->extent, fam_stripe->stripe_in_part, pr_chunk(pr_buf, chunk->data, chunk->parity),
		src_node, node->partition,
		fi_cntr_read(cntr), chunk->r_event);
	ON_FI_ERROR(fi_cntr_seterr(cntr, 0), "failed to reset counter error!");
    }

    UPDATE_STATS(lf_rd_stat, 1, len, start);

    return rc;
}

static inline long off_in_chunk(long foff) {
    return foff - ((foff >> unifycr_chunk_bits) << unifycr_chunk_bits);
}

static inline long chunk_num(long foff) {
    return foff >> unifycr_chunk_bits;
}


/* read data from specified chunk id, chunk offset, and count into user buffer,
 * count should fit within chunk starting from specified offset */
static int unifycr_logio_chunk_write(
    int fid,
    long pos,                /* write offset inside the file */
    unifycr_filemeta_t *meta, /* pointer to file meta data */
    int chunk_id,            /* logical chunk id to write to */
    off_t chunk_offset,      /* logical offset within chunk to write to */
    const void *buf,         /* buffer holding data to be written */
    size_t count)            /* number of bytes to write */
{
    int my_node;
    off_t my_off;

    /* get chunk meta data */
    unifycr_chunkmeta_t *chunk_meta = &(meta->chunk_meta[chunk_id]);
    /* determine location of chunk */
    if (chunk_meta->location == CHUNK_LOCATION_MEMFS) {
        /* just need a memcpy to write data */
        char *chunk_buf = unifycr_compute_chunk_buf(meta, chunk_id, chunk_offset);
        memcpy(chunk_buf, buf, count);
        /* Synchronize metadata*/

        md_index_t cur_idx;
        cur_idx.file_pos = pos;
        cur_idx.mem_pos = chunk_buf - unifycr_chunks;
        cur_idx.length = count;

        /* find the corresponding file attr entry and update attr*/
        unifycr_fattr_t tmp_meta_entry;
        tmp_meta_entry.fid = fid;
        unifycr_fattr_t *ptr_meta_entry
            = (unifycr_fattr_t *)bsearch(&tmp_meta_entry,
                                         unifycr_fattrs.meta_entry,
                                         *unifycr_fattrs.ptr_num_entries,
                                         sizeof(unifycr_fattr_t), compare_fattr);
        if (ptr_meta_entry !=  NULL) {
            ptr_meta_entry->file_attr.st_size = pos + count;
        }
        cur_idx.fid = ptr_meta_entry->gfid;

        /*split the write requests larger than unifycr_key_slice_range into
         * the ones smaller than unifycr_key_slice_range
         * */
        unifycr_split_index(&cur_idx, &tmp_index_set,
                            unifycr_key_slice_range);

        int i = 0;
        if (*(unifycr_indices.ptr_num_entries) + tmp_index_set.count
            < unifycr_max_index_entries) {
            /*coalesce contiguous indices*/

            if (*unifycr_indices.ptr_num_entries >= 1) {
                md_index_t *ptr_last_idx =
                    &unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries - 1];
                if (ptr_last_idx->fid == tmp_index_set.idxes[0].fid &&
                    ptr_last_idx->file_pos + ptr_last_idx->length
                    == tmp_index_set.idxes[0].file_pos) {
                    if (ptr_last_idx->file_pos / unifycr_key_slice_range
                        == tmp_index_set.idxes[0].file_pos / unifycr_key_slice_range) {
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


                unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries].fid
                    = tmp_index_set.idxes[i].fid;
                (*unifycr_indices.ptr_num_entries)++;
            }



        } else {
            /*TOdO:swap out existing metadata buffer to disk*/
        }

    } else if (chunk_meta->location == CHUNK_LOCATION_SPILLOVER) {
	int i;
        int chunk_phy_id = 0;
        off_t spill_offset = 0;

        /* spill over to a file, so write to file descriptor */
        MAP_OR_FAIL(pwrite);
        if (fs_type != FAMFS) {
            spill_offset = unifycr_compute_spill_offset(meta, chunk_id, chunk_offset);
            /*  printf("spill_offset is %ld, count:%ld, chunk_offset is %ld\n",
                      spill_offset, count, chunk_offset);
              fflush(stdout); */
            ssize_t rc = __real_pwrite(unifycr_spilloverblock, buf, count, spill_offset);
            if (rc < 0)  {
                perror("pwrite failed");
            }
        } else {

            /*  FAMFS: FAM chunk id */
            /* *FIXME* we need linearisation algo for this to work: fam_pos != file_pos :( */
            //chunk_id = chunk_num(pos);
            //chunk_offset = off_in_chunk(pos);

            chunk_phy_id = physical_chunk_id(meta, chunk_id);
            DEBUG("%d: write %zu bytes @%d phy_chunk:%d @%lu\n",
                  lfs_ctx->lfs_params->node_id, count, chunk_id, chunk_phy_id, chunk_offset);
            int rc = lf_write((char *)buf, count, chunk_phy_id, chunk_offset, &my_node, &my_off);
            if (rc) {
                /* Print the real error code */
                ioerr("lf-write failed ret:%d", rc);
                /* Report ENOSPC or EIO */
                if (rc != UNIFYCR_ERR_NOSPC)
                    rc = UNIFYCR_FAILURE;
                return rc;
            }

        }

        /* find the corresponding file attr entry and update attr*/
        md_index_t cur_idx;
        unifycr_fattr_t tmp_meta_entry;
        tmp_meta_entry.fid = fid;
        unifycr_fattr_t *ptr_meta_entry
            = (unifycr_fattr_t *)bsearch(&tmp_meta_entry,
                                         unifycr_fattrs.meta_entry, *unifycr_fattrs.ptr_num_entries,
                                         sizeof(unifycr_fattr_t), compare_fattr);
        if (ptr_meta_entry !=  NULL) {
            ptr_meta_entry->file_attr.st_size = pos + count;
        }
        cur_idx.fid = ptr_meta_entry->gfid;
        cur_idx.file_pos = pos;
        cur_idx.length = count;

        if (fs_type != FAMFS) {

            cur_idx.mem_pos = spill_offset + unifycr_max_chunks * (1 << unifycr_chunk_bits);


            /*split the write requests larger than unifycr_key_slice_range into
             * the ones smaller than unifycr_key_slice_range
             * */
            unifycr_split_index(&cur_idx, &tmp_index_set,
                                unifycr_key_slice_range);
            i = 0;
            if (*(unifycr_indices.ptr_num_entries) + tmp_index_set.count
                < unifycr_max_index_entries) {
                /*coalesce contiguous indices*/

                if (*unifycr_indices.ptr_num_entries >= 1) {
                    md_index_t *ptr_last_idx =
                        &unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries - 1];
                    if (ptr_last_idx->fid == tmp_index_set.idxes[0].fid &&
                        ptr_last_idx->file_pos + ptr_last_idx->length
                        == tmp_index_set.idxes[0].file_pos) {
                        if (ptr_last_idx->file_pos / unifycr_key_slice_range
                            == tmp_index_set.idxes[0].file_pos / unifycr_key_slice_range) {
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

                    unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries].fid
                        = tmp_index_set.idxes[i].fid;
                    (*unifycr_indices.ptr_num_entries)++;
                }

            } else {
                /*Todo:page out existing metadata buffer to disk*/
            }

        /* TOdo: check return code for errors */
        } else {

            cur_idx.mem_pos = my_off;
            cur_idx.nid = my_node; 
            cur_idx.cid = chunk_phy_id;

            /*split the write requests larger than unifycr_key_slice_range into
             * the ones smaller than unifycr_key_slice_range
             * */
            unifycr_split_index(&cur_idx, &tmp_index_set,
                                unifycr_key_slice_range);
            i = 0;
            if (*(unifycr_indices.ptr_num_entries) + tmp_index_set.count
                < unifycr_max_index_entries) {
                /*coalesce contiguous indices*/

                if (*unifycr_indices.ptr_num_entries >= 1) {
                    md_index_t *ptr_last_idx = &unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries - 1];
                    if (ptr_last_idx->fid == tmp_index_set.idxes[0].fid &&
                        ptr_last_idx->file_pos + ptr_last_idx->length
                        == tmp_index_set.idxes[0].file_pos) {
                        if (ptr_last_idx->file_pos / unifycr_key_slice_range
                            == tmp_index_set.idxes[0].file_pos / unifycr_key_slice_range) {
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

                    unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries].fid
                        = tmp_index_set.idxes[i].fid;
                    if (fs_type == FAMFS) {
                        unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries].cid = 
                            tmp_index_set.idxes[i].cid;
                        unifycr_indices.index_entry[*unifycr_indices.ptr_num_entries].nid = 
                            tmp_index_set.idxes[i].nid;
                    }
                    (*unifycr_indices.ptr_num_entries)++;
                }

            } else {
                /*Todo:page out existing metadata buffer to disk*/
            }

        /* TOdo: check return code for errors */
        }
    } else {
        /* unknown chunk type */
        DEBUG("unknown chunk type in read\n");
        return UNIFYCR_ERR_IO;
    }

    /* assume read was successful if we get to here */
    return UNIFYCR_SUCCESS;
}

static int cmp_md(const void *ap, const void *bp) {
    md_index_t *mda = (md_index_t *)ap, *mdb = (md_index_t *)bp;

    if (mda->fid > mdb->fid)
        return 1;
    else if (mda->fid < mdb->fid)
        return -1;
    if (mda->nid > mdb->nid)
        return 1;
    else if (mda->nid < mdb->nid)
        return -1;
    if (mda->cid > mdb->cid)
        return 1;
    else if (mda->cid < mdb->cid)
        return -1;
    if (mda->file_pos > mdb->file_pos)
        return 1;
    else if (mda->file_pos < mdb->file_pos)
        return -1;
    return 0;
}

static inline int same_chunk(md_index_t *a,  md_index_t *b) {
    return (a->fid == b->fid  && a->cid == b->cid && a->nid == b->nid);
}

void famfs_merge_md() {
    md_index_t *mdp = unifycr_indices.index_entry;
    off_t     *nrp = unifycr_indices.ptr_num_entries;

    if (*nrp <= 1)
        return;

    // first, or MD by file id and offset in it
    off_t i, j = 0, n = *nrp;
    qsort(mdp, n, sizeof(md_index_t), cmp_md);

    // merge sequential requests within same chunk
    for (i = 1; i < n; i++) {
        md_index_t *a = &mdp[j], *b =  &mdp[i];
        if (same_chunk(a, b) && b->file_pos == a->file_pos + a->length) {
            a->length += b->length;
            b->length = 0;
            if (a->mem_pos > b->mem_pos)
                a->mem_pos = b->mem_pos;
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

/* read data from specified chunk id, chunk offset, and count into user buffer,
 * count should fit within chunk starting from specified offset */
static int unifycr_chunk_write(
    unifycr_filemeta_t *meta, /* pointer to file meta data */
    int chunk_id,            /* logical chunk id to write to */
    off_t chunk_offset,      /* logical offset within chunk to write to */
    const void *buf,         /* buffer holding data to be written */
    size_t count)            /* number of bytes to write */
{
    /* get chunk meta data */
    unifycr_chunkmeta_t *chunk_meta = &(meta->chunk_meta[chunk_id]);

    /* determine location of chunk */
    if (chunk_meta->location == CHUNK_LOCATION_MEMFS) {
        /* just need a memcpy to write data */
        void *chunk_buf = unifycr_compute_chunk_buf(meta, chunk_id, chunk_offset);
        memcpy(chunk_buf, buf, count);
//        _intel_fast_memcpy(chunk_buf, buf, count);
//        unifycr_memcpy(chunk_buf, buf, count);
    } else if (chunk_meta->location == CHUNK_LOCATION_SPILLOVER) {
        /* spill over to a file, so write to file descriptor */
        //MAP_OR_FAIL(pwrite);
        off_t spill_offset = unifycr_compute_spill_offset(meta, chunk_id, chunk_offset);
        ssize_t rc = pwrite(unifycr_spilloverblock, buf, count, spill_offset);
        if (rc < 0)  {
            perror("pwrite failed");
        }

        /* TODO: check return code for errors */
    } else {
        /* unknown chunk type */
        DEBUG("unknown chunk type in read\n");
        return UNIFYCR_ERR_IO;
    }

    /* assume read was successful if we get to here */
    return UNIFYCR_SUCCESS;
}

/* ---------------------------------------
 * Operations on file storage
 * --------------------------------------- */

/* if length is greater than reserved space, reserve space up to length */
int unifycr_fid_store_fixed_extend(int fid, unifycr_filemeta_t *meta,
                                   off_t length)
{
    /* determine whether we need to allocate more chunks */
    off_t maxsize = meta->chunks << unifycr_chunk_bits;
//      printf("rank %d,meta->chunks is %d, length is %ld, maxsize is %ld\n", dbgrank, meta->chunks, length, maxsize);
    if (length > maxsize) {
        /* compute number of additional bytes we need */
        off_t additional = length - maxsize;
        while (additional > 0) {
            /* check that we don't overrun max number of chunks for file */
            if (meta->chunks == unifycr_max_chunks + unifycr_spillover_max_chunks) {
                return UNIFYCR_ERR_NOSPC;
            }
            /* allocate a new chunk */
            int rc = unifycr_chunk_alloc(fid, meta, meta->chunks);
            if (rc != UNIFYCR_SUCCESS) {
                DEBUG("failed to allocate chunk\n");
                return UNIFYCR_ERR_NOSPC;
            }

            /* increase chunk count and subtract bytes from the number we need */
            meta->chunks++;
            additional -= unifycr_chunk_size;
        }
    }

    return UNIFYCR_SUCCESS;
}

/* if length is shorter than reserved space, give back space down to length */
int unifycr_fid_store_fixed_shrink(int fid, unifycr_filemeta_t *meta,
                                   off_t length)
{
    /* determine the number of chunks to leave after truncating */
    off_t num_chunks = 0;
    if (length > 0) {
        num_chunks = (length >> unifycr_chunk_bits) + 1;
    }

    /* clear off any extra chunks */
    while (meta->chunks > num_chunks) {
        meta->chunks--;
        unifycr_chunk_free(fid, meta, meta->chunks);
    }

    return UNIFYCR_SUCCESS;
}

/* read data from file stored as fixed-size chunks */
int unifycr_fid_store_fixed_read(int fid, unifycr_filemeta_t *meta, off_t pos,
                                 void *buf, size_t count)
{
    int rc;

    /* get pointer to position within first chunk */
    int chunk_id = pos >> unifycr_chunk_bits;
    off_t chunk_offset = pos & unifycr_chunk_mask;

    /* determine how many bytes remain in the current chunk */
    size_t remaining = unifycr_chunk_size - chunk_offset;
    if (count <= remaining) {
        /* all bytes for this read fit within the current chunk */
        rc = unifycr_chunk_read(meta, chunk_id, chunk_offset, buf, count);
    } else {
        /* read what's left of current chunk */
        char *ptr = (char *) buf;
        rc = unifycr_chunk_read(meta, chunk_id, chunk_offset, (void *)ptr, remaining);
        ptr += remaining;

        /* read from the next chunk */
        size_t processed = remaining;
        while (processed < count && rc == UNIFYCR_SUCCESS) {
            /* get pointer to start of next chunk */
            chunk_id++;

            /* compute size to read from this chunk */
            size_t num = count - processed;
            if (num > unifycr_chunk_size) {
                num = unifycr_chunk_size;
            }

            /* read data */
            rc = unifycr_chunk_read(meta, chunk_id, 0, (void *)ptr, num);
            ptr += num;

            /* update number of bytes written */
            processed += num;
        }
    }

    return rc;
}

/* write data to file stored as fixed-size chunks */
int unifycr_fid_store_fixed_write(int fid, unifycr_filemeta_t *meta, off_t pos,
                                  const void *buf, size_t count)
{
    int rc;

    /* TODO: Add memory region cache for libfabric and translate 'buf' to local descriptor */

    /* get pointer to position within first chunk */
    int chunk_id;
    off_t chunk_offset;

    if (meta->storage == FILE_STORAGE_FIXED_CHUNK) {
        chunk_id = pos >> unifycr_chunk_bits;
        chunk_offset = pos & unifycr_chunk_mask;
    } else if (meta->storage == FILE_STORAGE_LOGIO) {
        chunk_id = meta->size >> unifycr_chunk_bits;
        chunk_offset = meta->size & unifycr_chunk_mask;
    } else {
        return UNIFYCR_ERR_IO;
    }

    /* determine how many bytes remain in the current chunk */
    size_t remaining = unifycr_chunk_size - chunk_offset;
    if (count <= remaining) {
        /* all bytes for this write fit within the current chunk */
        if (meta->storage == FILE_STORAGE_FIXED_CHUNK) {
            rc = unifycr_chunk_write(meta, chunk_id, chunk_offset, buf, count);
        } else if (meta->storage == FILE_STORAGE_LOGIO) {
            rc = unifycr_logio_chunk_write(fid, pos, meta, chunk_id, chunk_offset,
                                           buf, count);
        } else {
            return UNIFYCR_ERR_IO;
        }
    } else {
        /* otherwise, fill up the remainder of the current chunk */
        char *ptr = (char *) buf;
        if (meta->storage == FILE_STORAGE_FIXED_CHUNK) {
            rc = unifycr_chunk_write(meta, chunk_id, chunk_offset, (void *)ptr, remaining);
        } else if (meta->storage == FILE_STORAGE_LOGIO) {
            rc = unifycr_logio_chunk_write(fid, pos, meta, chunk_id, chunk_offset,
                                           (void *)ptr, remaining);
        } else {
            return UNIFYCR_ERR_IO;
        }

        ptr += remaining;
        pos += remaining;

        /* then write the rest of the bytes starting from beginning
         * of chunks */
        size_t processed = remaining;
        while (processed < count && rc == UNIFYCR_SUCCESS) {
            /* get pointer to start of next chunk */
            chunk_id++;

            /* compute size to write to this chunk */
            size_t num = count - processed;
            if (num > unifycr_chunk_size) {
                num = unifycr_chunk_size;
            }

            /* write data */
            if (meta->storage == FILE_STORAGE_FIXED_CHUNK) {
                rc = unifycr_chunk_write(meta, chunk_id, 0, (void *)ptr, num);
            } else if (meta->storage == FILE_STORAGE_LOGIO)
                rc = unifycr_logio_chunk_write(fid, pos, meta, chunk_id, 0,
                                               (void *)ptr, num);
            else {
                return UNIFYCR_ERR_IO;
            }
            ptr += num;
            pos += num;

            /* update number of bytes processed */
            processed += num;
        }
    }

    return rc;
}
