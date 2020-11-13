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
 * Written by: Teng Wang, Adam Moody, Wekuan Yu, Kento Sato, Kathryn Mohror
 * LLNL-CODE-728877. All rights reserved.
 *
 * This file is part of burstfs.
 * For details, see https://github.com/llnl/burstfs
 * Please read https://github.com/llnl/burstfs/LICNSE for full license text.
 */

#include "mdhim.h"
#include "indexes.h"
#include "log.h"
#include "famfs_maps.h"
#include "unifycr_metadata.h"
#include "arraylist.h"
#include "unifycr_const.h"
#include "famfs_global.h"
#include "f_pool.h"
#include "f_layout.h"
#include "f_layout_ctl.h"


fsmd_key_t **fsmd_keys;
fsmd_val_t **fsmd_vals;

fattr_key_t **fattr_keys;
fattr_val_t **fattr_vals;

struct mdhim_brm_t *brm, *brmp;
struct mdhim_bgetrm_t *bgrm, *bgrmp;
struct mdhim_t *md;

int fsmd_key_lens[MAX_META_PER_SEND] = {0};
int unifycr_val_lens[MAX_META_PER_SEND] = {0};

int fattr_key_lens[MAX_FILE_CNT_PER_NODE] = {0};
int fattr_val_lens[MAX_FILE_CNT_PER_NODE] = {0};

/* Need two maps per layout: CV and SM */
#define F_MD_IDX_MAPS_END	(F_MD_IDX_MAPS_START + F_LAYOUTS_MAX *2 - 1)
#define F_MD_IDX_SIZE		(F_MD_IDX_MAPS_END + 1)
struct index_t *unifycr_indexes[F_MD_IDX_SIZE];
int page_sz;

extern char *mds_vec;
extern int  num_mds;

static int create_persistent_map(F_MAP_INFO_t *info, int intl, char *name);
static ssize_t ps_bget(unsigned long *buf, int map_id, size_t size, uint64_t *keys, int op);
static int ps_bput(unsigned long *buf, int map_id, size_t size, void **keys,
    size_t value_len);
static int ps_bdel(int map_id, size_t size, void **keys);

static F_META_IFACE_t iface = {
	.create_map_fn = &create_persistent_map,
	.bget_fn = &ps_bget,
	.bput_fn = &ps_bput,
	.bdel_fn = &ps_bdel,
};

/* metadata configuration: set DB options and map interface */
int meta_init_conf(unifycr_cfg_t *server_cfg_p, mdhim_options_t **db_opts_p)
{
    f_set_meta_iface(&iface);
    return mdhim_options_cfg(server_cfg_p, db_opts_p);
}

/**
* initialize the key-value store
*/
int meta_init_store(mdhim_options_t *db_opts)
{
    int i, rc;

    db_opts->db_key_type = MDHIM_UNIFYCR_KEY;
    if (mds_vec)
	db_opts->rserver_factor = 1;

    md = mdhimInit(NULL, db_opts);

    /*this index is created for storing index metadata*/
    unifycr_indexes[0] = md->primary_index;


    /*this index is created for storing file attribute metadata*/
    unifycr_indexes[1] = create_global_index(md, md->db_opts->rserver_factor, 1,
                         LEVELDB, MDHIM_INT_KEY, "file_attr");

    unifycr_indexes[2] = create_global_index(md, md->db_opts->rserver_factor, 1,
                         LEVELDB, MDHIM_INT_KEY, "fam_map");

    for (i = F_MD_IDX_MAPS_START; i <= F_MD_IDX_MAPS_END; i++)
	unifycr_indexes[i] = NULL;

    rc = meta_init_indices();
    if (rc != 0) {
        return -1;
    }

    page_sz = getpagesize();
    return 0;
}

static int create_persistent_map(F_MAP_INFO_t *info, int intl, char *name)
{
    unsigned int id = F_MD_IDX_MAPS_START + (unsigned)info->map_id;

    if (!IN_RANGE(id, F_MD_IDX_MAPS_START, F_MD_IDX_MAPS_END) ||
	intl < 0 || md == NULL)
	    return -1;
    if (unifycr_indexes[id] == NULL) {
	unifycr_indexes[id] = create_global_index(md, md->db_opts->rserver_factor,
					intl, LEVELDB, MDHIM_LONG_INT_KEY, name);
	if (unifycr_indexes[id] == NULL)
		return -1;
	/* don't use stats */
	unifycr_indexes[id]->has_stats = 0;
    }

    /* If no range server running, set RO flag to protect persistent map */
    if (unifycr_indexes[id]->myinfo.rangesrv_num == 0)
	info->ro = 1;

    return 0;
}

/**
* initialize the key and value list used to
* put/get key-value pairs
* ToDo: split once the number of metadata exceeds MAX_META_PER_SEND
*/
int meta_init_indices()
{

    int i;

    /*init index metadata*/
    fsmd_keys = (fsmd_key_t **)malloc(MAX_META_PER_SEND
                                            * sizeof(fsmd_key_t *));

    fsmd_vals = (fsmd_val_t **)malloc(MAX_META_PER_SEND
                                            * sizeof(fsmd_val_t *));

    for (i = 0; i < MAX_META_PER_SEND; i++) {
        fsmd_keys[i] = (fsmd_key_t *)malloc(sizeof(fsmd_key_t));

        if (!fsmd_keys[i]) {
            return ULFS_ERROR_NOMEM;
        }
        memset(fsmd_keys[i], 0, sizeof(fsmd_key_t));
    }

    for (i = 0; i < MAX_META_PER_SEND; i++) {
        fsmd_vals[i] = (fsmd_val_t *)malloc(sizeof(fsmd_val_t));
        if (!fsmd_vals[i]) {
            return ULFS_ERROR_NOMEM;
        };
        memset(fsmd_vals[i], 0, sizeof(fsmd_val_t));
    }

    /*init attribute metadata*/
    fattr_keys = (fattr_key_t **)malloc(MAX_FILE_CNT_PER_NODE
                                        * sizeof(fattr_key_t *));

    fattr_vals = (fattr_val_t **)malloc(MAX_FILE_CNT_PER_NODE
                                        * sizeof(fattr_val_t *));

    for (i = 0; i < MAX_FILE_CNT_PER_NODE; i++) {
        fattr_keys[i] = (fattr_key_t *)malloc(sizeof(fattr_key_t));

        if (!fattr_keys[i]) {
            return ULFS_ERROR_NOMEM;
        }
        memset(fattr_keys[i], 0, sizeof(fattr_key_t));
    }

    for (i = 0; i < MAX_FILE_CNT_PER_NODE; i++) {
        fattr_vals[i] = (fattr_val_t *)malloc(sizeof(fattr_val_t));
        if (!fattr_vals[i]) {
            return ULFS_ERROR_NOMEM;
        };
        memset(fattr_vals[i], 0, sizeof(fattr_val_t));
    }

    return 0;

}

/**
* store the file attribute to the key-value store
* @param buf: file attribute received from the client
* @param qid: the connection id in poll_set of
* the delegator
* @return success/error code
*/
int meta_process_attr_set(char *buf, int qid)
{
    int rc = ULFS_SUCCESS;

    f_fattr_t *ptr_fattr =
        (f_fattr_t *)(buf + 2 * sizeof(int));

    *fattr_keys[0] = ptr_fattr->gfid;
    fattr_vals[0]->file_attr = ptr_fattr->file_attr;
    strcpy(fattr_vals[0]->fname, ptr_fattr->filename);

    /*  LOG(LOG_DBG, "rank:%d, setting fattr key:%d, value:%s\n",
                glb_rank, *fattr_keys[0], fattr_vals[0]->fname); */
    brm = mdhimPut(md, unifycr_indexes[1],
                   fattr_keys[0], sizeof(fattr_key_t),
                   fattr_vals[0], sizeof(fattr_val_t),
                   NULL, NULL);
    if (!brm || brm->error) {
        LOG(LOG_ERR, "client %d, no such gfid:%d", qid, *fattr_keys[0]);
        rc = ULFS_ERROR_MDHIM;
    } else {
        rc = ULFS_SUCCESS;
    }

    mdhim_full_release_msg(brm);

    return rc;
}

int f_do_fattr_set(f_svcrq_t *pcmd, f_fattr_t *pval) {
    int rc = ULFS_SUCCESS;

    *fattr_keys[0] = pval->gfid;
    fattr_vals[0]->file_attr = pval->file_attr;
    strcpy(fattr_vals[0]->fname, pval->filename);
    fattr_vals[0]->loid = pval->loid;

    brm = mdhimPut(md, unifycr_indexes[1],
                   fattr_keys[0], sizeof(fattr_key_t),
                   fattr_vals[0], sizeof(fattr_val_t),
                   NULL, NULL);
    if (!brm || brm->error) {
        LOG(LOG_ERR, "client %d, setting attributes for gfid %d error:%d",
            pcmd->cid, *fattr_keys[0], brm?brm->error:0);
        rc = ULFS_ERROR_MDHIM;
    } else {
        LOG(LOG_DBG, "client %d, setting fattr gfid %d in lo %d",
            pcmd->cid, *fattr_keys[0], fattr_vals[0]->loid);
        rc = ULFS_SUCCESS;
    }

    mdhim_full_release_msg(brm);

    return rc;
}



/* get the file attribute from the key-value store
* @param buf: a buffer that stores the gid
* @param qid: the connection id in poll_set of the delegator
* @return success/error code
*/
int meta_process_attr_get(char *buf, int qid, f_fattr_t *ptr_attr_val)
{
    *fattr_keys[0] = *((int *)(buf + 2 * sizeof(int)));
    fattr_val_t *tmp_ptr_attr;

    int rc;

    bgrm = mdhimGet(md, unifycr_indexes[1],
                    fattr_keys[0],
                    sizeof(fattr_key_t), MDHIM_GET_EQ);

    if (!bgrm || bgrm->error) {
        LOG(LOG_ERR, "client %d, no such file id:%d", qid, *fattr_keys[0]);
        rc = ULFS_ERROR_MDHIM;
    } else {
        tmp_ptr_attr = (fattr_val_t *)bgrm->values[0];
        ptr_attr_val->gfid = *fattr_keys[0];

        /*  LOG(LOG_DBG, "rank:%d, getting fattr key:%d\n",
                    glb_rank, *fattr_keys[0]); */
        ptr_attr_val->file_attr = tmp_ptr_attr->file_attr;
        strcpy(ptr_attr_val->filename, tmp_ptr_attr->fname);

        rc = ULFS_SUCCESS;
    }

    mdhim_full_release_msg(bgrm);
    return rc;
}

int f_do_fattr_get(f_svcrq_t *pcmd, f_fattr_t *pval) {
    *fattr_keys[0] = pcmd->fm_gfid;
    fattr_val_t *tmp_ptr_attr;

    int rc;

    bgrm = mdhimGet(md, unifycr_indexes[1], fattr_keys[0],
                    sizeof(fattr_key_t), MDHIM_GET_EQ);

    if (!bgrm || bgrm->error) {
        LOG(LOG_ERR, "client %d, gfid %d - error %d getting file attributes",
	    pcmd->cid, *fattr_keys[0], bgrm?bgrm->error:0);
        rc = ULFS_ERROR_MDHIM;
    } else {
        pval->gfid = *fattr_keys[0];
        tmp_ptr_attr = (fattr_val_t *)bgrm->values[0];
        pval->file_attr = tmp_ptr_attr->file_attr;
        pval->loid = tmp_ptr_attr->loid;
        strcpy(pval->filename, tmp_ptr_attr->fname);

        LOG(LOG_DBG, "client %d, got fattr for layout %d gfid %d",
            pcmd->cid, tmp_ptr_attr->loid, pval->gfid);

        rc = ULFS_SUCCESS;
    }

    mdhim_full_release_msg(bgrm);
    return rc;
}

int meta_famattr_put(int fam_id, fam_attr_val_t *val)
{
    size_t val_sz;
    uint32_t key;
    int rc;

    if (fam_id < 0)
        key = MDHIM_MAX_SLICES;
    else
        key = (uint32_t)fam_id;
    *fattr_keys[0] = key;
    val_sz = fam_attr_val_sz(val->part_cnt);
    LOG(LOG_DBG, "key:%u size:%zu cnt:%u prov_key:%lu virt_addr:%016lx",
        key, val_sz, val->part_cnt, val->part_attr[0].prov_key,
        val->part_attr[0].virt_addr);
    brm = mdhimPut(md, unifycr_indexes[2],
                   fattr_keys[0], sizeof(fattr_key_t),
		   val, val_sz, NULL, NULL);

    if (!brm || brm->error) {
        LOG(LOG_ERR, "error storing FAM %d attributes:%d", fam_id, brm?brm->error:0);
	rc = ULFS_ERROR_MDHIM;
    } else
	rc = ULFS_SUCCESS;

    mdhim_full_release_msg(brm);

    return rc;
}

int meta_famattr_get(int fam_id, fam_attr_val_t **val_p)
{
    *fattr_keys[0] = fam_id;
    fam_attr_val_t *tmp_ptr_attr;

    int rc;

    bgrm = mdhimGet(md, unifycr_indexes[2], fattr_keys[0],
		    sizeof(fattr_key_t), MDHIM_GET_EQ);

    if (!bgrm || bgrm->error) {
        LOG(LOG_ERR, "error getting FAM %d attributes:%d", fam_id, brm?brm->error:0);
	*val_p = NULL;
	rc = ULFS_ERROR_MDHIM;
    } else {
	size_t size;

	tmp_ptr_attr = (fam_attr_val_t *)bgrm->values[0];
	*val_p = (fam_attr_val_t *)malloc(fam_attr_val_sz(tmp_ptr_attr->part_cnt));
	(*val_p)->part_cnt = tmp_ptr_attr->part_cnt;
	size = tmp_ptr_attr->part_cnt*sizeof(LFS_EXCG_t);
	memcpy((*val_p)->part_attr, tmp_ptr_attr->part_attr, size);
        LOG(LOG_DBG, "key:%u size:%zu cnt:%u prov_key:%lu virt_addr:%016lx",
	    *((int*)fattr_keys[0]), size,
	    (*val_p)->part_cnt, (*val_p)->part_attr[0].prov_key,
	    (*val_p)->part_attr[0].virt_addr);

        rc = ULFS_SUCCESS;
    }

    mdhim_full_release_msg(bgrm);
    return rc;
}

/*synchronize all the indices and file attributes
* to the key-value store
* @param qid: the connection id in poll_set of the delegator
* @return success/error code
*/
int meta_process_fsync(int qid)
{
    int i, ret = 0;

    int app_id = invert_qids[qid];
    app_config_t *app_config = (app_config_t *)arraylist_get(app_config_list,
                               app_id);

    int client_side_id = app_config->client_ranks[qid];

    unsigned long num_entries =
        *((unsigned long *)(app_config->shm_superblocks[client_side_id]
                            + app_config->meta_offset));
    if (num_entries == 0)
        goto _process_fattr;

    /* indices are stored in the superblock shared memory
     *  created by the client*/
    md_index_t *meta_payload =
        (md_index_t *)(app_config->shm_superblocks[client_side_id]
                            + app_config->meta_offset + page_sz);

    for (i = 0; i < num_entries; i++) {
        fsmd_keys[i]->pk.fid = meta_payload[i].fid;
        fsmd_keys[i]->pk.loid = 0;
        fsmd_keys[i]->offset = meta_payload[i].file_pos;
        fsmd_vals[i]->addr = meta_payload[i].mem_pos;
        fsmd_vals[i]->len = meta_payload[i].length;

        fsmd_vals[i]->delegator_id = glb_rank;
        memcpy((char *) & (fsmd_vals[i]->app_rank_id), &app_id, sizeof(int));
        memcpy((char *) & (fsmd_vals[i]->app_rank_id) + sizeof(int),
               &client_side_id, sizeof(int));

        fsmd_key_lens[i] = sizeof(fsmd_key_t);
        unifycr_val_lens[i] = sizeof(fsmd_val_t);
    }

    //print_fsync_indices(fsmd_keys, fsmd_vals, num_entries);

    if (num_entries == 1) {
        brm = mdhimPut(md, unifycr_indexes[0],
                       fsmd_keys[0], sizeof(fsmd_key_t),
                       fsmd_vals[0], sizeof(fsmd_val_t),
                       NULL, NULL);
        if (!brm || brm->error) {
            ret = ULFS_ERROR_MDHIM;
            LOG(LOG_DBG, "Rank - %d: Error inserting keys/values into MDHIM\n",
                md->mdhim_rank);
        } else {
            ret = ULFS_SUCCESS;
        }
        mdhim_full_release_msg(brm);

    } else {
        brm = mdhimBPut(md, unifycr_indexes[0],
                        (void **)(&fsmd_keys[0]), fsmd_key_lens,
                        (void **)(&fsmd_vals[0]), unifycr_val_lens, num_entries,
                        NULL, NULL);
        brmp = brm;
        if (!brmp || brmp->error) {
            ret = ULFS_ERROR_MDHIM;
            LOG(LOG_DBG, "Rank - %d: Error inserting keys/values into MDHIM\n",
                md->mdhim_rank);
        }

        while (brmp) {
            if (brmp->error < 0) {
                ret = ULFS_ERROR_MDHIM;
                break;
            }

            brm = brmp;
            brmp = brmp->next;
            mdhim_full_release_msg(brm);
        }
    }

_process_fattr:
    num_entries =
        *((unsigned long *)(app_config->shm_superblocks[client_side_id]
                            + app_config->fmeta_offset));
    //printf("sync to process %d attrs\n", num_entries);
    if (num_entries == 0)
        return ret;

    /* file attributes are stored in the superblock shared memory
     * created by the client*/
    f_fattr_t *attr_payload =
        (f_fattr_t *)(app_config->shm_superblocks[client_side_id]
                + app_config->fmeta_offset + page_sz);


    for (i = 0; i < num_entries; i++) {
        *fattr_keys[i] = attr_payload[i].gfid;
        fattr_vals[i]->file_attr = attr_payload[i].file_attr;
        strcpy(fattr_vals[i]->fname, attr_payload[i].filename);

        fattr_key_lens[i] = sizeof(fattr_key_t);
        fattr_val_lens[i] = sizeof(fattr_val_t);
    }

    if (num_entries == 1) {
        brm = mdhimPut(md, unifycr_indexes[1],
                       fattr_keys[0], sizeof(fattr_key_t),
                       fattr_vals[0], sizeof(fattr_val_t),
                       NULL, NULL);
        if (!brm || brm->error) {
            ret = ULFS_ERROR_MDHIM;
            LOG(LOG_DBG, "Rank - %d: Error inserting keys/values into MDHIM\n",
                md->mdhim_rank);
        } else {
            ret = ULFS_SUCCESS;
        }
        mdhim_full_release_msg(brm);

    } else {
        brm = mdhimBPut(md, unifycr_indexes[1],
                        (void **)(&fattr_keys[0]), fattr_key_lens,
                        (void **)(&fattr_vals[0]), fattr_val_lens, num_entries,
                        NULL, NULL);
        brmp = brm;
        if (!brmp || brmp->error) {
            ret = ULFS_ERROR_MDHIM;
            LOG(LOG_DBG, "Rank - %d: Error inserting keys/values into MDHIM\n",
                md->mdhim_rank);
        }

        while (brmp) {
            if (brmp->error < 0) {
                ret = ULFS_ERROR_MDHIM;
                break;
            }

            brm = brmp;
            brmp = brmp->next;
            mdhim_full_release_msg(brm);
        }
    }

    return ret;
}

int f_do_fsync(f_svcrq_t *pcmd) {
    struct index_t *index = unifycr_indexes[0];
    struct mdhim_bput2m_t *bput2m;
    mdhim_basem_t *bm;
    int i, ret = 0;

    int qid = pcmd->cid;
    int app_id = invert_qids[qid];
    app_config_t *app_config = (app_config_t *)arraylist_get(app_config_list, app_id);

    int client_side_id = app_config->client_ranks[qid];

    unsigned long num_entries =
        *((unsigned long *)(app_config->shm_superblocks[client_side_id] + 
        app_config->meta_offset));

    if (num_entries == 0) {
        LOG(LOG_DBG, "nothing to fsync");
        goto _process_fattr;
    }

    /* indices are stored in the superblock shared memory
     *  created by the client*/
    md_index_t *meta_payload =
        (md_index_t *)(app_config->shm_superblocks[client_side_id]
                            + app_config->meta_offset + page_sz);

    LOG(LOG_DBG, "srv fsync from qid %d rank [%d] k/v num=%lu meta_offset=%ld",
        qid, client_side_id, num_entries, app_config->meta_offset);

    /* Create BULK_PUT2 message */
    bput2m = (struct mdhim_bput2m_t *) malloc(mdhim_bput2m_alloc_sz(num_entries));
    if (!bput2m) {
	ret = -errno;
	goto _exit;
    }
    bm = &bput2m->basem;
    bm->mtype = MDHIM_BULK_PUT2;
    bm->size = mdhim_bput2m_alloc_sz(num_entries);
    bm->server_rank = -1; /* to be set at bput2_records() */
    bm->index = index->id;
    bm->index_type = index->type;
    bm->seg_count = 1;

    /* message payload */
    fsmd_kv_t *kvs = &bput2m->seg.kvs[0];
    bput2m->seg.seg_id = 0;
    bput2m->seg.num_keys = num_entries;
    bput2m->seg.key_len = sizeof(fsmd_key_t);
    bput2m->seg.kv_length = sizeof(fsmd_kv_t);
    memcpy(kvs, meta_payload, num_entries*sizeof(fsmd_kv_t)); 

    IF_LOG(LOG_DBG3) {
	fsmd_kv_t *kv = kvs;
	for (i = 0; i < num_entries; i++, kv++) {

	    LOG(LOG_DBG3, "  k/v[%d] loid=%d fid=%d off/len=%ld/%ld addr=%ld s=%lu",
		i, kv->k.pk.loid, kv->k.pk.fid, kv->k.offset,
		kv->v.len, kv->v.addr, kv->v.stripe);
	}
    }

    brm = bput2_records(md, index, bput2m);
    free(bput2m);

    brmp = brm;
    if (!brmp) {
	ret = ULFS_ERROR_MDHIM;
	LOG(LOG_DBG, "Rank - %d: Error inserting keys/values into MDHIM\n",
	    md->mdhim_rank);
    }

    while (brmp) {
	if (brmp->error) {
	    ret = ULFS_ERROR_MDHIM;
	    LOG(LOG_DBG, "Rank - %d: Error inserting keys/values into MDHIM - %d\n",
		md->mdhim_rank, brmp->error);
	    break;
	}

	brm = brmp;
	brmp = brmp->next;
	mdhim_full_release_msg(brm);
    }

_process_fattr:
    num_entries =
        *((unsigned long *)(app_config->shm_superblocks[client_side_id]
                            + app_config->fmeta_offset));
    if (num_entries == 0) {
        LOG(LOG_DBG, "no file attribute entries to sync");
        return 0;
    }

    /* file attributes are stored in the superblock shared memory
     * created by the client*/
    f_fattr_t *attr_payload =
        (f_fattr_t *)(app_config->shm_superblocks[client_side_id]
                + app_config->fmeta_offset + page_sz);


    for (i = 0; i < num_entries; i++) {
        *fattr_keys[i] = attr_payload[i].gfid;
        fattr_vals[i]->loid = attr_payload[i].loid;
        fattr_vals[i]->file_attr = attr_payload[i].file_attr;
        strcpy(fattr_vals[i]->fname, attr_payload[i].filename);

        fattr_key_lens[i] = sizeof(fattr_key_t);
        fattr_val_lens[i] = sizeof(fattr_val_t);
    }

    if (num_entries == 1) {
        brm = mdhimPut(md, unifycr_indexes[1],
                       fattr_keys[0], sizeof(fattr_key_t),
                       fattr_vals[0], sizeof(fattr_val_t),
                       NULL, NULL);
        if (!brm || brm->error) {
            ret = ULFS_ERROR_MDHIM;
            LOG(LOG_DBG, "Rank - %d: Error inserting keys/values into MDHIM\n",
                md->mdhim_rank);
        } else {
            ret = ULFS_SUCCESS;
        }
        mdhim_full_release_msg(brm);

    } else {
        brm = mdhimBPut(md, unifycr_indexes[1],
                        (void **)(&fattr_keys[0]), fattr_key_lens,
                        (void **)(&fattr_vals[0]), fattr_val_lens, num_entries,
                        NULL, NULL);
        brmp = brm;
        if (!brmp || brmp->error) {
            ret = ULFS_ERROR_MDHIM;
            LOG(LOG_DBG, 
                "Rank - %d: Error inserting keys/values into MDHIM\n", md->mdhim_rank);
        }

        while (brmp) {
            if (brmp->error < 0) {
                ret = ULFS_ERROR_MDHIM;
                break;
            }

            brm = brmp;
            brmp = brmp->next;
            mdhim_full_release_msg(brm);
        }
    }

_exit:
    LOG(LOG_DBG, "fsync sts=%d", ret);
    return ret;
}

/* get the locations of all the requested file segments from
 * the key-value store.
* @param app_id: client's application id
* @param client_id: client-side process id
* @param del_req_set: the set of read requests to be
* @param thrd_id: the thread created for processing
* its client's read requests.
* @param dbg_rank: the client process's rank in its
* own application, used for debug purpose
* @param shm_reqbuf: the shared request memory that
* contains all the client's read requests
* @del_req_set: contains metadata information for all
* the read requests, such as the locations of the
* requested segments
* @return success/error code
*/
int meta_batch_get(int app_id, int client_id,
                   int thrd_id, int dbg_rank, char *shm_reqbuf, int num,
                   msg_meta_t *del_req_set)
{
    shm_meta_t *tmp_cli_req = (shm_meta_t *) shm_reqbuf;

    int i, rc = 0;
    for (i = 0; i < num; i++) {
        fsmd_keys[2 * i]->fid = \
        fsmd_keys[2 * i + 1]->fid = tmp_cli_req[i].src_fid;
        fsmd_keys[2 * i]->offset = tmp_cli_req[i].offset;
        fsmd_keys[2 * i + 1]->offset =
            tmp_cli_req[i].offset + tmp_cli_req[i].length - 1;
        fsmd_key_lens[2 * i] = \
        fsmd_key_lens[2 * i + 1] = sizeof(fsmd_key_t);

    }

    bgrm = mdhimBGet(md, unifycr_indexes[0],
                     (void **)fsmd_keys,
                     fsmd_key_lens, 2 * num, MDHIM_RANGE_BGET);

    int tot_num = 0;
    int dest_client, dest_app;
    fsmd_key_t *tmp_key;
    fsmd_val_t *tmp_val;

    bgrmp = bgrm;
    while (bgrmp) {
        if (bgrmp->error < 0) {
            rc = ULFS_ERROR_MDHIM;
        }

        for (i = 0; i < bgrmp->num_keys; i++) {
            tmp_key = (fsmd_key_t *)bgrm->keys[i];
            tmp_val = (fsmd_val_t *)bgrm->values[i];

            memcpy(&dest_app, (char *) & (tmp_val->app_rank_id), sizeof(int));
            memcpy(&dest_client, (char *) & (tmp_val->app_rank_id)
                   + sizeof(int), sizeof(int));
            /* rank of the remote delegator*/
            del_req_set->msg_meta[tot_num].dest_delegator_rank = tmp_val->delegator_id;

            /* physical offset of the requested file segment on the log file*/
            del_req_set->msg_meta[tot_num].dest_offset = tmp_val->addr;

            /* dest_client_id and dest_app_id uniquely identifies the remote physical
             * log file that contains the requested segments*/
            del_req_set->msg_meta[tot_num].dest_client_id = dest_client;
            del_req_set->msg_meta[tot_num].dest_app_id = dest_app;
            del_req_set->msg_meta[tot_num].length = tmp_val->len;

            /* src_app_id and src_cli_id identifies the requested client*/
            del_req_set->msg_meta[tot_num].src_app_id = app_id;
            del_req_set->msg_meta[tot_num].src_cli_id = client_id;

            /* src_offset is the logical offset of the shared file*/
            del_req_set->msg_meta[tot_num].src_offset = tmp_key->offset;
            del_req_set->msg_meta[tot_num].src_delegator_rank = glb_rank;
            del_req_set->msg_meta[tot_num].src_fid = tmp_key->fid;
            del_req_set->msg_meta[tot_num].src_dbg_rank = dbg_rank;
            del_req_set->msg_meta[tot_num].src_thrd = thrd_id;
            tot_num++;
        }
        bgrmp = bgrmp->next;
        mdhim_full_release_msg(bgrm);
        bgrm = bgrmp;
    }

    del_req_set->num = tot_num;
//    print_bget_indices(app_id, client_id, del_req_set->msg_meta, tot_num);

    return rc;
}

int meta_md_get(char *shm_reqbuf, int num, fsmd_kv_t *res_kv, int *total_kv) {

    int tot_num = 0;
    shm_meta_t *tmp_cli_req = (shm_meta_t *)shm_reqbuf;
    int legacy = (fam_fs == 0);
    F_POOL_t *pool = f_get_pool();
    F_SLABMAP_ENTRY_t *sme;
    F_MAP_KEYSET_u *keysets = NULL;

    int i, j, rc = 0;
    for (i = 0; i < num; i++) {
        /* legacy delegator shall not set layout id */
        if (legacy && tmp_cli_req[i].loid) {
            LOG(LOG_FATAL, " srv: md req %d of %d: loid=%d? fid=%d",
                i+1, num, tmp_cli_req[i].loid, tmp_cli_req[i].src_fid);
            return ULFS_ERROR_MDHIM;
        }
        /* pack loid, fid into MD key 'fid' */
        fsmd_keys[2*i]->pk.loid     = \
        fsmd_keys[2*i + 1]->pk.loid = tmp_cli_req[i].loid;
        fsmd_keys[2*i]->pk.fid      = \
        fsmd_keys[2*i + 1]->pk.fid  = tmp_cli_req[i].src_fid;

        fsmd_keys[2*i]->offset      = tmp_cli_req[i].offset;
        fsmd_keys[2*i + 1]->offset  = tmp_cli_req[i].offset + tmp_cli_req[i].length - 1;
        fsmd_key_lens[2*i]          = sizeof(fsmd_key_t);
        fsmd_key_lens[2*i + 1]      = sizeof(fsmd_key_t);
    }

    IF_LOG(LOG_DBG3) {
	LOG(LOG_DBG3, "srv: md req %d keys:", num);
	for (i = 0; i < num; i++) {
	    LOG(LOG_DBG3, "  [%d] lo %d fid=%d off=%jd/%jd len=%d",
		i, fsmd_keys[2*i]->pk.loid, fsmd_keys[2*i]->pk.fid,
		fsmd_keys[2*i]->offset,
		fsmd_keys[2*i + 1]->offset, fsmd_key_lens[2*i]);
	}
    }

    bgrm = mdhimBGet(md, unifycr_indexes[0],
                     (void **)fsmd_keys,
                     fsmd_key_lens, 2 * num, MDHIM_RANGE_BGET);

    bgrmp = bgrm;
    while (bgrmp) {
        if (bgrmp->error < 0) {
            rc = ULFS_ERROR_MDHIM;
        }

        for (i = 0; i < bgrmp->num_keys; i++) {
            res_kv[tot_num].k = *(fsmd_key_t *)bgrm->keys[i];
            res_kv[tot_num].v = *(fsmd_val_t *)bgrm->values[i];
            tot_num++;
        }
        bgrmp = bgrmp->next;
        mdhim_full_release_msg(bgrm);
        bgrm = bgrmp;
    }

    /*
     *  Check the slab map for every stripe received and update it 
     *  if that slab is missing 
     */
    keysets = calloc(pool->info.layouts_count, sizeof(F_MAP_KEYSET_u));
    if (keysets) {
	for (i = 0; i < tot_num; i++) {
	    F_LAYOUT_t *lo = f_get_layout(res_kv[i].k.pk.loid);
	    f_stripe_t stripe = res_kv[i].v.stripe;
	    f_slab_t slab;
	    F_MAP_KEYSET_u *keyset;
	    ASSERT(lo);

	    keyset = &keysets[res_kv[i].k.pk.loid];
	    if (!keyset->slabs)
    	    	keyset->slabs = calloc(tot_num, sizeof(f_slab_t));
	    slab = stripe_to_slab(lo, stripe);
	    for (j = 0; j < keyset->count; j++) {
		if (keyset->slabs[j] == slab) break;
	    }

	    if (j == keyset->count) {
		sme = (F_SLABMAP_ENTRY_t *)f_map_get_p(lo->slabmap, slab);
		if (!sme || !sme->slab_rec.mapped) {
		    keyset->slabs[keyset->count] = slab;
		    keyset->count++;
		    printf("added slab %u (s %lu) to update count %d\n",
			slab, stripe, keyset->count);
		}
	    }
	}

	for (i = 0; i < pool->info.layouts_count; i++) {
	    F_LAYOUT_t *lo = f_get_layout(i);
	    F_MAP_KEYSET_u *keyset = &keysets[i];
	    if (keyset->count > 0) {
		LOG(LOG_DBG2, "%s: updating %d slabs", lo->info.name, keyset->count);
	    	if ((rc = f_slabmap_update(lo->slabmap, keyset)))
		    LOG(LOG_ERR, "%s: error %d updating global slabmap", 
			lo->info.name, rc);
	    	if (log_print_level > 0)
		    f_print_sm(dbg_stream, lo->slabmap, lo->info.chunks, 
			lo->info.slab_stripes);
	    }
	    free(keyset->slabs);
	}
	free(keysets);
    }

    if (total_kv)
        *total_kv = tot_num;

    IF_LOG(LOG_DBG3) {
	LOG(LOG_DBG3, "srv: got %d k/v pairs:", tot_num);
	for (i = 0; i < tot_num; i++) {
	    LOG(LOG_DBG3, "  k/v[%d] lo %d fid=%d off/len=%jd/%jd addr=%ld s=%lu",
		i, res_kv[i].k.pk.loid, res_kv[i].k.pk.fid,
		res_kv[i].k.offset, res_kv[i].v.len,
		res_kv[i].v.addr, res_kv[i].v.stripe);
	}
    }

    return rc;
}

void print_bget_indices(int app_id, int cli_id,
                        send_msg_t *index_set, int tot_num)
{
    int i;

    long dest_offset;
    int dest_delegator_rank;
    int dest_client_id;
    int dest_app_id;
    long length;
    int src_app_id;
    int src_cli_id;
    long src_offset;
    int src_delegator_rank;
    int src_fid;
    int dbg_rank;

    for (i = 0; i < tot_num;  i++) {
        dest_offset = index_set[i].dest_offset;
        dest_delegator_rank = index_set[i].dest_delegator_rank;
        dest_client_id = index_set[i].dest_client_id;
        dest_app_id = index_set[i].dest_app_id;
        length = index_set[i].length;
        src_app_id = index_set[i].src_app_id;
        src_cli_id = index_set[i].src_cli_id;
        src_offset = index_set[i].src_offset;

        src_delegator_rank = index_set[i].src_delegator_rank;
        src_fid = index_set[i].src_fid;
        dbg_rank = index_set[i].src_dbg_rank;

        LOG(LOG_DBG, "index:dbg_rank:%d, dest_offset:%ld, "
            "dest_del_rank:%d, dest_cli_id:%d, dest_app_id:%d, "
            "length:%ld, src_app_id:%d, src_cli_id:%d, src_offset:%ld, "
            "src_del_rank:%d, "
            "src_fid:%d, num:%d\n", dbg_rank, dest_offset,
            dest_delegator_rank, dest_client_id,
            dest_app_id, length, src_app_id, src_cli_id,
            src_offset, src_delegator_rank,
            src_fid, tot_num);

    }


}

#if 0
void print_fsync_indices(fsmd_key_t **fsmd_keys,
                         fsmd_val_t **fsmd_vals, long num_entries)
{
    long i;
    for (i = 0; i < num_entries; i++) {
        LOG(LOG_DBG, "fid:%ld, offset:%ld, addr:%ld, len:%ld, del_id:%ld\n",
            fsmd_keys[i]->fid, fsmd_keys[i]->offset,
            fsmd_vals[i]->addr, fsmd_vals[i]->len,
            fsmd_vals[i]->delegator_id);

    }
}
#endif

int meta_free_indices()
{
    int i;
    for (i = 0; i < MAX_META_PER_SEND; i++) {
        free(fsmd_keys[i]);
    }
    free(fsmd_keys);

    for (i = 0; i < MAX_META_PER_SEND; i++) {
        free(fsmd_vals[i]);
    }
    free(fsmd_vals);

    for (i = 0; i < MAX_FILE_CNT_PER_NODE; i++) {
        free(fattr_keys[i]);
    }
    free(fattr_keys);

    for (i = 0; i < MAX_FILE_CNT_PER_NODE; i++) {
        free(fattr_vals[i]);
    }
    free(fattr_vals);
    return 0;
}

static ssize_t ps_bget(unsigned long *buf, int map_id, size_t size, uint64_t *keys, int op)
{
	struct index_t *primary_index = unifycr_indexes[F_MD_IDX_MAPS_START + map_id];

	return mdhim_ps_bget(md, primary_index, buf, size, keys, op);
}

static int ps_bput(unsigned long *buf, int map_id, size_t size, void **keys,
    size_t value_len)
{
	struct index_t *primary_index = unifycr_indexes[F_MD_IDX_MAPS_START + map_id];

	return mdhim_ps_bput(md, primary_index, buf, size, keys, value_len);
}

static int ps_bdel(int map_id, size_t size, void **keys)
{
	struct index_t *primary_index = unifycr_indexes[F_MD_IDX_MAPS_START + map_id];

	return mdhim_ps_bdel(md, primary_index, size, keys);
}

int meta_sanitize()
{
    mdhim_options_t *db_opts;
    int *ids, *types, max_id, i;
    int rank, ret, rc = ULFS_SUCCESS;

    char dbfilename[GEN_STR_LEN] = {0};
    char statfilename[GEN_STR_LEN+12] = {0};
    char manifestname[GEN_STR_LEN] = {0};

    meta_free_indices();

    db_opts = md->db_opts;
    rank = md->mdhim_rank;
    ids = (int*) malloc(sizeof(int)*F_MD_IDX_SIZE);
    types = (int*) malloc(sizeof(int)*F_MD_IDX_SIZE);
    max_id = 0;
    for (i = 0; i < F_MD_IDX_SIZE; i++) {
	if (!unifycr_indexes[i] || unifycr_indexes[i]->myinfo.rangesrv_num == 0)
	    continue;
	ids[max_id] = unifycr_indexes[i]->id;
	types[max_id] = unifycr_indexes[i]->type;
	max_id++;
    }
    mdhimClose(md);

    for (i = 0; i < max_id; i++) {
	sprintf(dbfilename, "%s/%s-%d-%d", db_opts->db_path,
		db_opts->db_name, ids[i], rank);
	sprintf(statfilename, "%s_stats", dbfilename);
	sprintf(manifestname, "%s%d_%d_%d", db_opts->manifest_path,
		types[i], ids[i], rank);

	ret = mdhimSanitize(dbfilename, statfilename, manifestname);
	if (rc == ULFS_SUCCESS)
		rc = ret; /* report first error */
    }
    free(ids);
    free(types);
    mdhim_options_destroy(db_opts);

    return rc;
}

