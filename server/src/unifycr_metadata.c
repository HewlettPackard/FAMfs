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


fsmd_key_t **fsmd_keys;
fsmd_val_t **fsmd_vals;

fattr_key_t **fattr_keys;
fattr_val_t **fattr_vals;

struct mdhim_brm_t *brm, *brmp;
struct mdhim_bgetrm_t *bgrm, *bgrmp;
struct mdhim_t *md;

int fsmd_ley_lens[MAX_META_PER_SEND] = {0};
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

static int create_persistent_map(int map_id, int intl, char *name);
static ssize_t ps_bget(unsigned long *buf, int map_id, size_t size, uint64_t *keys);
static int ps_bput(unsigned long *buf, int map_id, size_t size, uint64_t *keys);

static F_META_IFACE_t iface = {
	.create_map_fn = &create_persistent_map,
	.bget_fn = &ps_bget,
	.bput_fn = &ps_bput,
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

    db_opts->debug_level = MLOG_CRIT;
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

static int create_persistent_map(int map_id, int intl, char *name)
{
    int id = F_MD_IDX_MAPS_START + map_id;

    if (!IN_RANGE(id, F_MD_IDX_MAPS_START, F_MD_IDX_MAPS_END) ||
	intl < 0 || md == NULL)
	    return -1;
    if (unifycr_indexes[id] == NULL) {
	unifycr_indexes[id] = create_global_index(md, md->db_opts->rserver_factor,
					intl, LEVELDB, MDHIM_LONG_INT_KEY, name);
	if (unifycr_indexes[id] == NULL)
		return -1;
    }
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
* @param sock_id: the connection id in poll_set of
* the delegator
* @return success/error code
*/
int meta_process_attr_set(char *buf, int sock_id)
{
    int rc = ULFS_SUCCESS;

    unifycr_file_attr_t *ptr_fattr =
        (unifycr_file_attr_t *)(buf + 2 * sizeof(int));

    *fattr_keys[0] = ptr_fattr->gfid;
    fattr_vals[0]->file_attr = ptr_fattr->file_attr;
    strcpy(fattr_vals[0]->fname, ptr_fattr->filename);

    /*  LOG(LOG_DBG, "rank:%d, setting fattr key:%d, value:%s\n",
                glb_rank, *fattr_keys[0], fattr_vals[0]->fname); */
    md->primary_index = unifycr_indexes[1];
    brm = mdhimPut(md, fattr_keys[0], sizeof(fattr_key_t),
                   fattr_vals[0], sizeof(fattr_val_t),
                   NULL, NULL);
    if (!brm || brm->error) {
        rc = ULFS_ERROR_MDHIM;
    } else {
        rc = ULFS_SUCCESS;
    }

    mdhim_full_release_msg(brm);

    return rc;
}


/* get the file attribute from the key-value store
* @param buf: a buffer that stores the gid
* @param sock_id: the connection id in poll_set of the delegator
* @return success/error code
*/

int meta_process_attr_get(char *buf, int sock_id,
                          unifycr_file_attr_t *ptr_attr_val)
{
    *fattr_keys[0] = *((int *)(buf + 2 * sizeof(int)));
    fattr_val_t *tmp_ptr_attr;

    int rc;

    md->primary_index = unifycr_indexes[1];
    bgrm = mdhimGet(md, md->primary_index, fattr_keys[0],
                    sizeof(fattr_key_t), MDHIM_GET_EQ);

    if (!bgrm || bgrm->error) {
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

int meta_famattr_put(int fam_id, fam_attr_val_t *val)
{
    size_t val_sz;
    uint32_t key;
    int rc;

    md->primary_index = unifycr_indexes[2];

    if (fam_id < 0)
        key = MDHIM_MAX_SLICES;
    else
        key = (uint32_t)fam_id;
    *fattr_keys[0] = key;
    val_sz = fam_attr_val_sz(val->part_cnt);
    LOG(LOG_DBG, "key:%u size:%zu cnt:%u prov_key:%lu virt_addr:%016lx",
        key, val_sz, val->part_cnt, val->part_attr[0].prov_key,
        val->part_attr[0].virt_addr);
    brm = mdhimPut(md, fattr_keys[0], sizeof(fattr_key_t),
		   val, val_sz, NULL, NULL);

    if (!brm || brm->error)
	rc = ULFS_ERROR_MDHIM;
    else
	rc = ULFS_SUCCESS;

    mdhim_full_release_msg(brm);

    return rc;
}

int meta_famattr_get(char *buf, fam_attr_val_t **val_p)
{
    *fattr_keys[0] = *((int *)(buf + 2 * sizeof(int)));
    fam_attr_val_t *tmp_ptr_attr;

    int rc;

    md->primary_index = unifycr_indexes[2];
    bgrm = mdhimGet(md, md->primary_index, fattr_keys[0],
		    sizeof(fattr_key_t), MDHIM_GET_EQ);

    if (!bgrm || bgrm->error) {
	*val_p = NULL;
	rc = ULFS_ERROR_MDHIM;
    } else {
	size_t size;

	tmp_ptr_attr = (fam_attr_val_t *)bgrm->values[0];
	*val_p = (fam_attr_val_t *)malloc(fam_attr_val_sz(tmp_ptr_attr->part_cnt));
	//fam_id = *fattr_keys[0];
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
* @param sock_id: the connection id in poll_set of the delegator
* @return success/error code
*/

int meta_process_fsync(int sock_id)
{
    int i, ret = 0;

    int app_id = invert_sock_ids[sock_id];
    app_config_t *app_config = (app_config_t *)arraylist_get(app_config_list,
                               app_id);

    int client_side_id = app_config->client_ranks[sock_id];

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

    md->primary_index = unifycr_indexes[0];

    for (i = 0; i < num_entries; i++) {
        fsmd_keys[i]->fid = meta_payload[i].fid;
        fsmd_keys[i]->offset = meta_payload[i].file_pos;
        fsmd_vals[i]->addr = meta_payload[i].mem_pos;
        fsmd_vals[i]->len = meta_payload[i].length;
        if (fam_fs) {
            fsmd_vals[i]->node  = meta_payload[i].nid;
            fsmd_vals[i]->chunk = meta_payload[i].cid;
/*
        printf("srv: fsync k/v[%d] fid=%ld off=%ld/len=%ld addr=%lu node=%ld chunk=%ld\n", i,
        fsmd_keys[i]->fid, fsmd_keys[i]->offset, 
        fsmd_vals[i]->len, fsmd_vals[i]->addr, fsmd_vals[i]->node, fsmd_vals[i]->chunk);
*/

        } else {
            fsmd_vals[i]->delegator_id = glb_rank;
            memcpy((char *) & (fsmd_vals[i]->app_rank_id), &app_id, sizeof(int));
            memcpy((char *) & (fsmd_vals[i]->app_rank_id) + sizeof(int),
                   &client_side_id, sizeof(int));
        }

        fsmd_ley_lens[i] = sizeof(fsmd_key_t);
        unifycr_val_lens[i] = sizeof(fsmd_val_t);
    }

    //print_fsync_indices(fsmd_keys, fsmd_vals, num_entries);

    if (num_entries == 1) {
        brm = mdhimPut(md, fsmd_keys[0], sizeof(fsmd_key_t),
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

        brm = mdhimBPut(md, (void **)(&fsmd_keys[0]), fsmd_ley_lens,
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
    md->primary_index = unifycr_indexes[1];

    num_entries =
        *((unsigned long *)(app_config->shm_superblocks[client_side_id]
                            + app_config->fmeta_offset));
    //printf("sync to process %d attrs\n", num_entries);
    if (num_entries == 0)
        return ret;

    /* file attributes are stored in the superblock shared memory
     * created by the client*/
    unifycr_file_attr_t *attr_payload =
        (unifycr_file_attr_t *)(app_config->shm_superblocks[client_side_id]
                                + app_config->fmeta_offset + page_sz);


    for (i = 0; i < num_entries; i++) {
        *fattr_keys[i] = attr_payload[i].gfid;
        fattr_vals[i]->file_attr = attr_payload[i].file_attr;
        strcpy(fattr_vals[i]->fname, attr_payload[i].filename);

        fattr_key_lens[i] = sizeof(fattr_key_t);
        fattr_val_lens[i] = sizeof(fattr_val_t);
    }

    if (num_entries == 1) {
        brm = mdhimPut(md, fattr_keys[0], sizeof(fattr_key_t),
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

    brm = mdhimBPut(md, (void **)(&fattr_keys[0]), fattr_key_lens,
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
    cli_req_t *tmp_cli_req = (cli_req_t *) shm_reqbuf;

    int i, rc = 0;
    for (i = 0; i < num; i++) {
        fsmd_keys[2 * i]->fid = tmp_cli_req[i].fid;
        fsmd_keys[2 * i]->offset = tmp_cli_req[i].offset;
        fsmd_ley_lens[2 * i] = sizeof(fsmd_key_t);
        fsmd_keys[2 * i + 1]->fid = tmp_cli_req[i].fid;
        fsmd_keys[2 * i + 1]->offset =
            tmp_cli_req[i].offset + tmp_cli_req[i].length - 1;
        fsmd_ley_lens[2 * i + 1] = sizeof(fsmd_key_t);

    }

    md->primary_index = unifycr_indexes[0];
    bgrm = mdhimBGet(md, md->primary_index, (void **)fsmd_keys,
                     fsmd_ley_lens, 2 * num, MDHIM_RANGE_BGET);

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

            if (fam_fs) {
                /* TODO: Add support for app, client ids in FAMfs */
                dest_app = 0;
                dest_client = 0;
                del_req_set->msg_meta[tot_num].fam_cid = tmp_val->chunk;
                del_req_set->msg_meta[tot_num].fam_nid = tmp_val->node;
            } else {
                memcpy(&dest_app, (char *) & (tmp_val->app_rank_id), sizeof(int));
                memcpy(&dest_client, (char *) & (tmp_val->app_rank_id)
                       + sizeof(int), sizeof(int));
                /* rank of the remote delegator*/
                del_req_set->msg_meta[tot_num].dest_delegator_rank = tmp_val->delegator_id;
            }

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

int famfs_md_get(char *shm_reqbuf, int num, fsmd_kv_t *res_kv, int *total_kv) {

    int tot_num = 0;
    cli_req_t *tmp_cli_req = (cli_req_t *)shm_reqbuf;

    int i, rc = 0;
    for (i = 0; i < num; i++) {
        fsmd_keys[2*i]->fid        = tmp_cli_req[i].fid;
        fsmd_keys[2*i + 1]->fid    = tmp_cli_req[i].fid;
        fsmd_keys[2*i]->offset     = tmp_cli_req[i].offset;
        fsmd_keys[2*i + 1]->offset = tmp_cli_req[i].offset + tmp_cli_req[i].length - 1;
        fsmd_ley_lens[2*i]         = sizeof(fsmd_key_t);
        fsmd_ley_lens[2*i + 1]     = sizeof(fsmd_key_t);
    }

    md->primary_index = unifycr_indexes[0];
    bgrm = mdhimBGet(md, md->primary_index, (void **)fsmd_keys,
                     fsmd_ley_lens, 2 * num, MDHIM_RANGE_BGET);

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

    if (total_kv)
        *total_kv = tot_num;
    /*
    for (i = 0; i < *total_kv; i++)
        printf("srv: got md k/v[%d] fid=%ld off=%jd/len=%jd addr=%jd node=%jd chunk=%jd\n", i, 
        res_kv[i].k.fid, res_kv[i].k.offset, 
        res_kv[i].v.len, res_kv[i].v.addr, res_kv[i].v.node, res_kv[i].v.chunk);
    */

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

static ssize_t ps_bget(unsigned long *buf, int map_id, size_t size, uint64_t *keys)
{
	struct index_t *primary_index = unifycr_indexes[F_MD_IDX_MAPS_START + map_id];

	return mdhim_ps_bget(md, primary_index, buf, size, keys);
}

static int ps_bput(unsigned long *buf, int map_id, size_t size, uint64_t *keys)
{
	struct index_t *primary_index;
	int ret = 0;

	primary_index = unifycr_indexes[F_MD_IDX_MAPS_START + map_id];


	return ret;
}

int meta_sanitize()
{
    mdhim_options_t *db_opts;
    int i, rank, ret, rc = ULFS_SUCCESS;

    char dbfilename[GEN_STR_LEN] = {0};
    char statfilename[GEN_STR_LEN+12] = {0};
    char manifestname[GEN_STR_LEN] = {0};

    meta_free_indices();

    db_opts = md->db_opts;
    rank = md->mdhim_rank;
    mdhimClose(md);

    /* TODO: For each registered DB table */
    for (i = 0; i < F_MD_IDX_SIZE; i++) {
	struct index_t *index = &unifycr_indexes[i];

	if (!index)
		continue;
	sprintf(dbfilename, "%s/%s-%d-%d", db_opts->db_path,
		db_opts->db_name, index->id, rank);
	sprintf(statfilename, "%s_stats", dbfilename);
	sprintf(manifestname, "%s%d_%d_%d", db_opts->manifest_path,
		index->type, index->id, rank);

	ret = mdhimSanitize(dbfilename, statfilename, manifestname);
	if (rc == ULFS_SUCCESS)
		rc = ret; /* report first error */
    }

    mdhim_options_destroy(db_opts);

    return rc;
}

