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

#ifndef UNIFYCR_METADATA_H
#define UNIFYCR_METADATA_H
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "mdhim.h"
#include "indexes.h"
#include "arraylist.h"
#include "unifycr_const.h"
#include "unifycr_global.h"
#include "famfs_global.h"

#define MANIFEST_FILE_NAME "mdhim_manifest_"
#define F_MD_IDX_MAPS_START 3 /* map indexes start with 3 (unifycr_indexes) */


int meta_sanitize();
int meta_init_conf(unifycr_cfg_t *cfg, mdhim_options_t **db_opts_p);
int meta_init_store(mdhim_options_t *db_opts);
int meta_init_indices();
int meta_free_indices();
int meta_famattr_put(int fam_id, fam_attr_val_t *val);
int meta_famattr_get(int fam_id, fam_attr_val_t **ptr_val);
int meta_md_get(char *shm_reqbuf, int num, fsmd_kv_t *res_kv, int *total_kv);

void print_bget_indices(int app_id, int cli_id,
                        send_msg_t *index_set, int tot_num);
int meta_process_fsync(int qid);
int meta_batch_get(int app_id, int client_id,
                   int thrd_id, int dbg_rank, char *shm_reqbuf, int num,
                   msg_meta_t *del_req_set);
void print_fsync_indices(fsmd_key_t **keys, fsmd_val_t **vals, long num_entries);
int meta_process_attr_set(char *ptr_cmd, int qid);
int meta_process_attr_get(char *buf, int qid, f_fattr_t *ptr_attr_val);

#endif
