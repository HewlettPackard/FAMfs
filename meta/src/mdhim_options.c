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
 *
 * Copyright (c) 2014, Los Alamos National Laboratory
 *	All rights reserved.
 *
 */

/*
 * DB usage options.
 * Location and name of DB, type of DataSotre primary key type,
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "mdhim_options.h"

// Default path to a local path and name, levelDB=2, int_key_type=1, yes_create_new=1
// and debug=1 (mlog_CRIT)

#define MANIFEST_FILE_NAME "/mdhim_manifest_"

struct mdhim_options_t *mdhim_options_init()
{
	struct mdhim_options_t* opts;
	opts = malloc(sizeof(struct mdhim_options_t));
    
	opts->db_path = "./";
	opts->db_name = "mdhimTstDB-";
	opts->manifest_path = NULL;
	opts->db_type = 1; /* LEVELDB */
	opts->db_key_type = 1;
	opts->db_create_new = 1;
	opts->db_value_append = MDHIM_DB_OVERWRITE;
	
	opts->db_host = "localhost";
	opts->dbs_host = "localhost";
	opts->db_user = "test";
	opts->db_upswd = "pass";
	opts->dbs_user = "test";
	opts->dbs_upswd = "pass";		
	
        
	opts->debug_level = 0x00500000; /* MLOG_CRIT */
        opts->rserver_factor = 1;
        opts->max_recs_per_slice = 100000;
	opts->db_paths = NULL;
	opts->num_paths = 0;
	opts->num_wthreads = 1;

	set_manifest_path(opts, "./");
	return opts;
}

int check_path_length(mdhim_options_t* opts, char *path) {
	int path_len;
	int ret = 0;

	path_len = strlen(path) + 1;
	if (((!opts->db_name && path_len < PATH_MAX) || 
	     ((path_len + strlen(opts->db_name)) < PATH_MAX)) &&
	    (path_len + strlen(MANIFEST_FILE_NAME)) < PATH_MAX) {
		ret = 1;
	} else {
		printf("Path: %s exceeds: %d bytes, so it won't be used\n", path, PATH_MAX);
	}

	return ret;
}

void set_manifest_path(mdhim_options_t* opts, char *path) {
	char *manifest_path;
	int path_len = 0;

	if (opts->manifest_path) {
	  free(opts->manifest_path);
	  opts->manifest_path = NULL;
	}

	path_len = strlen(path) + strlen(MANIFEST_FILE_NAME) + 1;
	manifest_path = malloc(path_len);
	sprintf(manifest_path, "%s%s", path, MANIFEST_FILE_NAME);
	opts->manifest_path = manifest_path;
}

void mdhim_options_set_login_c(mdhim_options_t* opts, char* db_hl, char *db_ln, char *db_pw, char *dbs_hl, char *dbs_ln, char *dbs_pw){
	opts->db_host = db_hl;
	opts->db_user = db_ln;
	opts->db_upswd = db_pw;
	opts->dbs_host = dbs_hl;	
	opts->dbs_user = dbs_ln;
	opts->dbs_upswd = dbs_pw;
	
}
void mdhim_options_set_db_path(mdhim_options_t* opts, char *path)
{
	int ret;

	if (!path) {
		return;
	}

	ret = check_path_length(opts, path);
	if (ret) {
		opts->db_path = path;
		set_manifest_path(opts, path);
	}
};

void mdhim_options_set_db_paths(struct mdhim_options_t* opts, char **paths, int num_paths)
{
	int i = 0;
	int ret;
	int verified_paths = -1;

	if (num_paths <= 0) {
		return;
	}

	opts->db_paths = malloc(sizeof(char *) * num_paths);
	for (i = 0; i < num_paths; i++) {
		if (!paths[i]) {
			continue;
		}

		ret = check_path_length(opts, paths[i]);
		if (!ret) {
			continue;
		}
		if (!i) {
			set_manifest_path(opts, paths[i]);
		}

		verified_paths++;		
		opts->db_paths[verified_paths] = malloc(strlen(paths[i]) + 1);
		sprintf(opts->db_paths[verified_paths], "%s", paths[i]);
	}

	opts->num_paths = ++verified_paths;
};

void mdhim_options_set_db_name(mdhim_options_t* opts, char *name)
{
	opts->db_name = name;
};

void mdhim_options_set_db_type(mdhim_options_t* opts, int type)
{
	opts->db_type = type;
};

void mdhim_options_set_key_type(mdhim_options_t* opts, int key_type)
{
	opts->db_key_type = key_type;
};

void mdhim_options_set_create_new_db(mdhim_options_t* opts, int create_new)
{
	opts->db_create_new = create_new;
};

void mdhim_options_set_debug_level(mdhim_options_t* opts, int dbug)
{
	opts->debug_level = dbug;
};

void mdhim_options_set_value_append(mdhim_options_t* opts, int append)
{
	opts->db_value_append = append;
};

void mdhim_options_set_server_factor(mdhim_options_t* opts, int server_factor)
{
	opts->rserver_factor = server_factor;
};

void mdhim_options_set_max_recs_per_slice(mdhim_options_t* opts, uint64_t max_recs_per_slice)
{
	opts->max_recs_per_slice = max_recs_per_slice;
};

void mdhim_options_set_num_worker_threads(mdhim_options_t* opts, int num_wthreads)
{
	if (num_wthreads > 0) {
		opts->num_wthreads = num_wthreads;
	}
};

/* mdhim configuration: DB options */
int mdhim_options_cfg(unifycr_cfg_t *cfg, mdhim_options_t **db_opts_p)
{
    mdhim_options_t *db_opts;
    char *manifest_path;
    long l;
    int path_len, ret = -1;

    db_opts = mdhim_options_init();
    if (!db_opts) {
        return -1;
    }

    /* UNIFYCR_META_DB_PATH: file that stores the key value pair*/
    if (cfg->meta_db_path)
        db_opts->db_path = strdup(cfg->meta_db_path);
    if (db_opts->db_path == NULL)
        goto _err;

    db_opts->manifest_path = NULL;
    //db_opts->db_type = LEVELDB;
    db_opts->db_create_new = 1;

    /* UNIFYCR_META_SERVER_RATIO: number of metadata servers =
        number of processes/META_SERVER_RATIO */
    if (configurator_int_val(cfg->meta_server_ratio, &l))
	goto _err;
    db_opts->rserver_factor = (int)l;

    db_opts->db_paths = NULL;
    db_opts->num_paths = 0;
    db_opts->num_wthreads = 1;

    path_len = strlen(db_opts->db_path) + strlen(MANIFEST_FILE_NAME) + 2;
    manifest_path = malloc(path_len);
    if (!manifest_path)
        goto _err;

    sprintf(manifest_path, "%s/%s", db_opts->db_path, MANIFEST_FILE_NAME);
    db_opts->manifest_path = manifest_path;

    /* UNIFYCR_META_DB_NAME */
    if (cfg->meta_db_name)
        db_opts->db_name = strdup(cfg->meta_db_name);
    if (db_opts->db_name == NULL)
        goto _err;

    //db_opts->db_key_type = MDHIM_UNIFYCR_KEY;
    //db_opts->debug_level = MLOG_CRIT;

    /* indices/attributes are striped to servers according
     * to UnifyCR_META_RANGE_SZ.
     * */
    if (configurator_int_val(cfg->meta_range_size, &l))
        goto _err;
    db_opts->max_recs_per_slice = (unsigned long)l;

    *db_opts_p = db_opts;
    return 0;

_err:
    mdhim_options_destroy(db_opts);
    return ret;
}

void mdhim_options_destroy(mdhim_options_t *opts) {
	int i;

	for (i = 0; i < opts->num_paths; i++) {
		free(opts->db_paths[i]);
	}

	free(opts->manifest_path);
	free(opts);
};
