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

#ifndef FAMFS_CL_H
#define FAMFS_CL_H

#include "f_layout.h"

//extern int unifycr_debug_level;


static inline const char *famfs_strip_layout(const char *path) {
    const char *fpath = strstr(path, "::");
    return fpath ? fpath + 2 : path;
}

struct fam_attr_val_t;

int famfs_mount(const char prefix[], size_t size, int rank);
int f_server_sync();
int famfs_unmount();
int famfs_shutdown();

const char *famfs_intercept_path(const char *path);
int famfs_report_storage(int fid, size_t *total, size_t *free);
int famfs_fid_create_file(const char *path, const char *fpath, int loid);

int lf_connect(char *addr, char *srvc);
int get_global_fam_meta(int fam_id, fam_attr_val_t **fam_meta);
void famfs_merge_md();

/* TODO: Remove me! */
int f_srv_connect();

#endif /* FAMFS_CL_H */

