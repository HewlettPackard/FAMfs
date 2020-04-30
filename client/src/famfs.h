/*
 * Copyright (c) 2020, HPE
 *
 * Written by: Dmitry Ivanov
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
struct unifycr_chunkmeta_t_;
struct read_req_t_;

int famfs_mount(const char prefix[], size_t size, int rank);
int f_server_sync();
int famfs_unmount();
int famfs_shutdown();

const char *famfs_intercept_path(const char *path);
int famfs_report_storage(int fid, size_t *total, size_t *free);
int famfs_fid_create_file(const char *path, const char *fpath, int loid);

int lf_connect(char *addr, char *srvc);
int lf_fam_read(char *buf, size_t len, off_t fam_off, unsigned long sid);
int famfs_read(struct read_req_t_ *read_req, int count);
int get_global_fam_meta(int fam_id, fam_attr_val_t **fam_meta);
void famfs_merge_md();

/* TODO: Remove me! */
int f_srv_connect();

#endif /* FAMFS_CL_H */
