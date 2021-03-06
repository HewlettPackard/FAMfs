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

#ifndef F_GLOBAL_H_
#define F_GLOBAL_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>

#include "f_env.h"


#define GEN_STR_LEN 1024
#define UNIFYCR_MAX_FILENAME	ULFS_MAX_FILENAME


typedef struct f_fattr_t_ {
    int fid;
    int gfid;
    int loid;                               /* famfs layout id (from config file) */
    char filename[UNIFYCR_MAX_FILENAME];
    struct stat file_attr;
} f_fattr_t;


typedef enum {
    CMD_SVCRQ     = 0x1,    // request service
    CMD_MOUNT     = 0x2,    // mount FAMfs
    CMD_META      = 0x10,   // file metadata ops
    CMD_FCLOSE    = 0x11,   // file close op
    CMD_MDGET     = 0x20,   // retrieve file data access metadata
    CMD_UNMOUNT   = 0x31,   // unmount FAMfs
    CMD_QUIT      = 0x32,   // exit command for worker thread
    CMD_SHTDWN    = 0x33,   // shutdown FAMfs server

    CMD_READ      = 0x43,   // depricated
    CMD_DIGEST    = 0x45,   // depricated

    CMD_OPT_MASK  = 0xff00,
    CMD_OPT_FAMFS = 0x0100,
} f_srvcmd_t;

typedef enum {
    MDRQ_GETFA  = 1,
    MDRQ_SETFA  = 2,
    MDRQ_FSYNC  = 3,
    MDRQ_FAMAT  = 4
} f_mdrq_t;

#define F_MAX_FNM     ( 128 )

#define F_MAX_CMDQ     64
#define F_MAX_RPLYQ    8
#define F_CMDQ_NAME    "f_cmdq"
#define F_RPLYQ_NAME   "f_rplyq"


/*metadata format in the shared memory*/
typedef struct {
    int     fid;        /* global fid */
    int     loid;       /* layout id */
    off_t   file_pos;   /* file offset */
    off_t   mem_pos;    /* offset in stripe */
    size_t  length;
    uint64_t sid;       /* global stripe number */
} md_index_t;

/*metadata request format in the shared memory*/
typedef struct shm_meta_t_ {
    int src_fid;
    int loid; /* layout id */
    long offset;
    long length;
} shm_meta_t;

typedef struct fsmd_key_t_ {
    union {
        unsigned long fid;
        struct {
            int       fid;  /* global fid */
            int       loid; /* Little endian: sort by layout id first */
        } pk;
    };
    unsigned long offset;
} fsmd_key_t;
/* ds_leveldb.c: MDHIM Range compare function wants .offset at long */
_Static_assert( offsetof(struct fsmd_key_t_, offset) == sizeof(long),  "MDHIM Range Key offset");

typedef struct {
    unsigned long addr; /* famfs: data offset in stripe */
    unsigned long len;
    union {
        struct {
            unsigned int delegator_id;
            unsigned int app_rank_id; /*include both app and rank id*/
        };
	unsigned long stripe;
    };
} fsmd_val_t;

typedef struct {
    fsmd_key_t   k;
    fsmd_val_t   v;
} fsmd_kv_t;
_Static_assert( sizeof(fsmd_key_t)+sizeof(fsmd_val_t) == sizeof(fsmd_kv_t), "KV packed check");
_Static_assert( sizeof(fsmd_kv_t) == sizeof(md_index_t), "MDHIM KV size check");
_Static_assert( TYPE_ALINGMENT(fsmd_kv_t) == TYPE_ALINGMENT(md_index_t), "MDHIM KV alignment check");

typedef struct {
    char            *buf;
    size_t          len;
    struct fid_mr   **mreg;
    void            **desc;
} lf_mreg_t;

typedef struct {
    size_t          cnt;
    lf_mreg_t       *regs;
} famfs_mr_list_t;

typedef struct lfs_excg_ {
	uint64_t	prov_key;	/* memory registration key */
	uint64_t	virt_addr;	/* remote virtual address */
} LFS_EXCG_t;

typedef struct {
	uint32_t	_f __attribute__((aligned(8))); /* reserved */
	uint32_t	part_cnt;	/* number of partitions on this FAM */
	LFS_EXCG_t	part_attr[];	/* partition LF remote key & virt addr */
} __attribute__((packed))  fam_attr_val_t;
#define fam_attr_val_sz(cnt) (sizeof(fam_attr_val_t) + (cnt)*sizeof(LFS_EXCG_t))

typedef struct {
	uint64_t	fam_id;		/* FAM Id */
	uint32_t	_f;		/* reserved */
	uint32_t	part_cnt;	/* number of partitions on this FAM */
	LFS_EXCG_t	part_attr[];	/* partition LF remote key & virt addr */
} fam_attr_t;
#define fam_attr_sz(cnt) (sizeof(fam_attr_t) + (cnt)*sizeof(LFS_EXCG_t))

// server request
typedef struct {
    f_srvcmd_t          opcode;
    int                 cid;
    union {
        struct {
            int         app_id;
            int         dbg_rnk;
            int         num_prc;
            int         rqbf_sz;
            int         rcbf_sz;
            long        sblk_sz;
            long        meta_of;
            long        meta_sz;
            long        fmet_of;
            long        fmet_sz;
            long        data_of;
            long        data_sz;
            char        ext_dir[UNIFYCR_MAX_FILENAME];
        };
        struct {
            f_mdrq_t    md_type;
            union {
                f_fattr_t   fm_data;
                int         fm_gfid;
                int         fam_id;
                int         md_rcnt;
                int         fm_lid;
            };
        };
        struct {
            int     fid;
            int     lid;
        };
    };
} f_svcrq_t;

#define KA_PAIR_MAX  (sizeof(f_fattr_t)/sizeof(LFS_EXCG_t))
// server reply
typedef struct {
    f_srvcmd_t          ackcode;
    short               more;
    short               cnt;
    int                 rc;
    union {
        struct {
            off_t       data_off;
            size_t      data_size;
        };
//        uint64_t        max_rps;
        LFS_EXCG_t      prt_atr[KA_PAIR_MAX];
        f_fattr_t       fattr;
    };
} f_svcrply_t;

typedef struct {
    uint64_t    sync_bm;
    uint64_t    edr_bm;
    uint64_t    wait_bm;
    int         valid;
} f_close_ntfy_t;



extern famfs_mr_list_t known_mrs;

#endif

