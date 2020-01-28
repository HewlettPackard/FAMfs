#ifndef FAMFS_GLOBAL_H_
#define FAMFS_GLOBAL_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>

#include "famfs_env.h"


#define GEN_STR_LEN 1024
#define UNIFYCR_MAX_FILENAME     ( 128 )


typedef struct {
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
    MDRQ_GTFAM  = 4
} f_mdrq_t;

#define F_MAX_FNM     ( 128 )

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
            };
        };
    };
} f_svcrq_t;

typedef struct {
    f_srvcmd_t          ackcode;
    int                 cid;
    int                 rc;
    union {
        struct {
            off_t               data_off;
            size_t              data_size;
        };
        uint64_t                max_rps;
        f_fattr_t               fattr;
    };
} f_svcrply_t;

#define F_MAX_CMDQ     64
#define F_MAX_RPLYQ    8
#define F_CMDQ_NAME    "f_cmdq"
#define F_RPLYQ_NAME   "f_rplyq"


typedef struct {
    off_t   file_pos;
    off_t   mem_pos;
    size_t  length;
    int     fid;
    int     nid;
    int     cid;
} md_index_t;

typedef struct {
    unsigned long fid;
    unsigned long offset;
} fsmd_key_t;

typedef struct {
    unsigned long addr;
    unsigned long len;
    union {
        struct {
            unsigned long delegator_id;
            unsigned long app_rank_id; /*include both app and rank id*/
        };
        struct {
            unsigned long node;
            unsigned long chunk;
        };
    };
} fsmd_val_t;

typedef struct {
    fsmd_key_t   k;
    fsmd_val_t   v;
} fsmd_kv_t;

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


extern famfs_mr_list_t known_mrs;

#endif

