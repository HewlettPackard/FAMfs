#ifndef FAMFS_GLOBAL_H_
#define FAMFS_GLOBAL_H_

#include <sys/types.h>
#include <inttypes.h>


typedef enum {
    COMM_MOUNT     = 0x1, /*the list of addrs: appid, size of buffer, offset of data section, metadata section*/
    COMM_META      = 0x2,
    COMM_READ      = 0x3,
    COMM_UNMOUNT   = 0x4,
    COMM_DIGEST    = 0x5,
    COMM_SYNC_DEL  = 0x6,
    COMM_MDGET     = 0x7,

    COMM_OPT_MASK  = 0xff00,
    COMM_OPT_FAMFS = 0x0100,
} cmd_lst_t;

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

