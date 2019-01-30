#ifndef FAMFS_GLOBAL_H_
#define FAMFS_GLOBAL_H_ 
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
#endif

