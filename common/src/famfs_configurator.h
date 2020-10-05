/*
 * Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 *
 * Copyright 2017, UT-Battelle, LLC.
 * Copyright (c) 2018 - Michael J. Brim
 * Copyright (c) 2017-2019, HPE - Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAMFS_CONFIGURATOR_H
#define FAMFS_CONFIGURATOR_H

/* Configurator unifies config files, environment variables, and command-line
 * arguments into a set of simple preprocessor definitions that capture the
 * necessary info.
 *
 * See README.md for instructions on usage.
 */

// need bool, NULL, FILE*
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <uuid/uuid.h>

#include "famfs_env.h"


#ifndef TMPDIR
#define TMPDIR /tmp
#endif

#ifndef RUNDIR
#define RUNDIR /var/tmp // NOTE: typically user-writable, /var/run is not
#endif

#ifndef SYSCONFDIR
#define SYSCONFDIR /etc
#endif

#ifndef LOGDIR
#define LOGDIR TMPDIR
#endif

#define F_CFG_MSEC_MAX	64	/* max number of multi-section repeatition */
#define F_CFG_MSKEY_MAX	64	/* max number of key instances in multi-section */

// NOTE: NULLSTRING is a sentinel token meaning "no default string value"

/* UNIFYCR_CONFIGS is the list of configuration settings, and should contain
   one macro definition per setting */
#define UNIFYCR_CONFIGS \
    UNIFYCR_CFG_CLI(unifycr, configfile, STRING, SYSCONFDIR/famfs/famfs.conf, "path to configuration file", configurator_file_check, 'f', "specify full path to config file") \
    UNIFYCR_CFG_CLI(unifycr, daemonize, BOOL, off, "enable server daemonization", NULL, 'D', "on|off") \
    UNIFYCR_CFG_CLI(unifycr, debug, BOOL, off, "enable debug output", NULL, 'd', "on|off") \
    UNIFYCR_CFG_CLI(unifycr, mount_point, STRING, UNIFYCR_MOUNT_POINT, "mountpoint directory", NULL, 'm', "specify full path to desired mountpoint") \
    UNIFYCR_CFG_CLI(unifycr, fs_type, STRING, UNIFYCR_FS_TYPE, "filesystem type", NULL, 't', "types: unifycr, famfs, both") \
    UNIFYCR_CFG(unifycr, lfa_port, INT, UNIFYCR_LFA_PORT, "libfabric atomics port", NULL) \
    UNIFYCR_CFG(unifycr, cq_hwm, INT, UNIFYCR_CQ_HWM, "high water mark for committed stripes queue", NULL) \
    UNIFYCR_CFG(unifycr, cq_hwm_tmo, INT, UNIFYCR_CQ_HWM_TMO, "high water mark stripes queue timeout, sec", NULL) \
    UNIFYCR_CFG(unifycr, cache_wr, BOOL, off, "enable write cache", NULL) \
    UNIFYCR_CFG(unifycr, cache_rd, BOOL, off, "enable metadata cache on read", NULL) \
    UNIFYCR_CFG(unifycr, index_buf_size, INT, UNIFYCR_INDEX_BUF_SIZE, "log file system index buffer size", NULL) \
    UNIFYCR_CFG(unifycr, fattr_buf_size, INT, UNIFYCR_FATTR_BUF_SIZE, "log file system file attributes buffer size", NULL) \
    UNIFYCR_CFG(unifycr, chunk_bits, INT, UNIFYCR_CHUNK_BITS, "shared memory data chunk size in bits (i.e., size=2^bits)", NULL) \
    UNIFYCR_CFG(unifycr, chunk_mem, INT, UNIFYCR_CHUNK_MEM, "shared memory segment size for data chunks", NULL) \
    UNIFYCR_CFG(unifycr, fsync_tmo, INT, UNIFYCR_FSYNC_TMO, "range server fsync timeout, sec", NULL) \
    UNIFYCR_CFG_CLI(log, verbosity, INT, 0, "log verbosity level", NULL, 'v', "specify logging verbosity level") \
    UNIFYCR_CFG_CLI(log, file, STRING,  UNIFYCR_DEFAULT_LOG_FILE, "log file name", NULL, 'l', "specify log file name") \
    UNIFYCR_CFG_CLI(log, dir, STRING, LOGDIR, "log file directory", configurator_directory_check, 'L', "specify full path to directory to contain log file") \
    UNIFYCR_CFG(meta, db_name, STRING, META_DEFAULT_DB_NAME, "metadata database name", NULL) \
    UNIFYCR_CFG(meta, db_path, STRING, META_DEFAULT_DB_PATH, "metadata database path", NULL) \
    UNIFYCR_CFG(meta, server_ratio, INT, META_DEFAULT_SERVER_RATIO, "metadata server ratio", NULL) \
    UNIFYCR_CFG(meta, range_size, INT, META_DEFAULT_RANGE_SZ, "metadata range size", NULL) \
    UNIFYCR_CFG(shmem, recv_size, INT, UNIFYCR_SHMEM_RECV_SIZE, "shared memory segment size in bytes for receiving data from delegators", NULL) \
    UNIFYCR_CFG(shmem, req_size, INT, UNIFYCR_SHMEM_REQ_SIZE, "shared memory segment size in bytes for sending requests to delegators", NULL) \
    UNIFYCR_CFG(shmem, single, BOOL, off, "use single shared memory region for all clients", NULL) \
    UNIFYCR_CFG(spillover, data_dir, STRING, NULLSTRING, "spillover data directory", configurator_directory_check) \
    UNIFYCR_CFG(spillover, meta_dir, STRING, NULLSTRING, "spillover metadata directory", configurator_directory_check) \
    UNIFYCR_CFG(spillover, size, INT, UNIFYCR_SPILLOVER_SIZE, "spillover max data size in bytes", NULL) \
    UNIFYCR_CFG(client, max_files, INT, UNIFYCR_MAX_FILES, "client max file count", NULL) \
    UNIFYCR_CFG(encode, wait_on_close, BOOL, off, "wait for encode to finish on close ", NULL) \
    UNIFYCR_CFG(mddevice, pk, INT, 0, "MD region protection key", NULL) \
    UNIFYCR_CFG(mddevice, size, INT, 1M, "MD size (bytes)", NULL) \
    UNIFYCR_CFG(mddevice, offset, INT, 0, "MD offset (bytes)", NULL) \
    UNIFYCR_CFG(devices, uuid, STRING, NULLSTRING, "device UUID", configurator_uuid_check) \
    UNIFYCR_CFG(devices, extent_size, INT, UNIFYCR_EXTENT_SIZE, "pool extent size in bytes", NULL) \
    UNIFYCR_CFG(devices, emulated, BOOL, off, "FAMs are emulated", NULL) \
    UNIFYCR_CFG(devices, pk, INT, 0, "default FAM protection key", NULL) \
    UNIFYCR_CFG(devices, size, INT, UNIFYCR_EXTENT_SIZE, "default device size in bytes", NULL) \
    UNIFYCR_CFG(devices, offset, INT, UNIFYCR_EXTENT0_OFFSET, "default device extent zero offset in bytes", NULL) \
    UNIFYCR_CFG(devices, fabric, STRING, NULLSTRING, "libfabric network", NULL) \
    UNIFYCR_CFG(devices, domain, STRING, NULLSTRING, "libfabric interface", NULL) \
    UNIFYCR_CFG(devices, port, STRING, LFSRV_PORT, "libfabric service or port number", NULL) \
    UNIFYCR_CFG(devices, provider, STRING, LF_PROV_NAME, "libfabric provider", NULL) \
    UNIFYCR_CFG(devices, memreg, STRING, LF_MR_MODEL, "memory registration mode", NULL) \
    UNIFYCR_CFG(devices, progress, STRING, FAMFS_PROGRESS_AUTO, "data and control progress", NULL) \
    UNIFYCR_CFG(devices, use_cq, BOOL, off, "use completion queue instead of counters", NULL) \
    UNIFYCR_CFG(devices, timeout, INT, IO_TIMEOUT_MS, "libfabric timeout", NULL) \
    UNIFYCR_CFG(devices, single_ep, BOOL, on, "use single endpoint per domain", NULL) \
    /* Each multi-section should have 'id' field defined as INT, NULLSTRING, of size 1 */ \
    UNIFYCR_CFG_MULTI(ionode, id, INT, NULLSTRING, "IO node unique ID", NULL, 1) \
    UNIFYCR_CFG_MULTI(ionode, uuid, STRING, NULLSTRING, "IO node UUID", configurator_uuid_check, 1) \
    UNIFYCR_CFG_MULTI(ionode, host, STRING, NULLSTRING, "IO node IP or hostname", NULL, 1) \
    UNIFYCR_CFG_MULTI(ionode, mds, INT, 1, "number of MD servers on this node", NULL, 1) \
    UNIFYCR_CFG_MULTI(ionode, force_helper, BOOL, off, "force Helper threads on this node", NULL, 1) \
    UNIFYCR_CFG_MULTI(ionode, z_node, STRING, NULLSTRING, "ZFM node name", NULL, 1) \
    UNIFYCR_CFG_MULTI(ionode, topo, STRING, NULLSTRING, "ZFM node topology", NULL, 1) \
    UNIFYCR_CFG_MULTI(ionode, geo, STRING, NULLSTRING, "ION location (MFW model)", NULL, 1) \
    UNIFYCR_CFG_MULTI(device, id, INT, NULLSTRING, "device reference", NULL, 1) \
    UNIFYCR_CFG_MULTI(device, uuid, STRING, NULLSTRING, "device UUID", configurator_uuid_check, 1) \
    UNIFYCR_CFG_MULTI(device, url, STRING, NULLSTRING, "FAM URL", NULL, 1) \
    UNIFYCR_CFG_MULTI(device, z_node, STRING, NULLSTRING, "FAM ZFM name", NULL, 1) \
    UNIFYCR_CFG_MULTI(device, topo, STRING, NULLSTRING, "FAM ZFM topology", NULL, 1) \
    UNIFYCR_CFG_MULTI(device, geo, STRING, NULLSTRING, "FAM location (MFW model)", NULL, 1) \
    UNIFYCR_CFG_MULTI(device, pk, INT, 0, "FAM protection key", NULL, 1) \
    UNIFYCR_CFG_MULTI(device, size, INT, 0, "device size (bytes)", NULL, 1) \
    UNIFYCR_CFG_MULTI(device, failed, BOOL, off, "device is failed", NULL, 1) \
    UNIFYCR_CFG_MULTI(ag, id, INT, NULLSTRING, "allocation group", NULL, 1) \
    UNIFYCR_CFG_MULTI(ag, uuid, STRING, NULLSTRING, "AG UUID", configurator_uuid_check, 1) \
    UNIFYCR_CFG_MULTI(ag, devices, INT, NULLSTRING, "devices in AG", NULL, 0) \
    UNIFYCR_CFG_MULTI(layout, id, INT, NULLSTRING, "device ID in layout", NULL, 1) \
    UNIFYCR_CFG_MULTI(layout, devices, INT, NULLSTRING, "device ID in layout", NULL, 0) \
    UNIFYCR_CFG_MULTI(layout, name, STRING, LAYOUT0_NAME, "layout name (moniker)", configurator_moniker_check, 1) \
    UNIFYCR_CFG_MULTI(layout, sq_depth, INT, LAYOUT_SQ_DEPTH, "preallocated stripes queue size per compute node", NULL, 1) \
    UNIFYCR_CFG_MULTI(layout, sq_lwm, INT, LAYOUT_SQ_LWM, "low water mark for preallocated queue", NULL, 1) \


/* unifycr_cfg_t struct */
typedef struct unifycr_cfg_t_ {
    unsigned int sec_i; /* for parser use only: current section number */
    char *cur_key;	/* for ini parser */

#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn) \
    char *sec##_##key;

#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use) \
    char *sec##_##key;

#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me)		\
    char *sec##_##key[F_CFG_MSEC_MAX][(me>0?me:F_CFG_MSKEY_MAX)];	\
    unsigned n_##sec##_##key[F_CFG_MSEC_MAX]; /* second index: key instance */

#define UNIFYCR_CFG_MULTI_CLI(sec, key, typ, dv, desc, vfn, me, opt, use) \
    char *sec##_##key[me]; \
    unsigned n_##sec##_##key;

    UNIFYCR_CONFIGS

#undef UNIFYCR_CFG
#undef UNIFYCR_CFG_CLI
#undef UNIFYCR_CFG_MULTI
#undef UNIFYCR_CFG_MULTI_CLI
} unifycr_cfg_t;

/* initialization and cleanup */

int unifycr_config_init(unifycr_cfg_t *cfg,
                        int argc,
                        char **argv);

void unifycr_config_free(unifycr_cfg_t *cfg);

/* print configuration to specified file (or stderr if fp==NULL) */
void unifycr_config_print(unifycr_cfg_t *cfg,
                          FILE *fp);

/* print configuration in .INI format to specified file (or stderr) */
void unifycr_config_print_ini(unifycr_cfg_t *cfg,
                              FILE *inifp);

/* used internally, but may be useful externally */

int unifycr_config_set_defaults(unifycr_cfg_t *cfg);

void unifycr_config_cli_usage(char *arg0);
void unifycr_config_cli_usage_error(char *arg0,
                                    char *err_msg);

int unifycr_config_process_cli_args(unifycr_cfg_t *cfg,
                                    int argc,
                                    char **argv);

int unifycr_config_process_environ(unifycr_cfg_t *cfg);

int unifycr_config_process_ini_file(unifycr_cfg_t *cfg,
                                    const char *file);

int unifycr_config_validate(unifycr_cfg_t *cfg);

int famfs_config_setdef_multisec(unifycr_cfg_t *cfg);

/* validate function prototype
   -  Returns: 0 for valid input, non-zero otherwise.
   -  out_val: set this output parameter to specify an alternate value */
typedef int (*configurator_validate_fn)(const char *section,
                                        const char *key,
                                        const char *val,
                                        char **out_val);

/* predefined validation functions */
int configurator_bool_val(const char *val,
                          bool *b);
int configurator_bool_check(const char *section,
                            const char *key,
                            const char *val,
                            char **oval);

int configurator_float_val(const char *val,
                           double *d);
int configurator_float_check(const char *section,
                             const char *key,
                             const char *val,
                             char **oval);

int configurator_int_val(const char *val,
                         long *l);
int configurator_int_check(const char *section,
                           const char *key,
                           const char *val,
                           char **oval);

int configurator_file_check(const char *section,
                            const char *key,
                            const char *val,
                            char **oval);

int configurator_directory_check(const char *section,
                                 const char *key,
                                 const char *val,
                                 char **oval);

int configurator_moniker_check(const char *section,
                                 const char *key,
                                 const char *val,
                                 char **oval);

int configurator_uuid_check(const char *section,
                               const char *key,
                               const char *val,
                               char **oval);

int configurator_get_sizes(unifycr_cfg_t *cfg,
			   const char *section,
			   const char *key,
			   int *keylist_size);

int f_uuid_parse(const char *in, uuid_t uu);

static inline int configurator_get_sec_size(unifycr_cfg_t *cfg,
					    const char *section)
{
	return configurator_get_sizes(cfg, section, NULL, NULL);
}

/* Validate structure's size and/or alignment */
    _Static_assert( sizeof(uuid_t) == 16,	"uuid_t");
    _Static_assert( sizeof(uuid_t)*2+4+1 == F_UUID_BUF_SIZE, "uuid_t BUF_SIZE");

#endif /* FAMFS_CONFIGURATOR_H */
