/*
 * Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 *
 * Copyright 2017, UT-Battelle, LLC.
 * Copyright (c) 2018 - Michael J. Brim
 * Copyright (c) 2017-2018, HPE - Oleg Neverovitch, Dmitry Ivanov
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
#ifdef __cplusplus
# include <climits>
# include <cstddef>
# include <cstdio>
#else
# include <limits.h>
# include <stdbool.h>
# include <stddef.h>
# include <stdio.h>
#endif

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

// NOTE: NULLSTRING is a sentinel token meaning "no default string value"

/* UNIFYCR_CONFIGS is the list of configuration settings, and should contain
   one macro definition per setting */
#define UNIFYCR_CONFIGS \
    UNIFYCR_CFG_CLI(unifycr, configfile, STRING, SYSCONFDIR/famfs/famfs.conf, "path to configuration file", configurator_file_check, 'f', "specify full path to config file") \
    UNIFYCR_CFG_CLI(unifycr, daemonize, BOOL, off, "enable server daemonization", NULL, 'D', "on|off") \
    UNIFYCR_CFG_CLI(unifycr, debug, BOOL, off, "enable debug output", NULL, 'd', "on|off") \
    UNIFYCR_CFG_CLI(unifycr, mount_point, STRING, UNIFYCR_MOUNT_POINT, "mountpoint directory", NULL, 'm', "specify full path to desired mountpoint") \
    UNIFYCR_CFG_CLI(log, verbosity, INT, 0, "log verbosity level", NULL, 'v', "specify logging verbosity level") \
    UNIFYCR_CFG_CLI(log, file, STRING,  UNIFYCR_DEFAULT_LOG_FILE, "log file name", NULL, 'l', "specify log file name") \
    UNIFYCR_CFG_CLI(log, dir, STRING, LOGDIR, "log file directory", configurator_directory_check, 'L', "specify full path to directory to contain log file") \
    UNIFYCR_CFG(unifycr, index_buf_size, INT, UNIFYCR_INDEX_BUF_SIZE, "log file system index buffer size", NULL) \
    UNIFYCR_CFG(unifycr, fattr_buf_size, INT, UNIFYCR_FATTR_BUF_SIZE, "log file system file attributes buffer size", NULL) \
    UNIFYCR_CFG(meta, db_name, STRING, META_DEFAULT_DB_NAME, "metadata database name", NULL) \
    UNIFYCR_CFG(meta, db_path, STRING, META_DEFAULT_DB_PATH, "metadata database path", NULL) \
    UNIFYCR_CFG(meta, server_ratio, INT, META_DEFAULT_SERVER_RATIO, "metadata server ratio", NULL) \
    UNIFYCR_CFG(meta, range_size, INT, META_DEFAULT_RANGE_SZ, "metadata range size", NULL) \
    UNIFYCR_CFG(unifycr, chunk_bits, INT, UNIFYCR_CHUNK_BITS, "shared memory data chunk size in bits (i.e., size=2^bits)", NULL) \
    UNIFYCR_CFG(unifycr, chunk_mem, INT, UNIFYCR_CHUNK_MEM, "shared memory segment size for data chunks", NULL) \
    UNIFYCR_CFG(shmem, recv_size, INT, UNIFYCR_SHMEM_RECV_SIZE, "shared memory segment size in bytes for receiving data from delegators", NULL) \
    UNIFYCR_CFG(shmem, req_size, INT, UNIFYCR_SHMEM_REQ_SIZE, "shared memory segment size in bytes for sending requests to delegators", NULL) \
    UNIFYCR_CFG(shmem, single, BOOL, off, "use single shared memory region for all clients", NULL) \
    UNIFYCR_CFG(spillover, data_dir, STRING, NULLSTRING, "spillover data directory", configurator_directory_check) \
    UNIFYCR_CFG(spillover, meta_dir, STRING, NULLSTRING, "spillover metadata directory", configurator_directory_check) \
    UNIFYCR_CFG(spillover, size, INT, UNIFYCR_SPILLOVER_SIZE, "spillover max data size in bytes", NULL) \
    UNIFYCR_CFG(unifycr, extent_size, INT, UNIFYCR_EXTENT_SIZE, "pool extent size in bytes", NULL) \
    UNIFYCR_CFG(unifycr, extent0_offset, INT, UNIFYCR_EXTENT0_OFFSET, "extent zero starts with offset in bytes", NULL) \
    UNIFYCR_CFG(unifycr, ioncount, INT, UNIFYCR_ION_COUNT, "IO node (device) count", NULL) \
    UNIFYCR_CFG(unifycr, layouts_count, INT, UNIFYCR_LAYOUTS_COUNT, "number of layouts", NULL) \
    UNIFYCR_CFG(layout0, name, STRING, LAYOUT0_NAME, "Name (moniker) of the first layout", configurator_moniker_check) \
    UNIFYCR_CFG(layout0, devnum, INT, 1, "total number of devices in Layout 0", NULL) \
    UNIFYCR_CFG(layout1, name, STRING, NULLSTRING, "Name (moniker) of the first layout", configurator_moniker_check) \
    UNIFYCR_CFG(layout1, devnum, INT, 1, "total number of devices in Layout 1", NULL) \
    UNIFYCR_CFG(client, max_files, INT, UNIFYCR_MAX_FILES, "client max file count", NULL) \

#ifdef __cplusplus
extern "C" {
#endif

/* unifycr_cfg_t struct */
typedef struct {
#define UNIFYCR_CFG(sec, key, typ, dv, desc, vfn) \
    char *sec##_##key;

#define UNIFYCR_CFG_CLI(sec, key, typ, dv, desc, vfn, opt, use) \
    char *sec##_##key;

#define UNIFYCR_CFG_MULTI(sec, key, typ, dv, desc, vfn, me) \
    char *sec##_##key[me]; \
    unsigned n_##sec##_##key;

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

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* FAMFS_CONFIGURATOR_H */
