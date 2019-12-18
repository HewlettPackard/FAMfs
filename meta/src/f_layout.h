/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */

#ifndef F_LAYOUT_H_
#define F_LAYOUT_H_

#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>

#include "famfs_env.h"
//#include "famfs_bbitmap.h"

#define DRIVE_MAP_SIZE  BITS_TO_LONGS(F_STRIPE_DISK_COUNT)

/* Pool device index shareable atomics (blob) */
typedef struct f_pdi_sha_ {
    FI_UINT32_t __attribute__ ((aligned(4))) \
			extents_used;
    FI_UINT32_t		failed_extents;
} F_PDI_SHA_t;

typedef struct f_pooldev_index_ {
    uint32_t		pool_index;
    uint32_t		pl_extents_used;
    F_PDI_SHA_t		*sha;
} F_POOLDEV_INDEX_t;

#endif F_LAYOUT_H_

