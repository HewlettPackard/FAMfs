/*
 * Copyright (c) 2019-2020, HPE
 *
 * Written by: Dmitry Ivanov
 */

#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>

#include "famfs_env.h"
#include "famfs_ktypes.h"
#include "f_dict.h"

void f_dict_free(F_DICT_t *d) {
    free(d);
}

