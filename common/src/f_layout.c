/*
 * Copyright (c) 2020, HPE
 *
 * Written by: Dmitry Ivanov
 */

//#include <unistd.h>
//#include <stddef.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <malloc.h>

//#include "famfs_env.h"
//#include "famfs_error.h"
#include "f_layout.h"


/* Lookup device in lo->devlist by media_id */
F_POOLDEV_INDEX_t *f_find_pdi_by_media_id(F_LAYOUT_t *lo, unsigned int media_id)
{
    uint16_t idx;

    if (media_id > lo->info.pdi_max_idx)
	return NULL;

    idx = lo->info.pdi_by_media[media_id];
    return (idx >= lo->devlist_sz)? NULL:&lo->devlist[idx];
}


