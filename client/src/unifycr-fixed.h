/*
 * Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 *
 * Copyright 2017, UT-Battelle, LLC.
 *
 * LLNL-CODE-741539
 * All rights reserved.
 *
 * This is the license for UnifyCR.
 * For details, see https://github.com/LLNL/UnifyCR.
 * Please read https://github.com/LLNL/UnifyCR/LICENSE for full license text.
 */

/*
 * Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * Copyright (c) 2017, Florida State University. Contributions from
 * the Computer Architecture and Systems Research Laboratory (CASTL)
 * at the Department of Computer Science.
 *
 * Written by: Teng Wang, Adam Moody, Weikuan Yu, Kento Sato, Kathryn Mohror
 * LLNL-CODE-728877. All rights reserved.
 *
 * This file is part of burstfs.
 * For details, see https://github.com/llnl/burstfs
 * Please read https://github.com/llnl/burstfs/LICENSE for full license text.
 */

/*
 * Copyright (c) 2013, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * code Written by
 *   Raghunath Rajachandrasekar <rajachan@cse.ohio-state.edu>
 *   Kathryn Mohror <kathryn@llnl.gov>
 *   Adam Moody <moody20@llnl.gov>
 * All rights reserved.
 * This file is part of CRUISE.
 * For details, see https://github.com/hpc/cruise
 * Please also read this file LICENSE.CRUISE
 */

#ifndef UNIFYCR_FIXED_H
#define UNIFYCR_FIXED_H

#include "unifycr-internal.h"

/* if length is greater than reserved space,
 * reserve space up to length */
int unifycr_fid_store_fixed_extend(
    int fid,                 /* file id to reserve space for */
    unifycr_filemeta_t *meta, /* meta data for file */
    off_t length             /* number of bytes to reserve for file */
);

/* if length is shorter than reserved space,
 * give back space down to length */
int unifycr_fid_store_fixed_shrink(
    int fid,                 /* file id to free space for */
    unifycr_filemeta_t *meta, /* meta data for file */
    off_t length             /* number of bytes to reserve for file */
);

/* read data from file stored as fixed-size chunks,
 * returns UNIFYCR error code */
int unifycr_fid_store_fixed_read(
    int fid,                 /* file id to read from */
    unifycr_filemeta_t *meta, /* meta data for file */
    off_t pos,               /* position within file to read from */
    void *buf,               /* user buffer to store data in */
    size_t count             /* number of bytes to read */
);

/* write data to file stored as fixed-size chunks,
 * returns UNIFYCR error code */
int unifycr_fid_store_fixed_write(
    int fid,                 /* file id to write to */
    unifycr_filemeta_t *meta, /* meta data for file */
    off_t pos,               /* position within file to write to */
    const void *buf,         /* user buffer holding data */
    size_t count             /* number of bytes to write */
);

#endif /* UNIFYCR_FIXED_H */
