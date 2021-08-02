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

#ifndef UNIFYCR_H
#define UNIFYCR_H

#include <poll.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>
/* TODO: namespace C */

#ifndef _POSIX_C_SOURCE
# define HOST_NAME_MAX 64
#endif

/* linked list of chunk information given to an external library wanting
 * to RDMA out a file from UNIFYCR */
typedef struct {
    off_t chunk_id;
    int location;
    void *chunk_mr;
    off_t spillover_offset;
    struct chunk_list_t *next;
} chunk_list_t;

/*data structures defined for unifycr********************/

#define MMAP_OPEN_FLAG O_RDWR|O_CREAT
#define MMAP_OPEN_MODE 00777

/* fs mount type */
typedef enum {
    UNIFYCRFS,
    UNIFYCR_LOG,
    FAMFS,
} fs_type_t;


int unifycr_mount(const char prefix[], int rank, size_t size,
                  int l_app_id, int subtype);
int unifycr_unmount(void);


/* get information about the chunk data region
 * for external async libraries to register during their init */
size_t unifycr_get_data_region(void **ptr);

/* get a list of chunks for a given file (useful for RDMA, etc.) */
chunk_list_t *unifycr_get_chunk_list(char *path);

/* debug function to print list of chunks constituting a file
 * and to test above function*/
void unifycr_print_chunk_list(char *path);

/* FAMFS */
int unifycr_shutdown(void);
int famfs_buf_reg(char *buf, size_t len, void **ctx);
int famfs_buf_unreg(void *ctx);
int fs_supported(fs_type_t fs);

#endif /* UNIFYCR_H */
