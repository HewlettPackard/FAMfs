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
 * Copyright (c) 2018, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 *
 * Copyright 2018, UT-Battelle, LLC.
 *
 * LLNL-CODE-741539
 * All rights reserved.
 *
 * This is the license for UnifyCR.
 * For details, see https://github.com/LLNL/UnifyCR.
 * Please read https://github.com/LLNL/UnifyCR/LICENSE for full license text.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <mpi.h>
#include <linux/limits.h>
#include <unifycr.h>
#include "t/lib/tap.h"
#include "t/lib/testutil.h"

int main(int argc, char *argv[])
{
    int rank_num;
    int rank;
    char path[64];
    char *unifycr_root;
    int mode = 0600;
    int fd;
    int rc;

    MPI_Init(&argc, &argv);
    MPI_Comm_size(MPI_COMM_WORLD, &rank_num);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    plan(NO_PLAN);

    unifycr_root = testutil_get_mount_point();

    /* choose fs type: UNIFYCR_LOG or FAMFS */
    fs_type_t fs = FAMFS;
    if (!fs_supported(fs))
        fs = UNIFYCR_LOG;
    ok(fs_supported(fs), "support for %s - checking configuration file",
       fs==FAMFS?"FAMFS":"UNIFYCR_LOG");

    /*
     * Verify unifycr_mount succeeds.
     */
    rc = unifycr_mount(unifycr_root, rank, rank_num, 0, fs);
    ok(rc == 0, "unifycr_mount at %s (rc=%d)", unifycr_root, rc);

    testutil_rand_path(path, sizeof(path), unifycr_root);

    /*
     * Verify we can create a new file.
     */
    errno = 0;
    fd = open(path, O_CREAT|O_EXCL|O_RDWR, mode);
    ok(fd >= 0, "open non-existing file %s flags O_CREAT|O_EXCL (fd=%d): %s",
       path, fd, strerror(errno));

    /*
    char buf[4096];
    ssize_t w = write(fd, buf, sizeof(buf));
    ok(w == sizeof(buf), "write at %s:%d %m\n", path, w);
    */

    /*
     * Verify close succeeds.
     */
    errno = 0;
    rc = close(fd);
    ok(rc == 0, "close %s (rc=%d): %s", path, rc, strerror(errno));

    /*
     * Verify opening an existing file with O_CREAT|O_EXCL fails with
     * errno=EEXIST.
     */
    errno = 0;
    fd = open(path, O_CREAT|O_EXCL, mode);
    ok(fd < 0 && errno == EEXIST,
       "open existing file %s O_CREAT|O_EXCL should fail (fd=%d): %s",
       path, fd, strerror(errno));

    /*
     * Verify opening an existing file with O_RDWR succeeds.
     */
    errno = 0;
    fd = open(path, O_RDWR, mode);
    ok(fd >= 0, "open existing file %s O_RDWR (fd=%d): %s",
       path, fd, strerror(errno));

    /*
     * Verify close succeeds.
     */
    errno = 0;
    rc = close(fd);
    ok(rc == 0, "close %s (rc=%d): %s", path, rc, strerror(errno));

    MPI_Finalize();

    done_testing();

    return 0;
}
