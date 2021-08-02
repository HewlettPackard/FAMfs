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
 *
 * Written by: Dmitry Ivanov
 */

#include <stdio.h>
#include <mpi.h>
#include <unifycr.h>
#include "t/lib/tap.h"
#include "t/lib/testutil.h"

int main(int argc, char *argv[])
{
    char *unifycr_root;
    int rank_num;
    int rank;
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

    rc = unifycr_unmount();
    ok(rc == 0, "unifycr_unmount succeeds (rc=%d)", rc);

    MPI_Finalize();
    done_testing();

    return 0;
}
