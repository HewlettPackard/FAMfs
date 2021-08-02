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

#ifndef MPI_UTILS_H
#define MPI_UTILS_H

#include <inttypes.h>
#include <mpi.h>


int mpi_split_world(MPI_Comm *mpi_comm, int my_role, int zero_role,
    int gbl_rank, int gbl_size);
int mpi_comm_dup(MPI_Comm *dst_comm, const MPI_Comm *src_comm);

static inline int mpi_broadcast_arr64(uint64_t *keys, int size, int rank0)
{
    return MPI_Bcast(keys, size*sizeof(uint64_t), MPI_BYTE, rank0, MPI_COMM_WORLD);
}

#endif /* MPI_UTILS_H */

