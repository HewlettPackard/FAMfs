/*
 * Copyright (c) 2020, HPE
 *
 * Written by: Dmitry Ivanov
 */

#ifndef MPI_UTILS_H
#define MPI_UTILS_H

#include <inttypes.h>
#include <mpi.h>


int mpi_split_world(MPI_Comm *mpi_comm, int my_role, int zero_role,
    int gbl_rank, int gbl_size);

static inline int mpi_broadcast_arr64(uint64_t *keys, int size, int rank0)
{
    return MPI_Bcast(keys, size*sizeof(uint64_t), MPI_BYTE, rank0, MPI_COMM_WORLD);
}

#endif /* MPI_UTILS_H */

