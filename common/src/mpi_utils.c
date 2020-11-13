/*
 * Copyright (c) 2020, HPE
 *
 * Written by: Dmitry Ivanov
 */

#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <malloc.h>
#include <sys/types.h>

#include "f_env.h"
#include "f_error.h"
#include "mpi_utils.h"


/*
 * MPI utils
**/

/* Return the rank in COMM_WORLD of the first node of role 'zero_role' and
MPI subcommunicator of MPI_COMM_WORLD for nodes of 'my_role'. */
int mpi_split_world(MPI_Comm *mpi_comm, int my_role, int zero_role,
    int gbl_rank, int gbl_size)
{
	MPI_Comm	world_comm, comm = MPI_COMM_NULL;
	MPI_Group	group_all, group;
	int		*lf_roles, *ranks = NULL;
	int		i, size, zero_srv_rank, rc;

	lf_roles = (int *) calloc(gbl_size, sizeof(int));
	lf_roles[gbl_rank] = my_role;
	rc = MPI_Allgather(MPI_IN_PLACE, sizeof(int), MPI_BYTE,
			   lf_roles, sizeof(int), MPI_BYTE, MPI_COMM_WORLD);
	if (rc != MPI_SUCCESS) {
		err("MPI_Allgather");
		goto _err;
	}
	ranks = (int *) calloc(gbl_size, sizeof(int));
	zero_srv_rank = -1;
	for (i = 0, size = 0; i < gbl_size; i++) {
		if (lf_roles[i] == my_role)
			ranks[size++] = i;
		if (zero_srv_rank < 0 && lf_roles[i] == zero_role)
			zero_srv_rank = i;
	}
	free(lf_roles);

	rc = MPI_Comm_dup(MPI_COMM_WORLD, &world_comm);
	if (rc != MPI_SUCCESS) {
		err("MPI_Comm_dup failed:%d", rc);
		goto _err;
	}
	rc = MPI_Comm_group(world_comm, &group_all);
	if (rc != MPI_SUCCESS) {
		err("MPI_Comm_group failed:%d", rc);
		goto _err;
	}
	rc = MPI_Group_incl(group_all, size, ranks, &group);
	free(ranks);
	if (rc != MPI_SUCCESS) {
		err("MPI_Group_incl failed:%d role:%d size:%d",
		    rc, my_role, size);
		goto _err;
	}
	rc = MPI_Comm_create(world_comm, group, &comm);
	if (rc != MPI_SUCCESS) {
		err("MPI_Comm_create failed:%d role:%d size:%d",
		    rc, my_role, size);
		goto _err;
	}
	ASSERT(comm != MPI_COMM_NULL);

	memcpy(mpi_comm, &comm, sizeof(MPI_Comm));
	return zero_srv_rank;

_err:
	free(lf_roles);
	free(ranks);
	*mpi_comm = MPI_COMM_NULL;
	return -1;
}

/* Duplicate src_comm */
int mpi_comm_dup(MPI_Comm *dst_comm, const MPI_Comm *src_comm)
{
	int rc;
	MPI_Comm	src = src_comm?*src_comm:MPI_COMM_WORLD;
	MPI_Comm	comm, dup_comm_world;
	MPI_Group	group;

	/* Create private communicator (GASNET way) */
	rc = MPI_Comm_dup(src, &dup_comm_world);
	if (rc != MPI_SUCCESS) {
		err("MPI_Comm_dup failed:%d", rc);
		goto _err;
	}
	rc = MPI_Comm_group(dup_comm_world, &group);
	if (rc != MPI_SUCCESS) {
		err("MPI_Comm_group failed:%d", rc);
		goto _err;
	}
	rc = MPI_Comm_create(dup_comm_world, group, &comm);
	if (rc != MPI_SUCCESS) {
		err("MPI_Comm_create failed:%d", rc);
		goto _err;
	}
	rc = MPI_Group_free(&group);
	if (rc != MPI_SUCCESS) {
		err("MPI_Group_free failed:%d", rc);
		goto _err;
	}
	rc = MPI_Comm_free(&dup_comm_world);
	if (rc != MPI_SUCCESS) {
		err("MPI_Comm_free failed:%d", rc);
		goto _err;
	}

	memcpy(dst_comm, &comm, sizeof(MPI_Comm));
	return 0;

_err:
	*dst_comm = MPI_COMM_NULL;
	return rc;
}

