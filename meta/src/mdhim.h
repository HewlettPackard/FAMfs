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
 *
 * Copyright (c) 2014, Los Alamos National Laboratory
 *	All rights reserved.
 *
 */

#ifndef      __MDHIM_H
#define      __MDHIM_H

#include <mpi.h>
#include <stdint.h>
#include <pthread.h>
#include "data_store.h"
#include "range_server.h"
#include "messages.h"
#include "partitioner.h"
#include "Mlog2/mlog2.h"
#include "Mlog2/mlogfacs2.h"
#include "mdhim_options.h"
#include "indexes.h"
#include "mdhim_private.h"

#include "list.h"

#ifdef __cplusplus
extern "C"
{
#endif
#define MDHIM_SUCCESS 0
#define MDHIM_ERROR -1
#define MDHIM_DB_ERROR -2
#define MDHIM_DB_RESIDUAL -3 /* got less records than requested */

#define SECONDARY_GLOBAL_INFO 1
#define SECONDARY_LOCAL_INFO 2

/*
 * mdhim data
 * Contains client communicator
 * Contains a list of range servers
 * Contains a pointer to mdhim_rs_t if rank is a range server
 */
struct mdhim_t {
	//This communicator will include every process in the application, but is separate from main the app
        //It is used for sending and receiving to and from the range servers
	MPI_Comm mdhim_comm;
	pthread_mutex_t *mdhim_comm_lock;

	//This communicator will include every process in the application, but is separate from the app
        //It is used for barriers for clients
	MPI_Comm mdhim_client_comm;

	//The rank in the mdhim_comm
	int mdhim_rank;
	//The size of mdhim_comm
	int mdhim_comm_size;
	//Flag to indicate mdhimClose was called
	volatile int shutdown;
	//A pointer to the primary index
	struct index_t *primary_index;
	//A linked list of range servers
	struct index_t *indexes;
	// The hash to hold the indexes by name
	struct index_t *indexes_by_name;

	//Lock to allow concurrent readers and a single writer to the remote_indexes hash table
	pthread_rwlock_t *indexes_lock;

	//The range server structure which is used only if we are a range server
	mdhim_rs_t *mdhim_rs;
	//The mutex used if receiving from ourselves
	pthread_mutex_t *receive_msg_mutex;
	//The condition variable used if receiving from ourselves
	pthread_cond_t *receive_msg_ready_cv;
	/* The receive msg, which is sent to the client by the
	   range server running in the same process */
	//void *receive_msg;
	int receive_msg_cnt;
	struct list_head receive_msg_list;

        //Options for DB creation
        mdhim_options_t *db_opts;
};

struct secondary_info {
	struct index_t *secondary_index;
	void **secondary_keys;
	int *secondary_key_lens;
	int num_keys;
	int info_type;
};

struct secondary_bulk_info {
	struct index_t *secondary_index;
	void ***secondary_keys;
	int **secondary_key_lens;
	int *num_keys;
	int info_type;
};

struct mdhim_t *mdhimInit(void *appComm, struct mdhim_options_t *opts);
int mdhimClose(struct mdhim_t *md);
int mdhimCommit(struct mdhim_t *md, struct index_t *index);
int mdhimStatFlush(struct mdhim_t *md, struct index_t *index);
struct mdhim_brm_t *mdhimPut(struct mdhim_t *md, struct index_t *index,
			     void *key, int key_len,
			     void *value, int value_len,
			     struct secondary_info *secondary_global_info,
			     struct secondary_info *secondary_local_info);
struct mdhim_brm_t *mdhimPutSecondary(struct mdhim_t *md,
				      struct index_t *secondary_index,
				      /*Secondary key */
				      void *secondary_key, int secondary_key_len,
				      /* Primary key */
				      void *primary_key, int primary_key_len);
struct mdhim_brm_t *mdhimBPut(struct mdhim_t *md, struct index_t *index,
			      void **primary_keys, int *primary_key_lens,
			      void **primary_values, int *primary_value_lens,
			      int num_records,
			      struct secondary_bulk_info *secondary_global_info,
			      struct secondary_bulk_info *secondary_local_info);
struct mdhim_brm_t *bput2_records(struct mdhim_t *md, struct index_t *index,
                                  struct mdhim_bput2m_t *message);
struct mdhim_bgetrm_t *mdhimGet(struct mdhim_t *md, struct index_t *index,
			       void *key, int key_len,
			       int op);
struct mdhim_bgetrm_t *mdhimBGet(struct mdhim_t *md, struct index_t *index,
				 void **keys, int *key_lens,
				 int num_records, int op);
struct mdhim_bgetrm_t *mdhimBGetOp(struct mdhim_t *md, struct index_t *index,
				   void *key, int key_len,
				   int num_records, int op);

struct mdhim_bgetrm_t *mdhimBGetRange(struct mdhim_t *md, struct index_t *index,
				   void *start_key, void *end_key, int key_len);

struct mdhim_brm_t *mdhimDelete(struct mdhim_t *md, struct index_t *index,
			       void *key, int key_len);
struct mdhim_brm_t *mdhimBDelete(struct mdhim_t *md, struct index_t *index,
				 void **keys, int *key_lens,
				 int num_keys);
struct secondary_info *mdhimCreateSecondaryInfo(struct index_t *secondary_index,
						void **secondary_keys, int *secondary_key_lens,
						int num_keys, int info_type);

void mdhimReleaseSecondaryInfo(struct secondary_info *si);
struct secondary_bulk_info *mdhimCreateSecondaryBulkInfo(struct index_t *secondary_index,
							 void ***secondary_keys,
							 int **secondary_key_lens,
							 int *num_keys, int info_type);
void mdhimReleaseSecondaryBulkInfo(struct secondary_bulk_info *si);
int mdhimSanitize(char *dbfilename, char *statfilename, char *manifestfilename);
int rmrf(char *path);

ssize_t mdhim_ps_bget(struct mdhim_t *md, struct index_t *index, unsigned long *buf,
    size_t size, uint64_t *keys, int op);
int mdhim_ps_bput(struct mdhim_t *md, struct index_t *index, unsigned long *buf,
    size_t size, void **keys, size_t value_len);
int mdhim_ps_bdel(struct mdhim_t *md, struct index_t *index, size_t size,
    void **keys);

#ifdef __cplusplus
}
#endif
#endif
