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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <linux/limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "mdhim.h"
#include "range_server.h"
#include "partitioner.h"
#include "mdhim_options.h"
#include "ds_leveldb.h"
#include "uthash.h"

#include "list.h"
#include "f_error.h"


int recv_counter = 0;

struct timeval resp_put_comm_start, resp_put_comm_end;
double resp_put_comm_time = 0;

struct timeval resp_get_comm_start, resp_get_comm_end;
double resp_get_comm_time = 0;
struct index_t *tmp_index;

 //struct timeval worker_start, worker_end;
double worker_time=0;

struct timeval listener_start, listener_end;
double listener_time=0;

 //struct timeval worker_get_start, worker_get_end;
double worker_get_time=0;

 //struct timeval worker_put_start, worker_put_end;
double worker_put_time=0;

struct timeval stat_start, stat_end;
double stat_time=0;

struct timeval odbgetstart, odbgetend;
double odbgettime=0;

struct timeval statstart, statend;
double starttime=0;

int putflag = 1;


int unifycr_compare(const char* a, const char* b) {
	int ret;

	long offset, old_offset;
	long fid, old_fid;

	fid = *((unsigned long *)a);
	old_fid = *((unsigned long *)b);

	offset = *((unsigned long *)a+1);
	old_offset = *((unsigned long *)b+1);

	ret = fid - old_fid;

	if (ret != 0)
			return ret;
	else {
		if (offset - old_offset > 0)
				return 1;
		else if(offset - old_offset < 0)
				return -1;
		else
				return 0;
	}

	return ret;
}

void add_timing(struct timeval start, struct timeval end, int num, 
		struct mdhim_t *md, int mtype) {
	long double elapsed;

	elapsed = (long double) (end.tv_sec - start.tv_sec) + 
		((long double) (end.tv_usec - start.tv_usec)/1000000.0);
	if (mtype == MDHIM_PUT || mtype == MDHIM_BULK_PUT) {
		md->mdhim_rs->put_time += elapsed;
		md->mdhim_rs->num_put += num;
	} else if (mtype == MDHIM_BULK_GET) {
		md->mdhim_rs->get_time += elapsed;
		md->mdhim_rs->num_get += num;
	}
}

/**
 * send_locally_or_remote
 * Sends the message remotely or locally
 *
 * @param md       Pointer to the main MDHIM structure
 * @param dest     Destination rank
 * @param message  pointer to message to send
 * @param tag      client response queue tag
 * @return MDHIM_SUCCESS or MDHIM_ERROR on error
 */
int send_locally_or_remote(struct mdhim_t *md, int dest, void *message, void *tag) {
	int ret = MDHIM_SUCCESS;

	if (md->mdhim_rank != dest) {
		int sizebuf;
		void *sendbuf;

		ret = send_client_response(md, dest, message,
			&sizebuf, &sendbuf);
		mdhim_full_release_msg(message);
		free(sendbuf);
	} else {
		struct mdhim_basem_t *msg = (struct mdhim_basem_t *) message;

		//Sends the message locally
		INIT_LIST_HEAD(&msg->rcv_msg_item);
		msg->rcv_msg_tag = tag;

		pthread_mutex_lock(md->receive_msg_mutex);
		//md->receive_msg = message;
		list_add(&msg->rcv_msg_item, &md->receive_msg_list);
		md->receive_msg_cnt++;
		//pthread_cond_signal(md->receive_msg_ready_cv);
		pthread_cond_broadcast(md->receive_msg_ready_cv);
		pthread_mutex_unlock(md->receive_msg_mutex);
	}

	return ret;
}

struct index_t *find_index(struct mdhim_t *md, struct mdhim_basem_t *msg) {
	struct index_t *ret;
       
	ret = get_index(md, msg->index);

	return ret;

}

#if 0
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  find_index_by_name
 *  Description:  Search for index by name
 *    Variables:  <struct mdhim_t *md> the pointer to the mdhim structure
 *                <struct mdhim_basem_t *msg> A pointer to a base message that contains
 *                                            the name of the index
 * =====================================================================================
 */
struct index_t * find_index_by_name(struct mdhim_t *md, struct mdhim_basem_t *msg) {
    struct index_t *ret;

    ret = get_index_by_name(md, msg->index_name);

    return ret;
}
#endif

/**
 * range_server_add_work
 * Adds work to the work queue and signals the condition variable for the worker thread
 *
 * @param md      Pointer to the main MDHIM structure
 * @param item    pointer to new work item that contains a message to handle
 * @return MDHIM_SUCCESS
 */
int range_server_add_work(struct mdhim_t *md, work_item *item) {
	//Lock the work queue mutex
	pthread_mutex_lock(md->mdhim_rs->work_queue_mutex);
	item->next = NULL;
	item->prev = NULL;

	//Add work to the tail of the work queue
	if (md->mdhim_rs->work_queue->tail) {
		md->mdhim_rs->work_queue->tail->next = item;
		item->prev = md->mdhim_rs->work_queue->tail;
		md->mdhim_rs->work_queue->tail = item;
	} else {
		md->mdhim_rs->work_queue->head = item;
		md->mdhim_rs->work_queue->tail = item;
	}

	//Signal the waiting thread that there is work available
	pthread_cond_signal(md->mdhim_rs->work_ready_cv);
	pthread_mutex_unlock(md->mdhim_rs->work_queue_mutex);

	return MDHIM_SUCCESS;
}

/**
 * get_work
 * Returns the next work item from the work queue
 *
 * @param md  Pointer to the main MDHIM structure
 * @return  the next work_item to process
 */

work_item *get_work(struct mdhim_t *md) {
	work_item *item;

	item = md->mdhim_rs->work_queue->head;
	if (!item) {
		return NULL;
	}

	//Set the list head and tail to NULL
	md->mdhim_rs->work_queue->head = NULL;
	md->mdhim_rs->work_queue->tail = NULL;

	//Return the list
	return item;
}

/**
 * range_server_stop
 * Stop the range server (i.e., stops the threads and frees the relevant data in md)
 *
 * @param md  Pointer to the main MDHIM structure
 * @return    MDHIM_SUCCESS or MDHIM_ERROR on error
 */
int range_server_stop(struct mdhim_t *md) {
	int i, ret;
	work_item *head, *temp_item;

	//Signal to the listener thread that it needs to shutdown
	md->shutdown = 1;
	i = 0;
	ret = MPI_Send(&i, 1, MPI_INT, md->mdhim_rank, RANGESRV_WORK_SIZE_MSG, md->mdhim_comm);
	mlog(MDHIM_SERVER_INFO, "Rank: %d - Signal listener shutdown, ret:%d",
	     md->mdhim_rank, ret);

	/* Wait for the threads to finish */
	pthread_cond_broadcast(md->mdhim_rs->work_ready_cv);
	pthread_join(md->mdhim_rs->listener, NULL);
	/* Wait for the threads to finish */
	for (i = 0; i < md->db_opts->num_wthreads; i++) {
		pthread_join(*md->mdhim_rs->workers[i], NULL);
		free(md->mdhim_rs->workers[i]);
	}
	free(md->mdhim_rs->workers);
		
	//Destroy the condition variables
	if ((ret = pthread_cond_destroy(md->mdhim_rs->work_ready_cv)) != 0) {
	  mlog(MDHIM_SERVER_DBG, "Rank: %d - Error destroying work cond variable", 
	       md->mdhim_rank);
	}
	free(md->mdhim_rs->work_ready_cv);

	//Destroy the work queue mutex
	if ((ret = pthread_mutex_destroy(md->mdhim_rs->work_queue_mutex)) != 0) {
	  mlog(MDHIM_SERVER_DBG, "Rank: %d - Error destroying work queue mutex", 
	       md->mdhim_rank);
	}
	free(md->mdhim_rs->work_queue_mutex);
		
	//Clean outstanding sends
	/* TODO: Clean outstanding sends! */
	//Destroy the out req mutex
	if ((ret = pthread_mutex_destroy(md->mdhim_rs->out_req_mutex)) != 0) {
	  mlog(MDHIM_SERVER_DBG, "Rank: %d - Error destroying work queue mutex", 
	       md->mdhim_rank);
	}
	free(md->mdhim_rs->out_req_mutex);
		
	//Free the work queue
	head = md->mdhim_rs->work_queue->head;
	while (head) {
	  temp_item = head->next;
	  free(head);
	  head = temp_item;
	}
	free(md->mdhim_rs->work_queue);
		
	mlog(MDHIM_SERVER_INFO, "Rank: %d - Inserted: %ld records in %Lf seconds", 
	     md->mdhim_rank, md->mdhim_rs->num_put, md->mdhim_rs->put_time);
	mlog(MDHIM_SERVER_INFO, "Rank: %d - Retrieved: %ld records in %Lf seconds", 
	     md->mdhim_rank, md->mdhim_rs->num_get, md->mdhim_rs->get_time);
	  
	//Free the range server data
	free(md->mdhim_rs);
	md->mdhim_rs = NULL;

	return MDHIM_SUCCESS;
}

/**
 * range_server_put
 * Handles the put message and puts data in the database
 *
 * @param md        pointer to the main MDHIM struct
 * @param im        pointer to the put message to handle
 * @param source    source of the message
 * @return          MDHIM_SUCCESS or MDHIM_ERROR on error
 */
int range_server_put(struct mdhim_t *md, struct mdhim_putm_t *im, int source) {
	int ret;
	struct mdhim_rm_t *rm;
	int error = 0;
 /*
	void **value;
	int32_t *value_len;
 */
	int exists = 0;
	void *new_value;
	int32_t new_value_len;
 /*
	void *old_value;
	int32_t old_value_len;
 */
	struct timeval start, end;
	int inserted = 0;
	struct index_t *index;

 /*
	value = malloc(sizeof(void *));
	*value = NULL;
	value_len = malloc(sizeof(int32_t));
	*value_len = 0;
 */
	//Get the index referenced the message
	index = find_index(md, (struct mdhim_basem_t *) im);
	if (!index) {
		mlog(MDHIM_SERVER_CRIT, "Rank: %d - Error retrieving index for id: %d", 
		     md->mdhim_rank, im->basem.index);
		error = MDHIM_ERROR;
		goto done;
	}

	gettimeofday(&start, NULL);
       //Check for the key's existence
/*	index->mdhim_store->get(index->mdhim_store->db_handle, 
				       im->key, im->key_len, value, 
				       value_len);
*/
 /*
	//The key already exists
	if (*value && *value_len) {
		exists = 1;
	}

        //If the option to append was specified and there is old data, concat the old and new
	if (exists &&  md->db_opts->db_value_append == MDHIM_DB_APPEND) {
		old_value = *value;
		old_value_len = *value_len;
		new_value_len = old_value_len + im->value_len;
		new_value = malloc(new_value_len);
		memcpy(new_value, old_value, old_value_len);
		memcpy(new_value + old_value_len, im->value, im->value_len);
	} else {
 */
		new_value = im->value;
		new_value_len = im->value_len;
 /*
	}
    
	if (*value && *value_len) {
		free(*value);
	}
	free(value);
	free(value_len);
 */
        //Put the record in the database
	if ((ret = 
	     index->mdhim_store->put(index->mdhim_store->db_handle, 
				     im->key, im->key_len, new_value, 
				     new_value_len)) != MDHIM_SUCCESS) {
		mlog(MDHIM_SERVER_CRIT, "Rank: %d - Error putting record", 
		     md->mdhim_rank);	
		error = ret;
	} else {
		inserted = 1;
	}

	if (!exists && error == MDHIM_SUCCESS) {
		gettimeofday(&stat_start, NULL);
		update_stat(md, index, im->key, im->key_len);
		gettimeofday(&stat_end, NULL);
		stat_time += 1000000 * (stat_end.tv_sec - stat_start.tv_sec) + \
			stat_end.tv_usec - stat_start.tv_usec;
	}

	gettimeofday(&end, NULL);
	add_timing(start, end, inserted, md, MDHIM_PUT);

done:
	//Create the response message
	rm = malloc(sizeof(struct mdhim_rm_t));
	//Set the type
	rm->basem.mtype = MDHIM_RECV;
	//Set the operation return code as the error
	rm->error = error;
	//Set the server's rank
	rm->basem.server_rank = md->mdhim_rank;
	//Set index id
	rm->basem.index = index->id;
	//Set msg id
	rm->basem.msg_id = im->basem.msg_id;

	//Send response
	gettimeofday(&resp_put_comm_start, NULL);
	ret = send_locally_or_remote(md, source, rm, im);
 /*
 struct timeval en, tm, tm2;
 gettimeofday(&en, NULL);
 timersub(&stat_start, &start, &tm);
 timersub(&en, &resp_put_comm_start, &tm2);
 mlog(MDHIM_SERVER_INFO, ".. range_server_put key:%08x put:%ld send:%ld (%s)",
  *((unsigned int*)im->key), tm.tv_usec, tm2.tv_usec,
  (md->mdhim_rank == source)?"l":"R");
 */

	//Free memory
 /*
	if (exists && md->db_opts->db_value_append == MDHIM_DB_APPEND) {
		free(new_value);
	}
 */
	if (source != md->mdhim_rank) {
		free(im->key);
		free(im->value);
	}
	free(im);
	return MDHIM_SUCCESS;
}

static int range_server_bput2(struct mdhim_t *md, struct index_t *index,
    struct mdhim_bput2m_t *bim, int source)
{
	struct mdhim_rm_t *brm;
	int ret;
	int error = MDHIM_SUCCESS;
	int sizebuf;
	void *sendbuf;

	ASSERT( index->id == 0 ); /* suppost for I/O ranges Table only */
	ASSERT( bim->basem.seg_count == 1 ); /* support for one message segment only */
	ASSERT( bim->seg.seg_id == 0 );

	//Put the record in the database
	if ((ret = mdhim_leveldb_batch_put2(index->mdhim_store->db_handle,
					    bim->seg.kvs, bim->seg.kv_length, bim->seg.key_len,
					    bim->seg.num_keys)) != MDHIM_SUCCESS) {
		mlog(MDHIM_SERVER_CRIT, "Rank: %d - Error batch putting records",
		     md->mdhim_rank);
		error = ret;
	}

	//Create the response message
	brm = malloc(sizeof(struct mdhim_rm_t));
	//Set the type
	brm->basem.mtype = MDHIM_RECV;
	//Set the operation return code as the error
	brm->error = error;
	//Set the server's rank
	brm->basem.server_rank = md->mdhim_rank;
	//Set index id
	brm->basem.index = index->id;
	//Set msg id
	brm->basem.msg_id = bim->seg.seg_msg_id;

	gettimeofday(&resp_put_comm_start, NULL);

	/* TODO: Allow this assert if not running on a single node */
	//ASSERT( source != md->mdhim_rank ); /* message isn't coming from myself */

	//Send response remotely (send_locally_or_remote)
	ret = send_client_response(md, source, brm, &sizebuf, &sendbuf);
	free(sendbuf);

	mdhim_full_release_msg(brm);
	mdhim_full_release_msg(bim);

	return ret;
}

/**
 * range_server_bput
 * Handles the bulk put message and puts data in the database
 *
 * @param md        Pointer to the main MDHIM struct
 * @param bim       pointer to the bulk put message to handle
 * @param source    source of the message
 * @return    MDHIM_SUCCESS or MDHIM_ERROR on error
 */
int range_server_bput(struct mdhim_t *md, void *message, int source) {
	putflag = 1;
	int i;
	int ret;
	int error = MDHIM_SUCCESS;
	struct mdhim_rm_t *brm;
	void **value;
	int32_t *value_len;
	int *exists;
	void *new_value;
	int32_t new_value_len;
	void **new_values;
	int32_t *new_value_lens;
	void *old_value;
	int32_t old_value_len;
	struct timeval start, end;
	int num_put = 0;
	struct index_t *index;
	struct mdhim_basem_t *basem = (struct mdhim_basem_t *) message;

	gettimeofday(&start, NULL);

	//Get the index referenced the message
	index = find_index(md, basem);
	if (!index) {
		mlog(MDHIM_SERVER_CRIT, "Rank: %d - Error retrieving index for id: %d", 
		     md->mdhim_rank, basem->index);
		error = MDHIM_ERROR;
		goto done;
	}

	// I/O ranges Table?
	if (index->id == 0) {
		return range_server_bput2(md, index, (struct mdhim_bput2m_t *)message, source);
	}

	struct mdhim_bputm_t *bim = (struct mdhim_bputm_t *) message;

	exists = malloc(bim->num_keys * sizeof(int));
	new_values = malloc(bim->num_keys * sizeof(void *));
	new_value_lens = malloc(bim->num_keys * sizeof(int));
	value = malloc(sizeof(void *));
	value_len = malloc(sizeof(int32_t));

	for (i = 0; i < bim->num_keys && i < MAX_BULK_OPS; i++) {	
		*value = NULL;
		*value_len = 0;

		gettimeofday(&odbgetstart, NULL);
/*		index->mdhim_store->get(index->mdhim_store->db_handle, 
					       bim->keys[i], bim->key_lens[i], value, 
					       value_len);
*/
		if (*value && *value_len) {
			exists[i] = 1;
		} else {
			exists[i] = 0;
		}

		exists[i] = 0;
		if (exists[i] && md->db_opts->db_value_append == MDHIM_DB_APPEND) {
			old_value = *value;
			old_value_len = *value_len;
			new_value_len = old_value_len + bim->value_lens[i];
			new_value = malloc(new_value_len);
			memcpy(new_value, old_value, old_value_len);
			memcpy(new_value + old_value_len, bim->values[i], bim->value_lens[i]);		
			if (exists[i] && source != md->mdhim_rank) {
				free(bim->values[i]);
			}

			new_values[i] = new_value;
			new_value_lens[i] = new_value_len;
		} else {
			new_values[i] = bim->values[i];
			new_value_lens[i] = bim->value_lens[i];

		}
		
		if (*value) {
			free(*value);
		}	
		gettimeofday(&odbgetend, NULL);
		odbgettime+=1000000 * (odbgetend.tv_sec\
				- odbgetstart.tv_sec) + odbgetend.tv_usec - odbgetstart.tv_usec;
	}

	//Put the record in the database
	if ((ret = 
	     index->mdhim_store->batch_put(index->mdhim_store->db_handle, 
					   bim->keys, bim->key_lens, new_values, 
					   new_value_lens, bim->num_keys)) != MDHIM_SUCCESS) {
		mlog(MDHIM_SERVER_CRIT, "Rank: %d - Error batch putting records", 
		     md->mdhim_rank);
		error = ret;
	} else {
		num_put = bim->num_keys;
	}

	gettimeofday(&stat_start, NULL);
	for (i = 0; i < bim->num_keys && i < MAX_BULK_OPS; i++) {
		//Update the stats if this key didn't exist before
		if (!exists[i] && error == MDHIM_SUCCESS) {
			update_stat(md, index, bim->keys[i], bim->key_lens[i]);
		}
	       
		if (exists[i] && md->db_opts->db_value_append == MDHIM_DB_APPEND) {
			//Release the value created for appending the new and old value
			free(new_values[i]);
		}		

		//Release the bput keys/value if the message isn't coming from myself
		if (source != md->mdhim_rank) {
			free(bim->keys[i]);
			free(bim->values[i]);
		} 
	}
	gettimeofday(&stat_end, NULL);
	stat_time += 1000000 * (stat_end.tv_sec - stat_start.tv_sec) + \
		stat_end.tv_usec - stat_start.tv_usec;

	free(exists);
	free(new_values);
	free(new_value_lens);
	free(value);
	free(value_len);

	//Release the internals of the bput message
	free(bim->keys);
	free(bim->key_lens);
	free(bim->values);
	free(bim->value_lens);

	gettimeofday(&end, NULL);
	add_timing(start, end, num_put, md, MDHIM_BULK_PUT);

 done:
	//Create the response message
	brm = malloc(sizeof(struct mdhim_rm_t));
	//Set the type
	brm->basem.mtype = MDHIM_RECV;
	//Set the operation return code as the error
	brm->error = error;
	//Set the server's rank
	brm->basem.server_rank = md->mdhim_rank;
	//Set index id
	brm->basem.index = index->id;
	//Set msg id
	brm->basem.msg_id = basem->msg_id;

	//Send response
	gettimeofday(&resp_put_comm_start, NULL);
	ret = send_locally_or_remote(md, source, brm, message);
	free(message);

	return MDHIM_SUCCESS;
}

/**
 * range_server_del
 * Handles the delete message and deletes the data from the database
 *
 * @param md       Pointer to the main MDHIM struct
 * @param dm       pointer to the delete message to handle
 * @param source   source of the message
 * @return    MDHIM_SUCCESS or MDHIM_ERROR on error
 */
int range_server_del(struct mdhim_t *md, struct mdhim_delm_t *dm, int source) {
	int ret = MDHIM_ERROR;
	struct mdhim_rm_t *rm;
	struct index_t *index;

	//Get the index referenced the message
	index = find_index(md, (struct mdhim_basem_t *) dm);
	if (!index) {
		mlog(MDHIM_SERVER_CRIT, "Rank: %d - Error retrieving index for id: %d", 
		     md->mdhim_rank, dm->basem.index);
		ret = MDHIM_ERROR;
		goto done;
	}

	//Put the record in the database
	if ((ret = 
	     index->mdhim_store->del(index->mdhim_store->db_handle, 
				     dm->key, dm->key_len)) != MDHIM_SUCCESS) {
		mlog(MDHIM_SERVER_CRIT, "Rank: %d - Error deleting record", 
		     md->mdhim_rank);
	}

 done:
	//Create the response message
	rm = malloc(sizeof(struct mdhim_rm_t));
	//Set the type
	rm->basem.mtype = MDHIM_RECV;
	//Set the operation return code as the error
	rm->error = ret;
	//Set the server's rank
	rm->basem.server_rank = md->mdhim_rank;
	//Set index id
	rm->basem.index = index->id;
	//Set msg id
	rm->basem.msg_id = dm->basem.msg_id;

	//Send response
	ret = send_locally_or_remote(md, source, rm, dm);
	free(dm);

	return MDHIM_SUCCESS;
}

/**
 * range_server_bdel
 * Handles the bulk delete message and deletes the data from the database
 *
 * @param md        Pointer to the main MDHIM struct
 * @param bdm       pointer to the bulk delete message to handle
 * @param source    source of the message
 * @return    MDHIM_SUCCESS or MDHIM_ERROR on error
 */
int range_server_bdel(struct mdhim_t *md, struct mdhim_bdelm_t *bdm, int source) {
 	int i;
	int ret;
	int error = 0;
	struct mdhim_rm_t *brm;
	struct index_t *index;

	//Get the index referenced the message
	index = find_index(md, (struct mdhim_basem_t *) bdm);
	if (!index) {
		mlog(MDHIM_SERVER_CRIT, "Rank: %d - Error retrieving index for id: %d", 
		     md->mdhim_rank, bdm->basem.index);
		error = MDHIM_ERROR;
		goto done;
	}

	//Iterate through the arrays and delete each record
	for (i = 0; i < bdm->num_keys && i < MAX_BULK_OPS; i++) {
		//Put the record in the database
		if ((ret = 
		     index->mdhim_store->del(index->mdhim_store->db_handle, 
					     bdm->keys[i], bdm->key_lens[i])) 
		    != MDHIM_SUCCESS) {
			mlog(MDHIM_SERVER_CRIT, "Rank: %d - Error deleting record", 
			     md->mdhim_rank);
			error = ret;
		}
	}

done:
	//Create the response message
	brm = malloc(sizeof(struct mdhim_rm_t));
	//Set the type
	brm->basem.mtype = MDHIM_RECV;
	//Set the operation return code as the error
	brm->error = error;
	//Set the server's rank
	brm->basem.server_rank = md->mdhim_rank;
	//Set index id
	brm->basem.index = index->id;
	//Set msg id
	brm->basem.msg_id = bdm->basem.msg_id;

	//Send response
	ret = send_locally_or_remote(md, source, brm, bdm);
	free(bdm->keys);
	free(bdm->key_lens);
	free(bdm);

	return MDHIM_SUCCESS;
}

/**
 * range_server_commit
 * Handles the commit message and commits outstanding writes to the database
 *
 * @param md        pointer to the main MDHIM struct
 * @param im        pointer to the commit message to handle
 * @param source    source of the message
 * @return          MDHIM_SUCCESS or MDHIM_ERROR on error
 */
int range_server_commit(struct mdhim_t *md, struct mdhim_basem_t *im, int source) {
	int ret;
	struct mdhim_rm_t *rm;
	struct index_t *index;

	//Get the index referenced the message
	index = find_index(md, (struct mdhim_basem_t *) im);
	if (!index) {
		mlog(MDHIM_SERVER_CRIT, "Rank: %d - Error retrieving index for id: %d", 
		     md->mdhim_rank, im->index);
		ret = MDHIM_ERROR;
		goto done;
	}

        //Put the record in the database
	if ((ret = 
	     index->mdhim_store->commit(index->mdhim_store->db_handle)) 
	    != MDHIM_SUCCESS) {
		mlog(MDHIM_SERVER_CRIT, "Rank: %d - Error committing database", 
		     md->mdhim_rank);	
	}

 done:	
	//Create the response message
	rm = malloc(sizeof(struct mdhim_rm_t));
	//Set the type
	rm->basem.mtype = MDHIM_RECV;
	//Set the operation return code as the error
	rm->error = ret;
	//Set the server's rank
	rm->basem.server_rank = md->mdhim_rank;
	//Set index id
	rm->basem.index = index->id;
	//Set msg id
	rm->basem.msg_id = im->msg_id;

	//Send response
	ret = send_locally_or_remote(md, source, rm, im);
	free(im);

	return MDHIM_SUCCESS;
}

/**
 * range_server_bget
 * Handles the bulk get message, retrieves the data from the database, and sends the results back
 *
 * @param md        Pointer to the main MDHIM struct
 * @param bgm       pointer to the bulk get message to handle
 * @param source    source of the message
 * @return    MDHIM_SUCCESS or MDHIM_ERROR on error
 */
int range_server_bget(struct mdhim_t *md, struct mdhim_bgetm_t *bgm, int source) {
	putflag = 0;
	int ret;
	void **values;
	int32_t *value_lens;
	int i;
	struct mdhim_bgetrm_t *bgrm;
	int error = 0;
	struct timeval start, end;
	int num_retrieved = 0;
	struct index_t *index;

	gettimeofday(&start, NULL);
	if (bgm->op != MDHIM_RANGE_BGET) {
		values = malloc(sizeof(void *) * bgm->num_keys);
		value_lens = malloc(sizeof(int32_t) * bgm->num_keys);
		memset(value_lens, 0, sizeof(int32_t) * bgm->num_keys);
	}
	//Get the index referenced the message
	index = find_index(md, (struct mdhim_basem_t *) bgm);
	if (!index) {
		mlog(MDHIM_SERVER_CRIT, "Rank: %d - Error retrieving index for id: %d", 
		     md->mdhim_rank, bgm->basem.index);
		error = MDHIM_ERROR;
		goto done;
	}

	if (bgm->op == MDHIM_RANGE_BGET) {
		values = malloc(sizeof(void *) * bgm->num_keys/2);
		value_lens = malloc(sizeof(int32_t) * bgm->num_keys/2);
		memset(value_lens, 0, sizeof(int) * bgm->num_keys/2);

		void **ret_keys = malloc(bgm->num_keys * sizeof(char *)/2);
		int32_t *ret_key_lens = malloc(bgm->num_keys * sizeof(int32_t));
		memset(ret_key_lens, 0, sizeof(int) * bgm->num_keys/2);

		int out_record_cnt = 0;
		levedb_batch_ranges(index->mdhim_store->db_handle,
                                    (char **)bgm->keys, bgm->key_lens,
                                    (char ***)&ret_keys, &ret_key_lens,
                                    (char ***)&values, &value_lens,
                                    bgm->num_keys, &out_record_cnt);

		if (source != md->mdhim_rank) {
			for (i = 0; i < bgm->num_keys; i++) {
				free(bgm->keys[i]);
			}
		}
		free(bgm->key_lens);
		free(bgm->keys);

		bgm->keys = ret_keys;
		bgm->num_keys = out_record_cnt;
		bgm->key_lens = ret_key_lens;

	} else {
		for (i = 0; i < bgm->num_keys && i < MAX_BULK_OPS; i++) {
			switch(bgm->op) {
				// Gets the value for the given key
			case MDHIM_GET_EQ:
				//Get records from the database

				if ((ret =
					 index->mdhim_store->get(index->mdhim_store->db_handle,
								 bgm->keys[i], bgm->key_lens[i], &values[i],
								 &value_lens[i])) != MDHIM_SUCCESS) {
					error = ret;
					value_lens[i] = 0;
					values[i] = NULL;
					continue;
				}

				break;
				/* Gets the next key and value that is in order after the passed in key */
			case MDHIM_GET_NEXT:
				if ((ret =
					 index->mdhim_store->get_next(index->mdhim_store->db_handle,
								  &bgm->keys[i], &bgm->key_lens[i], &values[i],
								  &value_lens[i])) != MDHIM_SUCCESS) {
					mlog(MDHIM_SERVER_DBG, "Rank: %d - Error getting record", md->mdhim_rank);
					error = ret;
					value_lens[i] = 0;
					values[i] = NULL;
					continue;
				}

				/* at end? */
				if (bgm->num_keys == 1 && *bgm->key_lens == 0) {
					bgm->num_keys = 0;
					goto done;
				}

				break;
				/* Gets the previous key and value that is in order before the passed in key
				   or the last key if no key was passed in */
			case MDHIM_GET_PREV:
				if ((ret =
					 index->mdhim_store->get_prev(index->mdhim_store->db_handle,
								  &bgm->keys[i], &bgm->key_lens[i], &values[i],
								  &value_lens[i])) != MDHIM_SUCCESS) {
					mlog(MDHIM_SERVER_DBG, "Rank: %d - Error getting record", md->mdhim_rank);
					error = ret;
					value_lens[i] = 0;
					values[i] = NULL;
					continue;
				}

				break;
				/* Gets the first key/value */
			case MDHIM_GET_FIRST:
				if ((ret =
					 index->mdhim_store->get_next(index->mdhim_store->db_handle,
								  &bgm->keys[i], 0, &values[i],
								  &value_lens[i])) != MDHIM_SUCCESS) {
					mlog(MDHIM_SERVER_DBG, "Rank: %d - Error getting record", md->mdhim_rank);
					error = ret;
					value_lens[i] = 0;
					values[i] = NULL;
					continue;
				}

				break;
				/* Gets the last key/value */
			case MDHIM_GET_LAST:
				if ((ret =
					 index->mdhim_store->get_prev(index->mdhim_store->db_handle,
								  &bgm->keys[i], 0, &values[i],
								  &value_lens[i])) != MDHIM_SUCCESS) {
					mlog(MDHIM_SERVER_DBG, "Rank: %d - Error getting record", md->mdhim_rank);
					error = ret;
					value_lens[i] = 0;
					values[i] = NULL;
					continue;
				}

				break;
			default:
				mlog(MDHIM_SERVER_DBG, "Rank: %d - Invalid operation: %d given in range_server_get",
					 md->mdhim_rank, bgm->op);
				continue;
			}

			num_retrieved++;
		}
	}
	gettimeofday(&end, NULL);
	add_timing(start, end, num_retrieved, md, MDHIM_BULK_GET);

done:
	//Create the response message
	bgrm = malloc(sizeof(struct mdhim_bgetrm_t));
	//Set the type
	bgrm->basem.mtype = MDHIM_RECV_BULK_GET;
	//Set the operation return code as the error
	bgrm->error = error;
	//Set the server's rank
	bgrm->basem.server_rank = md->mdhim_rank;
	//Set the key and value
	if (source == md->mdhim_rank) {
		//If this message is coming from myself, copy the keys
		bgrm->key_lens = malloc(bgm->num_keys * sizeof(int));
		bgrm->keys = malloc(bgm->num_keys * sizeof(void *));
		for (i = 0; i < bgm->num_keys; i++) {
			bgrm->key_lens[i] = bgm->key_lens[i];
			bgrm->keys[i] = malloc(bgrm->key_lens[i]);
			memcpy(bgrm->keys[i], bgm->keys[i], bgrm->key_lens[i]);
		}

		free(bgm->keys);
		free(bgm->key_lens);
	} else {
		bgrm->keys = bgm->keys;
		bgrm->key_lens = bgm->key_lens;
	}

	bgrm->values = values;
	bgrm->value_lens = value_lens;
	bgrm->num_keys = bgm->num_keys;
	bgrm->basem.index = index->id;
	bgrm->basem.index_type = index->type;
	//Set msg id
	bgrm->basem.msg_id = bgm->basem.msg_id;

	mlog(MDHIM_SERVER_DBG, ".  [%d] found %d keys for [%d]",
		md->mdhim_rank, bgm->num_keys, source);

	//Send response
	gettimeofday(&resp_get_comm_start, NULL);
	ret = send_locally_or_remote(md, source, bgrm, bgm);

	//Release the bget message
	free(bgm);

	return MDHIM_SUCCESS;
}

/**
 * range_server_bget_op
 * Handles the get message given an op and number of records greater than 1
 *
 * @param md        Pointer to the main MDHIM struct
 * @param gm        pointer to the get message to handle
 * @param source    source of the message
 * @param op        operation to perform
 * @return    MDHIM_SUCCESS or MDHIM_ERROR on error
 */
int range_server_bget_op(struct mdhim_t *md, struct mdhim_bgetm_t *bgm, int source, int op) {
	putflag = 0;
	int error = 0;
	void **values;
	void **keys;
	void **get_key; //Used for passing the key to the db
	int *get_key_len; //Used for passing the key len to the db
	void **get_value;
	int *get_value_len;
	int32_t *key_lens;
	int32_t *value_lens;
	struct mdhim_bgetrm_t *bgrm;
	int ret;
	int i, j;
	int num_records;
	struct timeval start, end;
	struct index_t *index;

	//Initialize pointers and lengths
	values = malloc(sizeof(void *) * bgm->num_keys * bgm->num_recs);
	value_lens = malloc(sizeof(int32_t) * bgm->num_keys * bgm->num_recs);
	memset(value_lens, 0, sizeof(int32_t) *bgm->num_keys * bgm->num_recs);
	keys = malloc(sizeof(void *) * bgm->num_keys * bgm->num_recs);
	memset(keys, 0, sizeof(void *) * bgm->num_keys * bgm->num_recs);
	key_lens = malloc(sizeof(int32_t) * bgm->num_keys * bgm->num_recs);
	memset(key_lens, 0, sizeof(int32_t) * bgm->num_keys * bgm->num_recs);
	get_key = malloc(sizeof(void *));
	*get_key = NULL;
	get_key_len = malloc(sizeof(int32_t));
	*get_key_len = 0;
	get_value = malloc(sizeof(void *));
	get_value_len = malloc(sizeof(int32_t));
	num_records = 0;
	/*
	printf("range server bget op\n");
	fflush(stdout);
	*/
	//Get the index referenced the message
	index = find_index(md, (struct mdhim_basem_t *) bgm);
	if (!index) {
		mlog(MDHIM_SERVER_CRIT, "Rank: %d - Error retrieving index for id: %d", 
		     md->mdhim_rank, bgm->basem.index);
		error = MDHIM_ERROR;
		goto respond;
	}

	if (bgm->num_keys * bgm->num_recs > MAX_BULK_OPS) {
		/*
		printf("in range server, total bulk key%ld, recs %ld\n", bgm->num_keys, bgm->num_recs);
		fflush(stdout);
		*/
		mlog(MDHIM_SERVER_CRIT, "Rank: %d - Too many bulk operations requested", 
		     md->mdhim_rank);
		error = MDHIM_ERROR;
		goto respond;
	}

//	mlog(MDHIM_SERVER_CRIT, "Rank: %d - Num keys is: %d and num recs is: %d", 
//	     md->mdhim_rank, bgm->num_keys, bgm->num_recs);

	gettimeofday(&start, NULL);
	//Iterate through the arrays and get each record
	if (op != MDHIM_GET_NEXT) {
		for (i = 0; i < bgm->num_keys; i++) {
			for (j = 0; j < bgm->num_recs; j++) {
				keys[num_records] = NULL;
				key_lens[num_records] = 0;

				//If we were passed in a key, copy it
				if (!j && bgm->key_lens[i] && bgm->keys[i]) {
					*get_key = malloc(bgm->key_lens[i]);
					memcpy(*get_key, bgm->keys[i], bgm->key_lens[i]);
					*get_key_len = bgm->key_lens[i];
					//If we were not passed a key and this is a next/prev, then return an error
				} else if (!j && (!bgm->key_lens[i] || !bgm->keys[i])
					   && (op ==  MDHIM_GET_NEXT ||
						   op == MDHIM_GET_PREV)) {
					error = MDHIM_ERROR;
					goto respond;
				}

				switch(op) {
					//Get a record from the database
				case MDHIM_GET_FIRST:
					if (j == 0) {
						keys[num_records] = NULL;
						key_lens[num_records] = sizeof(int32_t);
					}
					/* FALLTHROUGH */
				case MDHIM_GET_NEXT:

					if (j && (ret =
						  index->mdhim_store->get_next(index->mdhim_store->db_handle,
										   get_key, get_key_len,
										   get_value,
										   get_value_len))
						!= MDHIM_SUCCESS) {
						mlog(MDHIM_SERVER_DBG, "Rank: %d - Couldn't get next record",
							 md->mdhim_rank);
						error = ret;

						key_lens[num_records] = 0;
						value_lens[num_records] = 0;
						goto respond;
					} else if (!j && (ret =
							  index->mdhim_store->get(index->mdhim_store->db_handle,
										  *get_key, *get_key_len,
										  get_value,
										  get_value_len))
						   != MDHIM_SUCCESS) {
					 if ((ret = index->mdhim_store->get_next(index->mdhim_store->db_handle,\
										  get_key, get_key_len, get_value, \
												get_value_len)) != MDHIM_SUCCESS) {

						 key_lens[num_records] = 0;
						 value_lens[num_records] = 0;
						 goto respond;
						}
					}

					break;
				case MDHIM_GET_LAST:
					if (j == 0) {
						keys[num_records] = NULL;
						key_lens[num_records] = sizeof(int32_t);
					}
					/* FALLTHROUGH */
				case MDHIM_GET_PREV:
					if (j && (ret =
						  index->mdhim_store->get_prev(index->mdhim_store->db_handle,
										   get_key, get_key_len,
										   get_value,
										   get_value_len))
						!= MDHIM_SUCCESS) {
						mlog(MDHIM_SERVER_DBG, "Rank: %d - Couldn't get prev record",
							 md->mdhim_rank);
						error = ret;
						key_lens[num_records] = 0;
						value_lens[num_records] = 0;
						goto respond;
					} else if (!j && (ret =
							  index->mdhim_store->get(index->mdhim_store->db_handle,
										  *get_key, *get_key_len,
										  get_value,
										  get_value_len))
						   != MDHIM_SUCCESS) {
						error = ret;
						key_lens[num_records] = 0;
						value_lens[num_records] = 0;
						goto respond;
					}
					break;
				default:
					mlog(MDHIM_SERVER_CRIT, "Rank: %d - Invalid operation for bulk get op",
						 md->mdhim_rank);
					goto respond;
					break;
				}

				keys[num_records] = *get_key;
				key_lens[num_records] = *get_key_len;
				values[num_records] = *get_value;
				value_lens[num_records] = *get_value_len;
				num_records++;
			}
		}
	}
	else {
		for (i = 0; i < bgm->num_keys; i++) {
			for (j = 0; j < bgm->num_recs; j++) {
				keys[i*bgm->num_recs+j] = NULL;
				key_lens[i*bgm->num_recs+j] = 0;
			}
		}

		num_records = 0;
		*get_key = malloc(bgm->key_lens[0]);
		memcpy(*get_key, bgm->keys[0], bgm->key_lens[0]);
		keys[0] = *get_key;
		*get_key_len = bgm->key_lens[0];
		key_lens[0] = *get_key_len;

		error = mdhim_levedb_batch_next(index->mdhim_store->db_handle,
						(char **)keys, key_lens,
						(char **)values, value_lens,
						bgm->num_keys * bgm->num_recs,
						&num_records);

		/* It's Ok to do bulk get with op=MDHIM_GET_NEXT and
		retreive any number of records */
		if (error == MDHIM_DB_RESIDUAL)
			error = MDHIM_SUCCESS;
	}

respond:

	gettimeofday(&end, NULL);
	add_timing(start, end, num_records, md, MDHIM_BULK_GET);

	//Create the response message
	bgrm = malloc(sizeof(struct mdhim_bgetrm_t));
	//Set the type
	bgrm->basem.mtype = MDHIM_RECV_BULK_GET;
	//Set the operation return code as the error
	bgrm->error = error;
	//Set the server's rank
	bgrm->basem.server_rank = md->mdhim_rank;
	//Set the keys and values
	bgrm->keys = keys;
	bgrm->key_lens = key_lens;
	bgrm->values = values;
	bgrm->value_lens = value_lens;
	bgrm->num_keys = num_records;
	bgrm->basem.index = index->id;
	bgrm->basem.index_type = index->type;
	//Set msg id
	bgrm->basem.msg_id = bgm->basem.msg_id;

	//Send response
	gettimeofday(&resp_get_comm_start, NULL);
	ret = send_locally_or_remote(md, source, bgrm, bgm);
	//Free stuff
	if (source == md->mdhim_rank) {
		/* If this message is not coming from myself,
		   free the keys and values from the get message */
		mdhim_partial_release_msg(bgm);
	}

	free(get_key);
	free(get_key_len);
	free(get_value);
	free(get_value_len);

	return MDHIM_SUCCESS;
}

/*
 * listener_thread
 * Function for the thread that listens for new messages
 */
void *listener_thread(void *data) {
	//Mlog statements could cause a deadlock on range_server_stop due to canceling of threads
	

	struct mdhim_t *md = (struct mdhim_t *) data;
	void *message;
	int source; //The source of the message
	int ret;
	work_item *item;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	while (1) {
		if (md->shutdown) {
			break;
		}	

		//Clean outstanding sends

		//Receive messages sent to this server
		ret = receive_rangesrv_work(md, &source, &message);
		if (ret < MDHIM_SUCCESS) {		
			continue;
		}
		gettimeofday(&listener_start, NULL);
		//printf("Rank: %d - Received message from rank: %d of type: %d", 
		//     md->mdhim_rank, source, mtype);
		recv_counter++;
		//Create a new work item
		item = malloc(sizeof(work_item));
		memset(item, 0, sizeof(work_item));
		             
		//Set the new buffer to the new item's message
		item->message = message;
		//Set the source in the work item
		item->source = source;
		//Add the new item to the work queue
		range_server_add_work(md, item);
		gettimeofday(&listener_end, NULL);
		listener_time += 1000000L*(listener_end.tv_sec-listener_start.tv_sec)+listener_end.tv_usec-listener_start.tv_usec;

 mlog(MDHIM_SERVER_INFO, ".  listener - message id:%d from rank:%d of type:%d for index:%d, time:%ld",
  ((struct mdhim_basem_t *)item->message)->msg_id,
  source, ((struct mdhim_basem_t *)item->message)->mtype, ((struct mdhim_basem_t *)item->message)->index,
  1000000L*(listener_end.tv_sec-listener_start.tv_sec)+listener_end.tv_usec-listener_start.tv_usec);

	}

	return NULL;
}

static void _pthread_mutex_unlock(pthread_mutex_t *mutex) {
	(void) pthread_mutex_unlock(mutex);
}

/*
 * worker_thread
 * Function for the thread that processes work in work queue
 */
void *worker_thread(void *data) {
	//Mlog statements could cause a deadlock on range_server_stop due to canceling of threads
	struct mdhim_t *md = (struct mdhim_t *) data;
	work_item *item, *item_tmp;
	int mtype;
	int op, num_records, num_keys;
#define DEBUG_WRK_THREAD
#ifdef DEBUG_WRK_THREAD
	struct timeval worker_start, worker_end;
	struct timeval worker_get_start, worker_get_end;
	struct timeval worker_put_start, worker_put_end;
	struct timeval worker_zero;

	/* Get worker id */
	int i;
	/* We want worker_id declared volatile to prevent clobbering if re-ordered
	inside pthread_cleanup_push/pop */
	volatile int worker_id = -1;
	pthread_t thId = pthread_self();
	for (i = 0; i < md->db_opts->num_wthreads; i++) {
		if (pthread_equal(*md->mdhim_rs->workers[i], thId)) {
			worker_id = i;
			break;
		}
	}

	gettimeofday(&worker_zero, NULL);
#endif
	while (1) {
		if (md->shutdown) {
			break;
		}
		pthread_cleanup_push((void (*)(void *)) &_pthread_mutex_unlock,
				     (void *) md->mdhim_rs->work_queue_mutex);
		//Lock the work queue mutex
		pthread_mutex_lock(md->mdhim_rs->work_queue_mutex);

		//Wait until there is work to be performed
		while ((item = get_work(md)) == NULL && !md->shutdown) {
			pthread_cond_wait(md->mdhim_rs->work_ready_cv, md->mdhim_rs->work_queue_mutex);
			//item = get_work(md);
		}

		pthread_mutex_unlock(md->mdhim_rs->work_queue_mutex);
		pthread_cleanup_pop(0);

		gettimeofday(&worker_start, NULL);
		while (item) {
			//Call the appropriate function depending on the message type
			//Get the message type
			mtype = ((struct mdhim_basem_t *) item->message)->mtype;

#ifdef DEBUG_WRK_THREAD
			mlog(MDHIM_SERVER_INFO, ". RS worker[%d] - msg id:%d from rank:%d of type:%d (%s), current time:%ld",
			     worker_id, ((struct mdhim_basem_t *) item->message)->msg_id, item->source, mtype,
			     (mtype==MDHIM_PUT)?"PUT":(mtype==MDHIM_BULK_GET)?"BGET":
				(mtype==MDHIM_BULK_PUT)?"BPUT":(mtype==MDHIM_BULK_PUT2)?"BPUT2":"?",
			     1000000L*(worker_start.tv_sec-worker_zero.tv_sec)+worker_start.tv_usec-worker_zero.tv_usec);
#endif

			switch(mtype) {
			case MDHIM_PUT:
				gettimeofday(&worker_put_start, NULL);
				//Pack the put message and pass to range_server_put
				range_server_put(md,
						 item->message,
						 item->source);
				gettimeofday(&worker_put_end, NULL);
				worker_put_time += 1000000*(worker_put_end.tv_sec-worker_put_start.tv_sec)+worker_put_end.tv_usec-worker_put_start.tv_usec;
#ifdef DEBUG_WRK_THREAD
				mlog(MDHIM_SERVER_INFO, ".  [%d] MDHIM_PUT time:%ld",
				     worker_id,
				     1000000L*(worker_put_end.tv_sec-worker_put_start.tv_sec)+worker_put_end.tv_usec-worker_put_start.tv_usec);
#endif
				break;
			case MDHIM_BULK_PUT:
			case MDHIM_BULK_PUT2:
				//Pack the bulk put message and pass to range_server_put
				gettimeofday(&worker_put_start, NULL);
				range_server_bput(md,
						  item->message,
						  item->source);
				gettimeofday(&worker_put_end, NULL);
				worker_put_time += 1000000*(worker_put_end.tv_sec-worker_put_start.tv_sec)+worker_put_end.tv_usec-worker_put_start.tv_usec;
#ifdef DEBUG_WRK_THREAD
				mlog(MDHIM_SERVER_INFO, ".  [%d] MDHIM_BULK_PUT%c time:%ld",
				worker_id, (mtype==MDHIM_BULK_PUT2)?'2':' ',
				1000000L*(worker_put_end.tv_sec-worker_put_start.tv_sec)+worker_put_end.tv_usec-worker_put_start.tv_usec);
#endif
				break;
			case MDHIM_BULK_GET:
				gettimeofday(&worker_get_start, NULL);
				op = ((struct mdhim_bgetm_t *) item->message)->op;
				num_records = ((struct mdhim_bgetm_t *) item->message)->num_recs;
				num_keys = ((struct mdhim_bgetm_t *) item->message)->num_keys;
#ifdef DEBUG_WRK_THREAD
				mlog(MDHIM_SERVER_INFO, ".  [%d] MDHIM_BULK_GET op:%d num_records:%d num_keys:%d",
				     worker_id, op, num_records, num_keys);
#endif
				//The client is sending one key, but requesting the retrieval of more than one
				if (num_records > 1 && num_keys == 1) {
					range_server_bget_op(md,
							     item->message,
							     item->source, op);
				} else {
					range_server_bget(md,
							  item->message,
							  item->source);
				}

				gettimeofday(&worker_get_end, NULL);
				worker_get_time += 1000000*(worker_get_end.tv_sec-worker_get_start.tv_sec)+worker_get_end.tv_usec-worker_get_start.tv_usec;
#ifdef DEBUG_WRK_THREAD
				mlog(MDHIM_SERVER_INFO, ".  [%d] MDHIM_BULK_GET op:%d num_records:%d num_keys:%d time:%ld",
				worker_id, op, num_records, num_keys,
				1000000L*(worker_get_end.tv_sec-worker_get_start.tv_sec)+worker_get_end.tv_usec-worker_get_start.tv_usec);
#endif
				break;
			case MDHIM_DEL:
				range_server_del(md, item->message, item->source);
				break;
			case MDHIM_BULK_DEL:
				range_server_bdel(md, item->message, item->source);
				break;
			case MDHIM_COMMIT:
				range_server_commit(md, item->message, item->source);
				break;
			default:
				printf("Rank: %d - Got unknown work type: %d"
				       " from: %d\n", md->mdhim_rank, mtype, item->source);
				break;
			}

			item_tmp = item;
			pthread_mutex_lock(md->mdhim_rs->work_queue_mutex);
			item = item->next;
			pthread_mutex_unlock(md->mdhim_rs->work_queue_mutex);
			free(item_tmp);
		}

		//Clean outstanding sends
		if (putflag == 0) {
			gettimeofday(&resp_get_comm_end, NULL);
			resp_get_comm_time+=1000000*(resp_get_comm_end.tv_sec\
			-resp_get_comm_start.tv_sec)+resp_get_comm_end.tv_usec\
			-resp_get_comm_start.tv_usec;
		}
		else {
			gettimeofday(&resp_put_comm_end, NULL);
			resp_put_comm_time+=1000000*(resp_put_comm_end.tv_sec\
			-resp_put_comm_start.tv_sec)+resp_put_comm_end.tv_usec\
			-resp_put_comm_start.tv_usec;
		}
		gettimeofday(&worker_end, NULL);
		worker_time += 1000000*(worker_end.tv_sec-worker_start.tv_sec)+worker_end.tv_usec-worker_start.tv_usec;
#ifdef DEBUG_WRK_THREAD
		mlog(MDHIM_SERVER_INFO, ". worker[%d] time:%ld (total:%.0lf) current:%ld",
		     worker_id,
		     1000000L*(worker_end.tv_sec-worker_start.tv_sec)+worker_end.tv_usec-worker_start.tv_usec,
		     worker_time,
		     1000000L*(worker_end.tv_sec-worker_zero.tv_sec)+worker_end.tv_usec-worker_zero.tv_usec);
#endif
	}
	return NULL;
}

/**
 * range_server_init
 * Initializes the range server (i.e., starts the threads and populates the relevant data in md)
 *
 * @param md  Pointer to the main MDHIM structure
 * @return    MDHIM_SUCCESS or MDHIM_ERROR on error
 */
int range_server_init(struct mdhim_t *md) {
	int ret;
	int i;

	//Allocate memory for the mdhim_rs_t struct
	md->mdhim_rs = malloc(sizeof(struct mdhim_rs_t));
	if (!md->mdhim_rs) {
		mlog(MDHIM_SERVER_CRIT, "MDHIM Rank: %d - " 
		     "Error while allocating memory for range server", 
		     md->mdhim_rank);
		return MDHIM_ERROR;
	}

	//Initialize variables for printing out timings
	md->mdhim_rs->put_time = 0;
	md->mdhim_rs->get_time = 0;
	md->mdhim_rs->num_put = 0;
	md->mdhim_rs->num_get = 0;
	//Initialize work queue
	md->mdhim_rs->work_queue = malloc(sizeof(work_queue_t));
	md->mdhim_rs->work_queue->head = NULL;
	md->mdhim_rs->work_queue->tail = NULL;

	//Initialize the outstanding request list
	md->mdhim_rs->out_req_list = NULL;

	//Initialize work queue mutex
	md->mdhim_rs->work_queue_mutex = malloc(sizeof(pthread_mutex_t));
	if (!md->mdhim_rs->work_queue_mutex) {
		mlog(MDHIM_SERVER_CRIT, "MDHIM Rank: %d - " 
		     "Error while allocating memory for range server", 
		     md->mdhim_rank);
		return MDHIM_ERROR;
	}
	if ((ret = pthread_mutex_init(md->mdhim_rs->work_queue_mutex, NULL)) != 0) {    
		mlog(MDHIM_SERVER_CRIT, "MDHIM Rank: %d - " 
		     "Error while initializing work queue mutex", md->mdhim_rank);
		return MDHIM_ERROR;
	}

	//Initialize out req mutex
	md->mdhim_rs->out_req_mutex = malloc(sizeof(pthread_mutex_t));
	if (!md->mdhim_rs->out_req_mutex) {
		mlog(MDHIM_SERVER_CRIT, "MDHIM Rank: %d - " 
		     "Error while allocating memory for range server", 
		     md->mdhim_rank);
		return MDHIM_ERROR;
	}
	if ((ret = pthread_mutex_init(md->mdhim_rs->out_req_mutex, NULL)) != 0) {    
		mlog(MDHIM_SERVER_CRIT, "MDHIM Rank: %d - " 
		     "Error while initializing out req mutex", md->mdhim_rank);
		return MDHIM_ERROR;
	}

	//Initialize the condition variables
	md->mdhim_rs->work_ready_cv = malloc(sizeof(pthread_cond_t));
	if (!md->mdhim_rs->work_ready_cv) {
		mlog(MDHIM_SERVER_CRIT, "MDHIM Rank: %d - " 
		     "Error while allocating memory for range server", 
		     md->mdhim_rank);
		return MDHIM_ERROR;
	}
	if ((ret = pthread_cond_init(md->mdhim_rs->work_ready_cv, NULL)) != 0) {
		mlog(MDHIM_SERVER_CRIT, "MDHIM Rank: %d - " 
		     "Error while initializing condition variable", 
		     md->mdhim_rank);
		return MDHIM_ERROR;
	}
	
	//Initialize worker threads
	md->mdhim_rs->workers = malloc(sizeof(pthread_t *) * md->db_opts->num_wthreads);
	for (i = 0; i < md->db_opts->num_wthreads; i++) {
		md->mdhim_rs->workers[i] = malloc(sizeof(pthread_t));
		if ((ret = pthread_create(md->mdhim_rs->workers[i], NULL, 
					  worker_thread, (void *) md)) != 0) {    
			mlog(MDHIM_SERVER_CRIT, "MDHIM Rank: %d - " 
			     "Error while initializing worker thread", 
			     md->mdhim_rank);
			return MDHIM_ERROR;
		}
	}

	//Initialize listener threads
	if ((ret = pthread_create(&md->mdhim_rs->listener, NULL, 
				  listener_thread, (void *) md)) != 0) {
	  mlog(MDHIM_SERVER_CRIT, "MDHIM Rank: %d - " 
	       "Error while initializing listener thread", 
	       md->mdhim_rank);
	  return MDHIM_ERROR;
	}

	return MDHIM_SUCCESS;
}
