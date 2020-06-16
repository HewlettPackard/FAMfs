#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <mpi.h>
#include "mdhim.h"

#define KEYS_PERRANK 10
#define REC_PER_SLICE KEYS_PERRANK/2
#define BGET_READAHEAD KEYS_PERRANK

int main(int argc, char **argv) {
	int ret;
	int provided = 0;
	struct mdhim_t *md;
	uint32_t key;
	unsigned int *value;
	struct mdhim_brm_t *brm;
	struct mdhim_bgetrm_t *bgrm;
	int i, j;
	int keys_per_rank = KEYS_PERRANK;
	char     *db_path = "/tmp/";
	char     *db_name = "mdhimTstDB-";
	int      dbug = MLOG_DBG;
	mdhim_options_t *db_opts; // Local variable for db create options to be passed
	int db_type = LEVELDB; //(data_store.h)
	struct timeval start_tv, end_tv;
	unsigned totaltime;
	MPI_Comm comm;

	// Create options for DB initialization
	db_opts = mdhim_options_init();
	mdhim_options_set_db_path(db_opts, db_path);
	mdhim_options_set_db_name(db_opts, db_name);
	mdhim_options_set_db_type(db_opts, db_type);
	mdhim_options_set_key_type(db_opts, MDHIM_INT_KEY);
	mdhim_options_set_max_recs_per_slice(db_opts, REC_PER_SLICE);
//	mdhim_options_set_debug_level(db_opts, dbug);	/* Uncomment for DB DEBUG! */

	gettimeofday(&start_tv, NULL);
	ret = MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &provided);
	if (ret != MPI_SUCCESS) {
		printf("Error initializing MPI with threads\n");
		exit(1);
	}

	if (provided != MPI_THREAD_MULTIPLE) {
                printf("Not able to enable MPI_THREAD_MULTIPLE mode\n");
                exit(1);
        }

	comm = MPI_COMM_WORLD;
	md = mdhimInit(&comm, db_opts);
	if (!md) {
		printf("Error initializing MDHIM\n");
		exit(1);
	}

#define val_len 131072
	value = malloc(val_len*sizeof(int));
	//Put the primary keys and values
#if 1	/* 1 - ascending, 0 - descending key creation order */
	for (i = 0; i < keys_per_rank; i++) {
#else
	for (i = keys_per_rank-1; i >= 0; i--) { /* create records in reverse order */
#endif
		key = (md->mdhim_rank * keys_per_rank) + i;
		value[0] = (10 * keys_per_rank) + (md->mdhim_rank * keys_per_rank) + i;
		brm = mdhimPut(md, md->primary_index,
			       &key, sizeof(key),
			       value, val_len*sizeof(int),
			       NULL, NULL);
		if (!brm || brm->error) {
			printf("Error inserting key/value into MDHIM\n");
		} else {
			printf("Rank: %d put key: %u with value: %d\n", md->mdhim_rank,
			       key, value[0]);
		}

		mdhim_full_release_msg(brm);
	}

#if 0
	//Commit the database
	ret = mdhimCommit(md, md->primary_index);
	if (ret != MDHIM_SUCCESS) {
		printf("Error committing MDHIM database\n");
	} else {
		printf("Committed MDHIM database\n");
	}

	//Get the stats for the primary index
	ret = mdhimStatFlush(md, md->primary_index);
	if (ret != MDHIM_SUCCESS) {
		printf("Error getting stats\n");
	} else {
		printf("Got stats\n");
	}
#else
	MPI_Barrier(MPI_COMM_WORLD);
#endif

	//Get the secondary keys and values using get_next
	int tst_rank = md->mdhim_comm_size - md->mdhim_rank -1;
        key = tst_rank * keys_per_rank;
	for (i = 0; i < keys_per_rank; i++) {
		value[0] = (10 * keys_per_rank) + (tst_rank * keys_per_rank) + i;
		bgrm = mdhimBGetOp(md, md->primary_index,
				   &key, sizeof(uint32_t), BGET_READAHEAD+1, MDHIM_GET_NEXT);
		if (!bgrm || bgrm->error) {
			printf("Rank: %d, Error getting next key/value given key: %d from MDHIM\n",
			       md->mdhim_rank, key);
		} else if (bgrm->keys && bgrm->values) {
			unsigned int *v = (unsigned int *) bgrm->values[0];
			printf("Rank: %d successfully got key: %d with value: %d from MDHIM\n",
			       md->mdhim_rank,
			       *((unsigned int *) bgrm->keys[0]),
			       *v);
#if 1 /* Check */
			for (j = 0; j < val_len; j++, v++) {
				if (value[j] != *v) {
					printf("Rank %d, ERROR exp[%d]:%u got:%u\n",
					       md->mdhim_rank, j, value[j], *v);
					break;
				}
			}
#endif
			key = *((unsigned int *) bgrm->keys[0]);
			if (bgrm->num_keys > 1)
				printf("Rank %d, num_keys:%d key0:%d last key%d:%d\n",
					md->mdhim_rank, bgrm->num_keys, *((unsigned int *) bgrm->keys[0]),
							bgrm->num_keys-1, *((unsigned int *) bgrm->keys[bgrm->num_keys-1]));
			key++;
		}
		mdhim_full_release_msg(bgrm);
	}
	free(value);

	ret = mdhimClose(md);
	mdhim_options_destroy(db_opts);
	if (ret != MDHIM_SUCCESS) {
		printf("Error closing MDHIM\n");
	}

	gettimeofday(&end_tv, NULL);
	double tt = (1000000ULL * end_tv.tv_sec + end_tv.tv_usec);
	tt -= (1000000ULL * start_tv.tv_sec + start_tv.tv_usec);
	tt /= 1000U;
	totaltime = end_tv.tv_sec - start_tv.tv_sec;
	MPI_Barrier(MPI_COMM_WORLD);
	MPI_Finalize();
	printf("Took %u seconds %.3f ms to insert and retrieve %d keys/values\n", totaltime, tt,
	       keys_per_rank);

	return 0;
}
