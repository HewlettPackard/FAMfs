/*
 * Copyright (c) 2018-2019, HPE
 *
 * Written by: Dmitry Ivanov
 */

#include <assert.h>
#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <malloc.h>
#include <sys/mman.h>
//#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/wait.h>
//#include <limits.h>

#include "famfs_error.h"
#include "famfs_env.h"
#include "log.h"
#include "lf_client.h"
#include "unifycr_metadata.h"
#include "famfs_maps.h"
#include "f_pool.h"
#include "mpi_utils.h"


/* Open fabric and create RMA endpoint connections to pool devices */
int create_lfs_ctx(LFS_CTX_t **lfs_ctx_p)
{
    LFS_CTX_t *lfs_ctx;
    F_POOL_t *pool;

    lfs_ctx = (LFS_CTX_t *) calloc(1, sizeof(LFS_CTX_t));
    if (lfs_ctx_p == NULL)
	return -ENOMEM;

    pool = f_get_pool();
    assert( pool ); /* f_set_layouts_info must fail if no pool */
    lfs_ctx->pool = pool;

    *lfs_ctx_p = lfs_ctx;
    return 0;
}

static void quit_child(LFS_CTX_t *lfs_ctx) {
    LFS_SHM_t *lfs_shm = lfs_ctx->lfs_shm;

    if (lfs_shm) {
        /* Signal FAM emulator to quit */
        if (lfs_ctx->child_pid) {
            pthread_mutex_lock(&lfs_shm->lock_quit);
            lfs_shm->quit_lfs = 1;
            pthread_mutex_unlock(&lfs_shm->lock_quit);
            pthread_cond_signal(&lfs_shm->cond_quit);
        }
	/* Wait for all children exit */
	while (!(wait(0) == -1 && errno == ECHILD)) ;

	if (lfs_shm->shm_size)
	    munmap(lfs_ctx->lfs_shm, lfs_shm->shm_size);
    }
}

/* Start FAM emulation servers on nodes in hostlist */
int lfs_emulate_fams(int rank, int size, LFS_CTX_t *lfs_ctx)
{
    F_POOL_t *pool = lfs_ctx->pool;
    F_MYNODE_t *node = &pool->mynode;
    LFS_SHM_t *lfs_shm;
    pthread_mutexattr_t pattr;
    pthread_condattr_t cattr;
    pid_t cpid;
    size_t shm_size, len;
    uint64_t *mr_prov_keys = NULL, *mr_virt_addrs = NULL;
    int *recvcounts = NULL, *displs = NULL;
    unsigned int srv_cnt, cnt;
    int rc = 0;

    /* Having the real FAM? */
    if (!PoolFAMEmul(pool))
        goto _exit;

    /*
     * FAM emulator
     */

    /* Initialize shared data on IO nodes */
    srv_cnt = node->emul_devs; /* number of emulated FAM regions on this node */
    shm_size = sizeof(LFS_SHM_t) + srv_cnt*sizeof(LFS_EXCG_t);
    lfs_shm = (LFS_SHM_t *) mmap(NULL, shm_size,
            PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (lfs_shm == NULL) {
        rc = -1;
        goto _exit;
    }
    lfs_shm->shm_size = shm_size;
    lfs_shm->node_servers = srv_cnt;
    lfs_shm->quit_lfs = 0;
    lfs_shm->lfs_ready = 0;
    pthread_mutexattr_init(&pattr);
    pthread_mutexattr_setpshared(&pattr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&lfs_shm->lock_ready, &pattr);
    pthread_mutex_init(&lfs_shm->lock_quit, &pattr);
    pthread_condattr_init(&cattr);
    pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
    pthread_cond_init(&lfs_shm->cond_ready, &cattr);
    pthread_cond_init(&lfs_shm->cond_quit, &cattr);
    lfs_ctx->lfs_shm = lfs_shm;

    /* On each node: fork FAM emulation server */
    cpid = fork();
    if (cpid < 0) {
        rc = -errno;
        err("fork failed: %m");
        goto _exit;
    } else if (cpid == 0) {
	LF_INFO_t *lf_info = pool->lf_info;

	/* On each ionode */
	if (NodeIsIOnode(node)) {

	    /* Initialize libfabric target on node 'i' */
	    rc = lf_servers_init(pool);
	    if (rc) {
		err("Can't start FAM emulation target on [%d]:%s rc:%d",
		    node->ionode_idx, node->hostname, rc);
	    } else if (!lf_info->mrreg.scalable) {
		F_POOL_DEV_t *pdev;

		for_each_emul_pdev(pool, pdev) {
		    FAM_DEV_t *fdev = &pdev->dev->f;

		    if (lf_info->mrreg.prov_key)
			lfs_shm->rmk[_i].prov_key = fdev->pkey;
		    if (lf_info->mrreg.virt_addr)
			lfs_shm->rmk[_i].virt_addr = fdev->virt_addr;
		}
	    }
	}

        /* It's Ok for parent process to proceed with MPI communication */
        pthread_mutex_lock(&lfs_shm->lock_ready);
        lfs_shm->lfs_ready = rc? -1 : 1;
        pthread_mutex_unlock(&lfs_shm->lock_ready);
        pthread_cond_signal(&lfs_shm->cond_ready);

        /* Sleep if libfabric was initialized successfully */
        if (rc == 0) {
            pthread_mutex_lock(&lfs_shm->lock_quit);
            while (lfs_shm->quit_lfs == 0)
                pthread_cond_wait(&lfs_shm->cond_quit, &lfs_shm->lock_quit);
            pthread_mutex_unlock(&lfs_shm->lock_quit);
        }
        pthread_cond_destroy(&lfs_shm->cond_quit);
        munmap(lfs_shm, shm_size);

        /* Close fabric and exit */
	lf_servers_free(pool);

	/* Free pool and all layout structures */
	rc = f_free_layouts_info();
        free(lfs_ctx);

        exit(rc?1:0);
    }

    /* Parent thread should wait */
    pthread_mutex_lock(&lfs_shm->lock_ready);
    while (lfs_shm->lfs_ready == 0)
            pthread_cond_wait(&lfs_shm->cond_ready, &lfs_shm->lock_ready);
    if (lfs_shm->lfs_ready == 1)
	lfs_ctx->child_pid = cpid;
    pthread_mutex_unlock(&lfs_shm->lock_ready);

    if (lfs_shm->lfs_ready != 1) {
        LOG(LOG_ERR, "Failed to start FAM emulator process!");
        rc = -1;
    }

    /* Way to go with MPI */
    MPI_Barrier(MPI_COMM_WORLD);

    if (pool->verbose && lfs_shm->lfs_ready == 1)
        LOG(LOG_INFO, "FAM module emulator is ready");

    pthread_cond_destroy(&lfs_shm->cond_ready);

    if (rc)
        goto _exit; /* will hang at MPI_Allgather? */

    /*
     * LF remote key/address exchange
     */
    LF_INFO_t *lf_info = pool->lf_info;
    F_IONODE_INFO_t *ioi;
    LFS_EXCG_t *rmk;
    unsigned int i, j, ionode_count, xchg_off, fam_xchg_off;
    int sendcount;

    if (!NodeIsIOnode(&pool->mynode) ||
	!(lf_info->mrreg.prov_key || lf_info->mrreg.virt_addr))
	goto _exit;

    /* Prepare MPI_Allgatherv args */
    len = srv_cnt * sizeof(uint64_t);
    sendcount = len;
    ionode_count = pool->ionode_count;
    recvcounts = (int *) calloc(ionode_count, sizeof(int));
    displs = (int *) calloc(ionode_count, sizeof(int));
    cnt = pool->info.dev_count;
    mr_prov_keys = (uint64_t *) calloc(cnt, sizeof(uint64_t));
    mr_virt_addrs = (uint64_t *) calloc(cnt, sizeof(uint64_t));
    ioi = pool->ionodes;
    /* Set FAM count and the offset in arrays of prov_keys/virt_addr for each IO node */
    for (i = 0; i < ionode_count; i++, ioi++) {
	recvcounts[i] = ioi->fam_devs;
	displs[i] = ioi->fam_xchg_off;
    }
    rmk = lfs_shm->rmk;
    fam_xchg_off = xchg_off = pool->ionodes[node->ionode_idx].fam_xchg_off;
    for (j = 0; j < srv_cnt; j++, rmk++, xchg_off++) {
	mr_prov_keys[xchg_off] = rmk->prov_key;
	mr_virt_addrs[xchg_off] = rmk->virt_addr;
    }

    /* Exchange the keys within servers */
    xchg_off = fam_xchg_off;
    if (lf_info->mrreg.prov_key &&
	((rc = MPI_Allgatherv(&mr_prov_keys[xchg_off], sendcount, MPI_BYTE,
                             mr_prov_keys, recvcounts, displs, MPI_BYTE,
                             pool->ionode_comm)))) {
	LOG(LOG_ERR, "LF PROV_KEYS MPI_Allgather failed:%d", rc);
        goto _exit;
    }
    if (lf_info->mrreg.virt_addr &&
	((rc = MPI_Allgatherv(&mr_virt_addrs[xchg_off], sendcount, MPI_BYTE,
                             mr_virt_addrs, recvcounts, displs, MPI_BYTE,
                             pool->ionode_comm)))) {
	LOG(LOG_ERR, "LF VIRT_ADDRS MPI_Allgather failed:%d", rc);
        goto _exit;
    }

    /* Broadcast the keys to all [clients] */
    if (lf_info->mrreg.prov_key &&
        ((rc = mpi_broadcast_arr64(mr_prov_keys, cnt,
				   pool->zero_ion_rank)))) {
        LOG(LOG_ERR, "LF PROV_KEYS MPI broadcast failed:%d", rc);
        goto _exit;
    }
    if (lf_info->mrreg.virt_addr &&
        ((rc = mpi_broadcast_arr64(mr_virt_addrs, cnt,
				   pool->zero_ion_rank)))) {
        LOG(LOG_ERR, "LF VIRT_ADDRS MPI broadcast failed:%d", rc);
    }

    /* Re-assign remote key/address to pool devices */
    ioi = pool->ionodes;
    for (i = 0; i < ionode_count; i++, ioi++) {
	F_POOL_DEV_t *pdev;
	unsigned int k, xchg_off = ioi->fam_xchg_off;
	uint16_t *pd_idx = pool->info.pdev_indexes;

	for (j = k = 0; j < pool->info.dev_count && k < ioi->fam_devs; j++, pd_idx++)
	{
	    pdev = &pool->devlist[*pd_idx];
	    if (pdev->dev->f.ionode_idx != i)
		continue;
	    if (lf_info->mrreg.prov_key)
		pdev->dev->f.mr_key = mr_prov_keys[xchg_off + k];
	    if (lf_info->mrreg.virt_addr)
		pdev->dev->f.virt_addr = mr_virt_addrs[xchg_off + k];
	    k++;
	}
    }

_exit:
    if (rc) {
	/* Force child to quit */
	quit_child(lfs_ctx);
    }
    free(mr_prov_keys);
    free(mr_virt_addrs);
    free(recvcounts);
    free(displs);
    return rc;
}

void free_lfs_ctx(LFS_CTX_t **lfs_ctx_p) {
    quit_child(*lfs_ctx_p);
    free(*lfs_ctx_p);
    *lfs_ctx_p = NULL;
}

int meta_register_fam(LFS_CTX_t *lfs_ctx)
{
    F_POOL_t *pool;
    F_POOL_DEV_t *pdev;
    fam_attr_val_t *fam_attr = NULL;
    LFS_EXCG_t *attr;
    unsigned int fam_id, node_id;
    int rc = 0;

    pool = lfs_ctx->pool;
    assert( pool );
    /* Do nothing on client */
    if (!NodeIsIOnode(&pool->mynode))
	return 0;

    //part_cnt = 1; /* TODO: Support FAM partitioning */
    fam_attr = (fam_attr_val_t *)malloc(fam_attr_val_sz(1));
    fam_attr->part_cnt = 1;
    attr = fam_attr->part_attr;

    /* Having the real FAM? */
    if (!PoolFAMEmul(pool)) {

	/* Register all FAMs on ionode zero */
	if (pool->mynode.ionode_idx == 0) {
	    for_each_pool_dev (pool, pdev) {
		FAM_DEV_t *fdev = &pdev->dev->f;

		fam_id = (unsigned int) pdev->pool_index;
		attr->prov_key = fdev->pkey;
		attr->virt_addr = fdev->virt_addr;
		rc |= meta_famattr_put(fam_id, fam_attr);
	    }
	}
    } else {

	/* NOTE: FAM emulation only; limited to 31 bits */
	node_id = pool->mynode.ionode_idx;
	assert( IN_RANGE(node_id, 0, pool->ionode_count-1) );

	for_each_pool_dev(pool, pdev) {
	    FAM_DEV_t *fdev = &pdev->dev->f;

	    if (pdev->ionode_idx != node_id)
		continue;

	    fam_id = (unsigned int) pdev->pool_index;
	    attr->prov_key = fdev->pkey;
	    attr->virt_addr = fdev->virt_addr;
	    rc |= meta_famattr_put(fam_id, fam_attr);
	}
    }
    free(fam_attr);
    return rc;
}

