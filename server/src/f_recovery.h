/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Yann Livis
 */

#ifndef F_RECOVERY_H
#define F_RECOVERY_H

#include "f_stats.h"
#include "f_ec.h"

#define F_RC_MAX_IO_SIZE	(16*MiB)	/* Max recovery I/O size */

typedef struct f_recovery_ {
	pthread_mutex_t	r_done_lock;	/* recovery batch done wait condition mutex */
	pthread_cond_t	r_batch_done;	/* recovery batch done wait condition */
	
	unsigned long	*failed_bmap;	/* bitmap of failed extents */
	unsigned long	slabs2recover;	/* slabs to recover, total, may increment after recovery start */
	unsigned long	done_slabs;	/* slabs recovered w/o error(s) */
	unsigned long	clean_slabs;	/* slabs that didn't need recovery */
	unsigned long	error_slabs;	/* slabs skipped due to error(s) */
	unsigned long	skipped_slabs;	/* slabs that were skipped (not degraded and not error'ed) */

        u8              *decode_table;  /* R-S decode table for this particualr error vector */

	atomic_t	in_progress;	/* # of recovery batches in progress */
} F_RECOVERY_t;

int f_start_recovery_thread(F_LAYOUT_t *lo);
int f_stop_recovery_thread(F_LAYOUT_t *lo);

#endif
