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
