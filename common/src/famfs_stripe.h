/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAMFS_STRIPE_H
#define FAMFS_STRIPE_H

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>

#include "famfs_error.h"


/* Chunk attributes */
typedef struct n_chunk_ {
	char		*lf_buf;	/* reference to libfabric I/O buffer */
	uint64_t	r_event;	/* read transfer complete counter */
	uint64_t	w_event;	/* write transfer complete counter */
	int		parity;		/* parity chunk number (0...) or -1 */
	int		data;		/* data chunk number or -1 */
	int		node;		/* libfabric node index in nodelist */

	int		lf_client_idx;	/* libfabric client index, see to_lf_client_id() */

	/* TODO: Remove me! */
	off_t		p_stripe0_off;	/* libfabric offset of the first stripe in partition */
} N_CHUNK_t;

/* FAM stripe attributes */
typedef struct n_stripe_ {
	unsigned int	extent;		/* I/O node FAM extent */
	/* calculated from 'extent' for convenience */
	unsigned int	stripe_in_part;	/* stripe in the partition */
	int 		partition;	/* libfabric target partition */
	/* constants */
	int		d;		/* number of data chunks */
	int 		p;		/* number of parity chunks */
	int		node_id;	/* client node index in clientlist */
	int		part_mreg;	/* 1: LF dest address starts with 0 at a partition; 1: single buffer per node */
	unsigned int	node_size;	/* client node count */
	unsigned int	extent_stipes;	/* extent size, in stripes */
	unsigned int	srv_extents;	/* partition size, in extents */
	unsigned int	part_count;	/* number of partitions on ION */
	struct n_chunk_	*chunks;	/* array (d+p) of chunks */
} N_STRIPE_t;

/* Bunch of stripes */
typedef struct b_stripes_ {
	uint64_t	extent;		/* extent # */
	uint64_t	phy_stripe;	/* physical stripe number */
	uint64_t	l_stripe;	/* logical stripe */
	uint64_t	stripes;	/* stripe count */
	uint64_t	ext_stripes;	/* extent size in stripes */
} B_STRIPES_t;


/*
 * Calculate chunk's logical block number in given stripe.
 * Where blocks - number of blocks per chunk.
 **/
static inline uint64_t chunk_to_lba(uint64_t stripe, int data, int chunk, uint64_t blocks)
{
	return (stripe * (unsigned int)data + (unsigned int)chunk) * blocks;
}

/* Get partition number by extent */
static inline unsigned int extent_to_part(unsigned int e, unsigned int srv_extents) {
	return srv_extents? (e / srv_extents) : 0;
}

static inline void map_stripe_chunk(N_CHUNK_t *chunk, int extent, int chunks, int parities)
{
	int p, chunk_n = chunk->node;

	/* p = (chunk_n - extent) mod chunks */
	p = (chunk_n - extent) % chunks;
	p = (p < 0)? (p + chunks) : p;
	if (p < parities) {
		chunk->parity = p;
		chunk->data = -1;
	} else {
		chunk->data = p - parities;
		ASSERT(chunk->data >= 0 && chunk->data < (chunks - parities));
		chunk->parity = -1;
	}
}

#define CHUNK_PR_BUF_SZ	12
#define ALLOCA_CHUNK_PR_BUF(name)	char name[CHUNK_PR_BUF_SZ]
static inline char* pr_chunk(char *buf, int d, int p) {
	if (d >= 0)
		snprintf(buf, CHUNK_PR_BUF_SZ, "D%d", d);
	else if (p >= 0)
		snprintf(buf, CHUNK_PR_BUF_SZ, "P%d", p);
	else
		sprintf(buf, "???");
	return buf;
}


#endif /* FAMFS_STRIPE_H */
