/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef FAM_STRIPE_H
#define FAM_STRIPE_H

#include <sys/types.h>
#include <stdint.h>

/* Chunk attributes */
typedef struct n_chunk_ {
//	char		*lf_buf;	/* reference to libfabric I/O buffer */
//	off_t		p_stripe0_off;	/* libfabric offset of the first stripe in partition */
	uint64_t	r_event;	/* read transfer complete counter */
	uint64_t	w_event;	/* write transfer complete counter */
	int		parity;		/* parity chunk number (0...) or -1 */
	int		data;		/* data chunk number or -1 */
	int		node;		/* libfabric node index in nodelist */

	int		lf_client_idx;	/* libfabric client index, see to_lf_client_id() */
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
	unsigned int	node_size;	/* client node count */
	unsigned int	extent_stipes;	/* extent size, in stripes */
	unsigned int	srv_extents;	/* partition size, in extents */
	unsigned int	part_count;	/* number of partitions on ION */
	struct n_chunk_	*chunks;	/* array (d+p) of chunks */
} N_STRIPE_t;

#if 0
typedef struct b_stripes_ {
	uint64_t	extent;		/* extent # */
	uint64_t	phy_stripe;	/* physical stripe number */
	uint64_t	l_stripe;	/* logical stripe */
	uint64_t	stripes;	/* stripe count */
	uint64_t	ext_stripes;	/* extent size in stripes */
} B_STRIPES_t;

typedef struct w_private_ {
	struct n_params_	*params;	/* reference to struct n_params_ */
	struct b_stripes_	bunch;		/* bunch of stripes belongs to the same extent */
	//struct perf_stat_	perf_stat;	/* per thread data transfer/encode/decode statistic */
	int			thr_id;		/* worker's thread id */
	/* Arrays of pointers to chunk and libfabric client for this stripe */
	struct n_chunk_		**chunks;	
	struct lf_cl_		**lf_clients; /* array of references */
} W_PRIVATE_t;
#endif


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

#define PR_BUF_SZ	12
static inline char* pr_chunk(char *buf, int d, int p) {
	if (d >= 0)
		snprintf(buf, PR_BUF_SZ, "D%d", d);
	else if (p >= 0)
		snprintf(buf, PR_BUF_SZ, "P%d", p);
	else
		sprintf(buf, "???");
	return buf;
}


/* FAM API */
N_CHUNK_t *get_fam_chunk(uint64_t ionode_chunk_id, struct n_stripe_ *stripe, int *dest_node_idx);
//void map_stripe_chunks(N_STRIPE_t *stripe, unsigned int extent);


#endif /* FAM_STRIPE_H */
