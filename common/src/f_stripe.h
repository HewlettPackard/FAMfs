/*
 * Copyright (c) 2017-2020, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef F_STRIPE_H
#define F_STRIPE_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#include "f_error.h"

struct f_pool_dev_;
struct f_layout_;

/* Chunk attributes */
typedef struct n_chunk_ {
	char		*lf_buf;	/* reference to libfabric I/O buffer */
	uint64_t	r_event;	/* read transfer complete counter */
	uint64_t	w_event;	/* write transfer complete counter */
	int		parity;		/* parity chunk number (0...) or -1 */
	int		data;		/* data chunk number or -1 */
	int		node;		/* libfabric node index in nodelist;
					FAMFS: pool device media_id */

	int		lf_client_idx;	/* libfabric client index, see to_lf_client_id();
					FAMFS: pool device index in info.pdev_indexes[] */
			/* only FAMFS: pdev, extent, length, offset */
	unsigned int	extent;		/* extent number (from Slab map) */
	struct f_pool_dev_ *pdev;	/* reference to pool device in devlist */
			/* stripe I/O mapping to a chunk */
	uint32_t	length;		/* length, bytes */
	uint32_t	offset;		/* offset in chunk, bytes */

	/* TODO: Remove me! */
	off_t		p_stripe0_off;	/* libfabric offset of the first stripe in partition */
} N_CHUNK_t;

/* FAM stripe attributes */
typedef struct n_stripe_ {
	unsigned int	extent;		/* I/O node FAM extent */
	/* calculated from 'extent' for convenience */
	unsigned int	stripe_in_part;	/* stripe in the partition;
					FAMFS: stripe in slab */
//	int 		partition;	/* libfabric target partition */
	uint64_t	stripe_0;	/* only FAMFS: this stripe's Slab entry key */
	/* constants */
	int		d;		/* number of data chunks */
	int 		p;		/* number of parity chunks */
	int		node_id;	/* client node index in clientlist */
	unsigned int	node_size;	/* client node count */
	unsigned int	extent_stipes;	/* extent size, in stripes */
	unsigned int	srv_extents;	/* partition size, in extents */
	uint32_t	chunk_sz;	/* layout chunk size in bytes */
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

static inline int n_stripe_in_slab(uint64_t s, N_STRIPE_t *stripe) {
	return (s/stripe->extent_stipes == stripe->extent);
}


/* FAM stripe API */

/*
 * Map stripe offset to FAM chunk.
 * Return the pointer to the corresponding N_CHUNK_t structure in stripe->chunks[]
 **/
static inline N_CHUNK_t *get_fam_chunk(N_STRIPE_t *stripe, int stripe_chunk)
{
    N_CHUNK_t *chunk = stripe->chunks;
    int i, n, data;

    data = stripe->d;
    n = data + stripe->p;

    /* find chunk index by D# or (P# + data) */
    for (i = 0; i < n; i++, chunk++) {
	if (stripe_chunk < data) {
	    if (chunk->data == stripe_chunk)
		break;
	} else {
	    if (chunk->parity == (stripe_chunk - data))
		break;
	}
    }
    ASSERT(i < n);
    return chunk;
}

/* Map chunks to physical stripe; allocate N_STRIPE_t on demand. */
int f_map_fam_stripe(struct f_layout_ *lo, N_STRIPE_t **stripe_p, uint64_t s, bool global);
/* Free N_STRIPE_t memory */
void free_fam_stripe(N_STRIPE_t *stripe);
/* Map logical I/O to stripe's physical chunks */
void map_fam_chunks(N_STRIPE_t *stripe, char *buf, off_t offset, size_t length,
    void* (*lookup_mreg_fn)(const char *buf, size_t len, int nid));
/* Start I/O to stripe's data chunks; wr: 0-read, 1-write */
int chunk_rma_start(N_STRIPE_t *stripe, int use_cq, int wr);
/* Wait for I/O that has been started by chunk_rma_start() */
int chunk_rma_wait(N_STRIPE_t *stripe, int use_cq, int wr, uint64_t io_timeout_ms);

#endif /* F_STRIPE_H */

