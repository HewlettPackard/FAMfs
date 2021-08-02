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
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef EC_PERF_H
#define EC_PERF_H

#include <sys/time.h>
#include <linux/types.h>

#include "f_stats.h"

#define u64 __u64
#define u8 __u8

struct ec_perf {
	struct timeval  start;
	struct timeval  stop;
        u64             elapsed;
        u64             data;
};

static inline void ec_perf_init(struct ec_perf *p) {
    p->elapsed = 0;
    p->data = 0;
}

static inline u64 ec_perf_start(struct ec_perf *p) {
	gettimeofday(&(p->start), 0);
        return (p->start.tv_sec*uSec + p->start.tv_usec);
}

static inline u64 ec_perf_stop(struct ec_perf *p) {
	gettimeofday(&(p->stop), 0);
        return (p->stop.tv_sec*uSec + p->stop.tv_usec);
}

static inline u64 ec_perf_add(struct ec_perf *p, u64 dsize) {
    p->elapsed += ec_perf_stop(p) - (p->start.tv_sec*uSec + p->start.tv_usec);
    p->data += dsize;
    return p->elapsed;
}

static inline double perf_get_bw(struct ec_perf *p, u64 tu, u64 bu) {
    return ((double)p->data/bu)/((double)p->elapsed/tu);
}


u8 *make_encode_matrix(int k, int p, u8 **pa);
u8 *make_decode_matrix(int k, int n, u8 *eix, u8 *a);
void encode_data(int how, int len, int ndata, int npar, u8 *enc_tbl, u8 **data, u8 **par);
void decode_data(int how, int len, int ndata, int nerr, u8 *dec_tbl, u8 **data, u8 **rst);

#endif
