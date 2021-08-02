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
 * Written by: Dmitry Ivanov
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "f_bitmap.h"

#define passes		3	/* Number of test passes */
#define rnd_passes	1000	/* Number of random test passes */
#define b_size_start	1
#define b_size_end	(BITS_PER_LONG*2+1)
#define cont_ones_end	(BITS_PER_LONG+1)


int main (void) {
    int sz, i, j, k, pos;
    int tg, t, pass;
    unsigned long *bmap = NULL;
    unsigned long bit;
    /* for random pattern test */
    int v0, v1;
    unsigned short *bmap16;

    printf("Unittest - bitmaps\n");
    tg = 1;
    printf("Running group %d tests: non-atomic ops\n", tg);
    /* sz: size */
    for (sz = b_size_start; sz <= b_size_end; sz++) {
	/* allocate */
	bmap = bitmap_zalloc(sz);
	/* Repeat the test */
	for (pass = 0; pass < passes; pass++) {
	    /* j: position of the first one */
	    for (j = 0; j < b_size_end; j++) {
		/* k: number of continious ones */
		for (k = 1; k <= cont_ones_end && (k+j) <= sz; k++) {
		    /* t: test number */
		    pos=0; i=0; bit=0;
		    /* bmap has all zeros */
		    t=1; if (!bitmap_empty(bmap, sz)) goto err;
		    t=2; if (bitmap_full(bmap, sz)) goto err;
		    t=3; if ((i = bitmap_weight(bmap, sz))) goto err;
		    /* pos: Set "1" in this position */
		    for (pos = j; pos < (j + k) && pos < sz; pos++) {
			/* Must be clear */
			t=4; if (test_bit(pos, bmap)) goto err;
			/* Test and Set */
			t=5; if (test_and_set_bit(pos, bmap)) goto err;
			/* Set */
			set_bit(pos, bmap);
			/* Test bit */
			t=6; if (!test_bit(pos, bmap)) goto err;
			/* Find first one */
			t=7; i = (int)find_first_bit(bmap, sz);
			if (i != j) goto err;
			/* Find next one at pos */
			t=8; i = (int)find_next_bit(bmap, sz, pos);
			if (i != pos) goto err;
			/* no next! */
			t=9; i = (int)find_next_bit(bmap, sz, pos+1);
			if (i != sz) goto err;
			/* Find first unset */
			t=10; i = (int)find_first_zero_bit(bmap, sz);
			if (i != (j? 0 : (j+pos+1))) goto err;
			/* Find next unset */
			t=11; i = (int)find_next_zero_bit(bmap, sz, j);
			if (i != (pos+1)) goto err;
			/* Count all ones in pos from j to the end */
			t=12; i = (int)__bitmap_weight64(bmap,
					(uint64_t)j, (uint64_t)(sz-j));
			if (i != (pos-j+1)) goto err;
		    } /* all (k) ones are set */
		    /* Check loops */
		    t=13; i = 0;
		    for_each_clear_bit(bit, bmap, sz) {
			if (test_bit(bit, bmap)) goto err;
			i++;
		    }
		    t=14; if (i != (sz-k)) goto err;
		    t=15; i = 0; bit = j;
		    for_each_set_bit_from(bit, bmap, sz) i++;
		    if (i != k) goto err;
		    /* Test find next */
		    t=16;
		    bit = find_next_bit(bmap, sz, 0);
		    if ((int)bit != j) goto err;
		    t=17;
		    bit = find_next_zero_bit(bmap, sz, bit);
		    if ((int)bit != j+k) goto err;
		    /* Count all ones */
		    t=18; if (bitmap_weight(bmap, sz) != k) goto err;
		    /* Find last one */
		    t=19;
		    bit = find_last_bit(bmap, sz);
		    if ((int)bit != (j+k-1)) goto err;
		    /* Zero out all ones */
		    for (i = j; i < (j+k); i++)
			clear_bit(i, bmap);
		    t=20; if (!bitmap_empty(bmap, sz)) goto err;
		    /* Fill in */
		    bitmap_fill(bmap, sz);
		    t=21; if ((i = bitmap_weight(bmap, sz)) != sz) goto err;
		    /* Zero all buffer */
		    bitmap_zero(bmap, sz);
		    t=22; if (!bitmap_empty(bmap, sz)) goto err;
		}
	    }
	}
	bitmap_free(bmap); bmap = NULL;
    }
    printf("Test group %d OK\n", tg);

    /* Test group two: long bitmaps with atomics */
    tg = 2;
    printf("Running group %d tests: atomic ops\n", tg);
    /* sz: size */
    for (sz = b_size_start; sz <= b_size_end; sz++) {
	/* allocate */
	bmap = bitmap_zalloc(sz);
	/* Repeat the test */
	for (pass = 0; pass < passes; pass++) {
	    /* j: position of the first one */
	    for (j = 0; j < b_size_end; j++) {
		/* k: number of continious ones */
		for (k = 1; k <= cont_ones_end && (k+j) <= sz; k++) {
		    /* t: test number */
		    pos=0; i=0; bit=0;
		    /* bmap has all zeros */
		    t=1; if (!bitmap_empty(bmap, sz)) goto err;
		    t=2; if (bitmap_full(bmap, sz)) goto err;
		    t=3; if ((i = bitmap_weight(bmap, sz))) goto err;
		    /* pos: Set "1" in this position */
		    for (pos = j; pos < (j + k) && pos < sz; pos++) {
			/* Must be clear */
			t=4; if (test_bit(pos, bmap)) goto err;
			/* Atomic Test and Set */
			t=5; if (atomic_test_and_set_bit(pos, bmap)) goto err;
			if (!test_bit(pos, bmap)) goto err;
			t=6; if (!atomic_test_and_clear_bit(pos, bmap)) goto err;
			if (test_bit(pos, bmap)) goto err;
			/* Atomic Set */
			t=6; atomic_set_bit(pos, bmap);
			if (!test_bit(pos, bmap)) goto err;
			/* Atomic Clear */
			t=7; atomic_clear_bit(pos, bmap);
			if (test_bit(pos, bmap)) goto err;
			/* Some extra set/clear */
			t=8; if (atomic_test_and_set_bit(pos, bmap)) goto err;
			if (!atomic_test_and_set_bit(pos, bmap)) goto err;
			if (!atomic_test_and_clear_bit(pos, bmap)) goto err;
			if (atomic_test_and_clear_bit(pos, bmap)) goto err;
			if (atomic_test_and_set_bit(pos, bmap)) goto err;
			/* Find first one */
			t=9; i = (int)find_first_bit(bmap, sz);
			if (i != j) goto err;
			/* Find next one at pos */
			t=10; i = (int)find_next_bit(bmap, sz, pos);
			if (i != pos) goto err;
			/* no next! */
			t=11; i = (int)find_next_bit(bmap, sz, pos+1);
			if (i != sz) goto err;
			/* Find next unset */
			t=12; i = (int)find_first_zero_bit(bmap, sz);
			if (i != (j? 0 :(pos+1))) goto err;
			/* Find next unset */
			t=13; i = (int)find_next_zero_bit(bmap, sz, j);
			if (i != (pos+1)) goto err;
		    } /* all (k) ones are set */
		    /* Check loops */
		    t=14; i = 0;
		    for_each_clear_bit(bit, bmap, sz) {
			if (test_bit(bit, bmap)) goto err;
			i++;
		    } /* expect (sz-k) zeros */
		    t=15; if (i != (sz-k)) goto err;
		    /* k ones */
		    t=16; i = 0; bit = j;
		    for_each_set_bit_from(bit, bmap, sz) i++;
		    if (i != k) goto err;
		    /* Count all ones */
		    t=17; if (bitmap_weight(bmap, sz) != k) goto err;
		    /* Zero out all ones */
		    t=18;
		    for (i = j; i < (j+k); i++)
			atomic_clear_bit(i, bmap);
		    if (!bitmap_empty(bmap, sz)) goto err;
		    /* Fill in */
		    t=19;
		    for (i = 0; i < sz; i++)
			atomic_set_bit(i, bmap);
		    if (!bitmap_full(bmap, sz)) goto err;
		    if (bitmap_weight(bmap, sz) != sz) goto err;
		    /* Zero whole bitmap */
		    t=20;
		    for_each_set_bit(bit, bmap, sz)
			if (!atomic_test_and_clear_bit(bit, bmap))
			    goto err;
		    if (!bitmap_empty(bmap, sz)) goto err;
		}
	    }
	}
	bitmap_free(bmap); bmap = NULL;
    }
    printf("Test group %d OK\n", tg);

    /* Test group three: random pattern */
    tg = 3;
    printf("Running group %d tests: random pattern\n", tg);
    srand((unsigned int)time(NULL));
    /* not used in this test */
    k = pos = 0; bit = 0;
    /* i: repeat random size test */
    for (i = b_size_start; i <= b_size_end; i++) {
	/* Repeat the test */
	for (pass = 0; pass < rnd_passes; pass++) {
	    /* sz: size */
	    sz = rand() % (b_size_end - b_size_start + 1) + b_size_start;
	    bmap = bitmap_zalloc(sz);

	    /* Fill with random */
	    bmap16 = (unsigned short *) bmap;
	    for (j = 0; j < (int)(DIV_ROUND_UP(sz, BITS_PER_BYTE * sizeof(short))); j++)
		bmap16[j] = rand() % 65536;

	    /* Test 1: weight() = sz - count_zeros() */
	    t = 1;
	    v0 = bitmap_weight(bmap, sz);
	    for (pos = 0; pos < sz; pos++)
		change_bit(pos, bmap);
	    v1 = bitmap_weight(bmap, sz);
	    if (v0 != (sz - v1)) {
		printf("  weight1:%d, weight2:%d\n", v0, v1);
		goto err;
	    }

	    /* Test 2: Cycles */
	    t = 2;
	    v0 = v1 = 0;
	    for_each_clear_bit(bit, bmap, sz) v0++;
	    pos = sz;
	    for_each_set_bit(bit, bmap, sz) {
		v1++;
		pos = bit;
	    }
	    if ((v0 + v1) != sz) {
		printf("  ones:%d, zeros:%d\n", v1, v0);
		goto err;
	    }
	    /* Test 3: Find last bit set */
	    t = 3;
	    bit = find_last_bit(bmap, sz);
	    if ((int)bit != pos) goto err;
	}
	bitmap_free(bmap); bmap = NULL;
    }
    printf("Test group %d OK\n", tg);

    printf("SUCCESS\n");
    return 0;
err:
    printf("Test %d.%d FAILED at pass %d of %d\n",
	   tg, t, pass+1, passes);
    printf("  %d one%s start @%d in bitmap of size:%d\n",
	   k, (k>1)?"s":"", j, sz);
    printf("  test variables: pos=%d buf[%d]=0x%016lX i=%d bit=%lu\n",
	   pos, BIT_WORD(pos), bmap[BIT_WORD(pos)], i, bit);
    return 1;
}

