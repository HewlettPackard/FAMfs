/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

//#include "famfs_bbitops.h"
#include "famfs_bbitmap.h"


int main (void) {
    int sz, i, j, k, pos;
    int tg, t;
#define bb_size_start	1
#define bb_size_end	(32*2+1)
#define cont_ones_end	(32+1)
    unsigned long *bbmap = NULL;
    BBIT_VALUE_t val;
    unsigned int pat;
    unsigned long bbit;
    /* for random pattern test */
    int v0, v1;
    unsigned int pat0, pat1;
    unsigned short *bbmap16;

    /* Test group one: long bitmaps */
    tg = 1;
    printf("Running group %d tests: non-atomic ops\n", tg);
    /* sz: size */
    for (sz = bb_size_start; sz <= bb_size_end; sz++) {
	/* allocate */
	bbmap = bbitmap_zalloc(sz);
	/* For all non-zero values */
	for (val = BBIT_01; val <= BBIT_11; val++) {
	    pat = BBITS_VAL2PAT(val);
	    /* j: position of the first one */
	    for (j = 0; j < bb_size_end; j++) {
		/* k: number of continious ones */
		for (k = 1; k <= cont_ones_end && (k+j) <= sz; k++) {
		    /* t: test number */
		    t=0; pos=0; i=0;
		    /* bbmap has all zeros */
		    t++; if (!bbitmap_empty(bbmap, sz)) goto err;
		    t++; if (!bbitmap_full(bbmap, BB_PAT_ZERO, sz)) goto err;
		    t++; if ((i = bbitmap_weight(bbmap, pat, sz))) goto err;
		    /* pos: Set "1" in this position */
		    for (pos = j; pos < (j + k) && pos < sz; pos++) {
			/* Must be clear */
			t=4; if (!test_bbit(pos, BBIT_ZERO, bbmap)) goto err;
			/* Test and Set */
			i = test_and_set_bbit(pos, val, bbmap);
			t++; if (i != BBIT_ZERO) goto err;
			i = test_and_set_bbit_pattern(pos, BB_PAT_ZERO, bbmap);
			t++; if (i != (int)pat) goto err;
			/* Set */
			set_bbit(pos, val, bbmap);
			/* Test bit */
			t++; if(!test_bbit(pos, val, bbmap)) goto err;
			t++; if(!test_bbit_patterns(pos, pat, bbmap)) goto err;
			/* Set pattern */
			set_bbit_pattern(pos, pat, bbmap);
			t++; if(!test_bbit(pos, val, bbmap)) goto err;
			/* Find first one */
			i = (int)find_first_bbit(bbmap, pat, sz);
			t++; if(i != j) goto err;
			/* Find next one at pos */
			i = (int)find_next_bbit(bbmap, pat, sz, pos);
			t++; if(i != pos) goto err;
			/* no next! */
			i = (int)find_next_bbit(bbmap, pat, sz, pos+1);
			t++; if(i != sz) goto err;
			/* Find first unset */
			i = (int)find_first_unset_bbit(bbmap, pat, sz);
			t++; if(i != (j? 0 : (j+pos+1))) goto err;
			/* Find next unset */
			i = (int)find_next_unset_bbit(bbmap, pat, sz, j);
			t++; if (i != (pos+1)) goto err;
			/* Count all ones in pos.. */
			i = __bbitmap_weight(bbmap, pat, j, sz-j);
			t++; if (i != (pos-j+1)) goto err;
		    } /* all (k) ones are set */
		    /* Check loops */
		    t=16; i = 0;
		    for_each_clear_bbit(bbit, bbmap, pat, sz) {
			if (!test_bbit(bbit, BBIT_ZERO, bbmap)) goto err;
			i++;
		    }
		    t++; if (i != (sz-k)) goto err;
		    t++; i = 0; bbit = j;
		    for_each_set_bbit_from(bbit, bbmap, pat, sz) i++;
		    if (i != k) goto err;
		    /* Filled by PAT00 and val */
		    t++; if (!bbitmap_full(bbmap, BB_PAT_ZERO|pat, sz)) goto err;
		    /* Count all ones */
		    t++; if (bbitmap_weight(bbmap, pat, sz) != k) goto err;
		    /* Zero out all ones */
		    for (i = j; i < (j+k); i++)
			set_bbit(i, BBIT_ZERO, bbmap);
		    t++; if (!bbitmap_empty(bbmap, sz)) goto err;
		    /* Fill in */
		    bbitmap_fill(bbmap, val, sz);
		    t++; if (bbitmap_weight(bbmap, pat, sz) != sz) goto err;
		    /* Zero all buffer */
		    bbitmap_zero(bbmap, sz);
		    t++; if (!bbitmap_empty(bbmap, sz)) goto err;
		}
	    }
	}
	bbitmap_free(bbmap); bbmap = NULL;
    }
    printf("Test group %d OK\n", tg);

    /* Test group two: long bitmaps with atomics */
    tg = 2;
    printf("Running group %d tests: atomic ops\n", tg);
    /* sz: size */
    for (sz = bb_size_start; sz <= bb_size_end; sz++) {
	/* allocate */
	bbmap = bbitmap_zalloc(sz);
	/* For all non-zero values */
	for (val = BBIT_01; val <= BBIT_11; val++) {
	    pat = BBITS_VAL2PAT(val);
	    /* j: position of the first one */
	    for (j = 0; j < bb_size_end; j++) {
		/* k: number of continious ones */
		for (k = 1; k <= cont_ones_end && (k+j) <= sz; k++) {
		    /* t: test number */
		    t=0; pos=0; i=0;
		    /* bbmap has all zeros */
		    t++; if (!bbitmap_empty(bbmap, sz)) goto err;
		    t++; if (!bbitmap_full(bbmap, BB_PAT_ZERO, sz)) goto err;
		    t++; if ((i=bbitmap_weight(bbmap, pat, sz))) goto err;
		    /* pos: Set "1" in this position */
		    for (pos = j; pos < (j + k) && pos < sz; pos++) {
			/* Must be clear */
			t=4; if (!test_bbit(pos, BBIT_ZERO, bbmap)) goto err;
			/* Atomic Test and Set */
			i = atomic_test_and_set_bbit(pos, val, bbmap);
			t++; if (i != BBIT_ZERO) goto err;
			i = atomic_test_and_set_bbit_pattern(pos, BB_PAT_ZERO, bbmap);
			t++; if (i != (int)pat) goto err;
			/* Atomic Set */
			atomic_set_bbit(pos, val, bbmap);
			/* Test bit */
			t++; if(!test_bbit(pos, val, bbmap)) goto err;
			t++; if(!test_bbit_patterns(pos, pat, bbmap)) goto err;
			/* Atomic Set Pattern */
			atomic_set_bbit_pattern(pos, pat, bbmap);
			t++; if(!test_bbit(pos, val, bbmap)) goto err;
			/* Find first one */
			i = (int)find_first_bbit(bbmap, pat, sz);
			t++; if(i != j) goto err;
			/* Find next one at pos */
			i = (int)find_next_bbit(bbmap, pat, sz, pos);
			t++; if(i != pos) goto err;
			/* no next! */
			i = (int)find_next_bbit(bbmap, pat, sz, pos+1);
			t++; if(i != sz) goto err;
			/* Find next unset */
			i = (int)find_first_unset_bbit(bbmap, pat, sz);
			t++; if (i != (j? 0 :(pos+1))) goto err;
			/* Find next unset */
			i = (int)find_next_unset_bbit(bbmap, pat, sz, j);
			t++; if (i != (pos+1)) goto err;
		    } /* all (k) ones are set */
		    /* Check loops */
		    t=15; i = 0;
		    for_each_clear_bbit(bbit, bbmap, pat, sz) {
			if (!test_bbit(bbit, BBIT_ZERO, bbmap)) goto err;
			i++;
		    } /* expect (sz-k) zeros */
		    t++; if (i != (sz-k)) goto err;
		    /* k ones */
		    t++; i = 0; bbit = j;
		    for_each_set_bbit_from(bbit, bbmap, pat, sz) i++;
		    if (i != k) goto err;
		    /* Filled by PAT00 and val */
		    t++; if (!bbitmap_full(bbmap, BB_PAT_ZERO|pat, sz)) goto err;
		    /* Count all ones */
		    t++; if (bbitmap_weight(bbmap, pat, sz) != k) goto err;
		    /* Zero out all ones */
		    for (i = j; i < (j+k); i++)
			atomic_set_bbit(i, BBIT_ZERO, bbmap);
		    t++; if (!bbitmap_empty(bbmap, sz)) goto err;
		    /* Fill in */
		    bbitmap_fill(bbmap, val, sz);
		    t++; if (bbitmap_weight(bbmap, pat, sz) != sz) goto err;
		    /* Zero whole buffer */
		    bbitmap_zero(bbmap, sz);
		    t++; if (!bbitmap_empty(bbmap, sz)) goto err;
		}
	    }
	}
	bbitmap_free(bbmap); bbmap = NULL;
    }
    printf("Test group %d OK\n", tg);

    /* Test group three: random pattern */
    tg = 3;
    printf("Running group %d tests: random pattern\n", tg);
    srand((unsigned int)time(NULL));
    /* not used in this test */
    val = k = pos = 0;
    /* i: repeat random size test */
    for (i = bb_size_start; i <= bb_size_end; i++) {
	/* sz: size */
	sz = rand() % (bb_size_end - bb_size_start + 1) + bb_size_start;
	bbmap = bbitmap_zalloc(sz);

	/* Fill with random */
	bbmap16 = (unsigned short *) bbmap;
	for (j = 0; j < (int)(DIV_ROUND_UP(sz, BBITS_PER_BYTE * sizeof(short))); j++)
	    bbmap16[j] = rand() % 65536;

	/* For a set of 1, 2 and 3 patterns */
	for (j = 1; j <= 3; j++) {

	    /* Generate a random set of j patterns */
	    do {
		pat1 = rand() % (BB_PAT11 << 1);
	    } while ((int)bb_pset_count(pat1) != j || bb_pset_chk(pat1));
	    /* Test 1: Inverse pattern */
	    t = 1;
	    pat0 = ~pat1 & BB_PAT_MASK;
	    if (bb_pset_chk(pat0)) {
		printf("  pat1:%d count:%d pat0:%d check failed\n",
			pat1, bb_pset_count(pat1), pat0);
		goto err;
	    }

	    /* Test 2: weight(pat) = sz - weight(~pat) */
	    t = 2;
	    v0 = bbitmap_weight(bbmap, pat0, sz);
	    v1 = bbitmap_weight(bbmap, pat1, sz);
	    if (v0 != (sz - v1)) {
		printf("  pat0:%d weight:%d, pat1:%d weight:%d\n", pat0, v0, pat1, v1);
		goto err;
	    }

	    /* Test 3: Cycles */
	    t = 3;
	    v0 = v1 = 0;
	    for_each_clear_bbit(bbit, bbmap, pat1, sz) v0++;
	    for_each_set_bbit(bbit, bbmap, pat0, sz) v1++;
	    if (v0 != v1) {
		printf("  pat0:%d ones:%d, pat1:%d zeros:%d\n", pat0, v1, pat1, v0);
		goto err;
	    }
	}
	bbitmap_free(bbmap); bbmap = NULL;
    }
    printf("Test group %d OK\n", tg);

    printf("SUCCESS\n");
    return 0;
err:
    printf("Test %d.%d FAILED sz:%d val:%d ones start @%d cnt:%d pos:%d buf[%d]:0x%016lX i:%d\n",
		 tg,t, sz, val, j, k, pos, BBIT_WORD(pos), bbmap[BBIT_WORD(pos)], i);
    return 1;
}
