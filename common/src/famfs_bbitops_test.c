/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */
#include <stdio.h>
#include <stdint.h>

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

    /* Test group one: long bitmaps */
    tg = 1;
    printf("Running group %d tests: non-atomic ops\n", tg);
    /* i: size */
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
		    } /* all (k) ones are set */
		    /* Check loops */
		    t=15; i = 0;
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
    /* i: size */
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

    printf("SUCCESS\n");
    return 0;
err:
    printf("Test %d.%d FAILED sz:%d val:%d ones start @%d cnt:%d pos:%d buf[%d]:0x%016lX i:%d\n",
		 tg,t, sz, val, j, k, pos, BBIT_WORD(pos), bbmap[BBIT_WORD(pos)], i);
    return 1;
}
