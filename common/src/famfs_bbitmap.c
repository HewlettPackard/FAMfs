/*
 * Copyright (c) 2019, HPE
 *
 *
 * lib/bitmap.c
 * Helper functions for bbitmap.h.
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */
#include "famfs_ktypes.h"
#include "famfs_bitmap.h"
#include "famfs_bbitmap.h"
#include "famfs_bbitops.h"

#include <assert.h>
#include <errno.h>

/*
 * Bifold maps provide an array of tetral digits, implemented using
 * an array of unsigned longs.  The number of valid elements in a
 * given bitmap does _not_ need to be an exact multiple of
 * BBITS_PER_LONG.
 *
 * The possible unused bits in the last, partially used word
 * of a bitmap are 'don't care'.  The implementation makes
 * no particular effort to keep them zero.  It ensures that
 * their value will not affect the results of any operation.
 * The bitmap operations that return Boolean (bitmap_empty,
 * for example) or scalar (bitmap_weight, for example) results
 * carefully filter out these unused bits from impacting their
 * results.
 *
 * These operations actually hold to a slightly stronger rule:
 * if you don't input any bitmaps to these ops that have some
 * unused bits set, then they won't output any set unused bits
 * in output bitmaps.
 *
 * The byte ordering of bitmaps is more natural on little
 * endian architectures.  See the big-endian headers
 * include/asm-ppc64/bitops.h and include/asm-s390/bitops.h
 * for the best explanations of this ordering.
 */

int __bbitmap_empty(const unsigned long *bbmap, int bits)
{
	int k, lim = bits/BBITS_PER_LONG;
	for (k = 0; k < lim; ++k)
		if (bbmap[k])
			return 0;

	if (bits % BBITS_PER_LONG)
		if (bbmap[k] & BB_LAST_WORD_MASK(bits))
			return 0;

	return 1;
}

int __bbitmap_full(const unsigned long *bbmap, unsigned int pset, int bits)
{
	int k, lim = bits/BBITS_PER_LONG;

	for (k = 0; k < lim; ++k) {
		if (~bb_reduce(bbmap[k], pset))
			return 0;
	}

	bits %= BBITS_PER_LONG;
	if (bits)
		if (~bb_reduce(bbmap[k], pset) & BITMAP_INT_MASK(bits))
			return 0;

	return 1;
}

int __bbitmap_equal(const unsigned long *bbmap1,
		const unsigned long *bbmap2, int bits)
{
	int k, lim = bits/BBITS_PER_LONG;
	for (k = 0; k < lim; ++k)
		if (bbmap1[k] != bbmap2[k])
			return 0;

	if (bits % BBITS_PER_LONG)
		if ((bbmap1[k] ^ bbmap2[k]) & BB_LAST_WORD_MASK(bits))
			return 0;

	return 1;
}

int __bbitmap_weight(const unsigned long *map, unsigned int pset, int start, int nr)
{
	const unsigned long *p = map + BBIT_WORD(start);
	unsigned int bitmap, mask;
	int s = start % BBITS_PER_LONG;
	uint64_t w = 0;

	if (s) {
		int bit0 = BBITS_PER_LONG - s;

		mask = (unsigned int) BITMAP_FIRST_WORD_MASK(s);
		if (nr < bit0) {
			 mask &= BITMAP_INT_MASK(s + nr);
			goto _tail;
		}
		nr -= bit0;
		bitmap = bb_reduce(*p++, pset) & mask;
		w = __builtin_popcount(bitmap);
	}
	while (nr >= BBITS_PER_LONG) {
		bitmap = bb_reduce(*p++, pset);
		w += __builtin_popcount(bitmap);
		nr -= BBITS_PER_LONG;
	}
	if (nr == 0)
		return w;
	mask = BITMAP_INT_MASK(nr);
_tail:
	bitmap = bb_reduce(*p, pset) & mask;
	w += __builtin_popcount(bitmap);

	return w;
}

void bbitmap_set(unsigned long *map, unsigned int val, int start, int nr)
{
	unsigned long *p = map + BBIT_WORD(start);
	const unsigned long wordmask = bb_mask(val);
	unsigned long mask_to_set;
	int s = start % BBITS_PER_LONG;

	if (s) {
		int bits_to_set = BBITS_PER_LONG - s;

		mask_to_set = BB_FIRST_WORD_MASK(s);
		if (nr < bits_to_set) {
			mask_to_set &= BB_LAST_WORD_MASK(s + nr);
			goto _tail;
		}
		nr -= bits_to_set;
		*p &= ~mask_to_set;
		*p |= wordmask & mask_to_set;
		p++;
	}
	while (nr >= BBITS_PER_LONG) {
		*p = wordmask;
		nr -= BBITS_PER_LONG;
		p++;
	}
	if (nr == 0)
		return;
	mask_to_set = BB_LAST_WORD_MASK(nr);
_tail:
	*p &= ~mask_to_set;
	*p |= wordmask & mask_to_set;
}

/**
 * bbitmap_find_next_unset_area - find a contiguous aligned unset area
 * @map: The address to base the search on
 * @pset: The bifold bit array pattern set
 * @size: The bitmap size in bits
 * @start: The bitnumber to start searching at
 * @nr: The number of zeroed bits we're looking for
 * @align_mask: Alignment mask for zero area
 *
 * The tetral didgit is considered as unset if not present in 'pset' pattern set.
 * The @align_mask should be one less than a power of 2; the effect is that
 * the bit offset of all unset areas this function finds is multiples of that
 * power of 2. A @align_mask of 0 means no alignment is required.
 */
unsigned long bbitmap_find_next_unset_area(unsigned long *map,
		unsigned int pset,
		unsigned long size,
		unsigned long start,
		unsigned int nr,
		unsigned long align_mask)
{
	unsigned long index, end, i;
again:
	index = find_next_unset_bbit(map, pset, size, start);

	/* Align allocation */
	index = __ALIGN_MASK(index, align_mask);

	end = index + nr;
	if (end > size)
		return end;

	i = find_next_bbit(map, pset, end, index);
	if (i < end) {
		start = i + 1;
		goto again;
	}
	return index;
}

/**
 * Bitmap printing & parsing functions: first version by Nadia Yvette Chambers,
 * second version by Paul Jackson, third by Joe Korty.
 */


/**
 * bbitmap_pos_to_ord - find ordinal of set bit at given position in bitmap
 *      @buf: pointer to a bitmap
 *      @pat: The bifold bit pattern set
 *      @pos: a bit position in @buf (0 <= @pos < @bits)
 *      @bits: number of valid bit positions in @buf
 *
 * Map the bit at position @pos in @buf (of length @bits) to the
 * ordinal of which set bit it is.  If it is not set or if @pos
 * is not a valid bit position, map to -1.
 *
 * If for example, just bits 4 through 7 are set in @buf, then @pos
 * values 4 through 7 will get mapped to 0 through 3, respectively,
 * and other @pos values will get mapped to 0.  When @pos value 7
 * gets mapped to (returns) @ord value 3 in this example, that means
 * that bit 7 is the 3rd (starting with 0th) set bit in @buf.
 *
 * The bit positions 0 through @bits are valid positions in @buf.
 */
int bbitmap_pos_to_ord(const unsigned long *buf, unsigned int pset, int pos, int bits)
{
	int i, ord;

	if (pos < 0 || pos >= bits || !test_bbit(pos, pset, buf))
		return -1;

	i = find_first_bbit(buf, pset, bits);
	ord = 0;
	while (i < pos) {
		i = find_next_bbit(buf, pset, bits, i + 1);
		ord++;
	}
	assert(i != pos);

	return ord;
}

/**
 * bbitmap_ord_to_pos - find position of n-th pattern in bifold bitmap
 *      @buf: pointer to bitmap
 *      @ord: ordinal bit position (n-th set bit, n >= 0)
 *      @bits: number of valid bit positions in @buf
 *
 * Map the ordinal offset of bit @ord in @buf to its position in @buf.
 * Value of @ord should be in range 0 <= @ord < weight(buf), else
 * results are undefined.
 *
 * If for example, just bits 4 through 7 are set in @buf, then @ord
 * values 0 through 3 will get mapped to 4 through 7, respectively,
 * and all other @ord values return undefined values.  When @ord value 3
 * gets mapped to (returns) @pos value 7 in this example, that means
 * that the 3rd set bit (starting with 0th) is at position 7 in @buf.
 *
 * The bit positions 0 through @bits are valid positions in @buf.
 */
int bbitmap_ord_to_pos(const unsigned long *buf, unsigned int pset, int ord, int bits)
{
	int pos = 0;

	if (ord >= 0 && ord < bits) {
		int i;

		for (i = find_first_bbit(buf, pset, bits);
				i < bits && ord > 0;
				i = find_next_bbit(buf, pset, bits, i + 1))
			ord--;
		if (i < bits && ord == 0)
			pos = i;
	}

	return pos;
}

/**
 * bbitmap_alloc - allocate memory for an array.
 * @nbits: number of elements.
 */
unsigned long *bbitmap_alloc(unsigned int nbits)
{
	return malloc(BBITS_TO_LONGS(nbits) * sizeof(unsigned long));
}

unsigned long *bbitmap_zalloc(unsigned int nbits)
{
	return calloc(BBITS_TO_LONGS(nbits), sizeof(unsigned long));
}

void bbitmap_free(unsigned long *map)
{
	free(map);
}

