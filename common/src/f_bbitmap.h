/*
 * (C) Copyright 2019 Hewlett Packard Enterprise Development LP
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

#ifndef F_BBITMAP_H_
#define F_BBITMAP_H_

#ifndef __ASSEMBLY__

#include "f_ktypes.h"
#include "f_bbitops.h"

/*
 * bbitmaps provide bifold bit arrays that consume one or more unsigned
 * longs.  The bbitmap interface and available operations are listed
 * here, in bbitmap.h
 *
 * Each two continious bits define a tetral digit, from '00' to '11'.
 * Up to four different digits of the tetrad define a pattern (mask)
 * that could be stored in char (or int) this way:
 *   bit 0 - is the digit '00',
 *   bit 1 - '01',
 *   bit 2 - '10',
 *   bit 3 - '11'.
 * Bifold bit set and fill operatons require the pattern which has one
 * and only one tetral digit set, i.e. the pattern's weight must be one.
 * Bifold clear and logical (and/or and so on) operations aren't defined.
 * Bifold zero is an alias for bbitmap_fill(dst, BBIT_ZERO, size).
 * bbitmap_empty(src, size) is an alias for bbitmap_full(src, BBIT_ZERO, size).
 * Bifold searches allow any pattern. The search exampleas are:
 *   bbitmap_weight, bbitmap_full, find_first_bbit, find_next_bbit.
 * find_first_zero_bbit and find_next_zero_bbit operations are in fact
 * find_first_bbit and find_next_bbit with the complement pattern.
 */

/*
 * The available bitmap operations and their rough meaning in the
 * case that the bitmap is a single unsigned long are thus:
 *
 * Note that nbits should be always a compile time evaluable constant.
 * Otherwise many inlines will generate horrible code.
 *
 * bbitmap_zero(dst, size)			*dst = 0UL where size is nbits*2
 * bbitmap_fill(dst, val, size)			*dst = 0bxx...xxUL with 'xx' tetral values
 * bbitmap_copy(dst, src, size)			*dst = *src
 * bbitmap_equal(src1, src2, size)		Are *src1 and *src2 equal?
 * bbitmap_empty(src, size)			Are all bits zero in *src?
 * bbitmap_full(src, pset, size)		Are all tetrals in *src set to a pattern in pset?
 * bbitmap_weight(src, pset, size)		Hamming Weight: number of patterns from set in *src
 * bbitmap_set(dst, val, pos, size)		Set specified bifold bit area to tetral value
 * bbitmap_find_next_unset_area(buf, pset,
 *			len, pos, n, mask)	Find a contiguous aligned unset area
 * bbitmap_pos_to_ord(ddr, pat, pos, size)	Find ordinal of pattern at a position
 * bbitmap_ord_to_pos(ddr, pat, n, size)	Find position of n-th pattern in bifold bitmap
 * //bbitmap_scnprintf(buf, len, src, size)	Print bifold bitmap src to buf
 * //bbitmap_parse(buf, buflen, dst, size)	Parse bifold bitmap dst from buf
 */

/*
 * Also the following operations in bbitops.h apply to bitmaps.
 *
 * test_bbit(pos, val, addr)			Is a tetral value in *addr at pos?
 * test_bbit_patterns(pos, pset, addr)		Is a pattern of pset present in *addr at pos?
 * atomic_set_bbit(pos, val, addr)		Set tetral value atomically
 * set_bbit(pos, val, addr)			Set tetral value at position in *addr
 * atomic_set_bbit_pattern(pos, pat, addr)	Set pattern atomically
 * set_bbit_pattern(pos, pat, addr)		Set pattern at position in *addr
 * atomic_test_and_set_bbit(bit, val, addr)	Set value and return old atomically
 * test_and_set_bbit(bit, val, addr)		Set tetral value and return old value
 * atomic_test_and_set_bbit_pattern(bit,
 * 				    pat, addr)	Set pattern and return old pattern
 * find_first_bbit(addr, pset, size)		Find first set pattern position in *addr
 * find_next_bbit(addr, pset, size, pos)	Find next set pattern in *addr at or after pos
 *
 * Atomic operations are:
 * atomic_set_bbit(), atomic_set_bbit_pattern(), atomic_test_and_set_bbit()
 * and atomic_test_and_set_bbit_pattern().
 */

/*
 * The DECLARE_BITMAP(name,size) macro, in linux/types.h, can be used
 * to declare an array named 'name' of just enough unsigned longs to
 * contain all pattern positions from 0 to 'size' - 1.
 */
#define DECLARE_BBITMAP(name,size) \
         unsigned long name[BBITS_TO_LONGS(size)]

/*
 * Allocation and deallocation of bifold bitmap.
 */
extern unsigned long *bbitmap_alloc(size_t size);
extern unsigned long *bbitmap_zalloc(size_t size);
extern void bbitmap_free(unsigned long *map);

/*
 * lib/bitmap.c provides these functions:
 */

extern int __bbitmap_empty(const unsigned long *map, int size);
extern int __bbitmap_full(const unsigned long *map, unsigned int pset, int size);
extern int __bbitmap_equal(const unsigned long *map1,
    const unsigned long *map2, int size);
extern void bbitmap_set(unsigned long *map, unsigned int val, int pos, int len);

extern unsigned long bbitmap_find_next_unset_area(unsigned long *map,
    unsigned int pset, unsigned long size, unsigned long start,
    unsigned int nr, unsigned long align_mask);
extern int bbitmap_pos_to_ord(const unsigned long *map, unsigned int pset,
    int pos, int size);
extern int bbitmap_ord_to_pos(const unsigned long *map, unsigned int pset,
    int ord, int size);

/*
 * 64 bits bit position
 */
extern uint64_t __bbitmap_weight64(const unsigned long *map, unsigned int pset,
    uint64_t start, uint64_t nr);

#define BB_FIRST_WORD_MASK(start)				\
	(~0UL << (2U*((start) % BBITS_PER_LONG)))
#define BB_LAST_WORD_MASK(nbits)				\
	(((nbits) % BBITS_PER_LONG) ?				\
		(1UL << (2U*((nbits) % BBITS_PER_LONG)))-1 : ~0UL)
#define BITMAP_INT_MASK(nbits)	((1U<<(nbits))-1U)

#define small_const_bbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= BBITS_PER_LONG)

static inline void bbitmap_zero(unsigned long *dst, int nbits)
{
	if (small_const_bbits(nbits))
		*dst = 0UL;
	else {
		int len = BBITS_TO_LONGS(nbits) * sizeof(unsigned long);
		memset(dst, 0, len);
	}
}

static inline void bbitmap_fill(unsigned long *dst, unsigned int val, int nbits)
{
	size_t nlongs = BBITS_TO_LONGS(nbits);
	if (!small_const_bbits(nbits)) {
		unsigned char byte = BBITS_MASK_B(val);
		int len = (nlongs - 1) * sizeof(unsigned long);
		memset(dst, byte,  len);
	}
	dst[nlongs - 1] = BB_LAST_WORD_MASK(nbits) & BBITS_MASK_W(val);
}

static inline void bbitmap_copy(unsigned long *dst, const unsigned long *src,
    int nbits)
{
	if (small_const_bbits(nbits))
		*dst = *src;
	else {
		int len = BBITS_TO_LONGS(nbits) * sizeof(unsigned long);
		memcpy(dst, src, len);
	}
}

static inline int bbitmap_equal(const unsigned long *src1,
			const unsigned long *src2, int nbits)
{
	if (small_const_bbits(nbits))
		return ! ((*src1 ^ *src2) & BB_LAST_WORD_MASK(nbits));
	else
		return __bbitmap_equal(src1, src2, nbits);
}

static inline int bbitmap_empty(const unsigned long *src, int nbits)
{
	if (small_const_bbits(nbits))
		return ! (*src & BB_LAST_WORD_MASK(nbits));
	else
		return __bbitmap_empty(src, nbits);
}

static inline int bbitmap_full(const unsigned long *src, unsigned int pset, int nbits)
{
	if (bb_pset_chk(pset))
		return -1; /* ASSERT? */
	return __bbitmap_full(src, pset, nbits);
}

static inline int __bbitmap_weight(const unsigned long *map, unsigned int pset,
    int start, int nr)
{
	return (int)__bbitmap_weight64(map, pset, (uint64_t)start, (uint64_t)nr);
}

static inline int bbitmap_weight(const unsigned long *src, unsigned int pset, int nbits)
{
	if (bb_pset_chk(pset))
		return -1; /* ASSERT? */
	return __bbitmap_weight(src, pset, 0, nbits);
}

#endif /* __ASSEMBLY__ */

#endif /* F_BBITMAP_H_ */
