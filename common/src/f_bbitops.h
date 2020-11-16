/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */
#ifndef F_BBITOPS_H_
#define F_BBITOPS_H_

#include "f_ktypes.h"
#include "f_bitops.h"


#define BBITS_PER_LONG		(BITS_PER_LONG >> 1)
#define BBIT_WORD(nr)		((nr) / BBITS_PER_LONG)
#define BBITS_PER_BYTE		4
#define BBITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BBITS_PER_BYTE * sizeof(long))
#define BBIT_NR_IN_LONG(nr)	((nr) % BBITS_PER_LONG)
#define BBIT_MASK_VAL(val, nr)	(((unsigned long) val) << (2U*BBIT_NR_IN_LONG(nr)))

typedef enum {
    BBIT_ZERO=0,
    BBIT_01,
    BBIT_10,
    BBIT_11
} BBIT_VALUE_t;
#define BBIT_MASK(nr)		BBIT_MASK_VAL(BBIT_11,nr)
#define BBIT_GET_VAL(buf, nr)	(((unsigned long)BBIT_11) &				\
				 ((buf)[BBIT_WORD(nr)] >> (2U*((nr)&(BBITS_PER_LONG-1)))))

#define BB_PAT_ZERO	(1UL << BBIT_ZERO)
#define BB_PAT01	(1UL << BBIT_01)
#define BB_PAT10	(1UL << BBIT_10)
#define BB_PAT11	(1UL << BBIT_11)
#define BB_PAT_MASK	((BB_PAT11 << 1) - 1)

static __always_inline unsigned long bb_mask(BBIT_VALUE_t val)
{
  int i;
  unsigned long m = 0;
  for (i=0; i<BBITS_PER_LONG; i++)
    m |= BBIT_MASK_VAL(val, i);
  return m;
}

/* byte mask */
#define BBITS_MASK_B(val) ({unsigned long v = 0x3U & (unsigned long)(val);	\
			(v | (v << 2) | (v << 4) | (v << 6)); })

#if BITS_PER_LONG == 64
/* LONG word mask */
#define BBITS_MASK_W(val) ({unsigned long v = 0x3U & (unsigned long)(val);	\
			(v | (v << 2) | (v << 4) | (v << 6)			\
			|(v << 8)  | (v << 10) | (v << 12) | (v << 14)		\
			|(v << 16) | (v << 18) | (v << 20) | (v << 22)		\
			|(v << 24) | (v << 26) | (v << 28) | (v << 30)		\
			|(v << 32) | (v << 34) | (v << 36) | (v << 38)		\
			|(v << 40) | (v << 42) | (v << 44) | (v << 46)		\
			|(v << 48) | (v << 50) | (v << 52) | (v << 54)		\
			|(v << 56) | (v << 58) | (v << 60) | (v << 62)); })
#elif BITS_PER_LONG == 32
#define BBITS_MASK_W(val) ({unsigned long v = 0x3U & (unsigned long)(val);	\
			(v | (v << 2) | (v << 4) | (v << 6)			\
			|(v << 8)  | (v << 10) | (v << 12) | (v << 14)		\
			|(v << 16) | (v << 18) | (v << 20) | (v << 22)		\
			|(v << 24) | (v << 26) | (v << 28) | (v << 30)); })
#else
#error BITS_PER_LONG not 32 or 64
#endif

#define BBITS_MASK_ARRAY				\
	{ BBITS_MASK_W(BBIT_ZERO), BBITS_MASK_W(BBIT_01),	\
	  BBITS_MASK_W(BBIT_10), BBITS_MASK_W(BBIT_11) }

#define BBITS_PAT2VAL(pat)	((pat) & BB_PAT11 ? BBIT_11 :		\
				  (pat) & BB_PAT10 ? BBIT_10 :		\
				   (pat) & BB_PAT01 ? BBIT_01 : BBIT_ZERO)

#define BBITS_VAL2PAT(val)	(1U << (val))

#define BBITS_PAT_HAS_VAL(pat, val)					\
	({int v = 0x3U & (unsigned long)(val);				\
	  unsigned int p = BB_PAT_MASK & (unsigned long)(pat);		\
	  int r;							\
	  switch(v) {							\
		case BBIT_ZERO: r = (p & BB_PAT_ZERO); break;		\
		case BBIT_01: r = (p & BB_PAT01); break;		\
		case BBIT_10: r = (p & BB_PAT10); break;		\
		case BBIT_11: r = (p & BB_PAT11); break;		\
		default: r = 0;						\
	  }								\
	  !!(r);							\
	})

/* Check the pattern set: return 0 if Ok */
static inline int bb_pset_chk(unsigned int pset) {
	/* Pattern combo should have one to trhee pattern bit(s) set in 3:0 */
	if (pset & ~BB_PAT_MASK)
	    return 1;		/* extra bit set */
	if ((~pset & BB_PAT_MASK) == 0)
	    return 1;		/* all ones */
	return pset ? 0 : 1;
}

/* Return the least significant unset bit in 'pset', starting with one: 0..3 */
static inline unsigned int bb_pset_ffu(unsigned int pset) {
	int ffz = __builtin_ffs(~pset);
	//ASSERT(ffz > 0 && ffz <= 4);
	if (ffz<1 || ffz>4)
		return 0; /* Don't assert, just return safe value */
	return (unsigned int)--ffz;
}

/* Return the number of patterns in set: 1..3 */
static inline unsigned int bb_pset_count(unsigned int pset) {
	return __builtin_popcount(pset);
}

/* Reduce bbitmap to Morton-encoded bitmap with all zero odd-indexed bits */
static __always_inline unsigned long _bb_reduce(const unsigned long word,
    unsigned int pset)
{
	unsigned int pcnt = bb_pset_count(pset);
	unsigned long mask[4] = BBITS_MASK_ARRAY;
	unsigned long x, w = word;

	switch (pcnt) {
	case 0: return 0;
		break;

	case 4:	return 0x5555555555555555;
		break;

	case 3:	/* Return ~FUNC(~word, ~pset) */
		pset ^= BB_PAT_MASK;
		w ^= ~mask[__builtin_ctz(pset)];
		x = w & BBITS_MASK_W(BBIT_10);
		w &= x >> 1;
		return w ^ BBITS_MASK_W(BBIT_01);

	case 1:	/* Single bbit value pattern */
		w ^= ~mask[__builtin_ctz(pset)]; /* BBITS_MASK[~VAL] */
		x = w & BBITS_MASK_W(BBIT_10);
		return w & (x >> 1);

	case 2: /* Pattern has two bbit values */
		if (pset == 6 || pset == 9) {
			x = (pset == 9)? ~w : w;
			w ^= x >> 1;
		} else {
			if (pset == 3 || pset == 5)
				w = ~w;
			if (pset == 3 || pset == 12)
				w >>= 1;
		}
		return w & BBITS_MASK_W(BBIT_01);
	default: assert(0);
	}
}

/* Reduce bbitmap to Morton-encoded bitmap with all-one odd-indexed bits */
static __always_inline unsigned long _bb_reduce1(const unsigned long word,
    unsigned int pset)
{
	return _bb_reduce(word, pset) | BBITS_MASK_W(BBIT_10);
}

static __always_inline unsigned int bb_reduce(const unsigned long word,
    const unsigned int pset)
{

	unsigned long el = _bb_reduce(word, pset);

	/* Decode 2D Morton: unpack all even-indexed bits in 64bit word */
	//el &= 0x5555555555555555;
	el = (el ^ (el >> 1)) & 0x3333333333333333;
	el = (el ^ (el >> 2)) & 0x0f0f0f0f0f0f0f0f;
	el = (el ^ (el >> 4)) & 0x00ff00ff00ff00ff;
	el = (el ^ (el >> 8)) & 0x0000ffff0000ffff;
	el = (el ^ (el >> 16)) /* & 0x00000000ffffffff */;
	return (unsigned int)el;
}

/* Expand a bitmap to one word of bifold bit array with given values for 0 and 1 */
static __always_inline unsigned long bb_expand(unsigned int bitmap,
    BBIT_VALUE_t one, BBIT_VALUE_t zero)
{
	unsigned long mask;

	/* Encode bitmap to 2D Morton */
	mask = (unsigned long)bitmap;
/* PDEP,PEXT take 18c on AMD - Avoid parallel bit instructions!
	mask = _pdep_u64((unsigned long)bitmap, BBITS_MASK_W(BBIT_01));
*/
	mask = (mask ^ (mask << 16)) & 0x0000ffff0000ffff;
	mask = (mask ^ (mask <<  8)) & 0x00ff00ff00ff00ff;
	mask = (mask ^ (mask <<  4)) & 0x0f0f0f0f0f0f0f0f;
	mask = (mask ^ (mask <<  2)) & 0x3333333333333333;
	mask = (mask ^ (mask <<  1)) & 0x5555555555555555;
	mask |= mask << 1;
	return (mask & BBITS_MASK_W(one)) | (~mask & BBITS_MASK_W(zero));
}

/* Find first set bifold bit in 'word', to any of pattern(s) defined by 'pset' */
static __always_inline unsigned long bb_ffs(unsigned long word, unsigned int pset)
{
	unsigned long bmap = _bb_reduce(word, pset);

	return __builtin_ffsl(bmap) >> 1;
}


#define for_each_set_bbit(bit, addr, pset, size)				\
		for ((bit) = find_first_bbit((addr), (pset), (size));		\
		(bit) < (unsigned long)(size);					\
		(bit) = find_next_bbit((addr), (pset), (size), (bit) + 1))

/* same as for_each_set_bbit() but use bit as value to start with */
#define for_each_set_bbit_from(bit, addr, pset, size)				\
		for ((bit) = find_next_bbit((addr), (pset), (size), (bit));	\
		(bit) < (unsigned long)(size);					\
		(bit) = find_next_bbit((addr), (pset), (size), (bit) + 1))

/*
 * Same as for_each_set_bbit(,,~pset,) but could work a bit faster.
 */
#define for_each_clear_bbit(bit, addr, pset, size)				\
		for ((bit) = find_first_unset_bbit((addr), (pset), (size));	\
		(bit) < (unsigned long)(size);					\
		(bit) = find_next_unset_bbit((addr), (pset), (size), (bit) + 1))

/* same as for_each_clear_bbit() but use bit as value to start with */
#define for_each_clear_bbit_from(bit, addr, pset, size)				\
		for ((bit) = find_next_unset_bbit((addr), (pset), (size), (bit));\
		(bit) < (unsigned long)(size);					\
		(bit) = find_next_unset_bbit((addr), ((pset), size), (bit) + 1))


/*
 * Find the next set bifold bit in a memory region starting at 'offset'.
 * The bifold is considered set if the pattern (tetral digit) is
 * in the pattern set 'pset'.
 * If no bits are set, returns 'size'.
 */
static inline unsigned long find_next_bbit(const unsigned long *addr,
    unsigned int pset, unsigned long size, unsigned long offset)
{
	const unsigned long *p;
	unsigned long result, tmp, mask, mask0;
	unsigned long wordmask[4] = BBITS_MASK_ARRAY;
	unsigned long bitmap;
	unsigned int off;

	/* Return 'size' if the pattern set empty or invalid */
	if (offset >= size)
		return size;

	p = addr + BBIT_WORD(offset);
	result = offset & ~(BBITS_PER_LONG-1);
	size -= result;
	off = offset % BBITS_PER_LONG;
	mask0 = wordmask[bb_pset_ffu(pset)];
	if (off) {
		tmp = *(p++);
		/* unset LSBB, off:0 */
		mask = ~0UL << (2U*off);
		tmp &= mask;
		if (mask0)
			tmp |= ~mask & mask0;
		/* need to unset MSBB? */
		if (size < BBITS_PER_LONG)
			goto found_first;
		/* Any BB set? */
		if ((bitmap = _bb_reduce(tmp, pset)))
			goto found_middle;
		size -= BBITS_PER_LONG;
		result += BBITS_PER_LONG;
	}
	while (size & ~(BBITS_PER_LONG-1)) {
		tmp = *(p++);
		if ((bitmap = _bb_reduce(tmp, pset)))
			goto found_middle;
		result += BBITS_PER_LONG;
		size -= BBITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	mask = ~0UL >> (2U*(BBITS_PER_LONG - size));
	tmp &= mask;
	if (mask0)
		tmp |= ~mask & mask0;
	/* None BB set? */
	if (!(bitmap = _bb_reduce(tmp, pset)))
		return result + size;   /* Nope. */
found_middle:
	result += __builtin_ctzl(bitmap) >> 1;
	return result;
}

/*
 * This implementation of find_{first,next}_zero_bit was stolen from
 * Linus' asm-alpha/bitops.h.
 */
static inline unsigned long find_next_unset_bbit(const unsigned long *addr,
    unsigned int pset, unsigned long size, unsigned long offset)
{
	const unsigned long *p;
	unsigned long result, tmp;
	unsigned long bitmap, bitmask;
	unsigned int off;

	/* Return 'size' if the pattern set empty or invalid */
	if (offset >= size)
		return size;

	p = addr + BBIT_WORD(offset);
	result = offset & ~(BBITS_PER_LONG-1);
	size -= result;
	off = offset % BBITS_PER_LONG;
	if (off) {
		tmp = *(p++);
		/* set LSBB, [2*off:0] */
		bitmask = ~0UL >> 2*(BITS_PER_INT - off);
		if (size < BBITS_PER_LONG)
			goto found_first;
		bitmap = ~(_bb_reduce1(tmp, pset) | bitmask);
		if (bitmap)
			goto found_middle;
		size -= BBITS_PER_LONG;
		result += BBITS_PER_LONG;
	}
	while (size & ~(BBITS_PER_LONG-1)) {
		tmp = *(p++);
		if ((bitmap = ~_bb_reduce1(tmp, pset)))
			goto found_middle;
		result += BBITS_PER_LONG;
		size -= BBITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;
	bitmask = 0;

found_first:
	/* Is any BB unset? */
	bitmask |= ~0UL << 2*size;
	bitmap = ~(_bb_reduce1(tmp, pset) | bitmask);
	if (bitmap == 0U)
		return result + size;   /* Nope. */
found_middle:
	/* result + ffs(bitmap) - 1 where bitmap should not be zero */
	result += __builtin_ctzl(bitmap) >> 1;
	return result;
}

/*
 * Find the first set bifold bit in a memory region.
 * The bifold is considered set if the pattern (tetral digit) is
 * in the pattern set 'pset'.
 * If no bits are set, returns 'size'.
 */
static __always_inline unsigned long find_first_bbit(const unsigned long *addr,
    unsigned int pset, unsigned long size)
{
	const unsigned long *p = addr;
	unsigned long bitmap, tmp, mask, mask0;
	unsigned long wordmask[4] = BBITS_MASK_ARRAY;
	unsigned long result = 0;

	while (size & ~(BBITS_PER_LONG-1)) {
		tmp = *(p++);
		if ((bitmap = _bb_reduce(tmp, pset)))
			goto found;
		result += BBITS_PER_LONG;
		size -= BBITS_PER_LONG;
	}
	if (!size)
		return result;

	mask = ~0UL >> (2U*(BBITS_PER_LONG - size));
	tmp = (*p) & mask;
	mask0 = wordmask[bb_pset_ffu(pset)];
	if (mask0)
		tmp |= ~mask & mask0;
	/* None set? */
	if (!(bitmap = _bb_reduce(tmp, pset)))
		return result + size;
found:
	result += __builtin_ctzl(bitmap) >> 1;
	return result;
}

/*
 * Find the first cleared bifold bit in a memory region.
 */
static inline unsigned long find_first_unset_bbit(const unsigned long *addr,
    unsigned int pset, unsigned long size)
{
	const unsigned long *p = addr;
	unsigned long tmp, bitmap;
	unsigned long result = 0;

	while (size & ~(BBITS_PER_LONG-1)) {
		tmp = *(p++);
		if ((bitmap = ~_bb_reduce1(tmp, pset)))
			goto found;
		result += BBITS_PER_LONG;
		size -= BBITS_PER_LONG;
	}
	if (!size)
		return result;

	tmp = *p;
	bitmap = ~(_bb_reduce1(tmp, pset) | (~0UL << 2*size));
	/* Is any BB unset? */
	if (bitmap == 0U)
		return result + size;   /* Nope. */
found:
	/* result + ffz(bitmap) */
	result += __builtin_ctzl(bitmap) >> 1;
	return result;
}

static inline int test_bbit(int nr, BBIT_VALUE_t val, const volatile unsigned long *addr)
{
	return (BBIT_GET_VAL(addr, nr) == val);
}

/**
 * test_bbit_patterns - Determine whether bifold bitarray element is set
 * to one of the patterns in pset.
 * @nr: bit number to test
 * @pset pattern set
 * @addr: Address to start counting from
 */
static inline int test_bbit_patterns(int nr, unsigned int pset,
    const volatile unsigned long *addr)
{
	unsigned long bbit = BBIT_GET_VAL(addr, nr);
	return BBITS_PAT_HAS_VAL(pset, bbit);
}

/* Non-atomic set_bbit() */
static inline void set_bbit(int nr, int val, volatile unsigned long *addr)
{
	unsigned long mask = BBIT_MASK(nr);
	volatile unsigned long *p = addr + BBIT_WORD(nr);

	*p  &= ~mask;
	*p  |= mask & BBITS_MASK_W(val);
}

/* Atomic set_bbit() */
static __always_inline void atomic_set_bbit(int nr, int val, volatile unsigned long *addr)
{
	unsigned long v, mask = BBIT_MASK(nr);
	volatile unsigned long *p = addr + BBIT_WORD(nr);
	unsigned long src, dst;

	v = mask & BBITS_MASK_W(val);
	dst = __atomic_load_8(p, __ATOMIC_SEQ_CST);
	do {
		src = dst & ~mask;
		src |= v;
	} while (dst != src &&
	    __atomic_compare_exchange_8(p, &dst, src, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));
}

static __always_inline void atomic_set_bbit_pattern(int nr, unsigned int pat,
    volatile unsigned long *addr)
{
	int val = BBITS_PAT2VAL(pat);

	atomic_set_bbit(nr, val, addr);
}

static inline void set_bbit_pattern(int nr, unsigned int pat, volatile unsigned long *addr) {
	set_bbit(nr, BBITS_PAT2VAL(pat), addr);
}

/**
 * test_and_set_bbit - Set a new and return the old tetral value in bifold bit array
 * @nr: Bit to set
 * @val: tetral value
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static inline int test_and_set_bbit(int nr, int val, volatile unsigned long *addr)
{
	unsigned long mask = BBIT_MASK(nr);
	volatile unsigned long *p = addr + BBIT_WORD(nr);
	unsigned long old = *p;

	*p &= ~mask;
	*p = old | (mask & BBITS_MASK_W(val));
	return (int)((old & mask) >> (2U*(nr % BBITS_PER_LONG)));
}

static inline unsigned int test_and_set_bbit_pattern(int nr, unsigned int pat,
    volatile unsigned long *addr)
{
	int val = BBITS_PAT2VAL(pat);

	return BBITS_VAL2PAT(test_and_set_bbit(nr, val, addr));
}

/**
 * atomic_test_and_set_bbit - Set a new and return the old tetral value in bifold bit array
 * @nr: Bit to set
 * @val: tetral value
 * @addr: Address to count from
 *
 * This operation is atomic.
 */
static __always_inline int atomic_test_and_set_bbit(int nr, int val, volatile unsigned long *addr)
{
	unsigned long v, mask = BBIT_MASK(nr);
	volatile unsigned long *p = addr + BBIT_WORD(nr);
	unsigned long src, dst;

	v = mask & BBITS_MASK_W(val);
	dst = __atomic_load_8(p, __ATOMIC_SEQ_CST);
	do {
		src = dst & ~mask;
		src |= v;
	} while (dst != src &&
	    !__atomic_compare_exchange_8(p, &dst, src, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));

	return (int)((dst & mask) >> (2U*(nr % BBITS_PER_LONG)));
}

/**
 * atomic_test_and_set_bbit_pattern
 * - Set a new pattern and return the old pattern in bifold bit array
 * @nr: Bit to set
 * @pat: pattern for setting tetral value, i.e. 1U << val
 * @addr: Address to count from
 *
 * This operation is atomic.
 */
static __always_inline unsigned int atomic_test_and_set_bbit_pattern(int nr, unsigned int pat,
    volatile unsigned long *addr)
{
	int val = BBITS_PAT2VAL(pat);

	return BBITS_VAL2PAT(atomic_test_and_set_bbit(nr, val, addr));
}

#endif /* F_BBITOPS_H_ */

