/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */
#ifndef F_BITOPS_H_
#define F_BITOPS_H_

#include "f_ktypes.h"		/* BITS_PER_LONG */

#define BIT(nr)			(1UL << (nr))
#define BIT_NR_IN_LONG(nr)	((nr) % BITS_PER_LONG)
#define BIT_MASK(nr)		(1UL << BIT_NR_IN_LONG(nr))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BIT_WORD64(nr)		((nr) / (unsigned)BITS_PER_LONG)
#define BITS_PER_BYTE		8
#define BITS_PER_INT		(BITS_PER_BYTE*sizeof(int))
#define BITS_TO_BYTES(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE)
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))


static __always_inline unsigned long __ffs(unsigned long word) {
	return __builtin_ctzl(word);
}

static __always_inline int fls(int x)
{
	int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xffff0000u)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}

static __always_inline unsigned long __fls(unsigned long word) {
	return BITS_PER_LONG - 1 - __builtin_clzl(word);
}

#if BITS_PER_LONG == 32
static __always_inline int fls64(u64 x)
{
	u32 h = x >> 32;
	if (h)
		return fls(h) + 32;
	return fls(x);
}
#elif BITS_PER_LONG == 64
static __always_inline int fls64(u64 x)
{
	if (x == 0)
		return 0;
	return __fls(x) + 1;
}
#else
#error BITS_PER_LONG not 32 or 64
#endif



#define for_each_set_bit(bit, addr, size)				\
		for ((bit) = find_first_bit((addr), (size));		\
		(bit) < (unsigned long)(size);				\
		(bit) = find_next_bit((addr), (size), (bit) + 1))

/* same as for_each_set_bit() but use bit as value to start with */
#define for_each_set_bit_from(bit, addr, size)				\
		for ((bit) = find_next_bit((addr), (size), (bit));	\
		(bit) < (unsigned long)(size);				\
		(bit) = find_next_bit((addr), (size), (bit) + 1))

#define for_each_clear_bit(bit, addr, size)				\
		for ((bit) = find_first_zero_bit((addr), (size));	\
		(bit) < (unsigned long)(size);				\
		(bit) = find_next_zero_bit((addr), (size), (bit) + 1))

/* same as for_each_clear_bit() but use bit as value to start with */
#define for_each_clear_bit_from(bit, addr, size)			\
		for ((bit) = find_next_zero_bit((addr), (size), (bit));	\
		(bit) < (unsigned long)(size);				\
		(bit) = find_next_zero_bit((addr), (size), (bit) + 1))

static __inline__ int get_count_order(unsigned int count)
{
	int order;

	order = fls(count) - 1;
	if (count & (count - 1))
		order++;
	return order;
}

#define __const_hweight8(w)             \
		((unsigned int)                 \
				((!!((w) & (1ULL << 0))) +     \
						(!!((w) & (1ULL << 1))) +     \
						(!!((w) & (1ULL << 2))) +     \
						(!!((w) & (1ULL << 3))) +     \
						(!!((w) & (1ULL << 4))) +     \
						(!!((w) & (1ULL << 5))) +     \
						(!!((w) & (1ULL << 6))) +     \
						(!!((w) & (1ULL << 7)))))

#define __const_hweight16(w) (__const_hweight8(w)  + __const_hweight8((w)  >> 8 ))
#define __const_hweight32(w) (__const_hweight16(w) + __const_hweight16((w) >> 16))
#define __const_hweight64(w) (__const_hweight32(w) + __const_hweight32((w) >> 32))
#define hweight64(w) (__const_hweight64(w))

/*
 * Generic interface.
 */

static __always_inline unsigned long hweight_long(unsigned long w)
{
    return __builtin_constant_p( w )?
	hweight64(w) : (unsigned) __builtin_popcountl(w);
}

/**
 * rol64 - rotate a 64-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline u64 rol64(u64 word, unsigned int shift)
{
	return (word << shift) | (word >> (64 - shift));
}

/**
 * ror64 - rotate a 64-bit value right
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline u64 ror64(u64 word, unsigned int shift)
{
	return (word >> shift) | (word << (64 - shift));
}

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline u32 rol32(u32 word, unsigned int shift)
{
	return (word << shift) | (word >> (32 - shift));
}

/**
 * ror32 - rotate a 32-bit value right
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline u32 ror32(u32 word, unsigned int shift)
{
	return (word >> shift) | (word << (32 - shift));
}

/**
 * rol16 - rotate a 16-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline u16 rol16(u16 word, unsigned int shift)
{
	return (word << shift) | (word >> (16 - shift));
}

/**
 * ror16 - rotate a 16-bit value right
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline u16 ror16(u16 word, unsigned int shift)
{
	return (word >> shift) | (word << (16 - shift));
}

/**
 * rol8 - rotate an 8-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline u8 rol8(u8 word, unsigned int shift)
{
	return (word << shift) | (word >> (8 - shift));
}

/**
 * ror8 - rotate an 8-bit value right
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline u8 ror8(u8 word, unsigned int shift)
{
	return (word >> shift) | (word << (8 - shift));
}

/**
 * sign_extend32 - sign extend a 32-bit value using specified bit as sign-bit
 * @value: value to sign extend
 * @index: 0 based bit index (0<=index<32) to sign bit
 */
static inline s32 sign_extend32(u32 value, int index)
{
	u8 shift = 31 - index;
	return (s32)(value << shift) >> shift;
}

static inline unsigned fls_long(unsigned long l)
{
	if (sizeof(l) == 4)
		return fls(l);
	return fls64(l);
}

/**
 * __ffs64 - find first set bit in a 64 bit word
 * @word: The 64 bit word
 *
 * On 64 bit arches this is a synomyn for __ffs
 * The result is not defined if no bits are set, so check that @word
 * is non-zero before calling this.
 */
static inline unsigned long __ffs64(u64 word)
{
#if BITS_PER_LONG == 32
	if (((u32)word) == 0UL)
		return __ffs((u32)(word >> 32)) + 32;
#elif BITS_PER_LONG != 64
#error BITS_PER_LONG not 32 or 64
#endif
	return __ffs((unsigned long)word);
}


/*
 * Find the next set bit in a memory region.
 */
static inline unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
		unsigned long offset)
{
	const unsigned long *p = addr + BIT_WORD(offset);
	unsigned long result = offset & ~(BITS_PER_LONG-1);
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_LONG;
	if (offset) {
		tmp = *(p++);
		tmp &= (~0UL << offset);
		if (size < BITS_PER_LONG)
			goto found_first;
		if (tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}
	while (size & ~(BITS_PER_LONG-1)) {
		if ((tmp = *(p++)))
			goto found_middle;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	tmp &= (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)         /* Are any bits set? */
		return result + size;   /* Nope. */
found_middle:
	return result + __ffs(tmp);
}

/*
 * ffz - find first zero in word.
 * @word: The word to search
 *
 * Undefined if no zero exists, so code should check against ~0UL first.
 */
#define ffz(x)  __ffs(~(x))

/*
 * This implementation of find_{first,next}_zero_bit was stolen from
 * Linus' asm-alpha/bitops.h.
 */
static inline unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size,
		unsigned long offset)
{
	const unsigned long *p = addr + BIT_WORD(offset);
	unsigned long result = offset & ~(BITS_PER_LONG-1);
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_LONG;
	if (offset) {
		tmp = *(p++);
		tmp |= ~0UL >> (BITS_PER_LONG - offset);
		if (size < BITS_PER_LONG)
			goto found_first;
		if (~tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}
	while (size & ~(BITS_PER_LONG-1)) {
		if (~(tmp = *(p++)))
			goto found_middle;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	tmp |= ~0UL << size;
	if (tmp == ~0UL)        /* Are any bits zero? */
		return result + size;   /* Nope. */
found_middle:
	return result + ffz(tmp);
}

/*
 * Find the first set bit in a memory region.
 */
static inline unsigned long find_first_bit(const unsigned long *addr, unsigned long size)
{
	const unsigned long *p = addr;
	unsigned long result = 0;
	unsigned long tmp;

	while (size & ~(BITS_PER_LONG-1)) {
		if ((tmp = *(p++)))
			goto found;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;

	tmp = (*p) & (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)         /* Are any bits set? */
		return result + size;   /* Nope. */
found:
	return result + __ffs(tmp);
}

/*
 * Find the first cleared bit in a memory region.
 */
static inline unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
	const unsigned long *p = addr;
	unsigned long result = 0;
	unsigned long tmp;

	while (size & ~(BITS_PER_LONG-1)) {
		if (~(tmp = *(p++)))
			goto found;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;

	tmp = (*p) | (~0UL << size);
	if (tmp == ~0UL)        /* Are any bits zero? */
		return result + size;   /* Nope. */
found:
	return result + ffz(tmp);
}

/*
 * Find the last set bit in a memory region.
 * Returns the bit number of the last set bit, or size.
 *
 * This implementation of find_last_bit was stolen from
 * Linus' lib/find_bit.c
 */
static inline unsigned long find_last_bit(const unsigned long *addr, unsigned long size)
{
	if (size) {
		unsigned long val = BITMAP_LAST_WORD_MASK(size);
		unsigned long idx = (size-1) / BITS_PER_LONG;

		do {
			val &= addr[idx];
			if (val)
				return idx * BITS_PER_LONG + __fls(val);

			val = ~0ul;
		} while (idx--);
	}
	return size;
}


/**
 * test_bit - Determine whether a bit is set
 * @nr: bit number to test
 * @addr: Address to start counting from
 */
static inline int test_bit(int nr, const volatile unsigned long *addr)
{
        return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}

static inline void set_bit(int nr, volatile unsigned long *addr)
{
        unsigned long mask = BIT_MASK(nr);
        volatile unsigned long *p = addr + BIT_WORD(nr);

        *p  |= mask;
}

static inline void clear_bit(int nr, volatile unsigned long *addr)
{
        unsigned long mask = BIT_MASK(nr);
        volatile unsigned long *p = addr + BIT_WORD(nr);

        *p &= ~mask;
}

static inline int test_bit64(uint64_t nr, const volatile unsigned long *addr)
{
        return 1UL & (addr[BIT_WORD64(nr)] >> (nr & (unsigned long)(BITS_PER_LONG-1)));
}

static inline void set_bit64(uint64_t nr, volatile unsigned long *addr)
{
        unsigned long mask = BIT_MASK(nr);
        volatile unsigned long *p = addr + BIT_WORD64(nr);

        *p  |= mask;
}

static inline void clear_bit64(uint64_t nr, volatile unsigned long *addr)
{
        unsigned long mask = BIT_MASK(nr);
        volatile unsigned long *p = addr + BIT_WORD64(nr);

        *p &= ~mask;
}

/**
 * __change_bit - Toggle a bit in memory
 * @nr: the bit to change
 * @addr: the address to start counting from
 *
 * Unlike change_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
static inline void change_bit(int nr, volatile unsigned long *addr)
{
        unsigned long mask = BIT_MASK(nr);
        volatile unsigned long *p = addr + BIT_WORD(nr);

        *p ^= mask;
}

/**
 * __test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static inline int test_and_set_bit(int nr, volatile unsigned long *addr)
{
        unsigned long mask = BIT_MASK(nr);
        volatile unsigned long *p = addr + BIT_WORD(nr);
        unsigned long old = *p;

        *p = old | mask;
        return (old & mask) != 0;
}

/**
 * __test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static inline int test_and_clear_bit(int nr, volatile unsigned long *addr)
{
        unsigned long mask = BIT_MASK(nr);
        volatile unsigned long *p = addr + BIT_WORD(nr);
        unsigned long old = *p;

        *p = old & ~mask;
        return (old & mask) != 0;
}

/* WARNING: non atomic and it can be reordered! */
static inline int test_and_change_bit(int nr,
                                            volatile unsigned long *addr)
{
        unsigned long mask = BIT_MASK(nr);
        volatile unsigned long *p = addr + BIT_WORD(nr);
        unsigned long old = *p;

        *p = old ^ mask;
        return (old & mask) != 0;
}


/*
 * Atomic bitmap ops
 */

/* Atomically set bit 'nr' in bitmap 'addr' */
static __always_inline void atomic_set_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	volatile unsigned long *p = addr + BIT_WORD(nr);
	unsigned long src, dst;

	dst = __atomic_load_8(p, __ATOMIC_SEQ_CST);
	do {
		src = dst | mask;
	} while (dst != src &&
	    __atomic_compare_exchange_8(p, &dst, src, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));
}

/* Atomically set or clear bit 'nr' in bitmap 'addr' */
static __always_inline void atomic_clear_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	volatile unsigned long *p = addr + BIT_WORD(nr);
	unsigned long src, dst;

	dst = __atomic_load_8(p, __ATOMIC_SEQ_CST);
	do {
		src = dst & ~mask;
	} while (dst != src &&
	    __atomic_compare_exchange_8(p, &dst, src, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));
}

/**
 * atomic_test_and_set_bit - Set a bit in bit array and return the old value
 * @nr: Bit to set
 * @val: value
 * @addr: Address to count from
 *
 * This operation is atomic.
 */
static __always_inline int atomic_test_and_set_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	volatile unsigned long *p = addr + BIT_WORD(nr);
	unsigned long src, dst;

	dst = __atomic_load_8(p, __ATOMIC_SEQ_CST);
	do {
		src = dst | mask;
	} while (dst != src &&
	    !__atomic_compare_exchange_8(p, &dst, src, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));

	return (int)((dst & mask) >> (nr % BITS_PER_LONG));
}

/**
 * atomic_test_and_clear_bit - Clear a bit in bit array and return the old value
 * @nr: Bit to set
 * @val: value
 * @addr: Address to count from
 *
 * This operation is atomic.
 */
static __always_inline int atomic_test_and_clear_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	volatile unsigned long *p = addr + BIT_WORD(nr);
	unsigned long src, dst;

	dst = __atomic_load_8(p, __ATOMIC_SEQ_CST);
	do {
		src = dst & ~mask;
	} while (dst != src &&
	    !__atomic_compare_exchange_8(p, &dst, src, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));

	return (int)((dst & mask) >> (nr % BITS_PER_LONG));
}


/* Macros to define access the flags access inline functions. */
#define BITOPS(name, what, var, flag) \
static inline int TestClear ## name ## what(struct var *v) \
{ return test_and_clear_bit(flag, &v->io.flags); } \
static inline int TestSet ## name ## what(struct var *v) \
{ return test_and_set_bit(flag, &v->io.flags); } \
static inline void Clear ## name ## what(struct var *v) \
{ clear_bit(flag, &v->io.flags); } \
static inline void Set ## name ## what(struct var *v) \
{ set_bit(flag, &v->io.flags); } \
static inline int name ## what(struct var *v) \
{ return test_bit(flag, &v->io.flags); }


#endif /* F_BITOPS_H_ */
