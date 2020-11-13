/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */
#ifndef F_KTYPES_H_
#define F_KTYPES_H_

#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <asm/bitsperlong.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <memory.h>
#include <assert.h>


#define BITS_PER_LONG __BITS_PER_LONG

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef unsigned uint128_t __attribute__ ((mode (TI)));

#ifndef dev_t
  typedef uint64_t dev_t;
#endif
_Static_assert( __builtin_types_compatible_p(typeof(dev_t), unsigned long), \
		"dev_t");

#define swab16(X) __builtin_bswap16(X)
#define swab32(X) __builtin_bswap32(X)
#define swab64(X) __builtin_bswap64(X)

typedef unsigned fmode_t;
typedef unsigned oom_flags_t;

static inline int WARN_ON_ONCE(int val) { if(val != 0) printf("WARN_ON_ONCE\n"); return val; }
static inline int WARN_ON(int val) { if(val != 0) printf("WARN_ON\n"); return val; }

//RCU
#define rcu_dereference_raw(p) (rcu_dereference(p))
#define __must_check __attribute__((warn_unused_result))
#define __force
#define __user
#define __pure                          __attribute__((pure))
#define __aligned(x)                    __attribute__((aligned(x)))
#define __printf(a, b)                  __attribute__((format(printf, a, b)))
#define __scanf(a, b)                   __attribute__((format(scanf, a, b)))
#define  noinline                       __attribute__((noinline))
//#define __attribute_const__             __attribute__((__const__))
#define __maybe_unused                  __attribute__((unused))
#define __always_unused                 __attribute__((unused))

#define PAGE_SIZE (4096)
#define PAGE_SHIFT (12)
#define PAGE_MASK       (~(PAGE_SIZE-1))
#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define NSEC_PER_USEC   1000L
#define NSEC_PER_MSEC   1000000L
#define USEC_PER_SEC    1000000L
#define NSEC_PER_SEC    1000000000L
#define FSEC_PER_SEC    1000000000000000LL

#define __ALIGN_KERNEL(x, a)            __ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)    (((x) + (mask)) & ~(mask))
#define __ALIGN_MASK(x, mask)   __ALIGN_KERNEL_MASK((x), (mask))
#define ALIGN(x, a)             __ALIGN_KERNEL((x), (a))
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
#define PTR_ALIGN(p, a)         ((typeof(p))ALIGN((unsigned long)(p), (a)))
#define IS_ALIGNED(x, a)                (((x) & ((typeof(x))(a) - 1)) == 0)

#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define ROUNDUP(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define DIV_ROUND_CLOSEST(x, divisor)(                  \
		{                                                       \
	typeof(divisor) __divisor = divisor;            \
	(((x) + ((__divisor) / 2)) / (__divisor));      \
		}                                                       \
)
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

typedef struct { int32_t counter; } atomic_t;

#define atomic_read(a) ((a)->counter)
#define atomic_set(a,b) ((a)->counter = (b))
#define atomic_test_and_set(a) (__atomic_test_and_set(&(a)->counter, __ATOMIC_SEQ_CST))
#define atomic_clear(a) (__atomic_clear(&(a)->counter, __ATOMIC_SEQ_CST))
#define atomic_inc_return(a) (__atomic_add_fetch(&(a)->counter, 1, __ATOMIC_SEQ_CST))
#define atomic_inc(a) ((void)atomic_inc_return(a))
#define atomic_dec_return(a) (__atomic_sub_fetch(&(a)->counter, 1, __ATOMIC_SEQ_CST))
#define atomic_dec(a) ((void)atomic_dec_return(a))
#define atomic_inc_and_test(a) (atomic_inc_return(a) == 0)
#define atomic_dec_and_test(a) (atomic_dec_return(a) == 0)

/* Memory and compiler barriers */
#ifndef cmm_barrier
#define cmm_barrier()   __asm__ __volatile__ ("" : : : "memory")
#endif

#ifndef cmm_mb
#define cmm_mb()    __asm__ __volatile__ ("mfence":::"memory")
#endif

//struct timespec
#define time_get_ts(p_timespec) (clock_gettime(CLOCK_MONOTONIC_RAW, p_timespec))
#ifndef timespec_sub
#define	timespec_sub(vvp, uvp)						\
	do {								\
		(vvp)->tv_sec -= (uvp)->tv_sec;				\
		(vvp)->tv_nsec -= (uvp)->tv_nsec;			\
		if ((vvp)->tv_nsec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_nsec += 1000000000;			\
		}							\
	} while (0)
#endif

#define MAX_ERRNO       4095
#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)
#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

static inline void * __must_check ERR_PTR(long error)
{
	return (void *) error;
}

static inline long __must_check PTR_ERR(__force const void *ptr)
{
	return (long) ptr;
}

static inline bool __must_check IS_ERR(__force const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool __must_check IS_ERR_OR_NULL(__force const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

/**
 * ERR_CAST - Explicitly cast an error-valued pointer to another pointer type
 * @ptr: The pointer to cast.
 *
 * Explicitly cast an error-valued pointer to another pointer type in such a
 * way as to make it clear that's what's going on.
 */
static inline void * __must_check ERR_CAST(__force const void *ptr)
{
	/* cast away the const */
	return (void *) ptr;
}

static inline int __must_check PTR_ERR_OR_ZERO(__force const void *ptr)
{
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	else
		return 0;
}

/*
 * Arithmetics
 */

/* Get floating point exponent - see arch/ia64/include/uapi/asm/gcc_intrin.h */
#define ia64_getf_exp(x)					\
({								\
	long ia64_intri_res;					\
	asm ("getf.exp %0=%1" : "=r"(ia64_intri_res) : "f"(x));	\
	ia64_intri_res;						\
})

/* Linux get page order - borrowed from arch/ia64/include/asm/page.h */
static inline int get_order(unsigned long size)
{
	long double d = size - 1;
	long order;

	order = ia64_getf_exp(d);
	order = order - PAGE_SHIFT - 0xffff + 1;
	if (order < 0)
		order = 0;
	return order;
}

#define const_ilog2(n)				\
(						\
	__builtin_constant_p(n) ? (		\
		(n) < 2 ? 0 :			\
		(n) & (1ULL << 63) ? 63 :	\
		(n) & (1ULL << 62) ? 62 :	\
		(n) & (1ULL << 61) ? 61 :	\
		(n) & (1ULL << 60) ? 60 :	\
		(n) & (1ULL << 59) ? 59 :	\
		(n) & (1ULL << 58) ? 58 :	\
		(n) & (1ULL << 57) ? 57 :	\
		(n) & (1ULL << 56) ? 56 :	\
		(n) & (1ULL << 55) ? 55 :	\
		(n) & (1ULL << 54) ? 54 :	\
		(n) & (1ULL << 53) ? 53 :	\
		(n) & (1ULL << 52) ? 52 :	\
		(n) & (1ULL << 51) ? 51 :	\
		(n) & (1ULL << 50) ? 50 :	\
		(n) & (1ULL << 49) ? 49 :	\
		(n) & (1ULL << 48) ? 48 :	\
		(n) & (1ULL << 47) ? 47 :	\
		(n) & (1ULL << 46) ? 46 :	\
		(n) & (1ULL << 45) ? 45 :	\
		(n) & (1ULL << 44) ? 44 :	\
		(n) & (1ULL << 43) ? 43 :	\
		(n) & (1ULL << 42) ? 42 :	\
		(n) & (1ULL << 41) ? 41 :	\
		(n) & (1ULL << 40) ? 40 :	\
		(n) & (1ULL << 39) ? 39 :	\
		(n) & (1ULL << 38) ? 38 :	\
		(n) & (1ULL << 37) ? 37 :	\
		(n) & (1ULL << 36) ? 36 :	\
		(n) & (1ULL << 35) ? 35 :	\
		(n) & (1ULL << 34) ? 34 :	\
		(n) & (1ULL << 33) ? 33 :	\
		(n) & (1ULL << 32) ? 32 :	\
		(n) & (1ULL << 31) ? 31 :	\
		(n) & (1ULL << 30) ? 30 :	\
		(n) & (1ULL << 29) ? 29 :	\
		(n) & (1ULL << 28) ? 28 :	\
		(n) & (1ULL << 27) ? 27 :	\
		(n) & (1ULL << 26) ? 26 :	\
		(n) & (1ULL << 25) ? 25 :	\
		(n) & (1ULL << 24) ? 24 :	\
		(n) & (1ULL << 23) ? 23 :	\
		(n) & (1ULL << 22) ? 22 :	\
		(n) & (1ULL << 21) ? 21 :	\
		(n) & (1ULL << 20) ? 20 :	\
		(n) & (1ULL << 19) ? 19 :	\
		(n) & (1ULL << 18) ? 18 :	\
		(n) & (1ULL << 17) ? 17 :	\
		(n) & (1ULL << 16) ? 16 :	\
		(n) & (1ULL << 15) ? 15 :	\
		(n) & (1ULL << 14) ? 14 :	\
		(n) & (1ULL << 13) ? 13 :	\
		(n) & (1ULL << 12) ? 12 :	\
		(n) & (1ULL << 11) ? 11 :	\
		(n) & (1ULL << 10) ? 10 :	\
		(n) & (1ULL <<  9) ?  9 :	\
		(n) & (1ULL <<  8) ?  8 :	\
		(n) & (1ULL <<  7) ?  7 :	\
		(n) & (1ULL <<  6) ?  6 :	\
		(n) & (1ULL <<  5) ?  5 :	\
		(n) & (1ULL <<  4) ?  4 :	\
		(n) & (1ULL <<  3) ?  3 :	\
		(n) & (1ULL <<  2) ?  2 :	\
		1) :				\
	-1)

/* ilog2 - log base 2 of 32-bit or a 64-bit unsigned value */
#define ilog2(n) \
( \
	__builtin_constant_p(n) ?	\
	const_ilog2(n) :		\
	(sizeof(n) <= 4) ?		\
	__ilog2_u32(n) :		\
	__ilog2_u64(n)			\
)

static inline __attribute__((const)) int __ilog2_u32(uint32_t n) {
	return (8*sizeof (uint32_t) - __builtin_clz((unsigned int)(n)) - 1);
}

static inline __attribute__((const)) int __ilog2_u64(uint64_t n) {
	return (8*sizeof (uint64_t) - __builtin_clzl((unsigned long)(n)) - 1);
}

#endif /* F_KTYPES_H_ */
