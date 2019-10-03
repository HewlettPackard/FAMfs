/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */
#ifndef FAMFS_KTYPES_H_
#define FAMFS_KTYPES_H_

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
typedef uint64_t dma_addr_t;
#if 0
typedef unsigned uint128_t __attribute__ ((mode (TI)));

#define be16_to_cpup(X) __be16_to_cpup(X)
#define be32_to_cpup(X) __be32_to_cpup(X)
#define be64_to_cpup(X) __be64_to_cpup(X)
#define be16_to_cpu(X) __be16_to_cpu(X)
#define be32_to_cpu(X) __be32_to_cpu(X)
#define be64_to_cpu(X) __be64_to_cpu(X)
#define le16_to_cpu(X) __le16_to_cpu(X)
#define le32_to_cpu(X) __le32_to_cpu(X)
#define le64_to_cpu(X) __le64_to_cpu(X)
#define le16_to_cpus(X) __le16_to_cpus(X)
#define le32_to_cpus(X) __le32_to_cpus(X)
#define cpu_to_be16(X) __cpu_to_be16(X)
#define cpu_to_be32(X) __cpu_to_be32(X)
#define cpu_to_be64(X) __cpu_to_be64(X)
#define cpu_to_le16(X) __cpu_to_le16(X)
#define cpu_to_le32(X) __cpu_to_le32(X)
#define cpu_to_le64(X) __cpu_to_le64(X)
#define cpu_to_le16s(X) __cpu_to_le16s(X)
#endif

#define swab16(X) __builtin_bswap16(X)
#define swab32(X) __builtin_bswap32(X)
#define swab64(X) __builtin_bswap64(X)

typedef unsigned gfp_t;
typedef unsigned fmode_t;
typedef unsigned oom_flags_t;

static inline int WARN_ON_ONCE(int val) { if(val != 0) printf("WARN_ON_ONCE\n"); return val; }
static inline int WARN_ON(int val) { if(val != 0) printf("WARN_ON\n"); return val; }

//RCU
#define rcu_dereference_raw(p) (rcu_dereference(p))
#define __must_check __attribute__((warn_unused_result))
#define __force
#define __user
#if 0
#define rcu_assign_pointer(a,b) ((a) = (b))
#define rcu_dereference(X) ((X))
#define rcu_dereference_protected(X, LOCK) ((X))
#define rcu_read_lock()
#define rcu_read_unlock()
#define __bitwise__
#define __kernel
#define __safe
#define __nocast
#define __iomem
#define __chk_user_ptr(x) (void)0
#define __chk_io_ptr(x) (void)0
#define __builtin_warning(x, y...) (1)
#define __must_hold(x)
#define __acquires(x)
#define __releases(x)
#define __acquire(x) (void)0
#define __release(x) (void)0
#define __cond_lock(x,c) (c)
#define __percpu
#define __rcu
#define __read_mostly
#define ____cacheline_aligned_in_smp __rte_cache_aligned
#endif

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

#if 0 //-------------------------------------------

#define mdelay(X) rte_delay_ms(X)
#define msleep_interruptible(X) mdelay(X)
#define udelay(X) rte_delay_us(X)
#define msleep(X) rte_delay_ms(X)

#endif //-------------------------------------------

/* Plain integer GFP bitmasks. Do not use this directly. */
#define ___GFP_DMA              0x01u
#define ___GFP_HIGHMEM          0x02u
#define ___GFP_DMA32            0x04u
#define ___GFP_MOVABLE          0x08u
#define ___GFP_WAIT             0x10u
#define ___GFP_HIGH             0x20u
#define ___GFP_IO               0x40u
#define ___GFP_FS               0x80u
#define ___GFP_COLD             0x100u
#define ___GFP_NOWARN           0x200u
#define ___GFP_REPEAT           0x400u
#define ___GFP_NOFAIL           0x800u
#define ___GFP_NORETRY          0x1000u
#define ___GFP_MEMALLOC         0x2000u
#define ___GFP_COMP             0x4000u
#define ___GFP_ZERO             0x8000u
#define ___GFP_NOMEMALLOC       0x10000u
#define ___GFP_HARDWALL         0x20000u
#define ___GFP_THISNODE         0x40000u
#define ___GFP_RECLAIMABLE      0x80000u
#define ___GFP_NOTRACK          0x200000u
#define ___GFP_NO_KSWAPD        0x400000u
#define ___GFP_OTHER_NODE       0x800000u
#define ___GFP_WRITE            0x1000000u
/* If the above are modified, __GFP_BITS_SHIFT may need updating */

/*
 * GFP bitmasks..
 *
 * Zone modifiers (see linux/mmzone.h - low three bits)
 *
 * Do not put any conditional on these. If necessary modify the definitions
 * without the underscores and use them consistently. The definitions here may
 * be used in bit comparisons.
 */
#define __GFP_DMA       ((__force gfp_t)___GFP_DMA)
#define __GFP_HIGHMEM   ((__force gfp_t)___GFP_HIGHMEM)
#define __GFP_DMA32     ((__force gfp_t)___GFP_DMA32)
#define __GFP_MOVABLE   ((__force gfp_t)___GFP_MOVABLE)  /* Page is movable */
#define GFP_ZONEMASK    (__GFP_DMA|__GFP_HIGHMEM|__GFP_DMA32|__GFP_MOVABLE)
/*
 * Action modifiers - doesn't change the zoning
 *
 * __GFP_REPEAT: Try hard to allocate the memory, but the allocation attempt
 * _might_ fail.  This depends upon the particular VM implementation.
 *
 * __GFP_NOFAIL: The VM implementation _must_ retry infinitely: the caller
 * cannot handle allocation failures.  This modifier is deprecated and no new
 * users should be added.
 *
 * __GFP_NORETRY: The VM implementation must not retry indefinitely.
 *
 * __GFP_MOVABLE: Flag that this page will be movable by the page migration
 * mechanism or reclaimed
 */
#define __GFP_WAIT      ((__force gfp_t)___GFP_WAIT)    /* Can wait and reschedule? */
#define __GFP_HIGH      ((__force gfp_t)___GFP_HIGH)    /* Should access emergency pools? */
#define __GFP_IO        ((__force gfp_t)___GFP_IO)      /* Can start physical IO? */
#define __GFP_FS        ((__force gfp_t)___GFP_FS)      /* Can call down to low-level FS? */
#define __GFP_COLD      ((__force gfp_t)___GFP_COLD)    /* Cache-cold page required */
#define __GFP_NOWARN    ((__force gfp_t)___GFP_NOWARN)  /* Suppress page allocation failure warning */
#define __GFP_REPEAT    ((__force gfp_t)___GFP_REPEAT)  /* See above */
#define __GFP_NOFAIL    ((__force gfp_t)___GFP_NOFAIL)  /* See above */
#define __GFP_NORETRY   ((__force gfp_t)___GFP_NORETRY) /* See above */
#define __GFP_MEMALLOC  ((__force gfp_t)___GFP_MEMALLOC)/* Allow access to emergency reserves */
#define __GFP_COMP      ((__force gfp_t)___GFP_COMP)    /* Add compound page metadata */
#define __GFP_ZERO      ((__force gfp_t)___GFP_ZERO)    /* Return zeroed page on success */
#define __GFP_NOMEMALLOC ((__force gfp_t)___GFP_NOMEMALLOC) /* Don't use emergency reserves.
 * This takes precedence over the
 * __GFP_MEMALLOC flag if both are
 * set
 */
#define __GFP_HARDWALL   ((__force gfp_t)___GFP_HARDWALL) /* Enforce hardwall cpuset memory allocs */
#define __GFP_THISNODE  ((__force gfp_t)___GFP_THISNODE)/* No fallback, no policies */
#define __GFP_RECLAIMABLE ((__force gfp_t)___GFP_RECLAIMABLE) /* Page is reclaimable */
#define __GFP_NOTRACK   ((__force gfp_t)___GFP_NOTRACK)  /* Don't track with kmemcheck */

#define __GFP_NO_KSWAPD ((__force gfp_t)___GFP_NO_KSWAPD)
#define __GFP_OTHER_NODE ((__force gfp_t)___GFP_OTHER_NODE) /* On behalf of other node */
#define __GFP_WRITE     ((__force gfp_t)___GFP_WRITE)   /* Allocator intends to dirty page */

/*
 * This may seem redundant, but it's a way of annotating false positives vs.
 * allocations that simply cannot be supported (e.g. page tables).
 */
#define __GFP_NOTRACK_FALSE_POSITIVE (__GFP_NOTRACK)

#define __GFP_BITS_SHIFT 25     /* Room for N __GFP_FOO bits */
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))

/* This equals 0, but use constants in case they ever change */
#define GFP_NOWAIT      (GFP_ATOMIC & ~__GFP_HIGH)
/* GFP_ATOMIC means both !wait (__GFP_WAIT not set) and use emergency pool */
#define GFP_ATOMIC      (__GFP_HIGH)
#define GFP_NOIO        (__GFP_WAIT)
#define GFP_NOFS        (__GFP_WAIT | __GFP_IO)
#define GFP_KERNEL      (__GFP_WAIT | __GFP_IO | __GFP_FS)
#define GFP_TEMPORARY   (__GFP_WAIT | __GFP_IO | __GFP_FS | \
		__GFP_RECLAIMABLE)
#define GFP_USER        (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
#define GFP_HIGHUSER    (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL | \
		__GFP_HIGHMEM)
#define GFP_HIGHUSER_MOVABLE    (__GFP_WAIT | __GFP_IO | __GFP_FS | \
		__GFP_HARDWALL | __GFP_HIGHMEM | \
		__GFP_MOVABLE)
#define GFP_IOFS        (__GFP_IO | __GFP_FS)
#define GFP_TRANSHUGE   (GFP_HIGHUSER_MOVABLE | __GFP_COMP | \
		__GFP_NOMEMALLOC | __GFP_NORETRY | __GFP_NOWARN | \
		__GFP_NO_KSWAPD)

////#include "list.h"

#if 0  //-------------------------------------------

typedef rte_spinlock_t mutex_t;
typedef rte_spinlock_t spinlock_t;
typedef rte_atomic32_t atomic_t;
typedef rte_spinlock_t rwlock_t;

#define ATOMIC_INIT(X) RTE_ATOMIC32_INIT(X)

#define DEFINE_MUTEX(_mutex) \
		rte_spinlock_t _mutex = {.locked=0}

#define mmiowb() rte_wmb()
#define wmb() rte_wmb()
#define mb() rte_mb()
#define rmb() rte_rmb()
#define read_barrier_depends() rte_rmb()
#define smp_mb() rte_mb()
#define smp_wmb() rte_wmb()
#define smp_rmb() rte_rmb()
#define smp_mb__before_atomic() barrier()
#define smp_mb__before_clear_bit() barrier()
#define synchronize_rcu() rte_mb()
#define synchronize_irq(X) rte_mb()
#define synchronize_rcu_expedited() rte_mb()
//#define timecounter_cyc2time(X, Y) (Y)
#define timecounter_cyc2time(clock, timestamp) (timestamp)
#define timecounter_read(clock)
#define timecounter_init(a,b,c)
#define time_is_before_jiffies(X) (jiffies > (X))

#define prefetch(ptr) rte_prefetch0(ptr)
#define prefetchw(ptr) rte_prefetch0(ptr)
//#define HZ (rte_get_tsc_hz())
#ifndef HZ
#define HZ 1000UL //1000 Hz
#endif
#define jiffies (HZ*rte_rdtsc()/rte_get_tsc_hz())

#define round_jiffies(x) (x)
#define round_jiffies_relative(x) (x)

#define spin_lock_init(X) rte_spinlock_init((mutex_t*)X)
#define spin_lock(X) rte_spinlock_lock((mutex_t*)X)
#define spin_unlock(X) rte_spinlock_unlock((mutex_t*)X)

#define spin_lock_irq spin_lock
#define spin_unlock_irq spin_unlock
#define spin_lock_irqsave(X,flag) spin_lock(X)
#define spin_unlock_irqrestore(X,flag) spin_unlock(X)
#define spin_lock_bh(X) spin_lock(X)
#define spin_unlock_bh(X) spin_unlock(X)

#define mutex_init(X) rte_spinlock_init((mutex_t*)X)
#define mutex_lock(X) rte_spinlock_lock((mutex_t*)X)
#define mutex_unlock(X) rte_spinlock_unlock((mutex_t*)X)
#define mutex_destroy(X)

#define rwlock_init(X) rte_spinlock_init(X)
#define read_lock(X) rte_spinlock_lock(X)
#define read_unlock(X) rte_spinlock_unlock(X)
#define write_lock(X) rte_spinlock_lock(X)
#define write_unlock(X) rte_spinlock_unlock(X)
#define read_lock_irqsave(X,flag) rte_spinlock_lock(X)
#define read_unlock_irqrestore(X,flag) rte_spinlock_unlock(X)
#define write_lock_irqsave(X,flag) rte_spinlock_lock(X)
#define write_unlock_irqrestore(X,flag) rte_spinlock_unlock(X)

#define readb read8
#define writeb write8
#define readw read16
#define writew write16
#define readl read32
#define writel write32
#define readq read64
#define writeq write64

#define kmalloc(size, flag) rte_malloc("kmalloc", size, RTE_CACHE_LINE_SIZE)
#define kzalloc(size, flag) rte_zmalloc("kzalloc", size, RTE_CACHE_LINE_SIZE)
#define kcalloc(count, unit, kern_flag) rte_calloc("kcalloc", count, unit, RTE_CACHE_LINE_SIZE)
#define kmalloc_node(size, flag, node) rte_malloc_socket("kmalloc_node", size, RTE_CACHE_LINE_SIZE, node)
#define kzalloc_node(size, kern_flag, node) rte_zmalloc_socket("kzalloc_node", size, RTE_CACHE_LINE_SIZE, node)
#define vzalloc(size) rte_zmalloc("vzalloc", size, RTE_CACHE_LINE_SIZE)
#define vzalloc_node(size, node) rte_zmalloc_socket("vzalloc", size, RTE_CACHE_LINE_SIZE, node)
#define vfree(ptr) rte_free(ptr)
#define vmalloc(size) rte_malloc("vmalloc", size, RTE_CACHE_LINE_SIZE)
#define vmalloc_node(size, node) rte_malloc_socket("vmalloc", size, RTE_CACHE_LINE_SIZE, node)

#define kfree(ptr) rte_free(ptr)

#define L1_CACHE_BYTES RTE_CACHE_LINE_SIZE
#define SMP_CACHE_BYTES L1_CACHE_BYTES
#define cache_line_size(X) RTE_CACHE_LINE_SIZE

#endif //-------------------------------------------

#if 0  //-------------------------------------------

#define atomic_cmpset(a,b,c) rte_atomic32_cmpset(a,b,c)
#define atomic_init(a) rte_atomic32_init(a)
#define atomic_set(a,b) rte_atomic32_set(a,b)
#define atomic_read(a) rte_atomic32_read(a)
#define atomic_add(a,b) rte_atomic32_add(b,a)
#define atomic_sub(a,b) rte_atomic32_sub(b,a)
#define atomic_inc(a) rte_atomic32_inc(a)
#define atomic_dec(a) rte_atomic32_dec(a)
#define atomic_add_return(a,b) rte_atomic32_add_return(b,a)
#define atomic_inc_return(a) rte_atomic32_add_return(a,1)
#define atomic_dec_return(a) rte_atomic32_add_return(a,-1)
#define atomic_inc_and_test(a) rte_atomic32_inc_and_test(a)
#define atomic_dec_and_test(a) rte_atomic32_dec_and_test(a)
#define atomic_test_and_set(a) rte_atomic32_test_and_set(a)
#define atomic_clear(a) rte_atomic32_clear(a)
#define cond_resched() rte_pause()

#define jiffies_to_msecs(X) (MSEC_PER_SEC*(X)/HZ)

#define max __MAX
#define min __MIN
#define MAX __MAX
#define MIN __MIN
#define __MAX(a,b) RTE_MAX((a),(b))
#define __MIN(a,b) RTE_MIN((a),(b))
#define min3(a,b,c) RTE_MIN(RTE_MIN((a),(b)),(c))
#define clamp_t(type, val, lo, hi) min_t(type, max_t(type, val, lo), hi)
#define min_t(type, a, b) MIN((type)(a), (type)(b))
#define max_t(type, a, b) MAX((type)(a), (type)(b))

//

#define __always_inline __inline __attribute__ ((__always_inline__))
#define __packed __attribute__((packed))

#define time_get_ts(p_timespec) (clock_gettime(CLOCK_MONOTONIC_RAW, p_timespec))

#define msecs_to_jiffies(msec) ((msec * HZ) / MSEC_PER_SEC)
#define jiffies_to_msec(jifi) ((jifi*MSEC_PER_SEC) / HZ)

#define __raw_writeq write64

struct mutex{
	mutex_t mutex;
}__attribute__((packed));

typedef struct semaphore
{
	int count;
	mutex_t lock;
}semaphore_t;
#define rw_semaphore semaphore
#define down_read down
#define up_read up
#define down_write down
#define up_write up
#define init_rwsem(x) sema_init(x,1)

#endif //-------------------------------------------

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

//#include "kcompat.h"
//#include "inline_functions.h"

#endif /* FAMFS_KTYPES_H_ */
