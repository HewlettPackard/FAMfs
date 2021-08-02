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

#ifndef F_DICT_H_
#define F_DICT_H_

#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>
#include <uuid/uuid.h>

#include "f_env.h"


/*
 * Key-value pair for pool device persistent label
 *
 * Key is fixed size 64 bit int that contains value type, (optional) index and persistent flag,
 * i.e. the key has constrains for its handling (parsing and storing).
 */

typedef enum {
    F_KEY_NONE=0,
    F_KEY_UUID,		/* object's UUID */
    F_KEY_NAME,		/* object's name */
    F_KEY_PDEV_UUID,	/* pool device UUID */
    F_KEY_PDEV_NAME,	/* pool device name */
    F_KEY_PDEV_URL,	/* pool FAM URL */
    F_KEY_PDEV_PK,	/* protection key associated with the remote memory */
    F_KEY_DESC,		/* object's description aka "long name" */
    F_KEY_DEVCOUNT,	/* the number of pool devices */
    F_KEY_NPARTS,	/* number of partitions in the pool or layout */
    FP_KEY_DEVLIST_SZ,	/* the size of the persistent pool devices list */
    FP_KEY_EXT_SIZE,	/* pool device extent size */
    FP_KEY_EXT_COUNT,	/* pool device extent count */
    FP_KEY_EXT_START,	/* pool device first data extent */
    FL_KEY_MONIKER,	/* Layout moniker */
    FL_KEY_DEVLIST_SZ,	/* the size of the persistent devices list for the layout */
    FL_KEY_SME_SZ,	/* slab map entry size, bytes */
    FA_KEY_DEVLIST_SZ,	/* the size of the pool devices list for the allocation grop */
    F_KEY_LAST,
} F_KEY_t;

typedef enum {
    FVAR_TYPE_NONE=0,	/* empty key-value pair (nil) */
    FVAR_TYPE_INT,	/* value type is int */
    FVAR_TYPE_UUID,	/* uuit_t */
    FVAR_TYPE_STR,	/* "long" string: */
    FVAR_TYPE_SHORT_STR,/* "short" length-terminated string; FVAR_SHORT_STR_MAX chars at most */
    FVAR_TYPE_NOVALUE,	/* KV has no value; the key is a filter for KV import/export */
    FVAR_TYPE_LAST,
} FVAR_TYPE_t;

typedef enum {
    F_KEY_OBJ_POOL = 0,
    F_KEY_OBJ_LAYOUT,
    F_KEY_OBJ_AG,
    F_KEY_OBJ_LAST,
} F_KEY_OBJ_t;

typedef struct fvar_key_ {
    uint16_t __attribute__ ((aligned(2))) \
		key;		/* F_KEY_t */
    uint8_t	key_object;	/* F_KEY_OBJ_t */
    uint8_t	key_hash;	/* device persistent flags when key is F_KEY_PDEV_UUID */
    uint16_t	key_index;	/* device index or "long" string fragment number */
    uint8_t	val_type;	/* FVAR_TYPE_t */
    union {
	uint8_t	flags;
	struct {
	    unsigned int	persistent:1;	/* persistent KV pair */
	    unsigned int	indexable:1;	/* indexable element, such as pool device */
	    unsigned int	_resv:6;
	} __attribute__ ((packed));
    };
} FVAR_KEY_t;

/* Value types are int (int64_t), uuid (128 bit) or string. This structure is fixed (16 bytes) */
#define FVAR_SHORT_STR_MAX	14	/* max length of a string which nested in value entry */
#define FVAR_STR_MAX		1024	/* max length of "long" string divided to fragments */
typedef union fvar_val_ {
    int64_t	val;		/* int, FVAR_TYPE_INT */
    uuid_t	uuid;		/* uuid: 16 bytes, FVAR_TYPE_UUID */
    struct {			/* "long" strings (FVAR_TYPE_STR) are fragmented, see key_index */
	unsigned char	str[FVAR_SHORT_STR_MAX];	/* short string, FVAR_TYPE_SHORT_STR */
	uint16_t	len;	/* string length in bytes */
    } __attribute__ ((packed));
} FVAR_VAL_t;

/* Key-value pair */
typedef struct {
        union {
            int64_t             key;
            struct fvar_key_    kvar_key;
        };
        union fvar_val_         value;
} __attribute__ ((packed)) FVAR_KVPAIR_t;

/* Short string (FVAR_TYPE_SHORT_STR) validator patterns */
#define FKEY_SH_STR_EXTRA	"_*.-=:"	/* string consists of [0-9a-zA-Z] and these chars */
#define FKEY_SH_STR_EXLUDE	"*.-=:0"	/* string may not start with these chars */

/* Persistent pool device flags: failed, disabled.
 * fvar_key: (F_KEY_PDEV_UUID, FVAR_TYPE_UUID, key_hash)
 * key_hash: flag bits
 * These bits are exact as pool_dev_flags defined in f_pool.h
 */
#define FKEY_PDEV_FAILED	(1<<0)	/* device failed. */
#define FKEY_PDEV_DISABLED	(1<<1)	/* device disabled (for example, being replaced). */
#define FKEY_PDEV_MASK		0x3	/* key_hash: device flags mask */

/* The Dictionary structure
 * for Pool, Layout and AGroup variables stored in Key:=Value form.
 */
typedef struct f_dict_ {
    uint32_t __attribute__ ((aligned(8))) \
			psize;		/* 1.. - size of the structure, in 4K pages */
    uint32_t		count;		/* key-value pair count */
    uint32_t		kv_size;	/* key-value pair array size */
    uint32_t		revision;	/* Reserved, must be zero */
    long long		_reserved;
    FVAR_KVPAIR_t	pdict_ref;	/* reference to parent's dictionary: F_KEY_UUID or NULL */
    FVAR_KVPAIR_t	dict_ref;	/* this Dictionary (object:=uuid) */
    FVAR_KVPAIR_t	kv_pairs[];	/* array of key-value pairs */
} F_DICT_t;
/* dictionary actual size */
#define F_DICT_SZ(d)	(offsetof(struct f_dict_, kv_pairs) + d->kv_size*sizeof(FVAR_KVPAIR_t))
/* available dictionary KV count, as a function of stucture size in 4K pages */
#define F_DICT_MAX(p)	(4096*(p)/sizeof(FVAR_KVPAIR_t) - sizeof(F_DICT_t))


void f_dict_free(F_DICT_t *d);

/* Validate structure's size and/or alignment */
    _Static_assert( sizeof(F_DICT_t) == 24*3,		"F_DICT_t");
    _Static_assert( TYPE_ALINGMENT(F_DICT_t) == 8,	"F_DICT_t alignment");

#endif /* F_DICT_H_ */

