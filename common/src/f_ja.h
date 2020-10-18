/*
 * Copyright (c) 2020, HPE
 *
 * Written by: Dmitry Ivanov
 */

#ifndef F_JA_H_
#define F_JA_H_

#include <sys/types.h>
#include <inttypes.h>

#include "list.h"

#include <urcu-qsbr.h>
//#include <urcu-call-rcu.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter" /* Matt.7.1 */
#include <urcu/rcuja.h>
#pragma GCC diagnostic pop
#define F_JA_MAX_KEY64	(UINT64_MAX-1)


/* Judy sparse array */
typedef struct cds_ja F_JUDY_t;
#define f_new_ja(key_size)	(cds_ja_new(key_size))	/* Usually 64-bit key */

/* Judy node */
typedef struct f_ja_node_ {
    struct cds_ja_node		node;
    struct rcu_head		head;		/* RCU delayed reclaim */
    uint64_t			entry;
} F_JA_NODE_t;

int f_ja_add(F_JUDY_t *ja, uint64_t entry); /* if no entry, create it */
int f_ja_rem(F_JUDY_t *ja, uint64_t entry); /* remove entry */
int f_ja_destroy(F_JUDY_t *ja); /* remove all entries */
uint64_t f_ja_max(F_JUDY_t *ja); /* max entry */
F_JA_NODE_t *f_ja_get(F_JUDY_t *ja, uint64_t entry); /* returns NULL if no entry */
int f_ja_remove(F_JUDY_t *ja, F_JA_NODE_t *n);
F_JA_NODE_t *f_ja_next(F_JUDY_t *ja, uint64_t entry); /* iterator (node->entry) */

#define ja_for_each_entry(ja, n, e) \
        /*for (e = 0; n = f_ja_next(ja, e), n && (e = n->entry); e++) */\
        for (e = 0; (n = f_ja_next(ja, e)) && (e = n->entry), (n); e++)

#endif /* F_JA_H_ */
