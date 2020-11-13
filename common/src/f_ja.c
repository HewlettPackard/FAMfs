/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Dmitry Ivanov
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "f_ja.h"
#include "f_error.h"
#include "f_ktypes.h"
#include "list.h"

static void node_free_cb(struct rcu_head *head)
{
	F_JA_NODE_t *n = container_of(head, struct f_ja_node_, head);

	free(n);
}

void f_ja_node_free(F_JA_NODE_t *n) {
	call_rcu(&n->head, node_free_cb);
}

/* RCU read-side lock should _not_ be held when calling this function,
 * however, QSBR threads need to be online.
 */
int f_ja_destroy(F_JUDY_t *ja)
{
	uint64_t key;
	struct cds_ja_node *node;
	int ret = 0;

	rcu_read_lock();
	cds_ja_for_each_key_rcu(ja, key, node) {
		F_JA_NODE_t *n;

		ret = cds_ja_del(ja, key, node);
		if (ret)
			goto _err;

		/* Alone using the array */
		n = container_of(node, F_JA_NODE_t, node);
		call_rcu(&n->head, node_free_cb);
	}
_err:
	rcu_read_unlock();

	if ((ret = cds_ja_destroy(ja)))
		return ret;
	rcu_quiescent_state();

	return ret;
}

F_JA_NODE_t *f_ja_get(F_JUDY_t *ja, uint64_t entry)
{
	struct cds_ja_node *node;

	rcu_read_lock();
	node = cds_ja_lookup(ja, entry);
	if (node) {
		F_JA_NODE_t *n = container_of(node, F_JA_NODE_t, node);
		rcu_read_unlock();

		return n;
	}
	rcu_read_unlock();

	return NULL;
}

int f_ja_add(F_JUDY_t *ja, uint64_t entry)
{
	F_JA_NODE_t *n;
	struct cds_ja_node *node;

	rcu_read_lock();
	node = cds_ja_lookup(ja, entry);
	if (node) {
		rcu_read_unlock();
		return -EEXIST;
	}
	rcu_read_unlock();

	n = (F_JA_NODE_t *) calloc(1, sizeof(F_JA_NODE_t));
	if (!n)
		return -ENOMEM;
	n->entry = entry;

	rcu_read_lock();
	node = cds_ja_add_unique(ja, entry, &n->node);
	if (unlikely(node != &n->node)) {
		call_rcu(&n->head, node_free_cb);
		rcu_read_unlock();

		return -EEXIST;
	}
	rcu_read_unlock();

	//rcu_quiescent_state();
	return 0;

}

int f_ja_remove(F_JUDY_t *ja, F_JA_NODE_t *n)
{
	int ret;

	rcu_read_lock();
	ret = cds_ja_del(ja, n->entry, &n->node);
	if (ret) {
		rcu_read_unlock();
		return ret;
	}
	call_rcu(&n->head, node_free_cb);
	rcu_read_unlock();

	//rcu_quiescent_state();
	return ret;
}

int f_ja_rem(F_JUDY_t *ja, uint64_t entry)
{
	F_JA_NODE_t *n;
	struct cds_ja_node *node;
	int ret;

	rcu_read_lock();
	node = cds_ja_lookup(ja, entry);
	if (!node) {
		rcu_read_unlock();
		return 0;
	}
	n = container_of(node, F_JA_NODE_t, node);

	ret = cds_ja_del(ja, n->entry, &n->node);
	if (ret) {
		rcu_read_unlock();
		return ret;
	}
	call_rcu(&n->head, node_free_cb);
	rcu_read_unlock();

	rcu_quiescent_state();
	return 0;
}

uint64_t f_ja_max(F_JUDY_t *ja)
{
	uint64_t idx = 0;
	struct cds_ja_node *node;

	rcu_read_lock();
	node = cds_ja_lookup_below_equal(ja, F_JA_MAX_KEY64, &idx);
	if (node)
		idx++;
	rcu_read_unlock();
	return idx;
}

F_JA_NODE_t *f_ja_next(F_JUDY_t *ja, uint64_t entry)
{
	F_JA_NODE_t *n;
	struct cds_ja_node *node;

	rcu_read_lock();
	node = cds_ja_lookup_above_equal(ja, entry, NULL);
	if (node == NULL) {
		rcu_read_unlock();
		return NULL;
	}
	n = container_of(node, F_JA_NODE_t, node);
	rcu_read_unlock();

	return n;
}

