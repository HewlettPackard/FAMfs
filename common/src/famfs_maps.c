/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#include "famfs_maps.h"


static F_META_IFACE_t *meta_iface = NULL;
F_LAYOUT_INFO_t *layouts_info = NULL;


/* Layout name (moniker) parser */
int f_layout_parse_name(struct f_layout_info_ *info)
{
	size_t chunk_size;
	int data, parity, mirrors;
	int ret = -1;

	if (info->name)
		ret = f_parse_moniker(info->name,
				&data, &parity, &mirrors, &chunk_size);
	if (ret == 0 && mirrors == 0) {
		info->data_chunks = data;
		info->chunks = data + parity;
		info->chunk_sz = chunk_size;
		info->slab_stripes = info->pool_info->extent_sz / chunk_size;
	}
	return ret;
}

void f_set_meta_iface(F_META_IFACE_t *iface)
{
	if (meta_iface == NULL)
		meta_iface = iface;
}

static int create_persistent_map(int map_id, int intl, char *db_name, int *mapid_p)
{
	int rc;

	if (!meta_iface || !meta_iface->create_map_fn)
		return -1;

	rc = meta_iface->create_map_fn(map_id, intl, db_name);
	if (rc == 0 && mapid_p)
		*mapid_p = map_id;
	return rc;
}

int f_create_persistent_sm(int layout_id, int intl, int *mapid_p)
{
	char name[5];
	int map_id = LO_TO_SM_ID(layout_id);

	snprintf(name, sizeof(name), "sm_%1.1d\n", map_id);
	return create_persistent_map(map_id, intl, name, mapid_p);
}

int f_create_persistent_cv(int layout_id, int intl, int *mapid_p)
{
	char name[5];
	int map_id = LO_TO_CV_ID(layout_id);

	snprintf(name, sizeof(name), "cv_%1.1d\n", map_id);
	return create_persistent_map(map_id, intl, name, mapid_p);
}

ssize_t f_db_bget(unsigned long *buf, int map_id, uint64_t *keys, size_t size,
    uint64_t *off_p)
{
	ssize_t ret;

	keys[0] = *off_p;
	ret = meta_iface->bget_fn(buf, map_id, size, keys);
	if (ret > 0)
		*off_p = keys[ret-1] + 1U;
	return ret;
}

int f_db_bput(unsigned long *buf, int map_id, void **keys, size_t size,
    size_t value_len)
{
	return meta_iface->bput_fn(buf, map_id, size, keys, value_len);
}

int f_db_bdel(int map_id, void **keys, size_t size)
{
	return meta_iface->bdel_fn(map_id, size, keys);
}

static int set_layouts_cfg(unifycr_cfg_t *c)
{
    F_POOL_INFO_t *pool_info;
    int i, count;
    long l;

    if (configurator_int_val(c->unifycr_layouts_count, &l))
	return -1;
    count = (int)l;
    if (count > F_LAYOUTS_MAX)
	count = F_LAYOUTS_MAX;

    layouts_info = (F_LAYOUT_INFO_t *) calloc(sizeof(F_LAYOUT_INFO_t), count);
    if (!layouts_info)
	return -ENOMEM;
    pool_info = (F_POOL_INFO_t *) calloc(sizeof(F_POOL_INFO_t), 1);
    pool_info->layouts_count = count;
    if (configurator_int_val(c->unifycr_ioncount, &l)) return -1;
    pool_info->dev_count = (unsigned int)l;
    if (configurator_int_val(c->unifycr_extent_size, &l)) return -1;
    pool_info->extent_sz = (unsigned long)l;
    if (configurator_int_val(c->unifycr_extent0_offset, &l)) return -1;
    pool_info->extent0_start = (unsigned long)l;

#define _get_layout_devnum(id, def)					\
    ({ unsigned int r;							\
    if (c->layout##id##_devnum == NULL) {				\
	r = def;							\
    } else {								\
	if (configurator_int_val(c->layout##id##_devnum, &l)) return -1;\
	r = (unsigned int)l;						\
    };									\
    r; })
#define _get_layout_name(id)	strdup(c->layout##id##_name)
    /* Layouts */
    for (i = 0; i < count; i++) {
	layouts_info[i].conf_id = i;
	layouts_info[i].pool_info = pool_info;
	switch (i) {
	case 0:
	    layouts_info[i].name = _get_layout_name(0);
	    layouts_info[i].devnum = _get_layout_devnum(0, pool_info->dev_count);
	    break;
	case 1:
	    layouts_info[i].name = _get_layout_name(1);
	    layouts_info[i].devnum = _get_layout_devnum(1, pool_info->dev_count);
	    break;
	default:;
	}
	if (f_layout_parse_name(&layouts_info[i])) return -1;
    }
#undef _get_layout_devnum
#undef _get_layout_name

    return 0;
}

/* Set layout info from configurator once */
int f_set_layout_info(unifycr_cfg_t *cfg)
{
    if (cfg && !layouts_info)
	return set_layouts_cfg(cfg);
    return -1;
}

/* Get layout 'layout_id' info */
F_LAYOUT_INFO_t *f_get_layout_info(int layout_id) {
    if (layouts_info) {
	int count = layouts_info->pool_info->layouts_count;

	if (IN_RANGE(layout_id, 0, count-1))
	    return (void*)&layouts_info[layout_id];
    }
    return NULL;
}

void f_free_layout_info(void)
{
    F_LAYOUT_INFO_t *info = layouts_info;

    if (info) {
	unsigned int i;
	F_POOL_INFO_t *pool_info = info->pool_info;

	for (i = 0; i < pool_info->layouts_count; i++, info++)
	    free(info->name);
	free(pool_info);
	free(layouts_info);
	layouts_info = NULL;
    }
}


