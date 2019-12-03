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

static int create_persistent_map(F_MAP_INFO_t *mapinfo, int intl, char *db_name)
{
	if (!meta_iface || !meta_iface->create_map_fn)
		return -1;

	mapinfo->ro = 0U; /* create_map_fn() could set map read-only flag */
	return meta_iface->create_map_fn(mapinfo, intl, db_name);
}

int f_create_persistent_sm(int layout_id, int intl, F_MAP_INFO_t *mapinfo)
{
	char name[6];
	unsigned int map_id = LO_TO_SM_ID(layout_id);

	snprintf(name, sizeof(name), "sm_%1u", map_id);
	mapinfo->map_id = map_id;
	return create_persistent_map(mapinfo, intl, name);
}

int f_create_persistent_cv(int layout_id, int intl, F_MAP_INFO_t *mapinfo)
{
	char name[6];
	unsigned int map_id = LO_TO_CV_ID(layout_id);

	snprintf(name, sizeof(name), "cv_%1u", map_id);
	mapinfo->map_id = map_id;
	return create_persistent_map(mapinfo, intl, name);
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

/*
    if (configurator_int_val(c->unifycr_layouts_count, &l))
	return -1;
    count = (int)l;
*/
    count = 0;
    for (; count < F_CFG_MSEC_MAX; count++) {
	if (configurator_int_val(c->layout_id[count][0], &l))
	    break;
    }
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

    /* Layouts */
    for (i = 0; i < count; i++) {
	layouts_info[i].conf_id = i;
	layouts_info[i].pool_info = pool_info;

	layouts_info[i].name = strdup(c->layout_name[i][0]);
	/* FIXME */
	layouts_info[i].devnum = pool_info->dev_count;
	if (f_layout_parse_name(&layouts_info[i])) return -1;
    }

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


