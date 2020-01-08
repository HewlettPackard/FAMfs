/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#include "f_pool.h"
#include "f_layout.h"
#include "famfs_maps.h"
#include "famfs_lf_connect.h"
#include "famfs_configurator.h"


F_POOL_t *pool = NULL;
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
		info->slab_stripes = pool->info.extent_sz / chunk_size;

		if (!IN_RANGE(info->chunks, 1, info->devnum))
			ret = -1;
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
    int count;
    unsigned int u;
    long l;
    bool b;

    pool = (F_POOL_t *) calloc(sizeof(F_POOL_t), 1);
    if (!pool)
	return -ENOMEM;

    if (pthread_rwlock_init(&pool->lock, NULL)) {
	free(pool);
	return -ENOMEM;
    }
    if (pthread_spin_init(&pool->dict_lock, PTHREAD_PROCESS_PRIVATE)) {
	free(pool);
	return -ENOMEM;
    }
    pool_info = &pool->info;

    /* Pool */
    if (f_parse_uuid(c->devices_uuid, &pool->uuid)) {
	assert( f_parse_uuid(FAMFS_PDEVS_UUID_DEF, &pool->uuid) == 0);
    }
    if (configurator_int_val(c->devices_extent_size, &l)) return -1;
    pool_info->extent_sz = (unsigned long)l;
    if (configurator_int_val(c->devices_offset, &l)) return -1;
    pool_info->extent_start = (unsigned long)l;
    if (configurator_bool_val(c->devices_emulated, &b)) return -1;
    if (b)
	SetPoolFAMEmul(pool);
    if (configurator_int_val(c->devices_size, &l)) return -1;
    pool_info->size_def = (size_t)l;
    if (configurator_int_val(c->devices_pk, &l)) return -1;
    pool_info->pkey_def = (uint64_t)l;

    /* Devices */
    count = configurator_get_sec_size(c, "device");
    if (!IN_RANGE(count, 1, F_DEVICES_MAX)) return -1;
    pool->pool_devs = (unsigned int)count;
    pool_info->dev_count = pool->pool_devs;

    /* Allocation groups */
    count = configurator_get_sec_size(c, "ag");
    pool->ags = (F_AG_t *) calloc(sizeof(F_AG_t), count);
    if (!pool->ags) return -ENOMEM;
    if (!IN_RANGE(count, 1, F_DEVICES_MAX)) return -1;
    pool->pool_ags = (uint32_t)count;
    for (u = 0; u < pool->pool_ags; u++) {
	F_AG_t *ag = &pool->ags[u];
	unsigned int uu;

	if (configurator_int_val(c->ag_id[u][0], &l)) return -1;
	ag->gid = (uint32_t)l;
	//f_parse_uuid(c->ag_uuid[u][0], &ag->uuid);
	ag->geo = c->ag_geo[u][0];
	/* List of devices in the group */
	count = u;
	if (configurator_get_sizes(c, "ag", "devices", &count) < 0)
	    return -1;
	if (!IN_RANGE((unsigned)count, 1, pool_info->dev_count))
	    return -1;
	ag->pdis = (uint32_t)count;
	ag->gpdi = (uint16_t *) calloc(sizeof(uint16_t), ag->pdis);
	for (uu = 0; uu < ag->pdis; uu++) {
	    if (configurator_int_val(c->ag_devices[u][uu], &l))
		ag->gpdi[uu] = F_PDI_NONE;
	    else
		ag->gpdi[uu] = (uint16_t)l;
	}
    }

    /* Devices */
    pool->devlist = (F_POOL_DEV_t*)calloc(sizeof(F_POOL_DEV_t), pool->pool_devs);
    if (!pool->devlist) return -ENOMEM;
    for (u = 0; u < pool->pool_devs; u++) {
	FAM_DEV_t *fam;
	F_POOL_DEV_t *pdev = &pool->devlist[u];

	pdev->pool_index = u;
	if (configurator_int_val(c->device_id[u][0], &l)) return -1;
	pdev->conf_id = (uint32_t)l;
	f_parse_uuid(c->device_uuid[u][0], &pdev->uuid);
	if (configurator_int_val(c->device_size[u][0], &l))
	    pdev->size = pool->info.size_def;
	else
	    pdev->size = (size_t)l;
	/* TODO: Parse extent_sz, extent_start */
	pdev->extent_start = pool->info.extent_start;
	pdev->extent_sz = pool->info.extent_sz;
	pdev->extent_count = pdev->size/pool->info.extent_sz;
	if (configurator_bool_val(c->device_failed[u][0], &b)) return -1;
	if (b)
	    SetDevFailed(&pdev->sha);
	pdev->dev = (F_DEV_t *) calloc(sizeof(F_DEV_t), 1);
	if (!pdev->dev) return -ENOMEM;
	fam = &pdev->dev->f;
	if (c->device_url[u][0])
	    fam->url = strdup(c->device_url[u][0]);
	if (configurator_int_val(c->device_pk[u][0], &l))
	    fam->pkey = pool_info->pkey_def;
	else
	    fam->pkey = (uint64_t)l;

	if (pthread_rwlock_init(&pdev->rwlock, NULL)) return -ENOMEM;
	pdev->pool = pool;

	/* TODO: probe, sha.extent_bmap */
    }

    /* Layouts */
    count = configurator_get_sec_size(c, "layout");
    if (!IN_RANGE(count, 1, F_LAYOUTS_MAX)) return -1;
    layouts_info = (F_LAYOUT_INFO_t *) calloc(sizeof(F_LAYOUT_INFO_t), count);
    if (!layouts_info) return -ENOMEM;
    pool_info->layouts_count = count;
    for (u = 0; u < pool_info->layouts_count; u++) {
	if (configurator_int_val(c->layout_id[u][0], &l)) return -1;
	layouts_info[u].conf_id = (unsigned int)l;
 //	layouts_info[u].pool = pool;
	layouts_info[u].name = strdup(c->layout_name[u][0]);

	count = u;
	if (configurator_get_sizes(c, "layout", "devices", &count) < 0)
	    return -1;
	if (!IN_RANGE((unsigned)count, 1, pool_info->dev_count))
	    return -1;
	layouts_info[u].devnum = (unsigned)count;

	if (f_layout_parse_name(&layouts_info[u]))
	    return -1;
    }
    return 0;
}

/* Set layout info from configurator once */
int f_set_layout_info(unifycr_cfg_t *cfg)
{
    if (cfg && pool == NULL)
	return set_layouts_cfg(cfg);
    return -1;
}

/* Get layout 'layout_id' info */
F_LAYOUT_INFO_t *f_get_layout_info(int layout_id) {
    if (layouts_info) {
	int count = pool->info.layouts_count;

	if (IN_RANGE(layout_id, 0, count-1))
	    return (void*)&layouts_info[layout_id];
    }
    return NULL;
}

static void free_pdev(F_POOL_DEV_t *pdev)
{
    pthread_rwlock_destroy(&pdev->rwlock);
    free(pdev->dev->f.url);
    free(pdev->dev);
}

void f_free_layout_info(void)
{
    F_LAYOUT_INFO_t *info;
    F_POOL_INFO_t *pool_info;
    F_POOL_DEV_t *pdev;

    if (pool) {
	unsigned int i;

	pdev = pool->devlist;
	for (i = 0; i < pool->pool_devs; i++, pdev++)
	    free_pdev(pdev);
	free(pool->devlist);

	for (i = 0; i < pool->pool_ags; i++)
	    free(pool->ags[i].gpdi);
	free(pool->ags);

	pool_info = &pool->info;
	info = layouts_info;
	for (i = 0; i < pool_info->layouts_count; i++, info++)
	    free(info->name);
	free(layouts_info);
	layouts_info = NULL;

	f_dict_free(pool->dict);
	pthread_spin_destroy(&pool->dict_lock);
	pthread_rwlock_destroy(&pool->lock);
	free(pool);
	pool = NULL;
    }
}


