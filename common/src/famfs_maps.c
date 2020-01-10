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

static void free_pdev(F_POOL_DEV_t *pdev)
{
    pthread_rwlock_destroy(&pdev->rwlock);
    free(pdev->dev->f.url);
    free(pdev->dev);
}

static void free_pool(F_POOL_t *p)
{
    if (p) {
	F_POOL_DEV_t *pdev;
	unsigned int i;

	pdev = p->devlist;
	if (pdev) {
	    for (i = 0; i < p->pool_devs; i++, pdev++)
		free_pdev(pdev);
	    free(p->devlist);
	}

	if (p->ags) {
	    for (i = 0; i < p->pool_ags; i++)
		free(p->ags[i].gpdi);
	    free(p->ags);
	}

	f_dict_free(p->dict);
	pthread_spin_destroy(&p->dict_lock);
	pthread_rwlock_destroy(&p->lock);
	free(p);
    }
}

static int cfg_load_pool(unifycr_cfg_t *c)
{
    F_POOL_t *p;
    F_POOL_INFO_t *pool_info;
    F_AG_t *ag;
    int rc, count;
    unsigned int u;
    long l;
    bool b;

    p = (F_POOL_t *) calloc(sizeof(F_POOL_t), 1);
    if (!p)
	return -ENOMEM;

    if (pthread_rwlock_init(&p->lock, NULL)) {
	free(p);
	return -ENOMEM;
    }
    if (pthread_spin_init(&p->dict_lock, PTHREAD_PROCESS_PRIVATE)) {
	free(p);
	return -ENOMEM;
    }
    INIT_LIST_HEAD(&p->layouts);
    pool_info = &p->info;

    /* Pool */
    if (f_parse_uuid(c->devices_uuid, &p->uuid)) {
	assert( f_parse_uuid(FAMFS_PDEVS_UUID_DEF, &p->uuid) == 0);
    }
    if (configurator_int_val(c->devices_extent_size, &l)) goto _noarg;
    pool_info->extent_sz = (unsigned long)l;
    if (configurator_int_val(c->devices_offset, &l)) goto _noarg;
    pool_info->extent_start = (unsigned long)l;
    if (configurator_bool_val(c->devices_emulated, &b)) goto _noarg;
    if (b)
	SetPoolFAMEmul(p);
    if (configurator_int_val(c->devices_size, &l)) goto _noarg;
    pool_info->size_def = (size_t)l;
    if (configurator_int_val(c->devices_pk, &l)) goto _noarg;
    pool_info->pkey_def = (uint64_t)l;

    /* Devices */
    count = configurator_get_sec_size(c, "device");
    if (!IN_RANGE(count, 1, F_DEVICES_MAX)) goto _noarg;
    p->pool_devs = (unsigned int)count;
    pool_info->dev_count = p->pool_devs;

    /* Allocation groups */
    count = configurator_get_sec_size(c, "ag");
    p->ags = (F_AG_t *) calloc(sizeof(F_AG_t), count);
    if (!p->ags) goto _nomem;
    if (!IN_RANGE(count, 1, F_DEVICES_MAX)) goto _noarg;
    p->pool_ags = (uint32_t)count;
    ag = p->ags;
    for (u = 0; u < p->pool_ags; u++, ag++) {
	unsigned int uu;

	if (configurator_int_val(c->ag_id[u][0], &l)) goto _noarg;
	ag->gid = (uint32_t)l;
	//f_parse_uuid(c->ag_uuid[u][0], &ag->uuid);
	ag->geo = c->ag_geo[u][0];
	/* List of devices in the group */
	count = u;
	if (configurator_get_sizes(c, "ag", "devices", &count) < 0)
	    goto _noarg;
	if (!IN_RANGE((unsigned)count, 1, pool_info->dev_count))
	    goto _noarg;
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
    p->devlist = (F_POOL_DEV_t*)calloc(sizeof(F_POOL_DEV_t), p->pool_devs);
    if (!p->devlist) goto _nomem;
    for (u = 0; u < p->pool_devs; u++) {
	FAM_DEV_t *fam;
	F_POOL_DEV_t *pdev = &p->devlist[u];

	pdev->pool_index = u;
	if (configurator_int_val(c->device_id[u][0], &l)) goto _noarg;
	pdev->conf_id = (uint32_t)l;
	f_parse_uuid(c->device_uuid[u][0], &pdev->uuid);
	if (configurator_int_val(c->device_size[u][0], &l))
	    pdev->size = p->info.size_def;
	else
	    pdev->size = (size_t)l;
	/* TODO: Parse extent_sz, extent_start */
	pdev->extent_start = p->info.extent_start;
	pdev->extent_sz = p->info.extent_sz;
	pdev->extent_count = pdev->size/p->info.extent_sz;
	if (configurator_bool_val(c->device_failed[u][0], &b)) goto _noarg;
	if (b)
	    SetDevFailed(&pdev->sha);
	pdev->dev = (F_DEV_t *) calloc(sizeof(F_DEV_t), 1);
	if (!pdev->dev) goto _nomem;
	fam = &pdev->dev->f;
	if (c->device_url[u][0])
	    fam->url = strdup(c->device_url[u][0]);
	if (configurator_int_val(c->device_pk[u][0], &l))
	    fam->pkey = pool_info->pkey_def;
	else
	    fam->pkey = (uint64_t)l;

	if (pthread_rwlock_init(&pdev->rwlock, NULL)) goto _nomem;
	pdev->pool = p;

	/* TODO: probe devices, sha.extent_bmap */
    }

    /* Layout count */
    count = configurator_get_sec_size(c, "layout");
    if (!IN_RANGE(count, 1, F_LAYOUTS_MAX)) goto _noarg;
    pool_info->layouts_count = count;

    pool = p;
    return 0;

_nomem:
    rc = -ENOMEM;
    goto _err;
_noarg:
    rc = -1; /* no mandatory parameter specified */
_err:
    free_pool(p);
    return rc;
}

static void free_layout(F_LAYOUT_t *lo)
{
    if (lo->lp) {
	pthread_spin_destroy(&lo->lp->alloc_lock);
	pthread_rwlock_destroy(&lo->lp->claimdec_lock);
	free(lo->lp);
    }
    free(lo->info.name);
    free(lo->devlist);
    f_dict_free(lo->dict);
    pthread_spin_destroy(&lo->dict_lock);
    pthread_rwlock_destroy(&lo->lock);
    free(lo);
}

/* Create layout structure from configurator at index */
static int cfg_load_layout(unifycr_cfg_t *c, int idx)
{
    F_LAYOUT_t *lo;
    F_LAYOUT_INFO_t *info;
    F_LO_PART_t *lp;
    F_POOLDEV_INDEX_t *pdi;
    unsigned int u, uu, conf_id;
    uint16_t pool_index;
    int rc, count;
    long l;
    bool all_pdevs;

    assert( pool && IN_RANGE(idx, 0, (int)pool->info.layouts_count-1) );
    lo = (F_LAYOUT_t *) calloc(sizeof(F_LAYOUT_t), 1);
    if (!lo) return -ENOMEM;
    if (pthread_rwlock_init(&lo->lock, NULL)) goto _nomem;
    if (pthread_spin_init(&lo->dict_lock, PTHREAD_PROCESS_PRIVATE)) goto _nomem;
    INIT_LIST_HEAD(&lo->list);
    /* Parse this layout's configurator ID and name */
    info = &lo->info;
    if (configurator_int_val(c->layout_id[idx][0], &l)) goto _noarg;
    info->conf_id = (unsigned int)l;
    /* Devices */
    count = idx; /* layout section index */
    all_pdevs = (configurator_get_sizes(c, "layout", "devices", &count) < 0);
    if (all_pdevs) {
	/* no layout devices list given - default to pool devices */
	count = pool->info.dev_count;
    } else {
	if (!IN_RANGE((unsigned)count, 1, pool->info.dev_count))
	    goto _noarg;
    }
    lo->devlist_sz = info->devnum = (unsigned)count;
    info->name = strdup(c->layout_name[idx][0]);
    if (f_layout_parse_name(info)) goto _noarg;
    lo->devlist = (F_POOLDEV_INDEX_t *) calloc(sizeof(F_POOLDEV_INDEX_t),
	lo->devlist_sz);
    if (!lo->devlist) goto _nomem;
    pdi = lo->devlist;
    for (u = 0; u < info->devnum; u++, pdi++) {
	if (configurator_int_val(c->layout_devices[idx][u], &l)) goto _noarg;
	conf_id = (unsigned int)l;
	if (all_pdevs) {
	    pool_index = u;
	} else {
	    /* find pool device index */
	    pool_index = F_PDI_NONE;
	    for (uu = 0; uu < pool->pool_devs; uu++)
		if (pool->devlist[uu].conf_id == conf_id)
		    break;
	    if (uu <= pool->pool_devs)
		pool_index = uu;
	}
	/* copy pdi */
	if (pool_index != F_PDI_NONE)
	    ;
    }

    /* Layout partition */
    lp = (F_LO_PART_t *) calloc(sizeof(F_LO_PART_t), 1);
    if (!lp) goto _nomem;
    if (pthread_rwlock_init(&lp->claimdec_lock, NULL)) goto _nomem;
    if (pthread_spin_init(&lp->alloc_lock, PTHREAD_PROCESS_PRIVATE)) goto _nomem;
    INIT_LIST_HEAD(&lp->alloc_buckets);
    INIT_LIST_HEAD(&lp->claimdecq);
    lo->lp = lp;

    lo->pool = pool;
    /* Add to layouts list */
    list_add(&lo->list, &pool->layouts);
    return 0;

_nomem:
    rc = -ENOMEM;
    goto _err;
_noarg:
    rc = -1; /* no mandatory parameter specified */
_err:
    free_layout(lo);
    return rc;
}

static int cfg_load(unifycr_cfg_t *c)
{
    int rc;
    unsigned int i;

    if ((rc = cfg_load_pool(c)))
	return rc;

    for (i = 0; i < pool->info.layouts_count; i++)
	if ((rc = cfg_load_layout(c, i)))
	    return rc;

    return 0;
}

/* Set layout info from configurator once */
int f_set_layouts_info(unifycr_cfg_t *cfg)
{
printf("pool=%p\n", pool);
    if (cfg && pool == NULL)
	return cfg_load(cfg);
    return -1;
}

/* Get layout 'layout_id' info */
F_LAYOUT_t *f_get_layout(int layout_id) {
    struct list_head *l;
    F_LAYOUT_t *lo;

    if (pool && pool) {
	list_for_each(l, &pool->layouts) {
	    lo = container_of(l, struct f_layout_, list);
	    if ((int)lo->info.conf_id == layout_id)
		return lo;
	}
    }
    return NULL;
}

/* Get layout 'layout_id' info */
F_LAYOUT_INFO_t *f_get_layout_info(int layout_id) {
    F_LAYOUT_t *lo = f_get_layout(layout_id);

    return lo?&lo->info:NULL;
}

F_LAYOUT_t *f_get_layout_by_name(const char *moniker) {
    struct list_head *l;
    F_LAYOUT_t *lo;

    if (pool && moniker) {
	list_for_each(l, &pool->layouts) {
	    lo = container_of(l, struct f_layout_, list);
	    if (!strcmp(lo->info.name, moniker))
		return lo;
	}
    }
    return NULL;
}

void f_free_layouts_info(void)
{
    F_LAYOUT_t *lo;
    struct list_head *l, *tmp;

    if (pool) {
	list_for_each_prev_safe(l, tmp, &pool->layouts) {
	    lo = container_of(l, struct f_layout_, list);
	    list_del(l);
	    free_layout(lo);
	}
	free_pool(pool);
	pool = NULL;
    }
}


