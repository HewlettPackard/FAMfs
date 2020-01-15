/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#include <uuid/uuid.h>

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

static F_IONODE_INFO_t *get_ionode_info(F_POOL_t *p, const char *hostname)
{
    F_IONODE_INFO_t *info;
    unsigned int count, u;
    int idx;
    char **nodelist;

    if (p == NULL)
	return NULL;

    /* List of IO nodes */
    count = p->ionode_count;
    nodelist = (char**) calloc(sizeof(char*), count);
    info = p->ionodes;
    for (u = 0; u < count; u++, info++)
	nodelist[u] = info->hostname;

    /* Find foreign hostname if given, otherwise local hostname or IP */
    if (hostname)
	idx = f_find_node(nodelist, (int)count, hostname);
    else
	idx = find_my_node(nodelist, (int)count, NULL);
    free(nodelist);

    if (idx < 0)
	return NULL;
    return &p->ionodes[idx];
}

/* Set ionode_id and HasMDS, IsIOnode flags in pool struct */
static void set_my_ionode_info(F_POOL_t *p)
{
    F_IONODE_INFO_t *info;

    assert (p && p->ionodes);
    info = get_ionode_info(p, NULL);
    if (info) {
	SetPoolIsIOnode(p);
	if (info->mds)
	    SetPoolHasMDS(p);
	else
	    ClearPoolHasMDS(p);
	p->ionode_id = (uint32_t)(info - p->ionodes);
    } else {
	ClearPoolIsIOnode(p);
	ClearPoolHasMDS(p);
    }
}

static int find_pd_index_in_ag(F_AG_t *ags, uint32_t pool_ags,
    uint32_t ag_devs, uint16_t index, F_POOL_DEV_t *devlist)
{
    F_AG_t *ag = ags;
    F_POOL_DEV_t (*ag_devlist)[ag_devs] = (F_POOL_DEV_t(*)[ag_devs])devlist;
    unsigned int u;

    for (u = 0; u < pool_ags; u++, ag++) {
	uint16_t *gpdi = ag->gpdi;
	unsigned int uu;

	assert( ag->pdis <= ag_devs );
	/* TODO: Check for duplicates in AG */
	for (uu = 0; uu < ag->pdis; uu++, gpdi++)
	    if (*gpdi == index)
		return (int)(&ag_devlist[u][uu] - devlist);
    }
    return -1;
}

struct f_pool_dev_ *f_find_pdev(unsigned int index) {
    struct f_pool_ *p = pool;
    F_AG_t *ag;
    unsigned int u;

    if (p == NULL)
	return NULL;

    ag = p->ags;
    for (u = 0; u < p->pool_ags; u++, ag++) {
	F_POOL_DEV_t *pdev = ((F_POOL_DEV_t (*)[p->ag_devs]) p->devlist)[u];
	unsigned int uu;

	for (uu = 0; uu < ag->pdis; uu++, pdev++)
	    if (pdev->pool_index == index)
		return pdev;
    }
    return NULL;
}

static int cmp_pdev_by_index(const void *a, const void *b)
{
    uint16_t ia = ((F_POOL_DEV_t *)a)->pool_index;
    uint16_t ib = ((F_POOL_DEV_t *)b)->pool_index;

    return ((int)ia - (int)ib); /* ascending order */
}

/* Sort layout devices in ascending order: AG first, then pool index */
static int cmp_pdi(const void *a, const void *b)
{
    F_POOLDEV_INDEX_t *pdia = (F_POOLDEV_INDEX_t *)a;
    F_POOLDEV_INDEX_t *pdib = (F_POOLDEV_INDEX_t *)b;
    unsigned int ia = pdia->idx_ag * (F_PDI_NONE+1) + pdia->idx_dev;
    unsigned int ib = pdib->idx_ag * (F_PDI_NONE+1) + pdib->idx_dev;
    if (ia > ib)
	return 1;
    else if (ia == ib)
	return 0;
    return -1;
}

static void free_pdev(F_POOL_DEV_t *pdev)
{
    if (pdev->dev) {
	pthread_rwlock_destroy(&pdev->rwlock);
	free(pdev->dev->f.url);
	free(pdev->dev);
    }
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
	    for (i = 0; i < p->pool_ags; i++) {
		free(p->ags[i].geo);
		free(p->ags[i].gpdi);
	    }
	    free(p->ags);
	}

	if (p->ionodes) {
	    for (i = 0; i < p->ionode_count; i++)
		free(p->ionodes[i].hostname);
	    free(p->ionodes);
	}
	free(p->ionode_fams);

	f_dict_free(p->dict);
	pthread_spin_destroy(&p->dict_lock);
	pthread_rwlock_destroy(&p->lock);
	free(p->hostname);
	free(p);
    }
}

static int cfg_load_pool(unifycr_cfg_t *c)
{
    F_POOL_t *p;
    F_POOL_INFO_t *pool_info;
    F_AG_t *ag;
    F_POOL_DEV_t *pdev;
    int rc, count;
    unsigned int u, uu, ag_maxlen;
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
    if (f_uuid_parse(c->devices_uuid, p->uuid)) {
	assert( uuid_parse(FAMFS_PDEVS_UUID_DEF, p->uuid) == 0);
    }
    /* my node name */
    p->hostname = f_get_myhostname();
    if (!p->hostname) goto _nomem;
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

    /* IO nodes */
    count = configurator_get_sec_size(c, "ionode");
    if (!IN_RANGE(count, 1, F_IONODES_MAX)) goto _noarg;
    p->ionode_count = (uint32_t)count;
    p->ionode_fams = (FAM_MAP_t *) calloc(sizeof(FAM_MAP_t), 1);
    p->ionode_fams->ionode_cnt = p->ionode_count;
    if (!p->ionode_fams) goto _nomem;
    p->ionodes = (F_IONODE_INFO_t*) calloc(sizeof(F_IONODE_INFO_t),
					   p->ionode_count);
    if (!p->ionodes) goto _nomem;
    for (u = 0; u < p->ionode_count; u++) {
	F_IONODE_INFO_t *ion = &p->ionodes[u];

	if (configurator_int_val(c->ionode_id[u][0], &l)) goto _syntax;
	ion->conf_id = (uint32_t)l;
	f_uuid_parse(c->ionode_uuid[u][0], ion->uuid);
	if (configurator_int_val(c->ionode_mds[u][0], &l)) goto _syntax;
	ion->mds = (uint32_t)l;
	if (c->ionode_host[u][0])
	    ion->hostname = strdup(c->ionode_host[u][0]);
	else if (u == 0)
	    ion->hostname = strdup(p->hostname);
	else
	    goto _noarg;
    }
    set_my_ionode_info(p);

    /* Device count */
    count = configurator_get_sec_size(c, "device");
    if (!IN_RANGE(count, 1, F_DEVICES_MAX)) goto _noarg;
    pool_info->dev_count = (unsigned int)count;

    /* Allocation groups */
    count = configurator_get_sec_size(c, "ag");
    p->ags = (F_AG_t *) calloc(sizeof(F_AG_t), count);
    if (!p->ags) goto _nomem;
    if (!IN_RANGE(count, 1, F_DEVICES_MAX)) goto _noarg;
    p->pool_ags = (uint32_t)count;
    ag = p->ags;
    ag_maxlen = 0;
    for (u = 0; u < p->pool_ags; u++, ag++) {
	/* AG id */
	if (configurator_int_val(c->ag_id[u][0], &l)) goto _syntax;
	ag->gid = (uint32_t)l;
	f_uuid_parse(c->ag_uuid[u][0], ag->uuid);
	if (c->ag_geo[u][0])
	    ag->geo = strdup(c->ag_geo[u][0]);
	/* List of devices in the group */
	count = u;
	if (configurator_get_sizes(c, "ag", "devices", &count) < 0)
	    goto _noarg;
	if (!IN_RANGE((unsigned)count, 1, pool_info->dev_count))
	    goto _noarg;
	ag->pdis = (uint32_t)count;
	if (ag->pdis > ag_maxlen)
	    ag_maxlen = ag->pdis; /* maximum number of group devices */
	ag->gpdi = (uint16_t *) calloc(sizeof(uint16_t), ag->pdis);
	for (uu = 0; uu < ag->pdis; uu++) {
	    if (configurator_int_val(c->ag_devices[u][uu], &l))
		ag->gpdi[uu] = F_PDI_NONE;
	    else
		ag->gpdi[uu] = (uint16_t)l;
	}
    }
    p->ag_devs = ag_maxlen;

    /* Devices */
    p->pool_devs = ag_maxlen * p->pool_ags;
    p->devlist = (F_POOL_DEV_t*)calloc(sizeof(F_POOL_DEV_t), p->pool_devs);
    if (!p->devlist) goto _nomem;
    pdev = p->devlist;
    for (u = 0; u < p->pool_devs; u++, pdev++)
	pdev->pool_index = F_PDI_NONE;
    for (u = 0; u < pool_info->dev_count; u++) {
	FAM_DEV_t *fam;
	int pd_index;
	uint16_t pool_index;

	if (configurator_int_val(c->device_id[u][0], &l)) goto _noarg;
	pool_index = (uint32_t)l;

	/* Find device in AG by pool_index and map it to devlist */
	pd_index = find_pd_index_in_ag(p->ags, p->pool_ags, p->ag_devs,
				       pool_index, p->devlist);
	if (!IN_RANGE(pd_index, 0, (int)p->pool_devs-1)) goto _syntax;
	pdev = &p->devlist[pd_index];
	pdev->pool_index = pool_index;

	f_uuid_parse(c->device_uuid[u][0], pdev->uuid);
	if (configurator_int_val(c->device_size[u][0], &l)) goto _syntax;
	pdev->size = (size_t)l;
	if (pdev->size == 0)
	    pdev->size = p->info.size_def;
	/* TODO: Parse extent_sz, extent_start */
	pdev->extent_start = p->info.extent_start;
	pdev->extent_sz = p->info.extent_sz;
	pdev->extent_count = pdev->size/p->info.extent_sz;
	if (configurator_bool_val(c->device_failed[u][0], &b)) goto _noarg;
	if (b)
	    SetDevFailed(&pdev->sha);
	/* Allocate FAMFS device */
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
    /* Sort pool devices array by pool_index for every AG */
    for (u = 0; u < p->pool_ags; u++) {
	pdev = ((F_POOL_DEV_t (*)[p->ag_devs]) p->devlist)[u];
	qsort(pdev, p->ag_devs, sizeof(F_POOL_DEV_t), cmp_pdev_by_index);
	/* check the presence and enumerate devices in AG */
	for (uu = 0; uu < p->ags[u].pdis; uu++, pdev++) {
	    if (pdev->pool_index == F_PDI_NONE) {
		/* non-existing device in AG */
		fprintf (stderr, " AG id:%u - device not in configuration!\n",
		    pdev->idx_ag);
		goto _syntax;
	    }
	    /* set pool device indexes in array for back-reference */
	    pdev->idx_ag = u;	/* 1st index */
	    pdev->idx_dev = uu;	/* 2nd index */
	}
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
_syntax:
    rc = -2; /* semantic error in configuration */
    goto _err;
_noarg:
    rc = -1; /* no mandatory parameter specified */
_err:
    free_pool(p);
    return rc;
}

static void free_layout(F_LAYOUT_t *lo)
{
    free(lo->info.name);
    if (lo->devlist) {
	F_POOLDEV_INDEX_t *pdi = lo->devlist;
	unsigned int u;

	for (u = 0; u < lo->devlist_sz; u++, pdi++)
	    free(pdi->sha);
	free(lo->devlist);
    }

    if (lo->lp) {
	pthread_spin_destroy(&lo->lp->alloc_lock);
	pthread_rwlock_destroy(&lo->lp->claimdec_lock);
	free(lo->lp);
    }

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
    F_POOL_t *p = pool;
    F_POOL_DEV_t *pdev;
    F_POOLDEV_INDEX_t *pdi;
    unsigned int u, uu;
    int rc, count;
    long l;
    bool all_pdevs;

    assert( p && IN_RANGE(idx, 0, (int)p->info.layouts_count-1) );
    lo = (F_LAYOUT_t *) calloc(sizeof(F_LAYOUT_t), 1);
    if (!lo) return -ENOMEM;
    if (pthread_rwlock_init(&lo->lock, NULL)) goto _nomem;
    if (pthread_spin_init(&lo->dict_lock, PTHREAD_PROCESS_PRIVATE)) goto _nomem;
    INIT_LIST_HEAD(&lo->list);
    /* Parse this layout's configurator ID and name */
    info = &lo->info;
    if (configurator_int_val(c->layout_id[idx][0], &l)) goto _noarg;
    info->conf_id = (unsigned int)l;

    /* Partition */
    lo->lp = (F_LO_PART_t *) calloc(sizeof(F_LO_PART_t), 1);
    if (!lo->lp) goto _nomem;
    lp = lo->lp;
    if (pthread_rwlock_init(&lp->claimdec_lock, NULL)) goto _nomem;
    if (pthread_spin_init(&lp->alloc_lock, PTHREAD_PROCESS_PRIVATE))
	goto _nomem;
    INIT_LIST_HEAD(&lp->alloc_buckets);
    INIT_LIST_HEAD(&lp->claimdecq);

    /* Devices */
    count = idx; /* layout section index */
    all_pdevs = (configurator_get_sizes(c, "layout", "devices", &count) < 0);
    if (all_pdevs) {
	/* no layout devices list given - default to pool devices */
	count = p->info.dev_count;
    } else {
	if (!IN_RANGE((unsigned)count, 1, p->info.dev_count))
	    goto _noarg;
    }
    lo->devlist_sz = info->devnum = (unsigned)count;
    info->name = strdup(c->layout_name[idx][0]);
    if (f_layout_parse_name(info)) goto _noarg;
    lo->devlist = (F_POOLDEV_INDEX_t *) calloc(sizeof(F_POOLDEV_INDEX_t),
	lo->devlist_sz);
    if (!lo->devlist) goto _nomem;
    pdi = lo->devlist;
    for (u = uu = 0; u < info->devnum; u++, pdi++) {
	/* find pool device by id */
	if (all_pdevs) {
	    pdev = &pool->devlist[uu];
	    while (pdev->pool_index == F_PDI_NONE &&
		   ++uu < p->pool_devs) pdev++;
	    assert( uu < p->pool_devs ); /* less than devnum */
	} else {
	    if (configurator_int_val(c->layout_devices[idx][u], &l))
		pdev = NULL;
	    else
		pdev = f_find_pdev((unsigned int)l);
	}
	/* copy pdev */
	if (pdev == NULL) {
	    pdi->pool_index = F_PDI_NONE;
	} else {
	    pdi->pool_index = pdev->pool_index;
	    pdi->idx_ag = pdev->idx_ag;
	    pdi->idx_dev = pdev->idx_dev;
	    /* Allocate the device index shareable atomics */
	    pdi->sha = (F_PDI_SHA_t *) calloc(sizeof(F_PDI_SHA_t), 1);
	    if (!pdi->sha) goto _nomem;
	}
    }
    /* Sort by AG first, then by pool index */
    qsort(lo->devlist, lo->devlist_sz, sizeof(F_POOLDEV_INDEX_t), cmp_pdi);

    lo->pool = p;
    /* Add to layouts list */
    list_add(&lo->list, &p->layouts);
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
	list_for_each_safe(l, tmp, &pool->layouts) {
	    lo = container_of(l, struct f_layout_, list);
	    list_del(l);
	    free_layout(lo);
	}
	free_pool(pool);
	pool = NULL;
    }
}

void f_print_layouts(void) {
    F_POOL_t *p = pool;
    F_POOL_INFO_t *pool_info;
    F_AG_t *ag;
    F_POOL_DEV_t *pdev;
    F_LAYOUT_t *lo;
    char pr_uuid[F_UUID_BUF_SIZE];
    struct list_head *l, *tmp;
    unsigned int u, uu;

    if (p == NULL)
	return;
    /* Pool */
    pool_info = &p->info;
    printf("Pool has %u devices in %u AGs, %u each\n",
	pool_info->dev_count, p->pool_ags, p->ag_devs);
    ag = p->ags;
    for (u = 0; u < p->pool_ags; u++, ag++) {
	pdev = ((F_POOL_DEV_t (*)[p->ag_devs]) p->devlist)[u];
	printf("  AG#%u id:%u has %u devices:\n",
		u, ag->gid, ag->pdis);
	for (uu = 0; uu < ag->pdis; uu++, pdev++) {
	    assert( pdev->pool_index != F_PDI_NONE );
	    uuid_unparse(pdev->uuid, pr_uuid);
	    printf ("    [%u,%u] id:%u uuid:%s size:%zu\n",
		pdev->idx_ag, pdev->idx_dev, pdev->pool_index,
		pr_uuid, pdev->size);
	}
    }

    /* Layouts */
    printf("\nPool has %u layout(s).\n", pool_info->layouts_count);
    list_for_each_prev_safe(l, tmp, &p->layouts) {
	F_LAYOUT_INFO_t *info;
	F_POOLDEV_INDEX_t *pdi;

	lo = container_of(l, struct f_layout_, list);
	info = &lo->info;
	printf("\nLayout id:%u moniker %s\n",
	    info->conf_id, info->name);
        printf("  %uD+%uP chunk:%u, stripes:%u per slab, total %u slab(s)\n",
	    info->data_chunks, (info->chunks - info->data_chunks),
	    info->chunk_sz, info->slab_stripes, info->slab_count);
	printf("  This layout has %u device(s), including %u missing.\n",
	    info->devnum, info->misdevnum);
	pdi = lo->devlist;
	for (u = 0; u < lo->devlist_sz; u++, pdi++) {
	    if (pdi->pool_index == F_PDI_NONE)
		continue;
	    printf("  dev#%u pool index:%u [%u,%u] ext used/failed:%u/%u\n",
		u, pdi->pool_index, pdi->idx_ag, pdi->idx_dev,
		pdi->sha->extents_used, pdi->sha->failed_extents);
	}
	printf("  Layout partition:%u\n", lo->lp->part_num);
    }

    /* IO nodes */
    printf("\nConfiguration has %u IO nodes:\n", p->ionode_count);
    for (u = 0; u < p->ionode_count; u++) {
	F_IONODE_INFO_t *info = &p->ionodes[u];

	printf("  #%u%s id:%u %s MDS:%u\n",
	    u, (u == p->ionode_id && PoolIsIOnode(p))?"*":"",
	    info->conf_id, info->hostname, info->mds);
    }
}

/* Is 'hostname' in IO nodes list? If NULL, check my node name */
int f_host_is_ionode(const char *hostname)
{
    if (hostname)
	return !!get_ionode_info(pool, hostname);

    return pool && PoolIsIOnode(pool);
}

/* Is 'hostname' a MD server? If NULL, check my node name */
int f_host_is_mds(const char *hostname)
{
    if (hostname) {
	F_IONODE_INFO_t *info = get_ionode_info(pool, hostname);

	return info && info->mds;
    }
    return pool && PoolHasMDS(pool);
}

