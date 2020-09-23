/*
 * Copyright (c) 2019, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#include <uuid/uuid.h>

#include "famfs_env.h"
#include "famfs_error.h"
#include "f_pool.h"
#include "f_layout.h"
#include "famfs_maps.h"
#include "famfs_lf_connect.h"
#include "famfs_configurator.h"
#include "mpi_utils.h"


F_POOL_t *pool = NULL;
static F_META_IFACE_t *meta_iface = NULL;


F_POOL_t *f_get_pool(void) {
    return pool;
}

/* Return 0 if the slab map entry checksum (CRC-4) is correct */
unsigned char f_crc4_sm_chk(F_SLAB_ENTRY_t *se)
{
    unsigned char c;
    size_t i;
    int crc = 0;

    for (i = 0; i < offsetof(F_SLAB_ENTRY_t, rc); i++) {
	c = ((unsigned char *)se)[i];
	crc = f_crc4_fast_table[crc | c];
    }
    /* Skip recovery count (32bits) */
    for (i += sizeof(se->rc); i < sizeof(F_SLAB_ENTRY_t); i++) {
	c = ((unsigned char *)se)[i];
	crc = f_crc4_fast_table[crc | c];
    }
    return (unsigned char)(crc >> 8);
}


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
    uint64_t *off_p, int op)
{
	ssize_t ret;

	/* search key */
	if (off_p)
		keys[0] = *off_p;

	ret = meta_iface->bget_fn(buf, map_id, size, keys, op);

	/* store the next key */
	if (off_p && ret > 0)
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

/* I/O node */

static F_IONODE_INFO_t *get_ionode_info(F_POOL_t *p, const char *hostname)
{
    unsigned int count;
    int idx;
    char **nodelist;

    if (p == NULL)
	return NULL;

    /* List of IO nodes */
    count = p->ionode_count;
    nodelist = p->ionodelist;
    assert( nodelist );

    /* Find foreign hostname if given, otherwise local hostname or IP */
    if (hostname)
	idx = f_find_node(nodelist, (int)count, hostname);
    else
	idx = find_my_node(nodelist, (int)count, NULL);

    if (idx < 0)
	return NULL;
    return &p->ionodes[idx];
}

static char *get_myhostname(void) {
    char *mpienvname = getenv("MPIR_CVAR_CH3_INTERFACE_HOSTNAME");
    char *hostname = f_get_myhostname();

    /* take host name from mpirun command if possible */
    if (mpienvname) {
	const char *p1, *p2;

	mpienvname = strdup(mpienvname);
	for (p1 = mpienvname, p2 = hostname ; *p1 && *p1 == *p2 ; p1++, p2++)
	    ;
	/* validate mpi host name or IP */
	if (!*p2 /* host name */ ||
	    (p1 == mpienvname && find_my_node(&mpienvname, 1, NULL) == 0) /* host IP */)
	{
	    free(hostname);
	    return mpienvname;
	}
	free(mpienvname);
    }
    return hostname;
}

/* Set ionode_id and HasMDS, IsIOnode flags in pool struct */
static void set_mynode_info(F_POOL_t *p)
{
    F_IONODE_INFO_t *info;

    assert (p && p->ionodes);
    info = get_ionode_info(p, NULL);
    if (info) {
	SetNodeIsIOnode(&p->mynode);
	if (IOnodeForceHelper(info))
	    SetNodeForceHelper(&p->mynode);
	if (info->mds)
	    SetNodeHasMDS(&p->mynode);
	else
	    ClearNodeHasMDS(&p->mynode);
	if (PoolFAMEmul(p))
	    SetNodeRunLFSrv(&p->mynode);
	p->mynode.ionode_idx = (uint16_t)(info - p->ionodes);
	assert( p->mynode.ionode_idx < p->ionode_count );
	p->mynode.hostname = strdup(info->hostname);
    } else {
	ClearNodeIsIOnode(&p->mynode);
	ClearNodeHasMDS(&p->mynode);
	p->mynode.hostname = get_myhostname();
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

static uint16_t find_pdev(struct f_pool_ *p, unsigned int index) {
    F_AG_t *ag;
    unsigned int u;

    ag = p->ags;
    for (u = 0; u < p->pool_ags; u++, ag++) {
	F_POOL_DEV_t *pdev = ((F_POOL_DEV_t (*)[p->ag_devs]) p->devlist)[u];
	unsigned int uu;

	for (uu = 0; uu < ag->pdis; uu++, pdev++)
	    if (pdev->pool_index == index)
		return p->ag_devs*u + uu;
    }
    return F_PDI_NONE;
}

struct f_pool_dev_ *f_find_pdev(unsigned int media_id) {
    struct f_pool_ *p = pool;

    return (media_id > p->info.pdev_max_idx)? NULL:
	( (p->info.pdi_by_media[media_id] == F_PDI_NONE)? NULL:
	  &p->devlist[ p->info.pdi_by_media[media_id] ]);
}

/* Convert the layout 'pdi' to pool device 'pdev' */
struct f_pool_dev_ *f_pdi_to_pdev(struct f_pool_ *p, struct f_pooldev_index_ *pdi) {
    return &((F_POOL_DEV_t (*)[p->ag_devs]) p->devlist)
					    [pdi->idx_ag][pdi->idx_dev];
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

static int dev_ionode(F_POOL_t *p, struct f_dev_ *dev)
{
    F_IONODE_INFO_t *ionode = p->ionodes;
    char *topo = dev->f.zfm.topo;
    uint32_t i;

    for (i = 0; i < p->ionode_count; i++, ionode++) {
	size_t l = strlen(ionode->zfm.topo);
	char *p = strrchr(topo, '.');

	if (!p || (p - topo) != (ssize_t)l)
	    continue;
	if (!strncmp(topo, ionode->zfm.topo, l))
	    return (int)i;
    }
    return -1;
}

static int clone_pool_dev(F_POOL_DEV_t *clone, F_POOL_DEV_t *pdev)
{
    FAM_DEV_t *fam, *cfam;

    uuid_copy(clone->uuid, pdev->uuid);
    clone->size = pdev->size;
    clone->extent_sz = pdev->extent_sz;
    clone->extent_start = pdev->extent_start;
    clone->extent_count = pdev->extent_count;
    clone->pool_index = pdev->pool_index;
    clone->idx_ag = pdev->idx_ag;
    clone->idx_dev = pdev->idx_dev;
    if (pthread_rwlock_init(&clone->rwlock, NULL))
	return -ENOMEM;
    assert( pdev->dev );
    fam = &pdev->dev->f;
    clone->dev = (F_DEV_t *) calloc(sizeof(F_DEV_t), 1);
    if (!clone->dev)
	return -ENOMEM;
    cfam = &clone->dev->f;
    cfam->lf_name = strdup(fam->lf_name);
    cfam->zfm.topo = strdup(fam->zfm.topo);
    if (fam->zfm.znode)
	cfam->zfm.znode = strdup(fam->zfm.znode);
    if (fam->zfm.geo)
	cfam->zfm.geo = strdup(fam->zfm.geo);
    cfam->ionode_idx = fam->ionode_idx;

    return 0;
}

static void free_pdev(F_POOL_DEV_t *pdev)
{
    if (pdev->dev) {
	FAM_DEV_t *d = &pdev->dev->f;

	free(d->zfm.url);
	free(d->zfm.znode);
	free(d->zfm.topo);
	free(d->zfm.geo);

	pthread_rwlock_destroy(&pdev->rwlock);
	free(pdev->dev);
    }
    free(pdev->sha);
}

/* Set back references to IO node index&position in all pool devices */
static void set_pdevs_to_ions(F_POOL_t *p)
{
    F_POOL_INFO_t *info = &p->info;
    F_IONODE_INFO_t *ioi;
    unsigned int i, j, k;
    unsigned int xchg_off = 0;

    ioi = p->ionodes;
    for (j = 0; j < p->ionode_count; j++, ioi++) {
	F_POOL_DEV_t *pdev;
	uint16_t *pd_idx = info->pdev_indexes;

	for (i = k = 0; i < info->dev_count; i++, pd_idx++) {
	    pdev = &p->devlist[*pd_idx];
	    if (pdev->dev->f.ionode_idx != j)
		continue;
	    /* set back refs to IO node id&pos */
	    pdev->ionode_idx = j;
	    pdev->idx_in_ion = k++;
	}
	ioi->fam_xchg_off = xchg_off;
	ioi->fam_devs = k;
	xchg_off += k;
    }
}

/* Allocate libfabric devices for FAM emulation on this IO node. */
static int emulated_devs_alloc(F_POOL_t *p)
{
    F_POOL_DEV_t *devlist = NULL;
    F_POOL_DEV_t *pdev, *em_pdev;
    F_POOL_INFO_t *info = &p->info;
    F_MYNODE_t *mynode = &p->mynode;
    size_t mr_size = 0;
    uint16_t ion_idx, *pd_idx;
    unsigned int i, k;
    int rc;

    ion_idx = (uint16_t)mynode->ionode_idx;
    mynode->emul_devs = p->ionodes[ion_idx].fam_devs;
    if (mynode->emul_devs == 0) {
	err("ionode #%u (%s) has no FAMs - please check configuration!",
	    ion_idx, mynode->hostname);
	return 0;
    }
    devlist = em_pdev = (F_POOL_DEV_t*) calloc(mynode->emul_devs,
						sizeof(F_POOL_DEV_t));
    if (!devlist)
	return -ENOMEM;

    pd_idx = info->pdev_indexes;
    for (i = k = 0; i < info->dev_count; i++, pd_idx++) {
        pdev = &p->devlist[*pd_idx];
	if (pdev->dev->f.ionode_idx != ion_idx)
	    continue;
	if ((rc = clone_pool_dev(em_pdev, pdev)))
	    goto _err;
	em_pdev->dev->f.zfm.url = strdup(mynode->hostname);
	em_pdev->dev->f.mr_size = em_pdev->size;
	//em_pdev->dev->f.offset = info->data_offset;
	em_pdev->pool = p;
	mr_size += em_pdev->size;
	em_pdev++; k++;
    }

    mynode->emul_devlist = devlist;
    mynode->emul_mr_size = mr_size;
    return 0;

_err:
    em_pdev = devlist;
    for (i = 0; i < k; i++, em_pdev++)
	 free_pdev(em_pdev);
    free(devlist);
    return rc;
}

static int free_pool(F_POOL_t *p)
{
    int rc;

    if (p) {
	F_POOL_DEV_t *pdev;
	unsigned int i;

	if (p->helper_comm)
	    MPI_Comm_free(&p->helper_comm);

	if ((rc = lf_clients_free(p)))
	    goto _err;

	if (p->devlist && p->info.pdev_indexes) {
	    for_each_pool_dev(p, pdev)
	        free_pdev(pdev);
	}
	if (p->devlist) free(p->devlist);
	if (p->info.pdev_indexes) free(p->info.pdev_indexes);
	if (p->info.pdi_by_media) free(p->info.pdi_by_media);

	if (p->ags) {
	    for (i = 0; i < p->pool_ags; i++)
		free(p->ags[i].gpdi);
	    free(p->ags);
	}

	if (p->ionodes) {
	    F_IONODE_INFO_t *ioi = p->ionodes;

	    for (i = 0; i < p->ionode_count; i++, ioi++) {
		free(ioi->hostname);
		free(ioi->zfm.url);
		free(ioi->zfm.znode);
		free(ioi->zfm.topo);
		free(ioi->zfm.geo);
	    }
	    free(p->ionodes);
	}
	nodelist_free(p->ionodelist, p->ionode_count);

	if (p->ionode_comm) {
	    MPI_Barrier(p->ionode_comm);
	    MPI_Comm_free(&p->ionode_comm);
	}

	if ((rc = lf_servers_free(p)))
	    goto _err;

	if (p->mynode.emul_devlist) {
	    pdev = p->mynode.emul_devlist;
	    for (i = 0; i < p->mynode.emul_devs; i++, pdev++)
		free_pdev(pdev);
	    free(p->mynode.emul_devlist);
	}

	if (p->lf_info) {
	    LF_INFO_t *lf_info = p->lf_info;

	    free(lf_info->fabric);
	    free(lf_info->domain);
	    free(lf_info->provider);
	    free(lf_info);
	}
	free(p->mynode.hostname);

	f_dict_free(p->dict);
	pthread_spin_destroy(&p->dict_lock);
	pthread_rwlock_destroy(&p->lock);
	pthread_cond_destroy(&p->event_cond);
	free(p);
    }
    return 0;

_err:
    err("failed to free pool:%d", rc);
    return rc;
}

static int cfg_load_pool(unifycr_cfg_t *c)
{
    F_POOL_t *p;
    F_POOL_INFO_t *pool_info;
    F_AG_t *ag;
    F_POOL_DEV_t *pdev;
    LF_INFO_t *lf_info;
    const char *s;
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
    pthread_cond_init(&p->event_cond, NULL); /* PTHREAD_PROCESS_PRIVATE */
    pthread_mutex_init(&p->event_lock, NULL);
    INIT_LIST_HEAD(&p->layouts);
    pool_info = &p->info;

    /* Pool */
    if (configurator_int_val(c->log_verbosity, &l)) goto _noarg;
    p->verbose = (int)l;
    if (f_uuid_parse(c->devices_uuid, p->uuid)) {
	assert( uuid_parse(FAMFS_PDEVS_UUID_DEF, p->uuid) == 0);
    }
    if (configurator_int_val(c->unifycr_lfa_port, &l)) goto _noarg;
    pool_info->lfa_port = (int)l;
    if (configurator_int_val(c->unifycr_cq_hwm, &l)) goto _noarg;
    pool_info->cq_hwm = (int)l;
    if (configurator_int_val(c->unifycr_cq_hwm_tmo, &l)) goto _noarg;
    pool_info->cq_hwm_tmo = (int)l;
    if (!strcmp(c->unifycr_fs_type, "famfs"))
	SetPoolFAMFS(p);
    else if (!strcmp(c->unifycr_fs_type, "unifycr"))
	SetPoolUNIFYCR(p);
    else if (!strcmp(c->unifycr_fs_type, "both")) {
	SetPoolFAMFS(p);
	SetPoolUNIFYCR(p);
    } else goto _syntax;
    if (configurator_bool_val(c->unifycr_cache_wr, &b)) goto _noarg;
    if (b)
	SetPoolWCache(p);
    if (configurator_bool_val(c->unifycr_cache_rd, &b)) goto _noarg;
    if (b)
	SetPoolRCache(p);

    /* Generic device section: 'devices' */
    lf_info = (LF_INFO_t *) calloc(sizeof(LF_INFO_t), 1);
    if (!lf_info) goto _nomem;
    lf_info->verbosity = p->verbose;
    if (configurator_int_val(c->devices_extent_size, &l)) goto _noarg;
    pool_info->extent_sz = (unsigned long)l;
    if (configurator_int_val(c->devices_offset, &l)) goto _noarg;
    pool_info->data_offset = (unsigned long)l;
    if (configurator_bool_val(c->devices_emulated, &b)) goto _noarg;
    if (b && PoolFAMFS(p))
	SetPoolFAMEmul(p);
    else
	lf_info->opts.true_fam = 1;
    if (configurator_int_val(c->devices_size, &l)) goto _noarg;
    pool_info->size_def = (size_t)l;
    if (configurator_int_val(c->devices_pk, &l)) goto _noarg;
    pool_info->pkey_def = (uint64_t)l;
    if (c->devices_fabric)
	lf_info->fabric = strdup(c->devices_fabric);
    if (c->devices_domain)
	lf_info->domain = strdup(c->devices_domain);
    if (c->devices_port == NULL) goto _noarg;
    if (sscanf(c->devices_port, "%5d", &lf_info->service) != 1) goto _syntax;
    lf_info->provider = strdup(c->devices_provider);
    if (!strcmp(lf_info->provider, "zhpe"))
	lf_info->opts.zhpe_support = 1;
    if (configurator_bool_val(c->devices_use_cq, &b)) goto _noarg;
    if (b)
	lf_info->opts.use_cq = 1;
    if (configurator_int_val(c->devices_timeout, &l)) goto _noarg;
    lf_info->io_timeout_ms = (uint64_t)l;
    if (configurator_bool_val(c->devices_single_ep, &b)) goto _noarg;
    if (b) {
	lf_info->single_ep = 1;
	if (!lf_info->opts.use_cq) {
	    ERROR("Cannot use counters with single EP!");
	    lf_info->opts.use_cq = 1;
	}
    }
    s = c->devices_memreg;
    lf_info->mrreg.scalable = strcasecmp(s, LF_MR_MODEL_SCALABLE)? 0:1;
    lf_info->mrreg.basic = strncasecmp(s, LF_MR_MODEL_BASIC,
				       strlen(LF_MR_MODEL_BASIC))? 0:1;
    lf_info->mrreg.local = strcasecmp(s + lf_info->mrreg.basic*(strlen(LF_MR_MODEL_BASIC)+1),
				LF_MR_MODEL_LOCAL)? 0:1;
    if (!lf_info->mrreg.scalable && !lf_info->mrreg.basic && !lf_info->mrreg.local)
	goto _badstr;
    if (lf_info->mrreg.basic) {
	/* basic registration is equivalent to FI_MR_VIRT_ADDR|FI_MR_ALLOCATED|FI_MR_PROV_KEY */
	lf_info->mrreg.basic = 0;
	lf_info->mrreg.allocated = 1;
	if (!strcmp(lf_info->provider, "verbs")) {
	    lf_info->mrreg.prov_key = 1;
	    lf_info->mrreg.virt_addr = 1;
	} else {
	    /* "zhpe" or "sockets" */
	    lf_info->mrreg.prov_key = 0;
	    lf_info->mrreg.virt_addr = 0;
	}
    }
    s = c->devices_progress;
    lf_info->progress.progress_manual = strncasecmp(s, "manual", 3)? 0:1;
    if (!lf_info->progress.progress_manual) {
	lf_info->progress.progress_auto = strcasecmp(s, "auto")? 0:1;
	if (!lf_info->progress.progress_auto && strcasecmp(s, "default"))
	    goto _badstr;
    }
    p->lf_info = lf_info;

    /* IO nodes */
    count = configurator_get_sec_size(c, "ionode");
    if (!IN_RANGE(count, 1, F_IONODES_MAX)) goto _noarg;
    p->ionode_count = (uint32_t)count;
    p->ionodes = (F_IONODE_INFO_t*) calloc(sizeof(F_IONODE_INFO_t),
					   p->ionode_count);
    if (!p->ionodes) goto _nomem;
    p->ionodelist = (char**) calloc(sizeof(char*), p->ionode_count);
    if (!p->ionodelist) goto _nomem;
    for (u = 0; u < p->ionode_count; u++) {
	F_IONODE_INFO_t *ioi = &p->ionodes[u];

	if (configurator_int_val(c->ionode_id[u][0], &l)) goto _syntax;
	ioi->conf_id = (uint32_t)l;
	f_uuid_parse(c->ionode_uuid[u][0], ioi->uuid);
	if (configurator_int_val(c->ionode_mds[u][0], &l)) goto _syntax;
	ioi->mds = (uint32_t)l;
	if (configurator_bool_val(c->ionode_force_helper[u][0], &b)) goto _syntax;
	if (b)
	    SetIOnodeForceHelper(ioi);
	if (c->ionode_host[u][0])
	    ioi->hostname = strdup(c->ionode_host[u][0]);
	else if (u > 0)
	    goto _noarg;
	if (!c->ionode_topo[u][0]) goto _noarg;
	ioi->zfm.topo = strdup(c->ionode_topo[u][0]);
	if (c->ionode_z_node[u][0])
	    ioi->zfm.znode = strdup(c->ionode_z_node[u][0]);
	if (c->ionode_geo[u][0])
	    ioi->zfm.geo = strdup(c->ionode_geo[u][0]);

    }
    /* Set IO node name to `hostname` if omitted on single-node configuration */
    if (p->ionodes[0].hostname == NULL) {
	if (p->ionode_count > 1) goto _noarg;
	if (!IOnodeForceHelper(p->ionodes)) goto _noarg;
	p->ionodes[0].hostname = get_myhostname();
    }
    for (u = 0; u < p->ionode_count; u++)
	p->ionodelist[u] = strdup(p->ionodes[u].hostname);
    set_mynode_info(p);

    /* Device count */
    count = configurator_get_sec_size(c, "device");
    if (!IN_RANGE(count, 1, F_DEVICES_MAX)) goto _noarg;
    pool_info->dev_count = (unsigned int)count;

    /* Allocation groups */
    count = configurator_get_sec_size(c, "ag");
    p->ags = (F_AG_t *) calloc(sizeof(F_AG_t), count);
    if (!p->ags) goto _nomem;
    if (!IN_RANGE(count, 1, F_AG_CNT_MAX)) goto _noarg;
    p->pool_ags = (uint32_t)count;
    ag = p->ags;
    ag_maxlen = 0;
    for (u = 0; u < p->pool_ags; u++, ag++) {
	/* AG id */
	if (configurator_int_val(c->ag_id[u][0], &l)) goto _syntax;
	ag->gid = (uint32_t)l;
	f_uuid_parse(c->ag_uuid[u][0], ag->uuid);
	/* List of devices in the group */
	count = u;
	assert( configurator_get_sizes(c, "ag", "devices", &count) );
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
    pool_info->pdev_max_idx = 0;
    pool_info->max_extents = 0;
    p->pool_devs = ag_maxlen * p->pool_ags;
    p->devlist = (F_POOL_DEV_t*) calloc(sizeof(F_POOL_DEV_t), p->pool_devs);
    if (!p->devlist) goto _nomem;
    pdev = p->devlist;
    for (u = 0; u < p->pool_devs; u++, pdev++)
	pdev->pool_index = F_PDI_NONE;
    for (u = 0; u < pool_info->dev_count; u++) {
	FAM_DEV_t *fam;
	int pd_index, idx;
	uint16_t pool_index;

	/* device media_id */
	if (configurator_int_val(c->device_id[u][0], &l)) goto _noarg;
	pool_index = (uint32_t)l;

	/* Find device in AG by media_id (pool_index) and map it to devlist */
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

	/* TODO: Parse extent_sz, offset */
	pdev->extent_start = p->info.data_offset/p->info.extent_sz;
	pdev->extent_sz = p->info.extent_sz;
	pdev->extent_count = pdev->size/p->info.extent_sz;

	pdev->sha = (F_PDEV_SHA_t *) calloc(sizeof(F_PDEV_SHA_t), 1);
	if (!pdev->sha) goto _nomem;

	if (configurator_bool_val(c->device_failed[u][0], &b)) goto _noarg;
	if (b)
	    SetDevFailed(pdev->sha);
	/* Allocate FAMFS device in devlist */
	pdev->dev = (F_DEV_t *) calloc(sizeof(F_DEV_t), 1);
	if (!pdev->dev) goto _nomem;
	fam = &pdev->dev->f;
	fam->mr_size = pdev->size;
	fam->offset = pool_info->data_offset;
	if (!c->device_topo[u][0]) goto _noarg;
	fam->zfm.topo = strdup(c->device_topo[u][0]);
	if (c->device_z_node[u][0])
	    fam->zfm.znode = strdup(c->device_z_node[u][0]);
	if (c->device_geo[u][0])
	    fam->zfm.geo = strdup(c->device_geo[u][0]);
	/* match device IO node by toplogy */
	if ((idx = dev_ionode(p, pdev->dev)) < 0) goto _syntax;
	    fam->ionode_idx = (uint16_t)idx;
	if (PoolFAMEmul(p)) {
	    fam->lf_name = strdup(p->ionodes[idx].hostname);
	} else {
	    if (!c->device_url[u][0]) goto _noarg;
	    fam->zfm.url = strdup(c->device_url[u][0]);
	    fam->lf_name = strdup(fam->zfm.url);
	}

	if (configurator_int_val(c->device_pk[u][0], &l))
	    fam->pkey = pool_info->pkey_def;
	else
	    fam->pkey = (uint64_t)l;
	/* Set max device media_id, extent_count in the pool */
	pool_info->pdev_max_idx = max(pool_info->pdev_max_idx, pool_index);
	pool_info->max_extents = max(pool_info->max_extents, pdev->extent_count);

	if (pthread_rwlock_init(&pdev->rwlock, NULL)) goto _nomem;
	pdev->pool = p;

	/* TODO: probe devices, sha.extent_bmap */
    }
    /* Sort pool devices array by pool_index for every AG */
    for (u = 0; u < p->pool_ags; u++) {
	pdev = ((F_POOL_DEV_t (*)[p->ag_devs]) p->devlist)[u];
	qsort(pdev, p->ag_devs, sizeof(F_POOL_DEV_t), cmp_pdev_by_index);

	p->ags[u].ionode_idx = pdev->dev->f.ionode_idx;
	/* check the presence and enumerate devices in AG */
	for (uu = 0; uu < p->ags[u].pdis; uu++, pdev++) {
	    if (pdev->pool_index == F_PDI_NONE) {
		/* non-existing device in AG */
		fprintf (stderr, " AG id:%u - device not in configuration!\n",
		    pdev->idx_ag);
		goto _syntax;
	    }
	    if (p->ags[u].ionode_idx != pdev->dev->f.ionode_idx) {
		/* mix of devices from different IO nodes in AG */
		fprintf (stderr, " AG id:%u - device id:%u does not belong to"
				 " IO node id:%u but %u\n",
		    pdev->idx_ag, pdev->pool_index,
		    p->ionodes[p->ags[u].ionode_idx].conf_id,
		    pdev->dev->f.ionode_idx);
		goto _syntax;
	    }
	    /* set pool device indexes in array for back-reference */
	    pdev->idx_ag = u;	/* 1st index */
	    pdev->idx_dev = uu;	/* 2nd index */
	}
    }

    /* Populate pool devlist lookup helper arrays */

    /* Array of indexes in devlist for devlist stripped of F_PDI_NONE devices */
    pool_info->pdev_indexes = (uint16_t *) calloc(pool_info->dev_count,
						  sizeof(uint16_t));
    if (!pool_info->pdev_indexes) goto _nomem;
    pdev = p->devlist;
    for (u = uu = 0; u < pool_info->dev_count; u++, uu++, pdev++) {
	    while (uu < p->pool_devs && pdev->pool_index == F_PDI_NONE) {
		pdev++;
		uu++;
	    }
	    assert( uu < p->pool_devs );
	    pool_info->pdev_indexes[u] = uu;
    }
    /* Array of indexes in devlist for each media_id from zero to 'pdev_max_idx' */
    pool_info->pdi_by_media = (uint16_t *) calloc(pool_info->pdev_max_idx+1,
						  sizeof(uint16_t));
    if (!pool_info->pdi_by_media) goto _nomem;
    for (u = 0; u <= pool_info->pdev_max_idx; u++)
	pool_info->pdi_by_media[u] = find_pdev(p, u);

    /* Set back references to IO node index&position in all pool devices */
    set_pdevs_to_ions(p);

    /* Allocate fabric devices for FAM emulation */
    if (NodeRunLFSrv(&p->mynode) && emulated_devs_alloc(p))
	goto _nomem;

    /* Layout count */
    count = configurator_get_sec_size(c, "layout");
    if (!IN_RANGE(count, 1, F_LAYOUTS_MAX)) goto _noarg;
    pool_info->layouts_count = count;

    pool = p;
    return 0;

_nomem:
    rc = -ENOMEM;
    goto _err;
_badstr:
    rc = -3; /* invalid string value */
    goto _err;
_syntax:
    rc = -2; /* semantic error in configuration */
    goto _err;
_noarg:
    rc = -1; /* no mandatory parameter specified */
_err:
    (void)free_pool(p);
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

static uint16_t find_pdi(F_LAYOUT_t *lo, unsigned int index) {
    unsigned int u;

    for (u = 0; u < lo->devlist_sz; u++) {
	F_POOLDEV_INDEX_t *pdi = &lo->devlist[u];

	if (pdi->pool_index == index)
	    return u;
    }
    return F_PDI_NONE;
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
    unsigned int u, uu, pdi_max_idx;
    int rc, count;
    long l;
    bool all_pdevs;

    assert( p && IN_RANGE(idx, 0, (int)p->info.layouts_count-1) );
    lo = (F_LAYOUT_t *) calloc(sizeof(F_LAYOUT_t), 1);
    if (!lo) return -ENOMEM;
    if (pthread_rwlock_init(&lo->lock, NULL)) goto _nomem;
    if (pthread_spin_init(&lo->dict_lock, PTHREAD_PROCESS_PRIVATE)) goto _nomem;
    INIT_LIST_HEAD(&lo->list);
    /* Parse this layout's configurator ID and parameters */
    info = &lo->info;
    if (configurator_int_val(c->layout_id[idx][0], &l)) goto _noarg;
    info->conf_id = (unsigned int)l;
    info->name = strdup(c->layout_name[idx][0]);
    if (configurator_int_val(c->layout_sq_depth[idx][0], &l)) goto _noarg;
    info->sq_depth = (unsigned int)l;
    if (configurator_int_val(c->layout_sq_lwm[idx][0], &l)) goto _noarg;
    info->sq_lwm = (unsigned int)l;

    /* Partition */
    lo->part_count = p->ionode_count;
    lo->lp = (F_LO_PART_t *) calloc(sizeof(F_LO_PART_t), 1);
    if (!lo->lp) goto _nomem;
    lp = lo->lp;
    lp->layout = lo;
    lp->part_num = p->mynode.ionode_idx;
    if (pthread_rwlock_init(&lp->claimdec_lock, NULL)) goto _nomem;
    if (pthread_spin_init(&lp->alloc_lock, PTHREAD_PROCESS_PRIVATE))
	goto _nomem;
    INIT_LIST_HEAD(&lp->alloc_buckets);
    INIT_LIST_HEAD(&lp->claimdecq);

    /* Devices */
    count = idx; /* layout section index */
    assert( configurator_get_sizes(c, "layout", "devices", &count) );
    all_pdevs = (count <= 0);
    if (all_pdevs) {
	/* no layout devices list given - default to pool devices */
	count = p->info.dev_count;
    } else {
	if (!IN_RANGE((unsigned)count, 1, p->info.dev_count))
	    goto _noarg;
    }
    lo->devlist_sz = info->devnum = (unsigned)count;

    /* parse layout's moniker */
    if (f_layout_parse_name(info)) goto _noarg;
    info->stripe_sz = info->chunk_sz*info->data_chunks;
    info->cv_intl_factor = ilog2(lo->info.slab_stripes);

    lo->devlist = (F_POOLDEV_INDEX_t *) calloc(sizeof(F_POOLDEV_INDEX_t),
	lo->devlist_sz);
    if (!lo->devlist) goto _nomem;
    pdi_max_idx = 0;
    pdi = lo->devlist;
    for (u = uu = 0; u < info->devnum; u++, uu++, pdi++) {
	/* find pool device by id */
	if (all_pdevs) {
	    pdev = &p->devlist[uu];
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
	    if (pdi_max_idx < pdev->pool_index)
		pdi_max_idx = pdev->pool_index;
	    pdi->idx_ag = pdev->idx_ag;
	    pdi->idx_dev = pdev->idx_dev;
	    /* Allocate the device index shareable atomics */
	    pdi->sha = (F_PDI_SHA_t *) calloc(sizeof(F_PDI_SHA_t), 1);
	    if (!pdi->sha) goto _nomem;
	    pdi->sha->io.flags = pdev->sha->io.flags;
	}
    }

    /* Sort by AG first, then by pool index */
    qsort(lo->devlist, lo->devlist_sz, sizeof(F_POOLDEV_INDEX_t), cmp_pdi);

    /* Build fast pdi access array */
    info->pdi_max_idx = pdi_max_idx;
    info->pdi_by_media = (uint16_t *) calloc(pdi_max_idx+1, sizeof(uint16_t));
    for (u = 0; u <= info->pdi_max_idx; u++)
	info->pdi_by_media[u] = find_pdi(lo, u);

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
    int rc = -1;

    if (cfg && pool == NULL) {
	int flag;

	f_crc4_init_table();
	if ((rc = cfg_load(cfg)))
	    return rc;
	if ((rc = MPI_Initialized(&flag)) != MPI_SUCCESS) {
		err("MPI_Initialized failed:%d", rc);
		return rc;
	}
	if (flag)
	    rc = mpi_comm_dup(&pool->helper_comm, NULL);
    }
    return rc;
}

/* Get layout 'layout_id' info */
F_LAYOUT_t *f_get_layout(int layout_id) {
    struct list_head *l;
    F_LAYOUT_t *lo;

    if (pool) {
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

int f_free_layouts_info(void)
{
    F_LAYOUT_t *lo;
    struct list_head *l, *tmp;
    int rc = 0;

    if (pool) {
	list_for_each_safe(l, tmp, &pool->layouts) {
	    lo = container_of(l, struct f_layout_, list);
	    list_del(l);
	    free_layout(lo);
	}
	rc = free_pool(pool);
	pool = NULL;
    }
    return rc;
}

static void print_lf_info(LF_INFO_t *info) {
    LF_MR_MODE_t m = info->mrreg;
    LF_PRG_MODE_t pgs = info->progress;
    LF_OPTS_t o = info->opts;

    printf("\nlibfabric\n");
    printf("provider:%s fabric:%s domain:%s service:%d timeout:%.3f sec\n",
	info->provider, info->fabric, info->domain, info->service,
	(float)info->io_timeout_ms/1000);
    printf("MR mode: %s%s%s%s%s%s\n",
	m.scalable?"scalable, ":"", m.basic?"basic, ":"",
	m.local?"local, ":"", m.prov_key?"prov_key, ":"",
	m. virt_addr?"virt_addr, ":"", m.allocated?"allocated":"");
    printf("Data/control progress: %s%s\n",
	pgs.progress_manual?"manual ":"", pgs.progress_auto?"progress_auto":"");
    printf("Options: %s%s%s%s\n",
	o.zhpe_support?"zhpe_support, ":"", o.true_fam?"true_fam, ":"",
	o.use_cq?"use_cq, ":"", info->single_ep?"single_EP":"multiple_EPs");
}

void f_print_layouts(void) {
    F_POOL_t *p = pool;
    F_POOL_INFO_t *pool_info;
    F_AG_t *ag;
    F_POOL_DEV_t *pdev;
    F_LAYOUT_t *lo;
    char pr_uuid[F_UUID_BUF_SIZE];
    struct list_head *l, *tmp;
    uint16_t *pdi_by_media_id;
    unsigned int u, uu;

    if (p == NULL)
	return;
    /* Pool */
    printf("FS mode:%s%s%s\n",
    PoolFAMFS(pool)?"FAMFS ":"", PoolUNIFYCR(pool)?"UNIFYCR ":"", PoolFAMEmul(pool)?"Emul":"");
    pool_info = &p->info;
    printf("Pool has %u devices in %u AGs, %u each\n",
	pool_info->dev_count, p->pool_ags, p->ag_devs);
    ag = p->ags;
    for (u = 0; u < p->pool_ags; u++, ag++) {
	pdev = ((F_POOL_DEV_t (*)[p->ag_devs]) p->devlist)[u];
	printf("  AG#%u id:%u has %u devices at ionode id:%u\n",
	       u, ag->gid, ag->pdis,
	       p->ionodes[ag->ionode_idx].conf_id);
	for (uu = 0; uu < ag->pdis; uu++, pdev++) {
	    F_ZFM_t *zfm;

	    assert( pdev->pool_index != F_PDI_NONE );
	    uuid_unparse(pdev->uuid, pr_uuid);
	    printf ("  %s [%u,%u] id:%u uuid:%s size:%zu\n",
		DevFailed(pdev->sha)?"F":" ",
		pdev->idx_ag, pdev->idx_dev, pdev->pool_index,
		pr_uuid, pdev->size);
	    zfm=&pdev->dev->f.zfm;
	    printf("    znode:%s topo:%s geo:%s at ionode id:%u\n",
		zfm->znode, zfm->topo, zfm->geo,
		p->ionodes[pdev->dev->f.ionode_idx].conf_id);
	}
    }
    /* report min, max device media_id and max extents */
    pdi_by_media_id = pool_info->pdi_by_media;
    for (u = 0; u <= pool_info->pdev_max_idx; u++, pdi_by_media_id++)
	if (*pdi_by_media_id != F_PDI_NONE)
	    break;
    printf("  pool media_id range is %u to %u, of %u extents at most.\n",
	   u, pool_info->pdev_max_idx, pool_info->max_extents);
    printf("  lfa_port:%d commit queue hwm:%d, TMO:%d sec.\n",
	   pool_info->lfa_port, pool_info->cq_hwm,  pool_info->cq_hwm_tmo);
    printf("  enabled pool cache(s): %s%s%s\n",
	   PoolWCache(p)?"W,":"", PoolRCache(p)?"R,":"", (PoolWCache(p)||PoolRCache(p))?"":"NONE");

    /* IO nodes */
    printf("Configuration has %u IO nodes:\n", p->ionode_count);
    for (u = 0; u < p->ionode_count; u++) {
	F_IONODE_INFO_t *info = &p->ionodes[u];

	printf("  #%u%s id:%u %s MDS:%u flags:%s znode:%s topo:%s geo:%s\n",
	    u, (u == p->mynode.ionode_idx && NodeIsIOnode(&p->mynode))?"*":"",
	    info->conf_id, info->hostname, info->mds,
	    IOnodeForceHelper(info)?"H":"",
	    info->zfm.znode, info->zfm.topo, info->zfm.geo);
    }

    /* libfabric info */
    print_lf_info(p->lf_info);

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
	printf("  preallocated stripes queue depth:%d, low water mark %d %%.\n",
	    info->sq_depth, info->sq_lwm);
	printf("  This layout has %u device(s), including %u missing.\n",
	    info->devnum, info->misdevnum);
	pdi = lo->devlist;
	for (u = 0; u < lo->devlist_sz; u++, pdi++) {
	    if (pdi->pool_index == F_PDI_NONE)
		continue;
	    //assert( pdi == f_find_pdi_by_media_id(lo, pdi->pool_index) );
	    printf("  dev#%u media id:%u [%u,%u] ext size/used/failed:%u/%u/%u\n",
		u, pdi->pool_index, pdi->idx_ag, pdi->idx_dev,
		((F_POOL_DEV_t (*)[p->ag_devs]) p->devlist)
			[pdi->idx_ag][pdi->idx_dev].extent_count,
		pdi->sha->extents_used, pdi->sha->failed_extents);
	}
	printf("  Layout partition:%u\n", lo->lp->part_num);
    }
}

#if 0
/* Is 'hostname' in IO nodes list? If NULL, check my node name */
int f_host_is_ionode(const char *hostname)
{
    if (hostname)
	return !!get_ionode_info(pool, hostname);

    return pool && NodeIsIOnode(&pool->mynode);
}

/* Is 'hostname' a MD server? If NULL, check my node name */
int f_host_is_mds(const char *hostname)
{
    if (hostname) {
	F_IONODE_INFO_t *info = get_ionode_info(pool, hostname);

	return info && info->mds;
    }
    return pool && NodeHasMDS(&pool->mynode);
}
#endif

int f_get_lo_stripe_sizes(F_POOL_t *p, size_t **stripe_sz_per_lo) {
    F_LAYOUT_t *lo;
    size_t *stripe_sizes = *stripe_sz_per_lo;
    int rc = 0;

    if (stripe_sizes == NULL)
	stripe_sizes = malloc(p->info.layouts_count * sizeof(size_t));
    if (stripe_sizes == NULL)
	return -ENOMEM;

    list_for_each_entry(lo, &p->layouts, list) {
	ASSERT( lo->info.conf_id < p->info.layouts_count );
	stripe_sizes[lo->info.conf_id] = lo->info.stripe_sz;
	rc++;
    }
    if (*stripe_sz_per_lo == NULL && rc > 0)
	*stripe_sz_per_lo = stripe_sizes;
    return rc;
}

