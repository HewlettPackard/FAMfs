/*
 * Copyright (c) 2020, HPE
 *
 * Written by: Dmitry Ivanov
 */

#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
//#include <stdlib.h>
#include <string.h>
#include <malloc.h>

//#include "famfs_env.h"
//#include "famfs_error.h"
#include "f_layout.h"
#include "f_map.h"


/* Lookup device in lo->devlist by media_id */
F_POOLDEV_INDEX_t *f_find_pdi_by_media_id(F_LAYOUT_t *lo, unsigned int media_id)
{
    uint16_t idx;

    if (media_id > lo->info.pdi_max_idx)
	return NULL;

    idx = lo->info.pdi_by_media[media_id];
    return (idx >= lo->devlist_sz)? NULL:&lo->devlist[idx];
}

/* Print maps */

/* Print slab map entry line to buffer, return true if not mapped. */
static int sprint_slab_entry(char *buf, size_t *len_p,
    uint64_t sei, F_SLAB_ENTRY_t *se, uint32_t slab_stripes)
{
    unsigned char crc_error;
    size_t len;
    bool unjam = true;

    /* Entry (slab) number */
    len = sprintf(buf, "%lu", sei);

    /* Slab map entry: "<stripe_0>[ [*]r<recovered>][ F|D]" if mapped,
    or "unmapped" or "*CRC:0x<crc>" error. */
    crc_error = f_crc4_sm_chk(se);
    if (crc_error) {
	len += sprintf(buf+len, " *CRC:0x%02x", se->checksum);
    } else if (se->mapped) {
	len  += sprintf(buf+len, " %lu", se->stripe_0);

	if (se->recovery)
	    len += sprintf(buf+len, " r%u", se->recovered);
	else if (se->recovered && (uint32_t)se->recovered != slab_stripes)
	    len += sprintf(buf+len, " *r%u", se->recovered);

	if (se->failed || se->degraded)
	    len += sprintf(buf+len,
			   " %s%s", se->failed?"F":"", se->degraded?"D":"");
    } else {
	len += sprintf(buf+len, " unmapped");
	unjam = false;
    }
    *len_p = len;
    return unjam;
}

static int sprint_extent_entry(char *buf, size_t *len_p,
    F_EXTENT_ENTRY_t *ee, unsigned int eei, bool mapped)
{
    size_t len = *len_p;
    bool unjam = true;

    if (0 && f_crc4_fast_chk((void*)ee, (int)sizeof(*ee))) {
	len += sprintf(buf+len, " *ext_%d CRC:0x%02x", eei, ee->checksum);
    } else {
	/* Extent entry: "[media_id]:*MF extent" if mapped */
	if (!mapped && !ee->mapped)
	    unjam = false;
	else
	    len += sprintf(buf+len, " [%u]:%s%s %u",
			   ee->media_id,
			   (!mapped && ee->mapped)?"*M":"", ee->failed?"F":"",
			   ee->extent);
    }
    *len_p = len;
    return unjam;
}

/* Print the whole slab map to open FILE stream. */
#define SPRINT_LINE_MAX 1024
void f_print_sm(FILE *f, F_MAP_t *sm, uint16_t chunks, uint32_t slab_stripes)
{
    F_SLABMAP_ENTRY_t *sme;
    F_SLAB_ENTRY_t *se;
    F_EXTENT_ENTRY_t *ee;
    F_ITER_t *sm_it;
    size_t len;
    uint64_t sei;
    char *line;
    bool mapped, jam;
    unsigned int eei;

    assert( f_map_is_structured(sm) );
    line = (char*)calloc(SPRINT_LINE_MAX, sizeof(*line));
    jam = false; /* line jamming */
    mapped = true; /* for line jamming: not unmapped */

    fprintf(f, "*** SLAB MAP ***\n");
    /* Generic map description: KV size, in-memory size and so on */
    f_map_fprint_desc(f, sm);

    /* For all Slab map entries */
    sm_it = f_map_get_iter(sm, F_NO_CONDITION, 0);
    for_each_iter(sm_it) {
	sei = sm_it->entry;
	sme = (F_SLABMAP_ENTRY_t *) sm_it->word_p;
	se = &sme->slab_rec;
	jam = !mapped;
	mapped = !!se->mapped;
	len = 0;

	/* Slab map entry */
	if (sprint_slab_entry(line, &len, sei, se, slab_stripes))
	    jam = false;

	/* Extents */
	ee = sme->extent_rec;
	for (eei = 0; eei < chunks; eei++, ee++) {
	    if (sprint_extent_entry(line, &len, ee, eei, mapped))
		jam = false;
	}

	/* Print line */
	assert( len < SPRINT_LINE_MAX );
	*(line+len++) = '\n';
	if (!jam)
	    fwrite(line, len, 1, f);
    }
    f_map_free_iter(sm_it);

    /* Always print the bottom entry */
    if (jam)
	fwrite(line, len, 1, f);

    fprintf(f, "*** MAP END ***\n");
}
#undef SPRINT_LINE_MAX


