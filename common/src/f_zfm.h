/*
 * Copyright (c) 2017-2018, HPE
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#ifndef F_ZFM_H
#define F_ZFM_H

/* GenZ fabric manager data: ION or FAM */
typedef struct f_zfm_ {
	char		*url;		/* GenZ device URL */
	char		*znode;		/* node name */
	char		*topo;		/* ION or FAM topology */
	char		*geo;		/* geolocation; MFW model */
} F_ZFM_t;

#endif /* F_ZFM_H */

