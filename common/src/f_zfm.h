/*
 * (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor
 *   Boston, MA 02110-1301, USA.
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

