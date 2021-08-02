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
 */

/*
 * Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 *
 * Copyright 2017, UT-Battelle, LLC.
 *
 * LLNL-CODE-741539
 * All rights reserved.
 *
 * This is the license for UnifyCR.
 * For details, see https://github.com/LLNL/UnifyCR.
 * Please read https://github.com/LLNL/UnifyCR/LICENSE for full license text.
 */

/*
 * Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * Copyright (c) 2017, Florida State University. Contributions from
 * the Computer Architecture and Systems Research Laboratory (CASTL)
 * at the Department of Computer Science.
 *
 * Written by: Teng Wang, Adam Moody, Weikuan Yu, Kento Sato, Kathryn Mohror
 * LLNL-CODE-728877. All rights reserved.
 *
 * This file is part of burstfs.
 * For details, see https://github.com/llnl/burstfs
 * Please read https://github.com/llnl/burstfs/LICENSE for full license text.
 */

/*
 *
 * Copyright (c) 2014, Los Alamos National Laboratory
 *	All rights reserved.
 *
 */

#ifndef      __LOCAL_CLIENT_H
#define      __LOCAL_CLIENT_H

#include "messages.h"

struct mdhim_rm_t *local_client_put(struct mdhim_t *md, struct mdhim_putm_t *pm);
struct mdhim_rm_t *local_client_bput(struct mdhim_t *md, struct mdhim_bputm_t *bpm);
struct mdhim_bgetrm_t *local_client_bget(struct mdhim_t *md, struct mdhim_bgetm_t *bgm);
struct mdhim_bgetrm_t *local_client_bget_op(struct mdhim_t *md, struct mdhim_getm_t *gm);
struct mdhim_rm_t *local_client_commit(struct mdhim_t *md, struct mdhim_basem_t *cm);
struct mdhim_rm_t *local_client_delete(struct mdhim_t *md, struct mdhim_delm_t *dm);
struct mdhim_rm_t *local_client_bdelete(struct mdhim_t *md, struct mdhim_bdelm_t *dm);
void local_client_close(struct mdhim_t *md, struct mdhim_basem_t *cm);

#endif
