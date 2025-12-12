/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#ifndef included_clib_ptclosure_h
#define included_clib_ptclosure_h

#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>

/*
 * set r[i][j] if item i "bears the relation to" item j
 *
 */

u8 **clib_ptclosure_alloc (int n);
void clib_ptclosure_free (u8 ** ptc);
void clib_ptclosure_copy (u8 ** dst, u8 ** src);
u8 **clib_ptclosure (u8 ** orig);

#endif /* included_clib_ptclosure_h */
