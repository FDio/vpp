/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#ifndef __CNAT_MAGLEV_H__
#define __CNAT_MAGLEV_H__

#include <cnat/cnat_types.h>
#include <cnat/cnat_translation.h>

typedef struct
{
  /* offset & skip used for sorting, should be first */
  u32 offset;
  u32 skip;
  u32 index;
} cnat_maglev_perm_t;

extern void cnat_translation_init_maglev (cnat_translation_t *ct);

#endif