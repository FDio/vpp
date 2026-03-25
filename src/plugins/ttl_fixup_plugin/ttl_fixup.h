/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

/* ttl_fixup.h - TTL/Hop-Limit fixup plugin header */

#ifndef __included_ttl_fixup_h__
#define __included_ttl_fixup_h__

#include <vnet/vnet.h>

typedef struct
{
  /* Per-interface enable flag for input features (indexed by sw_if_index) */
  u8 *input_enabled;

  /* Per-interface enable flag for output features (indexed by sw_if_index) */
  u8 *output_enabled;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vnet_main_t *vnet_main;
} ttl_fixup_main_t;

extern ttl_fixup_main_t ttl_fixup_main;

#endif /* __included_ttl_fixup_h__ */
