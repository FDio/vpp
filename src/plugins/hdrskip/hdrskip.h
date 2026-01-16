/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#ifndef __included_hdrskip_h__
#define __included_hdrskip_h__

#include <vnet/vnet.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* Per-interface byte counts */
  u32 *input_skip_by_sw_if_index;
  u32 *output_restore_by_sw_if_index;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} hdrskip_main_t;

extern hdrskip_main_t hdrskip_main;

#define HDRSKIP_MAX_ADJUST ((u32) 0x7fff)

int hdrskip_input_enable_disable (hdrskip_main_t *hsm, u32 sw_if_index,
				  int enable_disable, u32 skip_bytes,
				  int set_bytes);
int hdrskip_output_enable_disable (hdrskip_main_t *hsm, u32 sw_if_index,
				   int enable_disable, u32 restore_bytes,
				   int set_bytes);

#endif /* __included_hdrskip_h__ */
