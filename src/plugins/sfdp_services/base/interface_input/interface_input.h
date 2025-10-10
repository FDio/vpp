/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_nat_h__
#define __included_nat_h__

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>

typedef struct
{
  u16 *tenant_idx_by_sw_if_idx; /* vec */
  u16 msg_id_base;
} sfdp_interface_input_main_t;

extern sfdp_interface_input_main_t sfdp_interface_input_main;

clib_error_t *
sfdp_interface_input_set_tenant (sfdp_interface_input_main_t *nat,
				 u32 sw_if_index, u32 tenant_id, u8 unset);
#endif