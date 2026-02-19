/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_sfdp_interface_input_h__
#define __included_sfdp_interface_input_h__

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>

typedef enum
{
  SFDP_INTERFACE_INPUT_PROTO_IP4,
  SFDP_INTERFACE_INPUT_PROTO_IP6,
  SFDP_INTERFACE_INPUT_PROTO_N_TYPES,
} sfdp_interface_input_proto_t;

typedef struct
{
  u16 *tenant_idx_by_sw_if_idx[SFDP_INTERFACE_INPUT_PROTO_N_TYPES]; /* vec */
  u8 *offload_enabled_by_sw_if_idx[SFDP_INTERFACE_INPUT_PROTO_N_TYPES]; /* vec */
  u16 msg_id_base;
} sfdp_interface_input_main_t;

extern sfdp_interface_input_main_t sfdp_interface_input_main;

clib_error_t *sfdp_interface_input_set_tenant (sfdp_interface_input_main_t *vim, u32 sw_if_index,
					       u32 tenant_id, u8 is_ip6, u8 offload, u8 unset);
#endif /* __included_sfdp_interface_input_h__ */