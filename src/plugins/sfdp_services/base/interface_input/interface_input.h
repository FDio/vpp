/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_sfdp_interface_input_h__
#define __included_sfdp_interface_input_h__

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>

#define INTERFACE_INPUT_INVALID_TENANT_IDX (sfdp_tenant_index_t) (~0)

typedef enum
{
  SFDP_INTERFACE_INPUT_PROTO_IP4,
  SFDP_INTERFACE_INPUT_PROTO_IP6,
  SFDP_INTERFACE_INPUT_PROTO_N_TYPES,
} sfdp_interface_input_proto_t;

typedef struct
{
  u32 *tenant_idx_by_sw_if_idx[SFDP_INTERFACE_INPUT_PROTO_N_TYPES];
  u16 msg_id_base;
} sfdp_interface_input_main_t;

extern sfdp_interface_input_main_t sfdp_interface_input_main;

clib_error_t *sfdp_interface_input_set_tenant (sfdp_interface_input_main_t *vim, u32 sw_if_index,
					       sfdp_tenant_id_t tenant_id, u8 is_ip6, u8 unset);
#endif /* __included_sfdp_interface_input_h__ */