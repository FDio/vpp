/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/sfdp/sfdp.h>

#include <sfdp_services/base/interface_input/interface_input.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>

#include <vnet/format_fns.h>
#include <sfdp_services/base/interface_input/interface_input.api_enum.h>
#include <sfdp_services/base/interface_input/interface_input.api_types.h>

#define REPLY_MSG_ID_BASE vim->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_sfdp_interface_input_set_t_handler (
  vl_api_sfdp_interface_input_set_t *mp)
{
  sfdp_interface_input_main_t *vim = &sfdp_interface_input_main;
  u32 sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  u32 tenant_id = clib_net_to_host_u32 (mp->tenant_id);
  u8 unset = mp->is_disable;
  u8 is_ip6 = mp->is_ip6;
  u8 offload = mp->is_offload_enabled;
  clib_error_t *err =
    sfdp_interface_input_set_tenant (vim, sw_if_index, tenant_id, is_ip6, offload, unset);
  int rv = err ? -1 : 0;
  vl_api_sfdp_interface_input_set_reply_t *rmp;
  REPLY_MACRO (VL_API_SFDP_INTERFACE_INPUT_SET_REPLY);
}

#include <sfdp_services/base/interface_input/interface_input.api.c>
static clib_error_t *
sfdp_interface_input_api_hookup (vlib_main_t *vm)
{
  sfdp_interface_input_main_t *vim = &sfdp_interface_input_main;
  vim->msg_id_base = setup_message_id_table ();
  return 0;
}
VLIB_API_INIT_FUNCTION (sfdp_interface_input_api_hookup);
