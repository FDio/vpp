/*
 *------------------------------------------------------------------
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
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
  clib_error_t *err =
    sfdp_interface_input_set_tenant (vim, sw_if_index, tenant_id, unset);
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
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
