/*
 *------------------------------------------------------------------
 * adl_api.c - adl api
 *
 * Copyright (c) 2016,2020 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <adl/adl.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <adl/adl.api_enum.h>
#include <adl/adl.api_types.h>

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

#define REPLY_MSG_ID_BASE am->msg_id_base
#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg                                     \
_(ADL_INTERFACE_ENABLE_DISABLE, adl_interface_enable_disable)   \
_(ADL_LIST_ENABLE_DISABLE, adl_allowlist_enable_disable)

/*
 * Compatibility shim for the core engine cop_interface_enable_disable API,
 * which will be deprecated in vpp 20.12.
 */
int vl_api_cop_interface_enable_disable_callback
  (u32 sw_if_index, int enable_disable)
{
  return adl_interface_enable_disable (sw_if_index, enable_disable);
}

static void vl_api_adl_interface_enable_disable_t_handler
  (vl_api_adl_interface_enable_disable_t * mp)
{
  adl_main_t *am = &adl_main;
  vl_api_adl_interface_enable_disable_reply_t *rmp;
  int rv;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int enable_disable;

  VALIDATE_SW_IF_INDEX (mp);

  enable_disable = (int) mp->enable_disable;

  rv = adl_interface_enable_disable (sw_if_index, enable_disable);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_ADL_INTERFACE_ENABLE_DISABLE_REPLY);
}

/*
 * Compatibility shim for the core engine cop_whitelist_enable_disable API,
 * which will be deprecated in vpp 20.12.
 */
int vl_api_cop_whitelist_enable_disable_callback
  (adl_allowlist_enable_disable_args_t * a)
{
  return adl_allowlist_enable_disable (a);
}

static void vl_api_adl_allowlist_enable_disable_t_handler
  (vl_api_adl_allowlist_enable_disable_t * mp)
{
  adl_main_t *am = &adl_main;
  vl_api_adl_allowlist_enable_disable_reply_t *rmp;
  adl_allowlist_enable_disable_args_t _a, *a = &_a;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  a->sw_if_index = sw_if_index;
  a->ip4 = mp->ip4;
  a->ip6 = mp->ip6;
  a->default_adl = mp->default_adl;
  a->fib_id = ntohl (mp->fib_id);

  rv = adl_allowlist_enable_disable (a);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_ADL_ALLOWLIST_ENABLE_DISABLE_REPLY);
}

#include <adl/adl.api.c>
static clib_error_t *
adl_api_init (vlib_main_t * vm)
{
  adl_main_t *am = &adl_main;
  am->vlib_main = vm;

  /* Ask for a correctly-sized block of API message decode slots */
  am->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (adl_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
