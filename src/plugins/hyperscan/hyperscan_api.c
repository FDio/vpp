/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Intel and/or its affiliates.
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
*
*/

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>

#include <hyperscan/hyperscan.h>


#define vl_msg_id(n,h) n,
typedef enum
{
#include <hyperscan/hyperscan.api.h>
  /* We'll want to know how many messages IDs we need... */
  VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* define message structures */
#define vl_typedefs
#include <hyperscan/hyperscan.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <hyperscan/hyperscan.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <hyperscan/hyperscan.api.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <hyperscan/hyperscan.api.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <hyperscan/hyperscan.api.h>
#undef vl_msg_name_crc_list

#define REPLY_MSG_ID_BASE hsm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
setup_message_id_table (hyperscan_main_t * hsm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + hsm->msg_id_base);
  foreach_vl_msg_name_crc_hyperscan;
#undef _
}

#define foreach_hyperscan_plugin_api_msg                             \
_(SW_INTERFACE_SET_HYPERSCAN_BYPASS, sw_interface_set_hyperscan_bypass)

static void
  vl_api_sw_interface_set_hyperscan_bypass_t_handler
  (vl_api_sw_interface_set_hyperscan_bypass_t * mp)
{
  vl_api_sw_interface_set_hyperscan_bypass_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  hyperscan_main_t *hsm = &hyperscan_main;

  VALIDATE_SW_IF_INDEX (mp);

  vnet_int_hyperscan_bypass (sw_if_index, mp->is_ipv6, mp->enable);
  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_HYPERSCAN_BYPASS_REPLY);
}



static clib_error_t *
hyperscan_api_hookup (vlib_main_t * vm)
{
  hyperscan_main_t *hsm = &hyperscan_main;

  u8 *name = format (0, "hyperscan_%08x%c", api_version, 0);
  hsm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + hsm->msg_id_base),     \
                           #n,                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_hyperscan_plugin_api_msg;
#undef _

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (hsm, &api_main);

  return 0;
}

VLIB_API_INIT_FUNCTION (hyperscan_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
