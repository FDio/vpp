/*
 *------------------------------------------------------------------
 * cop_api.c - cop api
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
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg                                     \
_(COP_INTERFACE_ENABLE_DISABLE, cop_interface_enable_disable)   \
_(COP_WHITELIST_ENABLE_DISABLE, cop_whitelist_enable_disable)

typedef struct
{
  u32 sw_if_index;
  u8 ip4;
  u8 ip6;
  u8 default_cop;
  u32 fib_id;
} cop_whitelist_enable_disable_args_t;

/*
 * This API will be deprecated in vpp 20.12.
 *
 * Continue to support it for the moment if the "adl" plugin
 * is loaded...
 */
static int default_interface_enable_disable_callback
  (u32 sw_if_index, int enable_disable)
{
  return VNET_API_ERROR_UNIMPLEMENTED;
}

static int (*interface_enable_disable_callback) (u32, int) =
  default_interface_enable_disable_callback;

void
register_vl_api_cop_interface_enable_disable_callback (void *cb)
{
  interface_enable_disable_callback = cb;
}

static void vl_api_cop_interface_enable_disable_t_handler
  (vl_api_cop_interface_enable_disable_t * mp)
{
  vl_api_cop_interface_enable_disable_reply_t *rmp;
  int rv;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int enable_disable;

  VALIDATE_SW_IF_INDEX (mp);

  enable_disable = (int) mp->enable_disable;

  rv = (*interface_enable_disable_callback) (sw_if_index, enable_disable);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_COP_INTERFACE_ENABLE_DISABLE_REPLY);
}

/*
 * This API will be deprecated in vpp 20.12.
 *
 * Continue to support it for the moment if the "adl" plugin
 * is loaded...
 */

static int default_whitelist_enable_disable_callback
  (cop_whitelist_enable_disable_args_t * a)
{
  return VNET_API_ERROR_UNIMPLEMENTED;
}

static int (*whitelist_enable_disable_callback)
  (cop_whitelist_enable_disable_args_t * a) =
  default_whitelist_enable_disable_callback;

void
register_vl_api_cop_whitelist_enable_disable_callback (void *cb)
{
  whitelist_enable_disable_callback = cb;
}

static void vl_api_cop_whitelist_enable_disable_t_handler
  (vl_api_cop_whitelist_enable_disable_t * mp)
{
  vl_api_cop_whitelist_enable_disable_reply_t *rmp;
  cop_whitelist_enable_disable_args_t _a, *a = &_a;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  a->sw_if_index = sw_if_index;
  a->ip4 = mp->ip4;
  a->ip6 = mp->ip6;
  a->default_cop = mp->default_cop;
  a->fib_id = ntohl (mp->fib_id);

  rv = (*whitelist_enable_disable_callback) (a);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_COP_WHITELIST_ENABLE_DISABLE_REPLY);
}

/*
 * cop_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_cop;
#undef _
}

static clib_error_t *
cop_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (cop_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
