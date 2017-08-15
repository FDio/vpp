/*
 *------------------------------------------------------------------
 * tcp_api.c - vnet tcp-layer apis
 *
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vnet/tcp/tcp.h>

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

#define foreach_tcp_api_msg                                     \
_(TCP_CONFIGURE_SRC_ADDRESSES, tcp_configure_src_addresses)

static void
  vl_api_tcp_configure_src_addresses_t_handler
  (vl_api_tcp_configure_src_addresses_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_tcp_configure_src_addresses_reply_t *rmp;
  u32 vrf_id;
  int rv;

  vrf_id = clib_net_to_host_u32 (mp->vrf_id);

  if (mp->is_ipv6)
    rv = tcp_configure_v6_source_address_range
      (vm,
       (ip6_address_t *) mp->first_address,
       (ip6_address_t *) mp->last_address, vrf_id);
  else
    rv = tcp_configure_v4_source_address_range
      (vm,
       (ip4_address_t *) mp->first_address,
       (ip4_address_t *) mp->last_address, vrf_id);

  REPLY_MACRO (VL_API_TCP_CONFIGURE_SRC_ADDRESSES_REPLY);
}

#define vl_msg_name_crc_list
#include <vnet/tcp/tcp.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_tcp;
#undef _
}

static clib_error_t *
tcp_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_tcp_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (tcp_api_hookup);

void
tcp_api_reference (void)
{
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
