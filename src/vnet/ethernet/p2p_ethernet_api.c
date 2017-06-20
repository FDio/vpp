/*
 *------------------------------------------------------------------
 * p2p_ethernet_api.c - p2p ethernet api
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/vnet_msg_enum.h>
#include <vnet/ethernet/p2p_ethernet.h>

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

#define foreach_vpe_api_msg                               \
_(P2P_ETHERNET_ADD, p2p_ethernet_add)                     \
_(P2P_ETHERNET_DEL, p2p_ethernet_del)

void
vl_api_p2p_ethernet_add_t_handler (vl_api_p2p_ethernet_add_t * mp)
{
  vl_api_p2p_ethernet_add_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  int rv;

  u32 parent_if_index = htonl (mp->parent_if_index);
  u32 sub_id = htonl (mp->subif_id);
  u32 p2pe_if_index;
  u8 remote_mac[6];

  clib_memcpy (remote_mac, mp->remote_mac, 6);
  rv =
    p2p_ethernet_add_del (vm, parent_if_index, remote_mac, sub_id, 1,
			  &p2pe_if_index);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_P2P_ETHERNET_ADD_REPLY,
  ({
    rmp->sw_if_index = htonl(p2pe_if_index);
  }));
  /* *INDENT-ON* */
}

void
vl_api_p2p_ethernet_del_t_handler (vl_api_p2p_ethernet_del_t * mp)
{
  vl_api_p2p_ethernet_del_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  int rv;

  u32 parent_if_index = htonl (mp->parent_if_index);
  u8 remote_mac[6];

  clib_memcpy (remote_mac, mp->remote_mac, 6);
  rv = p2p_ethernet_add_del (vm, parent_if_index, remote_mac, ~0, 0, 0);

  REPLY_MACRO (VL_API_P2P_ETHERNET_DEL_REPLY);
}

/*
 * p2p_ethernet_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
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
  foreach_vl_msg_name_crc_p2p_ethernet;
#undef _
}

static clib_error_t *
p2p_ethernet_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

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

VLIB_API_INIT_FUNCTION (p2p_ethernet_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
