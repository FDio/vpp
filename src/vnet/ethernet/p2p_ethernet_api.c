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
#include <vnet/ethernet/p2p_ethernet.h>

#include <vnet/format_fns.h>
#include <vnet/ethernet/p2p_ethernet.api_enum.h>
#include <vnet/ethernet/p2p_ethernet.api_types.h>

#define REPLY_MSG_ID_BASE p2p_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

void
vl_api_p2p_ethernet_add_t_handler (vl_api_p2p_ethernet_add_t * mp)
{
  vl_api_p2p_ethernet_add_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  int rv;

  u32 parent_if_index = htonl (mp->parent_if_index);
  u32 sub_id = htonl (mp->subif_id);
  u32 p2pe_if_index = ~0;
  u8 remote_mac[6];

  if (!vnet_sw_if_index_is_api_valid (parent_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto bad_sw_if_index;
    }
  if (!vnet_sw_if_index_is_api_valid (sub_id))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX_2;
      goto bad_sw_if_index;
    }

  clib_memcpy (remote_mac, mp->remote_mac, 6);
  rv =
    p2p_ethernet_add_del (vm, parent_if_index, remote_mac, sub_id, 1,
			  &p2pe_if_index);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO2(VL_API_P2P_ETHERNET_ADD_REPLY,
  ({
    rmp->sw_if_index = htonl(p2pe_if_index);
  }));


}

void
vl_api_p2p_ethernet_del_t_handler (vl_api_p2p_ethernet_del_t * mp)
{
  vl_api_p2p_ethernet_del_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  int rv;

  u32 parent_if_index = htonl (mp->parent_if_index);
  u8 remote_mac[6];

  if (!vnet_sw_if_index_is_api_valid (parent_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto bad_sw_if_index;
    }

  clib_memcpy (remote_mac, mp->remote_mac, 6);
  rv = p2p_ethernet_add_del (vm, parent_if_index, remote_mac, ~0, 0, 0);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_P2P_ETHERNET_DEL_REPLY);
}

#include <vnet/ethernet/p2p_ethernet.api.c>
static clib_error_t *
p2p_ethernet_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

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
