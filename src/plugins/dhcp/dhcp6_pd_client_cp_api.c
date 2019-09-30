/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>

#include <dhcp/dhcp6_pd_client_dp.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <dhcp/dhcp6_pd_client_cp.api_enum.h>
#include <dhcp/dhcp6_pd_client_cp.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 dhcp_base_msg_id;
#define REPLY_MSG_ID_BASE dhcp_base_msg_id

#include <vlibapi/api_helper_macros.h>

static void
  vl_api_dhcp6_pd_client_enable_disable_t_handler
  (vl_api_dhcp6_pd_client_enable_disable_t * mp)
{
  vl_api_dhcp6_pd_client_enable_disable_reply_t *rmp;
  u32 sw_if_index;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);

  rv = dhcp6_pd_client_enable_disable (sw_if_index,
				       mp->prefix_group, mp->enable);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_DHCP6_PD_CLIENT_ENABLE_DISABLE_REPLY);
}

static void
  vl_api_ip6_add_del_address_using_prefix_t_handler
  (vl_api_ip6_add_del_address_using_prefix_t * mp)
{
  vl_api_ip6_add_del_address_using_prefix_reply_t *rmp;
  u32 sw_if_index;
  ip6_address_t address;
  u8 prefix_length;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);

  ip6_address_decode (mp->address_with_prefix.address, &address);
  prefix_length = mp->address_with_prefix.len;

  rv = dhcp6_cp_ip6_address_add_del (sw_if_index, mp->prefix_group, address,
				     prefix_length, mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_IP6_ADD_DEL_ADDRESS_USING_PREFIX_REPLY);
}

#define vl_msg_name_crc_list
#include <dhcp/dhcp6_pd_client_cp.api.c>
#undef vl_msg_name_crc_list

static clib_error_t *
dhcp_pd_client_cp_api_init (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  dhcp_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (dhcp_pd_client_cp_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
