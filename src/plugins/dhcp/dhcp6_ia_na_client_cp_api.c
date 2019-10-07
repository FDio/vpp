/*
 *------------------------------------------------------------------
 * dhcp_api.c - dhcp api
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

#include <dhcp/dhcp6_ia_na_client_dp.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <dhcp/dhcp6_ia_na_client_cp.api_enum.h>
#include <dhcp/dhcp6_ia_na_client_cp.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 dhcp_base_msg_id;
#define REPLY_MSG_ID_BASE dhcp_base_msg_id

#include <vlibapi/api_helper_macros.h>

static void
  vl_api_dhcp6_client_enable_disable_t_handler
  (vl_api_dhcp6_client_enable_disable_t * mp)
{
  vl_api_dhcp6_client_enable_disable_reply_t *rmp;
  u32 sw_if_index;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);

  rv = dhcp6_client_enable_disable (sw_if_index, mp->enable);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_DHCP6_CLIENT_ENABLE_DISABLE_REPLY);
}

#define vl_msg_name_crc_list
#include <dhcp/dhcp6_ia_na_client_cp.api.c>
#undef vl_msg_name_crc_list

static clib_error_t *
dhcp_ia_na_client_cp_api_init (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  dhcp_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (dhcp_ia_na_client_cp_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
