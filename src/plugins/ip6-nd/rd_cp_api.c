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

#include <ip6-nd/rd_cp.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <ip6-nd/rd_cp.api_enum.h>
#include <ip6-nd/rd_cp.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 rd_cp_base_msg_id;
#define REPLY_MSG_ID_BASE rd_cp_base_msg_id

#include <vlibapi/api_helper_macros.h>


static void
vl_api_ip6_nd_address_autoconfig_t_handler (vl_api_ip6_nd_address_autoconfig_t
					    * mp)
{
  vl_api_ip6_nd_address_autoconfig_reply_t *rmp;
  u32 sw_if_index;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);

  rv = rd_cp_set_address_autoconfig (sw_if_index,
				     mp->enable, mp->install_default_routes);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_IP6_ND_ADDRESS_AUTOCONFIG_REPLY);
}

#include <ip6-nd/rd_cp.api.c>

static clib_error_t *
rd_cp_api_init (vlib_main_t * vm)
{
  rd_cp_base_msg_id = setup_message_id_table ();

  return (NULL);
}

VLIB_INIT_FUNCTION (rd_cp_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
