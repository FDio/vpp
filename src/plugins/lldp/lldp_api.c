/*
 *------------------------------------------------------------------
 * lldp_api.c - lldp api
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

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <lldp/lldp.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_types_api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <lldp/lldp.api_enum.h>
#include <lldp/lldp.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 lldp_base_msg_id;
#define REPLY_MSG_ID_BASE lldp_base_msg_id

#include <vlibapi/api_helper_macros.h>

static void
vl_api_lldp_config_t_handler (vl_api_lldp_config_t * mp)
{
  vl_api_lldp_config_reply_t *rmp;
  int rv = 0;
  u8 *sys_name = 0;

  sys_name = vl_api_from_api_to_new_vec (mp, &mp->system_name);

  if (lldp_cfg_set (&sys_name, ntohl (mp->tx_hold), ntohl (mp->tx_interval))
      != lldp_ok)
    {
      vec_free (sys_name);
      rv = VNET_API_ERROR_INVALID_VALUE;
    }

  REPLY_MACRO (VL_API_LLDP_CONFIG_REPLY);
}

static void
vl_api_sw_interface_set_lldp_t_handler (vl_api_sw_interface_set_lldp_t * mp)
{
  vl_api_sw_interface_set_lldp_reply_t *rmp;
  int rv = 0;
  u8 *mgmt_oid = 0, *mgmt_ip4 = 0, *mgmt_ip6 = 0;
  char *port_desc = 0;
  u8 no_data[128] = { 0 };
  ip4_address_t ip4;
  ip6_address_t ip6;

  if (vl_api_string_len (&mp->port_desc) > 0)
    {
      port_desc = vl_api_from_api_to_new_c_string (&mp->port_desc);
    }

  ip4_address_decode (mp->mgmt_ip4, &ip4);

  if (ip4.as_u32 != 0)
    {
      vec_validate (mgmt_ip4, sizeof (ip4_address_t) - 1);
      clib_memcpy (mgmt_ip4, &ip4, vec_len (mgmt_ip4));
    }

  ip6_address_decode (mp->mgmt_ip6, &ip6);

  if (!ip6_address_is_zero (&ip6))
    {
      vec_validate (mgmt_ip6, sizeof (ip6_address_t) - 1);
      clib_memcpy (mgmt_ip6, &ip6, vec_len (mgmt_ip6));
    }

  if (memcmp (mp->mgmt_oid, no_data, strlen ((char *) mp->mgmt_oid)) != 0)
    {
      vec_validate (mgmt_oid, strlen ((char *) mp->mgmt_oid) - 1);
      strncpy ((char *) mgmt_oid, (char *) mp->mgmt_oid, vec_len (mgmt_oid));
    }

  VALIDATE_SW_IF_INDEX (mp);

  if (lldp_cfg_intf_set (ntohl (mp->sw_if_index), (u8 **) & port_desc,
			 &mgmt_ip4, &mgmt_ip6, &mgmt_oid,
			 mp->enable) != lldp_ok)
    {
      vec_free (port_desc);
      vec_free (mgmt_ip4);
      vec_free (mgmt_ip6);
      vec_free (mgmt_oid);
      rv = VNET_API_ERROR_INVALID_VALUE;
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_LLDP_REPLY);
}


/*
 *  * lldp_api_hookup
 *   * Add vpe's API message handlers to the table.
 *    * vlib has already mapped shared memory and
 *     * added the client registration handlers.
 *      * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 *       */
#include <lldp/lldp.api.c>

static clib_error_t *
lldp_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  lldp_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (lldp_api_hookup);

#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Link Layer Discovery Protocol (LLDP)",
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
