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
#include <vnet/lldp/lldp.h>

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

#define foreach_vpe_api_msg                             \
_(LLDP_CONFIG, lldp_config)                             \
_(SW_INTERFACE_SET_LLDP, sw_interface_set_lldp)

static void
vl_api_lldp_config_t_handler (vl_api_lldp_config_t * mp)
{
  vl_api_lldp_config_reply_t *rmp;
  int rv = 0;
  u8 *sys_name = 0;

  vec_validate (sys_name, strlen ((char *) mp->system_name) - 1);
  strncpy ((char *) sys_name, (char *) mp->system_name, vec_len (sys_name));

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
  u8 *port_desc = 0, *mgmt_ip4 = 0, *mgmt_ip6 = 0, *mgmt_oid = 0;
  u8 no_data[256];

  clib_memset (no_data, 0, 256);

  if (memcmp (mp->port_desc, no_data, strlen ((char *) mp->port_desc)) != 0)
    {
      vec_validate (port_desc, strlen ((char *) mp->port_desc) - 1);
      strncpy ((char *) port_desc, (char *) mp->port_desc,
	       vec_len (port_desc));
    }

  if (memcmp (mp->mgmt_ip4, no_data, sizeof (mp->mgmt_ip4)) != 0)
    {
      vec_validate (mgmt_ip4, sizeof (mp->mgmt_ip4) - 1);
      clib_memcpy (mgmt_ip4, mp->mgmt_ip4, vec_len (mgmt_ip4));
    }

  if (memcmp (mp->mgmt_ip6, no_data, sizeof (mp->mgmt_ip6)) != 0)
    {
      vec_validate (mgmt_ip6, sizeof (mp->mgmt_ip6) - 1);
      clib_memcpy (mgmt_ip6, mp->mgmt_ip6, vec_len (mgmt_ip6));
    }

  if (memcmp (mp->mgmt_oid, no_data, strlen ((char *) mp->mgmt_oid)) != 0)
    {
      vec_validate (mgmt_oid, strlen ((char *) mp->mgmt_oid) - 1);
      strncpy ((char *) mgmt_oid, (char *) mp->mgmt_oid, vec_len (mgmt_oid));
    }

  VALIDATE_SW_IF_INDEX (mp);

  if (lldp_cfg_intf_set (ntohl (mp->sw_if_index), &port_desc,
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
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_lldp;
#undef _
}

static clib_error_t *
lldp_api_hookup (vlib_main_t * vm)
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
   *    * Set up the (msg_name, crc, message-id) table
   *       */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (lldp_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
