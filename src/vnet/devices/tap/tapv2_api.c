/*
 *------------------------------------------------------------------
 * tap_api.c - vnet tap device driver API support
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
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>

#include <vnet/ethernet/ethernet_types_api.h>
#include <vnet/ip/ip_types_api.h>

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
#include <vnet/devices/tap/tap.h>

#define foreach_tapv2_api_msg                     \
_(TAP_CREATE_V2, tap_create_v2)                   \
_(TAP_DELETE_V2, tap_delete_v2)                   \
_(SW_INTERFACE_TAP_V2_DUMP, sw_interface_tap_v2_dump)

static void
vl_api_tap_create_v2_t_handler (vl_api_tap_create_v2_t * mp)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  vl_api_tap_create_v2_reply_t *rmp;
  vl_api_registration_t *reg;
  tap_create_if_args_t _a, *ap = &_a;

  clib_memset (ap, 0, sizeof (*ap));

  ap->id = ntohl (mp->id);
  if (!mp->use_random_mac)
    {
      mac_address_decode (mp->mac_address, &ap->mac_addr);
      ap->mac_addr_set = 1;
    }
  ap->rx_ring_sz = ntohs (mp->rx_ring_sz);
  ap->tx_ring_sz = ntohs (mp->tx_ring_sz);
  ap->sw_if_index = (u32) ~ 0;

  if (mp->host_if_name_set)
    ap->host_if_name = vl_api_from_api_string (&mp->host_if_name);

  if (mp->host_mac_addr_set)
    {
      mac_address_decode (mp->host_mac_addr, &ap->host_mac_addr);
      ap->mac_addr_set = 1;
    }

  if (mp->host_namespace_set)
    ap->host_namespace = vl_api_from_api_string (&mp->host_namespace);

  if (mp->host_bridge_set)
    ap->host_bridge = vl_api_from_api_string (&mp->host_bridge);

  if (mp->host_ip4_prefix_set)
    {
      ip4_address_decode (mp->host_ip4_prefix.address, &ap->host_ip4_addr);
      ap->host_ip4_prefix_len = mp->host_ip4_prefix.len;
    }

  if (mp->host_ip6_prefix_set)
    {
      ip6_address_decode (mp->host_ip6_prefix.address, &ap->host_ip6_addr);
      ap->host_ip6_prefix_len = mp->host_ip6_prefix.len;
    }

  if (mp->host_ip4_gw_set)
    {
      ip4_address_decode (mp->host_ip4_gw, &ap->host_ip4_gw);
      ap->host_ip4_gw_set = 1;
    }

  if (mp->host_ip6_gw_set)
    {
      ip6_address_decode (mp->host_ip6_gw, &ap->host_ip6_gw);
      ap->host_ip6_gw_set = 1;
    }

  if (mp->host_mtu_set)
    {
      ap->host_mtu_size = ntohl (mp->host_mtu_size);
      ap->host_mtu_set = 1;
    }

  ap->tap_flags = ntohl (mp->tap_flags);

  tap_create_if (vm, ap);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;;

  /* If a tag was supplied... */
  if (vl_api_string_len (&mp->tag))
    {
      u8 *tag = format (0, "%s%c", vl_api_from_api_string (&mp->tag), 0);
      vnet_set_sw_interface_tag (vnm, tag, ap->sw_if_index);
    }


  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_TAP_CREATE_V2_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (ap->rv);
  rmp->sw_if_index = ntohl (ap->sw_if_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
tap_send_sw_interface_event_deleted (vpe_api_main_t * am,
				     vl_api_registration_t * reg,
				     u32 sw_if_index)
{
  vl_api_sw_interface_event_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_EVENT);
  mp->sw_if_index = ntohl (sw_if_index);

  mp->flags = 0;
  mp->deleted = 1;
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_tap_delete_v2_t_handler (vl_api_tap_delete_v2_t * mp)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  int rv;
  vpe_api_main_t *vam = &vpe_api_main;
  vl_api_tap_delete_v2_reply_t *rmp;
  vl_api_registration_t *reg;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  rv = tap_delete_if (vm, sw_if_index);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_TAP_DELETE_V2_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);

  vl_api_send_msg (reg, (u8 *) rmp);

  if (!rv)
    {
      vnet_clear_sw_interface_tag (vnm, sw_if_index);
      tap_send_sw_interface_event_deleted (vam, reg, sw_if_index);
    }
}

static void
tap_send_sw_interface_details (vpe_api_main_t * am,
			       vl_api_registration_t * reg,
			       tap_interface_details_t * tap_if, u32 context)
{
  vl_api_sw_interface_tap_v2_details_t *mp;
  char *p;
  u32 dev_name_len = strlen ((const char *) tap_if->dev_name);
  u32 host_if_name_len = strlen ((const char *) tap_if->host_if_name);
  u32 host_namespace_len = strlen ((const char *) tap_if->host_namespace);
  u32 host_bridge_len = strlen ((const char *) tap_if->host_bridge);

  mp = vl_msg_api_alloc (sizeof (*mp) + dev_name_len + host_if_name_len +
			 host_namespace_len + host_bridge_len);
  clib_memset (mp, 0, sizeof (*mp) + dev_name_len + host_if_name_len +
	       host_namespace_len + host_bridge_len);
  mp->_vl_msg_id = htons (VL_API_SW_INTERFACE_TAP_V2_DETAILS);
  mp->id = htonl (tap_if->id);
  mp->sw_if_index = htonl (tap_if->sw_if_index);
  mp->tap_flags = htonl (tap_if->tap_flags);

  mp->rx_ring_sz = htons (tap_if->rx_ring_sz);
  mp->tx_ring_sz = htons (tap_if->tx_ring_sz);
  mac_address_encode (&tap_if->host_mac_addr, mp->host_mac_addr);

  if (tap_if->host_ip4_prefix_len)
    ip4_address_encode (&tap_if->host_ip4_addr, mp->host_ip4_prefix.address);
  mp->host_ip4_prefix.len = tap_if->host_ip4_prefix_len;
  if (tap_if->host_ip6_prefix_len)
    ip6_address_encode (&tap_if->host_ip6_addr, mp->host_ip6_prefix.address);
  mp->host_ip6_prefix.len = tap_if->host_ip6_prefix_len;

  p = (char *) &mp->dev_name;
  p +=
    vl_api_to_api_string (dev_name_len, (char *) tap_if->dev_name,
			  &mp->dev_name);
  p +=
    vl_api_to_api_string (host_if_name_len, (char *) tap_if->host_if_name,
			  (vl_api_string_t *) p);
  p +=
    vl_api_to_api_string (host_namespace_len, (char *) tap_if->host_namespace,
			  (vl_api_string_t *) p);
  p +=
    vl_api_to_api_string (host_bridge_len, (char *) tap_if->host_bridge,
			  (vl_api_string_t *) p);

  mp->context = context;
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_sw_interface_tap_v2_dump_t_handler (vl_api_sw_interface_tap_v2_dump_t *
					   mp)
{
  int rv;
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  tap_interface_details_t *tapifs = NULL;
  tap_interface_details_t *tap_if = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rv = tap_dump_ifs (&tapifs);
  if (rv)
    return;

  vec_foreach (tap_if, tapifs)
  {
    tap_send_sw_interface_details (am, reg, tap_if, mp->context);
  }

  vec_free (tapifs);
}

#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
tap_setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_tapv2;
#undef _
}

static clib_error_t *
tapv2_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_tapv2_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  tap_setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (tapv2_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
