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
      clib_memcpy (ap->mac_addr, mp->mac_address, 6);
      ap->mac_addr_set = 1;
    }
  ap->rx_ring_sz = ntohs (mp->rx_ring_sz);
  ap->tx_ring_sz = ntohs (mp->tx_ring_sz);
  ap->sw_if_index = (u32) ~ 0;

  if (mp->host_if_name_set)
    ap->host_if_name = mp->host_if_name;

  if (mp->host_mac_addr_set)
    {
      clib_memcpy (ap->host_mac_addr, mp->host_mac_addr, 6);
      ap->mac_addr_set = 1;
    }

  if (mp->host_namespace_set)
    ap->host_namespace = mp->host_namespace;

  if (mp->host_bridge_set)
    ap->host_bridge = mp->host_bridge;

  if (mp->host_ip4_addr_set)
    {
      clib_memcpy (&ap->host_ip4_addr.as_u8, mp->host_ip4_addr, 4);
      ap->host_ip4_prefix_len = mp->host_ip4_prefix_len;
    }

  if (mp->host_ip6_addr_set)
    {
      clib_memcpy (&ap->host_ip6_addr, mp->host_ip6_addr, 16);
      ap->host_ip6_prefix_len = mp->host_ip6_prefix_len;
    }

  if (mp->host_ip4_gw_set)
    {
      clib_memcpy (&ap->host_ip4_gw, mp->host_ip4_gw, 4);
      ap->host_ip4_gw_set = 1;
    }

  if (mp->host_ip6_gw_set)
    {
      clib_memcpy (&ap->host_ip6_gw, mp->host_ip6_gw, 16);
      ap->host_ip6_gw_set = 1;
    }

  ap->tap_flags = ntohl (mp->tap_flags);

  tap_create_if (vm, ap);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;;

  /* If a tag was supplied... */
  if (mp->tag[0])
    {
      /* Make sure it's a proper C-string */
      mp->tag[ARRAY_LEN (mp->tag) - 1] = 0;
      u8 *tag = format (0, "%s%c", mp->tag, 0);
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

  mp->admin_up_down = 0;
  mp->link_up_down = 0;
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
  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = htons (VL_API_SW_INTERFACE_TAP_V2_DETAILS);
  mp->id = htonl (tap_if->id);
  mp->sw_if_index = htonl (tap_if->sw_if_index);
  mp->tap_flags = htonl (tap_if->tap_flags);
  clib_memcpy (mp->dev_name, tap_if->dev_name,
	       MIN (ARRAY_LEN (mp->dev_name) - 1,
		    strlen ((const char *) tap_if->dev_name)));
  mp->rx_ring_sz = htons (tap_if->rx_ring_sz);
  mp->tx_ring_sz = htons (tap_if->tx_ring_sz);
  clib_memcpy (mp->host_mac_addr, tap_if->host_mac_addr, 6);
  clib_memcpy (mp->host_if_name, tap_if->host_if_name,
	       MIN (ARRAY_LEN (mp->host_if_name) - 1,
		    strlen ((const char *) tap_if->host_if_name)));
  clib_memcpy (mp->host_namespace, tap_if->host_namespace,
	       MIN (ARRAY_LEN (mp->host_namespace) - 1,
		    strlen ((const char *) tap_if->host_namespace)));
  clib_memcpy (mp->host_bridge, tap_if->host_bridge,
	       MIN (ARRAY_LEN (mp->host_bridge) - 1,
		    strlen ((const char *) tap_if->host_bridge)));
  if (tap_if->host_ip4_prefix_len)
    clib_memcpy (&mp->host_ip4_addr, &tap_if->host_ip4_addr, 4);
  mp->host_ip4_prefix_len = tap_if->host_ip4_prefix_len;
  if (tap_if->host_ip6_prefix_len)
    clib_memcpy (&mp->host_ip6_addr, &tap_if->host_ip6_addr, 16);
  mp->host_ip6_prefix_len = tap_if->host_ip6_prefix_len;

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
