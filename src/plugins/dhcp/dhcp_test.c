/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>

#include <dhcp/client.h>
#include <dhcp/dhcp_proxy.h>
#include <vnet/ip/ip_format_fns.h>
#include <vnet/ethernet/ethernet_format_fns.h>

/* define message IDs */
#include <dhcp/dhcp.api_enum.h>
#include <dhcp/dhcp.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} dhcp_test_main_t;

dhcp_test_main_t dhcp_test_main;

#define __plugin_msg_base dhcp_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Macro to finish up custom dump fns */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

static int
api_dhcp_proxy_config (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_dhcp_proxy_config_t *mp;
  u32 rx_vrf_id = 0;
  u32 server_vrf_id = 0;
  u8 is_add = 1;
  u8 v4_address_set = 0;
  u8 v6_address_set = 0;
  ip4_address_t v4address;
  ip6_address_t v6address;
  u8 v4_src_address_set = 0;
  u8 v6_src_address_set = 0;
  ip4_address_t v4srcaddress;
  ip6_address_t v6srcaddress;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "rx_vrf_id %d", &rx_vrf_id))
	;
      else if (unformat (i, "server_vrf_id %d", &server_vrf_id))
	;
      else if (unformat (i, "svr %U", unformat_ip4_address, &v4address))
	v4_address_set = 1;
      else if (unformat (i, "svr %U", unformat_ip6_address, &v6address))
	v6_address_set = 1;
      else if (unformat (i, "src %U", unformat_ip4_address, &v4srcaddress))
	v4_src_address_set = 1;
      else if (unformat (i, "src %U", unformat_ip6_address, &v6srcaddress))
	v6_src_address_set = 1;
      else
	break;
    }

  if (v4_address_set && v6_address_set)
    {
      errmsg ("both v4 and v6 server addresses set");
      return -99;
    }
  if (!v4_address_set && !v6_address_set)
    {
      errmsg ("no server addresses set");
      return -99;
    }

  if (v4_src_address_set && v6_src_address_set)
    {
      errmsg ("both v4 and v6  src addresses set");
      return -99;
    }
  if (!v4_src_address_set && !v6_src_address_set)
    {
      errmsg ("no src addresses set");
      return -99;
    }

  if (!(v4_src_address_set && v4_address_set) &&
      !(v6_src_address_set && v6_address_set))
    {
      errmsg ("no matching server and src addresses set");
      return -99;
    }

  /* Construct the API message */
  M (DHCP_PROXY_CONFIG, mp);

  mp->is_add = is_add;
  mp->rx_vrf_id = ntohl (rx_vrf_id);
  mp->server_vrf_id = ntohl (server_vrf_id);
  if (v6_address_set)
    {
      clib_memcpy (&mp->dhcp_server.un, &v6address, sizeof (v6address));
      clib_memcpy (&mp->dhcp_src_address.un, &v6srcaddress,
		   sizeof (v6address));
    }
  else
    {
      clib_memcpy (&mp->dhcp_server.un, &v4address, sizeof (v4address));
      clib_memcpy (&mp->dhcp_src_address.un, &v4srcaddress,
		   sizeof (v4address));
    }

  /* send it... */
  S (mp);

  /* Wait for a reply, return good/bad news  */
  W (ret);
  return ret;
}

#define vl_api_dhcp_proxy_details_t_endian vl_noop_handler
#define vl_api_dhcp_proxy_details_t_print vl_noop_handler

static void
vl_api_dhcp_proxy_details_t_handler (vl_api_dhcp_proxy_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 i, count = mp->count;
  vl_api_dhcp_server_t *s;

  if (mp->is_ipv6)
    print (vam->ofp,
	   "RX Table-ID %d, Source Address %U, VSS Type %d, "
	   "VSS ASCII VPN-ID '%s', VSS RFC2685 VPN-ID (oui:id) %d:%d",
	   ntohl (mp->rx_vrf_id),
	   format_ip6_address, mp->dhcp_src_address,
	   mp->vss_type, mp->vss_vpn_ascii_id,
	   ntohl (mp->vss_oui), ntohl (mp->vss_fib_id));
  else
    print (vam->ofp,
	   "RX Table-ID %d, Source Address %U, VSS Type %d, "
	   "VSS ASCII VPN-ID '%s', VSS RFC2685 VPN-ID (oui:id) %d:%d",
	   ntohl (mp->rx_vrf_id),
	   format_ip4_address, mp->dhcp_src_address,
	   mp->vss_type, mp->vss_vpn_ascii_id,
	   ntohl (mp->vss_oui), ntohl (mp->vss_fib_id));

  for (i = 0; i < count; i++)
    {
      s = &mp->servers[i];

      if (mp->is_ipv6)
	print (vam->ofp,
	       " Server Table-ID %d, Server Address %U",
	       ntohl (s->server_vrf_id), format_ip6_address, s->dhcp_server);
      else
	print (vam->ofp,
	       " Server Table-ID %d, Server Address %U",
	       ntohl (s->server_vrf_id), format_ip4_address, s->dhcp_server);
    }
}

static int
api_dhcp_proxy_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_dhcp_plugin_control_ping_t *mp_ping;
  vl_api_dhcp_proxy_dump_t *mp;
  u8 is_ipv6 = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (DHCP_PROXY_DUMP, mp);

  mp->is_ip6 = is_ipv6;
  S (mp);

  /* Use a control ping for synchronization */
  MPING (DHCP_PLUGIN_CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_dhcp_proxy_set_vss (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_dhcp_proxy_set_vss_t *mp;
  u8 is_ipv6 = 0;
  u8 is_add = 1;
  u32 tbl_id = ~0;
  u8 vss_type = VSS_TYPE_DEFAULT;
  u8 *vpn_ascii_id = 0;
  u32 oui = 0;
  u32 fib_id = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "tbl_id %d", &tbl_id))
	;
      else if (unformat (i, "vpn_ascii_id %s", &vpn_ascii_id))
	vss_type = VSS_TYPE_ASCII;
      else if (unformat (i, "fib_id %d", &fib_id))
	vss_type = VSS_TYPE_VPN_ID;
      else if (unformat (i, "oui %d", &oui))
	vss_type = VSS_TYPE_VPN_ID;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	break;
    }

  if (tbl_id == ~0)
    {
      errmsg ("missing tbl_id ");
      vec_free (vpn_ascii_id);
      return -99;
    }

  if ((vpn_ascii_id) && (vec_len (vpn_ascii_id) > 128))
    {
      errmsg ("vpn_ascii_id cannot be longer than 128 ");
      vec_free (vpn_ascii_id);
      return -99;
    }

  M (DHCP_PROXY_SET_VSS, mp);
  mp->tbl_id = ntohl (tbl_id);
  mp->vss_type = vss_type;
  if (vpn_ascii_id)
    {
      clib_memcpy (mp->vpn_ascii_id, vpn_ascii_id, vec_len (vpn_ascii_id));
      mp->vpn_ascii_id[vec_len (vpn_ascii_id)] = 0;
    }
  mp->vpn_index = ntohl (fib_id);
  mp->oui = ntohl (oui);
  mp->is_ipv6 = is_ipv6;
  mp->is_add = is_add;

  S (mp);
  W (ret);

  vec_free (vpn_ascii_id);
  return ret;
}

static int
api_dhcp_client_config (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_dhcp_client_config_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 is_add = 1;
  u8 *hostname = 0;
  u8 disable_event = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "hostname %s", &hostname))
	;
      else if (unformat (i, "disable_event"))
	disable_event = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (vec_len (hostname) > 63)
    {
      errmsg ("hostname too long");
    }
  vec_add1 (hostname, 0);

  /* Construct the API message */
  M (DHCP_CLIENT_CONFIG, mp);

  mp->is_add = is_add;
  mp->client.sw_if_index = htonl (sw_if_index);
  clib_memcpy (mp->client.hostname, hostname, vec_len (hostname));
  vec_free (hostname);
  mp->client.want_dhcp_event = disable_event ? 0 : 1;
  mp->client.pid = htonl (getpid ());

  /* send it... */
  S (mp);

  /* Wait for a reply, return good/bad news  */
  W (ret);
  return ret;
}

static int
api_want_dhcp6_reply_events (vat_main_t * vam)
{
  return -1;
}

static int
api_want_dhcp6_pd_reply_events (vat_main_t * vam)
{
  return -1;
}

static int
api_dhcp6_send_client_message (vat_main_t * vam)
{
  return -1;
}

static int
api_dhcp6_pd_send_client_message (vat_main_t * vam)
{
  return -1;
}

static int
api_dhcp_client_dump (vat_main_t * vam)
{
  return -1;
}

static int
api_dhcp6_duid_ll_set (vat_main_t * vam)
{
  return -1;
}

static int
api_dhcp6_clients_enable_disable (vat_main_t * vam)
{
  return -1;
}

static int
api_dhcp_plugin_control_ping (vat_main_t * vam)
{
  return -1;
}

static int
api_dhcp_plugin_get_version (vat_main_t * vam)
{
  return -1;
}

#define vl_api_dhcp_client_details_t_handler vl_noop_handler

static void
  vl_api_dhcp_plugin_get_version_reply_t_handler
  (vl_api_dhcp_plugin_get_version_reply_t * mp)
{
  vat_main_t *vam = dhcp_test_main.vat_main;
  clib_warning ("DHCP plugin version: %d.%d", ntohl (mp->major),
		ntohl (mp->minor));
  vam->result_ready = 1;
}

static void
  vl_api_dhcp_plugin_control_ping_reply_t_handler
  (vl_api_dhcp_plugin_control_ping_reply_t * mp)
{
  vat_main_t *vam = dhcp_test_main.vat_main;
  i32 retval = ntohl (mp->retval);
  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      vam->result_ready = 1;
    }
}

#include <dhcp/dhcp.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
