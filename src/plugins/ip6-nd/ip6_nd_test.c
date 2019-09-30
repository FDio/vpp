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
#include <vpp/api/types.h>

#include <vnet/ip/ip_format_fns.h>
#include <vnet/ethernet/ethernet_format_fns.h>

/* define message IDs */
#include <ip6-nd/ip6_nd.api_enum.h>
#include <ip6-nd/ip6_nd.api_types.h>
#include <vpp/api/vpe.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} ip6_nd_test_main_t;

ip6_nd_test_main_t ip6_nd_test_main;

#define __plugin_msg_base ip6_nd_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

static int
api_want_ip6_ra_events (vat_main_t * vam)
{
  return -1;
}

static int
api_ip6nd_send_router_solicitation (vat_main_t * vam)
{
  return -1;
}

static int
api_ip6nd_proxy_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip6nd_proxy_add_del_t *mp;
  u32 sw_if_index = ~0;
  u8 v6_address_set = 0;
  vl_api_ip6_address_t v6address;
  u8 is_add = 1;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "%U", unformat_vl_api_ip6_address, &v6address))
	v6_address_set = 1;
      if (unformat (i, "del"))
	is_add = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }
  if (!v6_address_set)
    {
      errmsg ("no address set");
      return -99;
    }

  /* Construct the API message */
  M (IP6ND_PROXY_ADD_DEL, mp);

  mp->is_add = is_add;
  mp->sw_if_index = ntohl (sw_if_index);
  clib_memcpy (mp->ip, v6address, sizeof (v6address));

  /* send it... */
  S (mp);

  /* Wait for a reply, return good/bad news  */
  W (ret);
  return ret;
}

static int
api_ip6nd_proxy_dump (vat_main_t * vam)
{
  vl_api_ip6nd_proxy_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  M (IP6ND_PROXY_DUMP, mp);

  S (mp);

  /* Use a control ping for synchronization */
  /* Use a control ping for synchronization */
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (ip6_nd_test_main.ping_id);
  mp_ping->client_index = vam->my_client_index;
  vam->result_ready = 0;

  S (mp_ping);

  W (ret);
  return ret;
}

static void vl_api_ip6nd_proxy_details_t_handler
  (vl_api_ip6nd_proxy_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "host %U sw_if_index %d",
	 format_vl_api_ip6_address, mp->ip, ntohl (mp->sw_if_index));
}

static int
api_sw_interface_ip6nd_ra_prefix (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_ip6nd_ra_prefix_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 v6_address_set = 0;
  vl_api_prefix_t pfx;
  u8 use_default = 0;
  u8 no_advertise = 0;
  u8 off_link = 0;
  u8 no_autoconfig = 0;
  u8 no_onlink = 0;
  u8 is_no = 0;
  u32 val_lifetime = 0;
  u32 pref_lifetime = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "%U", unformat_vl_api_prefix, &pfx))
	v6_address_set = 1;
      else if (unformat (i, "val_life %d", &val_lifetime))
	;
      else if (unformat (i, "pref_life %d", &pref_lifetime))
	;
      else if (unformat (i, "def"))
	use_default = 1;
      else if (unformat (i, "noadv"))
	no_advertise = 1;
      else if (unformat (i, "offl"))
	off_link = 1;
      else if (unformat (i, "noauto"))
	no_autoconfig = 1;
      else if (unformat (i, "nolink"))
	no_onlink = 1;
      else if (unformat (i, "isno"))
	is_no = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }
  if (!v6_address_set)
    {
      errmsg ("no address set");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_IP6ND_RA_PREFIX, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  clib_memcpy (&mp->prefix, &pfx, sizeof (pfx));
  mp->use_default = use_default;
  mp->no_advertise = no_advertise;
  mp->off_link = off_link;
  mp->no_autoconfig = no_autoconfig;
  mp->no_onlink = no_onlink;
  mp->is_no = is_no;
  mp->val_lifetime = ntohl (val_lifetime);
  mp->pref_lifetime = ntohl (pref_lifetime);

  /* send it... */
  S (mp);

  /* Wait for a reply, return good/bad news  */
  W (ret);
  return ret;
}

static int
api_sw_interface_ip6nd_ra_config (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_ip6nd_ra_config_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 suppress = 0;
  u8 managed = 0;
  u8 other = 0;
  u8 ll_option = 0;
  u8 send_unicast = 0;
  u8 cease = 0;
  u8 is_no = 0;
  u8 default_router = 0;
  u32 max_interval = 0;
  u32 min_interval = 0;
  u32 lifetime = 0;
  u32 initial_count = 0;
  u32 initial_interval = 0;
  int ret;


  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "maxint %d", &max_interval))
	;
      else if (unformat (i, "minint %d", &min_interval))
	;
      else if (unformat (i, "life %d", &lifetime))
	;
      else if (unformat (i, "count %d", &initial_count))
	;
      else if (unformat (i, "interval %d", &initial_interval))
	;
      else if (unformat (i, "suppress") || unformat (i, "surpress"))
	suppress = 1;
      else if (unformat (i, "managed"))
	managed = 1;
      else if (unformat (i, "other"))
	other = 1;
      else if (unformat (i, "ll"))
	ll_option = 1;
      else if (unformat (i, "send"))
	send_unicast = 1;
      else if (unformat (i, "cease"))
	cease = 1;
      else if (unformat (i, "isno"))
	is_no = 1;
      else if (unformat (i, "def"))
	default_router = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_IP6ND_RA_CONFIG, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->max_interval = ntohl (max_interval);
  mp->min_interval = ntohl (min_interval);
  mp->lifetime = ntohl (lifetime);
  mp->initial_count = ntohl (initial_count);
  mp->initial_interval = ntohl (initial_interval);
  mp->suppress = suppress;
  mp->managed = managed;
  mp->other = other;
  mp->ll_option = ll_option;
  mp->send_unicast = send_unicast;
  mp->cease = cease;
  mp->is_no = is_no;
  mp->default_router = default_router;

  /* send it... */
  S (mp);

  /* Wait for a reply, return good/bad news  */
  W (ret);
  return ret;
}

#include <ip6-nd/ip6_nd.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
