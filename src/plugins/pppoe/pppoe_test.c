/*
 * Copyright (c) 2017 Intel and/or its affiliates.
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
#include <pppoe/pppoe.h>
#include <vnet/format_fns.h>

#include <vnet/ip/ip_types_api.h>

#define __plugin_msg_base pppoe_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>


uword unformat_ip46_address (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  ip46_type_t type = va_arg (*args, ip46_type_t);
  if ((type != IP46_TYPE_IP6) &&
      unformat(input, "%U", unformat_ip4_address, &ip46->ip4)) {
    ip46_address_mask_ip4(ip46);
    return 1;
  } else if ((type != IP46_TYPE_IP4) &&
      unformat(input, "%U", unformat_ip6_address, &ip46->ip6)) {
    return 1;
  }
  return 0;
}
uword unformat_ip46_prefix (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  u8 *len = va_arg (*args, u8 *);
  ip46_type_t type = va_arg (*args, ip46_type_t);

  u32 l;
  if ((type != IP46_TYPE_IP6) && unformat(input, "%U/%u", unformat_ip4_address, &ip46->ip4, &l)) {
    if (l > 32)
      return 0;
    *len = l + 96;
    ip46->pad[0] = ip46->pad[1] = ip46->pad[2] = 0;
  } else if ((type != IP46_TYPE_IP4) && unformat(input, "%U/%u", unformat_ip6_address, &ip46->ip6, &l)) {
    if (l > 128)
      return 0;
    *len = l;
  } else {
    return 0;
  }
  return 1;
}
/////////////////////////

#include <pppoe/pppoe.api_enum.h>
#include <pppoe/pppoe.api_types.h>

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} pppoe_test_main_t;

pppoe_test_main_t pppoe_test_main;

static void vl_api_pppoe_add_del_session_reply_t_handler
  (vl_api_pppoe_add_del_session_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);
  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      vam->sw_if_index = ntohl (mp->sw_if_index);
      vam->result_ready = 1;
    }
}

static int
api_pppoe_add_del_session (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_pppoe_add_del_session_t *mp;
  u16 session_id = 0;
  ip46_address_t client_ip;
  u8 is_add = 1;
  u8 client_ip_set = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  u32 decap_vrf_id = 0;
  u8 client_mac[6] = { 0 };
  u8 client_mac_set = 0;
  int ret;

  /* Can't "universally zero init" (={0}) due to GCC bug 53119 */
  clib_memset (&client_ip, 0, sizeof client_ip);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (line_input, "session_id %d", &session_id))
	;
      else if (unformat (line_input, "client-ip %U",
			 unformat_ip4_address, &client_ip.ip4))
	{
	  client_ip_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "client-ip %U",
			 unformat_ip6_address, &client_ip.ip6))
	{
	  client_ip_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "decap-vrf-id %d", &decap_vrf_id))
        ;
      else if (unformat (line_input, "client-mac %U", unformat_ethernet_address, client_mac))
	client_mac_set = 1;
      else
	{
	  return -99;
	}
    }

  if (client_ip_set == 0)
    {
      errmsg ("session client_ip address not specified");
      return -99;
    }

  if (ipv4_set && ipv6_set)
    {
      errmsg ("both IPv4 and IPv6 addresses specified");
      return -99;
    }

  if (client_mac_set == 0)
    {
      errmsg("session client mac not specified");
      return -99;
    }

  M (PPPOE_ADD_DEL_SESSION, mp);


  if (ipv6_set)
    {
      ip_address_encode(&client_ip, IP46_TYPE_IP6, &mp->client_ip);
    }
  else
    {
      ip_address_encode(&client_ip, IP46_TYPE_IP4, &mp->client_ip);
    }

  mp->decap_vrf_id = ntohl (decap_vrf_id);
  mp->session_id = ntohl (session_id);
  mp->is_add = is_add;
  memcpy (mp->client_mac, client_mac, 6);

  S (mp);
  W (ret);
  return ret;
}

static void vl_api_pppoe_session_details_t_handler
  (vl_api_pppoe_session_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  ip46_address_t client_ip;
  ip_address_decode(&mp->client_ip, &client_ip);
  print (vam->ofp, "%11d%14d%24U%14d%14d%30U%30U",
       ntohl (mp->sw_if_index), ntohl (mp->session_id),
       format_ip46_address, &client_ip, IP46_TYPE_ANY,
       ntohl (mp->encap_if_index), ntohl (mp->decap_vrf_id),
       format_ethernet_address, mp->local_mac,
       format_ethernet_address, mp->client_mac);
}

static int
api_pppoe_session_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_pppoe_session_dump_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
      sw_if_index_set = 1;
      else
      break;
    }

  if (sw_if_index_set == 0)
    {
      sw_if_index = ~0;
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "%11s%24s%14s%14s%14s",
	   "sw_if_index", "client_ip", "session_id",
	   "encap_if_index", "decap_fib_index",
	   "local-mac", "client-mac");
    }

  /* Get list of pppoe-session interfaces */
  M (PPPOE_SESSION_DUMP, mp);

  mp->sw_if_index = htonl (sw_if_index);

  S (mp);

  W (ret);
  return ret;
}

#include <pppoe/pppoe.api_test.c>
