/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vnet/ip/ip_format_fns.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet_format_fns.h>
#include <l2tp/l2tp.h>

/* define message IDs */
#include <l2tp/l2tp.api_enum.h>
#include <l2tp/l2tp.api_types.h>
#include <vpp/api/vpe.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} l2tp_test_main_t;

l2tp_test_main_t l2tp_test_main;

#define __plugin_msg_base l2tp_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Macro to finish up custom dump fns */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

static void vl_api_l2tpv3_create_tunnel_reply_t_handler
  (vl_api_l2tpv3_create_tunnel_reply_t * mp)
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
api_l2tpv3_create_tunnel (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  ip6_address_t client_address, our_address;
  int client_address_set = 0;
  int our_address_set = 0;
  u32 local_session_id = 0;
  u32 remote_session_id = 0;
  u64 local_cookie = 0;
  u64 remote_cookie = 0;
  u8 l2_sublayer_present = 0;
  vl_api_l2tpv3_create_tunnel_t *mp;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "client_address %U", unformat_ip6_address,
		    &client_address))
	client_address_set = 1;
      else if (unformat (i, "our_address %U", unformat_ip6_address,
			 &our_address))
	our_address_set = 1;
      else if (unformat (i, "local_session_id %d", &local_session_id))
	;
      else if (unformat (i, "remote_session_id %d", &remote_session_id))
	;
      else if (unformat (i, "local_cookie %lld", &local_cookie))
	;
      else if (unformat (i, "remote_cookie %lld", &remote_cookie))
	;
      else if (unformat (i, "l2-sublayer-present"))
	l2_sublayer_present = 1;
      else
	break;
    }

  if (client_address_set == 0)
    {
      errmsg ("client_address required");
      return -99;
    }

  if (our_address_set == 0)
    {
      errmsg ("our_address required");
      return -99;
    }

  M (L2TPV3_CREATE_TUNNEL, mp);

  clib_memcpy (mp->client_address.un.ip6, client_address.as_u8,
	       sizeof (ip6_address_t));

  clib_memcpy (mp->our_address.un.ip6, our_address.as_u8,
	       sizeof (ip6_address_t));

  mp->local_session_id = ntohl (local_session_id);
  mp->remote_session_id = ntohl (remote_session_id);
  mp->local_cookie = clib_host_to_net_u64 (local_cookie);
  mp->remote_cookie = clib_host_to_net_u64 (remote_cookie);
  mp->l2_sublayer_present = l2_sublayer_present;

  S (mp);
  W (ret);
  return ret;
}

static int
api_l2tpv3_set_tunnel_cookies (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u64 new_local_cookie = 0;
  u64 new_remote_cookie = 0;
  vl_api_l2tpv3_set_tunnel_cookies_t *mp;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "new_local_cookie %lld", &new_local_cookie))
	;
      else if (unformat (i, "new_remote_cookie %lld", &new_remote_cookie))
	;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (L2TPV3_SET_TUNNEL_COOKIES, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->new_local_cookie = clib_host_to_net_u64 (new_local_cookie);
  mp->new_remote_cookie = clib_host_to_net_u64 (new_remote_cookie);

  S (mp);
  W (ret);
  return ret;
}

static int
api_l2tpv3_interface_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_l2tpv3_interface_enable_disable_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 enable_disable = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "enable"))
	enable_disable = 1;
      else if (unformat (i, "disable"))
	enable_disable = 0;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (L2TPV3_INTERFACE_ENABLE_DISABLE, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable_disable = enable_disable;

  S (mp);
  W (ret);
  return ret;
}

static int
api_l2tpv3_set_lookup_key (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_l2tpv3_set_lookup_key_t *mp;
  u8 key = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "lookup_v6_src"))
	key = L2T_LOOKUP_SRC_ADDRESS;
      else if (unformat (i, "lookup_v6_dst"))
	key = L2T_LOOKUP_DST_ADDRESS;
      else if (unformat (i, "lookup_session_id"))
	key = L2T_LOOKUP_SESSION_ID;
      else
	break;
    }

  if (key == (u8) ~ 0)
    {
      errmsg ("l2tp session lookup key unset");
      return -99;
    }

  M (L2TPV3_SET_LOOKUP_KEY, mp);

  mp->key = key;

  S (mp);
  W (ret);
  return ret;
}

static void vl_api_sw_if_l2tpv3_tunnel_details_t_handler
  (vl_api_sw_if_l2tpv3_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "* %U (our) %U (client) (sw_if_index %d)",
	 format_ip6_address, mp->our_address,
	 format_ip6_address, mp->client_address,
	 clib_net_to_host_u32 (mp->sw_if_index));

  print (vam->ofp,
	 "   local cookies %016llx %016llx remote cookie %016llx",
	 clib_net_to_host_u64 (mp->local_cookie[0]),
	 clib_net_to_host_u64 (mp->local_cookie[1]),
	 clib_net_to_host_u64 (mp->remote_cookie));

  print (vam->ofp, "   local session-id %d remote session-id %d",
	 clib_net_to_host_u32 (mp->local_session_id),
	 clib_net_to_host_u32 (mp->remote_session_id));

  print (vam->ofp, "   l2 specific sublayer %s\n",
	 mp->l2_sublayer_present ? "preset" : "absent");

}

static int
api_sw_if_l2tpv3_tunnel_dump (vat_main_t * vam)
{
  vl_api_sw_if_l2tpv3_tunnel_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  /* Get list of l2tpv3-tunnel interfaces */
  M (SW_IF_L2TPV3_TUNNEL_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  if (!l2tp_test_main.ping_id)
    l2tp_test_main.ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (l2tp_test_main.ping_id);
  mp_ping->client_index = vam->my_client_index;

  fformat (vam->ofp, "Sending ping id=%d\n", l2tp_test_main.ping_id);

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);
  return ret;
}

#include <l2tp/l2tp.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
