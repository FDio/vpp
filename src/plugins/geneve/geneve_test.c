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

#include <vnet/ip/ip.h>
#include <vnet/ip/ip_types_api.h>
#include <geneve/geneve.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <geneve/geneve.api_enum.h>
#include <geneve/geneve.api_types.h>
#include <vpp/api/vpe.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} geneve_test_main_t;

geneve_test_main_t geneve_test_main;

#define __plugin_msg_base geneve_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Macro to finish up custom dump fns */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

static void vl_api_geneve_add_del_tunnel_reply_t_handler
  (vl_api_geneve_add_del_tunnel_reply_t * mp)
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

static void vl_api_geneve_add_del_tunnel2_reply_t_handler
  (vl_api_geneve_add_del_tunnel2_reply_t * mp)
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
api_sw_interface_set_geneve_bypass (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_geneve_bypass_t *mp;
  u32 sw_if_index = 0;
  u8 sw_if_index_set = 0;
  u8 is_enable = 1;
  u8 is_ipv6 = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "enable"))
	is_enable = 1;
      else if (unformat (i, "disable"))
	is_enable = 0;
      else if (unformat (i, "ip4"))
	is_ipv6 = 0;
      else if (unformat (i, "ip6"))
	is_ipv6 = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_SET_GENEVE_BYPASS, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable = is_enable;
  mp->is_ipv6 = is_ipv6;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static uword unformat_geneve_decap_next
  (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);
  u32 tmp;

  if (unformat (input, "l2"))
    *result = GENEVE_INPUT_NEXT_L2_INPUT;
  else if (unformat (input, "%d", &tmp))
    *result = tmp;
  else
    return 0;
  return 1;
}

static int
api_geneve_add_del_tunnel (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_geneve_add_del_tunnel_t *mp;
  ip46_address_t src, dst;
  u8 is_add = 1;
  u8 ipv4_set = 0, ipv6_set = 0;
  u8 src_set = 0;
  u8 dst_set = 0;
  u8 grp_set = 0;
  u32 mcast_sw_if_index = ~0;
  u32 encap_vrf_id = 0;
  u32 decap_next_index = ~0;
  u32 vni = 0;
  int ret;

  /* Can't "universally zero init" (={0}) due to GCC bug 53119 */
  clib_memset (&src, 0, sizeof src);
  clib_memset (&dst, 0, sizeof dst);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else
	if (unformat (line_input, "src %U", unformat_ip4_address, &src.ip4))
	{
	  ipv4_set = 1;
	  src_set = 1;
	}
      else
	if (unformat (line_input, "dst %U", unformat_ip4_address, &dst.ip4))
	{
	  ipv4_set = 1;
	  dst_set = 1;
	}
      else
	if (unformat (line_input, "src %U", unformat_ip6_address, &src.ip6))
	{
	  ipv6_set = 1;
	  src_set = 1;
	}
      else
	if (unformat (line_input, "dst %U", unformat_ip6_address, &dst.ip6))
	{
	  ipv6_set = 1;
	  dst_set = 1;
	}
      else if (unformat (line_input, "group %U %U",
			 unformat_ip4_address, &dst.ip4,
			 unformat_sw_if_index, vam, &mcast_sw_if_index))
	{
	  grp_set = dst_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "group %U",
			 unformat_ip4_address, &dst.ip4))
	{
	  grp_set = dst_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "group %U %U",
			 unformat_ip6_address, &dst.ip6,
			 unformat_sw_if_index, vam, &mcast_sw_if_index))
	{
	  grp_set = dst_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "group %U",
			 unformat_ip6_address, &dst.ip6))
	{
	  grp_set = dst_set = 1;
	  ipv6_set = 1;
	}
      else
	if (unformat (line_input, "mcast_sw_if_index %u", &mcast_sw_if_index))
	;
      else if (unformat (line_input, "encap-vrf-id %d", &encap_vrf_id))
	;
      else if (unformat (line_input, "decap-next %U",
			 unformat_geneve_decap_next, &decap_next_index))
	;
      else if (unformat (line_input, "vni %d", &vni))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, line_input);
	  return -99;
	}
    }

  if (src_set == 0)
    {
      errmsg ("tunnel src address not specified");
      return -99;
    }
  if (dst_set == 0)
    {
      errmsg ("tunnel dst address not specified");
      return -99;
    }

  if (grp_set && !ip46_address_is_multicast (&dst))
    {
      errmsg ("tunnel group address not multicast");
      return -99;
    }
  if (grp_set && mcast_sw_if_index == ~0)
    {
      errmsg ("tunnel nonexistent multicast device");
      return -99;
    }
  if (grp_set == 0 && ip46_address_is_multicast (&dst))
    {
      errmsg ("tunnel dst address must be unicast");
      return -99;
    }


  if (ipv4_set && ipv6_set)
    {
      errmsg ("both IPv4 and IPv6 addresses specified");
      return -99;
    }

  if ((vni == 0) || (vni >> 24))
    {
      errmsg ("vni not specified or out of range");
      return -99;
    }

  M (GENEVE_ADD_DEL_TUNNEL, mp);

  if (ipv6_set)
    {
      clib_memcpy (&mp->local_address.un.ip6, &src.ip6, sizeof (src.ip6));
      clib_memcpy (&mp->remote_address.un.ip6, &dst.ip6, sizeof (dst.ip6));
    }
  else
    {
      clib_memcpy (&mp->local_address.un.ip4, &src.ip4, sizeof (src.ip4));
      clib_memcpy (&mp->remote_address.un.ip4, &dst.ip4, sizeof (dst.ip4));
    }
  mp->encap_vrf_id = ntohl (encap_vrf_id);
  mp->decap_next_index = ntohl (decap_next_index);
  mp->mcast_sw_if_index = ntohl (mcast_sw_if_index);
  mp->vni = ntohl (vni);
  mp->is_add = is_add;

  S (mp);
  W (ret);
  return ret;
}

static int
api_geneve_add_del_tunnel2 (vat_main_t * vam)
{
  return api_geneve_add_del_tunnel (vam);
}

static void vl_api_geneve_tunnel_details_t_handler
  (vl_api_geneve_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  ip46_address_t src = {.as_u64[0] = 0,.as_u64[1] = 0 };
  ip46_address_t dst = {.as_u64[0] = 0,.as_u64[1] = 0 };

  if (mp->src_address.af == ADDRESS_IP6)
    {
      clib_memcpy (&src.ip6, &mp->src_address.un.ip6, sizeof (ip6_address_t));
      clib_memcpy (&dst.ip6, &mp->dst_address.un.ip6, sizeof (ip6_address_t));
    }
  else
    {
      clib_memcpy (&src.ip4, &mp->src_address.un.ip4, sizeof (ip4_address_t));
      clib_memcpy (&dst.ip4, &mp->dst_address.un.ip4, sizeof (ip4_address_t));
    }

  print (vam->ofp, "%11d%24U%24U%14d%18d%13d%19d",
	 ntohl (mp->sw_if_index),
	 format_ip46_address, &src, IP46_TYPE_ANY,
	 format_ip46_address, &dst, IP46_TYPE_ANY,
	 ntohl (mp->encap_vrf_id),
	 ntohl (mp->decap_next_index), ntohl (mp->vni),
	 ntohl (mp->mcast_sw_if_index));
}

static int
api_geneve_tunnel_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_geneve_tunnel_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
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
      print (vam->ofp, "%11s%24s%24s%14s%18s%13s%19s",
	     "sw_if_index", "local_address", "remote_address",
	     "encap_vrf_id", "decap_next_index", "vni", "mcast_sw_if_index");
    }

  /* Get list of geneve-tunnel interfaces */
  M (GENEVE_TUNNEL_DUMP, mp);

  mp->sw_if_index = htonl (sw_if_index);

  S (mp);

  /* Use a control ping for synchronization */
  if (!geneve_test_main.ping_id)
    geneve_test_main.ping_id =
      vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (geneve_test_main.ping_id);
  mp_ping->client_index = vam->my_client_index;

  fformat (vam->ofp, "Sending ping id=%d\n", geneve_test_main.ping_id);

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);
  return ret;
}

/* _(sw_interface_set_geneve_bypass,                                        */
/*   "<intfc> | sw_if_index <id> [ip4 | ip6] [enable | disable]")           */
/* _(geneve_add_del_tunnel,                                                 */
/*   "src <ip-addr> { dst <ip-addr> | group <mcast-ip-addr>\n"              */
/*   "{ <intfc> | mcast_sw_if_index <nn> } }\n"                             */
/*   "vni <vni> [encap-vrf-id <nn>] [decap-next <l2|nn>] [del]")            */
/* _(geneve_tunnel_dump, "[<intfc> | sw_if_index <nn>]")                    */


#include <geneve/geneve.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
