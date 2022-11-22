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

#include <unistd.h>
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <gtpu/gtpu.h>
#include <vnet/ip/ip_types_api.h>

#define __plugin_msg_base gtpu_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

#include <vnet/format_fns.h>
#include <gtpu/gtpu.api_enum.h>
#include <gtpu/gtpu.api_types.h>

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

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} gtpu_test_main_t;

gtpu_test_main_t gtpu_test_main;

static void vl_api_gtpu_add_del_tunnel_reply_t_handler
  (vl_api_gtpu_add_del_tunnel_reply_t * mp)
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

static uword
api_unformat_hw_if_index (unformat_input_t * input, va_list * args)
{
  return 0;
}

static int
api_sw_interface_set_gtpu_bypass (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_gtpu_bypass_t *mp;
  u32 sw_if_index = 0;
  u8 sw_if_index_set = 0;
  u8 is_enable = 1;
  u8 is_ipv6 = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
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
  M (SW_INTERFACE_SET_GTPU_BYPASS, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable = is_enable;
  mp->is_ipv6 = is_ipv6;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static uword unformat_gtpu_decap_next
  (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);
  u32 tmp;

  if (unformat (input, "l2"))
    *result = GTPU_INPUT_NEXT_L2_INPUT;
  else if (unformat (input, "%d", &tmp))
    *result = tmp;
  else
    return 0;
  return 1;
}

static int
api_gtpu_offload_rx (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_gtpu_offload_rx_t *mp;
  u32 rx_sw_if_index = ~0;
  u32 hw_if_index = ~0;
  int is_add = 1;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
		  if (unformat (line_input, "hw %U", api_unformat_hw_if_index, vam, &hw_if_index))
		    ;
		  else
		  if (unformat (line_input, "rx %U", api_unformat_sw_if_index, vam, &rx_sw_if_index))
		    ;
		  else
      if (unformat (line_input, "del"))
      {
	is_add = 0;
	continue;
	    }
      else
      {
	errmsg ("parse error '%U'", format_unformat_error, line_input);
	return -99;
      }
    }

  if (rx_sw_if_index == ~0)
    {
      errmsg ("missing rx interface");
      return -99;
    }

  if (hw_if_index == ~0)
    {
      errmsg ("missing hw interface");
      return -99;
    }

  M (GTPU_OFFLOAD_RX, mp);
  mp->hw_if_index = ntohl (hw_if_index);
  mp->sw_if_index = ntohl (rx_sw_if_index);
  mp->enable = is_add;

  S (mp);
  W (ret);
  return ret;
}

static int
api_gtpu_add_del_tunnel (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_gtpu_add_del_tunnel_t *mp;
  ip46_address_t src, dst;
  u8 is_add = 1;
  u8 ipv4_set = 0, ipv6_set = 0;
  u8 src_set = 0;
  u8 dst_set = 0;
  u8 grp_set = 0;
  u32 mcast_sw_if_index = ~0;
  u32 encap_vrf_id = 0;
  u32 decap_next_index = ~0;
  u32 teid = 0, tteid = 0;
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
		       api_unformat_sw_if_index, vam, &mcast_sw_if_index))
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
		       api_unformat_sw_if_index, vam, &mcast_sw_if_index))
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
		       unformat_gtpu_decap_next, &decap_next_index))
      ;
      else if (unformat (line_input, "teid %d", &teid))
	;
      else if (unformat (line_input, "tteid %d", &tteid))
	;
      else
      {
	errmsg ("parse error '%U'", format_unformat_error, line_input);
	return -99;
      }
    }

  if (is_add && src_set == 0)
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

  M (GTPU_ADD_DEL_TUNNEL, mp);

  ip_address_encode(&src, ipv6_set ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		    &mp->src_address);
  ip_address_encode(&dst, ipv6_set ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		    &mp->dst_address);
  mp->encap_vrf_id = ntohl (encap_vrf_id);
  mp->decap_next_index = ntohl (decap_next_index);
  mp->mcast_sw_if_index = ntohl (mcast_sw_if_index);
  mp->teid = ntohl (teid);
  mp->tteid = ntohl (tteid);
  mp->is_add = is_add;

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_gtpu_add_del_tunnel_v2_reply_t_handler (
  vl_api_gtpu_add_del_tunnel_v2_reply_t *mp)
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
api_gtpu_add_del_tunnel_v2 (vat_main_t *vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_gtpu_add_del_tunnel_v2_t *mp;
  ip46_address_t src, dst;
  u8 is_add = 1;
  u8 ipv4_set = 0, ipv6_set = 0;
  u8 src_set = 0;
  u8 dst_set = 0;
  u8 grp_set = 0;
  u32 mcast_sw_if_index = ~0;
  u32 encap_vrf_id = 0;
  u32 decap_next_index = ~0;
  u32 teid = 0, tteid = 0;
  u8 pdu_extension = 0;
  u32 qfi = 0;
  int ret;

  /* Can't "universally zero init" (={0}) due to GCC bug 53119 */
  clib_memset (&src, 0, sizeof src);
  clib_memset (&dst, 0, sizeof dst);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "src %U", unformat_ip4_address, &src.ip4))
	{
	  ipv4_set = 1;
	  src_set = 1;
	}
      else if (unformat (line_input, "dst %U", unformat_ip4_address, &dst.ip4))
	{
	  ipv4_set = 1;
	  dst_set = 1;
	}
      else if (unformat (line_input, "src %U", unformat_ip6_address, &src.ip6))
	{
	  ipv6_set = 1;
	  src_set = 1;
	}
      else if (unformat (line_input, "dst %U", unformat_ip6_address, &dst.ip6))
	{
	  ipv6_set = 1;
	  dst_set = 1;
	}
      else if (unformat (line_input, "group %U %U", unformat_ip4_address,
			 &dst.ip4, api_unformat_sw_if_index, vam,
			 &mcast_sw_if_index))
	{
	  grp_set = dst_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "group %U", unformat_ip4_address,
			 &dst.ip4))
	{
	  grp_set = dst_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "group %U %U", unformat_ip6_address,
			 &dst.ip6, api_unformat_sw_if_index, vam,
			 &mcast_sw_if_index))
	{
	  grp_set = dst_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "group %U", unformat_ip6_address,
			 &dst.ip6))
	{
	  grp_set = dst_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "mcast_sw_if_index %u",
			 &mcast_sw_if_index))
	;
      else if (unformat (line_input, "encap-vrf-id %d", &encap_vrf_id))
	;
      else if (unformat (line_input, "decap-next %U", unformat_gtpu_decap_next,
			 &decap_next_index))
	;
      else if (unformat (line_input, "teid %d", &teid)) /* Change to %u ? */
	;
      else if (unformat (line_input, "tteid %d", &tteid)) /* Change to %u ? */
	;
      else if (unformat (line_input, "qfi %u", &qfi))
	pdu_extension = 1;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, line_input);
	  return -99;
	}
    }

  if (is_add && src_set == 0)
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
  if (qfi > 31)
    {
      errmsg ("qfi max value is 31");
      return -99;
    }

  M (GTPU_ADD_DEL_TUNNEL_V2, mp);

  ip_address_encode (&src, ipv6_set ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &mp->src_address);
  ip_address_encode (&dst, ipv6_set ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &mp->dst_address);
  mp->encap_vrf_id = ntohl (encap_vrf_id);
  mp->decap_next_index = ntohl (decap_next_index);
  mp->mcast_sw_if_index = ntohl (mcast_sw_if_index);
  mp->teid = ntohl (teid);
  mp->tteid = ntohl (tteid);
  mp->is_add = is_add;
  mp->pdu_extension = pdu_extension;
  mp->qfi = ntohl (qfi);

  S (mp);
  W (ret);
  return ret;
}
static int
api_gtpu_tunnel_update_tteid (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_gtpu_tunnel_update_tteid_t *mp;
  ip46_address_t dst;
  u8 ipv6_set = 0;
  u8 dst_set = 0;
  u32 encap_vrf_id = 0;
  u32 teid = 0, tteid = 0;
  int ret;

  /* Can't "universally zero init" (={0}) due to GCC bug 53119 */
  clib_memset (&dst, 0, sizeof dst);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "dst %U", unformat_ip4_address, &dst.ip4))
      {
	dst_set = 1;
      }
      else if (unformat (line_input, "dst %U", unformat_ip6_address, &dst.ip6))
      {
	ipv6_set = 1;
	dst_set = 1;
      }
      else if (unformat (line_input, "encap-vrf-id %d", &encap_vrf_id))
      ;
      else if (unformat (line_input, "teid %d", &teid))
      ;
      else if (unformat (line_input, "tteid %d", &tteid))
      ;
      else
      {
	errmsg ("parse error '%U'", format_unformat_error, line_input);
	return -99;
      }
    }

  if (dst_set == 0)
    {
      errmsg ("tunnel dst address not specified");
      return -99;
    }

  M (GTPU_TUNNEL_UPDATE_TTEID, mp);

  ip_address_encode(&dst, ipv6_set ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		    &mp->dst_address);
  mp->encap_vrf_id = ntohl (encap_vrf_id);
  mp->teid = ntohl (teid);
  mp->tteid = ntohl (tteid);

  S (mp);
  W (ret);
  return ret;
}

static void vl_api_gtpu_tunnel_details_t_handler
  (vl_api_gtpu_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  ip46_address_t src;
  ip46_address_t dst;
  ip_address_decode(&mp->dst_address, &dst);
  ip_address_decode(&mp->src_address, &src);
  print (vam->ofp, "%11d%24U%24U%14d%18d%13d%13d%19d",
	 ntohl (mp->sw_if_index),
	 format_ip46_address, &src, IP46_TYPE_ANY,
	 format_ip46_address, &dst, IP46_TYPE_ANY,
	 ntohl (mp->encap_vrf_id),
	 ntohl (mp->decap_next_index),
	 ntohl (mp->teid), ntohl (mp->tteid),
	 ntohl (mp->mcast_sw_if_index));
}

static void
vl_api_gtpu_tunnel_v2_details_t_handler (vl_api_gtpu_tunnel_v2_details_t *mp)
{
  vat_main_t *vam = &vat_main;
  ip46_address_t src;
  ip46_address_t dst;
  ip_address_decode (&mp->dst_address, &dst);
  ip_address_decode (&mp->src_address, &src);
  print (vam->ofp, "%11d%24U%24U%14d%18d%13d%13d%19d%15d%5d%15d%17d",
	 ntohl (mp->sw_if_index), format_ip46_address, &src, IP46_TYPE_ANY,
	 format_ip46_address, &dst, IP46_TYPE_ANY, ntohl (mp->encap_vrf_id),
	 ntohl (mp->decap_next_index), ntohl (mp->teid), ntohl (mp->tteid),
	 ntohl (mp->mcast_sw_if_index), mp->pdu_extension, mp->qfi,
	 mp->is_forwarding, ntohl (mp->forwarding_type));
}

static void
vl_api_gtpu_add_del_forward_reply_t_handler (
  vl_api_gtpu_add_del_forward_reply_t *mp)
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
api_gtpu_tunnel_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_gtpu_tunnel_dump_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;

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
      print (vam->ofp, "%11s%24s%24s%14s%18s%13s%13s%19s",
	     "sw_if_index", "src_address", "dst_address",
	     "encap_vrf_id", "decap_next_index", "teid", "tteid",
	     "mcast_sw_if_index");
    }

  /* Get list of gtpu-tunnel interfaces */
  M (GTPU_TUNNEL_DUMP, mp);

  mp->sw_if_index = htonl (sw_if_index);

  S (mp);

  /* No status response for this API call.
   * Wait 1 sec for any dump output before return to vat# */
  sleep (1);
  
  return 0;
}

static int
api_gtpu_tunnel_v2_dump (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_gtpu_tunnel_dump_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;

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
      print (vam->ofp, "%11s%24s%24s%14s%18s%13s%13s%19s%12s%5s%15s%17s",
	     "sw_if_index", "src_address", "dst_address", "encap_vrf_id",
	     "decap_next_index", "teid", "tteid", "mcast_sw_if_index",
	     "pdu_extension", "qfi", "is_forwarding", "forwarding_type");
    }

  /* Get list of gtpu-tunnel interfaces */
  M (GTPU_TUNNEL_DUMP, mp);

  mp->sw_if_index = htonl (sw_if_index);

  S (mp);

  /* No status response for this API call.
   * Wait 1 sec for any dump output before return to vat# */
  sleep (1);

  return 0;
}

static int
api_gtpu_add_del_forward (vat_main_t *vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_gtpu_add_del_forward_t *mp;
  int ret;
  u32 decap_next_index = GTPU_INPUT_NEXT_L2_INPUT;
  int is_add = 1;
  ip46_address_t dst;
  u8 dst_set = 0;
  u8 type = 0;
  u8 type_set = 0;
  u8 ipv6_set = 0;
  u32 encap_vrf_id;

  /* Cant "universally zero init" (={0}) due to GCC bug 53119 */
  clib_memset (&dst, 0, sizeof dst);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "dst %U", unformat_ip4_address, &dst.ip4))
	dst_set = 1;
      else if (unformat (line_input, "dst %U", unformat_ip6_address, &dst.ip6))
	{
	  dst_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "decap-next %U", unformat_gtpu_decap_next,
			 &decap_next_index))
	;
      else if (unformat (line_input, "encap-vrf-id %d", &encap_vrf_id))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "bad-header"))
	type |= GTPU_FORWARD_BAD_HEADER;
      else if (unformat (line_input, "unknown-teid"))
	type |= GTPU_FORWARD_UNKNOWN_TEID;
      else if (unformat (line_input, "unknown-type"))
	type |= GTPU_FORWARD_UNKNOWN_TYPE;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, line_input);
	  return -99;
	}
    }

  if (!type_set)
    {
      errmsg ("dst must be set to a valid IP address");
      return -99;
    }

  M (GTPU_ADD_DEL_FORWARD, mp);

  mp->is_add = is_add;
  ip_address_encode (&dst, ipv6_set ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &mp->dst_address);
  mp->forwarding_type = type;
  mp->encap_vrf_id = ntohl (encap_vrf_id);
  mp->decap_next_index = ntohl (decap_next_index);

  S (mp);
  W (ret);
  return ret;
}

static int
api_gtpu_get_transfer_counts (vat_main_t *vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_gtpu_get_transfer_counts_t *mp;
  u32 start_index;
  u32 capacity;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "start_index %u", &start_index))
	;
      else if (unformat (line_input, "capacity %u", &capacity))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, line_input);
	  return -99;
	}
    }

  M (GTPU_GET_TRANSFER_COUNTS, mp);
  mp->sw_if_index_start = start_index;
  mp->capacity = capacity;

  S (mp); // TODO: Handle the prints somehow. But how is it done??
  W (ret);
  return ret;
}

static void
vl_api_gtpu_get_transfer_counts_reply_t_handler (
  vl_api_gtpu_get_transfer_counts_reply_t *mp)
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
      // TODO: Add reply here?
      vam->result_ready = 1;
    }
}

#include <gtpu/gtpu.api_test.c>
