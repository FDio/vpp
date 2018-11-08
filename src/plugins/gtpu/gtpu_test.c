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
#include <gtpu/gtpu.h>

#define __plugin_msg_base gtpu_test_main.msg_id_base
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

#define vl_msg_id(n,h) n,
typedef enum {
#include <gtpu/gtpu.api.h>
    /* We'll want to know how many messages IDs we need... */
    VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* define message structures */
#define vl_typedefs
#include <gtpu/gtpu.api.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <gtpu/gtpu.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <gtpu/gtpu.api.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <gtpu/gtpu.api.h>
#undef vl_api_version

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


#define foreach_standard_reply_retval_handler   \
    _(sw_interface_set_gtpu_bypass_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = gtpu_test_main.vat_main;   \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
  foreach_standard_reply_retval_handler;
#undef _

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                               \
  _(SW_INTERFACE_SET_GTPU_BYPASS_REPLY, sw_interface_set_gtpu_bypass_reply) \
  _(GTPU_ADD_DEL_TUNNEL_REPLY, gtpu_add_del_tunnel_reply)               \
  _(GTPU_TUNNEL_DETAILS, gtpu_tunnel_details)


static uword
api_unformat_sw_if_index (unformat_input_t * input, va_list * args)
{
  vat_main_t *vam = va_arg (*args, vat_main_t *);
  u32 *result = va_arg (*args, u32 *);
  u8 *if_name;
  uword *p;

  if (!unformat (input, "%s", &if_name))
    return 0;

  p = hash_get_mem (vam->sw_if_index_by_interface_name, if_name);
  if (p == 0)
    return 0;
  *result = p[0];
  return 1;
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
  u32 teid = 0;
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

  M (GTPU_ADD_DEL_TUNNEL, mp);

  if (ipv6_set)
    {
      clib_memcpy (mp->src_address, &src.ip6, sizeof (src.ip6));
      clib_memcpy (mp->dst_address, &dst.ip6, sizeof (dst.ip6));
    }
  else
    {
      clib_memcpy (mp->src_address, &src.ip4, sizeof (src.ip4));
      clib_memcpy (mp->dst_address, &dst.ip4, sizeof (dst.ip4));
    }
  mp->encap_vrf_id = ntohl (encap_vrf_id);
  mp->decap_next_index = ntohl (decap_next_index);
  mp->mcast_sw_if_index = ntohl (mcast_sw_if_index);
  mp->teid = ntohl (teid);
  mp->is_add = is_add;
  mp->is_ipv6 = ipv6_set;

  S (mp);
  W (ret);
  return ret;
}

static void vl_api_gtpu_tunnel_details_t_handler
  (vl_api_gtpu_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  ip46_address_t src = to_ip46 (mp->is_ipv6, mp->dst_address);
  ip46_address_t dst = to_ip46 (mp->is_ipv6, mp->src_address);

  print (vam->ofp, "%11d%24U%24U%14d%18d%13d%19d",
       ntohl (mp->sw_if_index),
       format_ip46_address, &src, IP46_TYPE_ANY,
       format_ip46_address, &dst, IP46_TYPE_ANY,
       ntohl (mp->encap_vrf_id),
       ntohl (mp->decap_next_index), ntohl (mp->teid),
       ntohl (mp->mcast_sw_if_index));
}

static int
api_gtpu_tunnel_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_gtpu_tunnel_dump_t *mp;
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
	   "sw_if_index", "src_address", "dst_address",
	   "encap_vrf_id", "decap_next_index", "teid", "mcast_sw_if_index");
    }

  /* Get list of gtpu-tunnel interfaces */
  M (GTPU_TUNNEL_DUMP, mp);

  mp->sw_if_index = htonl (sw_if_index);

  S (mp);

  W (ret);
  return ret;
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg                                            \
_(sw_interface_set_gtpu_bypass,                                        \
      "<intfc> | sw_if_index <id> [ip4 | ip6] [enable | disable]")     \
_(gtpu_add_del_tunnel,                                                 \
        "src <ip-addr> { dst <ip-addr> | group <mcast-ip-addr>\n"      \
        "{ <intfc> | mcast_sw_if_index <nn> } }\n"                     \
        "teid <teid> [encap-vrf-id <nn>] [decap-next <l2|nn>] [del]")  \
_(gtpu_tunnel_dump, "[<intfc> | sw_if_index <nn>]")                    \

static void
gtpu_vat_api_hookup (vat_main_t *vam)
{
  gtpu_test_main_t * gtm = &gtpu_test_main;
  /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
  vl_msg_api_set_handlers((VL_API_##N + gtm->msg_id_base),       \
                          #n,                                   \
                          vl_api_##n##_t_handler,               \
                          vl_noop_handler,                      \
                          vl_api_##n##_t_endian,                \
                          vl_api_##n##_t_print,                 \
                          sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_reply_msg;
#undef _

  /* API messages we can send */
#define _(n,h) hash_set_mem (vam->function_by_name, #n, api_##n);
  foreach_vpe_api_msg;
#undef _

  /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
  foreach_vpe_api_msg;
#undef _
}

clib_error_t * vat_plugin_register (vat_main_t *vam)
{
  gtpu_test_main_t * gtm = &gtpu_test_main;

  u8 * name;

  gtm->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "gtpu_%08x%c", api_version, 0);
  gtm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (gtm->msg_id_base != (u16) ~0)
    gtpu_vat_api_hookup (vam);

  vec_free(name);

  return 0;
}
