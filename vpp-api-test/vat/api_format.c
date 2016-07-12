/*
 *------------------------------------------------------------------
 * api_format.c 
 * 
 * Copyright (c) 2014 Cisco and/or its affiliates.
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

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <vnet/ip/ip.h>
#include <vnet/sr/sr_packet.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2tp/l2tp.h>
#include <vnet/vxlan/vxlan.h>
#include <vnet/gre/gre.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/lisp-gpe/lisp_gpe.h>

#include <vpp-api/vpe_msg_enum.h>
#include <vnet/l2/l2_classify.h> 
#include <vnet/l2/l2_vtr.h>
#include <vnet/classify/input_acl.h>
#include <vnet/mpls-gre/mpls.h>
#if DPDK > 0
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ikev2.h>
#else
#include <inttypes.h>
#endif
#include <vnet/map/map.h>
#include <vnet/cop/cop.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/policer/xlate.h>
#include <vnet/policer/policer.h>

#include "vat/json_format.h"

#include <sys/stat.h>

#define vl_typedefs             /* define message structures */
#include <vpp-api/vpe_all_api_h.h> 
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <vpp-api/vpe_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <vpp-api/vpe_all_api_h.h>
#undef vl_printfun

uword unformat_sw_if_index (unformat_input_t * input, va_list * args)
{
  vat_main_t * vam = va_arg (*args, vat_main_t *);
  u32 * result = va_arg (*args, u32 *);
  u8 * if_name;
  uword * p;

  if (!unformat (input, "%s", &if_name))
      return 0;

  p = hash_get_mem (vam->sw_if_index_by_interface_name, if_name);
  if (p == 0)
      return 0;
  *result = p[0];
  return 1;
}

/* Parse an IP4 address %d.%d.%d.%d. */
uword unformat_ip4_address (unformat_input_t * input, va_list * args)
{
  u8 * result = va_arg (*args, u8 *);
  unsigned a[4];

  if (! unformat (input, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]))
    return 0;

  if (a[0] >= 256 || a[1] >= 256 || a[2] >= 256 || a[3] >= 256)
    return 0;

  result[0] = a[0];
  result[1] = a[1];
  result[2] = a[2];
  result[3] = a[3];

  return 1;
}


uword
unformat_ethernet_address (unformat_input_t * input, va_list * args)
{
  u8 * result = va_arg (*args, u8 *);
  u32 i, a[6];

  if (! unformat (input, "%_%x:%x:%x:%x:%x:%x%_",
		  &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]))
    return 0;

  /* Check range. */
  for (i = 0; i < 6; i++)
    if (a[i] >= (1 << 8))
      return 0;

  for (i = 0; i < 6; i++)
    result[i] = a[i];

  return 1;
}

/* Returns ethernet type as an int in host byte order. */
uword
unformat_ethernet_type_host_byte_order (unformat_input_t * input,
					va_list * args)
{
  u16 * result = va_arg (*args, u16 *);
  int type;

  /* Numeric type. */
  if (unformat (input, "0x%x", &type)
      || unformat (input, "%d", &type))
    {
      if (type >= (1 << 16))
	return 0;
      *result = type;
      return 1;
    }
  return 0;
}

/* Parse an IP6 address. */
uword unformat_ip6_address (unformat_input_t * input, va_list * args)
{
  ip6_address_t * result = va_arg (*args, ip6_address_t *);
  u16 hex_quads[8];
  uword hex_quad, n_hex_quads, hex_digit, n_hex_digits;
  uword c, n_colon, double_colon_index;

  n_hex_quads = hex_quad = n_hex_digits = n_colon = 0;
  double_colon_index = ARRAY_LEN (hex_quads);
  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      hex_digit = 16;
      if (c >= '0' && c <= '9')
	hex_digit = c - '0';
      else if (c >= 'a' && c <= 'f')
	hex_digit = c + 10 - 'a';
      else if (c >= 'A' && c <= 'F')
	hex_digit = c + 10 - 'A';
      else if (c == ':' && n_colon < 2)
	n_colon++;
      else
	{
	  unformat_put_input (input);
	  break;
	}

      /* Too many hex quads. */
      if (n_hex_quads >= ARRAY_LEN (hex_quads))
	return 0;

      if (hex_digit < 16)
	{
	  hex_quad = (hex_quad << 4) | hex_digit;

	  /* Hex quad must fit in 16 bits. */
	  if (n_hex_digits >= 4)
	    return 0;

	  n_colon = 0;
	  n_hex_digits++;
	}
      
      /* Save position of :: */
      if (n_colon == 2)
	{
	  /* More than one :: ? */
	  if (double_colon_index < ARRAY_LEN (hex_quads))
	    return 0;
	  double_colon_index = n_hex_quads;
	}

      if (n_colon > 0 && n_hex_digits > 0)
	{
	  hex_quads[n_hex_quads++] = hex_quad;
	  hex_quad = 0;
	  n_hex_digits = 0;
	}
    }

  if (n_hex_digits > 0)
    hex_quads[n_hex_quads++] = hex_quad;

  {
    word i;

    /* Expand :: to appropriate number of zero hex quads. */
    if (double_colon_index < ARRAY_LEN (hex_quads))
      {
	word n_zero = ARRAY_LEN (hex_quads) - n_hex_quads;

	for (i = n_hex_quads - 1; i >= (signed) double_colon_index; i--)
	  hex_quads[n_zero + i] = hex_quads[i];

	for (i = 0; i < n_zero; i++)
	  hex_quads[double_colon_index + i] = 0;

	n_hex_quads = ARRAY_LEN (hex_quads);
      }

    /* Too few hex quads given. */
    if (n_hex_quads < ARRAY_LEN (hex_quads))
      return 0;

    for (i = 0; i < ARRAY_LEN (hex_quads); i++)
      result->as_u16[i] = clib_host_to_net_u16 (hex_quads[i]);

    return 1;
  }
}

uword
unformat_ipsec_policy_action (unformat_input_t * input, va_list * args)
{
#if DPDK > 0
  u32 * r = va_arg (*args, u32 *);

  if (0) ;
#define _(v,f,s) else if (unformat (input, s)) *r = IPSEC_POLICY_ACTION_##f;
  foreach_ipsec_policy_action
#undef _
  else
    return 0;
  return 1;
#else
  return 0;
#endif
}

uword
unformat_ipsec_crypto_alg (unformat_input_t * input, va_list * args)
{
#if DPDK > 0
  u32 * r = va_arg (*args, u32 *);

  if (0) ;
#define _(v,f,s) else if (unformat (input, s)) *r = IPSEC_CRYPTO_ALG_##f;
  foreach_ipsec_crypto_alg
#undef _
  else
    return 0;
  return 1;
#else
  return 0;
#endif
}

u8 *
format_ipsec_crypto_alg (u8 * s, va_list * args)
{
#if DPDK > 0
  u32 i = va_arg (*args, u32);
  u8 * t = 0;

  switch (i)
    {
#define _(v,f,str) case IPSEC_CRYPTO_ALG_##f: t = (u8 *) str; break;
  foreach_ipsec_crypto_alg
#undef _
      default:
        return format (s, "unknown");
    }
  return format (s, "%s", t);
#else
  return format (s, "Unimplemented");
#endif
}

uword
unformat_ipsec_integ_alg (unformat_input_t * input, va_list * args)
{
#if DPDK > 0
  u32 * r = va_arg (*args, u32 *);

  if (0) ;
#define _(v,f,s) else if (unformat (input, s)) *r = IPSEC_INTEG_ALG_##f;
  foreach_ipsec_integ_alg
#undef _
  else
    return 0;
  return 1;
#else
  return 0;
#endif
}

u8 *
format_ipsec_integ_alg (u8 * s, va_list * args)
{
#if DPDK > 0
  u32 i = va_arg (*args, u32);
  u8 * t = 0;

  switch (i)
    {
#define _(v,f,str) case IPSEC_INTEG_ALG_##f: t = (u8 *) str; break;
  foreach_ipsec_integ_alg
#undef _
      default:
        return format (s, "unknown");
    }
  return format (s, "%s", t);
#else
  return format (s, "Unsupported");
#endif
}

uword
unformat_ikev2_auth_method (unformat_input_t * input, va_list * args)
{
#if DPDK > 0
  u32 * r = va_arg (*args, u32 *);

  if (0) ;
#define _(v,f,s) else if (unformat (input, s)) *r = IKEV2_AUTH_METHOD_##f;
  foreach_ikev2_auth_method
#undef _
  else
    return 0;
  return 1;
#else
  return 0;
#endif
}

uword
unformat_ikev2_id_type (unformat_input_t * input, va_list * args)
{
#if DPDK > 0
  u32 * r = va_arg (*args, u32 *);

  if (0) ;
#define _(v,f,s) else if (unformat (input, s)) *r = IKEV2_ID_TYPE_##f;
  foreach_ikev2_id_type
#undef _
  else
    return 0;
  return 1;
#else
  return 0;
#endif
}

uword
unformat_policer_rate_type (unformat_input_t * input, va_list * args)
{
  u8 * r = va_arg (*args, u8 *);

  if (unformat (input, "kbps"))
    *r = SSE2_QOS_RATE_KBPS;
  else if (unformat(input, "pps"))
    *r = SSE2_QOS_RATE_PPS;
  else
    return 0;
  return 1;
}

uword
unformat_policer_round_type (unformat_input_t * input, va_list * args)
{
  u8 * r = va_arg (*args, u8 *);

  if (unformat(input, "closest"))
    *r = SSE2_QOS_ROUND_TO_CLOSEST;
  else if (unformat (input, "up"))
    *r = SSE2_QOS_ROUND_TO_UP;
  else if (unformat (input, "down"))
    *r = SSE2_QOS_ROUND_TO_DOWN;
  else
    return 0;
  return 1;
}

uword
unformat_policer_type (unformat_input_t * input, va_list * args)
{
  u8 * r = va_arg (*args, u8 *);

  if (unformat (input, "1r2c"))
    *r = SSE2_QOS_POLICER_TYPE_1R2C;
  else if (unformat (input, "1r3c"))
    *r = SSE2_QOS_POLICER_TYPE_1R3C_RFC_2697;
  else if (unformat (input, "2r3c-2698"))
    *r = SSE2_QOS_POLICER_TYPE_2R3C_RFC_2698;
  else if (unformat (input, "2r3c-4115"))
    *r = SSE2_QOS_POLICER_TYPE_2R3C_RFC_4115;
  else if (unformat (input, "2r3c-mef5cf1"))
    *r = SSE2_QOS_POLICER_TYPE_2R3C_RFC_MEF5CF1;
  else
    return 0;
  return 1;
}

uword
unformat_dscp (unformat_input_t * input, va_list * va)
{
  u8 * r = va_arg (*va, u8 *);

  if (0) ;
#define _(v,f,str) else if (unformat (input, str)) *r = VNET_DSCP_##f;
      foreach_vnet_dscp
#undef _
  else
    return 0;
  return 1;
}

uword
unformat_policer_action_type (unformat_input_t * input, va_list * va)
{
  sse2_qos_pol_action_params_st * a
    = va_arg (*va, sse2_qos_pol_action_params_st *);

  if (unformat (input, "drop"))
    a->action_type = SSE2_QOS_ACTION_DROP;
  else if (unformat (input, "transmit"))
    a->action_type = SSE2_QOS_ACTION_TRANSMIT;
  else if (unformat (input, "mark-and-transmit %U", unformat_dscp, &a->dscp))
    a->action_type = SSE2_QOS_ACTION_MARK_AND_TRANSMIT;
  else
    return 0;
  return 1;
}

u8 * format_ip4_address (u8 * s, va_list * args)
{
  u8 * a = va_arg (*args, u8 *);
  return format (s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

u8 * format_ip6_address (u8 * s, va_list * args)
{
    ip6_address_t * a = va_arg (*args, ip6_address_t *);
    u32 i, i_max_n_zero, max_n_zeros, i_first_zero, n_zeros, last_double_colon;

    i_max_n_zero = ARRAY_LEN (a->as_u16);
    max_n_zeros = 0;
    i_first_zero = i_max_n_zero;
    n_zeros = 0;
    for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
      {
        u32 is_zero = a->as_u16[i] == 0;
        if (is_zero && i_first_zero >= ARRAY_LEN (a->as_u16))
          {
            i_first_zero = i;
            n_zeros = 0;
          }
        n_zeros += is_zero;
        if ((! is_zero && n_zeros > max_n_zeros)
            || (i + 1 >= ARRAY_LEN (a->as_u16) && n_zeros > max_n_zeros))
          {
            i_max_n_zero = i_first_zero;
            max_n_zeros = n_zeros;
            i_first_zero = ARRAY_LEN (a->as_u16);
            n_zeros = 0;
          }
      }

    last_double_colon = 0;
    for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
      {
        if (i == i_max_n_zero && max_n_zeros > 1)
          {
            s = format (s, "::");
            i += max_n_zeros - 1;
            last_double_colon = 1;
          }
        else
          {
            s = format (s, "%s%x",
                        (last_double_colon || i == 0) ? "" : ":",
                        clib_net_to_host_u16 (a->as_u16[i]));
            last_double_colon = 0;
          }
      }

    return s;
}

/* Format an IP46 address. */
u8 * format_ip46_address (u8 * s, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  ip46_type_t type = va_arg (*args, ip46_type_t);
  int is_ip4 = 1;

  switch (type)
    {
      case IP46_TYPE_ANY:
       is_ip4 = ip46_address_is_ip4(ip46);
       break;
      case IP46_TYPE_IP4:
       is_ip4 = 1;
       break;
      case IP46_TYPE_IP6:
       is_ip4 = 0;
       break;
    }

  return is_ip4 ?
      format(s, "%U", format_ip4_address, &ip46->ip4):
      format(s, "%U", format_ip6_address, &ip46->ip6);
}

u8 * format_ethernet_address (u8 * s, va_list * args)
{
  u8 * a = va_arg (*args, u8 *);

  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
                 a[0], a[1], a[2], a[3], a[4], a[5]);
}

void increment_v4_address (ip4_address_t * a)
{
    u32 v;

    v = ntohl(a->as_u32) + 1;
    a->as_u32 = ntohl(v);
}

void increment_v6_address (ip6_address_t * a)
{
    u64 v0, v1;

    v0 = clib_net_to_host_u64 (a->as_u64[0]);
    v1 = clib_net_to_host_u64 (a->as_u64[1]);

    v1 += 1;
    if (v1 == 0)
        v0 += 1;
    a->as_u64[0] = clib_net_to_host_u64 (v0);
    a->as_u64[1] = clib_net_to_host_u64 (v1);
}

void increment_mac_address (u64 *mac)
{
    u64 tmp = *mac;

    tmp = clib_net_to_host_u64(tmp);
    tmp += 1<<16; /* skip unused (least significant) octets */
    tmp = clib_host_to_net_u64 (tmp);
    *mac = tmp;
}

static void vl_api_create_loopback_reply_t_handler 
(vl_api_create_loopback_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);

    vam->retval = retval;
    vam->regenerate_interface_table = 1;
    vam->sw_if_index = ntohl (mp->sw_if_index);
    vam->result_ready = 1;
}

static void vl_api_create_loopback_reply_t_handler_json
(vl_api_create_loopback_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "sw_if_index", ntohl(mp->sw_if_index));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);
    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_af_packet_create_reply_t_handler 
(vl_api_af_packet_create_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);

    vam->retval = retval;
    vam->regenerate_interface_table = 1;
    vam->sw_if_index = ntohl (mp->sw_if_index);
    vam->result_ready = 1;
}

static void vl_api_af_packet_create_reply_t_handler_json
(vl_api_af_packet_create_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "sw_if_index", ntohl(mp->sw_if_index));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_create_vlan_subif_reply_t_handler 
(vl_api_create_vlan_subif_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);

    vam->retval = retval;
    vam->regenerate_interface_table = 1;
    vam->sw_if_index = ntohl (mp->sw_if_index);
    vam->result_ready = 1;
}

static void vl_api_create_vlan_subif_reply_t_handler_json
(vl_api_create_vlan_subif_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "sw_if_index", ntohl(mp->sw_if_index));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_create_subif_reply_t_handler 
(vl_api_create_subif_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);

    vam->retval = retval;
    vam->regenerate_interface_table = 1;
    vam->sw_if_index = ntohl (mp->sw_if_index);
    vam->result_ready = 1;
}

static void vl_api_create_subif_reply_t_handler_json
(vl_api_create_subif_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "sw_if_index", ntohl(mp->sw_if_index));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_interface_name_renumber_reply_t_handler 
(vl_api_interface_name_renumber_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);

    vam->retval = retval;
    vam->regenerate_interface_table = 1;
    vam->result_ready = 1;
}

static void vl_api_interface_name_renumber_reply_t_handler_json
(vl_api_interface_name_renumber_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

/* 
 * Special-case: build the interface table, maintain
 * the next loopback sw_if_index vbl.
 */
static void vl_api_sw_interface_details_t_handler
(vl_api_sw_interface_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    u8 * s = format (0, "%s%c", mp->interface_name, 0);

    hash_set_mem (vam->sw_if_index_by_interface_name, s, 
                  ntohl(mp->sw_if_index));

    /* In sub interface case, fill the sub interface table entry */
    if (mp->sw_if_index != mp->sup_sw_if_index) {
        sw_interface_subif_t * sub = NULL;

        vec_add2(vam->sw_if_subif_table, sub, 1);

        vec_validate(sub->interface_name, strlen((char *)s) + 1);
        strncpy((char *)sub->interface_name, (char *)s,
                vec_len(sub->interface_name));
        sub->sw_if_index = ntohl(mp->sw_if_index);
        sub->sub_id = ntohl(mp->sub_id);

        sub->sub_dot1ad = mp->sub_dot1ad;
        sub->sub_number_of_tags = mp->sub_number_of_tags;
        sub->sub_outer_vlan_id = ntohs(mp->sub_outer_vlan_id);
        sub->sub_inner_vlan_id = ntohs(mp->sub_inner_vlan_id);
        sub->sub_exact_match = mp->sub_exact_match;
        sub->sub_default = mp->sub_default;
        sub->sub_outer_vlan_id_any = mp->sub_outer_vlan_id_any;
        sub->sub_inner_vlan_id_any = mp->sub_inner_vlan_id_any;

        /* vlan tag rewrite */
        sub->vtr_op = ntohl(mp->vtr_op);
        sub->vtr_push_dot1q = ntohl(mp->vtr_push_dot1q);
        sub->vtr_tag1 = ntohl(mp->vtr_tag1);
        sub->vtr_tag2 = ntohl(mp->vtr_tag2);
    }
}

static void vl_api_sw_interface_details_t_handler_json
(vl_api_sw_interface_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node = NULL;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_uint(node, "sw_if_index", ntohl(mp->sw_if_index));
    vat_json_object_add_uint(node, "sup_sw_if_index", ntohl(mp->sup_sw_if_index));
    vat_json_object_add_uint(node, "l2_address_length", ntohl(mp->l2_address_length));
    vat_json_object_add_bytes(node, "l2_address", mp->l2_address, sizeof(mp->l2_address));
    vat_json_object_add_string_copy(node, "interface_name", mp->interface_name);
    vat_json_object_add_uint(node, "admin_up_down", mp->admin_up_down);
    vat_json_object_add_uint(node, "link_up_down", mp->link_up_down);
    vat_json_object_add_uint(node, "link_duplex", mp->link_duplex);
    vat_json_object_add_uint(node, "link_speed", mp->link_speed);
    vat_json_object_add_uint(node, "mtu", ntohs(mp->link_mtu));
    vat_json_object_add_uint(node, "sub_id", ntohl(mp->sub_id));
    vat_json_object_add_uint(node, "sub_dot1ad", mp->sub_dot1ad);
    vat_json_object_add_uint(node, "sub_number_of_tags", mp->sub_number_of_tags);
    vat_json_object_add_uint(node, "sub_outer_vlan_id", ntohs(mp->sub_outer_vlan_id));
    vat_json_object_add_uint(node, "sub_inner_vlan_id", ntohs(mp->sub_inner_vlan_id));
    vat_json_object_add_uint(node, "sub_exact_match", mp->sub_exact_match);
    vat_json_object_add_uint(node, "sub_default", mp->sub_default);
    vat_json_object_add_uint(node, "sub_outer_vlan_id_any", mp->sub_outer_vlan_id_any);
    vat_json_object_add_uint(node, "sub_inner_vlan_id_any", mp->sub_inner_vlan_id_any);
    vat_json_object_add_uint(node, "vtr_op", ntohl(mp->vtr_op));
    vat_json_object_add_uint(node, "vtr_push_dot1q", ntohl(mp->vtr_push_dot1q));
    vat_json_object_add_uint(node, "vtr_tag1", ntohl(mp->vtr_tag1));
    vat_json_object_add_uint(node, "vtr_tag2", ntohl(mp->vtr_tag2));
}

static void vl_api_sw_interface_set_flags_t_handler
(vl_api_sw_interface_set_flags_t * mp)
{
    vat_main_t * vam = &vat_main;
    if (vam->interface_event_display)
	errmsg ("interface flags: sw_if_index %d %s %s\n",
		ntohl(mp->sw_if_index),
		mp->admin_up_down ? "admin-up" : "admin-down",
		mp->link_up_down  ? "link-up"  : "link-down");
}

static void vl_api_sw_interface_set_flags_t_handler_json
(vl_api_sw_interface_set_flags_t * mp)
{
    /* JSON output not supported */
}

static void vl_api_cli_reply_t_handler
(vl_api_cli_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);

    vam->retval = retval;
    vam->shmem_result = (u8 *) mp->reply_in_shmem;
    vam->result_ready = 1;
}

static void vl_api_cli_reply_t_handler_json
(vl_api_cli_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;
    api_main_t * am = &api_main;
    void * oldheap;
    u8 * reply;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "reply_in_shmem", 
                             ntohl(mp->reply_in_shmem));
    /* Toss the shared-memory original... */
    pthread_mutex_lock (&am->vlib_rp->mutex);
    oldheap = svm_push_data_heap (am->vlib_rp);

    reply = (u8 *)(mp->reply_in_shmem);
    vec_free (reply);
    
    svm_pop_heap (oldheap);
    pthread_mutex_unlock (&am->vlib_rp->mutex);

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_classify_add_del_table_reply_t_handler
(vl_api_classify_add_del_table_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
        if (retval == 0 && 
            ((mp->new_table_index != 0xFFFFFFFF) ||
             (mp->skip_n_vectors != 0xFFFFFFFF) ||
             (mp->match_n_vectors != 0xFFFFFFFF)))
            /* 
             * Note: this is just barely thread-safe, depends on
             * the main thread spinning waiting for an answer...
             */
            errmsg ("new index %d, skip_n_vectors %d, match_n_vectors %d\n",
                    ntohl(mp->new_table_index),
                    ntohl(mp->skip_n_vectors), ntohl(mp->match_n_vectors));
	vam->result_ready = 1;
    }
}

static void vl_api_classify_add_del_table_reply_t_handler_json
(vl_api_classify_add_del_table_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "new_table_index", ntohl(mp->new_table_index));
    vat_json_object_add_uint(&node, "skip_n_vectors", ntohl(mp->skip_n_vectors));
    vat_json_object_add_uint(&node, "match_n_vectors", ntohl(mp->match_n_vectors));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_get_node_index_reply_t_handler
(vl_api_get_node_index_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
        if (retval == 0)
            errmsg ("node index %d\n", ntohl(mp->node_index));
        vam->result_ready = 1;
    }
}

static void vl_api_get_node_index_reply_t_handler_json
(vl_api_get_node_index_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "node_index", ntohl(mp->node_index));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_get_next_index_reply_t_handler
(vl_api_get_next_index_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
        if (retval == 0)
            errmsg ("next node index %d\n", ntohl(mp->next_index));
        vam->result_ready = 1;
    }
}

static void vl_api_get_next_index_reply_t_handler_json
(vl_api_get_next_index_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "next_index", ntohl(mp->next_index));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_add_node_next_reply_t_handler
(vl_api_add_node_next_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
        if (retval == 0)
            errmsg ("next index %d\n", ntohl(mp->next_index));
        vam->result_ready = 1;
    }
}

static void vl_api_add_node_next_reply_t_handler_json
(vl_api_add_node_next_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "next_index", ntohl(mp->next_index));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_mpls_gre_add_del_tunnel_reply_t_handler 
(vl_api_mpls_gre_add_del_tunnel_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    u32 sw_if_index = ntohl(mp->tunnel_sw_if_index);

    if (retval >= 0 && sw_if_index != (u32)~0) {
        errmsg ("tunnel_sw_if_index %d\n", sw_if_index);
    }
    vam->retval = retval;
    vam->result_ready = 1;
}

static void vl_api_mpls_gre_add_del_tunnel_reply_t_handler_json
(vl_api_mpls_gre_add_del_tunnel_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "tunnel_sw_if_index", ntohl(mp->tunnel_sw_if_index));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}


static void vl_api_show_version_reply_t_handler 
(vl_api_show_version_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);

    if (retval >= 0) {
        errmsg ("        program: %s\n", mp->program);
        errmsg ("        version: %s\n", mp->version);
        errmsg ("     build date: %s\n", mp->build_date);
        errmsg ("build directory: %s\n", mp->build_directory);
    }
    vam->retval = retval;
    vam->result_ready = 1;
}

static void vl_api_show_version_reply_t_handler_json
(vl_api_show_version_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_string_copy(&node, "program", mp->program);
    vat_json_object_add_string_copy(&node, "version", mp->version);
    vat_json_object_add_string_copy(&node, "build_date", mp->build_date);
    vat_json_object_add_string_copy(&node, "build_directory", mp->build_directory);

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_ip4_arp_event_t_handler 
(vl_api_ip4_arp_event_t * mp)
{
    vat_main_t * vam = &vat_main;
    errmsg ("arp event: address %U new mac %U sw_if_index %d\n",
            format_ip4_address, &mp->address,
            format_ethernet_address, mp->new_mac, mp->sw_if_index);
}

static void vl_api_ip4_arp_event_t_handler_json
(vl_api_ip4_arp_event_t * mp)
{
    /* JSON output not supported */
}

/* 
 * Special-case: build the bridge domain table, maintain
 * the next bd id vbl.
 */
static void vl_api_bridge_domain_details_t_handler
(vl_api_bridge_domain_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    u32 n_sw_ifs =  ntohl (mp->n_sw_ifs);

    fformat (vam->ofp, "\n%-3s %-3s %-3s %-3s %-3s %-3s\n",
             " ID", "LRN", "FWD", "FLD", "BVI", "#IF");

    fformat (vam->ofp, "%3d %3d %3d %3d %3d %3d\n",
             ntohl (mp->bd_id), mp->learn, mp->forward,
             mp->flood, ntohl (mp->bvi_sw_if_index), n_sw_ifs);

    if (n_sw_ifs)
        fformat (vam->ofp, "\n\n%s %s  %s\n", "sw_if_index", "SHG",
                 "Interface Name");
}

static void vl_api_bridge_domain_details_t_handler_json
(vl_api_bridge_domain_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node, *array = NULL;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_uint(node, "bd_id", ntohl(mp->bd_id));
    vat_json_object_add_uint(node, "flood", mp->flood);
    vat_json_object_add_uint(node, "forward", mp->forward);
    vat_json_object_add_uint(node, "learn", mp->learn);
    vat_json_object_add_uint(node, "bvi_sw_if_index", ntohl(mp->bvi_sw_if_index));
    vat_json_object_add_uint(node, "n_sw_ifs", ntohl(mp->n_sw_ifs));
    array = vat_json_object_add(node, "sw_if");
    vat_json_init_array(array);
}

/* 
 * Special-case: build the bridge domain sw if table.
 */
static void vl_api_bridge_domain_sw_if_details_t_handler
(vl_api_bridge_domain_sw_if_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    hash_pair_t * p;
    u8 * sw_if_name = 0;
    u32 sw_if_index;

    sw_if_index = ntohl (mp->sw_if_index);
    hash_foreach_pair (p, vam->sw_if_index_by_interface_name, 
    ({
        if ((u32) p->value[0] == sw_if_index) {
            sw_if_name = (u8 *)(p->key);
            break;
        }
    }));
   
    fformat (vam->ofp, "%7d     %3d  %s", sw_if_index, 
             mp->shg, sw_if_name ? (char *)sw_if_name : 
             "sw_if_index not found!");
}

static void vl_api_bridge_domain_sw_if_details_t_handler_json
(vl_api_bridge_domain_sw_if_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node = NULL;
    uword last_index = 0;

    ASSERT(VAT_JSON_ARRAY == vam->json_tree.type);
    ASSERT(vec_len(vam->json_tree.array) >= 1);
    last_index = vec_len(vam->json_tree.array) - 1;
    node = &vam->json_tree.array[last_index];
    node = vat_json_object_get_element(node, "sw_if");
    ASSERT(NULL != node);
    node = vat_json_array_add(node);

    vat_json_init_object(node);
    vat_json_object_add_uint(node, "bd_id", ntohl(mp->bd_id));
    vat_json_object_add_uint(node, "sw_if_index", ntohl(mp->sw_if_index));
    vat_json_object_add_uint(node, "shg", mp->shg);
}

static void vl_api_control_ping_reply_t_handler
(vl_api_control_ping_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
        vam->result_ready = 1;
    }
}

static void vl_api_control_ping_reply_t_handler_json
(vl_api_control_ping_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);

    if (VAT_JSON_NONE != vam->json_tree.type) {
        vat_json_print(vam->ofp, &vam->json_tree);
        vat_json_free(&vam->json_tree);
        vam->json_tree.type = VAT_JSON_NONE;
    } else {
        /* just print [] */
        vat_json_init_array(&vam->json_tree);
        vat_json_print(vam->ofp, &vam->json_tree);
        vam->json_tree.type = VAT_JSON_NONE;
    }

    vam->retval = retval;
    vam->result_ready = 1;
}

static void vl_api_l2_flags_reply_t_handler
(vl_api_l2_flags_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
        vam->result_ready = 1;
    }
}

static void vl_api_l2_flags_reply_t_handler_json
(vl_api_l2_flags_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "resulting_feature_bitmap", ntohl(mp->resulting_feature_bitmap));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_bridge_flags_reply_t_handler
(vl_api_bridge_flags_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
        vam->result_ready = 1;
    }
}

static void vl_api_bridge_flags_reply_t_handler_json
(vl_api_bridge_flags_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "resulting_feature_bitmap", ntohl(mp->resulting_feature_bitmap));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_tap_connect_reply_t_handler
(vl_api_tap_connect_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
	vam->sw_if_index = ntohl (mp->sw_if_index);
	vam->result_ready = 1;
    }
    
}

static void vl_api_tap_connect_reply_t_handler_json
(vl_api_tap_connect_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "sw_if_index", ntohl(mp->sw_if_index));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
    
}

static void vl_api_tap_modify_reply_t_handler
(vl_api_tap_modify_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
	vam->sw_if_index = ntohl (mp->sw_if_index);
        vam->result_ready = 1;
    }
}

static void vl_api_tap_modify_reply_t_handler_json
(vl_api_tap_modify_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "sw_if_index", ntohl(mp->sw_if_index));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_tap_delete_reply_t_handler
(vl_api_tap_delete_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
        vam->result_ready = 1;
    }
}

static void vl_api_tap_delete_reply_t_handler_json
(vl_api_tap_delete_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_mpls_ethernet_add_del_tunnel_reply_t_handler
(vl_api_mpls_ethernet_add_del_tunnel_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
        vam->result_ready = 1;
    }
}

static void vl_api_mpls_ethernet_add_del_tunnel_reply_t_handler_json
(vl_api_mpls_ethernet_add_del_tunnel_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "tunnel_sw_if_index", ntohl(mp->tunnel_sw_if_index));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_l2tpv3_create_tunnel_reply_t_handler
(vl_api_l2tpv3_create_tunnel_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
	vam->sw_if_index = ntohl (mp->sw_if_index);
        vam->result_ready = 1;
    }
}

static void vl_api_l2tpv3_create_tunnel_reply_t_handler_json
(vl_api_l2tpv3_create_tunnel_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "sw_if_index", ntohl(mp->sw_if_index));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_vxlan_add_del_tunnel_reply_t_handler
(vl_api_vxlan_add_del_tunnel_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
	vam->sw_if_index = ntohl (mp->sw_if_index);
        vam->result_ready = 1;
    }
}

static void vl_api_vxlan_add_del_tunnel_reply_t_handler_json
(vl_api_vxlan_add_del_tunnel_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "sw_if_index", ntohl(mp->sw_if_index));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_gre_add_del_tunnel_reply_t_handler
(vl_api_gre_add_del_tunnel_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
	vam->sw_if_index = ntohl (mp->sw_if_index);
        vam->result_ready = 1;
    }
}

static void vl_api_gre_add_del_tunnel_reply_t_handler_json
(vl_api_gre_add_del_tunnel_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "sw_if_index", ntohl(mp->sw_if_index));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_create_vhost_user_if_reply_t_handler
(vl_api_create_vhost_user_if_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
	vam->sw_if_index = ntohl (mp->sw_if_index);
        vam->result_ready = 1;
    }
}

static void vl_api_create_vhost_user_if_reply_t_handler_json
(vl_api_create_vhost_user_if_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "sw_if_index", ntohl(mp->sw_if_index));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_ip_address_details_t_handler
(vl_api_ip_address_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    static ip_address_details_t empty_ip_address_details = {{0}};
    ip_address_details_t * address = NULL;
    ip_details_t * current_ip_details = NULL;
    ip_details_t * details = NULL;

    details = vam->ip_details_by_sw_if_index[vam->is_ipv6];

    if (!details || vam->current_sw_if_index >= vec_len(details)
            || !details[vam->current_sw_if_index].present) {
        errmsg ("ip address details arrived but not stored\n");
        errmsg ("ip_dump should be called first\n");
        return;
    }

    current_ip_details = vec_elt_at_index(details,
            vam->current_sw_if_index);

#define addresses (current_ip_details->addr)

    vec_validate_init_empty(addresses, vec_len(addresses),
            empty_ip_address_details);

    address = vec_elt_at_index(addresses, vec_len(addresses) - 1);

    clib_memcpy(&address->ip, &mp->ip, sizeof(address->ip));
    address->prefix_length = mp->prefix_length;
#undef addresses
}

static void vl_api_ip_address_details_t_handler_json
(vl_api_ip_address_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node = NULL;
    struct in6_addr ip6;
    struct in_addr ip4;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    if (vam->is_ipv6) {
        clib_memcpy(&ip6, mp->ip, sizeof(ip6));
        vat_json_object_add_ip6(node, "ip",  ip6);
    } else {
        clib_memcpy(&ip4, mp->ip, sizeof(ip4));
        vat_json_object_add_ip4(node, "ip", ip4);
    }
    vat_json_object_add_uint(node, "prefix_length", mp->prefix_length);
}

static void vl_api_ip_details_t_handler (vl_api_ip_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    static ip_details_t empty_ip_details = {0};
    ip_details_t * ip = NULL;
    u32 sw_if_index = ~0;

    sw_if_index = ntohl(mp->sw_if_index);

    vec_validate_init_empty(vam->ip_details_by_sw_if_index[vam->is_ipv6],
            sw_if_index, empty_ip_details);

    ip = vec_elt_at_index(vam->ip_details_by_sw_if_index[vam->is_ipv6],
            sw_if_index);

    ip->present = 1;
}

static void vl_api_ip_details_t_handler_json (vl_api_ip_details_t * mp)
{
    vat_main_t * vam = &vat_main;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    vat_json_array_add_uint(&vam->json_tree, clib_net_to_host_u32(mp->sw_if_index));
}

static void vl_api_map_domain_details_t_handler_json
(vl_api_map_domain_details_t * mp)
{
    vat_json_node_t * node = NULL;
    vat_main_t * vam = &vat_main;
    struct in6_addr ip6;
    struct in_addr ip4;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }

    node = vat_json_array_add(&vam->json_tree);
    vat_json_init_object(node);

    vat_json_object_add_uint(node, "domain_index", clib_net_to_host_u32(mp->domain_index));
    clib_memcpy(&ip6, mp->ip6_prefix, sizeof(ip6));
    vat_json_object_add_ip6(node, "ip6_prefix", ip6);
    clib_memcpy(&ip4, mp->ip4_prefix, sizeof(ip4));
    vat_json_object_add_ip4(node, "ip4_prefix", ip4);
    clib_memcpy(&ip6, mp->ip6_src, sizeof(ip6));
    vat_json_object_add_ip6(node, "ip6_src", ip6);
    vat_json_object_add_int(node, "ip6_prefix_len", mp->ip6_prefix_len);
    vat_json_object_add_int(node, "ip4_prefix_len", mp->ip4_prefix_len);
    vat_json_object_add_int(node, "ip6_src_len", mp->ip6_src_len);
    vat_json_object_add_int(node, "ea_bits_len", mp->ea_bits_len);
    vat_json_object_add_int(node, "psid_offset", mp->psid_offset);
    vat_json_object_add_int(node, "psid_length", mp->psid_length);
    vat_json_object_add_uint(node, "flags", mp->flags);
    vat_json_object_add_uint(node, "mtu", clib_net_to_host_u16(mp->mtu));
    vat_json_object_add_int(node, "is_translation", mp->is_translation);
}

static void vl_api_map_domain_details_t_handler
(vl_api_map_domain_details_t * mp)
{
    vat_main_t * vam = &vat_main;

    if (mp->is_translation) {
        fformat(vam->ofp,  "* %U/%d (ipv4-prefix) %U/%d (ipv6-prefix) %U/%d (ip6-src) index: %u\n",
                  format_ip4_address, mp->ip4_prefix, mp->ip4_prefix_len,
                  format_ip6_address, mp->ip6_prefix, mp->ip6_prefix_len,
                  format_ip6_address, mp->ip6_src, mp->ip6_src_len, clib_net_to_host_u32(mp->domain_index));
    } else {
        fformat(vam->ofp,  "* %U/%d (ipv4-prefix) %U/%d (ipv6-prefix) %U (ip6-src) index: %u\n",
                  format_ip4_address, mp->ip4_prefix, mp->ip4_prefix_len,
                  format_ip6_address, mp->ip6_prefix, mp->ip6_prefix_len,
                  format_ip6_address, mp->ip6_src, clib_net_to_host_u32(mp->domain_index));
    }
    fformat(vam->ofp, "  ea-len %d psid-offset %d psid-len %d mtu %d %s\n",
            mp->ea_bits_len, mp->psid_offset, mp->psid_length, mp->mtu, mp->is_translation? "map-t":"");
}

static void vl_api_map_rule_details_t_handler_json
(vl_api_map_rule_details_t * mp)
{
    struct in6_addr ip6;
    vat_json_node_t * node = NULL;
    vat_main_t * vam = &vat_main;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }

    node = vat_json_array_add(&vam->json_tree);
    vat_json_init_object(node);

    vat_json_object_add_uint(node, "psid", clib_net_to_host_u16(mp->psid));
    clib_memcpy(&ip6, mp->ip6_dst, sizeof(ip6));
    vat_json_object_add_ip6(node, "ip6_dst", ip6);
}

static void vl_api_map_rule_details_t_handler
(vl_api_map_rule_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    fformat(vam->ofp, " %d (psid) %U (ip6-dst)\n", clib_net_to_host_u16(mp->psid),
            format_ip6_address, mp->ip6_dst);
}

static void vl_api_dhcp_compl_event_t_handler
(vl_api_dhcp_compl_event_t * mp)
{
    vat_main_t * vam = &vat_main;
    errmsg ("DHCP compl event: pid %d %s hostname %s host_addr %U "
            "router_addr %U host_mac %U\n",
            mp->pid, mp->is_ipv6 ? "ipv6":"ipv4", mp->hostname,
            format_ip4_address, &mp->host_address,
            format_ip4_address, &mp->router_address,
            format_ethernet_address, mp->host_mac);
}

static void vl_api_dhcp_compl_event_t_handler_json
(vl_api_dhcp_compl_event_t * mp)
{
    /* JSON output not supported */
}

static void set_simple_interface_counter (u8 vnet_counter_type, u32 sw_if_index,
                                          u32 counter)
{
    vat_main_t * vam = &vat_main;
    static u64 default_counter = 0;

    vec_validate_init_empty(vam->simple_interface_counters, vnet_counter_type, NULL);
    vec_validate_init_empty(vam->simple_interface_counters[vnet_counter_type],
                            sw_if_index, default_counter);
    vam->simple_interface_counters[vnet_counter_type][sw_if_index] = counter;
}

static void set_combined_interface_counter (u8 vnet_counter_type, u32 sw_if_index,
                                            interface_counter_t counter)
{
    vat_main_t * vam = &vat_main;
    static interface_counter_t default_counter = {0, };

    vec_validate_init_empty(vam->combined_interface_counters, vnet_counter_type, NULL);
    vec_validate_init_empty(vam->combined_interface_counters[vnet_counter_type],
                            sw_if_index, default_counter);
    vam->combined_interface_counters[vnet_counter_type][sw_if_index] = counter;
}

static void vl_api_vnet_interface_counters_t_handler
(vl_api_vnet_interface_counters_t *mp)
{
    /* not supported */
}

static void vl_api_vnet_interface_counters_t_handler_json
(vl_api_vnet_interface_counters_t *mp)
{
    interface_counter_t counter;
    vlib_counter_t *v;
    u64 *v_packets;
    u64 packets;
    u32 count;
    u32 first_sw_if_index;
    int i;

    count = ntohl(mp->count);
    first_sw_if_index = ntohl(mp->first_sw_if_index);

    if (!mp->is_combined) {
        v_packets = (u64*)&mp->data;
        for (i = 0; i < count; i++) {
            packets = clib_net_to_host_u64(clib_mem_unaligned(v_packets, u64));
            set_simple_interface_counter(mp->vnet_counter_type,
                    first_sw_if_index + i, packets);
            v_packets++;
        }
    } else {
        v = (vlib_counter_t*)&mp->data;
        for (i = 0; i < count; i++) {
            counter.packets = clib_net_to_host_u64(
                    clib_mem_unaligned(&v->packets, u64));
            counter.bytes = clib_net_to_host_u64(
                    clib_mem_unaligned(&v->bytes, u64));
            set_combined_interface_counter(mp->vnet_counter_type,
                    first_sw_if_index + i, counter);
            v++;
        }
    }
}

static u32 ip4_fib_counters_get_vrf_index_by_vrf_id (u32 vrf_id)
{
    vat_main_t * vam = &vat_main;
    u32 i;

    for (i = 0; i < vec_len(vam->ip4_fib_counters_vrf_id_by_index); i++) {
        if (vam->ip4_fib_counters_vrf_id_by_index[i] == vrf_id) {
            return i;
        }
    }
    return ~0;
}

static u32 ip6_fib_counters_get_vrf_index_by_vrf_id (u32 vrf_id)
{
    vat_main_t * vam = &vat_main;
    u32 i;

    for (i = 0; i < vec_len(vam->ip6_fib_counters_vrf_id_by_index); i++) {
        if (vam->ip6_fib_counters_vrf_id_by_index[i] == vrf_id) {
            return i;
        }
    }
    return ~0;
}

static void vl_api_vnet_ip4_fib_counters_t_handler
(vl_api_vnet_ip4_fib_counters_t *mp)
{
    /* not supported */
}

static void vl_api_vnet_ip4_fib_counters_t_handler_json
(vl_api_vnet_ip4_fib_counters_t *mp)
{
    vat_main_t * vam = &vat_main;
    vl_api_ip4_fib_counter_t *v;
    ip4_fib_counter_t *counter;
    struct in_addr ip4;
    u32 vrf_id;
    u32 vrf_index;
    u32 count;
    int i;

    vrf_id = ntohl(mp->vrf_id);
    vrf_index = ip4_fib_counters_get_vrf_index_by_vrf_id(vrf_id);
    if (~0 == vrf_index) {
        vrf_index = vec_len(vam->ip4_fib_counters_vrf_id_by_index);
        vec_validate(vam->ip4_fib_counters_vrf_id_by_index, vrf_index);
        vam->ip4_fib_counters_vrf_id_by_index[vrf_index] = vrf_id;
        vec_validate(vam->ip4_fib_counters, vrf_index);
        vam->ip4_fib_counters[vrf_index] = NULL;
    }

    vec_free(vam->ip4_fib_counters[vrf_index]);
    v = (vl_api_ip4_fib_counter_t*)&mp->c;
    count = ntohl(mp->count);
    for (i = 0; i < count; i++) {
        vec_validate(vam->ip4_fib_counters[vrf_index], i);
        counter = &vam->ip4_fib_counters[vrf_index][i];
        clib_memcpy(&ip4, &v->address, sizeof(ip4));
        counter->address = ip4;
        counter->address_length = v->address_length;
        counter->packets = clib_net_to_host_u64(v->packets);
        counter->bytes = clib_net_to_host_u64(v->bytes);
        v++;
    }
}

static void vl_api_vnet_ip6_fib_counters_t_handler
(vl_api_vnet_ip6_fib_counters_t *mp)
{
    /* not supported */
}

static void vl_api_vnet_ip6_fib_counters_t_handler_json
(vl_api_vnet_ip6_fib_counters_t *mp)
{
    vat_main_t * vam = &vat_main;
    vl_api_ip6_fib_counter_t *v;
    ip6_fib_counter_t *counter;
    struct in6_addr ip6;
    u32 vrf_id;
    u32 vrf_index;
    u32 count;
    int i;

    vrf_id = ntohl(mp->vrf_id);
    vrf_index = ip6_fib_counters_get_vrf_index_by_vrf_id(vrf_id);
    if (~0 == vrf_index) {
        vrf_index = vec_len(vam->ip6_fib_counters_vrf_id_by_index);
        vec_validate(vam->ip6_fib_counters_vrf_id_by_index, vrf_index);
        vam->ip6_fib_counters_vrf_id_by_index[vrf_index] = vrf_id;
        vec_validate(vam->ip6_fib_counters, vrf_index);
        vam->ip6_fib_counters[vrf_index] = NULL;
    }

    vec_free(vam->ip6_fib_counters[vrf_index]);
    v = (vl_api_ip6_fib_counter_t*)&mp->c;
    count = ntohl(mp->count);
    for (i = 0; i < count; i++) {
        vec_validate(vam->ip6_fib_counters[vrf_index], i);
        counter = &vam->ip6_fib_counters[vrf_index][i];
        clib_memcpy(&ip6, &v->address, sizeof(ip6));
        counter->address = ip6;
        counter->address_length = v->address_length;
        counter->packets = clib_net_to_host_u64(v->packets);
        counter->bytes = clib_net_to_host_u64(v->bytes);
        v++;
    }
}

static void vl_api_get_first_msg_id_reply_t_handler
(vl_api_get_first_msg_id_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
        vam->result_ready = 1;
    }
    if (retval >= 0) {
        errmsg ("first message id %d\n", ntohs(mp->first_msg_id));
    }
}

static void vl_api_get_first_msg_id_reply_t_handler_json
(vl_api_get_first_msg_id_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "first_msg_id", 
                             (uint) ntohs(mp->first_msg_id));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_get_node_graph_reply_t_handler
(vl_api_get_node_graph_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    api_main_t * am = &api_main;
    i32 retval = ntohl(mp->retval);
    u8 * pvt_copy, * reply;
    void * oldheap;
    vlib_node_t * node;
    int i;
    
    if (vam->async_mode) {
        vam->async_errors += (retval < 0);
    } else {
        vam->retval = retval;
        vam->result_ready = 1;
    }

    /* "Should never happen..." */
    if (retval != 0)
        return;

    reply = (u8 *)(mp->reply_in_shmem);
    pvt_copy = vec_dup (reply);

    /* Toss the shared-memory original... */
    pthread_mutex_lock (&am->vlib_rp->mutex);
    oldheap = svm_push_data_heap (am->vlib_rp);

    vec_free (reply);
    
    svm_pop_heap (oldheap);
    pthread_mutex_unlock (&am->vlib_rp->mutex);

    if (vam->graph_nodes) {
        hash_free (vam->graph_node_index_by_name);

        for (i = 0; i < vec_len (vam->graph_nodes); i++) {
            node = vam->graph_nodes[i];
            vec_free (node->name);
            vec_free (node->next_nodes);
            vec_free (node);
        }
        vec_free(vam->graph_nodes);
    }

    vam->graph_node_index_by_name = hash_create_string (0, sizeof(uword));
    vam->graph_nodes = vlib_node_unserialize (pvt_copy);
    vec_free (pvt_copy);

    for (i = 0; i < vec_len (vam->graph_nodes); i++) {
        node = vam->graph_nodes[i];
        hash_set_mem (vam->graph_node_index_by_name, node->name, i);
    }
}

static void vl_api_get_node_graph_reply_t_handler_json
(vl_api_get_node_graph_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    api_main_t * am = &api_main;
    void * oldheap;
    vat_json_node_t node;
    u8 * reply;

    /* $$$$ make this real? */
    vat_json_init_object(&node);
    vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
    vat_json_object_add_uint(&node, "reply_in_shmem", mp->reply_in_shmem);

    reply = (u8 *)(mp->reply_in_shmem);

    /* Toss the shared-memory original... */
    pthread_mutex_lock (&am->vlib_rp->mutex);
    oldheap = svm_push_data_heap (am->vlib_rp);

    vec_free (reply);
    
    svm_pop_heap (oldheap);
    pthread_mutex_unlock (&am->vlib_rp->mutex);

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void
vl_api_lisp_locator_set_details_t_handler (
    vl_api_lisp_locator_set_details_t *mp)
{
    vat_main_t *vam = &vat_main;
    u8 * tmp_str = NULL;

    if (mp->local) {
      fformat(vam->ofp, "%=20s%=16d%=16d%=16d\n",
              mp->locator_set_name,
              ntohl(mp->sw_if_index),
              mp->priority,
              mp->weight);
    } else {
      tmp_str = format(0,"%U/%d",
              mp->is_ipv6 ? format_ip6_address : format_ip4_address,
              mp->ip_address,
              mp->prefix_len);

      fformat(vam->ofp, "%=20s%=16s%=16d%=16d\n",
              mp->locator_set_name,
              tmp_str,
              mp->priority,
              mp->weight);
      vec_free(tmp_str);
    }
}

static void
vl_api_lisp_locator_set_details_t_handler_json (
    vl_api_lisp_locator_set_details_t *mp)
{
    vat_main_t *vam = &vat_main;
    vat_json_node_t *node = NULL;
    struct in6_addr ip6;
    struct in_addr ip4;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_string_copy(node, "locator-set", mp->locator_set_name);
    if (mp->local) {
        vat_json_object_add_uint(node, "locator", ntohl(mp->sw_if_index));
    } else {
        if (mp->is_ipv6) {
            clib_memcpy(&ip6, mp->ip_address, sizeof(ip6));
            vat_json_object_add_ip6(node, "locator", ip6);
        } else {
            clib_memcpy(&ip4, mp->ip_address, sizeof(ip4));
            vat_json_object_add_ip4(node, "locator", ip4);
        }
        vat_json_object_add_uint(node, "prefix-length", mp->prefix_len);
    }
    vat_json_object_add_uint(node, "priority", mp->priority);
    vat_json_object_add_uint(node, "weight", mp->weight);
}

static void
vl_api_lisp_local_eid_table_details_t_handler (
    vl_api_lisp_local_eid_table_details_t *mp)
{
    vat_main_t *vam = &vat_main;
    u8 *prefix;
    u8 * (*format_eid)(u8 *, va_list *) = 0;

    switch (mp->eid_type)
      {
      case 0: format_eid = format_ip4_address; break;
      case 1: format_eid = format_ip6_address; break;
      case 2: format_eid = format_ethernet_address; break;
      default:
        errmsg ("unknown EID type %d!", mp->eid_type);
        return;
      }

    prefix = format(0, "[%d] %U/%d",
                    clib_net_to_host_u32 (mp->vni),
                    format_eid, mp->eid, mp->eid_prefix_len);

    fformat(vam->ofp, "%=20s%=30s\n",
            mp->locator_set_name, prefix);

    vec_free(prefix);
}

static void
vl_api_lisp_eid_table_map_details_t_handler (
    vl_api_lisp_eid_table_map_details_t *mp)
{
    vat_main_t *vam = &vat_main;

    u8 * line = format(0, "%=10d%=10d",
                       clib_net_to_host_u32 (mp->vni),
                       clib_net_to_host_u32 (mp->vrf));
    fformat(vam->ofp, "%v\n", line);
    vec_free(line);
}

static void
vl_api_lisp_eid_table_map_details_t_handler_json (
    vl_api_lisp_eid_table_map_details_t *mp)
{
    vat_main_t *vam = &vat_main;
    vat_json_node_t *node = NULL;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);
    vat_json_init_object(node);
    vat_json_object_add_uint(node, "vrf", clib_net_to_host_u32 (mp->vrf));
    vat_json_object_add_uint(node, "vni", clib_net_to_host_u32 (mp->vni));
}

static void
vl_api_lisp_local_eid_table_details_t_handler_json (
    vl_api_lisp_local_eid_table_details_t *mp)
{
    vat_main_t *vam = &vat_main;
    vat_json_node_t *node = NULL;
    struct in6_addr ip6;
    struct in_addr ip4;
    u8 * s = 0;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_string_copy(node, "locator-set", mp->locator_set_name);
    switch (mp->eid_type)
      {
      case 0:
        clib_memcpy(&ip4, mp->eid, sizeof(ip4));
        vat_json_object_add_ip4(node, "eid-address", ip4);
        break;
      case 1:
        clib_memcpy(&ip6, mp->eid, sizeof(ip6));
        vat_json_object_add_ip6(node, "eid-address", ip6);
        break;
      case 2:
        s = format (0, "%U", format_ethernet_address, mp->eid);
        vec_add1(s, 0);
        vat_json_object_add_string_copy(node, "eid-address", s);
        vec_free(s);
        break;
      default:
        errmsg ("unknown EID type %d!", mp->eid_type);
        return;
      }
    vat_json_object_add_uint(node, "vni", clib_net_to_host_u32 (mp->vni));
    vat_json_object_add_uint(node, "eid-prefix-len", mp->eid_prefix_len);
}

static u8 *
format_decap_next (u8 * s, va_list * args)
{
  u32 next_index = va_arg (*args, u32);

  switch (next_index)
    {
    case LISP_GPE_INPUT_NEXT_DROP:
      return format (s, "drop");
    case LISP_GPE_INPUT_NEXT_IP4_INPUT:
      return format (s, "ip4");
    case LISP_GPE_INPUT_NEXT_IP6_INPUT:
      return format (s, "ip6");
    default:
      return format (s, "unknown %d", next_index);
    }
  return s;
}

static void
vl_api_lisp_gpe_tunnel_details_t_handler (vl_api_lisp_gpe_tunnel_details_t *mp)
{
    vat_main_t *vam = &vat_main;
    u8 *iid_str;
    u8 *flag_str = NULL;

    iid_str = format(0, "%d (0x%x)", ntohl(mp->iid), ntohl(mp->iid));

#define _(n,v) if (mp->flags & v) flag_str = format (flag_str, "%s-bit ", #n);
  foreach_lisp_gpe_flag_bit;
#undef _

    fformat(vam->ofp, "%=20d%=30U%=16U%=16d%=16d%=16U"
            "%=16d%=16d%=16sd=16d%=16s%=16s\n",
            mp->tunnels,
            mp->is_ipv6 ? format_ip6_address : format_ip4_address,
            mp->source_ip,
            mp->is_ipv6 ? format_ip6_address : format_ip4_address,
            mp->destination_ip,
            ntohl(mp->encap_fib_id),
            ntohl(mp->decap_fib_id),
            format_decap_next, ntohl(mp->dcap_next),
            mp->ver_res >> 6,
            flag_str,
            mp->next_protocol,
            mp->ver_res,
            mp->res,
            iid_str);

    vec_free(iid_str);
}

static void
vl_api_lisp_gpe_tunnel_details_t_handler_json (
    vl_api_lisp_gpe_tunnel_details_t *mp)
{
    vat_main_t *vam = &vat_main;
    vat_json_node_t *node = NULL;
    struct in6_addr ip6;
    struct in_addr ip4;
    u8 *next_decap_str;

    next_decap_str = format(0, "%U", format_decap_next, htonl(mp->dcap_next));

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_uint(node, "tunel", mp->tunnels);
    if (mp->is_ipv6) {
        clib_memcpy(&ip6, mp->source_ip, sizeof(ip6));
        vat_json_object_add_ip6(node, "source address", ip6);
        clib_memcpy(&ip6, mp->destination_ip, sizeof(ip6));
        vat_json_object_add_ip6(node, "destination address", ip6);
    } else {
        clib_memcpy(&ip4, mp->source_ip, sizeof(ip4));
        vat_json_object_add_ip4(node, "source address", ip4);
        clib_memcpy(&ip4, mp->destination_ip, sizeof(ip4));
        vat_json_object_add_ip4(node, "destination address", ip4);
    }
    vat_json_object_add_uint(node, "fib encap", ntohl(mp->encap_fib_id));
    vat_json_object_add_uint(node, "fib decap", ntohl(mp->decap_fib_id));
    vat_json_object_add_string_copy(node, "decap next", next_decap_str);
    vat_json_object_add_uint(node, "lisp version", mp->ver_res >> 6);
    vat_json_object_add_uint(node, "flags", mp->flags);
    vat_json_object_add_uint(node, "next protocol", mp->next_protocol);
    vat_json_object_add_uint(node, "ver_res", mp->ver_res);
    vat_json_object_add_uint(node, "res", mp->res);
    vat_json_object_add_uint(node, "iid", ntohl(mp->iid));

    vec_free(next_decap_str);
}

static void
vl_api_lisp_map_resolver_details_t_handler (
    vl_api_lisp_map_resolver_details_t *mp)
{
    vat_main_t *vam = &vat_main;

    fformat(vam->ofp, "%=20U\n",
            mp->is_ipv6 ? format_ip6_address : format_ip4_address,
            mp->ip_address);
}

static void
vl_api_lisp_map_resolver_details_t_handler_json (
    vl_api_lisp_map_resolver_details_t *mp)
{
    vat_main_t *vam = &vat_main;
    vat_json_node_t *node = NULL;
    struct in6_addr ip6;
    struct in_addr ip4;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    if (mp->is_ipv6) {
        clib_memcpy(&ip6, mp->ip_address, sizeof(ip6));
        vat_json_object_add_ip6(node, "map resolver", ip6);
    } else {
        clib_memcpy(&ip4, mp->ip_address, sizeof(ip4));
        vat_json_object_add_ip4(node, "map resolver", ip4);
    }
}

static void
vl_api_lisp_enable_disable_status_details_t_handler
(vl_api_lisp_enable_disable_status_details_t *mp)
{
    vat_main_t *vam = &vat_main;

    fformat(vam->ofp, "feature: %s\ngpe: %s\n",
            mp->feature_status ? "enabled" : "disabled",
            mp->gpe_status ? "enabled" : "disabled");
}

static void
vl_api_lisp_enable_disable_status_details_t_handler_json
(vl_api_lisp_enable_disable_status_details_t *mp)
{
    vat_main_t *vam = &vat_main;
    vat_json_node_t *node = NULL;
    u8 * gpe_status = NULL;
    u8 * feature_status = NULL;

    gpe_status = format (0, "%s", mp->gpe_status ? "enabled" : "disabled");
    feature_status = format (0, "%s",
                            mp->feature_status ? "enabled" : "disabled");
    vec_add1 (gpe_status, 0);
    vec_add1 (feature_status, 0);

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_string_copy(node, "gpe_status", gpe_status);
    vat_json_object_add_string_copy(node, "feature_status", feature_status);

    vec_free (gpe_status);
    vec_free (feature_status);
}

static void
vl_api_lisp_get_map_request_itr_rlocs_reply_t_handler (
    vl_api_lisp_get_map_request_itr_rlocs_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);

    if (retval >= 0) {
      fformat(vam->ofp, "%=20s\n",
              mp->locator_set_name);
    }

    vam->retval = retval;
    vam->result_ready = 1;
}

static void
vl_api_lisp_get_map_request_itr_rlocs_reply_t_handler_json (
    vl_api_lisp_get_map_request_itr_rlocs_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t * node = NULL;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_string_copy(node, "itr-rlocs", mp->locator_set_name);

    vat_json_print(vam->ofp, node);
    vat_json_free(node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void
vl_api_show_lisp_pitr_reply_t_handler (vl_api_show_lisp_pitr_reply_t * mp)
{
    vat_main_t *vam = &vat_main;
    i32 retval = ntohl(mp->retval);

    if (0 <= retval) {
      fformat(vam->ofp, "%-20s%-16s\n",
              mp->status ? "enabled" : "disabled",
              mp->status ? (char *) mp->locator_set_name : "");
    }

    vam->retval = retval;
    vam->result_ready = 1;
}

static void
vl_api_show_lisp_pitr_reply_t_handler_json (vl_api_show_lisp_pitr_reply_t * mp)
{
    vat_main_t *vam = &vat_main;
    vat_json_node_t node;
    u8 * status = 0;

    status = format (0, "%s", mp->status ? "enabled" : "disabled");
    vec_add1 (status, 0);

    vat_json_init_object(&node);
    vat_json_object_add_string_copy(&node, "status", status);
    if (mp->status) {
      vat_json_object_add_string_copy(&node, "locator_set", mp->locator_set_name);
    }

    vec_free (status);

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static u8 * format_policer_type (u8 * s, va_list * va)
{
    u32 i = va_arg (*va, u32);

    if (i == SSE2_QOS_POLICER_TYPE_1R2C)
        s = format (s, "1r2c");
    else if (i == SSE2_QOS_POLICER_TYPE_1R3C_RFC_2697)
        s = format (s, "1r3c");
    else if (i == SSE2_QOS_POLICER_TYPE_2R3C_RFC_2698)
        s = format (s, "2r3c-2698");
    else if (i == SSE2_QOS_POLICER_TYPE_2R3C_RFC_4115)
        s = format (s, "2r3c-4115");
    else if (i == SSE2_QOS_POLICER_TYPE_2R3C_RFC_MEF5CF1)
        s = format (s, "2r3c-mef5cf1");
    else
        s = format (s, "ILLEGAL");
    return s;
}

static u8 * format_policer_rate_type (u8 * s, va_list * va)
{
    u32 i = va_arg (*va, u32);

    if (i == SSE2_QOS_RATE_KBPS)
        s = format (s, "kbps");
    else if (i == SSE2_QOS_RATE_PPS)
        s = format(s, "pps");
    else
        s = format (s, "ILLEGAL");
    return s;
}

static u8 * format_policer_round_type (u8 * s, va_list * va)
{
    u32 i = va_arg (*va, u32);

    if (i == SSE2_QOS_ROUND_TO_CLOSEST)
        s = format(s, "closest");
    else if (i == SSE2_QOS_ROUND_TO_UP)
        s = format (s, "up");
    else if (i == SSE2_QOS_ROUND_TO_DOWN)
        s = format (s, "down");
    else
        s = format (s, "ILLEGAL");
  return s;
}

static u8 * format_policer_action_type (u8 * s, va_list * va)
{
    u32 i = va_arg (*va, u32);

    if (i == SSE2_QOS_ACTION_DROP)
        s = format (s, "drop");
    else if (i == SSE2_QOS_ACTION_TRANSMIT)
        s = format (s, "transmit");
    else if (i == SSE2_QOS_ACTION_MARK_AND_TRANSMIT)
        s = format (s, "mark-and-transmit");
    else
        s = format (s, "ILLEGAL");
    return s;
}

static u8 * format_dscp (u8 * s, va_list * va)
{
  u32 i = va_arg (*va, u32);
  char * t = 0;

  switch (i) {
  #define _(v,f,str) case VNET_DSCP_##f: t = str; break;
    foreach_vnet_dscp
  #undef _
    default:
      return format (s, "ILLEGAL");
  }
  s = format (s, "%s", t);
  return s;
}

static void vl_api_policer_details_t_handler
(vl_api_policer_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    u8 *conform_dscp_str, *exceed_dscp_str, *violate_dscp_str;

    if (mp->conform_action_type == SSE2_QOS_ACTION_MARK_AND_TRANSMIT)
        conform_dscp_str = format(0, "%U", format_dscp, mp->conform_dscp);
    else
        conform_dscp_str = format(0, "");

    if (mp->exceed_action_type == SSE2_QOS_ACTION_MARK_AND_TRANSMIT)
        exceed_dscp_str = format(0, "%U", format_dscp, mp->exceed_dscp);
    else
        exceed_dscp_str = format(0, "");

    if (mp->violate_action_type == SSE2_QOS_ACTION_MARK_AND_TRANSMIT)
        violate_dscp_str = format(0, "%U", format_dscp, mp->violate_dscp);
    else
        violate_dscp_str = format(0, "");

    fformat (vam->ofp, "Name \"%s\", type %U, cir %u, eir %u, cb %u, eb %u, "
             "rate type %U, round type %U, %s rate, %s color-aware, "
             "cir %u tok/period, pir %u tok/period, scale %u, cur lim %u, "
             "cur bkt %u, ext lim %u, ext bkt %u, last update %llu"
             "conform action %U%s, exceed action %U%s, violate action %U%s\n",
             mp->name,
             format_policer_type, mp->type,
             ntohl(mp->cir),
             ntohl(mp->eir),
             ntohl(mp->cb),
             ntohl(mp->eb),
             format_policer_rate_type, mp->rate_type,
             format_policer_round_type, mp->round_type,
             mp->single_rate ? "single" : "dual",
             mp->color_aware ? "is" : "not",
             ntohl(mp->cir_tokens_per_period),
             ntohl(mp->pir_tokens_per_period),
             ntohl(mp->scale),
             ntohl(mp->current_limit),
             ntohl(mp->current_bucket),
             ntohl(mp->extended_limit),
             ntohl(mp->extended_bucket),
             clib_net_to_host_u64(mp->last_update_time),
             format_policer_action_type, mp->conform_action_type,
             conform_dscp_str,
             format_policer_action_type, mp->exceed_action_type,
             exceed_dscp_str,
             format_policer_action_type, mp->violate_action_type,
             violate_dscp_str);

    vec_free(conform_dscp_str);
    vec_free(exceed_dscp_str);
    vec_free(violate_dscp_str);
}

static void vl_api_policer_details_t_handler_json
(vl_api_policer_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node;
    u8 *rate_type_str, *round_type_str, *type_str;
    u8 *conform_action_str, *exceed_action_str, *violate_action_str;

    rate_type_str = format(0, "%U", format_policer_rate_type, mp->rate_type);
    round_type_str = format(0, "%U", format_policer_round_type, mp->round_type);
    type_str = format(0, "%U", format_policer_type, mp->type);
    conform_action_str = format(0, "%U", format_policer_action_type,
                                mp->conform_action_type);
    exceed_action_str = format(0, "%U", format_policer_action_type,
                                mp->exceed_action_type);
    violate_action_str = format(0, "%U", format_policer_action_type,
                                mp->violate_action_type);

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_string_copy(node, "name", mp->name);
    vat_json_object_add_uint(node, "cir", ntohl(mp->cir));
    vat_json_object_add_uint(node, "eir", ntohl(mp->eir));
    vat_json_object_add_uint(node, "cb", ntohl(mp->cb));
    vat_json_object_add_uint(node, "eb", ntohl(mp->eb));
    vat_json_object_add_string_copy(node, "rate_type", rate_type_str);
    vat_json_object_add_string_copy(node, "round_type", round_type_str);
    vat_json_object_add_string_copy(node, "type", type_str);
    vat_json_object_add_uint(node, "single_rate", mp->single_rate);
    vat_json_object_add_uint(node, "color_aware", mp->color_aware);
    vat_json_object_add_uint(node, "scale", ntohl(mp->scale));
    vat_json_object_add_uint(node, "cir_tokens_per_period",
                             ntohl(mp->cir_tokens_per_period));
    vat_json_object_add_uint(node, "eir_tokens_per_period",
                             ntohl(mp->pir_tokens_per_period));
    vat_json_object_add_uint(node, "current_limit", ntohl(mp->current_limit));
    vat_json_object_add_uint(node, "current_bucket", ntohl(mp->current_bucket));
    vat_json_object_add_uint(node, "extended_limit", ntohl(mp->extended_limit));
    vat_json_object_add_uint(node, "extended_bucket",
                             ntohl(mp->extended_bucket));
    vat_json_object_add_uint(node, "last_update_time",
                             ntohl(mp->last_update_time));
    vat_json_object_add_string_copy(node, "conform_action", conform_action_str);
    if (mp->conform_action_type == SSE2_QOS_ACTION_MARK_AND_TRANSMIT) {
        u8 *dscp_str = format(0, "%U", format_dscp, mp->conform_dscp);
        vat_json_object_add_string_copy(node, "conform_dscp", dscp_str);
        vec_free(dscp_str);
    }
    vat_json_object_add_string_copy(node, "exceed_action", exceed_action_str);
    if (mp->exceed_action_type == SSE2_QOS_ACTION_MARK_AND_TRANSMIT) {
        u8 *dscp_str = format(0, "%U", format_dscp, mp->exceed_dscp);
        vat_json_object_add_string_copy(node, "exceed_dscp", dscp_str);
        vec_free(dscp_str);
    }
    vat_json_object_add_string_copy(node, "violate_action", violate_action_str);
    if (mp->violate_action_type == SSE2_QOS_ACTION_MARK_AND_TRANSMIT) {
        u8 *dscp_str = format(0, "%U", format_dscp, mp->violate_dscp);
        vat_json_object_add_string_copy(node, "violate_dscp", dscp_str);
        vec_free(dscp_str);
    }

    vec_free(rate_type_str);
    vec_free(round_type_str);
    vec_free(type_str);
    vec_free(conform_action_str);
    vec_free(exceed_action_str);
    vec_free(violate_action_str);
}

static void vl_api_classify_table_ids_reply_t_handler (vl_api_classify_table_ids_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    int i, count = ntohl(mp->count);

    if (count>0)
    	fformat (vam->ofp, "classify table ids (%d) : ", count);
    for (i = 0; i < count; i++)
    {
        fformat (vam->ofp, "%d", ntohl(mp->ids[i]));
        fformat (vam->ofp, (i<count-1)?",":"\n");
    }
    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_classify_table_ids_reply_t_handler_json (vl_api_classify_table_ids_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    int i, count = ntohl(mp->count);

    if (count>0) {
        vat_json_node_t node;

        vat_json_init_object(&node);
	    for (i = 0; i < count; i++)
	    {
	    	vat_json_object_add_uint(&node, "table_id", ntohl(mp->ids[i]));
	    }
	    vat_json_print(vam->ofp, &node);
	    vat_json_free(&node);
    }
    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_classify_table_by_interface_reply_t_handler (vl_api_classify_table_by_interface_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    u32 table_id;

    table_id = ntohl(mp->l2_table_id);
    if (table_id != ~0)
    	fformat (vam->ofp, "l2 table id : %d\n", table_id);
    else
    	fformat (vam->ofp, "l2 table id : No input ACL tables configured\n");
    table_id = ntohl(mp->ip4_table_id);
    if (table_id != ~0)
    	fformat (vam->ofp, "ip4 table id : %d\n", table_id);
    else
    	fformat (vam->ofp, "ip4 table id : No input ACL tables configured\n");
    table_id = ntohl(mp->ip6_table_id);
    if (table_id != ~0)
    	fformat (vam->ofp, "ip6 table id : %d\n", table_id);
    else
    	fformat (vam->ofp, "ip6 table id : No input ACL tables configured\n");
    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_classify_table_by_interface_reply_t_handler_json (vl_api_classify_table_by_interface_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    vat_json_init_object(&node);

    vat_json_object_add_int(&node, "l2_table_id", ntohl(mp->l2_table_id));
    vat_json_object_add_int(&node, "ip4_table_id", ntohl(mp->ip4_table_id));
    vat_json_object_add_int(&node, "ip6_table_id", ntohl(mp->ip6_table_id));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

/* Format hex dump. */
u8 * format_hex_bytes (u8 * s, va_list * va)
{
    u8 * bytes = va_arg (*va, u8 *);
    int n_bytes = va_arg (*va, int);
    uword i;

    /* Print short or long form depending on byte count. */
    uword short_form = n_bytes <= 32;
    uword indent = format_get_indent (s);

    if (n_bytes == 0)
        return s;

    for (i = 0; i < n_bytes; i++)
    {
        if (! short_form && (i % 32) == 0)
            s = format (s, "%08x: ", i);
        s = format (s, "%02x", bytes[i]);
        if (! short_form && ((i + 1) % 32) == 0 && (i + 1) < n_bytes)
            s = format (s, "\n%U", format_white_space, indent);
    }

    return s;
}

static void vl_api_classify_table_info_reply_t_handler (vl_api_classify_table_info_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);
    if (retval == 0) {
        fformat (vam->ofp, "classify table info :\n");
        fformat (vam->ofp, "sessions: %d nexttbl: %d nextnode: %d\n", ntohl(mp->active_sessions), ntohl(mp->next_table_index), ntohl(mp->miss_next_index));
        fformat (vam->ofp, "nbuckets: %d skip: %d match: %d\n", ntohl(mp->nbuckets), ntohl(mp->skip_n_vectors), ntohl(mp->match_n_vectors));
        fformat (vam->ofp, "mask: %U\n", format_hex_bytes, mp->mask, ntohl(mp->mask_length));
    }
    vam->retval = retval;
    vam->result_ready = 1;
}

static void vl_api_classify_table_info_reply_t_handler_json (vl_api_classify_table_info_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    i32 retval = ntohl(mp->retval);
    if (retval == 0) {
        vat_json_init_object(&node);

        vat_json_object_add_int(&node, "sessions", ntohl(mp->active_sessions));
        vat_json_object_add_int(&node, "nexttbl", ntohl(mp->next_table_index));
        vat_json_object_add_int(&node, "nextnode", ntohl(mp->miss_next_index));
        vat_json_object_add_int(&node, "nbuckets", ntohl(mp->nbuckets));
        vat_json_object_add_int(&node, "skip", ntohl(mp->skip_n_vectors));
        vat_json_object_add_int(&node, "match", ntohl(mp->match_n_vectors));
        u8 * s = format (0, "%U%c",format_hex_bytes, mp->mask, ntohl(mp->mask_length), 0);
        vat_json_object_add_string_copy(&node, "mask", s);

        vat_json_print(vam->ofp, &node);
        vat_json_free(&node);
    }
    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_classify_session_details_t_handler (vl_api_classify_session_details_t * mp)
{
    vat_main_t * vam = &vat_main;

    fformat (vam->ofp, "next_index: %d advance: %d opaque: %d ", ntohl(mp->hit_next_index), ntohl(mp->advance), ntohl(mp->opaque_index));
    fformat (vam->ofp, "mask: %U\n", format_hex_bytes, mp->match, ntohl(mp->match_length));
}

static void vl_api_classify_session_details_t_handler_json (vl_api_classify_session_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node = NULL;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_int(node, "next_index", ntohl(mp->hit_next_index));
    vat_json_object_add_int(node, "advance", ntohl(mp->advance));
    vat_json_object_add_int(node, "opaque", ntohl(mp->opaque_index));
    u8 * s = format (0, "%U%c",format_hex_bytes, mp->match, ntohl(mp->match_length), 0);
    vat_json_object_add_string_copy(node, "match", s);
}

static void vl_api_pg_create_interface_reply_t_handler
(vl_api_pg_create_interface_reply_t * mp)
{
    vat_main_t * vam = &vat_main;

    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

static void vl_api_pg_create_interface_reply_t_handler_json
(vl_api_pg_create_interface_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;

    i32 retval = ntohl(mp->retval);
    if (retval == 0) {
        vat_json_init_object(&node);

        vat_json_object_add_int(&node, "sw_if_index", ntohl(mp->sw_if_index));

        vat_json_print(vam->ofp, &node);
        vat_json_free(&node);
    }
    vam->retval = ntohl(mp->retval);
    vam->result_ready = 1;
}

#define vl_api_vnet_ip4_fib_counters_t_endian vl_noop_handler
#define vl_api_vnet_ip4_fib_counters_t_print vl_noop_handler
#define vl_api_vnet_ip6_fib_counters_t_endian vl_noop_handler
#define vl_api_vnet_ip6_fib_counters_t_print vl_noop_handler

/* 
 * Generate boilerplate reply handlers, which
 * dig the return value out of the xxx_reply_t API message,
 * stick it into vam->retval, and set vam->result_ready
 *
 * Could also do this by pointing N message decode slots at
 * a single function, but that could break in subtle ways.
 */

#define foreach_standard_reply_retval_handler           \
_(sw_interface_set_flags_reply)                         \
_(sw_interface_add_del_address_reply)                   \
_(sw_interface_set_table_reply)                         \
_(sw_interface_set_vpath_reply)                         \
_(sw_interface_set_l2_bridge_reply)                     \
_(bridge_domain_add_del_reply)                          \
_(sw_interface_set_l2_xconnect_reply)                   \
_(l2fib_add_del_reply)                                  \
_(ip_add_del_route_reply)                               \
_(proxy_arp_add_del_reply)                              \
_(proxy_arp_intfc_enable_disable_reply)                 \
_(mpls_add_del_encap_reply)                             \
_(mpls_add_del_decap_reply)                             \
_(mpls_ethernet_add_del_tunnel_2_reply)                 \
_(sw_interface_set_unnumbered_reply)                    \
_(ip_neighbor_add_del_reply)                            \
_(reset_vrf_reply)                                      \
_(oam_add_del_reply)                                    \
_(reset_fib_reply)                                      \
_(dhcp_proxy_config_reply)                              \
_(dhcp_proxy_config_2_reply)                            \
_(dhcp_proxy_set_vss_reply)                             \
_(dhcp_client_config_reply)                             \
_(set_ip_flow_hash_reply)                               \
_(sw_interface_ip6_enable_disable_reply)                \
_(sw_interface_ip6_set_link_local_address_reply)        \
_(sw_interface_ip6nd_ra_prefix_reply)                   \
_(sw_interface_ip6nd_ra_config_reply)                   \
_(set_arp_neighbor_limit_reply)                         \
_(l2_patch_add_del_reply)                               \
_(sr_tunnel_add_del_reply)                              \
_(sr_policy_add_del_reply)                              \
_(sr_multicast_map_add_del_reply)                       \
_(classify_add_del_session_reply)                       \
_(classify_set_interface_ip_table_reply)                \
_(classify_set_interface_l2_tables_reply)               \
_(l2tpv3_set_tunnel_cookies_reply)                      \
_(l2tpv3_interface_enable_disable_reply)                \
_(l2tpv3_set_lookup_key_reply)                          \
_(l2_fib_clear_table_reply)                             \
_(l2_interface_efp_filter_reply)                        \
_(l2_interface_vlan_tag_rewrite_reply)                  \
_(modify_vhost_user_if_reply)                           \
_(delete_vhost_user_if_reply)                           \
_(want_ip4_arp_events_reply)                            \
_(input_acl_set_interface_reply)                        \
_(ipsec_spd_add_del_reply)                              \
_(ipsec_interface_add_del_spd_reply)                    \
_(ipsec_spd_add_del_entry_reply)                        \
_(ipsec_sad_add_del_entry_reply)                        \
_(ipsec_sa_set_key_reply)                               \
_(ikev2_profile_add_del_reply)                          \
_(ikev2_profile_set_auth_reply)                         \
_(ikev2_profile_set_id_reply)                           \
_(ikev2_profile_set_ts_reply)                           \
_(ikev2_set_local_key_reply)                            \
_(delete_loopback_reply)                                \
_(bd_ip_mac_add_del_reply)                              \
_(map_del_domain_reply)                                 \
_(map_add_del_rule_reply)                               \
_(want_interface_events_reply)                          \
_(want_stats_reply)					\
_(cop_interface_enable_disable_reply)			\
_(cop_whitelist_enable_disable_reply)                   \
_(sw_interface_clear_stats_reply)                       \
_(trace_profile_add_reply)                              \
_(trace_profile_apply_reply)                            \
_(trace_profile_del_reply)                              \
_(lisp_add_del_locator_set_reply)                       \
_(lisp_add_del_locator_reply)                           \
_(lisp_add_del_local_eid_reply)                         \
_(lisp_add_del_remote_mapping_reply)                    \
_(lisp_add_del_adjacency_reply)                         \
_(lisp_gpe_add_del_fwd_entry_reply)                     \
_(lisp_add_del_map_resolver_reply)                      \
_(lisp_gpe_enable_disable_reply)                        \
_(lisp_gpe_add_del_iface_reply)                         \
_(lisp_enable_disable_reply)                            \
_(lisp_pitr_set_locator_set_reply)                      \
_(lisp_add_del_map_request_itr_rlocs_reply)             \
_(lisp_eid_table_add_del_map_reply)                     \
_(vxlan_gpe_add_del_tunnel_reply)			\
_(af_packet_delete_reply)                               \
_(policer_add_del_reply)                                \
_(netmap_create_reply)                                  \
_(netmap_delete_reply)                                  \
_(ipfix_enable_reply)                                   \
_(pg_capture_reply)                                     \
_(pg_enable_disable_reply)

#define _(n)                                    \
    static void vl_api_##n##_t_handler          \
    (vl_api_##n##_t * mp)                       \
    {                                           \
        vat_main_t * vam = &vat_main;           \
        i32 retval = ntohl(mp->retval);         \
        if (vam->async_mode) {                  \
            vam->async_errors += (retval < 0);  \
        } else {                                \
            vam->retval = retval;               \
            vam->result_ready = 1;              \
        }                                       \
    }
foreach_standard_reply_retval_handler;
#undef _

#define _(n)                                    \
    static void vl_api_##n##_t_handler_json     \
    (vl_api_##n##_t * mp)                       \
    {                                           \
        vat_main_t * vam = &vat_main;           \
        vat_json_node_t node;                   \
        vat_json_init_object(&node);            \
        vat_json_object_add_int(&node, "retval", ntohl(mp->retval));    \
        vat_json_print(vam->ofp, &node);        \
        vam->retval = ntohl(mp->retval);        \
        vam->result_ready = 1;                  \
    }
foreach_standard_reply_retval_handler;
#undef _

/* 
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */

#define foreach_vpe_api_reply_msg                                       \
_(CREATE_LOOPBACK_REPLY, create_loopback_reply)                         \
_(SW_INTERFACE_DETAILS, sw_interface_details)                           \
_(SW_INTERFACE_SET_FLAGS, sw_interface_set_flags)                       \
_(SW_INTERFACE_SET_FLAGS_REPLY, sw_interface_set_flags_reply)           \
_(CONTROL_PING_REPLY, control_ping_reply)                               \
_(CLI_REPLY, cli_reply)                                                 \
_(SW_INTERFACE_ADD_DEL_ADDRESS_REPLY,                                   \
  sw_interface_add_del_address_reply)                                   \
_(SW_INTERFACE_SET_TABLE_REPLY, sw_interface_set_table_reply) 		\
_(SW_INTERFACE_SET_VPATH_REPLY, sw_interface_set_vpath_reply) 		\
_(SW_INTERFACE_SET_L2_XCONNECT_REPLY,                                   \
  sw_interface_set_l2_xconnect_reply)                                   \
_(SW_INTERFACE_SET_L2_BRIDGE_REPLY,                                     \
  sw_interface_set_l2_bridge_reply)                                     \
_(BRIDGE_DOMAIN_ADD_DEL_REPLY, bridge_domain_add_del_reply)             \
_(BRIDGE_DOMAIN_DETAILS, bridge_domain_details)                         \
_(BRIDGE_DOMAIN_SW_IF_DETAILS, bridge_domain_sw_if_details)             \
_(L2FIB_ADD_DEL_REPLY, l2fib_add_del_reply)                             \
_(L2_FLAGS_REPLY, l2_flags_reply)                                       \
_(BRIDGE_FLAGS_REPLY, bridge_flags_reply)                               \
_(TAP_CONNECT_REPLY, tap_connect_reply)					\
_(TAP_MODIFY_REPLY, tap_modify_reply)					\
_(TAP_DELETE_REPLY, tap_delete_reply)					\
_(SW_INTERFACE_TAP_DETAILS, sw_interface_tap_details)                   \
_(IP_ADD_DEL_ROUTE_REPLY, ip_add_del_route_reply)			\
_(PROXY_ARP_ADD_DEL_REPLY, proxy_arp_add_del_reply)                     \
_(PROXY_ARP_INTFC_ENABLE_DISABLE_REPLY,                                 \
  proxy_arp_intfc_enable_disable_reply)                                 \
_(MPLS_ADD_DEL_ENCAP_REPLY, mpls_add_del_encap_reply)                   \
_(MPLS_ADD_DEL_DECAP_REPLY, mpls_add_del_decap_reply)                   \
_(MPLS_GRE_ADD_DEL_TUNNEL_REPLY, mpls_gre_add_del_tunnel_reply)         \
_(MPLS_ETHERNET_ADD_DEL_TUNNEL_REPLY,                                   \
  mpls_ethernet_add_del_tunnel_reply)                                   \
_(MPLS_ETHERNET_ADD_DEL_TUNNEL_2_REPLY,                                 \
  mpls_ethernet_add_del_tunnel_2_reply)                                 \
_(SW_INTERFACE_SET_UNNUMBERED_REPLY,                                    \
  sw_interface_set_unnumbered_reply)                                    \
_(IP_NEIGHBOR_ADD_DEL_REPLY, ip_neighbor_add_del_reply)                 \
_(RESET_VRF_REPLY, reset_vrf_reply)                                     \
_(CREATE_VLAN_SUBIF_REPLY, create_vlan_subif_reply)                     \
_(CREATE_SUBIF_REPLY, create_subif_reply)                     		\
_(OAM_ADD_DEL_REPLY, oam_add_del_reply)                                 \
_(RESET_FIB_REPLY, reset_fib_reply)                                     \
_(DHCP_PROXY_CONFIG_REPLY, dhcp_proxy_config_reply)                     \
_(DHCP_PROXY_CONFIG_2_REPLY, dhcp_proxy_config_2_reply)                 \
_(DHCP_PROXY_SET_VSS_REPLY, dhcp_proxy_set_vss_reply)                   \
_(DHCP_CLIENT_CONFIG_REPLY, dhcp_client_config_reply)                   \
_(SET_IP_FLOW_HASH_REPLY, set_ip_flow_hash_reply)                       \
_(SW_INTERFACE_IP6_ENABLE_DISABLE_REPLY,                                \
  sw_interface_ip6_enable_disable_reply)                                \
_(SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS_REPLY,                        \
  sw_interface_ip6_set_link_local_address_reply)                        \
_(SW_INTERFACE_IP6ND_RA_PREFIX_REPLY,                                   \
  sw_interface_ip6nd_ra_prefix_reply)                                   \
_(SW_INTERFACE_IP6ND_RA_CONFIG_REPLY,                                   \
  sw_interface_ip6nd_ra_config_reply)                                   \
_(SET_ARP_NEIGHBOR_LIMIT_REPLY, set_arp_neighbor_limit_reply)           \
_(L2_PATCH_ADD_DEL_REPLY, l2_patch_add_del_reply)                       \
_(SR_TUNNEL_ADD_DEL_REPLY, sr_tunnel_add_del_reply)                     \
_(SR_POLICY_ADD_DEL_REPLY, sr_policy_add_del_reply)                     \
_(SR_MULTICAST_MAP_ADD_DEL_REPLY, sr_multicast_map_add_del_reply)                     \
_(CLASSIFY_ADD_DEL_TABLE_REPLY, classify_add_del_table_reply)           \
_(CLASSIFY_ADD_DEL_SESSION_REPLY, classify_add_del_session_reply)       \
_(CLASSIFY_SET_INTERFACE_IP_TABLE_REPLY,                                \
classify_set_interface_ip_table_reply)                                  \
_(CLASSIFY_SET_INTERFACE_L2_TABLES_REPLY,                               \
  classify_set_interface_l2_tables_reply)                               \
_(GET_NODE_INDEX_REPLY, get_node_index_reply)                           \
_(ADD_NODE_NEXT_REPLY, add_node_next_reply)                             \
_(L2TPV3_CREATE_TUNNEL_REPLY, l2tpv3_create_tunnel_reply)               \
_(L2TPV3_SET_TUNNEL_COOKIES_REPLY, l2tpv3_set_tunnel_cookies_reply)     \
_(L2TPV3_INTERFACE_ENABLE_DISABLE_REPLY,                                \
  l2tpv3_interface_enable_disable_reply)                                \
_(L2TPV3_SET_LOOKUP_KEY_REPLY, l2tpv3_set_lookup_key_reply)             \
_(SW_IF_L2TPV3_TUNNEL_DETAILS, sw_if_l2tpv3_tunnel_details)             \
_(VXLAN_ADD_DEL_TUNNEL_REPLY, vxlan_add_del_tunnel_reply)               \
_(VXLAN_TUNNEL_DETAILS, vxlan_tunnel_details)                           \
_(GRE_ADD_DEL_TUNNEL_REPLY, gre_add_del_tunnel_reply)                   \
_(GRE_TUNNEL_DETAILS, gre_tunnel_details)                               \
_(L2_FIB_CLEAR_TABLE_REPLY, l2_fib_clear_table_reply)                   \
_(L2_INTERFACE_EFP_FILTER_REPLY, l2_interface_efp_filter_reply)         \
_(L2_INTERFACE_VLAN_TAG_REWRITE_REPLY, l2_interface_vlan_tag_rewrite_reply) \
_(SW_INTERFACE_VHOST_USER_DETAILS, sw_interface_vhost_user_details)     \
_(CREATE_VHOST_USER_IF_REPLY, create_vhost_user_if_reply)               \
_(MODIFY_VHOST_USER_IF_REPLY, modify_vhost_user_if_reply)               \
_(DELETE_VHOST_USER_IF_REPLY, delete_vhost_user_if_reply)               \
_(SHOW_VERSION_REPLY, show_version_reply)                               \
_(L2_FIB_TABLE_ENTRY, l2_fib_table_entry)				\
_(VXLAN_GPE_ADD_DEL_TUNNEL_REPLY, vxlan_gpe_add_del_tunnel_reply)	    \
_(VXLAN_GPE_TUNNEL_DETAILS, vxlan_gpe_tunnel_details)                   \
_(INTERFACE_NAME_RENUMBER_REPLY, interface_name_renumber_reply)		\
_(WANT_IP4_ARP_EVENTS_REPLY, want_ip4_arp_events_reply)			\
_(IP4_ARP_EVENT, ip4_arp_event)                                         \
_(INPUT_ACL_SET_INTERFACE_REPLY, input_acl_set_interface_reply)         \
_(IP_ADDRESS_DETAILS, ip_address_details)                               \
_(IP_DETAILS, ip_details)                                               \
_(IPSEC_SPD_ADD_DEL_REPLY, ipsec_spd_add_del_reply)                     \
_(IPSEC_INTERFACE_ADD_DEL_SPD_REPLY, ipsec_interface_add_del_spd_reply) \
_(IPSEC_SPD_ADD_DEL_ENTRY_REPLY, ipsec_spd_add_del_entry_reply)         \
_(IPSEC_SAD_ADD_DEL_ENTRY_REPLY, ipsec_sad_add_del_entry_reply)         \
_(IPSEC_SA_SET_KEY_REPLY, ipsec_sa_set_key_reply)                       \
_(IKEV2_PROFILE_ADD_DEL_REPLY, ikev2_profile_add_del_reply)             \
_(IKEV2_PROFILE_SET_AUTH_REPLY, ikev2_profile_set_auth_reply)           \
_(IKEV2_PROFILE_SET_ID_REPLY, ikev2_profile_set_id_reply)               \
_(IKEV2_PROFILE_SET_TS_REPLY, ikev2_profile_set_ts_reply)               \
_(IKEV2_SET_LOCAL_KEY_REPLY, ikev2_set_local_key_reply)                 \
_(DELETE_LOOPBACK_REPLY, delete_loopback_reply)                         \
_(BD_IP_MAC_ADD_DEL_REPLY, bd_ip_mac_add_del_reply)                     \
_(DHCP_COMPL_EVENT, dhcp_compl_event)                                   \
_(VNET_INTERFACE_COUNTERS, vnet_interface_counters)                     \
_(VNET_IP4_FIB_COUNTERS, vnet_ip4_fib_counters)                         \
_(VNET_IP6_FIB_COUNTERS, vnet_ip6_fib_counters)                         \
_(MAP_ADD_DOMAIN_REPLY, map_add_domain_reply)                           \
_(MAP_DEL_DOMAIN_REPLY, map_del_domain_reply)                           \
_(MAP_ADD_DEL_RULE_REPLY, map_add_del_rule_reply)	                \
_(MAP_DOMAIN_DETAILS, map_domain_details)                               \
_(MAP_RULE_DETAILS, map_rule_details)                                   \
_(WANT_INTERFACE_EVENTS_REPLY, want_interface_events_reply)             \
_(WANT_STATS_REPLY, want_stats_reply)					\
_(GET_FIRST_MSG_ID_REPLY, get_first_msg_id_reply)    			\
_(COP_INTERFACE_ENABLE_DISABLE_REPLY, cop_interface_enable_disable_reply) \
_(COP_WHITELIST_ENABLE_DISABLE_REPLY, cop_whitelist_enable_disable_reply) \
_(GET_NODE_GRAPH_REPLY, get_node_graph_reply)                           \
_(SW_INTERFACE_CLEAR_STATS_REPLY, sw_interface_clear_stats_reply)      \
_(TRACE_PROFILE_ADD_REPLY, trace_profile_add_reply)                   \
_(TRACE_PROFILE_APPLY_REPLY, trace_profile_apply_reply)               \
_(TRACE_PROFILE_DEL_REPLY, trace_profile_del_reply)                     \
_(LISP_ADD_DEL_LOCATOR_SET_REPLY, lisp_add_del_locator_set_reply)       \
_(LISP_ADD_DEL_LOCATOR_REPLY, lisp_add_del_locator_reply)               \
_(LISP_ADD_DEL_LOCAL_EID_REPLY, lisp_add_del_local_eid_reply)           \
_(LISP_ADD_DEL_REMOTE_MAPPING_REPLY, lisp_add_del_remote_mapping_reply) \
_(LISP_ADD_DEL_ADJACENCY_REPLY, lisp_add_del_adjacency_reply)           \
_(LISP_GPE_ADD_DEL_FWD_ENTRY_REPLY, lisp_gpe_add_del_fwd_entry_reply)   \
_(LISP_ADD_DEL_MAP_RESOLVER_REPLY, lisp_add_del_map_resolver_reply)     \
_(LISP_GPE_ENABLE_DISABLE_REPLY, lisp_gpe_enable_disable_reply)         \
_(LISP_ENABLE_DISABLE_REPLY, lisp_enable_disable_reply)                 \
_(LISP_PITR_SET_LOCATOR_SET_REPLY, lisp_pitr_set_locator_set_reply)     \
_(LISP_EID_TABLE_ADD_DEL_MAP_REPLY, lisp_eid_table_add_del_map_reply)   \
_(LISP_GPE_ADD_DEL_IFACE_REPLY, lisp_gpe_add_del_iface_reply)           \
_(LISP_LOCATOR_SET_DETAILS, lisp_locator_set_details)                   \
_(LISP_LOCAL_EID_TABLE_DETAILS, lisp_local_eid_table_details)           \
_(LISP_EID_TABLE_MAP_DETAILS, lisp_eid_table_map_details)               \
_(LISP_GPE_TUNNEL_DETAILS, lisp_gpe_tunnel_details)                     \
_(LISP_MAP_RESOLVER_DETAILS, lisp_map_resolver_details)                 \
_(LISP_ENABLE_DISABLE_STATUS_DETAILS,                                   \
  lisp_enable_disable_status_details)                                   \
_(LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY,                             \
  lisp_add_del_map_request_itr_rlocs_reply)                             \
_(LISP_GET_MAP_REQUEST_ITR_RLOCS_REPLY,                                 \
  lisp_get_map_request_itr_rlocs_reply)                                 \
_(SHOW_LISP_PITR_REPLY, show_lisp_pitr_reply)                           \
_(AF_PACKET_CREATE_REPLY, af_packet_create_reply)                       \
_(AF_PACKET_DELETE_REPLY, af_packet_delete_reply)                       \
_(POLICER_ADD_DEL_REPLY, policer_add_del_reply)                         \
_(POLICER_DETAILS, policer_details)                                     \
_(NETMAP_CREATE_REPLY, netmap_create_reply)                             \
_(NETMAP_DELETE_REPLY, netmap_delete_reply)                             \
_(MPLS_GRE_TUNNEL_DETAILS, mpls_gre_tunnel_details)                     \
_(MPLS_ETH_TUNNEL_DETAILS, mpls_eth_tunnel_details)                     \
_(MPLS_FIB_ENCAP_DETAILS, mpls_fib_encap_details)                       \
_(MPLS_FIB_DECAP_DETAILS, mpls_fib_decap_details)                       \
_(CLASSIFY_TABLE_IDS_REPLY, classify_table_ids_reply)                   \
_(CLASSIFY_TABLE_BY_INTERFACE_REPLY, classify_table_by_interface_reply) \
_(CLASSIFY_TABLE_INFO_REPLY, classify_table_info_reply)                 \
_(CLASSIFY_SESSION_DETAILS, classify_session_details)                   \
_(IPFIX_ENABLE_REPLY, ipfix_enable_reply)                               \
_(IPFIX_DETAILS, ipfix_details)                                         \
_(GET_NEXT_INDEX_REPLY, get_next_index_reply)                           \
_(PG_CREATE_INTERFACE_REPLY, pg_create_interface_reply)                 \
_(PG_CAPTURE_REPLY, pg_capture_reply)                                   \
_(PG_ENABLE_DISABLE_REPLY, pg_enable_disable_reply)

/* M: construct, but don't yet send a message */

#define M(T,t)                                  \
do {                                            \
    vam->result_ready = 0;                      \
    mp = vl_msg_api_alloc(sizeof(*mp));         \
    memset (mp, 0, sizeof (*mp));               \
    mp->_vl_msg_id = ntohs (VL_API_##T);        \
    mp->client_index = vam->my_client_index;    \
} while(0);

#define M2(T,t,n)                               \
do {                                            \
    vam->result_ready = 0;                      \
    mp = vl_msg_api_alloc(sizeof(*mp)+(n));     \
    memset (mp, 0, sizeof (*mp));               \
    mp->_vl_msg_id = ntohs (VL_API_##T);        \
    mp->client_index = vam->my_client_index;    \
} while(0);


/* S: send a message */
#define S (vl_msg_api_send_shmem (vam->vl_input_queue, (u8 *)&mp))

/* W: wait for results, with timeout */
#define W                                       \
do {                                            \
    timeout = vat_time_now (vam) + 1.0;         \
                                                \
    while (vat_time_now (vam) < timeout) {      \
        if (vam->result_ready == 1) {           \
            return (vam->retval);               \
        }                                       \
    }                                           \
    return -99;                                 \
} while(0);

/* W2: wait for results, with timeout */
#define W2(body)				\
do {                                            \
    timeout = vat_time_now (vam) + 1.0;         \
                                                \
    while (vat_time_now (vam) < timeout) {      \
        if (vam->result_ready == 1) {           \
	  (body);				\
	  return (vam->retval);			\
        }                                       \
    }                                           \
    return -99;                                 \
} while(0);

typedef struct {
    u8 * name;
    u32 value;
} name_sort_t;


#define STR_VTR_OP_CASE(op)     \
    case L2_VTR_ ## op:         \
        return "" # op;

static const char *str_vtr_op(u32 vtr_op)
{
    switch(vtr_op) {
        STR_VTR_OP_CASE(DISABLED);
        STR_VTR_OP_CASE(PUSH_1);
        STR_VTR_OP_CASE(PUSH_2);
        STR_VTR_OP_CASE(POP_1);
        STR_VTR_OP_CASE(POP_2);
        STR_VTR_OP_CASE(TRANSLATE_1_1);
        STR_VTR_OP_CASE(TRANSLATE_1_2);
        STR_VTR_OP_CASE(TRANSLATE_2_1);
        STR_VTR_OP_CASE(TRANSLATE_2_2);
    }

    return "UNKNOWN";
}

static int dump_sub_interface_table (vat_main_t * vam)
{
    const sw_interface_subif_t * sub = NULL;

    if (vam->json_output) {
        clib_warning ("JSON output supported only for VPE API calls and dump_stats_table");
        return -99;
    }

    fformat (vam->ofp,
             "%-30s%-12s%-11s%-7s%-5s%-9s%-9s%-6s%-8s%-10s%-10s\n",
             "Interface", "sw_if_index",
             "sub id", "dot1ad", "tags", "outer id",
             "inner id", "exact", "default",
             "outer any", "inner any");

    vec_foreach (sub, vam->sw_if_subif_table) {
        fformat (vam->ofp,
                 "%-30s%-12d%-11d%-7s%-5d%-9d%-9d%-6d%-8d%-10d%-10d\n",
                 sub->interface_name,
                 sub->sw_if_index,
                 sub->sub_id, sub->sub_dot1ad ? "dot1ad" : "dot1q",
                 sub->sub_number_of_tags, sub->sub_outer_vlan_id,
                 sub->sub_inner_vlan_id, sub->sub_exact_match, sub->sub_default,
                 sub->sub_outer_vlan_id_any, sub->sub_inner_vlan_id_any);
        if (sub->vtr_op != L2_VTR_DISABLED) {
            fformat (vam->ofp,
                     "  vlan-tag-rewrite - op: %-14s [ dot1q: %d "
                     "tag1: %d tag2: %d ]\n",
                     str_vtr_op(sub->vtr_op), sub->vtr_push_dot1q, 
                     sub->vtr_tag1, sub->vtr_tag2);
        }
    }

    return 0;
}

static int name_sort_cmp (void * a1, void * a2)
{
  name_sort_t * n1 = a1;
  name_sort_t * n2 = a2;

  return strcmp ((char *)n1->name, (char *)n2->name);
}

static int dump_interface_table (vat_main_t * vam)
{
    hash_pair_t * p;
    name_sort_t * nses = 0, * ns;

    if (vam->json_output) {
        clib_warning ("JSON output supported only for VPE API calls and dump_stats_table");
        return -99;
    }

    hash_foreach_pair (p, vam->sw_if_index_by_interface_name, 
    ({
        vec_add2 (nses, ns, 1);
        ns->name = (u8 *)(p->key);
        ns->value = (u32) p->value[0];
    }));

    vec_sort_with_function (nses, name_sort_cmp);

    fformat (vam->ofp, "%-25s%-15s\n", "Interface", "sw_if_index");
    vec_foreach (ns, nses) {
        fformat (vam->ofp, "%-25s%-15d\n", ns->name, ns->value);
    }
    vec_free (nses);
    return 0;
}

static int dump_ip_table (vat_main_t * vam, int is_ipv6)
{
    const ip_details_t * det = NULL;
    const ip_address_details_t * address = NULL;
    u32 i = ~0;

    fformat (vam->ofp,
             "%-12s\n",
             "sw_if_index");

    if (0 == vam) {
        return 0;
    }

    vec_foreach (det, vam->ip_details_by_sw_if_index[is_ipv6]) {
        i++;
        if (!det->present) {
            continue;
        }
        fformat (vam->ofp,
                 "%-12d\n",
                 i);
        fformat (vam->ofp,
                 "            %-30s%-13s\n",
                 "Address", "Prefix length");
        if (!det->addr) {
            continue;
        }
        vec_foreach (address, det->addr) {
            fformat (vam->ofp,
                     "            %-30U%-13d\n",
                     is_ipv6 ? format_ip6_address : format_ip4_address,
                     address->ip,
                     address->prefix_length);
        }
    }

    return 0;
}

static int dump_ipv4_table (vat_main_t * vam)
{
    if (vam->json_output) {
        clib_warning ("JSON output supported only for VPE API calls and dump_stats_table");
        return -99;
    }

    return dump_ip_table (vam, 0);
}

static int dump_ipv6_table (vat_main_t * vam)
{
    if (vam->json_output) {
        clib_warning ("JSON output supported only for VPE API calls and dump_stats_table");
        return -99;
    }

    return dump_ip_table (vam, 1);
}

static char* counter_type_to_str (u8 counter_type, u8 is_combined)
{
    if (!is_combined) {
        switch(counter_type) {
        case VNET_INTERFACE_COUNTER_DROP:
            return "drop";
        case VNET_INTERFACE_COUNTER_PUNT:
            return "punt";
        case VNET_INTERFACE_COUNTER_IP4:
            return "ip4";
        case VNET_INTERFACE_COUNTER_IP6:
            return "ip6";
        case VNET_INTERFACE_COUNTER_RX_NO_BUF:
            return "rx-no-buf";
        case VNET_INTERFACE_COUNTER_RX_MISS:
            return "rx-miss";
        case VNET_INTERFACE_COUNTER_RX_ERROR:
            return "rx-error";
        case VNET_INTERFACE_COUNTER_TX_ERROR:
            return "tx-error";
        default:
            return "INVALID-COUNTER-TYPE";
        }
    } else {
        switch(counter_type) {
        case VNET_INTERFACE_COUNTER_RX:
            return "rx";
        case VNET_INTERFACE_COUNTER_TX:
            return "tx";
        default:
            return "INVALID-COUNTER-TYPE";
        }
    }
}

static int dump_stats_table (vat_main_t * vam)
{
    vat_json_node_t node;
    vat_json_node_t *msg_array;
    vat_json_node_t *msg;
    vat_json_node_t *counter_array;
    vat_json_node_t *counter;
    interface_counter_t c;
    u64 packets;
    ip4_fib_counter_t *c4;
    ip6_fib_counter_t *c6;
    int i, j;

    if (!vam->json_output) {
        clib_warning ("dump_stats_table supported only in JSON format");
        return -99;
    }

    vat_json_init_object(&node);

    /* interface counters */
    msg_array = vat_json_object_add(&node, "interface_counters");
    vat_json_init_array(msg_array);
    for (i = 0; i < vec_len(vam->simple_interface_counters); i++) {
        msg = vat_json_array_add(msg_array);
        vat_json_init_object(msg);
        vat_json_object_add_string_copy(msg, "vnet_counter_type",
                (u8*)counter_type_to_str(i, 0));
        vat_json_object_add_int(msg, "is_combined", 0);
        counter_array = vat_json_object_add(msg, "data");
        vat_json_init_array(counter_array);
        for (j = 0; j < vec_len(vam->simple_interface_counters[i]); j++) {
            packets = vam->simple_interface_counters[i][j];
            vat_json_array_add_uint(counter_array, packets);
        }
    }
    for (i = 0; i < vec_len(vam->combined_interface_counters); i++) {
        msg = vat_json_array_add(msg_array);
        vat_json_init_object(msg);
        vat_json_object_add_string_copy(msg, "vnet_counter_type",
                (u8*)counter_type_to_str(i, 1));
        vat_json_object_add_int(msg, "is_combined", 1);
        counter_array = vat_json_object_add(msg, "data");
        vat_json_init_array(counter_array);
        for (j = 0; j < vec_len(vam->combined_interface_counters[i]); j++) {
            c = vam->combined_interface_counters[i][j];
            counter = vat_json_array_add(counter_array);
            vat_json_init_object(counter);
            vat_json_object_add_uint(counter, "packets", c.packets);
            vat_json_object_add_uint(counter, "bytes", c.bytes);
        }
    }

    /* ip4 fib counters */
    msg_array = vat_json_object_add(&node, "ip4_fib_counters");
    vat_json_init_array(msg_array);
    for (i = 0; i < vec_len(vam->ip4_fib_counters); i++) {
        msg = vat_json_array_add(msg_array);
        vat_json_init_object(msg);
        vat_json_object_add_uint(msg, "vrf_id", vam->ip4_fib_counters_vrf_id_by_index[i]);
        counter_array = vat_json_object_add(msg, "c");
        vat_json_init_array(counter_array);
        for (j = 0; j < vec_len(vam->ip4_fib_counters[i]); j++) {
            counter = vat_json_array_add(counter_array);
            vat_json_init_object(counter);
            c4 = &vam->ip4_fib_counters[i][j];
            vat_json_object_add_ip4(counter, "address", c4->address);
            vat_json_object_add_uint(counter, "address_length", c4->address_length);
            vat_json_object_add_uint(counter, "packets", c4->packets);
            vat_json_object_add_uint(counter, "bytes", c4->bytes);
        }
    }

    /* ip6 fib counters */
    msg_array = vat_json_object_add(&node, "ip6_fib_counters");
    vat_json_init_array(msg_array);
    for (i = 0; i < vec_len(vam->ip6_fib_counters); i++) {
        msg = vat_json_array_add(msg_array);
        vat_json_init_object(msg);
        vat_json_object_add_uint(msg, "vrf_id", vam->ip6_fib_counters_vrf_id_by_index[i]);
        counter_array = vat_json_object_add(msg, "c");
        vat_json_init_array(counter_array);
        for (j = 0; j < vec_len(vam->ip6_fib_counters[i]); j++) {
            counter = vat_json_array_add(counter_array);
            vat_json_init_object(counter);
            c6 = &vam->ip6_fib_counters[i][j];
            vat_json_object_add_ip6(counter, "address", c6->address);
            vat_json_object_add_uint(counter, "address_length", c6->address_length);
            vat_json_object_add_uint(counter, "packets", c6->packets);
            vat_json_object_add_uint(counter, "bytes", c6->bytes);
        }
    }

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);

    return 0;
}

int exec (vat_main_t * vam)
{
    api_main_t * am = &api_main;
    vl_api_cli_request_t *mp;
    f64 timeout;
    void * oldheap;
    u8 * cmd = 0;
    unformat_input_t * i = vam->input;

    if (vec_len(i->buffer) == 0)
        return -1;

    if (vam->exec_mode == 0 && unformat (i, "mode")) {        
        vam->exec_mode = 1;
        return 0;
    }
    if (vam->exec_mode == 1 && 
        (unformat (i, "exit") || unformat (i, "quit"))) {
        vam->exec_mode = 0;
        return 0;
    }
    

    M(CLI_REQUEST, cli_request);

    /* 
     * Copy cmd into shared memory.
     * In order for the CLI command to work, it
     * must be a vector ending in \n, not a C-string ending
     * in \n\0.
     */
    pthread_mutex_lock (&am->vlib_rp->mutex);
    oldheap = svm_push_data_heap (am->vlib_rp);

    vec_validate (cmd, vec_len(vam->input->buffer)-1);
    clib_memcpy (cmd, vam->input->buffer, vec_len(vam->input->buffer));

    svm_pop_heap (oldheap);
    pthread_mutex_unlock (&am->vlib_rp->mutex);

    mp->cmd_in_shmem = (u64) cmd;
    S;
    timeout = vat_time_now (vam) + 10.0;

    while (vat_time_now (vam) < timeout) {
        if (vam->result_ready == 1) {
            u8 * free_me;
            if (vam->shmem_result != NULL)
                fformat (vam->ofp, "%s", vam->shmem_result);
            pthread_mutex_lock (&am->vlib_rp->mutex);
            oldheap = svm_push_data_heap (am->vlib_rp);
            
            free_me = (u8 *)vam->shmem_result;
            vec_free (free_me);

            svm_pop_heap (oldheap);
            pthread_mutex_unlock (&am->vlib_rp->mutex);
            return 0;
        }
    }
    return -99;
}

static int api_create_loopback (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_create_loopback_t *mp;
    f64 timeout;
    u8 mac_address[6];
    u8 mac_set = 0;

    memset (mac_address, 0, sizeof (mac_address));

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
      {
        if (unformat (i, "mac %U", unformat_ethernet_address, mac_address))
            mac_set = 1;
        else
          break;
      }

    /* Construct the API message */
    M(CREATE_LOOPBACK, create_loopback);
    if (mac_set)
        clib_memcpy (mp->mac_address, mac_address, sizeof (mac_address));

    S; W;
}

static int api_delete_loopback (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_delete_loopback_t *mp;
    f64 timeout;
    u32 sw_if_index = ~0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
      {
        if (unformat (i, "sw_if_index %d", &sw_if_index))
          ;
        else
          break;
      }

    if (sw_if_index == ~0)
      {
        errmsg ("missing sw_if_index\n");
        return -99;
      }

    /* Construct the API message */
    M(DELETE_LOOPBACK, delete_loopback);
    mp->sw_if_index = ntohl (sw_if_index);

    S; W;
}

static int api_want_stats (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_want_stats_t * mp;
    f64 timeout;
    int enable = -1;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
      {
        if (unformat (i, "enable"))
          enable = 1;
        else if (unformat (i, "disable"))
          enable = 0;
        else
          break;
      }

    if (enable == -1)
      {
        errmsg ("missing enable|disable\n");
        return -99;
      }

    M(WANT_STATS, want_stats);
    mp->enable_disable = enable;

    S; W;
}

static int api_want_interface_events (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_want_interface_events_t * mp;
    f64 timeout;
    int enable = -1;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
      {
        if (unformat (i, "enable"))
          enable = 1;
        else if (unformat (i, "disable"))
          enable = 0;
        else
          break;
      }

    if (enable == -1)
      {
        errmsg ("missing enable|disable\n");
        return -99;
      }

    M(WANT_INTERFACE_EVENTS, want_interface_events);
    mp->enable_disable = enable;

    vam->interface_event_display = enable;

    S; W;
}


/* Note: non-static, called once to set up the initial intfc table */
int api_sw_interface_dump (vat_main_t * vam)
{
    vl_api_sw_interface_dump_t *mp;
    f64 timeout;
    hash_pair_t * p;
    name_sort_t * nses = 0, * ns;
    sw_interface_subif_t * sub = NULL;

    /* Toss the old name table */
    hash_foreach_pair (p, vam->sw_if_index_by_interface_name, 
    ({
        vec_add2 (nses, ns, 1);
        ns->name = (u8 *)(p->key);
        ns->value = (u32) p->value[0];
    }));

    hash_free (vam->sw_if_index_by_interface_name);

    vec_foreach (ns, nses)
        vec_free (ns->name);

    vec_free (nses);

    vec_foreach (sub, vam->sw_if_subif_table) {
        vec_free (sub->interface_name);
    }
    vec_free (vam->sw_if_subif_table);

    /* recreate the interface name hash table */
    vam->sw_if_index_by_interface_name 
        = hash_create_string (0, sizeof(uword));

    /* Get list of ethernets */
    M(SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, "Ether", sizeof(mp->name_filter)-1);
    S;

    /* and local / loopback interfaces */
    M(SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, "lo", sizeof(mp->name_filter)-1);
    S;


    /* and vxlan-gpe tunnel interfaces */
    M(SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, "vxlan_gpe", sizeof(mp->name_filter)-1);
    S;

    /* and vxlan tunnel interfaces */
    M(SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, "vxlan", sizeof(mp->name_filter)-1);
    S;

    /* and host (af_packet) interfaces */
    M(SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, "host", sizeof(mp->name_filter)-1);
    S;

    /* and l2tpv3 tunnel interfaces */
    M(SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, "l2tpv3_tunnel", sizeof(mp->name_filter)-1);
    S;

    /* and GRE tunnel interfaces */
    M(SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, "gre", sizeof(mp->name_filter)-1);
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}

static int api_sw_interface_set_flags (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_sw_interface_set_flags_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8 sw_if_index_set = 0;
    u8 admin_up = 0, link_up = 0;
    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "admin-up"))
            admin_up = 1;
        else if (unformat (i, "admin-down"))
            admin_up = 0;
        else if (unformat (i, "link-up"))
            link_up = 1;
        else if (unformat (i, "link-down"))
            link_up = 0;
        else if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else
            break;
    }

    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    /* Construct the API message */
    M(SW_INTERFACE_SET_FLAGS, sw_interface_set_flags);
    mp->sw_if_index = ntohl (sw_if_index);
    mp->admin_up_down = admin_up;
    mp->link_up_down = link_up;

    /* send it... */
    S;

    /* Wait for a reply, return the good/bad news... */
    W;
}

static int api_sw_interface_clear_stats (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_sw_interface_clear_stats_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8 sw_if_index_set = 0;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else
            break;
    }

    /* Construct the API message */
    M(SW_INTERFACE_CLEAR_STATS, sw_interface_clear_stats);

    if (sw_if_index_set == 1)
        mp->sw_if_index = ntohl (sw_if_index);
    else
    	mp->sw_if_index = ~0;

    /* send it... */
    S;

    /* Wait for a reply, return the good/bad news... */
    W;
}

static int api_sw_interface_add_del_address (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_sw_interface_add_del_address_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8 sw_if_index_set = 0;
    u8 is_add = 1, del_all = 0;
    u32 address_length = 0;
    u8 v4_address_set = 0;
    u8 v6_address_set = 0;
    ip4_address_t v4address;
    ip6_address_t v6address;
    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "del-all"))
            del_all = 1;
        else if (unformat (i, "del"))
            is_add = 0;
        else if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "%U/%d", 
                           unformat_ip4_address, &v4address, 
                           &address_length))
            v4_address_set = 1;
        else if (unformat (i, "%U/%d", 
                           unformat_ip6_address, &v6address, 
                           &address_length))
            v6_address_set = 1;
        else
            break;
    }

    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }
    if (v4_address_set && v6_address_set) {
        errmsg ("both v4 and v6 addresses set\n");
        return -99;
    }
    if (!v4_address_set && !v6_address_set && !del_all) {
        errmsg ("no addresses set\n");
        return -99;
    }

    /* Construct the API message */
    M(SW_INTERFACE_ADD_DEL_ADDRESS, sw_interface_add_del_address);

    mp->sw_if_index = ntohl (sw_if_index);
    mp->is_add = is_add;
    mp->del_all = del_all;
    if (v6_address_set) {
        mp->is_ipv6 = 1;
        clib_memcpy (mp->address, &v6address, sizeof (v6address));
    } else {
        clib_memcpy (mp->address, &v4address, sizeof (v4address));
    }
    mp->address_length = address_length;

    /* send it... */
    S;

    /* Wait for a reply, return good/bad news  */
    W;
}

static int api_sw_interface_set_table (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_sw_interface_set_table_t *mp;
    f64 timeout;
    u32 sw_if_index, vrf_id = 0;
    u8 sw_if_index_set = 0;
    u8 is_ipv6 = 0;
    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "vrf %d", &vrf_id))
            ;
        else if (unformat (i, "ipv6"))
            is_ipv6 = 1;
        else
            break;
    }

    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    /* Construct the API message */
    M(SW_INTERFACE_SET_TABLE, sw_interface_set_table);

    mp->sw_if_index = ntohl (sw_if_index);
    mp->is_ipv6 = is_ipv6;
    mp->vrf_id = ntohl (vrf_id);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static int api_sw_interface_set_vpath (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_sw_interface_set_vpath_t *mp;
    f64 timeout;
    u32 sw_if_index = 0;
    u8 sw_if_index_set = 0;
    u8 is_enable = 0;
    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "enable"))
            is_enable = 1;
        else if (unformat (i, "disable"))
            is_enable = 0;
        else
            break;
    }

    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    /* Construct the API message */
    M(SW_INTERFACE_SET_VPATH, sw_interface_set_vpath);

    mp->sw_if_index = ntohl (sw_if_index);
    mp->enable = is_enable;

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static int api_sw_interface_set_l2_xconnect (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_sw_interface_set_l2_xconnect_t *mp;
    f64 timeout;
    u32 rx_sw_if_index;
    u8 rx_sw_if_index_set = 0;
    u32 tx_sw_if_index;
    u8 tx_sw_if_index_set = 0;
    u8 enable = 1;
    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "rx_sw_if_index %d", &rx_sw_if_index))
            rx_sw_if_index_set = 1;	
	else if (unformat (i, "tx_sw_if_index %d", &tx_sw_if_index))
            tx_sw_if_index_set = 1;
	else if (unformat (i, "rx")) {
	    if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
		if (unformat (i, "%U", unformat_sw_if_index, vam,
			      &rx_sw_if_index))
		    rx_sw_if_index_set = 1;
	    } else
		break;
	} else if (unformat (i, "tx")) {
	    if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
		if (unformat (i, "%U", unformat_sw_if_index, vam,
			      &tx_sw_if_index))
		    tx_sw_if_index_set = 1;
	    } else
		break;
	} else if (unformat (i, "enable"))
	    enable = 1;
	else if (unformat (i, "disable")) 
	    enable = 0;
	else
            break;
    }

    if (rx_sw_if_index_set == 0) {
        errmsg ("missing rx interface name or rx_sw_if_index\n");
        return -99;
    }

    if (enable && (tx_sw_if_index_set == 0)) {
        errmsg ("missing tx interface name or tx_sw_if_index\n");
        return -99;
    }
    
    M(SW_INTERFACE_SET_L2_XCONNECT, sw_interface_set_l2_xconnect);

    mp->rx_sw_if_index = ntohl(rx_sw_if_index);
    mp->tx_sw_if_index = ntohl(tx_sw_if_index);
    mp->enable = enable;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_sw_interface_set_l2_bridge (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_sw_interface_set_l2_bridge_t *mp;
    f64 timeout;
    u32 rx_sw_if_index;
    u8 rx_sw_if_index_set = 0;
    u32 bd_id;
    u8 bd_id_set = 0;
    u8 bvi = 0;
    u32 shg = 0;
    u8 enable = 1;
    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "sw_if_index %d", &rx_sw_if_index))
            rx_sw_if_index_set = 1;	
	else if (unformat (i, "bd_id %d", &bd_id))
            bd_id_set = 1;
	else if (unformat (i, "%U", unformat_sw_if_index, vam,
                           &rx_sw_if_index))
            rx_sw_if_index_set = 1;
	else if (unformat (i, "shg %d", &shg)) 
            ;
        else if (unformat (i, "bvi"))
            bvi = 1;
	else if (unformat (i, "enable"))
	    enable = 1;
	else if (unformat (i, "disable")) 
	    enable = 0;
	else
            break;
    }

    if (rx_sw_if_index_set == 0) {
        errmsg ("missing rx interface name or sw_if_index\n");
        return -99;
    }

    if (enable && (bd_id_set == 0)) {
        errmsg ("missing bridge domain\n");
        return -99;
    }
    
    M(SW_INTERFACE_SET_L2_BRIDGE, sw_interface_set_l2_bridge);

    mp->rx_sw_if_index = ntohl(rx_sw_if_index);
    mp->bd_id = ntohl(bd_id);
    mp->shg = (u8)shg;
    mp->bvi = bvi;
    mp->enable = enable;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_bridge_domain_dump (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_bridge_domain_dump_t *mp;
    f64 timeout;
    u32 bd_id = ~0;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "bd_id %d", &bd_id))
            ;
        else
            break;
    }

    M(BRIDGE_DOMAIN_DUMP, bridge_domain_dump);
    mp->bd_id = ntohl(bd_id);
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }

    W;
    /* NOTREACHED */
    return 0;
}

static int api_bridge_domain_add_del (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_bridge_domain_add_del_t *mp;
    f64 timeout;
    u32 bd_id = ~0;
    u8 is_add = 1;
    u32 flood = 1, forward = 1, learn = 1, uu_flood = 1, arp_term = 0;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "bd_id %d", &bd_id))
            ;
	else if (unformat (i, "flood %d", &flood))
             ;
	else if (unformat (i, "uu-flood %d", &uu_flood))
             ;
	else if (unformat (i, "forward %d", &forward))
             ;
	else if (unformat (i, "learn %d", &learn))
             ;
	else if (unformat (i, "arp-term %d", &arp_term))
             ;
	else if (unformat (i, "del")) {
             is_add = 0;
             flood = uu_flood = forward = learn = 0;
        }
        else
            break;
    }

    if (bd_id == ~0) {
        errmsg ("missing bridge domain\n");
        return -99;
    }

    M(BRIDGE_DOMAIN_ADD_DEL, bridge_domain_add_del);

    mp->bd_id = ntohl(bd_id);
    mp->flood = flood;
    mp->uu_flood = uu_flood;
    mp->forward = forward;
    mp->learn = learn;
    mp->arp_term = arp_term;
    mp->is_add = is_add;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_l2fib_add_del (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_l2fib_add_del_t *mp;
    f64 timeout;
    u64 mac = 0;
    u8 mac_set = 0;
    u32 bd_id;
    u8 bd_id_set = 0;
    u32 sw_if_index;
    u8 sw_if_index_set = 0;
    u8 is_add = 1;
    u8 static_mac = 0;
    u8 filter_mac = 0;
    u8 bvi_mac = 0;
    int count = 1;
    f64 before = 0;
    int j;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "mac %U", unformat_ethernet_address, &mac))
            mac_set = 1;
	else if (unformat (i, "bd_id %d", &bd_id))
            bd_id_set = 1;
	else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;	
	else if (unformat (i, "sw_if")) {
	    if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
		if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
		    sw_if_index_set = 1;
	    } else
		break;
	} else if (unformat (i, "static"))
	    static_mac = 1;
	else if (unformat (i, "filter")) {
	    filter_mac = 1;
	    static_mac = 1;
	} else if (unformat (i, "bvi")) {
	    bvi_mac = 1;
	    static_mac = 1;
	} else if (unformat (i, "del"))
	    is_add = 0;
        else if (unformat (i, "count %d", &count))
	    ;
	else
	    break;
    }

    if (mac_set == 0) {
        errmsg ("missing mac address\n");
        return -99;
    }

    if (bd_id_set == 0) {
        errmsg ("missing bridge domain\n");
        return -99;
    }

    if (is_add && (sw_if_index_set == 0)) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    if (count > 1) {
        /* Turn on async mode */
        vam->async_mode = 1;
        vam->async_errors = 0;
        before = vat_time_now(vam);
    }

    for (j = 0; j < count; j++) {
	M(L2FIB_ADD_DEL, l2fib_add_del);
	
	mp->mac = mac;
	mp->bd_id = ntohl(bd_id);
	mp->is_add = is_add;
	
	if (is_add) {
	    mp->sw_if_index = ntohl(sw_if_index);
	    mp->static_mac = static_mac;
	    mp->filter_mac = filter_mac;
	    mp->bvi_mac = bvi_mac;
	}
	increment_mac_address (&mac);
	/* send it... */
        S;
    }

    if (count > 1) {
        vl_api_control_ping_t * mp;
        f64 after;

        /* Shut off async mode */
        vam->async_mode = 0;

        M(CONTROL_PING, control_ping);
        S;

        timeout = vat_time_now(vam) + 1.0;
        while (vat_time_now (vam) < timeout)
            if (vam->result_ready == 1)
                goto out;
        vam->retval = -99;

    out:
        if (vam->retval == -99)
            errmsg ("timeout\n");

        if (vam->async_errors > 0) {
            errmsg ("%d asynchronous errors\n", vam->async_errors);
            vam->retval = -98;
        }
        vam->async_errors = 0;
        after = vat_time_now(vam);

        fformat(vam->ofp, "%d routes in %.6f secs, %.2f routes/sec\n",
                count, after - before, count / (after - before));
    } else {
        /* Wait for a reply... */
        W;
    }
    /* Return the good/bad news */
    return (vam->retval);
}

static int api_l2_flags (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_l2_flags_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u32 feature_bitmap = 0;
    u8 sw_if_index_set = 0;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;	
        else if (unformat (i, "sw_if")) {
            if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
                if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
                    sw_if_index_set = 1;
            } else
                break;
	} else if (unformat (i, "learn"))
            feature_bitmap |= L2INPUT_FEAT_LEARN;
	else if (unformat (i, "forward"))
	    feature_bitmap |= L2INPUT_FEAT_FWD;
	else if (unformat (i, "flood"))
	    feature_bitmap |= L2INPUT_FEAT_FLOOD;
	else if (unformat (i, "uu-flood"))
	    feature_bitmap |= L2INPUT_FEAT_UU_FLOOD;
	else
            break;
    }

    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    M(L2_FLAGS, l2_flags);

    mp->sw_if_index = ntohl(sw_if_index);
    mp->feature_bitmap = ntohl(feature_bitmap);

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_bridge_flags (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_bridge_flags_t *mp;
    f64 timeout;
    u32 bd_id;
    u8 bd_id_set = 0;
    u8 is_set = 1;
    u32 flags = 0;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "bd_id %d", &bd_id))
            bd_id_set = 1;
	else if (unformat (i, "learn"))
	    flags |= L2_LEARN;
	else if (unformat (i, "forward"))
	    flags |= L2_FWD;
	else if (unformat (i, "flood"))
	    flags |= L2_FLOOD;
	else if (unformat (i, "uu-flood"))
	    flags |= L2_UU_FLOOD;
	else if (unformat (i, "arp-term"))
	    flags |= L2_ARP_TERM;
	else if (unformat (i, "off"))
	    is_set = 0;
	else if (unformat (i, "disable"))
	    is_set = 0;
	else
            break;
    }

    if (bd_id_set == 0) {
        errmsg ("missing bridge domain\n");
        return -99;
    }

    M(BRIDGE_FLAGS, bridge_flags);

    mp->bd_id = ntohl(bd_id);
    mp->feature_bitmap = ntohl(flags);
    mp->is_set = is_set;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_bd_ip_mac_add_del (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_bd_ip_mac_add_del_t *mp;
    f64 timeout;
    u32 bd_id;
    u8 is_ipv6 = 0;
    u8 is_add = 1;
    u8 bd_id_set = 0;
    u8 ip_set = 0;
    u8 mac_set = 0;
    ip4_address_t v4addr;
    ip6_address_t v6addr;
    u8 macaddr[6];
    

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "bd_id %d", &bd_id)) {
            bd_id_set++;
	} else if (unformat (i, "%U", unformat_ip4_address, &v4addr)) {
	    ip_set++;
	} else if (unformat (i, "%U", unformat_ip6_address, &v6addr)) {
	    ip_set++;
	    is_ipv6++;
	} else if (unformat (i, "%U", unformat_ethernet_address, macaddr)) {
	    mac_set++;
	} else if (unformat (i, "del"))
	    is_add = 0;
	else
            break;
    }

    if (bd_id_set == 0) {
        errmsg ("missing bridge domain\n");
        return -99;
    } else if (ip_set == 0) {
        errmsg ("missing IP address\n");
        return -99;
    } else if (mac_set == 0) {
        errmsg ("missing MAC address\n");
        return -99;
    }

    M(BD_IP_MAC_ADD_DEL, bd_ip_mac_add_del);

    mp->bd_id = ntohl(bd_id);
    mp->is_ipv6 = is_ipv6;
    mp->is_add = is_add;
    if (is_ipv6)
	 clib_memcpy (mp->ip_address, &v6addr, sizeof (v6addr));
    else clib_memcpy (mp->ip_address, &v4addr, sizeof (v4addr));
    clib_memcpy (mp->mac_address, macaddr, 6);
    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_tap_connect (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_tap_connect_t *mp;
    f64 timeout;
    u8 mac_address[6];
    u8 random_mac = 1;
    u8 name_set = 0;
    u8 * tap_name;

    memset (mac_address, 0, sizeof (mac_address));
    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "mac %U", unformat_ethernet_address, mac_address)) {
            random_mac = 0;
        }
        else if (unformat (i, "random-mac"))
            random_mac = 1;
        else if (unformat (i, "tapname %s", &tap_name))
            name_set = 1;
        else
            break;
    }

    if (name_set == 0) {
        errmsg ("missing tap name\n");
        return -99;
    }
    if (vec_len (tap_name) > 63) {
        errmsg ("tap name too long\n");
    }
    vec_add1 (tap_name, 0);
        
    /* Construct the API message */
    M(TAP_CONNECT, tap_connect);

    mp->use_random_mac = random_mac;
    clib_memcpy (mp->mac_address, mac_address, 6);
    clib_memcpy (mp->tap_name, tap_name, vec_len (tap_name));
    vec_free (tap_name);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static int api_tap_modify (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_tap_modify_t *mp;
    f64 timeout;
    u8 mac_address[6];
    u8 random_mac = 1;
    u8 name_set = 0;
    u8 * tap_name;
    u32 sw_if_index = ~0;
    u8 sw_if_index_set = 0;

    memset (mac_address, 0, sizeof (mac_address));
    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "mac %U", unformat_ethernet_address, mac_address)) {
            random_mac = 0;
        }
        else if (unformat (i, "random-mac"))
            random_mac = 1;
        else if (unformat (i, "tapname %s", &tap_name))
            name_set = 1;
        else
            break;
    }

    if (sw_if_index_set == 0) {
        errmsg ("missing vpp interface name");
        return -99;
    }
    if (name_set == 0) {
        errmsg ("missing tap name\n");
        return -99;
    }
    if (vec_len (tap_name) > 63) {
        errmsg ("tap name too long\n");
    }
    vec_add1 (tap_name, 0);
        
    /* Construct the API message */
    M(TAP_MODIFY, tap_modify);

    mp->use_random_mac = random_mac;
    mp->sw_if_index = ntohl(sw_if_index);
    clib_memcpy (mp->mac_address, mac_address, 6);
    clib_memcpy (mp->tap_name, tap_name, vec_len (tap_name));
    vec_free (tap_name);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static int api_tap_delete (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_tap_delete_t *mp;
    f64 timeout;
    u32 sw_if_index = ~0;
    u8 sw_if_index_set = 0;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else
            break;
    }

    if (sw_if_index_set == 0) {
        errmsg ("missing vpp interface name");
        return -99;
    }
        
    /* Construct the API message */
    M(TAP_DELETE, tap_delete);

    mp->sw_if_index = ntohl(sw_if_index);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static int api_ip_add_del_route (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_ip_add_del_route_t *mp;
    f64 timeout;
    u32 sw_if_index = ~0, vrf_id = 0;
    u8 sw_if_index_set = 0;
    u8 is_ipv6 = 0;
    u8 is_local = 0, is_drop = 0;
    u8 create_vrf_if_needed = 0;
    u8 is_add = 1;
    u8 next_hop_weight = 1;
    u8 not_last = 0;
    u8 is_multipath = 0;
    u8 address_set = 0;
    u8 address_length_set = 0;
    u32 lookup_in_vrf = 0;
    u32 resolve_attempts = 0;
    u32 dst_address_length = 0;
    u8 next_hop_set = 0;
    ip4_address_t v4_dst_address, v4_next_hop_address;
    ip6_address_t v6_dst_address, v6_next_hop_address;
    int count = 1;
    int j;
    f64 before = 0;
    u32 random_add_del = 0;
    u32 * random_vector = 0;
    uword * random_hash;
    u32 random_seed = 0xdeaddabe;
    u32 classify_table_index = ~0;
    u8 is_classify = 0;
    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "%U", unformat_ip4_address,
                           &v4_dst_address)) {
            address_set = 1;
            is_ipv6 = 0;
        }
        else if (unformat (i, "%U", unformat_ip6_address, &v6_dst_address)) {
            address_set = 1;
            is_ipv6 = 1;
        }
        else if (unformat (i, "/%d", &dst_address_length)) {
            address_length_set = 1;
        }
        
        else if (is_ipv6 == 0 && unformat (i, "via %U", unformat_ip4_address, 
                                           &v4_next_hop_address)) {
            next_hop_set = 1;
        }
        else if (is_ipv6 == 1 && unformat (i, "via %U", unformat_ip6_address, 
                                           &v6_next_hop_address)) {
            next_hop_set = 1;
        }
        else if (unformat (i, "resolve-attempts %d", &resolve_attempts))
            ;
        else if (unformat (i, "weight %d", &next_hop_weight))
            ;
        else if (unformat (i, "drop")) {
            is_drop = 1;
        } else if (unformat (i, "local")) {
            is_local = 1;
        } else if (unformat (i, "classify %d", &classify_table_index)) {
            is_classify = 1;
        } else if (unformat (i, "del"))
            is_add = 0;
        else if (unformat (i, "add"))
            is_add = 1;
        else if (unformat (i, "not-last"))
            not_last = 1;
        else if (unformat (i, "multipath"))
            is_multipath = 1;
        else if (unformat (i, "vrf %d", &vrf_id))
            ;
        else if (unformat (i, "create-vrf"))
            create_vrf_if_needed = 1;
        else if (unformat (i, "count %d", &count))
            ;
        else if (unformat (i, "lookup-in-vrf %d", &lookup_in_vrf))
            ;
        else if (unformat (i, "random"))
            random_add_del = 1;
        else if (unformat (i, "seed %d", &random_seed))
            ;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (resolve_attempts > 0 && sw_if_index_set == 0) {
        errmsg ("ARP resolution needs explicit interface or sw_if_index\n");
        return -99;
    }
    
    if (!next_hop_set && !is_drop && !is_local && !is_classify) {
        errmsg ("next hop / local / drop / classify not set\n");
        return -99;
    }

    if (address_set == 0) {
        errmsg ("missing addresses\n");
        return -99;
    }

    if (address_length_set == 0) {
        errmsg ("missing address length\n");
        return -99;
    }
    
    /* Generate a pile of unique, random routes */
    if (random_add_del) {
        u32 this_random_address;
        random_hash = hash_create (count, sizeof(uword));

        hash_set (random_hash, v4_next_hop_address.as_u32, 1);
        for (j = 0; j <= count; j++) {
            do {
                this_random_address = random_u32 (&random_seed);
                this_random_address = 
                    clib_host_to_net_u32 (this_random_address);
            } while (hash_get (random_hash, this_random_address));
            vec_add1 (random_vector, this_random_address);
            hash_set (random_hash, this_random_address, 1);
        }
        hash_free (random_hash);
        v4_dst_address.as_u32 = random_vector[0];
    }

    if (count > 1) {
        /* Turn on async mode */
        vam->async_mode = 1;
        vam->async_errors = 0;
        before = vat_time_now(vam);
    }

    for (j = 0; j < count; j++) {
        /* Construct the API message */
        M(IP_ADD_DEL_ROUTE, ip_add_del_route);
    
        mp->next_hop_sw_if_index = ntohl (sw_if_index);
        mp->vrf_id = ntohl (vrf_id);
        if (resolve_attempts > 0) {
            mp->resolve_attempts = ntohl (resolve_attempts);
            mp->resolve_if_needed = 1;
        }
        mp->create_vrf_if_needed = create_vrf_if_needed;
    
        mp->is_add = is_add;
        mp->is_drop = is_drop;
        mp->is_ipv6 = is_ipv6;
        mp->is_local = is_local;
        mp->is_classify = is_classify;
        mp->is_multipath = is_multipath;
        mp->not_last = not_last;
        mp->next_hop_weight = next_hop_weight;
        mp->dst_address_length = dst_address_length;
        mp->lookup_in_vrf = ntohl(lookup_in_vrf);
        mp->classify_table_index = ntohl(classify_table_index);

        if (is_ipv6){
            clib_memcpy (mp->dst_address, &v6_dst_address, sizeof (v6_dst_address));
            if (next_hop_set)
                clib_memcpy (mp->next_hop_address, &v6_next_hop_address, 
                        sizeof (v6_next_hop_address));
            increment_v6_address (&v6_dst_address);
        } else {
            clib_memcpy (mp->dst_address, &v4_dst_address, sizeof (v4_dst_address));
            if (next_hop_set)
                clib_memcpy (mp->next_hop_address, &v4_next_hop_address, 
                        sizeof (v4_next_hop_address));
            if (random_add_del)
                v4_dst_address.as_u32 = random_vector[j+1];
            else
                increment_v4_address (&v4_dst_address);
        }
        /* send it... */
        S;
    }

    /* When testing multiple add/del ops, use a control-ping to sync */
    if (count > 1) {
        vl_api_control_ping_t * mp;
        f64 after;

        /* Shut off async mode */
        vam->async_mode = 0;

        M(CONTROL_PING, control_ping);
        S;

        timeout = vat_time_now(vam) + 1.0;
        while (vat_time_now (vam) < timeout)
            if (vam->result_ready == 1)
                goto out;
        vam->retval = -99;

    out:
        if (vam->retval == -99)
            errmsg ("timeout\n");

        if (vam->async_errors > 0) {
            errmsg ("%d asynchronous errors\n", vam->async_errors);
            vam->retval = -98;
        }
        vam->async_errors = 0;
        after = vat_time_now(vam);

        fformat(vam->ofp, "%d routes in %.6f secs, %.2f routes/sec\n",
                count, after - before, count / (after - before));
    } else {
        /* Wait for a reply... */
        W;
    }

    /* Return the good/bad news */
    return (vam->retval);
}

static int api_proxy_arp_add_del (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_proxy_arp_add_del_t *mp;
    f64 timeout;
    u32 vrf_id = 0;
    u8 is_add = 1;
    ip4_address_t lo, hi;
    u8 range_set = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "vrf %d", &vrf_id))
	    ;
	else if (unformat (i, "%U - %U", unformat_ip4_address, &lo, 
			   unformat_ip4_address, &hi))
	    range_set = 1;
	else if (unformat (i, "del"))
	    is_add = 0;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }
    
    if (range_set == 0) {
        errmsg ("address range not set\n");
        return -99;
    }

    M(PROXY_ARP_ADD_DEL, proxy_arp_add_del);

    mp->vrf_id = ntohl(vrf_id);
    mp->is_add = is_add;
    clib_memcpy(mp->low_address, &lo, sizeof (mp->low_address));
    clib_memcpy(mp->hi_address, &hi, sizeof (mp->hi_address));

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_proxy_arp_intfc_enable_disable (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_proxy_arp_intfc_enable_disable_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8 enable = 1;
    u8 sw_if_index_set = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
	else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
	else if (unformat (i, "enable"))
            enable = 1;
	else if (unformat (i, "disable"))
            enable = 0;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }
    
    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    M(PROXY_ARP_INTFC_ENABLE_DISABLE, proxy_arp_intfc_enable_disable);

    mp->sw_if_index = ntohl(sw_if_index);
    mp->enable_disable = enable;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_mpls_add_del_decap (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_mpls_add_del_decap_t *mp;
    f64 timeout;
    u32 rx_vrf_id = 0;
    u32 tx_vrf_id = 0;
    u32 label = 0;
    u8 is_add = 1;
    u8 s_bit = 1;
    u32 next_index = 1;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "rx_vrf_id %d", &rx_vrf_id))
	    ;
	else if (unformat (i, "tx_vrf_id %d", &tx_vrf_id))
	    ;
	else if (unformat (i, "label %d", &label))
	    ;
	else if (unformat (i, "next-index %d", &next_index))
            ;
	else if (unformat (i, "del"))
	    is_add = 0;
        else if (unformat (i, "s-bit-clear"))
            s_bit = 0;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }
    
    M(MPLS_ADD_DEL_DECAP, mpls_add_del_decap);

    mp->rx_vrf_id = ntohl(rx_vrf_id);
    mp->tx_vrf_id = ntohl(tx_vrf_id);
    mp->label = ntohl(label);
    mp->next_index = ntohl(next_index);
    mp->s_bit = s_bit;
    mp->is_add = is_add;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_mpls_add_del_encap (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_mpls_add_del_encap_t *mp;
    f64 timeout;
    u32 vrf_id = 0;
    u32 *labels = 0;
    u32 label;
    ip4_address_t dst_address;
    u8 is_add = 1;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "vrf %d", &vrf_id))
	    ;
	else if (unformat (i, "label %d", &label))
            vec_add1 (labels, ntohl(label));
	else if (unformat (i, "dst %U", unformat_ip4_address, &dst_address))
            ;
	else if (unformat (i, "del"))
	    is_add = 0;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (vec_len (labels) == 0) {
        errmsg ("missing encap label stack\n");
        return -99;
    }
    
    M2(MPLS_ADD_DEL_ENCAP, mpls_add_del_encap, 
       sizeof (u32) * vec_len (labels));

    mp->vrf_id = ntohl(vrf_id);
    clib_memcpy(mp->dst_address, &dst_address, sizeof (dst_address));
    mp->is_add = is_add;
    mp->nlabels = vec_len (labels);
    clib_memcpy(mp->labels, labels, sizeof(u32)*mp->nlabels);

    vec_free(labels);

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_mpls_gre_add_del_tunnel (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_mpls_gre_add_del_tunnel_t *mp;
    f64 timeout;
    u32 inner_vrf_id = 0;
    u32 outer_vrf_id = 0;
    ip4_address_t src_address;
    ip4_address_t dst_address;
    ip4_address_t intfc_address;
    u32 tmp;
    u8 intfc_address_length = 0;
    u8 is_add = 1;
    u8 l2_only = 0;
    
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "inner_vrf_id %d", &inner_vrf_id))
	    ;
	else if (unformat (i, "outer_vrf_id %d", &outer_vrf_id))
	    ;
	else if (unformat (i, "src %U", unformat_ip4_address, &src_address))
            ;
	else if (unformat (i, "dst %U", unformat_ip4_address, &dst_address))
            ;
        else if (unformat (i, "adj %U/%d", unformat_ip4_address,
                           &intfc_address, &tmp))
            intfc_address_length = tmp;
        else if (unformat (i, "l2-only"))
            l2_only = 1;
	else if (unformat (i, "del"))
	    is_add = 0;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }
    
    M(MPLS_GRE_ADD_DEL_TUNNEL, mpls_gre_add_del_tunnel);

    mp->inner_vrf_id = ntohl(inner_vrf_id);
    mp->outer_vrf_id = ntohl(outer_vrf_id);
    clib_memcpy(mp->src_address, &src_address, sizeof (src_address));
    clib_memcpy(mp->dst_address, &dst_address, sizeof (dst_address));
    clib_memcpy(mp->intfc_address, &intfc_address, sizeof (intfc_address));
    mp->intfc_address_length = intfc_address_length;
    mp->l2_only = l2_only;
    mp->is_add = is_add;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_mpls_ethernet_add_del_tunnel (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_mpls_ethernet_add_del_tunnel_t *mp;
    f64 timeout;
    u32 inner_vrf_id = 0;
    ip4_address_t intfc_address;
    u8 dst_mac_address[6];
    int dst_set = 1;
    u32 tmp;
    u8 intfc_address_length = 0;
    u8 is_add = 1;
    u8 l2_only = 0;
    u32 tx_sw_if_index;
    int tx_sw_if_index_set = 0;
    
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "vrf %d", &inner_vrf_id))
	    ;
        else if (unformat (i, "adj %U/%d", unformat_ip4_address,
                           &intfc_address, &tmp))
            intfc_address_length = tmp;
        else if (unformat (i, "%U", 
                           unformat_sw_if_index, vam, &tx_sw_if_index))
            tx_sw_if_index_set = 1;
        else if (unformat (i, "tx_sw_if_index %d", &tx_sw_if_index))
            tx_sw_if_index_set = 1;
        else if (unformat (i, "dst %U", unformat_ethernet_address, 
                           dst_mac_address))
            dst_set = 1;
	else if (unformat (i, "l2-only"))
	    l2_only = 1;
	else if (unformat (i, "del"))
	    is_add = 0;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (!dst_set) {
        errmsg ("dst (mac address) not set\n");
        return -99;
    }
    if (!tx_sw_if_index_set) {
        errmsg ("tx-intfc not set\n");
        return -99;
    }
    
    M(MPLS_ETHERNET_ADD_DEL_TUNNEL, mpls_ethernet_add_del_tunnel);

    mp->vrf_id = ntohl(inner_vrf_id);
    clib_memcpy (mp->adj_address, &intfc_address, sizeof (intfc_address));
    mp->adj_address_length = intfc_address_length;
    clib_memcpy (mp->dst_mac_address, dst_mac_address, sizeof (dst_mac_address));
    mp->tx_sw_if_index = ntohl(tx_sw_if_index);
    mp->l2_only = l2_only;
    mp->is_add = is_add;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_mpls_ethernet_add_del_tunnel_2 (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_mpls_ethernet_add_del_tunnel_2_t *mp;
    f64 timeout;
    u32 inner_vrf_id = 0;
    u32 outer_vrf_id = 0;
    ip4_address_t adj_address;
    int adj_address_set = 0;
    ip4_address_t next_hop_address;
    int next_hop_address_set = 0;
    u32 tmp;
    u8 adj_address_length = 0;
    u8 l2_only = 0;
    u8 is_add = 1;
    u32 resolve_attempts = 5;
    u8 resolve_if_needed = 1;
    
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "inner_vrf_id %d", &inner_vrf_id))
	    ;
	else if (unformat (i, "outer_vrf_id %d", &outer_vrf_id))
	    ;
        else if (unformat (i, "adj %U/%d", unformat_ip4_address,
                           &adj_address, &tmp)) {
            adj_address_length = tmp;
            adj_address_set = 1;
        }
        else if (unformat (i, "next-hop %U", unformat_ip4_address,
                           &next_hop_address))
            next_hop_address_set = 1;
        else if (unformat (i, "resolve-attempts %d", &resolve_attempts))
            ;
        else if (unformat (i, "resolve-if-needed %d", &tmp))
            resolve_if_needed = tmp;
	else if (unformat (i, "l2-only"))
	    l2_only = 1;
	else if (unformat (i, "del"))
	    is_add = 0;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }
    
    if (!adj_address_set) {
        errmsg ("adjacency address/mask not set\n");
        return -99;
    }
    if (!next_hop_address_set) {
        errmsg ("ip4 next hop address (in outer fib) not set\n");
        return -99;
    }
    
    M(MPLS_ETHERNET_ADD_DEL_TUNNEL_2, mpls_ethernet_add_del_tunnel_2);
    
    mp->inner_vrf_id = ntohl(inner_vrf_id);
    mp->outer_vrf_id = ntohl(outer_vrf_id);
    mp->resolve_attempts = ntohl(resolve_attempts);
    mp->resolve_if_needed = resolve_if_needed;
    mp->is_add = is_add;
    mp->l2_only = l2_only;
    clib_memcpy (mp->adj_address, &adj_address, sizeof (adj_address));
    mp->adj_address_length = adj_address_length;
    clib_memcpy (mp->next_hop_ip4_address_in_outer_vrf, &next_hop_address, 
            sizeof (next_hop_address));

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_sw_interface_set_unnumbered (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_sw_interface_set_unnumbered_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u32 unnum_sw_index;
    u8  is_add = 1;
    u8 sw_if_index_set = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
	else if (unformat (i, "sw_if_index %d", &sw_if_index))
	    sw_if_index_set = 1;
	else if (unformat (i, "unnum_if_index %d", &unnum_sw_index))
	    ;
	else if (unformat (i, "del"))
	    is_add = 0;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }
    
    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    M(SW_INTERFACE_SET_UNNUMBERED, sw_interface_set_unnumbered);

    mp->sw_if_index = ntohl(sw_if_index);
    mp->unnumbered_sw_if_index = ntohl(unnum_sw_index);
    mp->is_add = is_add;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_ip_neighbor_add_del (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_ip_neighbor_add_del_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8 sw_if_index_set = 0;
    u32 vrf_id = 0;
    u8 is_add = 1;
    u8 is_static = 0;
    u8 mac_address[6];
    u8 mac_set = 0;
    u8 v4_address_set = 0;
    u8 v6_address_set = 0;
    ip4_address_t v4address;
    ip6_address_t v6address;
    
    memset (mac_address, 0, sizeof (mac_address));
    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "mac %U", unformat_ethernet_address, mac_address)) {
            mac_set = 1;
        }
        else if (unformat (i, "del"))
            is_add = 0;
        else if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "is_static"))
            is_static = 1;
        else if (unformat (i, "vrf %d", &vrf_id))
            ;
        else if (unformat (i, "dst %U", 
                           unformat_ip4_address, &v4address))
                v4_address_set = 1;
        else if (unformat (i, "dst %U", 
                           unformat_ip6_address, &v6address))
                v6_address_set = 1;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }
    if (v4_address_set && v6_address_set) {
        errmsg ("both v4 and v6 addresses set\n");
        return -99;
    }
    if (!v4_address_set && !v6_address_set) {
        errmsg ("no address set\n");
        return -99;
    }

    /* Construct the API message */
    M(IP_NEIGHBOR_ADD_DEL, ip_neighbor_add_del);

    mp->sw_if_index = ntohl (sw_if_index);
    mp->is_add = is_add;
    mp->vrf_id = ntohl (vrf_id);
    mp->is_static = is_static;
    if (mac_set)
        clib_memcpy (mp->mac_address, mac_address, 6);
    if (v6_address_set) {
        mp->is_ipv6 = 1;
        clib_memcpy (mp->dst_address, &v6address, sizeof (v6address));
    } else {
        /* mp->is_ipv6 = 0; via memset in M macro above */
        clib_memcpy (mp->dst_address, &v4address, sizeof (v4address));
    }

    /* send it... */
    S;

    /* Wait for a reply, return good/bad news  */
    W;

    /* NOTREACHED */
    return 0;
}

static int api_reset_vrf (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_reset_vrf_t *mp;
    f64 timeout;
    u32 vrf_id = 0;
    u8 is_ipv6 = 0;
    u8 vrf_id_set = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "vrf %d", &vrf_id))
	    vrf_id_set = 1;
	else if (unformat (i, "ipv6"))
	    is_ipv6 = 1;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (vrf_id_set == 0) {
        errmsg ("missing vrf id\n");
        return -99;
    }
    
    M(RESET_VRF, reset_vrf);

    mp->vrf_id = ntohl(vrf_id);
    mp->is_ipv6 = is_ipv6;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_create_vlan_subif (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_create_vlan_subif_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8  sw_if_index_set = 0;
    u32 vlan_id;
    u8  vlan_id_set = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "sw_if_index %d", &sw_if_index))
	    sw_if_index_set = 1;
        else if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
	else if (unformat (i, "vlan %d", &vlan_id))
	    vlan_id_set = 1;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }
    
    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    if (vlan_id_set == 0) {
        errmsg ("missing vlan_id\n");
        return -99;
    }
    M(CREATE_VLAN_SUBIF, create_vlan_subif);

    mp->sw_if_index = ntohl(sw_if_index);
    mp->vlan_id = ntohl(vlan_id);

    S; W;
    /* NOTREACHED */
    return 0;
}

#define foreach_create_subif_bit                \
_(no_tags)                                      \
_(one_tag)                                      \
_(two_tags)                                     \
_(dot1ad)                                       \
_(exact_match)                                  \
_(default_sub)                                  \
_(outer_vlan_id_any)                            \
_(inner_vlan_id_any)

static int api_create_subif (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_create_subif_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8  sw_if_index_set = 0;
    u32 sub_id;
    u8  sub_id_set = 0;
    u32 no_tags = 0;
    u32 one_tag = 0;
    u32 two_tags = 0;
    u32 dot1ad = 0;
    u32 exact_match = 0;
    u32 default_sub = 0;
    u32 outer_vlan_id_any = 0;
    u32 inner_vlan_id_any = 0;
    u32 tmp;
    u16 outer_vlan_id = 0;
    u16 inner_vlan_id = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "sw_if_index %d", &sw_if_index))
	    sw_if_index_set = 1;
        else if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
	else if (unformat (i, "sub_id %d", &sub_id))
	    sub_id_set = 1;
        else if (unformat (i, "outer_vlan_id %d", &tmp))
            outer_vlan_id = tmp;
        else if (unformat (i, "inner_vlan_id %d", &tmp))
            inner_vlan_id = tmp;

#define _(a) else if (unformat (i, #a)) a = 1 ;
        foreach_create_subif_bit
#undef _

        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }
    
    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    if (sub_id_set == 0) {
        errmsg ("missing sub_id\n");
        return -99;
    }
    M(CREATE_SUBIF, create_subif);

    mp->sw_if_index = ntohl(sw_if_index);
    mp->sub_id = ntohl(sub_id);
    
#define _(a) mp->a = a;
    foreach_create_subif_bit;
#undef _
        
    mp->outer_vlan_id = ntohs (outer_vlan_id);
    mp->inner_vlan_id = ntohs (inner_vlan_id);

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_oam_add_del (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_oam_add_del_t *mp;
    f64 timeout;
    u32 vrf_id = 0;
    u8 is_add = 1;
    ip4_address_t src, dst;
    u8 src_set = 0;
    u8 dst_set = 0;
    
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "vrf %d", &vrf_id))
	    ;
	else if (unformat (i, "src %U", unformat_ip4_address, &src))
	    src_set = 1;
	else if (unformat (i, "dst %U", unformat_ip4_address, &dst))
	    dst_set = 1;
	else if (unformat (i, "del"))
	    is_add = 0;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }
    
    if (src_set == 0) {
        errmsg ("missing src addr\n");
        return -99;
    }

    if (dst_set == 0) {
        errmsg ("missing dst addr\n");
        return -99;
    }

    M(OAM_ADD_DEL, oam_add_del);

    mp->vrf_id = ntohl(vrf_id);
    mp->is_add = is_add;
    clib_memcpy(mp->src_address, &src, sizeof (mp->src_address));
    clib_memcpy(mp->dst_address, &dst, sizeof (mp->dst_address));

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_reset_fib (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_reset_fib_t *mp;
    f64 timeout;
    u32 vrf_id = 0;
    u8 is_ipv6 = 0;
    u8 vrf_id_set = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "vrf %d", &vrf_id))
	    vrf_id_set = 1;
	else if (unformat (i, "ipv6"))
	    is_ipv6 = 1;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (vrf_id_set == 0) {
        errmsg ("missing vrf id\n");
        return -99;
    }
    
    M(RESET_FIB, reset_fib);

    mp->vrf_id = ntohl(vrf_id);
    mp->is_ipv6 = is_ipv6;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_dhcp_proxy_config (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_dhcp_proxy_config_t *mp;
    f64 timeout;
    u32 vrf_id = 0;
    u8 is_add = 1;
    u8 insert_cid = 1;
    u8 v4_address_set = 0;
    u8 v6_address_set = 0;
    ip4_address_t v4address;
    ip6_address_t v6address;
    u8 v4_src_address_set = 0;
    u8 v6_src_address_set = 0;
    ip4_address_t v4srcaddress;
    ip6_address_t v6srcaddress;
    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "del"))
            is_add = 0;
        else if (unformat (i, "vrf %d", &vrf_id))
            ;
        else if (unformat (i, "insert-cid %d", &insert_cid))
            ;
        else if (unformat (i, "svr %U", 
                           unformat_ip4_address, &v4address))
                v4_address_set = 1;
        else if (unformat (i, "svr %U", 
                           unformat_ip6_address, &v6address))
                v6_address_set = 1;
        else if (unformat (i, "src %U", 
                           unformat_ip4_address, &v4srcaddress))
                v4_src_address_set = 1;
        else if (unformat (i, "src %U", 
                           unformat_ip6_address, &v6srcaddress))
                v6_src_address_set = 1;
        else
            break;
    }

    if (v4_address_set && v6_address_set) {
        errmsg ("both v4 and v6 server addresses set\n");
        return -99;
    }
    if (!v4_address_set && !v6_address_set) {
        errmsg ("no server addresses set\n");
        return -99;
    }

    if (v4_src_address_set && v6_src_address_set) {
        errmsg ("both v4 and v6  src addresses set\n");
        return -99;
    }
    if (!v4_src_address_set && !v6_src_address_set) {
        errmsg ("no src addresses set\n");
        return -99;
    }

    if (!(v4_src_address_set && v4_address_set) &&
        !(v6_src_address_set && v6_address_set)) {
        errmsg ("no matching server and src addresses set\n");
        return -99;
    }

    /* Construct the API message */
    M(DHCP_PROXY_CONFIG, dhcp_proxy_config);

    mp->insert_circuit_id = insert_cid;
    mp->is_add = is_add;
    mp->vrf_id = ntohl (vrf_id);
    if (v6_address_set) {
        mp->is_ipv6 = 1;
        clib_memcpy (mp->dhcp_server, &v6address, sizeof (v6address));
        clib_memcpy (mp->dhcp_src_address, &v6srcaddress, sizeof (v6address));
    } else {
        clib_memcpy (mp->dhcp_server, &v4address, sizeof (v4address));
        clib_memcpy (mp->dhcp_src_address, &v4srcaddress, sizeof (v4address));
    }

    /* send it... */
    S;

    /* Wait for a reply, return good/bad news  */
    W;
    /* NOTREACHED */
    return 0;
}

static int api_dhcp_proxy_config_2 (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_dhcp_proxy_config_2_t *mp;
    f64 timeout;
    u32 rx_vrf_id = 0;
    u32 server_vrf_id = 0;
    u8 is_add = 1;
    u8 insert_cid = 1;
    u8 v4_address_set = 0;
    u8 v6_address_set = 0;
    ip4_address_t v4address;
    ip6_address_t v6address;
    u8 v4_src_address_set = 0;
    u8 v6_src_address_set = 0;
    ip4_address_t v4srcaddress;
    ip6_address_t v6srcaddress;
    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "del"))
            is_add = 0;
        else if (unformat (i, "rx_vrf_id %d", &rx_vrf_id))
            ;
        else if (unformat (i, "server_vrf_id %d", &server_vrf_id))
            ;
        else if (unformat (i, "insert-cid %d", &insert_cid))
            ;
        else if (unformat (i, "svr %U", 
                           unformat_ip4_address, &v4address))
                v4_address_set = 1;
        else if (unformat (i, "svr %U", 
                           unformat_ip6_address, &v6address))
                v6_address_set = 1;
        else if (unformat (i, "src %U", 
                           unformat_ip4_address, &v4srcaddress))
                v4_src_address_set = 1;
        else if (unformat (i, "src %U", 
                           unformat_ip6_address, &v6srcaddress))
                v6_src_address_set = 1;
        else
            break;
    }

    if (v4_address_set && v6_address_set) {
        errmsg ("both v4 and v6 server addresses set\n");
        return -99;
    }
    if (!v4_address_set && !v6_address_set) {
        errmsg ("no server addresses set\n");
        return -99;
    }

    if (v4_src_address_set && v6_src_address_set) {
        errmsg ("both v4 and v6  src addresses set\n");
        return -99;
    }
    if (!v4_src_address_set && !v6_src_address_set) {
        errmsg ("no src addresses set\n");
        return -99;
    }

    if (!(v4_src_address_set && v4_address_set) &&
        !(v6_src_address_set && v6_address_set)) {
        errmsg ("no matching server and src addresses set\n");
        return -99;
    }

    /* Construct the API message */
    M(DHCP_PROXY_CONFIG_2, dhcp_proxy_config_2);

    mp->insert_circuit_id = insert_cid;
    mp->is_add = is_add;
    mp->rx_vrf_id = ntohl (rx_vrf_id);
    mp->server_vrf_id = ntohl (server_vrf_id);
    if (v6_address_set) {
        mp->is_ipv6 = 1;
        clib_memcpy (mp->dhcp_server, &v6address, sizeof (v6address));
        clib_memcpy (mp->dhcp_src_address, &v6srcaddress, sizeof (v6address));
    } else {
        clib_memcpy (mp->dhcp_server, &v4address, sizeof (v4address));
        clib_memcpy (mp->dhcp_src_address, &v4srcaddress, sizeof (v4address));
    }

    /* send it... */
    S;

    /* Wait for a reply, return good/bad news  */
    W;
    /* NOTREACHED */
    return 0;
}

static int api_dhcp_proxy_set_vss (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_dhcp_proxy_set_vss_t *mp;
    f64 timeout;
    u8  is_ipv6 = 0;
    u8  is_add = 1;
    u32 tbl_id;
    u8  tbl_id_set = 0;
    u32 oui;
    u8  oui_set = 0;
    u32 fib_id;
    u8  fib_id_set = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "tbl_id %d", &tbl_id))
	    tbl_id_set = 1;
	if (unformat (i, "fib_id %d", &fib_id))
	    fib_id_set = 1;
	if (unformat (i, "oui %d", &oui))
	    oui_set = 1;
	else if (unformat (i, "ipv6"))
	    is_ipv6 = 1;
	else if (unformat (i, "del"))
	    is_add = 0;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (tbl_id_set == 0) {
        errmsg ("missing tbl id\n");
        return -99;
    }

    if (fib_id_set == 0) {
        errmsg ("missing fib id\n");
        return -99;
    }
    if (oui_set == 0) {
        errmsg ("missing oui\n");
        return -99;
    }
    
    M(DHCP_PROXY_SET_VSS, dhcp_proxy_set_vss);
    mp->tbl_id = ntohl(tbl_id);
    mp->fib_id = ntohl(fib_id);
    mp->oui = ntohl(oui);
    mp->is_ipv6 = is_ipv6;
    mp->is_add = is_add;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_dhcp_client_config (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_dhcp_client_config_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8 sw_if_index_set = 0;
    u8 is_add = 1;
    u8 * hostname = 0;
    u8 disable_event = 0;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
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

    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    if (vec_len (hostname) > 63) {
        errmsg ("hostname too long\n");
    }
    vec_add1 (hostname, 0);

    /* Construct the API message */
    M(DHCP_CLIENT_CONFIG, dhcp_client_config);

    mp->sw_if_index = ntohl (sw_if_index);
    clib_memcpy (mp->hostname, hostname, vec_len (hostname));
    vec_free (hostname);
    mp->is_add = is_add;
    mp->want_dhcp_event = disable_event ? 0 : 1;
    mp->pid = getpid();
   
    /* send it... */
    S;

    /* Wait for a reply, return good/bad news  */
    W;
    /* NOTREACHED */
    return 0;
}

static int api_set_ip_flow_hash (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_set_ip_flow_hash_t *mp;
    f64 timeout;
    u32 vrf_id = 0;
    u8 is_ipv6 = 0;
    u8 vrf_id_set = 0;
    u8 src = 0;
    u8 dst = 0;
    u8 sport = 0;
    u8 dport = 0;
    u8 proto = 0;
    u8 reverse = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "vrf %d", &vrf_id))
	    vrf_id_set = 1;
	else if (unformat (i, "ipv6"))
	    is_ipv6 = 1;
	else if (unformat (i, "src"))
	    src = 1;
	else if (unformat (i, "dst"))
	    dst = 1;
	else if (unformat (i, "sport"))
	    sport = 1;
	else if (unformat (i, "dport"))
	    dport = 1;
	else if (unformat (i, "proto"))
	    proto = 1;
	else if (unformat (i, "reverse"))
	    reverse = 1;

        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (vrf_id_set == 0) {
        errmsg ("missing vrf id\n");
        return -99;
    }
    
    M(SET_IP_FLOW_HASH, set_ip_flow_hash);
    mp->src = src;
    mp->dst = dst;
    mp->sport = sport;
    mp->dport = dport;
    mp->proto = proto;
    mp->reverse = reverse;
    mp->vrf_id = ntohl(vrf_id);
    mp->is_ipv6 = is_ipv6;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_sw_interface_ip6_enable_disable (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_sw_interface_ip6_enable_disable_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8  sw_if_index_set = 0;
    u8  enable = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
	else if (unformat (i, "sw_if_index %d", &sw_if_index))
	    sw_if_index_set = 1;
	else if (unformat (i, "enable"))
	    enable = 1;
	else if (unformat (i, "disable"))
	    enable = 0;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }
    
    M(SW_INTERFACE_IP6_ENABLE_DISABLE, sw_interface_ip6_enable_disable);

    mp->sw_if_index = ntohl(sw_if_index);
    mp->enable = enable;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_sw_interface_ip6_set_link_local_address (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_sw_interface_ip6_set_link_local_address_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8 sw_if_index_set = 0;
    u32 address_length = 0;
    u8 v6_address_set = 0;
    ip6_address_t v6address;
    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "%U/%d", 
                           unformat_ip6_address, &v6address, 
                           &address_length))
            v6_address_set = 1;
        else
            break;
    }

    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }
    if (!v6_address_set) {
        errmsg ("no address set\n");
        return -99;
    }

    /* Construct the API message */
    M(SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS, \
      sw_interface_ip6_set_link_local_address);

    mp->sw_if_index = ntohl (sw_if_index);
    clib_memcpy (mp->address, &v6address, sizeof (v6address));
    mp->address_length = address_length;

    /* send it... */
    S;

    /* Wait for a reply, return good/bad news  */
    W;

    /* NOTREACHED */
    return 0;
}


static int api_sw_interface_ip6nd_ra_prefix (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_sw_interface_ip6nd_ra_prefix_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8 sw_if_index_set = 0;
    u32 address_length = 0;
    u8 v6_address_set = 0;
    ip6_address_t v6address;
    u8 use_default = 0;
    u8 no_advertise = 0;
    u8 off_link = 0;
    u8 no_autoconfig = 0;
    u8 no_onlink = 0;
    u8 is_no = 0;
    u32 val_lifetime = 0;
    u32 pref_lifetime = 0;
    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "%U/%d", 
                           unformat_ip6_address, &v6address, 
                           &address_length))
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
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }        
    }

    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }
    if (!v6_address_set) {
        errmsg ("no address set\n");
        return -99;
    }

    /* Construct the API message */
    M(SW_INTERFACE_IP6ND_RA_PREFIX, sw_interface_ip6nd_ra_prefix);

    mp->sw_if_index = ntohl (sw_if_index);
    clib_memcpy (mp->address, &v6address, sizeof (v6address));
    mp->address_length = address_length;
    mp->use_default = use_default;
    mp->no_advertise = no_advertise;
    mp->off_link = off_link;
    mp->no_autoconfig = no_autoconfig;
    mp->no_onlink = no_onlink;
    mp->is_no = is_no;
    mp->val_lifetime = ntohl(val_lifetime);
    mp->pref_lifetime = ntohl(pref_lifetime);

    /* send it... */
    S;

    /* Wait for a reply, return good/bad news  */
    W;

    /* NOTREACHED */
    return 0;
}

static int api_sw_interface_ip6nd_ra_config (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_sw_interface_ip6nd_ra_config_t *mp;
    f64 timeout;
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

    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
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
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }        
    }

    if (sw_if_index_set == 0) {
	errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    /* Construct the API message */
    M(SW_INTERFACE_IP6ND_RA_CONFIG, sw_interface_ip6nd_ra_config);

    mp->sw_if_index = ntohl (sw_if_index);
    mp->max_interval = ntohl(max_interval);
    mp->min_interval = ntohl(min_interval);
    mp->lifetime = ntohl(lifetime);
    mp->initial_count = ntohl(initial_count);
    mp->initial_interval = ntohl(initial_interval);
    mp->suppress = suppress;
    mp->managed = managed;
    mp->other = other;
    mp->ll_option = ll_option;
    mp->send_unicast = send_unicast;
    mp->cease = cease;
    mp->is_no = is_no;
    mp->default_router = default_router;

    /* send it... */
    S;

    /* Wait for a reply, return good/bad news  */
    W;

    /* NOTREACHED */
    return 0;
}

static int api_set_arp_neighbor_limit (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_set_arp_neighbor_limit_t *mp;
    f64 timeout;
    u32 arp_nbr_limit;
    u8 limit_set = 0;
    u8 is_ipv6 = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "arp_nbr_limit %d", &arp_nbr_limit))
	    limit_set = 1;
	else if (unformat (i, "ipv6"))
	    is_ipv6 = 1;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (limit_set == 0) {
        errmsg ("missing limit value\n");
        return -99;
    }
    
    M(SET_ARP_NEIGHBOR_LIMIT, set_arp_neighbor_limit);

    mp->arp_neighbor_limit = ntohl(arp_nbr_limit);
    mp->is_ipv6 = is_ipv6;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_l2_patch_add_del (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_l2_patch_add_del_t *mp;
    f64 timeout;
    u32 rx_sw_if_index;
    u8 rx_sw_if_index_set = 0;
    u32 tx_sw_if_index;
    u8 tx_sw_if_index_set = 0;
    u8 is_add = 1;
    
    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "rx_sw_if_index %d", &rx_sw_if_index))
            rx_sw_if_index_set = 1;	
	else if (unformat (i, "tx_sw_if_index %d", &tx_sw_if_index))
            tx_sw_if_index_set = 1;
	else if (unformat (i, "rx")) {
	    if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
		if (unformat (i, "%U", unformat_sw_if_index, vam,
			      &rx_sw_if_index))
		    rx_sw_if_index_set = 1;
	    } else
		break;
	} else if (unformat (i, "tx")) {
	    if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
		if (unformat (i, "%U", unformat_sw_if_index, vam,
			      &tx_sw_if_index))
		    tx_sw_if_index_set = 1;
	    } else
		break;
	} else if (unformat (i, "del"))
	    is_add = 0;
	else
            break;
    }

    if (rx_sw_if_index_set == 0) {
        errmsg ("missing rx interface name or rx_sw_if_index\n");
        return -99;
    }

    if (tx_sw_if_index_set == 0) {
        errmsg ("missing tx interface name or tx_sw_if_index\n");
        return -99;
    }
    
    M(L2_PATCH_ADD_DEL, l2_patch_add_del);

    mp->rx_sw_if_index = ntohl(rx_sw_if_index);
    mp->tx_sw_if_index = ntohl(tx_sw_if_index);
    mp->is_add = is_add;

    S; W;
    /* NOTREACHED */
    return 0;
}
static int api_trace_profile_add (vat_main_t *vam)
{
   unformat_input_t * input = vam->input;
   vl_api_trace_profile_add_t *mp;
   f64 timeout;
   u32 id = 0;
   u32 trace_option_elts = 0;
   u32 trace_type = 0, node_id = 0, app_data = 0, trace_tsp = 2;
   int has_pow_option = 0;
   int has_ppc_option = 0;
  
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "id %d trace-type 0x%x trace-elts %d "
                           "trace-tsp %d node-id 0x%x app-data 0x%x", 
		    &id, &trace_type, &trace_option_elts, &trace_tsp,
                      &node_id, &app_data))
            ;
      else if (unformat (input, "pow"))
        has_pow_option = 1;
      else if (unformat (input, "ppc encap"))
        has_ppc_option = PPC_ENCAP;
      else if (unformat (input, "ppc decap"))
        has_ppc_option = PPC_DECAP;
      else if (unformat (input, "ppc none"))
        has_ppc_option = PPC_NONE;
      else
        break;
    }
  M(TRACE_PROFILE_ADD, trace_profile_add);
  mp->id = htons(id);
  mp->trace_type = trace_type;
  mp->trace_num_elt = trace_option_elts;
  mp->trace_ppc = has_ppc_option;
  mp->trace_app_data = htonl(app_data);
  mp->pow_enable = has_pow_option;
  mp->trace_tsp = trace_tsp;
  mp->node_id = htonl(node_id);
  
  S; W;
  
  return(0);
   
}
static int api_trace_profile_apply (vat_main_t *vam)
{
  unformat_input_t * input = vam->input;
  vl_api_trace_profile_apply_t *mp;
  f64 timeout;
  ip6_address_t addr;
  u32 mask_width = ~0;
  int is_add = 0;
  int is_pop = 0;
  int is_none = 0;
  u32 vrf_id = 0;
  u32 id = 0;
  
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U/%d",
                    unformat_ip6_address, &addr, &mask_width))
        ;
      else if (unformat (input, "id %d", &id))
	;
      else if (unformat (input, "vrf-id %d", &vrf_id))
        ;
      else if (unformat (input, "add"))
        is_add = 1;
      else if (unformat (input, "pop"))
        is_pop = 1;
      else if (unformat (input, "none"))
        is_none = 1;
      else
        break;
    }

  if ((is_add + is_pop + is_none) != 1) {
    errmsg("One of (add, pop, none) required");
    return -99;
  }
  if (mask_width == ~0) {
    errmsg("<address>/<mask-width> required");
    return -99;
  }
  M(TRACE_PROFILE_APPLY, trace_profile_apply);
  clib_memcpy(mp->dest_ipv6, &addr, sizeof(mp->dest_ipv6));
  mp->id = htons(id);
  mp->prefix_length = htonl(mask_width);
  mp->vrf_id = htonl(vrf_id);
  if (is_add)
    mp->trace_op = IOAM_HBYH_ADD;
  else if (is_pop)
    mp->trace_op = IOAM_HBYH_POP;
  else
    mp->trace_op = IOAM_HBYH_MOD;

  if(is_none)
    mp->enable = 0;
  else
    mp->enable = 1;
  
  S; W;

  return 0;
}

static int api_trace_profile_del (vat_main_t *vam)
{
   vl_api_trace_profile_del_t *mp;
   f64 timeout;
   
   M(TRACE_PROFILE_DEL, trace_profile_del);
   S; W;
   return 0;
}

static int api_sr_tunnel_add_del (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  vl_api_sr_tunnel_add_del_t *mp;
  f64 timeout;
  int is_del = 0;
  int pl_index;
  ip6_address_t src_address;
  int src_address_set = 0;
  ip6_address_t dst_address;
  u32 dst_mask_width;
  int dst_address_set = 0;
  u16 flags = 0;
  u32 rx_table_id = 0;
  u32 tx_table_id = 0;
  ip6_address_t * segments = 0;
  ip6_address_t * this_seg;
  ip6_address_t * tags = 0;
  ip6_address_t * this_tag;
  ip6_address_t next_address, tag;
  u8 * name = 0;
  u8 * policy_name = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
        is_del = 1;
      else if (unformat (i, "name %s", &name))
            ;
      else if (unformat (i, "policy %s", &policy_name))
            ;
      else if (unformat (i, "rx_fib_id %d", &rx_table_id))
        ;
      else if (unformat (i, "tx_fib_id %d", &tx_table_id))
        ;
      else if (unformat (i, "src %U", unformat_ip6_address, &src_address))
        src_address_set = 1;
      else if (unformat (i, "dst %U/%d", 
                         unformat_ip6_address, &dst_address,
                         &dst_mask_width))
        dst_address_set = 1;
      else if (unformat (i, "next %U", unformat_ip6_address,
                         &next_address))
        {
          vec_add2 (segments, this_seg, 1);
          clib_memcpy (this_seg->as_u8, next_address.as_u8, sizeof (*this_seg));
        }
      else if (unformat (i, "tag %U", unformat_ip6_address,
                         &tag))
        {
          vec_add2 (tags, this_tag, 1);
          clib_memcpy (this_tag->as_u8, tag.as_u8, sizeof (*this_tag));
        }
      else if (unformat (i, "clean"))
        flags |= IP6_SR_HEADER_FLAG_CLEANUP;
      else if (unformat (i, "protected"))
        flags |= IP6_SR_HEADER_FLAG_PROTECTED;
      else if (unformat (i, "InPE %d", &pl_index))
        {
          if (pl_index <= 0 || pl_index > 4)
            {
            pl_index_range_error:
              errmsg ("pl index %d out of range\n", pl_index);
              return -99;
            }
          flags |= IP6_SR_HEADER_FLAG_PL_ELT_INGRESS_PE << (3*(pl_index - 1));
        }
      else if (unformat (i, "EgPE %d", &pl_index))
        {
          if (pl_index <= 0 || pl_index > 4)
            goto pl_index_range_error;
          flags |= IP6_SR_HEADER_FLAG_PL_ELT_EGRESS_PE << (3*(pl_index - 1));
        }
      else if (unformat (i, "OrgSrc %d", &pl_index))
        {
          if (pl_index <= 0 || pl_index > 4)
            goto pl_index_range_error;
          flags |= IP6_SR_HEADER_FLAG_PL_ELT_ORIG_SRC_ADDR << (3*(pl_index - 1));
        }
      else 
        break;
    }

  if (!src_address_set)
    {
      errmsg ("src address required\n");
      return -99;
    }

  if (!dst_address_set)
    {
      errmsg ("dst address required\n");
      return -99;
    }

  if (!segments)
    {
      errmsg ("at least one sr segment required\n");
      return -99;
    }

  M2(SR_TUNNEL_ADD_DEL, sr_tunnel_add_del, 
     vec_len(segments) * sizeof (ip6_address_t) 
     + vec_len(tags) * sizeof (ip6_address_t));

  clib_memcpy (mp->src_address, &src_address, sizeof (mp->src_address));
  clib_memcpy (mp->dst_address, &dst_address, sizeof (mp->dst_address));
  mp->dst_mask_width = dst_mask_width;
  mp->flags_net_byte_order = clib_host_to_net_u16 (flags);
  mp->n_segments = vec_len (segments);
  mp->n_tags = vec_len (tags);
  mp->is_add = is_del == 0;
  clib_memcpy (mp->segs_and_tags, segments, 
          vec_len(segments)* sizeof (ip6_address_t));
  clib_memcpy (mp->segs_and_tags + vec_len(segments)*sizeof (ip6_address_t),
          tags, vec_len(tags)* sizeof (ip6_address_t));

  mp->outer_vrf_id = ntohl (rx_table_id);
  mp->inner_vrf_id = ntohl (tx_table_id);
  memcpy (mp->name, name, vec_len(name));
  memcpy (mp->policy_name, policy_name, vec_len(policy_name));

  vec_free (segments);
  vec_free (tags);
  
  S; W;
  /* NOTREACHED */
}

static int api_sr_policy_add_del (vat_main_t * vam)
{
  unformat_input_t * input = vam->input;
  vl_api_sr_policy_add_del_t *mp;
  f64 timeout;
  int is_del = 0;
  u8 * name = 0;
  u8 * tunnel_name = 0;
  u8 ** tunnel_names = 0;
  
  int name_set = 0 ;
  int tunnel_set = 0;
  int j = 0;
  int tunnel_names_length = 1; // Init to 1 to offset the #tunnel_names counter byte
  int tun_name_len = 0; // Different naming convention used as confusing these would be "bad" (TM)

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
        is_del = 1;
      else if (unformat (input, "name %s", &name))
	name_set = 1;
      else if (unformat (input, "tunnel %s", &tunnel_name))
        {
	  if (tunnel_name)
	    {
	      vec_add1 (tunnel_names, tunnel_name);
	      /* For serializer: 
		 - length = #bytes to store in serial vector
		 - +1 = byte to store that length
	      */
	      tunnel_names_length += (vec_len (tunnel_name) + 1); 
	      tunnel_set = 1;
	      tunnel_name = 0;
	    }
        }
      else 
        break;
    }

  if (!name_set)
    {
      errmsg ("policy name required\n");
      return -99;
    }

  if ((!tunnel_set) && (!is_del))
    {
      errmsg ("tunnel name required\n");
      return -99;
    }

  M2(SR_POLICY_ADD_DEL, sr_policy_add_del, tunnel_names_length);

  

  mp->is_add = !is_del;

  memcpy (mp->name, name, vec_len(name));
  // Since mp->tunnel_names is of type u8[0] and not a u8 *, u8 ** needs to be serialized
  u8 * serial_orig = 0;
  vec_validate (serial_orig, tunnel_names_length);
  *serial_orig = vec_len(tunnel_names); // Store the number of tunnels as length in first byte of serialized vector
  serial_orig += 1; // Move along one byte to store the length of first tunnel_name

  for (j=0; j < vec_len(tunnel_names); j++)
    {
      tun_name_len = vec_len (tunnel_names[j]);
      *serial_orig = tun_name_len; // Store length of tunnel name in first byte of Length/Value pair
      serial_orig += 1; // Move along one byte to store the actual tunnel name
      memcpy (serial_orig, tunnel_names[j], tun_name_len);
      serial_orig += tun_name_len; // Advance past the copy
    }
  memcpy (mp->tunnel_names, serial_orig - tunnel_names_length, tunnel_names_length); // Regress serial_orig to head then copy fwd

  vec_free (tunnel_names);
  vec_free (tunnel_name);
  
  S; W;
  /* NOTREACHED */
}

static int api_sr_multicast_map_add_del (vat_main_t * vam)
{
  unformat_input_t * input = vam->input;
  vl_api_sr_multicast_map_add_del_t *mp;
  f64 timeout;
  int is_del = 0;
  ip6_address_t multicast_address;
  u8 * policy_name = 0;
  int multicast_address_set = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
        is_del = 1;
      else if (unformat (input, "address %U", unformat_ip6_address, &multicast_address))
	multicast_address_set = 1;
      else if (unformat (input, "sr-policy %s", &policy_name))
        ;
      else 
        break;
    }

  if (!is_del && !policy_name)
    {
      errmsg ("sr-policy name required\n");
      return -99;
    }


  if (!multicast_address_set)
    {
      errmsg ("address required\n");
      return -99;
    }

  M(SR_MULTICAST_MAP_ADD_DEL, sr_multicast_map_add_del);

  mp->is_add = !is_del;
  memcpy (mp->policy_name, policy_name, vec_len(policy_name));
  clib_memcpy (mp->multicast_address, &multicast_address, sizeof (mp->multicast_address));


  vec_free (policy_name);
  
  S; W;
  /* NOTREACHED */
}


#define foreach_ip4_proto_field                 \
_(src_address)                                  \
_(dst_address)                                  \
_(tos)                                          \
_(length)					\
_(fragment_id)                                  \
_(ttl)                                          \
_(protocol)                                     \
_(checksum)

uword unformat_ip4_mask (unformat_input_t * input, va_list * args)
{
  u8 ** maskp = va_arg (*args, u8 **);
  u8 * mask = 0;
  u8 found_something = 0;
  ip4_header_t * ip;
  
#define _(a) u8 a=0;
  foreach_ip4_proto_field;
#undef _
  u8 version = 0;
  u8 hdr_length = 0;
  
  
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) 
    {
      if (unformat (input, "version")) 
        version = 1;
      else if (unformat (input, "hdr_length"))
        hdr_length = 1;
      else if (unformat (input, "src"))
        src_address = 1;
      else if (unformat (input, "dst"))
        dst_address = 1;
      else if (unformat (input, "proto"))
        protocol = 1;
      
#define _(a) else if (unformat (input, #a)) a=1;
      foreach_ip4_proto_field
#undef _
      else
        break;
    }
  
#define _(a) found_something += a;
  foreach_ip4_proto_field;
#undef _
  
  if (found_something == 0)
    return 0;
  
  vec_validate (mask, sizeof (*ip) - 1);
  
  ip = (ip4_header_t *) mask;
  
#define _(a) if (a) memset (&ip->a, 0xff, sizeof (ip->a));
  foreach_ip4_proto_field;
#undef _
  
  ip->ip_version_and_header_length = 0;
  
  if (version)
    ip->ip_version_and_header_length |= 0xF0;
  
  if (hdr_length)
    ip->ip_version_and_header_length |= 0x0F;
  
  *maskp = mask;
  return 1;
}

#define foreach_ip6_proto_field                 \
_(src_address)                                  \
_(dst_address)                                  \
_(payload_length)				\
_(hop_limit)                                    \
_(protocol)

uword unformat_ip6_mask (unformat_input_t * input, va_list * args)
{
  u8 ** maskp = va_arg (*args, u8 **);
  u8 * mask = 0;
  u8 found_something = 0;
  ip6_header_t * ip;
  u32 ip_version_traffic_class_and_flow_label;
  
#define _(a) u8 a=0;
  foreach_ip6_proto_field;
#undef _
  u8 version = 0;
  u8 traffic_class = 0;
  u8 flow_label = 0;
  
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) 
    {
      if (unformat (input, "version")) 
        version = 1;
      else if (unformat (input, "traffic-class"))
        traffic_class = 1;
      else if (unformat (input, "flow-label"))
        flow_label = 1;
      else if (unformat (input, "src"))
        src_address = 1;
      else if (unformat (input, "dst"))
        dst_address = 1;
      else if (unformat (input, "proto"))
        protocol = 1;
      
#define _(a) else if (unformat (input, #a)) a=1;
      foreach_ip6_proto_field
#undef _
      else
        break;
    }
  
#define _(a) found_something += a;
  foreach_ip6_proto_field;
#undef _
  
  if (found_something == 0)
    return 0;
  
  vec_validate (mask, sizeof (*ip) - 1);
  
  ip = (ip6_header_t *) mask;
  
#define _(a) if (a) memset (&ip->a, 0xff, sizeof (ip->a));
  foreach_ip6_proto_field;
#undef _
  
  ip_version_traffic_class_and_flow_label = 0;
  
  if (version)
    ip_version_traffic_class_and_flow_label |= 0xF0000000;

  if (traffic_class)
    ip_version_traffic_class_and_flow_label |= 0x0FF00000;

  if (flow_label)
    ip_version_traffic_class_and_flow_label |= 0x000FFFFF;

  ip->ip_version_traffic_class_and_flow_label = 
    clib_host_to_net_u32 (ip_version_traffic_class_and_flow_label);
  
  *maskp = mask;
  return 1;
}

uword unformat_l3_mask (unformat_input_t * input, va_list * args)
{
  u8 ** maskp = va_arg (*args, u8 **);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "ip4 %U", unformat_ip4_mask, maskp))
      return 1;
    else if (unformat (input, "ip6 %U", unformat_ip6_mask, maskp))
      return 1;
    else
      break;
  }
  return 0;
}

uword unformat_l2_mask (unformat_input_t * input, va_list * args)
{
  u8 ** maskp = va_arg (*args, u8 **);
  u8 * mask = 0;
  u8 src = 0;
  u8 dst = 0;
  u8 proto = 0;
  u8 tag1 = 0;
  u8 tag2 = 0;
  u8 ignore_tag1 = 0;
  u8 ignore_tag2 = 0;
  u8 cos1 = 0;
  u8 cos2 = 0;
  u8 dot1q = 0;
  u8 dot1ad = 0;
  int len = 14;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "src"))
      src = 1;
    else if (unformat (input, "dst"))
      dst = 1;
    else if (unformat (input, "proto"))
      proto = 1;
    else if (unformat (input, "tag1"))
      tag1 = 1;
    else if (unformat (input, "tag2"))
      tag2 = 1;
    else if (unformat (input, "ignore-tag1"))
      ignore_tag1 = 1;
    else if (unformat (input, "ignore-tag2"))
      ignore_tag2 = 1;
    else if (unformat (input, "cos1"))
      cos1 = 1;
    else if (unformat (input, "cos2"))
      cos2 = 1;
    else if (unformat (input, "dot1q"))
      dot1q = 1;
    else if (unformat (input, "dot1ad"))
      dot1ad = 1;
    else
      break;
  }
  if ((src + dst + proto + tag1 + tag2 + dot1q + dot1ad +
      ignore_tag1 + ignore_tag2 + cos1 + cos2) == 0)
    return 0;

  if (tag1 || ignore_tag1 || cos1 || dot1q)
    len = 18;
  if (tag2 || ignore_tag2 || cos2 || dot1ad)
    len = 22;

  vec_validate (mask, len-1);

  if (dst)
    memset (mask, 0xff, 6);

  if (src)
    memset (mask + 6, 0xff, 6);
  
  if (tag2 || dot1ad)
    {
      /* inner vlan tag */
      if (tag2)
        {
          mask[19] = 0xff;
          mask[18] = 0x0f;
        }
      if (cos2)
        mask[18] |= 0xe0;
      if (proto)
          mask[21] = mask [20] = 0xff;
      if (tag1)
        {
          mask [15] = 0xff;
          mask [14] = 0x0f;
        }
      if (cos1)
        mask[14] |= 0xe0;
      *maskp = mask;
      return 1;
    }
  if (tag1 | dot1q)
    {
      if (tag1)
        {
          mask [15] = 0xff;
          mask [14] = 0x0f;
        }
      if (cos1)
        mask[14] |= 0xe0;
      if (proto)
          mask[16] = mask [17] = 0xff;

      *maskp = mask;
      return 1;
    }
  if (cos2)
    mask[18] |= 0xe0;
  if (cos1)
    mask[14] |= 0xe0;
  if (proto)
    mask[12] = mask [13] = 0xff;
    
  *maskp = mask;
  return 1;
}

uword unformat_classify_mask (unformat_input_t * input, va_list * args)
{
  u8 ** maskp = va_arg (*args, u8 **);
  u32 * skipp = va_arg (*args, u32 *);
  u32 * matchp = va_arg (*args, u32 *);
  u32 match;
  u8 * mask = 0;
  u8 * l2 = 0;
  u8 * l3 = 0;
  int i;
  
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "hex %U", unformat_hex_string, &mask))
      ;
    else if (unformat (input, "l2 %U", unformat_l2_mask, &l2))
      ;
    else if (unformat (input, "l3 %U", unformat_l3_mask, &l3))
      ;
    else
      break;
  }

  if (mask || l2 || l3)
    {
      if (l2 || l3)
        {
          /* "With a free Ethernet header in every package" */
          if (l2 == 0)
            vec_validate (l2, 13);
          mask = l2;
          vec_append (mask, l3);
          vec_free (l3);
        }

      /* Scan forward looking for the first significant mask octet */
      for (i = 0; i < vec_len (mask); i++)
        if (mask[i])
          break;

      /* compute (skip, match) params */
      *skipp = i / sizeof(u32x4);
      vec_delete (mask, *skipp * sizeof(u32x4), 0);

      /* Pad mask to an even multiple of the vector size */
      while (vec_len (mask) % sizeof (u32x4))
        vec_add1 (mask, 0);

      match = vec_len (mask) / sizeof (u32x4);

      for (i = match*sizeof(u32x4); i > 0; i-= sizeof(u32x4))
        {
          u64 *tmp = (u64 *)(mask + (i-sizeof(u32x4)));
          if (*tmp || *(tmp+1))
            break;
          match--;
        }
      if (match == 0)
        clib_warning ("BUG: match 0");

      _vec_len (mask) = match * sizeof(u32x4);

      *matchp = match;
      *maskp = mask;

      return 1;
    }

  return 0;
}

#define foreach_l2_next                         \
_(drop, DROP)                                   \
_(ethernet, ETHERNET_INPUT)                     \
_(ip4, IP4_INPUT)                               \
_(ip6, IP6_INPUT)

uword unformat_l2_next_index (unformat_input_t * input, va_list * args)
{
  u32 * miss_next_indexp = va_arg (*args, u32 *);
  u32 next_index = 0;
  u32 tmp;
  
#define _(n,N) \
  if (unformat (input, #n)) { next_index = L2_CLASSIFY_NEXT_##N; goto out;}
  foreach_l2_next;
#undef _
  
  if (unformat (input, "%d", &tmp))
    { 
      next_index = tmp; 
      goto out; 
    }
  
  return 0;

 out:
  *miss_next_indexp = next_index;
  return 1;
}

#define foreach_ip_next                         \
_(miss, MISS)                                   \
_(drop, DROP)                                   \
_(local, LOCAL)                                 \
_(rewrite, REWRITE)

uword unformat_ip_next_index (unformat_input_t * input, va_list * args)
{
  u32 * miss_next_indexp = va_arg (*args, u32 *);
  u32 next_index = 0;
  u32 tmp;
  
#define _(n,N) \
  if (unformat (input, #n)) { next_index = IP_LOOKUP_NEXT_##N; goto out;}
  foreach_ip_next;
#undef _
  
  if (unformat (input, "%d", &tmp))
    { 
      next_index = tmp; 
      goto out; 
    }
  
  return 0;

 out:
  *miss_next_indexp = next_index;
  return 1;
}

#define foreach_acl_next                        \
_(deny, DENY)

uword unformat_acl_next_index (unformat_input_t * input, va_list * args)
{
  u32 * miss_next_indexp = va_arg (*args, u32 *);
  u32 next_index = 0;
  u32 tmp;

#define _(n,N) \
  if (unformat (input, #n)) { next_index = ACL_NEXT_INDEX_##N; goto out;}
  foreach_acl_next;
#undef _

  if (unformat (input, "permit"))
    {
      next_index = ~0;
      goto out;
    }
  else if (unformat (input, "%d", &tmp))
    {
      next_index = tmp;
      goto out;
    }

  return 0;

 out:
  *miss_next_indexp = next_index;
  return 1;
}

static int api_classify_add_del_table (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  vl_api_classify_add_del_table_t *mp;

  u32 nbuckets = 2;
  u32 skip = ~0;
  u32 match = ~0;
  int is_add = 1;
  u32 table_index = ~0;
  u32 next_table_index = ~0;
  u32 miss_next_index = ~0;
  u32 memory_size = 32<<20;
  u8 * mask = 0;
  f64 timeout;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
    if (unformat (i, "del"))
      is_add = 0;
    else if (unformat (i, "buckets %d", &nbuckets))
      ;
    else if (unformat (i, "memory_size %d", &memory_size))
      ;
    else if (unformat (i, "skip %d", &skip))
      ;
    else if (unformat (i, "match %d", &match))
      ;
    else if (unformat (i, "table %d", &table_index))
      ;
    else if (unformat (i, "mask %U", unformat_classify_mask, 
                       &mask, &skip, &match))
      ;
    else if (unformat (i, "next-table %d", &next_table_index))
      ;
    else if (unformat (i, "miss-next %U", unformat_ip_next_index,
                       &miss_next_index))
      ;
    else if (unformat (i, "l2-miss-next %U", unformat_l2_next_index,
                       &miss_next_index))
      ;
    else if (unformat (i, "acl-miss-next %U", unformat_acl_next_index,
                       &miss_next_index))
      ;
    else
      break;
  }
  
  if (is_add && mask == 0) {
      errmsg ("Mask required\n");
      return -99;
  }

  if (is_add && skip == ~0) {
      errmsg ("skip count required\n");
      return -99;
  }

  if (is_add && match == ~0) {
      errmsg ("match count required\n");
      return -99;
  }
      
  if (!is_add && table_index == ~0) {
      errmsg ("table index required for delete\n");
      return -99;
  }

  M2 (CLASSIFY_ADD_DEL_TABLE, classify_add_del_table,
      vec_len(mask));

  mp->is_add = is_add;
  mp->table_index = ntohl(table_index);
  mp->nbuckets = ntohl(nbuckets);
  mp->memory_size = ntohl(memory_size);
  mp->skip_n_vectors = ntohl(skip);
  mp->match_n_vectors = ntohl(match);
  mp->next_table_index = ntohl(next_table_index);
  mp->miss_next_index = ntohl(miss_next_index);
  clib_memcpy (mp->mask, mask, vec_len(mask));

  vec_free(mask);

  S; W;
  /* NOTREACHED */
}

uword unformat_ip4_match (unformat_input_t * input, va_list * args)
{
  u8 ** matchp = va_arg (*args, u8 **);
  u8 * match = 0;
  ip4_header_t * ip;
  int version = 0;
  u32 version_val;
  int hdr_length = 0;
  u32 hdr_length_val;
  int src = 0, dst = 0;
  ip4_address_t src_val, dst_val;
  int proto = 0;
  u32 proto_val;
  int tos = 0;
  u32 tos_val;
  int length = 0;
  u32 length_val;
  int fragment_id = 0;
  u32 fragment_id_val;
  int ttl = 0;
  int ttl_val;
  int checksum = 0;
  u32 checksum_val;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) 
    {
      if (unformat (input, "version %d", &version_val)) 
        version = 1;
      else if (unformat (input, "hdr_length %d", &hdr_length_val))
        hdr_length = 1;
      else if (unformat (input, "src %U", unformat_ip4_address, &src_val))
        src = 1;
      else if (unformat (input, "dst %U", unformat_ip4_address, &dst_val))
        dst = 1;
      else if (unformat (input, "proto %d", &proto_val))
        proto = 1;
      else if (unformat (input, "tos %d", &tos_val))
        tos = 1;
      else if (unformat (input, "length %d", &length_val))
        length = 1;
      else if (unformat (input, "fragment_id %d", &fragment_id_val))
        fragment_id = 1;
      else if (unformat (input, "ttl %d", &ttl_val))
        ttl = 1;
      else if (unformat (input, "checksum %d", &checksum_val))
        checksum = 1;
      else
        break;
    }
  
  if (version + hdr_length + src + dst + proto + tos + length + fragment_id
      + ttl + checksum == 0)
    return 0;

  /* 
   * Aligned because we use the real comparison functions
   */
  vec_validate_aligned (match, sizeof (*ip) - 1, sizeof(u32x4));
  
  ip = (ip4_header_t *) match;
  
  /* These are realistically matched in practice */
  if (src)
    ip->src_address.as_u32 = src_val.as_u32;

  if (dst)
    ip->dst_address.as_u32 = dst_val.as_u32;
  
  if (proto)
    ip->protocol = proto_val;
    

  /* These are not, but they're included for completeness */
  if (version)
    ip->ip_version_and_header_length |= (version_val & 0xF)<<4;

  if (hdr_length)
    ip->ip_version_and_header_length |= (hdr_length_val & 0xF);
    
  if (tos)
    ip->tos = tos_val;
  
  if (length)
    ip->length = length_val;
  
  if (ttl)
    ip->ttl = ttl_val;

  if (checksum)
    ip->checksum = checksum_val;

  *matchp = match;
  return 1;
}

uword unformat_ip6_match (unformat_input_t * input, va_list * args)
{
  u8 ** matchp = va_arg (*args, u8 **);
  u8 * match = 0;
  ip6_header_t * ip;
  int version = 0;
  u32 version_val;
  u8  traffic_class;
  u32 traffic_class_val;
  u8  flow_label;
  u8  flow_label_val;
  int src = 0, dst = 0;
  ip6_address_t src_val, dst_val;
  int proto = 0;
  u32 proto_val;
  int payload_length = 0;
  u32 payload_length_val;
  int hop_limit = 0;
  int hop_limit_val;
  u32 ip_version_traffic_class_and_flow_label;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) 
    {
      if (unformat (input, "version %d", &version_val)) 
        version = 1;
      else if (unformat (input, "traffic_class %d", &traffic_class_val))
        traffic_class = 1;
      else if (unformat (input, "flow_label %d", &flow_label_val))
        flow_label = 1;
      else if (unformat (input, "src %U", unformat_ip6_address, &src_val))
        src = 1;
      else if (unformat (input, "dst %U", unformat_ip6_address, &dst_val))
        dst = 1;
      else if (unformat (input, "proto %d", &proto_val))
        proto = 1;
      else if (unformat (input, "payload_length %d", &payload_length_val))
        payload_length = 1;
      else if (unformat (input, "hop_limit %d", &hop_limit_val))
        hop_limit = 1;
      else
        break;
    }
  
  if (version + traffic_class + flow_label + src + dst + proto +
      payload_length + hop_limit == 0)
    return 0;

  /* 
   * Aligned because we use the real comparison functions
   */
  vec_validate_aligned (match, sizeof (*ip) - 1, sizeof(u32x4));
  
  ip = (ip6_header_t *) match;
  
  if (src)
    clib_memcpy (&ip->src_address, &src_val, sizeof (ip->src_address));

  if (dst)
    clib_memcpy (&ip->dst_address, &dst_val, sizeof (ip->dst_address));
  
  if (proto)
    ip->protocol = proto_val;
    
  ip_version_traffic_class_and_flow_label = 0;

  if (version)
    ip_version_traffic_class_and_flow_label |= (version_val & 0xF) << 28;

  if (traffic_class)
    ip_version_traffic_class_and_flow_label |= (traffic_class_val & 0xFF) << 20;

  if (flow_label)
    ip_version_traffic_class_and_flow_label |= (flow_label_val & 0xFFFFF);
    
  ip->ip_version_traffic_class_and_flow_label = 
    clib_host_to_net_u32 (ip_version_traffic_class_and_flow_label);

  if (payload_length)
    ip->payload_length = clib_host_to_net_u16 (payload_length_val);
  
  if (hop_limit)
    ip->hop_limit = hop_limit_val;

  *matchp = match;
  return 1;
}

uword unformat_l3_match (unformat_input_t * input, va_list * args)
{
  u8 ** matchp = va_arg (*args, u8 **);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "ip4 %U", unformat_ip4_match, matchp))
      return 1;
    else if (unformat (input, "ip6 %U", unformat_ip6_match, matchp))
      return 1;
    else
      break;
  }
  return 0;
}

uword unformat_vlan_tag (unformat_input_t * input, va_list * args)
{
  u8 * tagp = va_arg (*args, u8 *);
  u32 tag;

  if (unformat(input, "%d", &tag))
    {
      tagp[0] = (tag>>8) & 0x0F;
      tagp[1] = tag & 0xFF;
      return 1;
    }

  return 0;
}

uword unformat_l2_match (unformat_input_t * input, va_list * args)
{
  u8 ** matchp = va_arg (*args, u8 **);
  u8 * match = 0;
  u8 src = 0;
  u8 src_val[6];
  u8 dst = 0;
  u8 dst_val[6];
  u8 proto = 0;
  u16 proto_val;
  u8 tag1 = 0;
  u8 tag1_val [2];
  u8 tag2 = 0;
  u8 tag2_val [2];
  int len = 14;
  u8 ignore_tag1 = 0;
  u8 ignore_tag2 = 0;
  u8 cos1 = 0;
  u8 cos2 = 0;
  u32 cos1_val = 0;
  u32 cos2_val = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "src %U", unformat_ethernet_address, &src_val))
      src = 1;
    else if (unformat (input, "dst %U", unformat_ethernet_address, &dst_val))
      dst = 1;
    else if (unformat (input, "proto %U", 
                       unformat_ethernet_type_host_byte_order, &proto_val))
      proto = 1;
    else if (unformat (input, "tag1 %U", unformat_vlan_tag, tag1_val))
      tag1 = 1;
    else if (unformat (input, "tag2 %U", unformat_vlan_tag, tag2_val))
      tag2 = 1;
    else if (unformat (input, "ignore-tag1"))
      ignore_tag1 = 1;
    else if (unformat (input, "ignore-tag2"))
      ignore_tag2 = 1;
    else if (unformat (input, "cos1 %d", &cos1_val))
      cos1 = 1;
    else if (unformat (input, "cos2 %d", &cos2_val))
      cos2 = 1;
    else
      break;
  }
  if ((src + dst + proto + tag1 + tag2 +
      ignore_tag1 + ignore_tag2 + cos1 + cos2) == 0)
    return 0;

  if (tag1 || ignore_tag1 || cos1)
    len = 18;
  if (tag2 || ignore_tag2 || cos2)
    len = 22;

  vec_validate_aligned (match, len-1, sizeof(u32x4));

  if (dst)
    clib_memcpy (match, dst_val, 6);

  if (src)
    clib_memcpy (match + 6, src_val, 6);
  
  if (tag2)
    {
      /* inner vlan tag */
      match[19] = tag2_val[1];
      match[18] = tag2_val[0];
      if (cos2)
        match [18] |= (cos2_val & 0x7) << 5;
      if (proto)
        {
          match[21] = proto_val & 0xff;
          match[20] = proto_val >> 8;
        }
      if (tag1)
        {
          match [15] = tag1_val[1];
          match [14] = tag1_val[0];
        }
      if (cos1)
        match [14] |= (cos1_val & 0x7) << 5;
      *matchp = match;
      return 1;
    }
  if (tag1)
    {
      match [15] = tag1_val[1];
      match [14] = tag1_val[0];
      if (proto)
        {
          match[17] = proto_val & 0xff;
          match[16] = proto_val >> 8;
        }
      if (cos1)
        match [14] |= (cos1_val & 0x7) << 5;

      *matchp = match;
      return 1;
    }
  if (cos2)
    match [18] |= (cos2_val & 0x7) << 5;
  if (cos1)
    match [14] |= (cos1_val & 0x7) << 5;
  if (proto)
    {
      match[13] = proto_val & 0xff;
      match[12] = proto_val >> 8;
    }
  
  *matchp = match;
  return 1;
}


uword unformat_classify_match (unformat_input_t * input, va_list * args)
{
  u8 ** matchp = va_arg (*args, u8 **);
  u32 skip_n_vectors = va_arg (*args, u32);
  u32 match_n_vectors = va_arg (*args, u32);
  
  u8 * match = 0;
  u8 * l2 = 0;
  u8 * l3 = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "hex %U", unformat_hex_string, &match))
      ;
    else if (unformat (input, "l2 %U", unformat_l2_match, &l2))
      ;
    else if (unformat (input, "l3 %U", unformat_l3_match, &l3))
      ;
    else
      break;
  }

  if (match || l2 || l3)
    {
      if (l2 || l3)
        {
          /* "Win a free Ethernet header in every packet" */
          if (l2 == 0)
            vec_validate_aligned (l2, 13, sizeof(u32x4));
          match = l2;
          vec_append_aligned (match, l3, sizeof(u32x4));
          vec_free (l3);
        }

      /* Make sure the vector is big enough even if key is all 0's */
      vec_validate_aligned 
          (match, ((match_n_vectors + skip_n_vectors) * sizeof(u32x4)) - 1,
           sizeof(u32x4));
      
      /* Set size, include skipped vectors*/
      _vec_len (match) = (match_n_vectors+skip_n_vectors) * sizeof(u32x4);

      *matchp = match;

      return 1;
    }

  return 0;
}

static int api_classify_add_del_session (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_classify_add_del_session_t *mp;
    int is_add = 1;
    u32 table_index = ~0;
    u32 hit_next_index = ~0;
    u32 opaque_index = ~0;
    u8 * match = 0;
    i32 advance = 0;
    f64 timeout;
    u32 skip_n_vectors = 0;
    u32 match_n_vectors = 0;

    /* 
     * Warning: you have to supply skip_n and match_n
     * because the API client cant simply look at the classify
     * table object.
     */

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "del"))
            is_add = 0;
        else if (unformat (i, "hit-next %U", unformat_ip_next_index,
                           &hit_next_index))
            ;
        else if (unformat (i, "l2-hit-next %U", unformat_l2_next_index,
                           &hit_next_index))
            ;
        else if (unformat (i, "acl-hit-next %U", unformat_acl_next_index,
                           &hit_next_index))
            ;
        else if (unformat (i, "opaque-index %d", &opaque_index))
            ;
        else if (unformat (i, "skip_n %d", &skip_n_vectors))
            ;
        else if (unformat (i, "match_n %d", &match_n_vectors))
            ;
        else if (unformat (i, "match %U", unformat_classify_match,
                           &match, skip_n_vectors, match_n_vectors))
            ;
        else if (unformat (i, "advance %d", &advance))
            ;
        else if (unformat (i, "table-index %d", &table_index))
            ;
        else
            break;
    }

    if (table_index == ~0) {
        errmsg ("Table index required\n");
        return -99;
    }

    if (is_add && match == 0) {
        errmsg ("Match value required\n");
        return -99;
    }

    M2 (CLASSIFY_ADD_DEL_SESSION, classify_add_del_session,
        vec_len(match));

    mp->is_add = is_add;
    mp->table_index = ntohl(table_index);
    mp->hit_next_index = ntohl(hit_next_index);
    mp->opaque_index = ntohl(opaque_index);
    mp->advance = ntohl(advance);
    clib_memcpy (mp->match, match, vec_len(match));
    vec_free(match);

    S; W;
    /* NOTREACHED */
}

static int api_classify_set_interface_ip_table (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_classify_set_interface_ip_table_t *mp;
    f64 timeout;
    u32 sw_if_index;
    int sw_if_index_set;
    u32 table_index = ~0;
    u8  is_ipv6 = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
	else if (unformat (i, "sw_if_index %d", &sw_if_index))
	    sw_if_index_set = 1;
	else if (unformat (i, "table %d", &table_index))
	    ;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }
    
    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }


    M(CLASSIFY_SET_INTERFACE_IP_TABLE, classify_set_interface_ip_table);

    mp->sw_if_index = ntohl(sw_if_index);
    mp->table_index = ntohl(table_index);
    mp->is_ipv6 = is_ipv6;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_classify_set_interface_l2_tables (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_classify_set_interface_l2_tables_t *mp;
    f64 timeout;
    u32 sw_if_index;
    int sw_if_index_set;
    u32 ip4_table_index = ~0;
    u32 ip6_table_index = ~0;
    u32 other_table_index = ~0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
	else if (unformat (i, "sw_if_index %d", &sw_if_index))
	    sw_if_index_set = 1;
	else if (unformat (i, "ip4-table %d", &ip4_table_index))
	    ;
	else if (unformat (i, "ip6-table %d", &ip6_table_index))
	    ;
	else if (unformat (i, "other-table %d", &other_table_index))
	    ;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }
    
    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }


    M(CLASSIFY_SET_INTERFACE_L2_TABLES, classify_set_interface_l2_tables);

    mp->sw_if_index = ntohl(sw_if_index);
    mp->ip4_table_index = ntohl(ip4_table_index);
    mp->ip6_table_index = ntohl(ip6_table_index);
    mp->other_table_index = ntohl(other_table_index);


    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_ipfix_enable (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_ipfix_enable_t *mp;
    ip4_address_t collector_address;
    u8 collector_address_set = 0;
    u32 collector_port = ~0;
    ip4_address_t src_address;
    u8 src_address_set = 0;
    u32 vrf_id = ~0;
    u32 path_mtu = ~0;
    u32 template_interval = ~0;
    f64 timeout;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "collector_address %U", unformat_ip4_address,
            &collector_address))
            collector_address_set = 1;
        else if (unformat (i, "collector_port %d", &collector_port))
            ;
        else if (unformat (i, "src_address %U", unformat_ip4_address,
                 &src_address))
            src_address_set = 1;
        else if (unformat (i, "vrf_id %d", &vrf_id))
            ;
        else if (unformat (i, "path_mtu %d", &path_mtu))
            ;
        else if (unformat (i, "template_interval %d", &template_interval))
            ;
        else
            break;
    }

    if (collector_address_set == 0) {
        errmsg ("collector_address required\n");
        return -99;
    }

    if (src_address_set == 0) {
        errmsg ("src_address required\n");
        return -99;
    }

    M (IPFIX_ENABLE, ipfix_enable);

    memcpy(mp->collector_address, collector_address.data,
           sizeof(collector_address.data));
    mp->collector_port = htons((u16)collector_port);
    memcpy(mp->src_address, src_address.data,
           sizeof(src_address.data));
    mp->vrf_id = htonl(vrf_id);
    mp->path_mtu = htonl(path_mtu);
    mp->template_interval = htonl(template_interval);

    S; W;
    /* NOTREACHED */
}

static int api_get_node_index (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_get_node_index_t * mp;
    f64 timeout;
    u8 * name = 0;
    
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "node %s", &name))
            ;
        else
            break;
    }
    if (name == 0) {
        errmsg ("node name required\n");
        return -99;
    }
    if (vec_len (name) >= ARRAY_LEN(mp->node_name)) {
        errmsg ("node name too long, max %d\n", ARRAY_LEN(mp->node_name));
        return -99;
    }

    M(GET_NODE_INDEX, get_node_index);
    clib_memcpy (mp->node_name, name, vec_len(name));
    vec_free(name);
    
    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_get_next_index (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_get_next_index_t * mp;
    f64 timeout;
    u8 * node_name = 0, * next_node_name = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "node-name %s", &node_name))
            ;
        else if (unformat (i, "next-node-name %s", &next_node_name))
            break;
    }

    if (node_name == 0) {
        errmsg ("node name required\n");
        return -99;
    }
    if (vec_len (node_name) >= ARRAY_LEN(mp->node_name)) {
        errmsg ("node name too long, max %d\n", ARRAY_LEN(mp->node_name));
        return -99;
    }

    if (next_node_name == 0) {
        errmsg ("next node name required\n");
        return -99;
    }
    if (vec_len (next_node_name) >= ARRAY_LEN(mp->next_name)) {
        errmsg ("next node name too long, max %d\n", ARRAY_LEN(mp->next_name));
        return -99;
    }

    M(GET_NEXT_INDEX, get_next_index);
    clib_memcpy (mp->node_name, node_name, vec_len(node_name));
    clib_memcpy (mp->next_name, next_node_name, vec_len(next_node_name));
    vec_free(node_name);
    vec_free(next_node_name);

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_add_node_next (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_add_node_next_t * mp;
    f64 timeout;
    u8 * name = 0;
    u8 * next = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "node %s", &name))
            ;
        else if (unformat (i, "next %s", &next))
            ;
        else
            break;
    }
    if (name == 0) {
        errmsg ("node name required\n");
        return -99;
    }
    if (vec_len (name) >= ARRAY_LEN(mp->node_name)) {
        errmsg ("node name too long, max %d\n", ARRAY_LEN(mp->node_name));
        return -99;
    }
    if (next == 0) {
        errmsg ("next node required\n");
        return -99;
    }
    if (vec_len (next) >= ARRAY_LEN(mp->next_name)) {
        errmsg ("next name too long, max %d\n", ARRAY_LEN(mp->next_name));
        return -99;
    }
    
    M(ADD_NODE_NEXT, add_node_next);
    clib_memcpy (mp->node_name, name, vec_len(name));
    clib_memcpy (mp->next_name, next, vec_len(next));
    vec_free(name);
    vec_free(next);
    
    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_l2tpv3_create_tunnel (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    ip6_address_t client_address, our_address;
    int client_address_set = 0;
    int our_address_set = 0;
    u32 local_session_id = 0;
    u32 remote_session_id = 0;
    u64 local_cookie = 0;
    u64 remote_cookie = 0;
    u8 l2_sublayer_present = 0;
    vl_api_l2tpv3_create_tunnel_t * mp;
    f64 timeout;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
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

    if (client_address_set == 0) {
        errmsg ("client_address required\n");
        return -99;
    }

    if (our_address_set == 0) {
        errmsg ("our_address required\n");
        return -99;
    }

    M(L2TPV3_CREATE_TUNNEL, l2tpv3_create_tunnel);

    clib_memcpy (mp->client_address, client_address.as_u8, 
            sizeof (mp->client_address));

    clib_memcpy (mp->our_address, our_address.as_u8, 
            sizeof (mp->our_address));
    
    mp->local_session_id = ntohl (local_session_id);
    mp->remote_session_id = ntohl (remote_session_id);
    mp->local_cookie = clib_host_to_net_u64 (local_cookie);
    mp->remote_cookie = clib_host_to_net_u64 (remote_cookie);
    mp->l2_sublayer_present = l2_sublayer_present;
    mp->is_ipv6 = 1;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_l2tpv3_set_tunnel_cookies (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    u32 sw_if_index;
    u8  sw_if_index_set = 0;
    u64 new_local_cookie = 0;
    u64 new_remote_cookie = 0;
    vl_api_l2tpv3_set_tunnel_cookies_t *mp;
    f64 timeout;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
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

    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    M(L2TPV3_SET_TUNNEL_COOKIES, l2tpv3_set_tunnel_cookies);

    mp->sw_if_index = ntohl(sw_if_index);
    mp->new_local_cookie = clib_host_to_net_u64 (new_local_cookie);
    mp->new_remote_cookie = clib_host_to_net_u64 (new_remote_cookie);

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_l2tpv3_interface_enable_disable (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_l2tpv3_interface_enable_disable_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8  sw_if_index_set = 0;
    u8  enable_disable = 1;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
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

    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }
    
    M(L2TPV3_INTERFACE_ENABLE_DISABLE, l2tpv3_interface_enable_disable);

    mp->sw_if_index = ntohl(sw_if_index);
    mp->enable_disable = enable_disable;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_l2tpv3_set_lookup_key (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_l2tpv3_set_lookup_key_t * mp;
    f64 timeout;
    u8 key = ~0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "lookup_v6_src"))
            key = L2T_LOOKUP_SRC_ADDRESS;
        else if (unformat (i, "lookup_v6_dst"))
            key = L2T_LOOKUP_DST_ADDRESS;
        else if (unformat (i, "lookup_session_id"))
            key = L2T_LOOKUP_SESSION_ID;
        else
            break;
    }

    if (key == (u8) ~0) {
        errmsg ("l2tp session lookup key unset\n");
        return -99;
    }
    
    M(L2TPV3_SET_LOOKUP_KEY, l2tpv3_set_lookup_key);

    mp->key = key;

    S; W;
    /* NOTREACHED */
    return 0;
}

static void vl_api_sw_if_l2tpv3_tunnel_details_t_handler
(vl_api_sw_if_l2tpv3_tunnel_details_t * mp)
{
    vat_main_t * vam = &vat_main;

    fformat(vam->ofp,  "* %U (our) %U (client) (sw_if_index %d)\n",
              format_ip6_address, mp->our_address,
              format_ip6_address, mp->client_address,
              clib_net_to_host_u32(mp->sw_if_index));

    fformat (vam->ofp, "   local cookies %016llx %016llx remote cookie %016llx\n",
              clib_net_to_host_u64 (mp->local_cookie[0]),
              clib_net_to_host_u64 (mp->local_cookie[1]),
              clib_net_to_host_u64 (mp->remote_cookie));

    fformat (vam->ofp, "   local session-id %d remote session-id %d\n",
              clib_net_to_host_u32 (mp->local_session_id),
              clib_net_to_host_u32 (mp->remote_session_id));

    fformat (vam->ofp, "   l2 specific sublayer %s\n\n",
              mp->l2_sublayer_present ? "preset" : "absent");

}

static void vl_api_sw_if_l2tpv3_tunnel_details_t_handler_json
(vl_api_sw_if_l2tpv3_tunnel_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node = NULL;
    struct in6_addr addr;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);

    clib_memcpy(&addr, mp->our_address, sizeof(addr));
    vat_json_object_add_ip6(node, "our_address", addr);
    clib_memcpy(&addr, mp->client_address, sizeof(addr));
    vat_json_object_add_ip6(node, "client_address", addr);

    vat_json_node_t * lc = vat_json_object_add(node, "local_cookie");
    vat_json_init_array(lc);
    vat_json_array_add_uint(lc, clib_net_to_host_u64(mp->local_cookie[0]));
    vat_json_array_add_uint(lc, clib_net_to_host_u64(mp->local_cookie[1]));
    vat_json_object_add_uint(node, "remote_cookie", clib_net_to_host_u64(mp->remote_cookie));

    printf("local id: %u", clib_net_to_host_u32(mp->local_session_id));
    vat_json_object_add_uint(node, "local_session_id", clib_net_to_host_u32(mp->local_session_id));
    vat_json_object_add_uint(node, "remote_session_id", clib_net_to_host_u32(mp->remote_session_id));
    vat_json_object_add_string_copy(node, "l2_sublayer", mp->l2_sublayer_present ?
            (u8*)"present" : (u8*)"absent");
}

static int api_sw_if_l2tpv3_tunnel_dump (vat_main_t * vam)
{
    vl_api_sw_if_l2tpv3_tunnel_dump_t *mp;
    f64 timeout;

    /* Get list of l2tpv3-tunnel interfaces */
    M(SW_IF_L2TPV3_TUNNEL_DUMP, sw_if_l2tpv3_tunnel_dump);
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}


static void vl_api_sw_interface_tap_details_t_handler
(vl_api_sw_interface_tap_details_t * mp)
{
    vat_main_t * vam = &vat_main;

    fformat(vam->ofp,  "%-16s %d\n",
              mp->dev_name,
              clib_net_to_host_u32(mp->sw_if_index));
}

static void vl_api_sw_interface_tap_details_t_handler_json
(vl_api_sw_interface_tap_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node = NULL;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_uint(node, "sw_if_index", ntohl(mp->sw_if_index));
    vat_json_object_add_string_copy(node, "dev_name", mp->dev_name);
}

static int api_sw_interface_tap_dump (vat_main_t * vam)
{
    vl_api_sw_interface_tap_dump_t *mp;
    f64 timeout;

    fformat(vam->ofp,  "\n%-16s %s\n", "dev_name", "sw_if_index");
    /* Get list of tap interfaces */
    M(SW_INTERFACE_TAP_DUMP, sw_interface_tap_dump);
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}

static uword unformat_vxlan_decap_next 
(unformat_input_t * input, va_list * args)
{
  u32 * result = va_arg (*args, u32 *);
  u32 tmp;
  
  if (unformat (input, "drop"))
    *result = VXLAN_INPUT_NEXT_DROP;
  else if (unformat (input, "ip4"))
    *result = VXLAN_INPUT_NEXT_IP4_INPUT;
  else if (unformat (input, "ip6"))
    *result = VXLAN_INPUT_NEXT_IP6_INPUT;
  else if (unformat (input, "l2"))
    *result = VXLAN_INPUT_NEXT_L2_INPUT;
  else if (unformat (input, "%d", &tmp))
    *result = tmp;
  else
    return 0;
  return 1;
}

static int api_vxlan_add_del_tunnel (vat_main_t * vam)
{
    unformat_input_t * line_input = vam->input;
    vl_api_vxlan_add_del_tunnel_t *mp;
    f64 timeout;
    ip4_address_t src4, dst4;
    ip6_address_t src6, dst6;
    u8 is_add = 1;
    u8 ipv4_set = 0, ipv6_set = 0;
    u8 src_set = 0;
    u8 dst_set = 0;
    u32 encap_vrf_id = 0;
    u32 decap_next_index = ~0;
    u32 vni = 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (line_input, "del"))
            is_add = 0;
        else if (unformat (line_input, "src %U", 
                           unformat_ip4_address, &src4))
          {
            ipv4_set = 1;
            src_set = 1;
          }
        else if (unformat (line_input, "dst %U",
                           unformat_ip4_address, &dst4))
          {
            ipv4_set = 1;
            dst_set = 1;
          }
        else if (unformat (line_input, "src %U", 
                           unformat_ip6_address, &src6))
          {
            ipv6_set = 1;
            src_set = 1;
          }
        else if (unformat (line_input, "dst %U",
                           unformat_ip6_address, &dst6))
          {
            ipv6_set = 1;
            dst_set = 1;
          }
        else if (unformat (line_input, "encap-vrf-id %d", &encap_vrf_id))
            ;
        else if (unformat (line_input, "decap-next %U", 
                           unformat_vxlan_decap_next, &decap_next_index))
            ;
        else if (unformat (line_input, "vni %d", &vni))
            ;
        else {
            errmsg ("parse error '%U'\n", format_unformat_error, line_input);
            return -99;
        }
    }

    if (src_set == 0) {
        errmsg ("tunnel src address not specified\n");
        return -99;
    }
    if (dst_set == 0) {
        errmsg ("tunnel dst address not specified\n");
        return -99;
    }

    if (ipv4_set && ipv6_set) {
        errmsg ("both IPv4 and IPv6 addresses specified");
        return -99;
    }

    if ((vni == 0) || (vni>>24)) {
        errmsg ("vni not specified or out of range\n");
        return -99;
    }

    M (VXLAN_ADD_DEL_TUNNEL, vxlan_add_del_tunnel);

    if (ipv6_set) {
        clib_memcpy(&mp->src_address, &src6, sizeof(src6));
        clib_memcpy(&mp->dst_address, &dst6, sizeof(dst6));
    } else { 
        clib_memcpy(&mp->src_address, &src4, sizeof(src4));
        clib_memcpy(&mp->dst_address, &dst4, sizeof(dst4));
    }
    mp->encap_vrf_id = ntohl(encap_vrf_id);
    mp->decap_next_index = ntohl(decap_next_index);
    mp->vni = ntohl(vni);
    mp->is_add = is_add;
    mp->is_ipv6 = ipv6_set;

    S; W;
    /* NOTREACHED */
    return 0;
}

static void vl_api_vxlan_tunnel_details_t_handler
(vl_api_vxlan_tunnel_details_t * mp)
{
    vat_main_t * vam = &vat_main;

    fformat(vam->ofp, "%11d%24U%24U%14d%18d%13d\n",
            ntohl(mp->sw_if_index),
            format_ip46_address, &(mp->src_address[0]),
	    IP46_TYPE_ANY,
            format_ip46_address, &(mp->dst_address[0]),
	    IP46_TYPE_ANY,
            ntohl(mp->encap_vrf_id),
            ntohl(mp->decap_next_index),
            ntohl(mp->vni));
}

static void vl_api_vxlan_tunnel_details_t_handler_json
(vl_api_vxlan_tunnel_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node = NULL;
    struct in_addr ip4;
    struct in6_addr ip6;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_uint(node, "sw_if_index", ntohl(mp->sw_if_index));
    if (mp->is_ipv6) {
        clib_memcpy(&ip6, &(mp->src_address[0]), sizeof(ip6));
        vat_json_object_add_ip6(node, "src_address", ip6);
        clib_memcpy(&ip6, &(mp->dst_address[0]), sizeof(ip6));
        vat_json_object_add_ip6(node, "dst_address", ip6);
    } else {
        clib_memcpy(&ip4, &(mp->src_address[0]), sizeof(ip4));
        vat_json_object_add_ip4(node, "src_address", ip4);
        clib_memcpy(&ip4, &(mp->dst_address[0]), sizeof(ip4));
        vat_json_object_add_ip4(node, "dst_address", ip4);
    }
    vat_json_object_add_uint(node, "encap_vrf_id", ntohl(mp->encap_vrf_id));
    vat_json_object_add_uint(node, "decap_next_index", ntohl(mp->decap_next_index));
    vat_json_object_add_uint(node, "vni", ntohl(mp->vni));
    vat_json_object_add_uint(node, "is_ipv6", mp->is_ipv6 ? 1 : 0);
}

static int api_vxlan_tunnel_dump (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_vxlan_tunnel_dump_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8 sw_if_index_set = 0;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else
            break;
    }

    if (sw_if_index_set == 0) {
        sw_if_index = ~0;
    }

    if (!vam->json_output) {
        fformat(vam->ofp, "%11s%24s%24s%14s%18s%13s\n",
                "sw_if_index", "src_address", "dst_address",
                "encap_vrf_id", "decap_next_index", "vni");
    }

    /* Get list of vxlan-tunnel interfaces */
    M(VXLAN_TUNNEL_DUMP, vxlan_tunnel_dump);

    mp->sw_if_index = htonl(sw_if_index);

    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}

static int api_gre_add_del_tunnel (vat_main_t * vam)
{
    unformat_input_t * line_input = vam->input;
    vl_api_gre_add_del_tunnel_t *mp;
    f64 timeout;
    ip4_address_t src4, dst4;
    u8 is_add = 1;
    u8 src_set = 0;
    u8 dst_set = 0;
    u32 outer_fib_id = 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (line_input, "del"))
            is_add = 0;
        else if (unformat (line_input, "src %U",
                           unformat_ip4_address, &src4))
            src_set = 1;
        else if (unformat (line_input, "dst %U",
                           unformat_ip4_address, &dst4))
            dst_set = 1;
        else if (unformat (line_input, "outer-fib-id %d", &outer_fib_id))
            ;
        else {
            errmsg ("parse error '%U'\n", format_unformat_error, line_input);
            return -99;
        }
    }

    if (src_set == 0) {
        errmsg ("tunnel src address not specified\n");
        return -99;
    }
    if (dst_set == 0) {
        errmsg ("tunnel dst address not specified\n");
        return -99;
    }


    M (GRE_ADD_DEL_TUNNEL, gre_add_del_tunnel);

    clib_memcpy(&mp->src_address, &src4, sizeof(src4));
    clib_memcpy(&mp->dst_address, &dst4, sizeof(dst4));
    mp->outer_table_id = ntohl(outer_fib_id);
    mp->is_add = is_add;

    S; W;
    /* NOTREACHED */
    return 0;
}

static void vl_api_gre_tunnel_details_t_handler
(vl_api_gre_tunnel_details_t * mp)
{
    vat_main_t * vam = &vat_main;

    fformat(vam->ofp, "%11d%15U%15U%14d\n",
            ntohl(mp->sw_if_index),
            format_ip4_address, &mp->src_address,
            format_ip4_address, &mp->dst_address,
            ntohl(mp->outer_table_id));
}

static void vl_api_gre_tunnel_details_t_handler_json
(vl_api_gre_tunnel_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node = NULL;
    struct in_addr ip4;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_uint(node, "sw_if_index", ntohl(mp->sw_if_index));
    clib_memcpy(&ip4, &mp->src_address, sizeof(ip4));
    vat_json_object_add_ip4(node, "src_address", ip4);
    clib_memcpy(&ip4, &mp->dst_address, sizeof(ip4));
    vat_json_object_add_ip4(node, "dst_address", ip4);
    vat_json_object_add_uint(node, "outer_fib_id", ntohl(mp->outer_table_id));
}

static int api_gre_tunnel_dump (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_gre_tunnel_dump_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8 sw_if_index_set = 0;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else
            break;
    }

    if (sw_if_index_set == 0) {
        sw_if_index = ~0;
    }

    if (!vam->json_output) {
        fformat(vam->ofp, "%11s%15s%15s%14s\n",
                "sw_if_index", "src_address", "dst_address",
                "outer_fib_id");
    }

    /* Get list of gre-tunnel interfaces */
    M(GRE_TUNNEL_DUMP, gre_tunnel_dump);

    mp->sw_if_index = htonl(sw_if_index);

    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}

static int api_l2_fib_clear_table (vat_main_t * vam)
{
//  unformat_input_t * i = vam->input;
    vl_api_l2_fib_clear_table_t *mp;
    f64 timeout;

    M(L2_FIB_CLEAR_TABLE, l2_fib_clear_table);

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_l2_interface_efp_filter (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_l2_interface_efp_filter_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8 enable = 1;
    u8 sw_if_index_set = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
	else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
	else if (unformat (i, "enable"))
            enable = 1;
	else if (unformat (i, "disable"))
            enable = 0;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }
    
    if (sw_if_index_set == 0) {
        errmsg ("missing sw_if_index\n");
        return -99;
    }

    M(L2_INTERFACE_EFP_FILTER, l2_interface_efp_filter);

    mp->sw_if_index = ntohl(sw_if_index);
    mp->enable_disable = enable;

    S; W;
    /* NOTREACHED */
    return 0;
}

#define foreach_vtr_op                          \
_("disable",  L2_VTR_DISABLED)                  \
_("push-1",  L2_VTR_PUSH_1)                     \
_("push-2",  L2_VTR_PUSH_2)                     \
_("pop-1",  L2_VTR_POP_1)                       \
_("pop-2",  L2_VTR_POP_2)                       \
_("translate-1-1",  L2_VTR_TRANSLATE_1_1)       \
_("translate-1-2",  L2_VTR_TRANSLATE_1_2)       \
_("translate-2-1",  L2_VTR_TRANSLATE_2_1)       \
_("translate-2-2",  L2_VTR_TRANSLATE_2_2)

static int api_l2_interface_vlan_tag_rewrite (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_l2_interface_vlan_tag_rewrite_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8 sw_if_index_set = 0;
    u8 vtr_op_set = 0;
    u32 vtr_op = 0;
    u32 push_dot1q = 1;
    u32 tag1 = ~0;
    u32 tag2 = ~0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "vtr_op %d", &vtr_op))
            vtr_op_set = 1;
#define _(n,v) else if (unformat(i, n)) {vtr_op = v; vtr_op_set = 1;}
        foreach_vtr_op
#undef _
        
        else if (unformat (i, "push_dot1q %d", &push_dot1q))
            ;
        else if (unformat (i, "tag1 %d", &tag1))
            ;
        else if (unformat (i, "tag2 %d", &tag2))
            ;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }
    
    if ((sw_if_index_set == 0)||(vtr_op_set == 0)) {
        errmsg ("missing vtr operation or sw_if_index\n");
        return -99;
    }

    M(L2_INTERFACE_VLAN_TAG_REWRITE, l2_interface_vlan_tag_rewrite)

    mp->sw_if_index = ntohl(sw_if_index);
    mp->vtr_op = ntohl(vtr_op);
    mp->push_dot1q = ntohl(push_dot1q);
    mp->tag1 = ntohl(tag1);
    mp->tag2 = ntohl(tag2);

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_create_vhost_user_if (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_create_vhost_user_if_t *mp;
    f64 timeout;
    u8 * file_name;
    u8 is_server = 0;
    u8 file_name_set = 0;
    u32 custom_dev_instance = ~0;
    u8 hwaddr[6];
    u8 use_custom_mac = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
      if (unformat (i, "socket %s", &file_name)) {
        file_name_set = 1;
      }
      else if (unformat (i, "renumber %"PRIu32, &custom_dev_instance))
        ;
      else if (unformat (i, "mac %U", unformat_ethernet_address, hwaddr))
        use_custom_mac = 1;
      else if (unformat (i, "server"))
        is_server = 1;
      else
        break;
    }

    if (file_name_set == 0) {
      errmsg ("missing socket file name\n");
      return -99;
    }

    if (vec_len (file_name) > 255) {
      errmsg ("socket file name too long\n");
      return -99;
    }
    vec_add1 (file_name, 0);

    M(CREATE_VHOST_USER_IF, create_vhost_user_if);

    mp->is_server = is_server;
    clib_memcpy(mp->sock_filename, file_name, vec_len(file_name));
    vec_free(file_name);
    if (custom_dev_instance != ~0) {
        mp->renumber = 1;
        mp->custom_dev_instance = ntohl(custom_dev_instance);
    }
    mp->use_custom_mac = use_custom_mac;
    clib_memcpy(mp->mac_address, hwaddr, 6);

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_modify_vhost_user_if (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_modify_vhost_user_if_t *mp;
    f64 timeout;
    u8 * file_name;
    u8 is_server = 0;
    u8 file_name_set = 0;
    u32 custom_dev_instance = ~0;
    u8 sw_if_index_set = 0;
    u32 sw_if_index = (u32)~0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
          sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
          sw_if_index_set = 1;
      else if (unformat (i, "socket %s", &file_name)) {
        file_name_set = 1;
      }
      else if (unformat (i, "renumber %"PRIu32, &custom_dev_instance))
        ;
      else if (unformat (i, "server"))
        is_server = 1;
      else
        break;
    }

    if (sw_if_index_set == 0) {
       errmsg ("missing sw_if_index or interface name\n");
       return -99;
    }

    if (file_name_set == 0) {
      errmsg ("missing socket file name\n");
      return -99;
    }

    if (vec_len (file_name) > 255) {
      errmsg ("socket file name too long\n");
      return -99;
    }
    vec_add1 (file_name, 0);

    M(MODIFY_VHOST_USER_IF, modify_vhost_user_if);

    mp->sw_if_index = ntohl(sw_if_index);
    mp->is_server = is_server;
    clib_memcpy(mp->sock_filename, file_name, vec_len(file_name));
    vec_free(file_name);
    if (custom_dev_instance != ~0) {
        mp->renumber = 1;
        mp->custom_dev_instance = ntohl(custom_dev_instance);
    }

    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_delete_vhost_user_if (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_delete_vhost_user_if_t *mp;
    f64 timeout;
    u32 sw_if_index = ~0;
    u8 sw_if_index_set = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
          sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
          sw_if_index_set = 1;
      else
        break;
    }

    if (sw_if_index_set == 0) {
       errmsg ("missing sw_if_index or interface name\n");
       return -99;
    }


    M(DELETE_VHOST_USER_IF, delete_vhost_user_if);

    mp->sw_if_index = ntohl(sw_if_index);

    S; W;
    /* NOTREACHED */
    return 0;
}

static void vl_api_sw_interface_vhost_user_details_t_handler
(vl_api_sw_interface_vhost_user_details_t * mp)
{
    vat_main_t * vam = &vat_main;

    fformat(vam->ofp, "%-25s %3" PRIu32 " %6" PRIu32 " %8x %6d %7d %s\n",
            (char *)mp->interface_name,
            ntohl(mp->sw_if_index), ntohl(mp->virtio_net_hdr_sz),
            clib_net_to_host_u64(mp->features), mp->is_server,
            ntohl(mp->num_regions), (char *)mp->sock_filename);
    fformat(vam->ofp, "    Status: '%s'\n", strerror(ntohl(mp->sock_errno)));
}

static void vl_api_sw_interface_vhost_user_details_t_handler_json
(vl_api_sw_interface_vhost_user_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node = NULL;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_uint(node, "sw_if_index", ntohl(mp->sw_if_index));
    vat_json_object_add_string_copy(node, "interface_name", mp->interface_name);
    vat_json_object_add_uint(node, "virtio_net_hdr_sz", ntohl(mp->virtio_net_hdr_sz));
    vat_json_object_add_uint(node, "features", clib_net_to_host_u64(mp->features));
    vat_json_object_add_uint(node, "is_server", mp->is_server);
    vat_json_object_add_string_copy(node, "sock_filename", mp->sock_filename);
    vat_json_object_add_uint(node, "num_regions", ntohl(mp->num_regions));
    vat_json_object_add_uint(node, "sock_errno", ntohl(mp->sock_errno));
}

static int api_sw_interface_vhost_user_dump (vat_main_t * vam)
{
    vl_api_sw_interface_vhost_user_dump_t *mp;
    f64 timeout;
    fformat(vam->ofp, "Interface name           idx hdr_sz features server regions filename\n");

    /* Get list of vhost-user interfaces */
    M(SW_INTERFACE_VHOST_USER_DUMP, sw_interface_vhost_user_dump);
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}

static int api_show_version (vat_main_t * vam)
{
    vl_api_show_version_t *mp;
    f64 timeout;

    M(SHOW_VERSION, show_version);

    S; W;
    /* NOTREACHED */
    return 0;
}


static int api_vxlan_gpe_add_del_tunnel (vat_main_t * vam)
{
    unformat_input_t * line_input = vam->input;
    vl_api_vxlan_gpe_add_del_tunnel_t *mp;
    f64 timeout;
    ip4_address_t local4, remote4;
    ip6_address_t local6, remote6;
    u8 is_add = 1;
    u8 ipv4_set = 0, ipv6_set = 0;
    u8 local_set = 0;
    u8 remote_set = 0;
    u32 encap_vrf_id = 0;
    u32 decap_vrf_id = 0;
    u8 protocol = ~0;
    u32 vni;
    u8 vni_set = 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (line_input, "del"))
            is_add = 0;
        else if (unformat (line_input, "local %U", 
                           unformat_ip4_address, &local4))
        {
            local_set = 1;
            ipv4_set = 1;
        }
        else if (unformat (line_input, "remote %U",
                           unformat_ip4_address, &remote4))
        {
            remote_set = 1;
            ipv4_set = 1;
        }
        else if (unformat (line_input, "local %U",
                           unformat_ip6_address, &local6))
        {
            local_set = 1;
            ipv6_set = 1;
        }
        else if (unformat (line_input, "remote %U",
                           unformat_ip6_address, &remote6))
        {
            remote_set = 1;
            ipv6_set = 1;
        }
        else if (unformat (line_input, "encap-vrf-id %d", &encap_vrf_id))
            ;
        else if (unformat (line_input, "decap-vrf-id %d", &decap_vrf_id))
            ;
        else if (unformat (line_input, "vni %d", &vni))
            vni_set = 1;
        else if (unformat(line_input, "next-ip4"))
            protocol = 1;
        else if (unformat(line_input, "next-ip6"))
            protocol = 2;
        else if (unformat(line_input, "next-ethernet"))
            protocol = 3;
        else if (unformat(line_input, "next-nsh"))
            protocol = 4;
        else {
            errmsg ("parse error '%U'\n", format_unformat_error, line_input);
            return -99;
        }
    }

    if (local_set == 0) {
        errmsg ("tunnel local address not specified\n");
        return -99;
    }
    if (remote_set == 0) {
        errmsg ("tunnel remote address not specified\n");
        return -99;
    }
    if (ipv4_set && ipv6_set) {
        errmsg ("both IPv4 and IPv6 addresses specified");
        return -99;
    }

    if (vni_set == 0) {
        errmsg ("vni not specified\n");
        return -99;
    }

    M(VXLAN_GPE_ADD_DEL_TUNNEL, vxlan_gpe_add_del_tunnel);
    

    if (ipv6_set) {
        clib_memcpy(&mp->local, &local6, sizeof(local6));
        clib_memcpy(&mp->remote, &remote6, sizeof(remote6));
    } else {
        clib_memcpy(&mp->local, &local4, sizeof(local4));
        clib_memcpy(&mp->remote, &remote4, sizeof(remote4));
    }

    mp->encap_vrf_id = ntohl(encap_vrf_id);
    mp->decap_vrf_id = ntohl(decap_vrf_id);
    mp->protocol = ntohl(protocol);
    mp->vni = ntohl(vni);
    mp->is_add = is_add;
    mp->is_ipv6 = ipv6_set;

    S; W;
    /* NOTREACHED */
    return 0;
}

static void vl_api_vxlan_gpe_tunnel_details_t_handler
(vl_api_vxlan_gpe_tunnel_details_t * mp)
{
    vat_main_t * vam = &vat_main;

    fformat(vam->ofp, "%11d%24U%24U%13d%12d%14d%14d\n",
            ntohl(mp->sw_if_index),
            format_ip46_address, &(mp->local[0]),
            format_ip46_address, &(mp->remote[0]),
			ntohl(mp->vni),
            ntohl(mp->protocol),
            ntohl(mp->encap_vrf_id),
            ntohl(mp->decap_vrf_id));
}

static void vl_api_vxlan_gpe_tunnel_details_t_handler_json
(vl_api_vxlan_gpe_tunnel_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node = NULL;
    struct in_addr ip4;
    struct in6_addr ip6;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_uint(node, "sw_if_index", ntohl(mp->sw_if_index));
    if (mp->is_ipv6) {
        clib_memcpy(&ip6, &(mp->local[0]), sizeof(ip6));
        vat_json_object_add_ip6(node, "local", ip6);
        clib_memcpy(&ip6, &(mp->remote[0]), sizeof(ip6));
        vat_json_object_add_ip6(node, "remote", ip6);
    } else {
        clib_memcpy(&ip4, &(mp->local[0]), sizeof(ip4));
        vat_json_object_add_ip4(node, "local", ip4);
        clib_memcpy(&ip4, &(mp->remote[0]), sizeof(ip4));
        vat_json_object_add_ip4(node, "remote", ip4);
    }
    vat_json_object_add_uint(node, "vni", ntohl(mp->vni));
    vat_json_object_add_uint(node, "protocol", ntohl(mp->protocol));
    vat_json_object_add_uint(node, "encap_vrf_id", ntohl(mp->encap_vrf_id));
    vat_json_object_add_uint(node, "decap_vrf_id", ntohl(mp->decap_vrf_id));
    vat_json_object_add_uint(node, "is_ipv6", mp->is_ipv6 ? 1 : 0);
}

static int api_vxlan_gpe_tunnel_dump (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_vxlan_gpe_tunnel_dump_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8 sw_if_index_set = 0;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else
            break;
    }

    if (sw_if_index_set == 0) {
        sw_if_index = ~0;
    }

    if (!vam->json_output) {
        fformat(vam->ofp, "%11s%24s%24s%13s%15s%14s%14s\n",
                "sw_if_index", "local", "remote", "vni",
				"protocol","encap_vrf_id", "decap_vrf_id");
    }

    /* Get list of vxlan-tunnel interfaces */
    M(VXLAN_GPE_TUNNEL_DUMP, vxlan_gpe_tunnel_dump);

    mp->sw_if_index = htonl(sw_if_index);

    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}

u8 * format_l2_fib_mac_address (u8 * s, va_list * args)
{
  u8 * a = va_arg (*args, u8 *);

  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
                 a[2], a[3], a[4], a[5], a[6], a[7]);
}

static void vl_api_l2_fib_table_entry_t_handler
(vl_api_l2_fib_table_entry_t * mp)
{
    vat_main_t * vam = &vat_main;

    fformat(vam->ofp, "%3" PRIu32 "    %U    %3" PRIu32
            "       %d       %d     %d\n",
            ntohl(mp->bd_id), format_l2_fib_mac_address, &mp->mac,
            ntohl(mp->sw_if_index), mp->static_mac, mp->filter_mac,
            mp->bvi_mac);
}

static void vl_api_l2_fib_table_entry_t_handler_json
(vl_api_l2_fib_table_entry_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node = NULL;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_uint(node, "bd_id", ntohl(mp->bd_id));
    vat_json_object_add_uint(node, "mac", clib_net_to_host_u64(mp->mac));
    vat_json_object_add_uint(node, "sw_if_index", ntohl(mp->sw_if_index));
    vat_json_object_add_uint(node, "static_mac", mp->static_mac);
    vat_json_object_add_uint(node, "filter_mac", mp->filter_mac);
    vat_json_object_add_uint(node, "bvi_mac", mp->bvi_mac);
}

static int api_l2_fib_table_dump (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_l2_fib_table_dump_t *mp;
    f64 timeout;
    u32 bd_id;
    u8 bd_id_set = 0;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "bd_id %d", &bd_id))
            bd_id_set = 1;
	else
            break;
    }

    if (bd_id_set == 0) {
        errmsg ("missing bridge domain\n");
        return -99;
    }

    fformat(vam->ofp, "BD-ID     Mac Address      sw-ndx  Static  Filter  BVI\n");

    /* Get list of l2 fib entries */
    M(L2_FIB_TABLE_DUMP, l2_fib_table_dump);

    mp->bd_id = ntohl(bd_id);
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}


static int
api_interface_name_renumber (vat_main_t * vam)
{
    unformat_input_t * line_input = vam->input;
    vl_api_interface_name_renumber_t *mp;
    u32 sw_if_index = ~0;
    f64 timeout;
    u32 new_show_dev_instance = ~0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (line_input, "%U", unformat_sw_if_index, vam, 
                      &sw_if_index))
            ;
        else if (unformat (line_input, "sw_if_index %d", &sw_if_index))
            ;
        else if (unformat (line_input, "new_show_dev_instance %d", 
                           &new_show_dev_instance))
            ;
        else
            break;
    }

    if (sw_if_index == ~0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    if (new_show_dev_instance == ~0) {
        errmsg ("missing new_show_dev_instance\n");
        return -99;
    }

    M(INTERFACE_NAME_RENUMBER, interface_name_renumber);

    mp->sw_if_index = ntohl (sw_if_index);
    mp->new_show_dev_instance = ntohl (new_show_dev_instance);

    S; W;
}

static int
api_want_ip4_arp_events (vat_main_t * vam)
{
    unformat_input_t * line_input = vam->input;
    vl_api_want_ip4_arp_events_t * mp;
    f64 timeout;
    ip4_address_t address;
    int address_set = 0;
    u32 enable_disable = 1;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (line_input, "address %U", 
                      unformat_ip4_address, &address))
            address_set = 1;
        else if (unformat (line_input, "del"))
            enable_disable = 0;
        else
            break;
    }
    
    if (address_set == 0) {
        errmsg ("missing addresses\n");
        return -99;
    }
        
    M(WANT_IP4_ARP_EVENTS, want_ip4_arp_events);
    mp->enable_disable = enable_disable;
    mp->pid = getpid();
    mp->address = address.as_u32;

    S; W; 
}

static int api_input_acl_set_interface (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_input_acl_set_interface_t *mp;
    f64 timeout;
    u32 sw_if_index;
    int sw_if_index_set;
    u32 ip4_table_index = ~0;
    u32 ip6_table_index = ~0;
    u32 l2_table_index = ~0;
    u8 is_add = 1;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
	else if (unformat (i, "sw_if_index %d", &sw_if_index))
	    sw_if_index_set = 1;
        else if (unformat (i, "del"))
            is_add = 0;
	else if (unformat (i, "ip4-table %d", &ip4_table_index))
	    ;
	else if (unformat (i, "ip6-table %d", &ip6_table_index))
	    ;
	else if (unformat (i, "l2-table %d", &l2_table_index))
	    ;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    M(INPUT_ACL_SET_INTERFACE, input_acl_set_interface);

    mp->sw_if_index = ntohl(sw_if_index);
    mp->ip4_table_index = ntohl(ip4_table_index);
    mp->ip6_table_index = ntohl(ip6_table_index);
    mp->l2_table_index = ntohl(l2_table_index);
    mp->is_add = is_add;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int
api_ip_address_dump (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_ip_address_dump_t * mp;
    u32 sw_if_index = ~0;
    u8 sw_if_index_set = 0;
    u8 ipv4_set = 0;
    u8 ipv6_set = 0;
    f64 timeout;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "ipv4"))
            ipv4_set = 1;
        else if (unformat (i, "ipv6"))
            ipv6_set = 1;
        else
            break;
    }

    if (ipv4_set && ipv6_set) {
        errmsg ("ipv4 and ipv6 flags cannot be both set\n");
        return -99;
    }

    if ((!ipv4_set) && (!ipv6_set)) {
        errmsg ("no ipv4 nor ipv6 flag set\n");
        return -99;
    }

    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    vam->current_sw_if_index = sw_if_index;
    vam->is_ipv6 = ipv6_set;

    M(IP_ADDRESS_DUMP, ip_address_dump);
    mp->sw_if_index = ntohl(sw_if_index);
    mp->is_ipv6 = ipv6_set;
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}

static int
api_ip_dump (vat_main_t * vam)
{
    vl_api_ip_dump_t * mp;
    unformat_input_t * in = vam->input;
    int ipv4_set = 0;
    int ipv6_set = 0;
    int is_ipv6;
    f64 timeout;
    int i;

    while (unformat_check_input (in) != UNFORMAT_END_OF_INPUT) {
        if (unformat (in, "ipv4"))
            ipv4_set = 1;
        else if (unformat (in, "ipv6"))
            ipv6_set = 1;
        else
            break;
    }

    if (ipv4_set && ipv6_set) {
        errmsg ("ipv4 and ipv6 flags cannot be both set\n");
        return -99;
    }

    if ((!ipv4_set) && (!ipv6_set)) {
        errmsg ("no ipv4 nor ipv6 flag set\n");
        return -99;
    }

    is_ipv6 = ipv6_set;
    vam->is_ipv6 = is_ipv6;

    /* free old data */
    for (i = 0; i < vec_len(vam->ip_details_by_sw_if_index[is_ipv6]); i++) {
        vec_free(vam->ip_details_by_sw_if_index[is_ipv6][i].addr);
    }
    vec_free(vam->ip_details_by_sw_if_index[is_ipv6]);

    M(IP_DUMP, ip_dump);
    mp->is_ipv6 = ipv6_set;
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}

static int
api_ipsec_spd_add_del (vat_main_t * vam)
{
#if DPDK > 0
    unformat_input_t * i = vam->input;
    vl_api_ipsec_spd_add_del_t *mp;
    f64 timeout;
    u32 spd_id = ~0;
    u8 is_add = 1;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
	if (unformat (i, "spd_id %d", &spd_id))
	    ;
	else if (unformat (i, "del"))
	    is_add = 0;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }
    if (spd_id == ~0) {
        errmsg ("spd_id must be set\n");
        return -99;
    }

    M(IPSEC_SPD_ADD_DEL, ipsec_spd_add_del);

    mp->spd_id = ntohl(spd_id);
    mp->is_add = is_add;

    S; W;
    /* NOTREACHED */
    return 0;
#else
    clib_warning ("unsupported (no dpdk)");
    return -99;
#endif
}

static int
api_ipsec_interface_add_del_spd (vat_main_t * vam)
{
#if DPDK > 0
    unformat_input_t * i = vam->input;
    vl_api_ipsec_interface_add_del_spd_t *mp;
    f64 timeout;
    u32 sw_if_index;
    u8 sw_if_index_set = 0;
    u32 spd_id = (u32) ~0;
    u8 is_add = 1;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "del"))
            is_add = 0;
	else if (unformat (i, "spd_id %d", &spd_id))
	    ;
        else if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            sw_if_index_set = 1;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            sw_if_index_set = 1;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }

    }

    if (spd_id == (u32) ~0) {
        errmsg ("spd_id must be set\n");
        return -99;
    }

    if (sw_if_index_set == 0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    M(IPSEC_INTERFACE_ADD_DEL_SPD, ipsec_interface_add_del_spd);

    mp->spd_id = ntohl(spd_id);
    mp->sw_if_index = ntohl (sw_if_index);
    mp->is_add = is_add;

    S; W;
    /* NOTREACHED */
    return 0;
#else
    clib_warning ("unsupported (no dpdk)");
    return -99;
#endif
}

static int
api_ipsec_spd_add_del_entry (vat_main_t * vam)
{
#if DPDK > 0
    unformat_input_t * i = vam->input;
    vl_api_ipsec_spd_add_del_entry_t *mp;
    f64 timeout;
    u8 is_add = 1, is_outbound = 0, is_ipv6 = 0, is_ip_any = 1;
    u32 spd_id, sa_id, protocol = 0, policy = 0;
    i32 priority;
    u32 rport_start = 0, rport_stop = (u32) ~0;
    u32 lport_start = 0, lport_stop = (u32) ~0;
    ip4_address_t laddr4_start, laddr4_stop, raddr4_start, raddr4_stop;
    ip6_address_t laddr6_start, laddr6_stop, raddr6_start, raddr6_stop;

    laddr4_start.as_u32 = raddr4_start.as_u32 = 0;
    laddr4_stop.as_u32 = raddr4_stop.as_u32 = (u32) ~0;
    laddr6_start.as_u64[0] = raddr6_start.as_u64[0] = 0;
    laddr6_start.as_u64[1] = raddr6_start.as_u64[1] = 0;
    laddr6_stop.as_u64[0] = raddr6_stop.as_u64[0] = (u64) ~0;
    laddr6_stop.as_u64[1] = raddr6_stop.as_u64[1] = (u64) ~0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "del"))
            is_add = 0;
        if (unformat (i, "outbound"))
            is_outbound = 1;
        if (unformat (i, "inbound"))
            is_outbound = 0;
	else if (unformat (i, "spd_id %d", &spd_id))
	    ;
	else if (unformat (i, "sa_id %d", &sa_id))
	    ;
	else if (unformat (i, "priority %d", &priority))
	    ;
	else if (unformat (i, "protocol %d", &protocol))
	    ;
	else if (unformat (i, "lport_start %d", &lport_start))
	    ;
	else if (unformat (i, "lport_stop %d", &lport_stop))
	    ;
	else if (unformat (i, "rport_start %d", &rport_start))
	    ;
	else if (unformat (i, "rport_stop %d", &rport_stop))
	    ;
        else if (unformat (i, "laddr_start %U", unformat_ip4_address, &laddr4_start))
          {
            is_ipv6 = 0;
            is_ip_any =0;
          }
        else if (unformat (i, "laddr_stop %U", unformat_ip4_address, &laddr4_stop))
          {
            is_ipv6 = 0;
            is_ip_any = 0;
          }
        else if (unformat (i, "raddr_start %U", unformat_ip4_address, &raddr4_start))
          {
            is_ipv6 = 0;
            is_ip_any = 0;
          }
        else if (unformat (i, "raddr_stop %U", unformat_ip4_address, &raddr4_stop))
          {
            is_ipv6 = 0;
            is_ip_any = 0;
          }
        else if (unformat (i, "laddr_start %U", unformat_ip6_address, &laddr6_start))
          {
            is_ipv6 = 1;
            is_ip_any = 0;
          }
        else if (unformat (i, "laddr_stop %U", unformat_ip6_address, &laddr6_stop))
          {
            is_ipv6 = 1;
            is_ip_any = 0;
          }
        else if (unformat (i, "raddr_start %U", unformat_ip6_address, &raddr6_start))
          {
            is_ipv6 = 1;
            is_ip_any = 0;
          }
        else if (unformat (i, "raddr_stop %U", unformat_ip6_address, &raddr6_stop))
          {
            is_ipv6 = 1;
            is_ip_any = 0;
          }
        else if (unformat (i, "action %U", unformat_ipsec_policy_action, &policy))
          {
            if (policy == IPSEC_POLICY_ACTION_RESOLVE) {
                clib_warning ("unsupported action: 'resolve'");
                return -99;
            }
          }
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }

    }

    M(IPSEC_SPD_ADD_DEL_ENTRY, ipsec_spd_add_del_entry);

    mp->spd_id = ntohl(spd_id);
    mp->priority = ntohl(priority);
    mp->is_outbound = is_outbound;

    mp->is_ipv6 = is_ipv6;
    if (is_ipv6 || is_ip_any) {
        clib_memcpy (mp->remote_address_start, &raddr6_start, sizeof(ip6_address_t));
        clib_memcpy (mp->remote_address_stop, &raddr6_stop, sizeof(ip6_address_t));
        clib_memcpy (mp->local_address_start, &laddr6_start, sizeof(ip6_address_t));
        clib_memcpy (mp->local_address_stop, &laddr6_stop, sizeof(ip6_address_t));
    } else {
        clib_memcpy (mp->remote_address_start, &raddr4_start, sizeof(ip4_address_t));
        clib_memcpy (mp->remote_address_stop, &raddr4_stop, sizeof(ip4_address_t));
        clib_memcpy (mp->local_address_start, &laddr4_start, sizeof(ip4_address_t));
        clib_memcpy (mp->local_address_stop, &laddr4_stop, sizeof(ip4_address_t));
    }
    mp->protocol = (u8) protocol;
    mp->local_port_start = ntohs((u16) lport_start);
    mp->local_port_stop = ntohs((u16) lport_stop);
    mp->remote_port_start = ntohs((u16) rport_start);
    mp->remote_port_stop = ntohs((u16) rport_stop);
    mp->policy = (u8) policy;
    mp->sa_id = ntohl(sa_id);
    mp->is_add = is_add;
    mp->is_ip_any = is_ip_any;
    S; W;
    /* NOTREACHED */
    return 0;
#else
    clib_warning ("unsupported (no dpdk)");
    return -99;
#endif
}

static int
api_ipsec_sad_add_del_entry (vat_main_t * vam)
{
#if DPDK > 0
    unformat_input_t * i = vam->input;
    vl_api_ipsec_sad_add_del_entry_t *mp;
    f64 timeout;
    u32 sad_id, spi;
    u8 * ck, * ik;
    u8 is_add = 1;

    u8 protocol = IPSEC_PROTOCOL_AH;
    u8 is_tunnel = 0, is_tunnel_ipv6 = 0;
    u32 crypto_alg = 0, integ_alg = 0;
    ip4_address_t tun_src4;
    ip4_address_t tun_dst4;
    ip6_address_t tun_src6;
    ip6_address_t tun_dst6;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "del"))
            is_add = 0;
	else if (unformat (i, "sad_id %d", &sad_id))
	    ;
	else if (unformat (i, "spi %d", &spi))
	    ;
	else if (unformat (i, "esp"))
	    protocol = IPSEC_PROTOCOL_ESP;
        else if (unformat (i, "tunnel_src %U", unformat_ip4_address, &tun_src4)) {
            is_tunnel = 1;
            is_tunnel_ipv6 = 0;
        }
        else if (unformat (i, "tunnel_dst %U", unformat_ip4_address, &tun_dst4)) {
            is_tunnel = 1;
            is_tunnel_ipv6 = 0;
        }
        else if (unformat (i, "tunnel_src %U", unformat_ip6_address, &tun_src6)) {
            is_tunnel = 1;
            is_tunnel_ipv6 = 1;
        }
        else if (unformat (i, "tunnel_dst %U", unformat_ip6_address, &tun_dst6)) {
            is_tunnel = 1;
            is_tunnel_ipv6 = 1;
        }
        else if (unformat (i, "crypto_alg %U", unformat_ipsec_crypto_alg, &crypto_alg)) {
            if (crypto_alg < IPSEC_CRYPTO_ALG_AES_CBC_128 ||
                crypto_alg > IPSEC_INTEG_ALG_SHA_512_256) {
                clib_warning ("unsupported crypto-alg: '%U'",
                              format_ipsec_crypto_alg, crypto_alg);
                return -99;
            }
        }
        else if (unformat (i, "crypto_key %U", unformat_hex_string, &ck))
            ;
        else if (unformat (i, "integ_alg %U", unformat_ipsec_integ_alg, &integ_alg)) {
            if (integ_alg < IPSEC_INTEG_ALG_SHA1_96 ||
                integ_alg > IPSEC_INTEG_ALG_SHA_512_256) {
                clib_warning ("unsupported integ-alg: '%U'",
                              format_ipsec_integ_alg, integ_alg);
                return -99;
            }
        }
        else if (unformat (i, "integ_key %U", unformat_hex_string, &ik))
            ;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }

    }

    M(IPSEC_SAD_ADD_DEL_ENTRY, ipsec_sad_add_del_entry);

    mp->sad_id = ntohl(sad_id);
    mp->is_add = is_add;
    mp->protocol = protocol;
    mp->spi = ntohl(spi);
    mp->is_tunnel = is_tunnel;
    mp->is_tunnel_ipv6 = is_tunnel_ipv6;
    mp->crypto_algorithm = crypto_alg;
    mp->integrity_algorithm = integ_alg;
    mp->crypto_key_length = vec_len(ck);
    mp->integrity_key_length = vec_len(ik);

    if (mp->crypto_key_length > sizeof(mp->crypto_key))
      mp->crypto_key_length = sizeof(mp->crypto_key);

    if (mp->integrity_key_length > sizeof(mp->integrity_key))
      mp->integrity_key_length = sizeof(mp->integrity_key);

    clib_memcpy (mp->crypto_key, ck, mp->crypto_key_length);
    clib_memcpy (mp->integrity_key, ik, mp->integrity_key_length);

    if (is_tunnel) {
      if (is_tunnel_ipv6) {
        clib_memcpy (mp->tunnel_src_address, &tun_src6, sizeof(ip6_address_t));
        clib_memcpy (mp->tunnel_dst_address, &tun_dst6, sizeof(ip6_address_t));
      } else {
        clib_memcpy (mp->tunnel_src_address, &tun_src4, sizeof(ip4_address_t));
        clib_memcpy (mp->tunnel_dst_address, &tun_dst4, sizeof(ip4_address_t));
      }
    }

    S; W;
    /* NOTREACHED */
    return 0;
#else
    clib_warning ("unsupported (no dpdk)");
    return -99;
#endif
}

static int
api_ipsec_sa_set_key (vat_main_t * vam)
{
#if DPDK > 0
    unformat_input_t * i = vam->input;
    vl_api_ipsec_sa_set_key_t *mp;
    f64 timeout;
    u32 sa_id;
    u8 * ck, * ik;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "sa_id %d", &sa_id))
            ;
        else if (unformat (i, "crypto_key %U", unformat_hex_string, &ck))
            ;
        else if (unformat (i, "integ_key %U", unformat_hex_string, &ik))
            ;
        else {
            clib_warning ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    M(IPSEC_SA_SET_KEY, ipsec_set_sa_key);

    mp->sa_id = ntohl(sa_id);
    mp->crypto_key_length = vec_len(ck);
    mp->integrity_key_length = vec_len(ik);

    if (mp->crypto_key_length > sizeof(mp->crypto_key))
      mp->crypto_key_length = sizeof(mp->crypto_key);

    if (mp->integrity_key_length > sizeof(mp->integrity_key))
      mp->integrity_key_length = sizeof(mp->integrity_key);

    clib_memcpy (mp->crypto_key, ck, mp->crypto_key_length);
    clib_memcpy (mp->integrity_key, ik, mp->integrity_key_length);

    S; W;
    /* NOTREACHED */
    return 0;
#else
    clib_warning ("unsupported (no dpdk)");
    return -99;
#endif
}

static int
api_ikev2_profile_add_del (vat_main_t * vam)
{
#if DPDK > 0
    unformat_input_t * i = vam->input;
    vl_api_ikev2_profile_add_del_t * mp;
    f64 timeout;
    u8 is_add = 1;
    u8 * name = 0;

    const char * valid_chars = "a-zA-Z0-9_";

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "del"))
            is_add = 0;
        else if (unformat (i, "name %U", unformat_token, valid_chars, &name))
            vec_add1 (name, 0);
        else {
            errmsg ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (!vec_len (name)) {
        errmsg ("profile name must be specified");
        return -99;
    }

    if (vec_len (name) > 64) {
        errmsg ("profile name too long");
        return -99;
    }

    M(IKEV2_PROFILE_ADD_DEL, ikev2_profile_add_del);

    clib_memcpy(mp->name, name, vec_len (name));
    mp->is_add = is_add;
    vec_free (name);

    S; W;
    /* NOTREACHED */
    return 0;
#else
    clib_warning ("unsupported (no dpdk)");
    return -99;
#endif
}

static int
api_ikev2_profile_set_auth (vat_main_t * vam)
{
#if DPDK > 0
    unformat_input_t * i = vam->input;
    vl_api_ikev2_profile_set_auth_t * mp;
    f64 timeout;
    u8 * name = 0;
    u8 * data = 0;
    u32 auth_method = 0;
    u8 is_hex = 0;

    const char * valid_chars = "a-zA-Z0-9_";

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "name %U", unformat_token, valid_chars, &name))
            vec_add1 (name, 0);
        else if (unformat (i, "auth_method %U",
                           unformat_ikev2_auth_method, &auth_method))
            ;
        else if (unformat (i, "auth_data 0x%U", unformat_hex_string, &data))
            is_hex = 1;
        else if (unformat (i, "auth_data %v", &data))
            ;
        else {
            errmsg ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (!vec_len (name)) {
        errmsg ("profile name must be specified");
        return -99;
    }

    if (vec_len (name) > 64) {
        errmsg ("profile name too long");
        return -99;
    }

    if (!vec_len(data)) {
        errmsg ("auth_data must be specified");
        return -99;
    }

    if (!auth_method) {
        errmsg ("auth_method must be specified");
        return -99;
    }

    M(IKEV2_PROFILE_SET_AUTH, ikev2_profile_set_auth);

    mp->is_hex = is_hex;
    mp->auth_method = (u8) auth_method;
    mp->data_len = vec_len (data);
    clib_memcpy (mp->name, name, vec_len (name));
    clib_memcpy (mp->data, data, vec_len (data));
    vec_free (name);
    vec_free (data);

    S; W;
    /* NOTREACHED */
    return 0;
#else
    clib_warning ("unsupported (no dpdk)");
    return -99;
#endif
}

static int
api_ikev2_profile_set_id (vat_main_t * vam)
{
#if DPDK > 0
    unformat_input_t * i = vam->input;
    vl_api_ikev2_profile_set_id_t * mp;
    f64 timeout;
    u8 * name = 0;
    u8 * data = 0;
    u8 is_local = 0;
    u32 id_type = 0;
    ip4_address_t ip4;

    const char * valid_chars = "a-zA-Z0-9_";

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "name %U", unformat_token, valid_chars, &name))
            vec_add1 (name, 0);
        else if (unformat (i, "id_type %U",
                           unformat_ikev2_id_type, &id_type))
            ;
        else if (unformat (i, "id_data %U", unformat_ip4_address, &ip4))
          {
            data = vec_new(u8, 4);
            clib_memcpy(data, ip4.as_u8, 4);
          }
        else if (unformat (i, "id_data 0x%U", unformat_hex_string, &data))
            ;
        else if (unformat (i, "id_data %v", &data))
            ;
        else if (unformat (i, "local"))
            is_local = 1;
        else if (unformat (i, "remote"))
            is_local = 0;
        else {
            errmsg ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (!vec_len (name)) {
        errmsg ("profile name must be specified");
        return -99;
    }

    if (vec_len (name) > 64) {
        errmsg ("profile name too long");
        return -99;
    }

    if (!vec_len(data)) {
        errmsg ("id_data must be specified");
        return -99;
    }

    if (!id_type) {
        errmsg ("id_type must be specified");
        return -99;
    }

    M(IKEV2_PROFILE_SET_ID, ikev2_profile_set_id);

    mp->is_local = is_local;
    mp->id_type = (u8) id_type;
    mp->data_len = vec_len (data);
    clib_memcpy (mp->name, name, vec_len (name));
    clib_memcpy (mp->data, data, vec_len (data));
    vec_free (name);
    vec_free (data);

    S; W;
    /* NOTREACHED */
    return 0;
#else
    clib_warning ("unsupported (no dpdk)");
    return -99;
#endif
}

static int
api_ikev2_profile_set_ts (vat_main_t * vam)
{
#if DPDK > 0
    unformat_input_t * i = vam->input;
    vl_api_ikev2_profile_set_ts_t * mp;
    f64 timeout;
    u8 * name = 0;
    u8 is_local = 0;
    u32 proto = 0, start_port = 0, end_port = (u32) ~0;
    ip4_address_t start_addr, end_addr;

    const char * valid_chars = "a-zA-Z0-9_";

    start_addr.as_u32 = 0;
    end_addr.as_u32 = (u32) ~0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "name %U", unformat_token, valid_chars, &name))
            vec_add1 (name, 0);
	else if (unformat (i, "protocol %d", &proto))
	    ;
	else if (unformat (i, "start_port %d", &start_port))
	    ;
	else if (unformat (i, "end_port %d", &end_port))
	    ;
        else if (unformat (i, "start_addr %U", unformat_ip4_address, &start_addr))
            ;
        else if (unformat (i, "end_addr %U", unformat_ip4_address, &end_addr))
            ;
        else if (unformat (i, "local"))
            is_local = 1;
        else if (unformat (i, "remote"))
            is_local = 0;
        else {
            errmsg ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (!vec_len (name)) {
        errmsg ("profile name must be specified");
        return -99;
    }

    if (vec_len (name) > 64) {
        errmsg ("profile name too long");
        return -99;
    }

    M(IKEV2_PROFILE_SET_TS, ikev2_profile_set_ts);

    mp->is_local = is_local;
    mp->proto = (u8) proto;
    mp->start_port = (u16) start_port;
    mp->end_port = (u16) end_port;
    mp->start_addr = start_addr.as_u32;
    mp->end_addr = end_addr.as_u32;
    clib_memcpy (mp->name, name, vec_len (name));
    vec_free (name);

    S; W;
    /* NOTREACHED */
    return 0;
#else
    clib_warning ("unsupported (no dpdk)");
    return -99;
#endif
}

static int
api_ikev2_set_local_key (vat_main_t * vam)
{
#if DPDK > 0
    unformat_input_t * i = vam->input;
    vl_api_ikev2_set_local_key_t * mp;
    f64 timeout;
    u8 * file = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "file %v", &file))
            vec_add1 (file, 0);
        else {
            errmsg ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (!vec_len (file)) {
        errmsg ("RSA key file must be specified");
        return -99;
    }

    if (vec_len (file) > 256) {
        errmsg ("file name too long");
        return -99;
    }

    M(IKEV2_SET_LOCAL_KEY, ikev2_set_local_key);

    clib_memcpy (mp->key_file, file, vec_len (file));
    vec_free (file);

    S; W;
    /* NOTREACHED */
    return 0;
#else
    clib_warning ("unsupported (no dpdk)");
    return -99;
#endif
}

/*
 * MAP
 */
static int api_map_add_domain (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_map_add_domain_t *mp;
  f64 timeout;

  ip4_address_t ip4_prefix;
  ip6_address_t ip6_prefix;
  ip6_address_t ip6_src;
  u32 num_m_args = 0;
  u32 ip6_prefix_len, ip4_prefix_len, ea_bits_len, psid_offset,
    psid_length;
  u8 is_translation = 0;
  u32 mtu = 0;
  u8 ip6_src_len = 128;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
    if (unformat (i, "ip4-pfx %U/%d", unformat_ip4_address,
		  &ip4_prefix, &ip4_prefix_len))
      num_m_args++;
    else if (unformat (i, "ip6-pfx %U/%d", unformat_ip6_address,
		       &ip6_prefix, &ip6_prefix_len))
      num_m_args++;
    else if (unformat (i, "ip6-src %U/%d", unformat_ip6_address, &ip6_src, &ip6_src_len))
      num_m_args++;
    else if (unformat (i, "ip6-src %U", unformat_ip6_address, &ip6_src))
      num_m_args++;
    else if (unformat (i, "ea-bits-len %d", &ea_bits_len))
      num_m_args++;
    else if (unformat (i, "psid-offset %d", &psid_offset))
      num_m_args++;
    else if (unformat (i, "psid-len %d", &psid_length))
      num_m_args++;
    else if (unformat (i, "mtu %d", &mtu))
      num_m_args++;
    else if (unformat (i, "map-t"))
      is_translation = 1;
    else {
      clib_warning ("parse error '%U'", format_unformat_error, i);
      return -99;
    }
  }

  if (num_m_args != 6) {
    errmsg("mandatory argument(s) missing\n");
    return -99;
  }

  /* Construct the API message */
  M(MAP_ADD_DOMAIN, map_add_domain);

  clib_memcpy(mp->ip4_prefix, &ip4_prefix, sizeof(ip4_prefix));
  mp->ip4_prefix_len = ip4_prefix_len;

  clib_memcpy(mp->ip6_prefix, &ip6_prefix, sizeof(ip6_prefix));
  mp->ip6_prefix_len = ip6_prefix_len;

  clib_memcpy(mp->ip6_src, &ip6_src, sizeof(ip6_src));
  mp->ip6_src_prefix_len = ip6_src_len;

  mp->ea_bits_len = ea_bits_len;
  mp->psid_offset = psid_offset;
  mp->psid_length = psid_length;
  mp->is_translation = is_translation;
  mp->mtu = htons(mtu);

  /* send it... */
  S;

  /* Wait for a reply, return good/bad news  */
  W;
}

static int api_map_del_domain (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_map_del_domain_t *mp;
  f64 timeout;

  u32 num_m_args = 0;
  u32 index;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
    if (unformat (i, "index %d", &index))
      num_m_args++;
    else {
      clib_warning ("parse error '%U'", format_unformat_error, i);
      return -99;
    }
  }

  if (num_m_args != 1) {
    errmsg("mandatory argument(s) missing\n");
    return -99;
  }

  /* Construct the API message */
  M(MAP_DEL_DOMAIN, map_del_domain);

  mp->index = ntohl(index);

  /* send it... */
  S;

  /* Wait for a reply, return good/bad news  */
  W;
}

static int api_map_add_del_rule (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_map_add_del_rule_t *mp;
  f64 timeout;
  u8 is_add = 1;
  ip6_address_t ip6_dst;
  u32 num_m_args = 0, index, psid;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
    if (unformat (i, "index %d", &index))
      num_m_args++;
    else if (unformat (i, "psid %d", &psid))
      num_m_args++;
    else if (unformat (i, "dst %U", unformat_ip6_address, &ip6_dst))
      num_m_args++;
    else if (unformat (i, "del")) {
      is_add = 0;
    } else {
      clib_warning ("parse error '%U'", format_unformat_error, i);
      return -99;
    }
  }

  /* Construct the API message */
  M(MAP_ADD_DEL_RULE, map_add_del_rule);

  mp->index = ntohl(index);
  mp->is_add = is_add;
  clib_memcpy(mp->ip6_dst, &ip6_dst, sizeof(ip6_dst));
  mp->psid = ntohs(psid);

  /* send it... */
  S;

  /* Wait for a reply, return good/bad news  */
  W;
}

static int api_map_domain_dump (vat_main_t * vam)
{
    vl_api_map_domain_dump_t *mp;
    f64 timeout;

    /* Construct the API message */
    M(MAP_DOMAIN_DUMP, map_domain_dump);

    /* send it... */
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}

static int api_map_rule_dump (vat_main_t * vam)
{
    unformat_input_t *i = vam->input;
    vl_api_map_rule_dump_t *mp;
    f64 timeout;
    u32 domain_index = ~0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "index %u", &domain_index))
            ;
        else
            break;
    }

    if (domain_index == ~0) {
        clib_warning("parse error: domain index expected");
        return -99;
    }

    /* Construct the API message */
    M(MAP_RULE_DUMP, map_rule_dump);

    mp->domain_index = htonl(domain_index);

    /* send it... */
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}

static void vl_api_map_add_domain_reply_t_handler
(vl_api_map_add_domain_reply_t * mp)
{
  vat_main_t * vam = &vat_main;
  i32 retval = ntohl(mp->retval);

  if (vam->async_mode) {
      vam->async_errors += (retval < 0);
  } else {
      vam->retval = retval;
      vam->result_ready = 1;
  }
}

static void vl_api_map_add_domain_reply_t_handler_json
(vl_api_map_add_domain_reply_t * mp)
{
  vat_main_t * vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object(&node);
  vat_json_object_add_int(&node, "retval", ntohl(mp->retval));
  vat_json_object_add_uint(&node, "index", ntohl(mp->index));

  vat_json_print(vam->ofp, &node);
  vat_json_free(&node);

  vam->retval = ntohl(mp->retval);
  vam->result_ready = 1;
}

static int
api_get_first_msg_id (vat_main_t * vam)
{
    vl_api_get_first_msg_id_t * mp;
    f64 timeout;
    unformat_input_t * i = vam->input;
    u8 * name;
    u8 name_set = 0;
    
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "client %s", &name))
            name_set = 1;
        else 
            break;
    }

    if (name_set == 0) {
        errmsg ("missing client name\n");
        return -99;
    }
    vec_add1 (name, 0);

    if (vec_len (name) > 63) {
        errmsg ("client name too long\n");
        return -99;
    }

    M(GET_FIRST_MSG_ID, get_first_msg_id);
    clib_memcpy (mp->name, name, vec_len(name));
    S; W;
    /* NOTREACHED */
    return 0;
}

static int api_cop_interface_enable_disable (vat_main_t * vam)
{
    unformat_input_t * line_input = vam->input;
    vl_api_cop_interface_enable_disable_t * mp;
    f64 timeout;
    u32 sw_if_index = ~0;
    u8 enable_disable = 1;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (line_input, "disable"))
            enable_disable = 0;
        if (unformat (line_input, "enable"))
            enable_disable = 1;
        else if (unformat (line_input, "%U", unformat_sw_if_index,
                           vam, &sw_if_index))
            ;
        else if (unformat (line_input, "sw_if_index %d", &sw_if_index))
            ;
        else
            break;
    }
        
    if (sw_if_index == ~0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    /* Construct the API message */
    M(COP_INTERFACE_ENABLE_DISABLE, cop_interface_enable_disable);
    mp->sw_if_index = ntohl(sw_if_index);
    mp->enable_disable = enable_disable;

    /* send it... */
    S;
    /* Wait for the reply */
    W;
}

static int api_cop_whitelist_enable_disable (vat_main_t * vam)
{
    unformat_input_t * line_input = vam->input;
    vl_api_cop_whitelist_enable_disable_t * mp;
    f64 timeout;
    u32 sw_if_index = ~0;
    u8 ip4=0, ip6=0, default_cop=0;
    u32 fib_id;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (line_input, "ip4"))
            ip4 = 1;
        else if (unformat (line_input, "ip6"))
            ip6 = 1;
        else if (unformat (line_input, "default"))
            default_cop = 1;
        else if (unformat (line_input, "%U", unformat_sw_if_index,
                           vam, &sw_if_index))
            ;
        else if (unformat (line_input, "sw_if_index %d", &sw_if_index))
            ;
        else if (unformat (line_input, "fib-id %d", &fib_id))
            ;
        else
            break;
    }
        
    if (sw_if_index == ~0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    /* Construct the API message */
    M(COP_WHITELIST_ENABLE_DISABLE, cop_whitelist_enable_disable);
    mp->sw_if_index = ntohl(sw_if_index);
    mp->fib_id = ntohl(fib_id);
    mp->ip4 = ip4;
    mp->ip6 = ip6;
    mp->default_cop = default_cop;

    /* send it... */
    S;
    /* Wait for the reply */
    W;
}

static int api_get_node_graph (vat_main_t * vam)
{
    vl_api_get_node_graph_t * mp;
    f64 timeout;

    M(GET_NODE_GRAPH, get_node_graph);

    /* send it... */
    S;
    /* Wait for the reply */
    W;
}

static int
api_lisp_add_del_locator_set(vat_main_t * vam)
{
    unformat_input_t * input = vam->input;
    vl_api_lisp_add_del_locator_set_t *mp;
    f64 timeout = ~0;
    u8  is_add = 1;
    u8 *locator_set_name = NULL;
    u8  locator_set_name_set = 0;

    /* Parse args required to build the message */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "del")) {
            is_add = 0;
        } else if (unformat(input, "locator-set %s", &locator_set_name)) {
            locator_set_name_set = 1;
        } else
            break;
    }

    if (locator_set_name_set == 0) {
        errmsg ("missing locator-set name");
        return -99;
    }

    if (vec_len(locator_set_name) > 64) {
        errmsg ("locator-set name too long\n");
        vec_free(locator_set_name);
        return -99;
    }
    vec_add1(locator_set_name, 0);

    /* Construct the API message */
    M(LISP_ADD_DEL_LOCATOR_SET, lisp_add_del_locator_set);

    mp->is_add = is_add;
    clib_memcpy(mp->locator_set_name, locator_set_name,
           vec_len(locator_set_name));
    vec_free(locator_set_name);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

static int
api_lisp_add_del_locator(vat_main_t * vam)
{
    unformat_input_t * input = vam->input;
    vl_api_lisp_add_del_locator_t *mp;
    f64 timeout = ~0;
    u32 tmp_if_index = ~0;
    u32 sw_if_index = ~0;
    u8  sw_if_index_set = 0;
    u8  sw_if_index_if_name_set = 0;
    u32  priority = ~0;
    u8  priority_set = 0;
    u32  weight = ~0;
    u8  weight_set = 0;
    u8  is_add = 1;
    u8  *locator_set_name = NULL;
    u8  locator_set_name_set = 0;

    /* Parse args required to build the message */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "del")) {
            is_add = 0;
        } else if (unformat(input, "locator-set %s", &locator_set_name)) {
            locator_set_name_set = 1;
        } else if (unformat(input, "iface %U", unformat_sw_if_index, vam,
            &tmp_if_index)) {
            sw_if_index_if_name_set = 1;
            sw_if_index = tmp_if_index;
        } else if (unformat(input,"sw_if_index %d", &tmp_if_index)) {
            sw_if_index_set = 1;
            sw_if_index = tmp_if_index;
        } else if (unformat(input, "p %d", &priority)) {
            priority_set = 1;
        } else if (unformat(input, "w %d", &weight)) {
            weight_set = 1;
        } else
            break;
    }

    if (locator_set_name_set == 0) {
        errmsg ("missing locator-set name");
        return -99;
    }

    if (sw_if_index_set == 0 && sw_if_index_if_name_set == 0) {
        errmsg ("missing sw_if_index");
        vec_free(locator_set_name);
        return -99;
    }

    if (sw_if_index_set != 0 && sw_if_index_if_name_set != 0) {
        errmsg ("cannot use both params interface name and sw_if_index");
        vec_free(locator_set_name);
        return -99;
    }

    if (priority_set == 0) {
        errmsg ("missing locator-set priority\n");
        vec_free(locator_set_name);
        return -99;
    }

    if (weight_set == 0) {
        errmsg ("missing locator-set weight\n");
        vec_free(locator_set_name);
        return -99;
    }

    if (vec_len(locator_set_name) > 64) {
        errmsg ("locator-set name too long\n");
        vec_free(locator_set_name);
        return -99;
    }
    vec_add1(locator_set_name, 0);

    /* Construct the API message */
    M(LISP_ADD_DEL_LOCATOR, lisp_add_del_locator);

    mp->is_add = is_add;
    mp->sw_if_index = ntohl(sw_if_index);
    mp->priority = priority;
    mp->weight = weight;
    clib_memcpy(mp->locator_set_name, locator_set_name,
           vec_len(locator_set_name));
    vec_free(locator_set_name);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

static int
api_lisp_add_del_local_eid(vat_main_t * vam)
{
    unformat_input_t * input = vam->input;
    vl_api_lisp_add_del_local_eid_t *mp;
    f64 timeout = ~0;
    u8 is_add = 1;
    u8 eidv4_set = 0;
    u8 eidv6_set = 0;
    u8 eid_type = (u8)~0;
    ip4_address_t eidv4;
    ip6_address_t eidv6;
    u8 mac[6] = {0};
    u32 tmp_eid_lenght = ~0;
    u8 eid_lenght = ~0;
    u8 *locator_set_name = NULL;
    u8 locator_set_name_set = 0;
    u32 vni = 0;

    /* Parse args required to build the message */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "del")) {
            is_add = 0;
        } else if (unformat(input, "vni %d", &vni)) {
            ;
        } else if (unformat(input, "eid %U/%d", unformat_ip4_address,
            &eidv4, &tmp_eid_lenght)) {
            eid_lenght = tmp_eid_lenght;
            eidv4_set = 1;
            eid_type = 0; /* ipv4 type */
        } else if (unformat(input, "eid %U/%d", unformat_ip6_address,
            &eidv6, &tmp_eid_lenght)) {
            eid_lenght = tmp_eid_lenght;
            eidv6_set = 1;
            eid_type = 1; /* ipv6 type */
        } else if (unformat(input, "eid %U", unformat_ethernet_address, mac)) {
            eid_type = 2; /* mac type */
        } else if (unformat(input, "locator-set %s", &locator_set_name)) {
            locator_set_name_set = 1;
        } else
            break;
    }

    if (locator_set_name_set == 0) {
        errmsg ("missing locator-set name\n");
        return -99;
    }

    if ((u8)~0 == eid_type) {
        errmsg ("EID address not set!");
        vec_free(locator_set_name);
        return -99;
    }

    if (vec_len(locator_set_name) > 64) {
        errmsg ("locator-set name too long\n");
        vec_free(locator_set_name);
        return -99;
    }
    vec_add1(locator_set_name, 0);

    if (eidv4_set && eidv6_set) {
        errmsg ("both eid v4 and v6 addresses set\n");
        vec_free(locator_set_name);
        return -99;
    }

    if (eidv4_set && eid_lenght > 32) {
        errmsg ("eid prefix to big\n");
        vec_free(locator_set_name);
        return -99;
    }

    if (eidv6_set && eid_lenght > 128) {
        errmsg ("eid prefix to big\n");
        vec_free(locator_set_name);
        return -99;
    }

    /* Construct the API message */
    M(LISP_ADD_DEL_LOCAL_EID, lisp_add_del_local_eid);

    mp->is_add = is_add;
    switch (eid_type) {
    case 0: /* ipv4 */
      clib_memcpy (mp->eid, &eidv4, sizeof(eidv4));
      break;
    case 1: /* ipv6 */
      clib_memcpy (mp->eid, &eidv6, sizeof(eidv6));
      break;
    case 2: /* mac */
      clib_memcpy (mp->eid, mac, 6);
      break;
    }
    mp->eid_type = eid_type;
    mp->prefix_len = eid_lenght;
    mp->vni = clib_host_to_net_u32(vni);
    clib_memcpy(mp->locator_set_name, locator_set_name,
           vec_len(locator_set_name));
    vec_free(locator_set_name);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

static int
api_lisp_gpe_add_del_fwd_entry(vat_main_t * vam)
{
    unformat_input_t * input = vam->input;
    vl_api_lisp_gpe_add_del_fwd_entry_t *mp;
    f64 timeout = ~0;
    u8 is_add = 1;
    u8 eidv4_set = 0, slocv4_set = 0, dlocv4_set = 0;
    u8 eidv6_set = 0, slocv6_set = 0, dlocv6_set = 0;
    ip4_address_t eidv4, slocv4, dlocv4;
    ip6_address_t eidv6, slocv6, dlocv6;
    u32 tmp_eid_lenght = ~0;
    u8 eid_lenght = ~0;

    /* Parse args required to build the message */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "del")) {
            is_add = 0;
        } else if (unformat(input, "eid %U/%d", unformat_ip4_address,
                            &eidv4, &tmp_eid_lenght)) {
            eid_lenght = tmp_eid_lenght;
            eidv4_set = 1;
        } else if (unformat(input, "eid %U/%d", unformat_ip6_address,
                            &eidv6, &tmp_eid_lenght)) {
            eid_lenght = tmp_eid_lenght;
            eidv6_set = 1;
        } else if (unformat(input, "sloc %U", unformat_ip4_address, &slocv4)) {
            slocv4_set = 1;
        } else if (unformat(input, "sloc %U", unformat_ip6_address, &slocv6)) {
            slocv6_set = 1;
        } else if (unformat(input, "dloc %U", unformat_ip4_address, &dlocv4)) {
            dlocv4_set = 1;
        } else if (unformat(input, "dloc %U", unformat_ip6_address, &dlocv6)) {
            dlocv6_set = 1;
        } else
            break;
    }

    if (eidv4_set && eidv6_set) {
        errmsg ("both eid v4 and v6 addresses set\n");
        return -99;
    }

    if (!eidv4_set && !eidv6_set) {
        errmsg ("eid addresses not set\n");
        return -99;
    }

    if (slocv4_set && slocv6_set) {
        errmsg ("both source v4 and v6 addresses set\n");
        return -99;
    }

    if (!slocv4_set && !slocv6_set) {
        errmsg ("source addresses not set\n");
        return -99;
    }

    if (dlocv4_set && dlocv6_set) {
        errmsg ("both destination v4 and v6 addresses set\n");
        return -99;
    }

    if (dlocv4_set && dlocv6_set) {
        errmsg ("destination addresses not set\n");
        return -99;
    }

    if (!(slocv4_set == dlocv4_set && slocv6_set == dlocv6_set)) {
        errmsg ("mixing type of source and destination address\n");
        return -99;
    }

    /* Construct the API message */
    M(LISP_GPE_ADD_DEL_FWD_ENTRY, lisp_gpe_add_del_fwd_entry);

    mp->is_add = is_add;
    if (eidv6_set) {
        mp->eid_is_ipv6 = 1;
        clib_memcpy(mp->eid_ip_address, &eidv6, sizeof(eidv6));
    } else {
        mp->eid_is_ipv6 = 0;
        clib_memcpy(mp->eid_ip_address, &eidv4, sizeof(eidv4));
    }
    mp->eid_prefix_len = eid_lenght;
    if (slocv6_set) {
        mp->address_is_ipv6 = 1;
        clib_memcpy(mp->source_ip_address, &slocv6, sizeof(slocv6));
        clib_memcpy(mp->destination_ip_address, &dlocv6, sizeof(dlocv6));
    } else {
        mp->address_is_ipv6 = 0;
        clib_memcpy(mp->source_ip_address, &slocv4, sizeof(slocv4));
        clib_memcpy(mp->destination_ip_address, &dlocv4, sizeof(dlocv4));
    }

    /* send it... */
    S;

    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

static int
api_lisp_add_del_map_resolver(vat_main_t * vam)
{
    unformat_input_t * input = vam->input;
    vl_api_lisp_add_del_map_resolver_t *mp;
    f64 timeout = ~0;
    u8 is_add = 1;
    u8 ipv4_set = 0;
    u8 ipv6_set = 0;
    ip4_address_t ipv4;
    ip6_address_t ipv6;

    /* Parse args required to build the message */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "del")) {
            is_add = 0;
        } else if (unformat(input, "%U", unformat_ip4_address, &ipv4)) {
            ipv4_set = 1;
        } else if (unformat(input, "%U", unformat_ip6_address, &ipv6)) {
            ipv6_set = 1;
        } else
            break;
    }

    if (ipv4_set && ipv6_set) {
        errmsg ("both eid v4 and v6 addresses set\n");
        return -99;
    }

    if (!ipv4_set && !ipv6_set) {
        errmsg ("eid addresses not set\n");
        return -99;
    }

    /* Construct the API message */
    M(LISP_ADD_DEL_MAP_RESOLVER, lisp_add_del_map_resolver);

    mp->is_add = is_add;
    if (ipv6_set) {
        mp->is_ipv6 = 1;
        clib_memcpy(mp->ip_address, &ipv6, sizeof(ipv6));
    } else {
        mp->is_ipv6 = 0;
        clib_memcpy(mp->ip_address, &ipv4, sizeof(ipv4));
    }

    /* send it... */
    S;

    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

static int
api_lisp_gpe_enable_disable (vat_main_t * vam)
{
  unformat_input_t * input = vam->input;
  vl_api_lisp_gpe_enable_disable_t *mp;
  f64 timeout = ~0;
  u8 is_set = 0;
  u8 is_en = 1;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
      if (unformat(input, "enable")) {
          is_set = 1;
          is_en = 1;
      } else if (unformat(input, "disable")) {
          is_set = 1;
          is_en = 0;
      } else
          break;
  }

  if (is_set == 0) {
      errmsg("Value not set\n");
      return -99;
  }

  /* Construct the API message */
  M(LISP_GPE_ENABLE_DISABLE, lisp_gpe_enable_disable);

  mp->is_en = is_en;

  /* send it... */
  S;

  /* Wait for a reply... */
  W;

  /* NOTREACHED */
  return 0;
}

static int
api_lisp_enable_disable (vat_main_t * vam)
{
  unformat_input_t * input = vam->input;
  vl_api_lisp_enable_disable_t *mp;
  f64 timeout = ~0;
  u8 is_set = 0;
  u8 is_en = 0;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
        {
          is_set = 1;
          is_en = 1;
        }
      else if (unformat (input, "disable"))
        {
          is_set = 1;
        }
      else
          break;
    }

  if (!is_set)
    {
      errmsg ("Value not set\n");
      return -99;
    }

  /* Construct the API message */
  M(LISP_ENABLE_DISABLE, lisp_enable_disable);

  mp->is_en = is_en;

  /* send it... */
  S;

  /* Wait for a reply... */
  W;

  /* NOTREACHED */
  return 0;
}

/** Used for transferring locators via VPP API */
typedef CLIB_PACKED(struct
{
    u8 is_ip4; /**< is locator an IPv4 address? */
    u8 priority; /**< locator priority */
    u8 weight;   /**< locator weight */
    u8 addr[16]; /**< IPv4/IPv6 address */
}) rloc_t;

/**
 * Enable/disable LISP proxy ITR.
 *
 * @param vam vpp API test context
 * @return return code
 */
static int
api_lisp_pitr_set_locator_set (vat_main_t * vam)
{
  f64 timeout = ~0;
  u8 ls_name_set = 0;
  unformat_input_t * input = vam->input;
  vl_api_lisp_pitr_set_locator_set_t * mp;
  u8 is_add = 1;
  u8 * ls_name = 0;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
        is_add = 0;
      else if (unformat (input, "locator-set %s", &ls_name))
        ls_name_set = 1;
      else
        {
          errmsg ("parse error '%U'", format_unformat_error, input);
          return -99;
        }
    }

  if (!ls_name_set)
    {
      errmsg ("locator-set name not set!");
      return -99;
    }

  M(LISP_PITR_SET_LOCATOR_SET, lisp_pitr_set_locator_set);

  mp->is_add = is_add;
  clib_memcpy (mp->ls_name, ls_name, vec_len (ls_name));
  vec_free (ls_name);

  /* send */
  S;

  /* wait for reply */
  W;

  /* notreached*/
  return 0;
}

static int
api_show_lisp_pitr (vat_main_t * vam)
{
    vl_api_show_lisp_pitr_t *mp;
    f64 timeout = ~0;

    if (!vam->json_output) {
        fformat(vam->ofp, "%=20s\n",
                "lisp status:");
    }

    M(SHOW_LISP_PITR, show_lisp_pitr);
    /* send it... */
    S;

    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

/**
 * Add/delete mapping between vni and vrf
 */
static int
api_lisp_eid_table_add_del_map (vat_main_t * vam)
{
  f64 timeout = ~0;
  unformat_input_t * input = vam->input;
  vl_api_lisp_eid_table_add_del_map_t *mp;
  u8 is_add = 1, vni_set = 0, vrf_set = 0;
  u32 vni, vrf;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
        is_add = 0;
      else if (unformat(input, "vrf %d", &vrf))
        vrf_set = 1;
      else if (unformat(input, "vni %d", &vni))
        vni_set = 1;
      else
        break;
    }

  if (!vni_set || !vrf_set)
    {
      errmsg ("missing arguments!");
      return -99;
    }

  M(LISP_EID_TABLE_ADD_DEL_MAP, lisp_eid_table_add_del_map);

  mp->is_add = is_add;
  mp->vni = htonl (vni);
  mp->vrf = htonl (vrf);

  /* send */
  S;

  /* wait for reply */
  W;

  /* notreached*/
  return 0;
}

/**
 * Add/del remote mapping to/from LISP control plane
 *
 * @param vam vpp API test context
 * @return return code
 */
static int
api_lisp_add_del_remote_mapping (vat_main_t * vam)
{
    unformat_input_t * input = vam->input;
    vl_api_lisp_add_del_remote_mapping_t *mp;
    f64 timeout = ~0;
    u32 vni = 0;
    ip4_address_t seid4, deid4, rloc4;
    ip6_address_t seid6, deid6, rloc6;
    u8 deid_mac[6] = {0};
    u8 seid_mac[6] = {0};
    u8 deid_type, seid_type;
    u32 seid_len = 0, deid_len = 0, len;
    u8 is_add = 1, del_all = 0;
    u32 action = ~0, p, w;
    rloc_t * rlocs = 0, rloc, * curr_rloc = 0;

    seid_type = deid_type =  (u8)~0;

    /* Parse args required to build the message */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "del-all")) {
            del_all = 1;
        } else if (unformat(input, "del")) {
            is_add = 0;
        } else if (unformat(input, "add")) {
            is_add = 1;
        } else if (unformat(input, "deid %U/%d", unformat_ip4_address,
                            &deid4, &len)) {
            deid_type = 0; /* ipv4 */
            deid_len = len;
        } else if (unformat(input, "deid %U/%d", unformat_ip6_address,
                            &deid6, &len)) {
            deid_type = 1; /* ipv6 */
            deid_len = len;
        } else if (unformat(input, "deid %U", unformat_ethernet_address,
                            deid_mac)) {
            deid_type = 2; /* mac */
        } else if (unformat(input, "seid %U/%d", unformat_ip4_address,
                            &seid4, &len)) {
            seid_type = 0; /* ipv4 */
            seid_len = len;
        } else if (unformat(input, "seid %U/%d", unformat_ip6_address,
                            &seid6, &len)) {
            seid_type = 1; /* ipv6 */
            seid_len = len;
        } else if (unformat(input, "seid %U", unformat_ethernet_address,
                            seid_mac)) {
            seid_type = 2; /* mac */
        } else if (unformat(input, "vni %d", &vni)) {
            ;
        } else if (unformat(input, "p %d w %d", &p, &w)) {
            if (!curr_rloc) {
              errmsg ("No RLOC configured for setting priority/weight!");
              return -99;
            }
            curr_rloc->priority = p;
            curr_rloc->weight = w;
        } else if (unformat(input, "rloc %U", unformat_ip4_address, &rloc4)) {
            rloc.is_ip4 = 1;
            clib_memcpy (&rloc.addr, &rloc4, sizeof (rloc4));
            vec_add1 (rlocs, rloc);
            curr_rloc = &rlocs[vec_len (rlocs) - 1];
        } else if (unformat(input, "rloc %U", unformat_ip6_address, &rloc6)) {
            rloc.is_ip4 = 0;
            clib_memcpy (&rloc.addr, &rloc6, sizeof (rloc6));
            vec_add1 (rlocs, rloc);
            curr_rloc = &rlocs[vec_len (rlocs) - 1];
        } else if (unformat(input, "action %d", &action)) {
            ;
        } else {
            clib_warning ("parse error '%U'", format_unformat_error, input);
            return -99;
        }
    }

    if ((u8)~0 == deid_type) {
        errmsg ("missing params!");
        return -99;
    }

    if (seid_type != deid_type) {
        errmsg ("source and destination EIDs are of different types!");
        return -99;
    }

    if (is_add && (~0 == action)
        && 0 == vec_len (rlocs)) {
          errmsg ("no action set for negative map-reply!");
          return -99;
    }

    M(LISP_ADD_DEL_REMOTE_MAPPING, lisp_add_del_remote_mapping);
    mp->is_add = is_add;
    mp->vni = htonl (vni);
    mp->seid_len = seid_len;
    mp->action = (u8) action;
    mp->deid_len = deid_len;
    mp->del_all = del_all;
    mp->eid_type = deid_type;

    switch (mp->eid_type) {
    case 0:
        clib_memcpy (mp->seid, &seid4, sizeof (seid4));
        clib_memcpy (mp->deid, &deid4, sizeof (deid4));
        break;
    case 1:
        clib_memcpy (mp->seid, &seid6, sizeof (seid6));
        clib_memcpy (mp->deid, &deid6, sizeof (deid6));
        break;
    case 2:
        clib_memcpy (mp->seid, seid_mac, 6);
        clib_memcpy (mp->deid, deid_mac, 6);
        break;
    default:
        errmsg ("unknown EID type %d!", mp->eid_type);
        return 0;
    }

    mp->rloc_num = vec_len (rlocs);
    clib_memcpy (mp->rlocs, rlocs, (sizeof (rloc_t) * vec_len (rlocs)));
    vec_free (rlocs);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

/**
 * Add/del LISP adjacency. Saves mapping in LISP control plane and updates
 * forwarding entries in data-plane accordingly.
 *
 * @param vam vpp API test context
 * @return return code
 */
static int
api_lisp_add_del_adjacency (vat_main_t * vam)
{
    unformat_input_t * input = vam->input;
    vl_api_lisp_add_del_adjacency_t *mp;
    f64 timeout = ~0;
    u32 vni = 0;
    ip4_address_t seid4, deid4;
    ip6_address_t seid6, deid6;
    u8 deid_mac[6] = {0};
    u8 seid_mac[6] = {0};
    u8 deid_type, seid_type;
    u32 seid_len = 0, deid_len = 0, len;
    u8 is_add = 1;

    seid_type = deid_type =  (u8)~0;

    /* Parse args required to build the message */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "del")) {
            is_add = 0;
        } else if (unformat(input, "add")) {
            is_add = 1;
        } else if (unformat(input, "deid %U/%d", unformat_ip4_address,
                            &deid4, &len)) {
            deid_type = 0; /* ipv4 */
            deid_len = len;
        } else if (unformat(input, "deid %U/%d", unformat_ip6_address,
                            &deid6, &len)) {
            deid_type = 1; /* ipv6 */
            deid_len = len;
        } else if (unformat(input, "deid %U", unformat_ethernet_address,
                            deid_mac)) {
            deid_type = 2; /* mac */
        } else if (unformat(input, "seid %U/%d", unformat_ip4_address,
                            &seid4, &len)) {
            seid_type = 0; /* ipv4 */
            seid_len = len;
        } else if (unformat(input, "seid %U/%d", unformat_ip6_address,
                            &seid6, &len)) {
            seid_type = 1; /* ipv6 */
            seid_len = len;
        } else if (unformat(input, "seid %U", unformat_ethernet_address,
                            seid_mac)) {
            seid_type = 2; /* mac */
        } else if (unformat(input, "vni %d", &vni)) {
            ;
        } else {
            errmsg ("parse error '%U'", format_unformat_error, input);
            return -99;
        }
    }

    if ((u8)~0 == deid_type) {
        errmsg ("missing params!");
        return -99;
    }

    if (seid_type != deid_type) {
        errmsg ("source and destination EIDs are of different types!");
        return -99;
    }

    M(LISP_ADD_DEL_ADJACENCY, lisp_add_del_adjacency);
    mp->is_add = is_add;
    mp->vni = htonl (vni);
    mp->seid_len = seid_len;
    mp->deid_len = deid_len;
    mp->eid_type = deid_type;

    switch (mp->eid_type) {
    case 0:
        clib_memcpy (mp->seid, &seid4, sizeof (seid4));
        clib_memcpy (mp->deid, &deid4, sizeof (deid4));
        break;
    case 1:
        clib_memcpy (mp->seid, &seid6, sizeof (seid6));
        clib_memcpy (mp->deid, &deid6, sizeof (deid6));
        break;
    case 2:
        clib_memcpy (mp->seid, seid_mac, 6);
        clib_memcpy (mp->deid, deid_mac, 6);
        break;
    default:
        errmsg ("unknown EID type %d!", mp->eid_type);
        return 0;
    }

    /* send it... */
    S;

    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

static int
api_lisp_gpe_add_del_iface(vat_main_t * vam)
{
    unformat_input_t * input = vam->input;
    vl_api_lisp_gpe_add_del_iface_t *mp;
    f64 timeout = ~0;
    u8 is_set = 0;
    u8 is_add = 1;
    u32 table_id, vni;

    /* Parse args required to build the message */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "up")) {
            is_set = 1;
            is_add = 1;
        } else if (unformat(input, "down")) {
            is_set = 1;
            is_add = 0;
        } else if (unformat(input, "table_id %d", &table_id)) {
            ;
        } else if (unformat(input, "vni %d", &vni)) {
            ;
        } else
            break;
    }

    if (is_set == 0) {
        errmsg("Value not set\n");
        return -99;
    }

    /* Construct the API message */
    M(LISP_GPE_ADD_DEL_IFACE, lisp_gpe_add_del_iface);

    mp->is_add = is_add;
    mp->table_id = table_id;
    mp->vni = vni;

    /* send it... */
    S;

    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

/**
 * Add/del map request itr rlocs from LISP control plane and updates
 *
 * @param vam vpp API test context
 * @return return code
 */
static int
api_lisp_add_del_map_request_itr_rlocs(vat_main_t * vam)
{
    unformat_input_t * input = vam->input;
    vl_api_lisp_add_del_map_request_itr_rlocs_t *mp;
    f64 timeout = ~0;
    u8 *locator_set_name = 0;
    u8  locator_set_name_set = 0;
    u8 is_add = 1;

    /* Parse args required to build the message */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "del")) {
            is_add = 0;
        } else if (unformat(input, "%_%v%_", &locator_set_name)) {
            locator_set_name_set = 1;
        } else {
            clib_warning ("parse error '%U'", format_unformat_error, input);
            return -99;
        }
    }

    if (is_add && !locator_set_name_set) {
        errmsg ("itr-rloc is not set!");
        return -99;
    }

    if (is_add && vec_len(locator_set_name) > 64) {
        errmsg ("itr-rloc locator-set name too long\n");
        vec_free(locator_set_name);
        return -99;
    }

    M(LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS, lisp_add_del_map_request_itr_rlocs);
    mp->is_add = is_add;
    if (is_add) {
      clib_memcpy (mp->locator_set_name , locator_set_name,
                   vec_len(locator_set_name));
    } else {
      memset(mp->locator_set_name, 0, sizeof(mp->locator_set_name));
    }
    vec_free (locator_set_name);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

static int
api_lisp_locator_set_dump(vat_main_t *vam)
{
    vl_api_lisp_locator_set_dump_t *mp;
    f64 timeout = ~0;

    if (!vam->json_output) {
        fformat(vam->ofp, "%=20s%=16s%=16s%=16s\n",
                "Locator-set", "Locator", "Priority", "Weight");
    }

    M(LISP_LOCATOR_SET_DUMP, lisp_locator_set_dump);
    /* send it... */
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

static int
api_lisp_eid_table_map_dump(vat_main_t *vam)
{
    vl_api_lisp_eid_table_map_dump_t *mp;
    f64 timeout = ~0;

    if (!vam->json_output) {
        fformat (vam->ofp, "%=10s%=10s\n", "VNI", "VRF");
    }

    M(LISP_EID_TABLE_MAP_DUMP, lisp_eid_table_map_dump);

    /* send it... */
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

static int
api_lisp_local_eid_table_dump(vat_main_t *vam)
{
    unformat_input_t * i = vam->input;
    vl_api_lisp_local_eid_table_dump_t *mp;
    f64 timeout = ~0;
    struct in_addr ip4;
    struct in6_addr ip6;
    u8 mac[6];
    u8 eid_type = ~0, eid_set;
    u32 prefix_length = ~0, t, vni = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "eid %U/%d", unformat_ip4_address, &ip4, &t)) {
            eid_set = 1;
            eid_type = 0;
            prefix_length = t;
        } else if (unformat (i, "eid %U/%d", unformat_ip6_address, &ip6, &t)) {
            eid_set = 1;
            eid_type = 1;
            prefix_length = t;
        } else if (unformat (i, "eid %U", unformat_ethernet_address, mac)) {
            eid_set = 1;
            eid_type = 2;
        } else if (unformat (i, "vni %d", &t))
            vni = t;
        else {
            errmsg ("parse error '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (!vam->json_output) {
        fformat(vam->ofp, "%=20s%=30s\n",
                "Locator-set", "Eid");
    }

    M(LISP_LOCAL_EID_TABLE_DUMP, lisp_local_eid_table_dump);

    if (eid_set) {
        mp->eid_set = 1;
        mp->vni = htonl (vni);
        mp->eid_type = eid_type;
        switch (eid_type) {
        case 0:
            mp->prefix_length = prefix_length;
            clib_memcpy (mp->eid, &ip4, sizeof (ip4));
            break;
        case 1:
            mp->prefix_length = prefix_length;
            clib_memcpy (mp->eid, &ip6, sizeof (ip6));
            break;
        case 2:
            clib_memcpy (mp->eid, mac, sizeof (mac));
            break;
        default:
            errmsg ("unknown EID type %d!", eid_type);
            return -99;
        }
    }

    /* send it... */
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

static int
api_lisp_gpe_tunnel_dump(vat_main_t *vam)
{
    vl_api_lisp_gpe_tunnel_dump_t *mp;
    f64 timeout = ~0;

    if (!vam->json_output) {
        fformat(vam->ofp, "%=20s%=30s%=16s%=16s%=16s%=16s"
                "%=16s%=16s%=16s%=16s%=16s\n",
                "Tunel", "Source", "Destination", "Fib encap", "Fib decap",
                "Decap next", "Lisp version", "Flags", "Next protocol",
                "ver_res", "res", "iid");
    }

    M(LISP_GPE_TUNNEL_DUMP, lisp_gpe_tunnel_dump);
    /* send it... */
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

static int
api_lisp_map_resolver_dump(vat_main_t *vam)
{
    vl_api_lisp_map_resolver_dump_t *mp;
    f64 timeout = ~0;

    if (!vam->json_output) {
        fformat(vam->ofp, "%=20s\n",
                "Map resolver");
    }

    M(LISP_MAP_RESOLVER_DUMP, lisp_map_resolver_dump);
    /* send it... */
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

static int
api_lisp_enable_disable_status_dump(vat_main_t *vam)
{
    vl_api_lisp_enable_disable_status_dump_t *mp;
    f64 timeout = ~0;

    if (!vam->json_output) {
        fformat(vam->ofp, "%-20s%-16s\n",
                "lisp status", "locator-set");
    }

    M(LISP_ENABLE_DISABLE_STATUS_DUMP,
      lisp_enable_disable_status_dump);
    /* send it... */
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

static int
api_lisp_get_map_request_itr_rlocs(vat_main_t *vam)
{
    vl_api_lisp_get_map_request_itr_rlocs_t *mp;
    f64 timeout = ~0;

    if (!vam->json_output) {
        fformat(vam->ofp, "%=20s\n",
                "itr-rlocs:");
    }

    M(LISP_GET_MAP_REQUEST_ITR_RLOCS, lisp_get_map_request_itr_rlocs);
    /* send it... */
    S;
    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

static int
api_af_packet_create (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_af_packet_create_t * mp;
    f64 timeout;
    u8 * host_if_name = 0;
    u8 hw_addr[6];
    u8 random_hw_addr = 1;

    memset (hw_addr, 0, sizeof (hw_addr));

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "name %s", &host_if_name))
            vec_add1 (host_if_name, 0);
        else if (unformat (i, "hw_addr %U", unformat_ethernet_address, hw_addr))
            random_hw_addr = 0;
        else
          break;
    }

    if (!vec_len (host_if_name)) {
        errmsg ("host-interface name must be specified");
        return -99;
    }

    if (vec_len (host_if_name) > 64) {
        errmsg ("host-interface name too long");
        return -99;
    }

    M(AF_PACKET_CREATE, af_packet_create);

    clib_memcpy (mp->host_if_name, host_if_name, vec_len (host_if_name));
    clib_memcpy (mp->hw_addr, hw_addr, 6);
    mp->use_random_hw_addr = random_hw_addr;
    vec_free (host_if_name);

    S; W2(fprintf(vam->ofp," new sw_if_index = %d ", vam->sw_if_index));
    /* NOTREACHED */
    return 0;
}

static int
api_af_packet_delete (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_af_packet_delete_t * mp;
    f64 timeout;
    u8 * host_if_name = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "name %s", &host_if_name))
            vec_add1 (host_if_name, 0);
        else
          break;
    }

    if (!vec_len (host_if_name)) {
        errmsg ("host-interface name must be specified");
        return -99;
    }

    if (vec_len (host_if_name) > 64) {
        errmsg ("host-interface name too long");
        return -99;
    }

    M(AF_PACKET_DELETE, af_packet_delete);

    clib_memcpy (mp->host_if_name, host_if_name, vec_len (host_if_name));
    vec_free (host_if_name);

    S; W;
    /* NOTREACHED */
    return 0;
}

static int
api_policer_add_del (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_policer_add_del_t * mp;
    f64 timeout;
    u8 is_add = 1;
    u8 * name = 0;
    u32 cir = 0;
    u32 eir = 0;
    u64 cb = 0;
    u64 eb = 0;
    u8 rate_type = 0;
    u8 round_type = 0;
    u8 type = 0;
    sse2_qos_pol_action_params_st conform_action, exceed_action, violate_action;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "del"))
            is_add = 0;
        else if (unformat (i, "name %s", &name))
            vec_add1 (name, 0);
        else if (unformat (i, "cir %u", &cir))
            ;
        else if (unformat (i, "eir %u", &eir))
            ;
        else if (unformat (i, "cb %u", &cb))
            ;
        else if (unformat (i, "eb %u", &eb))
            ;
        else if (unformat (i, "rate_type %U", unformat_policer_rate_type,
                           &rate_type))
            ;
        else if (unformat (i, "round_type %U", unformat_policer_round_type,
                           &round_type))
            ;
        else if (unformat (i, "type %U", unformat_policer_type, &type))
            ;
        else if (unformat (i, "conform_action %U", unformat_policer_action_type,
                           &conform_action))
            ;
        else if (unformat (i, "exceed_action %U", unformat_policer_action_type,
                           &exceed_action))
            ;
        else if (unformat (i, "violate_action %U", unformat_policer_action_type,
                           &violate_action))
            ;
        else
          break;
    }

    if (!vec_len (name)) {
        errmsg ("policer name must be specified");
        return -99;
    }

    if (vec_len (name) > 64) {
        errmsg ("policer name too long");
        return -99;
    }

    M(POLICER_ADD_DEL, policer_add_del);

    clib_memcpy (mp->name, name, vec_len (name));
    vec_free (name);
    mp->is_add = is_add;
    mp->cir = cir;
    mp->eir = eir;
    mp->cb = cb;
    mp->eb = eb;
    mp->rate_type = rate_type;
    mp->round_type = round_type;
    mp->type = type;
    mp->conform_action_type = conform_action.action_type;
    mp->conform_dscp = conform_action.dscp;
    mp->exceed_action_type = exceed_action.action_type;
    mp->exceed_dscp = exceed_action.dscp;
    mp->violate_action_type = violate_action.action_type;
    mp->violate_dscp = violate_action.dscp;

    S; W;
    /* NOTREACHED */
    return 0;
}

static int
api_policer_dump(vat_main_t *vam)
{
    unformat_input_t * i = vam->input;
    vl_api_policer_dump_t *mp;
    f64 timeout = ~0;
    u8 *match_name = 0;
    u8 match_name_valid = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "name %s", &match_name)) {
            vec_add1 (match_name, 0);
            match_name_valid = 1;
        } else
            break;
    }

    M(POLICER_DUMP, policer_dump);
    mp->match_name_valid = match_name_valid;
    clib_memcpy (mp->match_name, match_name, vec_len (match_name));
    vec_free (match_name);
    /* send it... */
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    /* Wait for a reply... */
    W;

    /* NOTREACHED */
    return 0;
}

static int
api_netmap_create (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_netmap_create_t * mp;
    f64 timeout;
    u8 * if_name = 0;
    u8 hw_addr[6];
    u8 random_hw_addr = 1;
    u8 is_pipe = 0;
    u8 is_master = 0;

    memset (hw_addr, 0, sizeof (hw_addr));

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "name %s", &if_name))
            vec_add1 (if_name, 0);
        else if (unformat (i, "hw_addr %U", unformat_ethernet_address, hw_addr))
            random_hw_addr = 0;
        else if (unformat (i, "pipe"))
            is_pipe = 1;
        else if (unformat (i, "master"))
            is_master = 1;
        else if (unformat (i, "slave"))
            is_master = 0;
        else
          break;
    }

    if (!vec_len (if_name)) {
        errmsg ("interface name must be specified");
        return -99;
    }

    if (vec_len (if_name) > 64) {
        errmsg ("interface name too long");
        return -99;
    }

    M(NETMAP_CREATE, netmap_create);

    clib_memcpy (mp->netmap_if_name, if_name, vec_len (if_name));
    clib_memcpy (mp->hw_addr, hw_addr, 6);
    mp->use_random_hw_addr = random_hw_addr;
    mp->is_pipe = is_pipe;
    mp->is_master = is_master;
    vec_free (if_name);

    S; W;
    /* NOTREACHED */
    return 0;
}

static int
api_netmap_delete (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    vl_api_netmap_delete_t * mp;
    f64 timeout;
    u8 * if_name = 0;

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "name %s", &if_name))
            vec_add1 (if_name, 0);
        else
            break;
    }

    if (!vec_len (if_name)) {
        errmsg ("interface name must be specified");
        return -99;
    }

    if (vec_len (if_name) > 64) {
        errmsg ("interface name too long");
        return -99;
    }

    M(NETMAP_DELETE, netmap_delete);

    clib_memcpy (mp->netmap_if_name, if_name, vec_len (if_name));
    vec_free (if_name);

    S; W;
    /* NOTREACHED */
    return 0;
}

static void vl_api_mpls_gre_tunnel_details_t_handler
(vl_api_mpls_gre_tunnel_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 i;
    i32 len = ntohl(mp->nlabels);

    if (mp->l2_only == 0) {
        fformat(vam->ofp, "[%d]: src %U, dst %U, adj %U/%d, labels ",
                ntohl(mp->tunnel_index),
                format_ip4_address, &mp->tunnel_src,
                format_ip4_address, &mp->tunnel_dst,
                format_ip4_address, &mp->intfc_address,
                ntohl(mp->mask_width));
        for (i = 0; i < len; i++) {
            fformat(vam->ofp, "%u ", ntohl(mp->labels[i]));
        }
        fformat(vam->ofp, "\n");
        fformat(vam->ofp, "      inner fib index %d, outer fib index %d\n",
                ntohl(mp->inner_fib_index), ntohl(mp->outer_fib_index));
    } else {
        fformat(vam->ofp, "[%d]: src %U, dst %U, key %U, labels ",
                ntohl(mp->tunnel_index),
                format_ip4_address, &mp->tunnel_src,
                format_ip4_address, &mp->tunnel_dst,
                format_ip4_address, &mp->intfc_address);
        for (i = 0; i < len; i++) {
            fformat(vam->ofp, "%u ", ntohl(mp->labels[i]));
        }
        fformat(vam->ofp, "\n");
        fformat(vam->ofp, "      l2 interface %d, outer fib index %d\n",
                ntohl(mp->hw_if_index), ntohl(mp->outer_fib_index));
    }
}

static void vl_api_mpls_gre_tunnel_details_t_handler_json
(vl_api_mpls_gre_tunnel_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node = NULL;
    struct in_addr ip4;
    i32 i;
    i32 len = ntohl(mp->nlabels);

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_uint(node, "tunnel_index", ntohl(mp->tunnel_index));
    clib_memcpy(&ip4, &(mp->intfc_address), sizeof(ip4));
    vat_json_object_add_ip4(node, "intfc_address", ip4);
    vat_json_object_add_uint(node, "inner_fib_index", ntohl(mp->inner_fib_index));
    vat_json_object_add_uint(node, "mask_width", ntohl(mp->mask_width));
    vat_json_object_add_uint(node, "encap_index", ntohl(mp->encap_index));
    vat_json_object_add_uint(node, "hw_if_index", ntohl(mp->hw_if_index));
    vat_json_object_add_uint(node, "l2_only", ntohl(mp->l2_only));
    clib_memcpy(&ip4, &(mp->tunnel_src), sizeof(ip4));
    vat_json_object_add_ip4(node, "tunnel_src", ip4);
    clib_memcpy(&ip4, &(mp->tunnel_dst), sizeof(ip4));
    vat_json_object_add_ip4(node, "tunnel_dst", ip4);
    vat_json_object_add_uint(node, "outer_fib_index", ntohl(mp->outer_fib_index));
    vat_json_object_add_uint(node, "label_count", len);
    for (i = 0; i < len; i++) {
        vat_json_object_add_uint(node, "label", ntohl(mp->labels[i]));
    }
}

static int api_mpls_gre_tunnel_dump (vat_main_t * vam)
{
    vl_api_mpls_gre_tunnel_dump_t *mp;
    f64 timeout;
    i32 index = -1;

    /* Parse args required to build the message */
    while (unformat_check_input (vam->input) != UNFORMAT_END_OF_INPUT) {
        if (!unformat (vam->input, "tunnel_index %d", &index)) {
            index = -1;
            break;
        }
    }

    fformat(vam->ofp, "  tunnel_index %d\n", index);

    M(MPLS_GRE_TUNNEL_DUMP, mpls_gre_tunnel_dump);
    mp->tunnel_index = htonl(index);
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}

static void vl_api_mpls_eth_tunnel_details_t_handler
(vl_api_mpls_eth_tunnel_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 i;
    i32 len = ntohl(mp->nlabels);

    fformat(vam->ofp, "[%d]: dst %U, adj %U/%d, labels ",
            ntohl(mp->tunnel_index),
            format_ethernet_address, &mp->tunnel_dst_mac,
            format_ip4_address, &mp->intfc_address,
            ntohl(mp->mask_width));
    for (i = 0; i < len; i++) {
        fformat(vam->ofp, "%u ", ntohl(mp->labels[i]));
    }
    fformat(vam->ofp, "\n");
    fformat(vam->ofp, "      tx on %d, rx fib index %d\n",
            ntohl(mp->tx_sw_if_index),
            ntohl(mp->inner_fib_index));
}

static void vl_api_mpls_eth_tunnel_details_t_handler_json
(vl_api_mpls_eth_tunnel_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node = NULL;
    struct in_addr ip4;
    i32 i;
    i32 len = ntohl(mp->nlabels);

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_uint(node, "tunnel_index", ntohl(mp->tunnel_index));
    clib_memcpy(&ip4, &(mp->intfc_address), sizeof(ip4));
    vat_json_object_add_ip4(node, "intfc_address", ip4);
    vat_json_object_add_uint(node, "inner_fib_index", ntohl(mp->inner_fib_index));
    vat_json_object_add_uint(node, "mask_width", ntohl(mp->mask_width));
    vat_json_object_add_uint(node, "encap_index", ntohl(mp->encap_index));
    vat_json_object_add_uint(node, "hw_if_index", ntohl(mp->hw_if_index));
    vat_json_object_add_uint(node, "l2_only", ntohl(mp->l2_only));
    vat_json_object_add_string_copy(node, "tunnel_dst_mac",
            format(0, "%U", format_ethernet_address, &mp->tunnel_dst_mac));
    vat_json_object_add_uint(node, "tx_sw_if_index", ntohl(mp->tx_sw_if_index));
    vat_json_object_add_uint(node, "label_count", len);
    for (i = 0; i < len; i++) {
        vat_json_object_add_uint(node, "label", ntohl(mp->labels[i]));
    }
}

static int api_mpls_eth_tunnel_dump (vat_main_t * vam)
{
    vl_api_mpls_eth_tunnel_dump_t *mp;
    f64 timeout;
    i32 index = -1;

    /* Parse args required to build the message */
    while (unformat_check_input (vam->input) != UNFORMAT_END_OF_INPUT) {
        if (!unformat (vam->input, "tunnel_index %d", &index)) {
            index = -1;
            break;
        }
    }

    fformat(vam->ofp, "  tunnel_index %d\n", index);

    M(MPLS_ETH_TUNNEL_DUMP, mpls_eth_tunnel_dump);
    mp->tunnel_index = htonl(index);
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}

static void vl_api_mpls_fib_encap_details_t_handler
(vl_api_mpls_fib_encap_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 i;
    i32 len = ntohl(mp->nlabels);

    fformat(vam->ofp, "table %d, dest %U, label ",
            ntohl(mp->fib_index),
            format_ip4_address, &mp->dest,
            len);
    for (i = 0; i < len; i++) {
        fformat(vam->ofp, "%u ", ntohl(mp->labels[i]));
    }
    fformat(vam->ofp, "\n");
}

static void vl_api_mpls_fib_encap_details_t_handler_json
(vl_api_mpls_fib_encap_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node = NULL;
    i32 i;
    i32 len = ntohl(mp->nlabels);
    struct in_addr ip4;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_uint(node, "table", ntohl(mp->fib_index));
    vat_json_object_add_uint(node, "entry_index", ntohl(mp->entry_index));
    clib_memcpy(&ip4, &(mp->dest), sizeof(ip4));
    vat_json_object_add_ip4(node, "dest", ip4);
    vat_json_object_add_uint(node, "s_bit", ntohl(mp->s_bit));
    vat_json_object_add_uint(node, "label_count", len);
    for (i = 0; i < len; i++) {
        vat_json_object_add_uint(node, "label", ntohl(mp->labels[i]));
    }
}

static int api_mpls_fib_encap_dump (vat_main_t * vam)
{
    vl_api_mpls_fib_encap_dump_t *mp;
    f64 timeout;

    M(MPLS_FIB_ENCAP_DUMP, mpls_fib_encap_dump);
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}

static void vl_api_mpls_fib_decap_details_t_handler
(vl_api_mpls_fib_decap_details_t * mp)
{
    vat_main_t * vam = &vat_main;

    fformat(vam->ofp, "RX table %d, TX table/intfc %u, swif_tag '%s', label %u, s_bit %u\n",
            ntohl(mp->rx_table_id),
            ntohl(mp->tx_table_id),
            mp->swif_tag,
            ntohl(mp->label),
            ntohl(mp->s_bit));
}

static void vl_api_mpls_fib_decap_details_t_handler_json
(vl_api_mpls_fib_decap_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t *node = NULL;
    struct in_addr ip4;

    if (VAT_JSON_ARRAY != vam->json_tree.type) {
        ASSERT(VAT_JSON_NONE == vam->json_tree.type);
        vat_json_init_array(&vam->json_tree);
    }
    node = vat_json_array_add(&vam->json_tree);

    vat_json_init_object(node);
    vat_json_object_add_uint(node, "table", ntohl(mp->fib_index));
    vat_json_object_add_uint(node, "entry_index", ntohl(mp->entry_index));
    clib_memcpy(&ip4, &(mp->dest), sizeof(ip4));
    vat_json_object_add_ip4(node, "dest", ip4);
    vat_json_object_add_uint(node, "s_bit", ntohl(mp->s_bit));
    vat_json_object_add_uint(node, "label", ntohl(mp->label));
    vat_json_object_add_uint(node, "rx_table_id", ntohl(mp->rx_table_id));
    vat_json_object_add_uint(node, "tx_table_id", ntohl(mp->tx_table_id));
    vat_json_object_add_string_copy(node, "swif_tag", mp->swif_tag);
}

static int api_mpls_fib_decap_dump (vat_main_t * vam)
{
    vl_api_mpls_fib_decap_dump_t *mp;
    f64 timeout;

    M(MPLS_FIB_DECAP_DUMP, mpls_fib_decap_dump);
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
}

int api_classify_table_ids (vat_main_t *vam)
{
    vl_api_classify_table_ids_t *mp;
    f64 timeout;

    /* Construct the API message */
    M(CLASSIFY_TABLE_IDS, classify_table_ids);
    mp->context = 0;

    S; W;
    /* NOTREACHED */
    return 0;
}

int api_classify_table_by_interface (vat_main_t *vam)
{
    unformat_input_t * input = vam->input;
    vl_api_classify_table_by_interface_t *mp;
    f64 timeout;

    u32 sw_if_index = ~0;
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "%U", unformat_sw_if_index, vam, &sw_if_index))
            ;
        else if (unformat (input, "sw_if_index %d", &sw_if_index))
            ;
        else
            break;
    }
    if (sw_if_index == ~0) {
        errmsg ("missing interface name or sw_if_index\n");
        return -99;
    }

    /* Construct the API message */
    M(CLASSIFY_TABLE_BY_INTERFACE, classify_table_by_interface);
    mp->context = 0;
    mp->sw_if_index = ntohl(sw_if_index);

    S; W;
    /* NOTREACHED */
    return 0;
}

int api_classify_table_info (vat_main_t *vam)
{
    unformat_input_t * input = vam->input;
    vl_api_classify_table_info_t *mp;
    f64 timeout;

    u32 table_id = ~0;
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "table_id %d", &table_id))
            ;
        else
            break;
    }
    if (table_id == ~0) {
        errmsg ("missing table id\n");
        return -99;
    }

    /* Construct the API message */
    M(CLASSIFY_TABLE_INFO, classify_table_info);
    mp->context = 0;
    mp->table_id = ntohl(table_id);

    S; W;
    /* NOTREACHED */
    return 0;
}

int api_classify_session_dump (vat_main_t *vam)
{
    unformat_input_t * input = vam->input;
    vl_api_classify_session_dump_t *mp;
    f64 timeout;

    u32 table_id = ~0;
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "table_id %d", &table_id))
            ;
        else
            break;
    }
    if (table_id == ~0) {
        errmsg ("missing table id\n");
        return -99;
    }

    /* Construct the API message */
    M(CLASSIFY_SESSION_DUMP, classify_session_dump);
    mp->context = 0;
    mp->table_id = ntohl(table_id);
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
    /* NOTREACHED */
    return 0;
}

static void vl_api_ipfix_details_t_handler (vl_api_ipfix_details_t * mp)
{
    vat_main_t * vam = &vat_main;

    fformat(vam->ofp, "collector_address %U, collector_port %d, "
                      "src_address %U, fib_index %u, path_mtu %u, "
                      "template_interval %u\n",
            format_ip4_address, mp->collector_address,
            ntohs(mp->collector_port),
            format_ip4_address, mp->src_address,
            ntohl(mp->fib_index),
            ntohl(mp->path_mtu),
            ntohl(mp->template_interval));

    vam->retval = 0;
    vam->result_ready = 1;
}

static void vl_api_ipfix_details_t_handler_json
(vl_api_ipfix_details_t * mp)
{
    vat_main_t * vam = &vat_main;
    vat_json_node_t node;
    struct in_addr collector_address;
    struct in_addr src_address;

    vat_json_init_object(&node);
    clib_memcpy(&collector_address, &mp->collector_address,
                sizeof(collector_address));
    vat_json_object_add_ip4(&node, "collector_address", collector_address);
    vat_json_object_add_uint(&node, "collector_port",
                             ntohs(mp->collector_port));
    clib_memcpy(&src_address, &mp->src_address, sizeof(src_address));
    vat_json_object_add_ip4(&node, "src_address", src_address);
    vat_json_object_add_uint(&node, "fib_index", ntohl(mp->fib_index));
    vat_json_object_add_uint(&node, "path_mtu", ntohl(mp->path_mtu));
    vat_json_object_add_uint(&node, "template_interval",
                             ntohl(mp->template_interval));

    vat_json_print(vam->ofp, &node);
    vat_json_free(&node);
    vam->retval = 0;
    vam->result_ready = 1;
}

int api_ipfix_dump (vat_main_t *vam)
{
    vl_api_ipfix_dump_t *mp;
    f64 timeout;

    /* Construct the API message */
    M(IPFIX_DUMP, ipfix_dump);
    mp->context = 0;

    S; W;
    /* NOTREACHED */
    return 0;
}

int api_pg_create_interface (vat_main_t *vam)
{
    unformat_input_t * input = vam->input;
    vl_api_pg_create_interface_t *mp;
    f64 timeout;

    u32 if_id = ~0;
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "if_id %d", &if_id))
            ;
        else
            break;
    }
    if (if_id == ~0) {
        errmsg ("missing pg interface index\n");
        return -99;
    }

    /* Construct the API message */
    M(PG_CREATE_INTERFACE, pg_create_interface);
    mp->context = 0;
    mp->interface_id = ntohl(if_id);

    S; W;
    /* NOTREACHED */
    return 0;
}

int api_pg_capture (vat_main_t *vam)
{
    unformat_input_t * input = vam->input;
    vl_api_pg_capture_t *mp;
    f64 timeout;

    u32 if_id = ~0;
    u8 enable = 1;
    u32 count = 1;
    u8 pcap_file_set = 0;
    u8 * pcap_file = 0;
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "if_id %d", &if_id))
            ;
        else if (unformat (input, "pcap %s", &pcap_file))
            pcap_file_set = 1;
        else if (unformat (input, "count %d", &count))
            ;
        else if (unformat (input, "disable"))
            enable = 0;
        else
            break;
    }
    if (if_id == ~0) {
        errmsg ("missing pg interface index\n");
        return -99;
    }
    if (pcap_file_set>0) {
    	if (vec_len (pcap_file) > 255) {
    	    errmsg ("pcap file name is too long\n");
    	    return -99;
    	}
    }

    u32 name_len = vec_len(pcap_file);
    /* Construct the API message */
    M(PG_CAPTURE, pg_capture);
    mp->context = 0;
    mp->interface_id = ntohl(if_id);
    mp->is_enabled = enable;
    mp->count = ntohl(count);
    mp->pcap_name_length = ntohl(name_len);
    if (pcap_file_set != 0) {
        clib_memcpy(mp->pcap_file_name, pcap_file, name_len);
    }
    vec_free(pcap_file);

    S; W;
    /* NOTREACHED */
    return 0;
}

int api_pg_enable_disable (vat_main_t *vam)
{
    unformat_input_t * input = vam->input;
    vl_api_pg_enable_disable_t *mp;
    f64 timeout;

    u8 enable = 1;
    u8 stream_name_set = 0;
    u8 * stream_name = 0;
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "stream %s", &stream_name))
            stream_name_set = 1;
    	else if (unformat (input, "disable"))
            enable = 0;
        else
            break;
    }

    if (stream_name_set>0) {
    	if (vec_len (stream_name) > 255) {
            errmsg ("stream name too long\n");
            return -99;
    	}
    }

    u32 name_len = vec_len(stream_name);
    /* Construct the API message */
    M(PG_ENABLE_DISABLE, pg_enable_disable);
    mp->context = 0;
    mp->is_enabled = enable;
    if (stream_name_set != 0) {
        mp->stream_name_length = ntohl(name_len);
        clib_memcpy(mp->stream_name, stream_name, name_len);
    }
    vec_free(stream_name);

    S; W;
    /* NOTREACHED */
    return 0;
}

static int q_or_quit (vat_main_t * vam)
{
    longjmp (vam->jump_buf, 1);
    return 0; /* not so much */
}
static int q (vat_main_t * vam) {return q_or_quit (vam);}
static int quit (vat_main_t * vam) {return q_or_quit (vam);}

static int comment (vat_main_t * vam)
{
    return 0;
}

static int cmd_cmp (void * a1, void * a2)
{
  u8 ** c1 = a1;
  u8 ** c2 = a2;

  return strcmp ((char *)(c1[0]), (char *)(c2[0]));
}

static int help (vat_main_t * vam)
{
    u8 ** cmds = 0;
    u8 * name = 0;
    hash_pair_t * p;
    unformat_input_t * i = vam->input;
    int j;

    if (unformat (i, "%s", &name)) {
        uword *hs;

        vec_add1(name, 0);

        hs = hash_get_mem (vam->help_by_name, name);
        if (hs)
            fformat (vam->ofp, "usage: %s %s\n", name, hs[0]);
        else
            fformat (vam->ofp, "No such msg / command '%s'\n", name);
        vec_free(name);
        return 0;
    }

    fformat(vam->ofp, "Help is available for the following:\n");

    hash_foreach_pair (p, vam->function_by_name, 
    ({
        vec_add1 (cmds, (u8 *)(p->key));
    }));

    vec_sort_with_function (cmds, cmd_cmp);

    for (j = 0; j < vec_len(cmds); j++)
        fformat (vam->ofp, "%s\n", cmds[j]);

    vec_free (cmds);
    return 0;
}

static int set (vat_main_t * vam)
{
    u8 * name = 0, * value = 0;
    unformat_input_t * i = vam->input;

    if (unformat (i, "%s", &name)) {
        /* The input buffer is a vector, not a string. */
        value = vec_dup (i->buffer);
        vec_delete (value, i->index, 0);
        /* Almost certainly has a trailing newline */
        if (value[vec_len(value)-1] == '\n')
            value[vec_len(value)-1] = 0;
        /* Make sure it's a proper string, one way or the other */
        vec_add1 (value, 0);
        (void) clib_macro_set_value (&vam->macro_main, 
                                     (char *)name, (char *)value);
    }
    else
        errmsg ("usage: set <name> <value>\n");

    vec_free (name);
    vec_free (value);
    return 0;
}

static int unset (vat_main_t * vam)
{
    u8 * name = 0;

    if (unformat (vam->input, "%s", &name))
        if (clib_macro_unset (&vam->macro_main, (char *)name) == 1)
            errmsg ("unset: %s wasn't set\n", name);
    vec_free (name);
    return 0;
}

typedef struct {
    u8 * name;
    u8 * value;
} macro_sort_t;


static int macro_sort_cmp (void * a1, void * a2)
{
  macro_sort_t * s1 = a1;
  macro_sort_t * s2 = a2;

  return strcmp ((char *)(s1->name), (char *)(s2->name));
}

static int dump_macro_table (vat_main_t * vam)
{
    macro_sort_t * sort_me = 0, * sm;    
    int i;
    hash_pair_t * p;

    hash_foreach_pair (p, vam->macro_main.the_value_table_hash, 
    ({
        vec_add2 (sort_me, sm, 1);
        sm->name = (u8 *)(p->key);
        sm->value = (u8 *) (p->value[0]);
    }));
    
    vec_sort_with_function (sort_me, macro_sort_cmp);

    if (vec_len(sort_me))
        fformat (vam->ofp, "%-15s%s\n", "Name", "Value");
    else
        fformat (vam->ofp, "The macro table is empty...\n");

    for (i = 0; i < vec_len (sort_me); i++)
        fformat (vam->ofp, "%-15s%s\n", sort_me[i].name,
                 sort_me[i].value);
    return 0;
}

static int dump_node_table (vat_main_t * vam)
{
    int i, j;
    vlib_node_t * node, * next_node;

    if (vec_len (vam->graph_nodes) == 0) {
        fformat (vam->ofp, "Node table empty, issue get_node_graph...\n");
        return 0;
    }

    for (i = 0; i < vec_len (vam->graph_nodes); i++) {
        node = vam->graph_nodes[i];
        fformat (vam->ofp, "[%d] %s\n", i, node->name);
        for (j = 0; j < vec_len (node->next_nodes); j++) {
            if (node->next_nodes[j] != ~0) {
                next_node = vam->graph_nodes[node->next_nodes[j]];
                fformat (vam->ofp, "  [%d] %s\n", j, next_node->name);
            }
        }
    }
    return 0;
}

static int search_node_table (vat_main_t * vam)
{
    unformat_input_t * line_input = vam->input;
    u8 * node_to_find;
    int j;
    vlib_node_t * node, * next_node;
    uword * p;

    if (vam->graph_node_index_by_name == 0) {
        fformat (vam->ofp, "Node table empty, issue get_node_graph...\n");
        return 0;
    }

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (line_input, "%s", &node_to_find)) {
            vec_add1 (node_to_find, 0);
            p = hash_get_mem (vam->graph_node_index_by_name, node_to_find);
            if (p == 0) {
                fformat (vam->ofp, "%s not found...\n", node_to_find);
                goto out;
            }
            node = vam->graph_nodes[p[0]];
            fformat (vam->ofp, "[%d] %s\n", p[0], node->name);
            for (j = 0; j < vec_len (node->next_nodes); j++) {
                if (node->next_nodes[j] != ~0) {
                    next_node = vam->graph_nodes[node->next_nodes[j]];
                    fformat (vam->ofp, "  [%d] %s\n", j, next_node->name);
                }
            }
        }
            
        else {
            clib_warning ("parse error '%U'", format_unformat_error, 
                          line_input);
            return -99;
        }

    out:
        vec_free(node_to_find);
        
    }

    return 0;        
}


static int script (vat_main_t * vam)
{
    u8 * s = 0;
    char * save_current_file;
    unformat_input_t save_input;
    jmp_buf save_jump_buf;
    u32 save_line_number;

    FILE * new_fp, * save_ifp;

    if (unformat (vam->input, "%s", &s)) {
        new_fp = fopen ((char *)s, "r");
        if (new_fp == 0) {
            errmsg ("Couldn't open script file %s\n", s);
            vec_free (s);
            return -99;
        }
    } else {
        errmsg ("Missing script name\n");
        return -99;
    }

    clib_memcpy (&save_input, &vam->input, sizeof (save_input));
    clib_memcpy (&save_jump_buf, &vam->jump_buf, sizeof (save_jump_buf));
    save_ifp = vam->ifp;
    save_line_number = vam->input_line_number;
    save_current_file = (char *) vam->current_file;

    vam->input_line_number = 0;
    vam->ifp = new_fp;
    vam->current_file = s;
    do_one_file (vam);

    clib_memcpy (&vam->input, &save_input, sizeof (vam->input));
    clib_memcpy (&vam->jump_buf, &save_jump_buf, sizeof (save_jump_buf));
    vam->ifp = save_ifp;
    vam->input_line_number = save_line_number;
    vam->current_file = (u8 *) save_current_file;
    vec_free (s);

    return 0;
}

static int echo (vat_main_t * vam)
{
    fformat (vam->ofp, "%v", vam->input->buffer);
    return 0;
}

/* List of API message constructors, CLI names map to api_xxx */
#define foreach_vpe_api_msg                                             \
_(create_loopback,"[mac <mac-addr>]")                                   \
_(sw_interface_dump,"")                                                 \
_(sw_interface_set_flags,                                               \
  "<intfc> | sw_if_index <id> admin-up | admin-down link-up | link down") \
_(sw_interface_add_del_address,                                         \
  "<intfc> | sw_if_index <id> <ip4-address> | <ip6-address> [del] [del-all] ") \
_(sw_interface_set_table,                                               \
  "<intfc> | sw_if_index <id> vrf <table-id> [ipv6]")                   \
_(sw_interface_set_vpath,                                               \
  "<intfc> | sw_if_index <id> enable | disable")                        \
_(sw_interface_set_l2_xconnect,                                         \
  "rx <intfc> | rx_sw_if_index <id> tx <intfc> | tx_sw_if_index <id>\n" \
  "enable | disable")                                                   \
_(sw_interface_set_l2_bridge,                                           \
  "rx <intfc> | rx_sw_if_index <id> bd_id <bridge-domain-id>\n"         \
  "[shg <split-horizon-group>] [bvi]\n"                                 \
  "enable | disable")                                                   \
_(bridge_domain_add_del,                                                \
  "bd_id <bridge-domain-id> [flood 1|0] [uu-flood 1|0] [forward 1|0] [learn 1|0] [arp-term 1|0] [del]\n")\
_(bridge_domain_dump, "[bd_id <bridge-domain-id>]\n")     \
_(l2fib_add_del,                                                        \
  "mac <mac-addr> bd_id <bridge-domain-id> [del] | sw_if <intfc> | sw_if_index <id> [static] [filter] [bvi] [count <nn>]\n") \
_(l2_flags,                                                             \
  "sw_if <intfc> | sw_if_index <id> [learn] [forward] [uu-flood] [flood]\n")       \
_(bridge_flags,                                                         \
  "bd_id <bridge-domain-id> [learn] [forward] [uu-flood] [flood] [arp-term] [disable]\n") \
_(tap_connect,                                                          \
  "tapname <name> mac <mac-addr> | random-mac")                         \
_(tap_modify,                                                           \
  "<vpp-if-name> | sw_if_index <id> tapname <name> mac <mac-addr> | random-mac") \
_(tap_delete,                                                           \
  "<vpp-if-name> | sw_if_index <id>")                                   \
_(sw_interface_tap_dump, "")                                            \
_(ip_add_del_route,                                                     \
  "<addr>/<mask> via <addr> [vrf <n>]\n"                                \
  "[<intfc> | sw_if_index <id>] [resolve-attempts <n>]\n"               \
  "[weight <n>] [drop] [local] [classify <n>] [del]\n"                  \
  "[multipath] [count <n>]")                                            \
_(proxy_arp_add_del,                                                    \
  "<lo-ip4-addr> - <hi-ip4-addr> [vrf <n>] [del]")                      \
_(proxy_arp_intfc_enable_disable,                                       \
  "<intfc> | sw_if_index <id> enable | disable")                        \
_(mpls_add_del_encap,                                                   \
  "label <n> dst <ip4-addr> [vrf <n>] [del]")                           \
_(mpls_add_del_decap,                                                   \
  "label <n> [rx_vrf_id <n>] [tx_vrf_id] [s-bit-clear][del]")           \
_(mpls_gre_add_del_tunnel,                                              \
  "inner_vrf_id <n> outer_vrf_id <n> src <ip4-address> dst <ip4-address>\n" \
  "adj <ip4-address>/<mask-width> [del]")                               \
_(sw_interface_set_unnumbered,                                          \
  "<intfc> | sw_if_index <id> unnum_if_index <id> [del]")               \
_(ip_neighbor_add_del,                                                  \
  "(<intfc> | sw_if_index <id>) dst <ip46-address> "                    \
  "[mac <mac-addr>] [vrf <vrf-id>] [is_static] [del]")                  \
_(reset_vrf, "vrf <id> [ipv6]")                                         \
_(create_vlan_subif, "<intfc> | sw_if_index <id> vlan <n>")             \
_(create_subif, "<intfc> | sw_if_index <id> sub_id <n>\n"               \
  "[outer_vlan_id <n>][inner_vlan_id <n>]\n"                            \
  "[no_tags][one_tag][two_tags][dot1ad][exact_match][default_sub]\n"    \
  "[outer_vlan_id_any][inner_vlan_id_any]")                             \
_(oam_add_del, "src <ip4-address> dst <ip4-address> [vrf <n>] [del]")   \
_(reset_fib, "vrf <n> [ipv6]")                                          \
_(dhcp_proxy_config,                                                    \
  "svr <v46-address> src <v46-address>\n"                               \
   "insert-cid <n> [del]")                                              \
_(dhcp_proxy_config_2,                                                  \
  "svr <v46-address> src <v46-address>\n"                               \
   "rx_vrf_id <nn> server_vrf_id <nn> insert-cid <n> [del]")            \
_(dhcp_proxy_set_vss,                                                   \
  "tbl_id <n> fib_id <n> oui <n> [ipv6] [del]")                         \
_(dhcp_client_config,                                                   \
  "<intfc> | sw_if_index <id> [hostname <name>] [disable_event] [del]") \
_(set_ip_flow_hash,                                                     \
  "vrf <n> [src] [dst] [sport] [dport] [proto] [reverse] [ipv6]")       \
_(sw_interface_ip6_enable_disable,                                      \
  "<intfc> | sw_if_index <id> enable | disable")                        \
_(sw_interface_ip6_set_link_local_address,                              \
  "<intfc> | sw_if_index <id> <ip6-address>/<mask-width>")              \
_(sw_interface_ip6nd_ra_prefix,                                         \
  "<intfc> | sw_if_index <id> <ip6-address>/<mask-width>\n"             \
  "val_life <n> pref_life <n> [def] [noadv] [offl] [noauto]\n"          \
  "[nolink] [isno]")                                                    \
_(sw_interface_ip6nd_ra_config,                                         \
  "<intfc> | sw_if_index <id> [maxint <n>] [minint <n>]\n"              \
  "[life <n>] [count <n>] [interval <n>] [suppress]\n"                  \
  "[managed] [other] [ll] [send] [cease] [isno] [def]")                 \
_(set_arp_neighbor_limit, "arp_nbr_limit <n> [ipv6]")                   \
_(l2_patch_add_del,                                                     \
  "rx <intfc> | rx_sw_if_index <id> tx <intfc> | tx_sw_if_index <id>\n" \
  "enable | disable")                                                   \
_(mpls_ethernet_add_del_tunnel,                                         \
  "tx <intfc> | tx_sw_if_index <n> dst <mac-addr>\n"                    \
  "adj <ip4-addr>/<mw> dst <mac-addr> [del]")                           \
_(mpls_ethernet_add_del_tunnel_2,                                       \
  "inner_vrf_id <n> outer_vrf_id <n> next-hop <ip4-addr>\n"             \
  "resolve-attempts <n> resolve-if-needed 0 | 1 [del]")                 \
_(sr_tunnel_add_del,                                                    \
  "[name <name>] src <ip6-addr> dst <ip6-addr>/<mw> \n"                 \
  "(next <ip6-addr>)+ [tag <ip6-addr>]* [clean] [reroute] \n"           \
  "[policy <policy_name>]")						\
_(sr_policy_add_del,                                                    \
  "name <name> tunnel <tunnel-name> [tunnel <tunnel-name>]* [del]")	\
_(sr_multicast_map_add_del,                                             \
  "address [ip6 multicast address] sr-policy [policy name] [del]")	\
_(classify_add_del_table,                                               \
  "buckets <nn> [skip <n>] [match <n>] [memory_size <nn-bytes>]\n"	\
  "[del] mask <mask-value>\n"						\
  " [l2-miss-next | miss-next | acl-miss-next] <name|nn>") 		\
_(classify_add_del_session,                                             \
  "[hit-next|l2-hit-next|acl-hit-next] <name|nn> table-index <nn>\n"    \
  "skip_n <nn> match_n <nn> match [hex] [l2] [l3 [ip4|ip6]]")		\
_(classify_set_interface_ip_table,                                      \
  "<intfc> | sw_if_index <nn> table <nn>")				\
_(classify_set_interface_l2_tables,                                     \
  "<intfc> | sw_if_index <nn> [ip4-table <nn>] [ip6-table <nn>]\n"      \
  "  [other-table <nn>]")                                               \
_(get_node_index, "node <node-name")                                    \
_(add_node_next, "node <node-name> next <next-node-name>")              \
_(l2tpv3_create_tunnel,                                                 \
  "client_address <ip6-addr> our_address <ip6-addr>\n"                  \
  "[local_session_id <nn>][remote_session_id <nn>][local_cookie <nn>]\n"\
  "[remote_cookie <nn>]\n[l2-sublayer-preset]\n")                       \
_(l2tpv3_set_tunnel_cookies,                                            \
  "<intfc> | sw_if_index <nn> [new_local_cookie <nn>]\n"                \
  "[new_remote_cookie <nn>]\n")                                         \
_(l2tpv3_interface_enable_disable,                                      \
  "<intfc> | sw_if_index <nn> enable | disable")                        \
_(l2tpv3_set_lookup_key,                                                \
  "lookup_v6_src | lookup_v6_dst | lookup_session_id")                  \
_(sw_if_l2tpv3_tunnel_dump, "")                                         \
_(vxlan_add_del_tunnel,                                                 \
  "src <ip-addr> dst <ip-addr> vni <vni> [encap-vrf-id <nn>]\n"         \
  " [decap-next l2|ip4|ip6] [del]")                                     \
_(vxlan_tunnel_dump, "[<intfc> | sw_if_index <nn>]")                    \
_(gre_add_del_tunnel,                                                   \
  "src <ip4-addr> dst <ip4-addr> [outer-fib-id <nn>] [del]\n")          \
_(gre_tunnel_dump, "[<intfc> | sw_if_index <nn>]")                      \
_(l2_fib_clear_table, "")                                               \
_(l2_interface_efp_filter, "sw_if_index <nn> enable | disable")         \
_(l2_interface_vlan_tag_rewrite,                                        \
  "<intfc> | sw_if_index <nn> \n"                                       \
  "[disable][push-[1|2]][pop-[1|2]][translate-1-[1|2]] \n"              \
  "[translate-2-[1|2]] [push_dot1q 0] tag1 <nn> tag2 <nn>")             \
_(create_vhost_user_if,                                                 \
        "socket <filename> [server] [renumber <dev_instance>] "         \
        "[mac <mac_address>]")                                          \
_(modify_vhost_user_if,                                                 \
        "<intfc> | sw_if_index <nn> socket <filename>\n"                \
        "[server] [renumber <dev_instance>]")                           \
_(delete_vhost_user_if, "<intfc> | sw_if_index <nn>")                   \
_(sw_interface_vhost_user_dump, "")                                     \
_(show_version, "")                                                     \
_(vxlan_gpe_add_del_tunnel,                                             \
  "local <addr> remote <addr> vni <nn>\n"                               \
    "[encap-vrf-id <nn>] [decap-vrf-id <nn>] [next-ip4][next-ip6]"      \
  "[next-ethernet] [next-nsh]\n")                                       \
_(vxlan_gpe_tunnel_dump, "[<intfc> | sw_if_index <nn>]")                \
_(l2_fib_table_dump, "bd_id <bridge-domain-id>")			\
_(interface_name_renumber,                                              \
  "<intfc> | sw_if_index <nn> new_show_dev_instance <nn>")		\
_(input_acl_set_interface,                                              \
  "<intfc> | sw_if_index <nn> [ip4-table <nn>] [ip6-table <nn>]\n"      \
  "  [l2-table <nn>] [del]")                                            \
_(want_ip4_arp_events, "address <ip4-address> [del]")                   \
_(ip_address_dump, "(ipv4 | ipv6) (<intfc> | sw_if_index <id>)")        \
_(ip_dump, "ipv4 | ipv6")                                               \
_(ipsec_spd_add_del, "spd_id <n> [del]")                                \
_(ipsec_interface_add_del_spd, "(<intfc> | sw_if_index <id>)\n"         \
  "  spid_id <n> ")                                                     \
_(ipsec_sad_add_del_entry, "sad_id <n> spi <n> crypto_alg <alg>\n"      \
  "  crypto_key <hex> tunnel_src <ip4|ip6> tunnel_dst <ip4|ip6>\n"      \
  "  integ_alg <alg> integ_key <hex>")                                  \
_(ipsec_spd_add_del_entry, "spd_id <n> priority <n> action <action>\n"  \
  "  (inbound|outbound) [sa_id <n>] laddr_start <ip4|ip6>\n"            \
  "  laddr_stop <ip4|ip6> raddr_start <ip4|ip6> raddr_stop <ip4|ip6>\n" \
  "  [lport_start <n> lport_stop <n>] [rport_start <n> rport_stop <n>]" )\
_(ipsec_sa_set_key, "sa_id <n> crypto_key <hex> integ_key <hex>")       \
_(ikev2_profile_add_del, "name <profile_name> [del]")                   \
_(ikev2_profile_set_auth, "name <profile_name> auth_method <method>\n"  \
  "(auth_data 0x<data> | auth_data <data>)")                            \
_(ikev2_profile_set_id, "name <profile_name> id_type <type>\n"          \
  "(id_data 0x<data> | id_data <data>) (local|remote)")                 \
_(ikev2_profile_set_ts, "name <profile_name> protocol <proto>\n"        \
  "start_port <port> end_port <port> start_addr <ip4> end_addr <ip4>\n" \
  "(local|remote)")                                                     \
_(ikev2_set_local_key, "file <absolute_file_path>")                     \
_(delete_loopback,"sw_if_index <nn>")                                   \
_(bd_ip_mac_add_del, "bd_id <bridge-domain-id> <ip4/6-addr> <mac-addr> [del]") \
_(map_add_domain,                                                       \
  "ip4-pfx <ip4pfx> ip6-pfx <ip6pfx> "					\
  "ip6-src <ip6addr> "							\
  "ea-bits-len <n> psid-offset <n> psid-len <n>")			\
_(map_del_domain, "index <n>")                                          \
_(map_add_del_rule,                                                     \
  "index <n> psid <n> dst <ip6addr> [del]")                             \
_(map_domain_dump, "")                                                  \
_(map_rule_dump, "index <map-domain>")                                  \
_(want_interface_events,  "enable|disable")                             \
_(want_stats,"enable|disable")                                          \
_(get_first_msg_id, "client <name>")					\
_(cop_interface_enable_disable, "<intfc> | sw_if_index <nn> [disable]") \
_(cop_whitelist_enable_disable, "<intfc> | sw_if_index <nn>\n"		\
  "fib-id <nn> [ip4][ip6][default]")					\
_(get_node_graph, " ")                                                  \
_(sw_interface_clear_stats,"<intfc> | sw_if_index <nn>")                \
_(trace_profile_add, "id <nn> trace-type <0x1f|0x3|0x9|0x11|0x19> "     \
  "trace-elts <nn> trace-tsp <0|1|2|3> node-id <node id in hex> "       \
  "app-data <app_data in hex> [pow] [ppc <encap|decap>]")               \
_(trace_profile_apply, "id <nn> <ip6-address>/<width>"                  \
  " vrf_id <nn>  add | pop | none")                                     \
_(trace_profile_del, "")                                                \
_(lisp_add_del_locator_set, "locator-set <locator_name> [del]")         \
_(lisp_add_del_locator, "locator-set <locator_name> "                   \
                        "iface <intf> | sw_if_index <sw_if_index> "     \
                        "p <priority> w <weight> [del]")                \
_(lisp_add_del_local_eid, "<ipv4|ipv6>/<prefix> "                       \
                          "locator-set <locator_name> [del]")           \
_(lisp_gpe_add_del_fwd_entry, "eid <ip4|6-addr>/<prefix> "              \
    "sloc <ip4/6-addr> dloc <ip4|6-addr> [del]")                        \
_(lisp_add_del_map_resolver, "<ip4|6-addr> [del]")                      \
_(lisp_gpe_enable_disable, "enable|disable")                            \
_(lisp_enable_disable, "enable|disable")                                \
_(lisp_gpe_add_del_iface, "up|down")                                    \
_(lisp_add_del_remote_mapping, "add|del vni <vni> deid <dest-eid> seid" \
                               " <src-eid> rloc <locator> p <prio> "    \
                               "w <weight> [rloc <loc> ... ] "          \
                               "action <action>")                       \
_(lisp_add_del_adjacency, "add|del vni <vni> deid <dest-eid> seid "     \
                          "<src-eid> rloc <locator> p <prio> w <weight>"\
                          "[rloc <loc> ... ] action <action>")          \
_(lisp_pitr_set_locator_set, "locator-set <loc-set-name> | del")        \
_(lisp_add_del_map_request_itr_rlocs, "<loc-set-name> [del]")           \
_(lisp_eid_table_add_del_map, "[del] vni <vni> vrf <vrf>")              \
_(lisp_locator_set_dump, "")                                            \
_(lisp_local_eid_table_dump, "")                                        \
_(lisp_eid_table_map_dump, "")                                          \
_(lisp_gpe_tunnel_dump, "")                                             \
_(lisp_map_resolver_dump, "")                                           \
_(lisp_enable_disable_status_dump, "")                                  \
_(lisp_get_map_request_itr_rlocs, "")                                   \
_(show_lisp_pitr, "")                                                   \
_(af_packet_create, "name <host interface name> [hw_addr <mac>]")       \
_(af_packet_delete, "name <host interface name>")                       \
_(policer_add_del, "name <policer name> <params> [del]")                \
_(policer_dump, "[name <policer name>]")                                \
_(netmap_create, "name <interface name> [hw-addr <mac>] [pipe] "        \
    "[master|slave]")                                                   \
_(netmap_delete, "name <interface name>")                               \
_(mpls_gre_tunnel_dump, "tunnel_index <tunnel-id>")                     \
_(mpls_eth_tunnel_dump, "tunnel_index <tunnel-id>")                     \
_(mpls_fib_encap_dump, "")                                              \
_(mpls_fib_decap_dump, "")                                              \
_(classify_table_ids, "")                                               \
_(classify_table_by_interface, "sw_if_index <sw_if_index>")             \
_(classify_table_info, "table_id <nn>")                                 \
_(classify_session_dump, "table_id <nn>")                               \
_(ipfix_enable, "collector_address <ip4> [collector_port <nn>] "        \
                "src_address <ip4> [fib_id <nn>] [path_mtu <nn>] "      \
                "[template_interval <nn>]")                             \
_(ipfix_dump, "")                                                       \
_(get_next_index, "node-name <node-name> next-node-name <node-name>")   \
_(pg_create_interface, "if_id <nn>")                                    \
_(pg_capture, "if_id <nnn> pcap <file_name> count <nnn> [disable]")     \
_(pg_enable_disable, "[stream <id>] disable")

/* List of command functions, CLI names map directly to functions */
#define foreach_cli_function                                    \
_(comment, "usage: comment <ignore-rest-of-line>")		\
_(dump_interface_table, "usage: dump_interface_table")          \
_(dump_sub_interface_table, "usage: dump_sub_interface_table")  \
_(dump_ipv4_table, "usage: dump_ipv4_table")                    \
_(dump_ipv6_table, "usage: dump_ipv6_table")                    \
_(dump_stats_table, "usage: dump_stats_table")                  \
_(dump_macro_table, "usage: dump_macro_table ")                 \
_(dump_node_table, "usage: dump_node_table")			\
_(echo, "usage: echo <message>")				\
_(exec, "usage: exec <vpe-debug-CLI-command>")                  \
_(help, "usage: help")                                          \
_(q, "usage: quit")                                             \
_(quit, "usage: quit")                                          \
_(search_node_table, "usage: search_node_table <name>...")	\
_(set, "usage: set <variable-name> <value>")                    \
_(script, "usage: script <file-name>")                          \
_(unset, "usage: unset <variable-name>")

#define _(N,n)                                  \
    static void vl_api_##n##_t_handler_uni      \
    (vl_api_##n##_t * mp)                       \
    {                                           \
        vat_main_t * vam = &vat_main;           \
        if (vam->json_output) {                 \
            vl_api_##n##_t_handler_json(mp);    \
        } else {                                \
            vl_api_##n##_t_handler(mp);         \
        }                                       \
    }
foreach_vpe_api_reply_msg;
#undef _

void vat_api_hookup (vat_main_t *vam)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler_uni,          \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_vpe_api_reply_msg;
#undef _

    vl_msg_api_set_first_available_msg_id (VL_MSG_FIRST_AVAILABLE);

    vam->sw_if_index_by_interface_name = 
        hash_create_string (0, sizeof (uword));

    vam->function_by_name = 
        hash_create_string (0, sizeof(uword));

    vam->help_by_name = 
        hash_create_string (0, sizeof(uword));

    /* API messages we can send */
#define _(n,h) hash_set_mem (vam->function_by_name, #n, api_##n);
    foreach_vpe_api_msg;
#undef _

    /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
    foreach_vpe_api_msg;
#undef _

    /* CLI functions */
#define _(n,h) hash_set_mem (vam->function_by_name, #n, n);
    foreach_cli_function;
#undef _

    /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
    foreach_cli_function;
#undef _
}

#undef vl_api_version
#define vl_api_version(n,v) static u32 vpe_api_version = v;
#include <vpp-api/vpe.api.h>
#undef vl_api_version

void vl_client_add_api_signatures (vl_api_memclnt_create_t *mp) 
{
    /* 
     * Send the main API signature in slot 0. This bit of code must
     * match the checks in ../vpe/api/api.c: vl_msg_api_version_check().
     */
    mp->api_versions[0] = clib_host_to_net_u32 (vpe_api_version);
}
