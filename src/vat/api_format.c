/*
 *------------------------------------------------------------------
 * api_format.c
 *
 * Copyright (c) 2014-2016 Cisco and/or its affiliates.
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
#include <vpp/api/types.h>
#include <vppinfra/socket.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip_neighbor.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2tp/l2tp.h>
#include <vnet/vxlan/vxlan.h>
#include <vnet/geneve/geneve.h>
#include <vnet/gre/gre.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/lisp-gpe/lisp_gpe.h>

#include <vpp/api/vpe_msg_enum.h>
#include <vnet/l2/l2_classify.h>
#include <vnet/l2/l2_vtr.h>
#include <vnet/classify/in_out_acl.h>
#include <vnet/classify/policer_classify.h>
#include <vnet/classify/flow_classify.h>
#include <vnet/mpls/mpls.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ikev2.h>
#include <inttypes.h>
#include <vnet/cop/cop.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/ip/ip_source_and_port_range_check.h>
#include <vnet/policer/xlate.h>
#include <vnet/span/span.h>
#include <vnet/policer/policer.h>
#include <vnet/policer/police.h>
#include <vnet/mfib/mfib_types.h>
#include <vnet/dhcp/dhcp_proxy.h>
#include <vnet/bonding/node.h>
#include <vnet/qos/qos_types.h>
#include "vat/json_format.h"
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

#include <inttypes.h>
#include <sys/stat.h>

#define vl_typedefs		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun

#define __plugin_msg_base 0
#include <vlibapi/vat_helper_macros.h>

#if VPP_API_TEST_BUILTIN == 0
#include <netdb.h>

u32
vl (void *p)
{
  return vec_len (p);
}

int
vat_socket_connect (vat_main_t * vam)
{
  int rv;
  vam->socket_client_main = &socket_client_main;
  if ((rv = vl_socket_client_connect ((char *) vam->socket_name,
				      "vpp_api_test",
				      0 /* default socket rx, tx buffer */ )))
    return rv;
  /* vpp expects the client index in network order */
  vam->my_client_index = htonl (socket_client_main.client_index);
  return 0;
}
#else /* vpp built-in case, we don't do sockets... */
int
vat_socket_connect (vat_main_t * vam)
{
  return 0;
}

int
vl_socket_client_read (int wait)
{
  return -1;
};

int
vl_socket_client_write ()
{
  return -1;
};

void *
vl_socket_client_msg_alloc (int nbytes)
{
  return 0;
}
#endif


f64
vat_time_now (vat_main_t * vam)
{
#if VPP_API_TEST_BUILTIN
  return vlib_time_now (vam->vlib_main);
#else
  return clib_time_now (&vam->clib_time);
#endif
}

void
errmsg (char *fmt, ...)
{
  vat_main_t *vam = &vat_main;
  va_list va;
  u8 *s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  vec_add1 (s, 0);

#if VPP_API_TEST_BUILTIN
  vlib_cli_output (vam->vlib_main, (char *) s);
#else
  {
    if (vam->ifp != stdin)
      fformat (vam->ofp, "%s(%d): \n", vam->current_file,
	       vam->input_line_number);
    fformat (vam->ofp, (char *) s);
    fflush (vam->ofp);
  }
#endif

  vec_free (s);
}

#if VPP_API_TEST_BUILTIN == 0
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

static uword
api_unformat_hw_if_index (unformat_input_t * input, va_list * args)
{
  return 0;
}

/* Parse an IP4 address %d.%d.%d.%d. */
uword
unformat_ip4_address (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  unsigned a[4];

  if (!unformat (input, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]))
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
  u8 *result = va_arg (*args, u8 *);
  u32 i, a[6];

  if (!unformat (input, "%_%x:%x:%x:%x:%x:%x%_",
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
  u16 *result = va_arg (*args, u16 *);
  int type;

  /* Numeric type. */
  if (unformat (input, "0x%x", &type) || unformat (input, "%d", &type))
    {
      if (type >= (1 << 16))
	return 0;
      *result = type;
      return 1;
    }
  return 0;
}

/* Parse an IP6 address. */
uword
unformat_ip6_address (unformat_input_t * input, va_list * args)
{
  ip6_address_t *result = va_arg (*args, ip6_address_t *);
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
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = IPSEC_POLICY_ACTION_##f;
  foreach_ipsec_policy_action
#undef _
    else
    return 0;
  return 1;
}

uword
unformat_ipsec_crypto_alg (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = IPSEC_CRYPTO_ALG_##f;
  foreach_ipsec_crypto_alg
#undef _
    else
    return 0;
  return 1;
}

u8 *
format_ipsec_crypto_alg (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v,f,str) case IPSEC_CRYPTO_ALG_##f: t = (u8 *) str; break;
      foreach_ipsec_crypto_alg
#undef _
    default:
      return format (s, "unknown");
    }
  return format (s, "%s", t);
}

uword
unformat_ipsec_integ_alg (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = IPSEC_INTEG_ALG_##f;
  foreach_ipsec_integ_alg
#undef _
    else
    return 0;
  return 1;
}

u8 *
format_ipsec_integ_alg (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v,f,str) case IPSEC_INTEG_ALG_##f: t = (u8 *) str; break;
      foreach_ipsec_integ_alg
#undef _
    default:
      return format (s, "unknown");
    }
  return format (s, "%s", t);
}

uword
unformat_ikev2_auth_method (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = IKEV2_AUTH_METHOD_##f;
  foreach_ikev2_auth_method
#undef _
    else
    return 0;
  return 1;
}

uword
unformat_ikev2_id_type (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = IKEV2_ID_TYPE_##f;
  foreach_ikev2_id_type
#undef _
    else
    return 0;
  return 1;
}
#else /* VPP_API_TEST_BUILTIN == 1 */
static uword
api_unformat_sw_if_index (unformat_input_t * input, va_list * args)
{
  vat_main_t *vam __attribute__ ((unused)) = va_arg (*args, vat_main_t *);
  vnet_main_t *vnm = vnet_get_main ();
  u32 *result = va_arg (*args, u32 *);

  return unformat (input, "%U", unformat_vnet_sw_interface, vnm, result);
}

static uword
api_unformat_hw_if_index (unformat_input_t * input, va_list * args)
{
  vat_main_t *vam __attribute__ ((unused)) = va_arg (*args, vat_main_t *);
  vnet_main_t *vnm = vnet_get_main ();
  u32 *result = va_arg (*args, u32 *);

  return unformat (input, "%U", unformat_vnet_hw_interface, vnm, result);
}

#endif /* VPP_API_TEST_BUILTIN */

static uword
unformat_policer_rate_type (unformat_input_t * input, va_list * args)
{
  u8 *r = va_arg (*args, u8 *);

  if (unformat (input, "kbps"))
    *r = SSE2_QOS_RATE_KBPS;
  else if (unformat (input, "pps"))
    *r = SSE2_QOS_RATE_PPS;
  else
    return 0;
  return 1;
}

static uword
unformat_policer_round_type (unformat_input_t * input, va_list * args)
{
  u8 *r = va_arg (*args, u8 *);

  if (unformat (input, "closest"))
    *r = SSE2_QOS_ROUND_TO_CLOSEST;
  else if (unformat (input, "up"))
    *r = SSE2_QOS_ROUND_TO_UP;
  else if (unformat (input, "down"))
    *r = SSE2_QOS_ROUND_TO_DOWN;
  else
    return 0;
  return 1;
}

static uword
unformat_policer_type (unformat_input_t * input, va_list * args)
{
  u8 *r = va_arg (*args, u8 *);

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

static uword
unformat_dscp (unformat_input_t * input, va_list * va)
{
  u8 *r = va_arg (*va, u8 *);

  if (0);
#define _(v,f,str) else if (unformat (input, str)) *r = VNET_DSCP_##f;
  foreach_vnet_dscp
#undef _
    else
    return 0;
  return 1;
}

static uword
unformat_policer_action_type (unformat_input_t * input, va_list * va)
{
  sse2_qos_pol_action_params_st *a
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

static uword
unformat_policer_classify_table_type (unformat_input_t * input, va_list * va)
{
  u32 *r = va_arg (*va, u32 *);
  u32 tid;

  if (unformat (input, "ip4"))
    tid = POLICER_CLASSIFY_TABLE_IP4;
  else if (unformat (input, "ip6"))
    tid = POLICER_CLASSIFY_TABLE_IP6;
  else if (unformat (input, "l2"))
    tid = POLICER_CLASSIFY_TABLE_L2;
  else
    return 0;

  *r = tid;
  return 1;
}

static uword
unformat_flow_classify_table_type (unformat_input_t * input, va_list * va)
{
  u32 *r = va_arg (*va, u32 *);
  u32 tid;

  if (unformat (input, "ip4"))
    tid = FLOW_CLASSIFY_TABLE_IP4;
  else if (unformat (input, "ip6"))
    tid = FLOW_CLASSIFY_TABLE_IP6;
  else
    return 0;

  *r = tid;
  return 1;
}

static const char *mfib_flag_names[] = MFIB_ENTRY_NAMES_SHORT;
static const char *mfib_flag_long_names[] = MFIB_ENTRY_NAMES_LONG;
static const char *mfib_itf_flag_long_names[] = MFIB_ITF_NAMES_LONG;
static const char *mfib_itf_flag_names[] = MFIB_ITF_NAMES_SHORT;

#if (VPP_API_TEST_BUILTIN==0)
uword
unformat_mfib_itf_flags (unformat_input_t * input, va_list * args)
{
  mfib_itf_flags_t old, *iflags = va_arg (*args, mfib_itf_flags_t *);
  mfib_itf_attribute_t attr;

  old = *iflags;
  FOR_EACH_MFIB_ITF_ATTRIBUTE (attr)
  {
    if (unformat (input, mfib_itf_flag_long_names[attr]))
      *iflags |= (1 << attr);
  }
  FOR_EACH_MFIB_ITF_ATTRIBUTE (attr)
  {
    if (unformat (input, mfib_itf_flag_names[attr]))
      *iflags |= (1 << attr);
  }

  return (old == *iflags ? 0 : 1);
}

uword
unformat_mfib_entry_flags (unformat_input_t * input, va_list * args)
{
  mfib_entry_flags_t old, *eflags = va_arg (*args, mfib_entry_flags_t *);
  mfib_entry_attribute_t attr;

  old = *eflags;
  FOR_EACH_MFIB_ATTRIBUTE (attr)
  {
    if (unformat (input, mfib_flag_long_names[attr]))
      *eflags |= (1 << attr);
  }
  FOR_EACH_MFIB_ATTRIBUTE (attr)
  {
    if (unformat (input, mfib_flag_names[attr]))
      *eflags |= (1 << attr);
  }

  return (old == *eflags ? 0 : 1);
}

u8 *
format_ip4_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

u8 *
format_ip6_address (u8 * s, va_list * args)
{
  ip6_address_t *a = va_arg (*args, ip6_address_t *);
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
      if ((!is_zero && n_zeros > max_n_zeros)
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
u8 *
format_ip46_address (u8 * s, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  ip46_type_t type = va_arg (*args, ip46_type_t);
  int is_ip4 = 1;

  switch (type)
    {
    case IP46_TYPE_ANY:
      is_ip4 = ip46_address_is_ip4 (ip46);
      break;
    case IP46_TYPE_IP4:
      is_ip4 = 1;
      break;
    case IP46_TYPE_IP6:
      is_ip4 = 0;
      break;
    }

  return is_ip4 ?
    format (s, "%U", format_ip4_address, &ip46->ip4) :
    format (s, "%U", format_ip6_address, &ip46->ip6);
}

u8 *
format_ethernet_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);

  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
		 a[0], a[1], a[2], a[3], a[4], a[5]);
}
#endif

static void
increment_v4_address (ip4_address_t * a)
{
  u32 v;

  v = ntohl (a->as_u32) + 1;
  a->as_u32 = ntohl (v);
}

static void
increment_v6_address (ip6_address_t * a)
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

static void
increment_mac_address (u8 * mac)
{
  u64 tmp = *((u64 *) mac);
  tmp = clib_net_to_host_u64 (tmp);
  tmp += 1 << 16;		/* skip unused (least significant) octets */
  tmp = clib_host_to_net_u64 (tmp);

  clib_memcpy (mac, &tmp, 6);
}

static void vl_api_create_loopback_reply_t_handler
  (vl_api_create_loopback_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  vam->retval = retval;
  vam->regenerate_interface_table = 1;
  vam->sw_if_index = ntohl (mp->sw_if_index);
  vam->result_ready = 1;
}

static void vl_api_create_loopback_reply_t_handler_json
  (vl_api_create_loopback_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);
  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_create_loopback_instance_reply_t_handler
  (vl_api_create_loopback_instance_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  vam->retval = retval;
  vam->regenerate_interface_table = 1;
  vam->sw_if_index = ntohl (mp->sw_if_index);
  vam->result_ready = 1;
}

static void vl_api_create_loopback_instance_reply_t_handler_json
  (vl_api_create_loopback_instance_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);
  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_af_packet_create_reply_t_handler
  (vl_api_af_packet_create_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  vam->retval = retval;
  vam->regenerate_interface_table = 1;
  vam->sw_if_index = ntohl (mp->sw_if_index);
  vam->result_ready = 1;
}

static void vl_api_af_packet_create_reply_t_handler_json
  (vl_api_af_packet_create_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_create_vlan_subif_reply_t_handler
  (vl_api_create_vlan_subif_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  vam->retval = retval;
  vam->regenerate_interface_table = 1;
  vam->sw_if_index = ntohl (mp->sw_if_index);
  vam->result_ready = 1;
}

static void vl_api_create_vlan_subif_reply_t_handler_json
  (vl_api_create_vlan_subif_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_create_subif_reply_t_handler
  (vl_api_create_subif_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  vam->retval = retval;
  vam->regenerate_interface_table = 1;
  vam->sw_if_index = ntohl (mp->sw_if_index);
  vam->result_ready = 1;
}

static void vl_api_create_subif_reply_t_handler_json
  (vl_api_create_subif_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_interface_name_renumber_reply_t_handler
  (vl_api_interface_name_renumber_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  vam->retval = retval;
  vam->regenerate_interface_table = 1;
  vam->result_ready = 1;
}

static void vl_api_interface_name_renumber_reply_t_handler_json
  (vl_api_interface_name_renumber_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

/*
 * Special-case: build the interface table, maintain
 * the next loopback sw_if_index vbl.
 */
static void vl_api_sw_interface_details_t_handler
  (vl_api_sw_interface_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u8 *s = format (0, "%s%c", mp->interface_name, 0);

  hash_set_mem (vam->sw_if_index_by_interface_name, s,
		ntohl (mp->sw_if_index));

  /* In sub interface case, fill the sub interface table entry */
  if (mp->sw_if_index != mp->sup_sw_if_index)
    {
      sw_interface_subif_t *sub = NULL;

      vec_add2 (vam->sw_if_subif_table, sub, 1);

      vec_validate (sub->interface_name, strlen ((char *) s) + 1);
      strncpy ((char *) sub->interface_name, (char *) s,
	       vec_len (sub->interface_name));
      sub->sw_if_index = ntohl (mp->sw_if_index);
      sub->sub_id = ntohl (mp->sub_id);

      sub->sub_dot1ad = mp->sub_dot1ad;
      sub->sub_number_of_tags = mp->sub_number_of_tags;
      sub->sub_outer_vlan_id = ntohs (mp->sub_outer_vlan_id);
      sub->sub_inner_vlan_id = ntohs (mp->sub_inner_vlan_id);
      sub->sub_exact_match = mp->sub_exact_match;
      sub->sub_default = mp->sub_default;
      sub->sub_outer_vlan_id_any = mp->sub_outer_vlan_id_any;
      sub->sub_inner_vlan_id_any = mp->sub_inner_vlan_id_any;

      /* vlan tag rewrite */
      sub->vtr_op = ntohl (mp->vtr_op);
      sub->vtr_push_dot1q = ntohl (mp->vtr_push_dot1q);
      sub->vtr_tag1 = ntohl (mp->vtr_tag1);
      sub->vtr_tag2 = ntohl (mp->vtr_tag2);
    }
}

static void vl_api_sw_interface_details_t_handler_json
  (vl_api_sw_interface_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  vat_json_object_add_uint (node, "sup_sw_if_index",
			    ntohl (mp->sup_sw_if_index));
  vat_json_object_add_uint (node, "l2_address_length",
			    ntohl (mp->l2_address_length));
  vat_json_object_add_bytes (node, "l2_address", mp->l2_address,
			     sizeof (mp->l2_address));
  vat_json_object_add_string_copy (node, "interface_name",
				   mp->interface_name);
  vat_json_object_add_uint (node, "admin_up_down", mp->admin_up_down);
  vat_json_object_add_uint (node, "link_up_down", mp->link_up_down);
  vat_json_object_add_uint (node, "link_duplex", mp->link_duplex);
  vat_json_object_add_uint (node, "link_speed", mp->link_speed);
  vat_json_object_add_uint (node, "mtu", ntohs (mp->link_mtu));
  vat_json_object_add_uint (node, "sub_id", ntohl (mp->sub_id));
  vat_json_object_add_uint (node, "sub_dot1ad", mp->sub_dot1ad);
  vat_json_object_add_uint (node, "sub_number_of_tags",
			    mp->sub_number_of_tags);
  vat_json_object_add_uint (node, "sub_outer_vlan_id",
			    ntohs (mp->sub_outer_vlan_id));
  vat_json_object_add_uint (node, "sub_inner_vlan_id",
			    ntohs (mp->sub_inner_vlan_id));
  vat_json_object_add_uint (node, "sub_exact_match", mp->sub_exact_match);
  vat_json_object_add_uint (node, "sub_default", mp->sub_default);
  vat_json_object_add_uint (node, "sub_outer_vlan_id_any",
			    mp->sub_outer_vlan_id_any);
  vat_json_object_add_uint (node, "sub_inner_vlan_id_any",
			    mp->sub_inner_vlan_id_any);
  vat_json_object_add_uint (node, "vtr_op", ntohl (mp->vtr_op));
  vat_json_object_add_uint (node, "vtr_push_dot1q",
			    ntohl (mp->vtr_push_dot1q));
  vat_json_object_add_uint (node, "vtr_tag1", ntohl (mp->vtr_tag1));
  vat_json_object_add_uint (node, "vtr_tag2", ntohl (mp->vtr_tag2));
  if (mp->sub_dot1ah)
    {
      vat_json_object_add_string_copy (node, "pbb_vtr_dmac",
				       format (0, "%U",
					       format_ethernet_address,
					       &mp->b_dmac));
      vat_json_object_add_string_copy (node, "pbb_vtr_smac",
				       format (0, "%U",
					       format_ethernet_address,
					       &mp->b_smac));
      vat_json_object_add_uint (node, "pbb_vtr_b_vlanid", mp->b_vlanid);
      vat_json_object_add_uint (node, "pbb_vtr_i_sid", mp->i_sid);
    }
}

#if VPP_API_TEST_BUILTIN == 0
static void vl_api_sw_interface_event_t_handler
  (vl_api_sw_interface_event_t * mp)
{
  vat_main_t *vam = &vat_main;
  if (vam->interface_event_display)
    errmsg ("interface flags: sw_if_index %d %s %s",
	    ntohl (mp->sw_if_index),
	    mp->admin_up_down ? "admin-up" : "admin-down",
	    mp->link_up_down ? "link-up" : "link-down");
}
#endif

static void vl_api_sw_interface_event_t_handler_json
  (vl_api_sw_interface_event_t * mp)
{
  /* JSON output not supported */
}

static void
vl_api_cli_reply_t_handler (vl_api_cli_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  vam->retval = retval;
  vam->shmem_result = uword_to_pointer (mp->reply_in_shmem, u8 *);
  vam->result_ready = 1;
}

static void
vl_api_cli_reply_t_handler_json (vl_api_cli_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;
  api_main_t *am = &api_main;
  void *oldheap;
  u8 *reply;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "reply_in_shmem",
			    ntohl (mp->reply_in_shmem));
  /* Toss the shared-memory original... */
  pthread_mutex_lock (&am->vlib_rp->mutex);
  oldheap = svm_push_data_heap (am->vlib_rp);

  reply = uword_to_pointer (mp->reply_in_shmem, u8 *);
  vec_free (reply);

  svm_pop_heap (oldheap);
  pthread_mutex_unlock (&am->vlib_rp->mutex);

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
vl_api_cli_inband_reply_t_handler (vl_api_cli_inband_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);
  u32 length = vl_api_string_len (&mp->reply);

  vec_reset_length (vam->cmd_reply);

  vam->retval = retval;
  if (retval == 0)
    {
      vec_validate (vam->cmd_reply, length);
      clib_memcpy ((char *) (vam->cmd_reply),
		   vl_api_from_api_string (&mp->reply), length);
      vam->cmd_reply[length] = 0;
    }
  vam->result_ready = 1;
}

static void
vl_api_cli_inband_reply_t_handler_json (vl_api_cli_inband_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vec_reset_length (vam->cmd_reply);

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_string_copy (&node, "reply",
				   vl_api_from_api_string (&mp->reply));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_classify_add_del_table_reply_t_handler
  (vl_api_classify_add_del_table_reply_t * mp)
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
      if (retval == 0 &&
	  ((mp->new_table_index != 0xFFFFFFFF) ||
	   (mp->skip_n_vectors != 0xFFFFFFFF) ||
	   (mp->match_n_vectors != 0xFFFFFFFF)))
	/*
	 * Note: this is just barely thread-safe, depends on
	 * the main thread spinning waiting for an answer...
	 */
	errmsg ("new index %d, skip_n_vectors %d, match_n_vectors %d",
		ntohl (mp->new_table_index),
		ntohl (mp->skip_n_vectors), ntohl (mp->match_n_vectors));
      vam->result_ready = 1;
    }
}

static void vl_api_classify_add_del_table_reply_t_handler_json
  (vl_api_classify_add_del_table_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "new_table_index",
			    ntohl (mp->new_table_index));
  vat_json_object_add_uint (&node, "skip_n_vectors",
			    ntohl (mp->skip_n_vectors));
  vat_json_object_add_uint (&node, "match_n_vectors",
			    ntohl (mp->match_n_vectors));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_get_node_index_reply_t_handler
  (vl_api_get_node_index_reply_t * mp)
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
      if (retval == 0)
	errmsg ("node index %d", ntohl (mp->node_index));
      vam->result_ready = 1;
    }
}

static void vl_api_get_node_index_reply_t_handler_json
  (vl_api_get_node_index_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "node_index", ntohl (mp->node_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_get_next_index_reply_t_handler
  (vl_api_get_next_index_reply_t * mp)
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
      if (retval == 0)
	errmsg ("next node index %d", ntohl (mp->next_index));
      vam->result_ready = 1;
    }
}

static void vl_api_get_next_index_reply_t_handler_json
  (vl_api_get_next_index_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "next_index", ntohl (mp->next_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_add_node_next_reply_t_handler
  (vl_api_add_node_next_reply_t * mp)
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
      if (retval == 0)
	errmsg ("next index %d", ntohl (mp->next_index));
      vam->result_ready = 1;
    }
}

static void vl_api_add_node_next_reply_t_handler_json
  (vl_api_add_node_next_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "next_index", ntohl (mp->next_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_show_version_reply_t_handler
  (vl_api_show_version_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (retval >= 0)
    {
      char *s;
      char *p = (char *) &mp->program;

      s = vl_api_from_api_string_c ((vl_api_string_t *) p);
      errmsg ("        program: %s\n", s);
      free (s);

      p +=
	vl_api_string_len ((vl_api_string_t *) p) + sizeof (vl_api_string_t);
      s = vl_api_from_api_string_c ((vl_api_string_t *) p);
      errmsg ("        version: %s\n", s);
      free (s);

      p +=
	vl_api_string_len ((vl_api_string_t *) p) + sizeof (vl_api_string_t);
      s = vl_api_from_api_string_c ((vl_api_string_t *) p);
      errmsg ("     build date: %s\n", s);
      free (s);

      p +=
	vl_api_string_len ((vl_api_string_t *) p) + sizeof (vl_api_string_t);
      s = vl_api_from_api_string_c ((vl_api_string_t *) p);
      errmsg ("build directory: %s\n", s);
      free (s);
    }
  vam->retval = retval;
  vam->result_ready = 1;
}

static void vl_api_show_version_reply_t_handler_json
  (vl_api_show_version_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  char *p = (char *) &mp->program;
  vat_json_object_add_string_copy (&node, "program",
				   vl_api_from_api_string ((vl_api_string_t *)
							   p));
  p += vl_api_string_len ((vl_api_string_t *) p) + sizeof (u32);
  vat_json_object_add_string_copy (&node, "version",
				   vl_api_from_api_string ((vl_api_string_t *)
							   p));
  p += vl_api_string_len ((vl_api_string_t *) p) + sizeof (u32);
  vat_json_object_add_string_copy (&node, "build_date",
				   vl_api_from_api_string ((vl_api_string_t *)
							   p));
  p += vl_api_string_len ((vl_api_string_t *) p) + sizeof (u32);
  vat_json_object_add_string_copy (&node, "build_directory",
				   vl_api_from_api_string ((vl_api_string_t *)
							   p));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_show_threads_reply_t_handler
  (vl_api_show_threads_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);
  int i, count = 0;

  if (retval >= 0)
    count = ntohl (mp->count);

  for (i = 0; i < count; i++)
    print (vam->ofp,
	   "\n%-2d %-11s %-11s %-5d %-6d %-4d %-6d",
	   ntohl (mp->thread_data[i].id), mp->thread_data[i].name,
	   mp->thread_data[i].type, ntohl (mp->thread_data[i].pid),
	   ntohl (mp->thread_data[i].cpu_id), ntohl (mp->thread_data[i].core),
	   ntohl (mp->thread_data[i].cpu_socket));

  vam->retval = retval;
  vam->result_ready = 1;
}

static void vl_api_show_threads_reply_t_handler_json
  (vl_api_show_threads_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;
  vl_api_thread_data_t *td;
  i32 retval = ntohl (mp->retval);
  int i, count = 0;

  if (retval >= 0)
    count = ntohl (mp->count);

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", retval);
  vat_json_object_add_uint (&node, "count", count);

  for (i = 0; i < count; i++)
    {
      td = &mp->thread_data[i];
      vat_json_object_add_uint (&node, "id", ntohl (td->id));
      vat_json_object_add_string_copy (&node, "name", td->name);
      vat_json_object_add_string_copy (&node, "type", td->type);
      vat_json_object_add_uint (&node, "pid", ntohl (td->pid));
      vat_json_object_add_int (&node, "cpu_id", ntohl (td->cpu_id));
      vat_json_object_add_int (&node, "core", ntohl (td->id));
      vat_json_object_add_int (&node, "cpu_socket", ntohl (td->cpu_socket));
    }

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = retval;
  vam->result_ready = 1;
}

static int
api_show_threads (vat_main_t * vam)
{
  vl_api_show_threads_t *mp;
  int ret;

  print (vam->ofp,
	 "\n%-2s %-11s %-11s %-5s %-6s %-4s %-6s",
	 "ID", "Name", "Type", "LWP", "cpu_id", "Core", "Socket");

  M (SHOW_THREADS, mp);

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_ip4_arp_event_t_handler (vl_api_ip4_arp_event_t * mp)
{
  u32 sw_if_index = ntohl (mp->sw_if_index);
  errmsg ("arp %s event: pid %d address %U new mac %U sw_if_index %d\n",
	  mp->mac_ip ? "mac/ip binding" : "address resolution",
	  ntohl (mp->pid), format_ip4_address, &mp->address,
	  format_ethernet_address, mp->new_mac, sw_if_index);
}

static void
vl_api_ip4_arp_event_t_handler_json (vl_api_ip4_arp_event_t * mp)
{
  /* JSON output not supported */
}

static void
vl_api_ip6_nd_event_t_handler (vl_api_ip6_nd_event_t * mp)
{
  u32 sw_if_index = ntohl (mp->sw_if_index);
  errmsg ("ip6 nd %s event: pid %d address %U new mac %U sw_if_index %d\n",
	  mp->mac_ip ? "mac/ip binding" : "address resolution",
	  ntohl (mp->pid), format_ip6_address, mp->address,
	  format_ethernet_address, mp->new_mac, sw_if_index);
}

static void
vl_api_ip6_nd_event_t_handler_json (vl_api_ip6_nd_event_t * mp)
{
  /* JSON output not supported */
}

static void
vl_api_l2_macs_event_t_handler (vl_api_l2_macs_event_t * mp)
{
  u32 n_macs = ntohl (mp->n_macs);
  errmsg ("L2MAC event received with pid %d cl-idx %d for %d macs: \n",
	  ntohl (mp->pid), mp->client_index, n_macs);
  int i;
  for (i = 0; i < n_macs; i++)
    {
      vl_api_mac_entry_t *mac = &mp->mac[i];
      errmsg (" [%d] sw_if_index %d  mac_addr %U  action %d \n",
	      i + 1, ntohl (mac->sw_if_index),
	      format_ethernet_address, mac->mac_addr, mac->action);
      if (i == 1000)
	break;
    }
}

static void
vl_api_l2_macs_event_t_handler_json (vl_api_l2_macs_event_t * mp)
{
  /* JSON output not supported */
}

#define vl_api_bridge_domain_details_t_endian vl_noop_handler
#define vl_api_bridge_domain_details_t_print vl_noop_handler

/*
 * Special-case: build the bridge domain table, maintain
 * the next bd id vbl.
 */
static void vl_api_bridge_domain_details_t_handler
  (vl_api_bridge_domain_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 n_sw_ifs = ntohl (mp->n_sw_ifs);
  int i;

  print (vam->ofp, "\n%-3s %-3s %-3s %-3s %-3s %-6s %-3s",
	 " ID", "LRN", "FWD", "FLD", "BVI", "UU-FWD", "#IF");

  print (vam->ofp, "%3d %3d %3d %3d %3d %6d %3d",
	 ntohl (mp->bd_id), mp->learn, mp->forward,
	 mp->flood, ntohl (mp->bvi_sw_if_index),
	 ntohl (mp->uu_fwd_sw_if_index), n_sw_ifs);

  if (n_sw_ifs)
    {
      vl_api_bridge_domain_sw_if_t *sw_ifs;
      print (vam->ofp, "\n\n%s %s  %s", "sw_if_index", "SHG",
	     "Interface Name");

      sw_ifs = mp->sw_if_details;
      for (i = 0; i < n_sw_ifs; i++)
	{
	  u8 *sw_if_name = 0;
	  u32 sw_if_index;
	  hash_pair_t *p;

	  sw_if_index = ntohl (sw_ifs->sw_if_index);

	  /* *INDENT-OFF* */
	  hash_foreach_pair (p, vam->sw_if_index_by_interface_name,
			     ({
			       if ((u32) p->value[0] == sw_if_index)
				 {
				   sw_if_name = (u8 *)(p->key);
				   break;
				 }
			     }));
	  /* *INDENT-ON* */
	  print (vam->ofp, "%7d     %3d  %s", sw_if_index,
		 sw_ifs->shg, sw_if_name ? (char *) sw_if_name :
		 "sw_if_index not found!");

	  sw_ifs++;
	}
    }
}

static void vl_api_bridge_domain_details_t_handler_json
  (vl_api_bridge_domain_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node, *array = NULL;
  u32 n_sw_ifs = ntohl (mp->n_sw_ifs);

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "bd_id", ntohl (mp->bd_id));
  vat_json_object_add_uint (node, "flood", mp->flood);
  vat_json_object_add_uint (node, "forward", mp->forward);
  vat_json_object_add_uint (node, "learn", mp->learn);
  vat_json_object_add_uint (node, "bvi_sw_if_index",
			    ntohl (mp->bvi_sw_if_index));
  vat_json_object_add_uint (node, "n_sw_ifs", n_sw_ifs);
  array = vat_json_object_add (node, "sw_if");
  vat_json_init_array (array);



  if (n_sw_ifs)
    {
      vl_api_bridge_domain_sw_if_t *sw_ifs;
      int i;

      sw_ifs = mp->sw_if_details;
      for (i = 0; i < n_sw_ifs; i++)
	{
	  node = vat_json_array_add (array);
	  vat_json_init_object (node);
	  vat_json_object_add_uint (node, "sw_if_index",
				    ntohl (sw_ifs->sw_if_index));
	  vat_json_object_add_uint (node, "shg", sw_ifs->shg);
	  sw_ifs++;
	}
    }
}

static void vl_api_control_ping_reply_t_handler
  (vl_api_control_ping_reply_t * mp)
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
      vam->result_ready = 1;
    }
  if (vam->socket_client_main)
    vam->socket_client_main->control_pings_outstanding--;
}

static void vl_api_control_ping_reply_t_handler_json
  (vl_api_control_ping_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (VAT_JSON_NONE != vam->json_tree.type)
    {
      vat_json_print (vam->ofp, &vam->json_tree);
      vat_json_free (&vam->json_tree);
      vam->json_tree.type = VAT_JSON_NONE;
    }
  else
    {
      /* just print [] */
      vat_json_init_array (&vam->json_tree);
      vat_json_print (vam->ofp, &vam->json_tree);
      vam->json_tree.type = VAT_JSON_NONE;
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_bridge_domain_set_mac_age_reply_t_handler
  (vl_api_bridge_domain_set_mac_age_reply_t * mp)
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
      vam->result_ready = 1;
    }
}

static void vl_api_bridge_domain_set_mac_age_reply_t_handler_json
  (vl_api_bridge_domain_set_mac_age_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
vl_api_l2_flags_reply_t_handler (vl_api_l2_flags_reply_t * mp)
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
      vam->result_ready = 1;
    }
}

static void vl_api_l2_flags_reply_t_handler_json
  (vl_api_l2_flags_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "resulting_feature_bitmap",
			    ntohl (mp->resulting_feature_bitmap));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_bridge_flags_reply_t_handler
  (vl_api_bridge_flags_reply_t * mp)
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
      vam->result_ready = 1;
    }
}

static void vl_api_bridge_flags_reply_t_handler_json
  (vl_api_bridge_flags_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "resulting_feature_bitmap",
			    ntohl (mp->resulting_feature_bitmap));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_tap_connect_reply_t_handler
  (vl_api_tap_connect_reply_t * mp)
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

static void vl_api_tap_connect_reply_t_handler_json
  (vl_api_tap_connect_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;

}

static void
vl_api_tap_modify_reply_t_handler (vl_api_tap_modify_reply_t * mp)
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

static void vl_api_tap_modify_reply_t_handler_json
  (vl_api_tap_modify_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
vl_api_tap_delete_reply_t_handler (vl_api_tap_delete_reply_t * mp)
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
      vam->result_ready = 1;
    }
}

static void vl_api_tap_delete_reply_t_handler_json
  (vl_api_tap_delete_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
vl_api_tap_create_v2_reply_t_handler (vl_api_tap_create_v2_reply_t * mp)
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

static void vl_api_tap_create_v2_reply_t_handler_json
  (vl_api_tap_create_v2_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;

}

static void
vl_api_tap_delete_v2_reply_t_handler (vl_api_tap_delete_v2_reply_t * mp)
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
      vam->result_ready = 1;
    }
}

static void vl_api_tap_delete_v2_reply_t_handler_json
  (vl_api_tap_delete_v2_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
vl_api_bond_create_reply_t_handler (vl_api_bond_create_reply_t * mp)
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

static void vl_api_bond_create_reply_t_handler_json
  (vl_api_bond_create_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
vl_api_bond_delete_reply_t_handler (vl_api_bond_delete_reply_t * mp)
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
      vam->result_ready = 1;
    }
}

static void vl_api_bond_delete_reply_t_handler_json
  (vl_api_bond_delete_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
vl_api_bond_enslave_reply_t_handler (vl_api_bond_enslave_reply_t * mp)
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
      vam->result_ready = 1;
    }
}

static void vl_api_bond_enslave_reply_t_handler_json
  (vl_api_bond_enslave_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
vl_api_bond_detach_slave_reply_t_handler (vl_api_bond_detach_slave_reply_t *
					  mp)
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
      vam->result_ready = 1;
    }
}

static void vl_api_bond_detach_slave_reply_t_handler_json
  (vl_api_bond_detach_slave_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_sw_interface_bond_details_t_handler
  (vl_api_sw_interface_bond_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp,
	 "%-16s %-12d %-12U %-13U %-14u %-14u",
	 mp->interface_name, ntohl (mp->sw_if_index),
	 format_bond_mode, mp->mode, format_bond_load_balance, mp->lb,
	 ntohl (mp->active_slaves), ntohl (mp->slaves));
}

static void vl_api_sw_interface_bond_details_t_handler_json
  (vl_api_sw_interface_bond_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  vat_json_object_add_string_copy (node, "interface_name",
				   mp->interface_name);
  vat_json_object_add_uint (node, "mode", mp->mode);
  vat_json_object_add_uint (node, "load_balance", mp->lb);
  vat_json_object_add_uint (node, "active_slaves", ntohl (mp->active_slaves));
  vat_json_object_add_uint (node, "slaves", ntohl (mp->slaves));
}

static int
api_sw_interface_bond_dump (vat_main_t * vam)
{
  vl_api_sw_interface_bond_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  print (vam->ofp,
	 "\n%-16s %-12s %-12s %-13s %-14s %-14s",
	 "interface name", "sw_if_index", "mode", "load balance",
	 "active slaves", "slaves");

  /* Get list of bond interfaces */
  M (SW_INTERFACE_BOND_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void vl_api_sw_interface_slave_details_t_handler
  (vl_api_sw_interface_slave_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp,
	 "%-25s %-12d %-12d %d", mp->interface_name,
	 ntohl (mp->sw_if_index), mp->is_passive, mp->is_long_timeout);
}

static void vl_api_sw_interface_slave_details_t_handler_json
  (vl_api_sw_interface_slave_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  vat_json_object_add_string_copy (node, "interface_name",
				   mp->interface_name);
  vat_json_object_add_uint (node, "passive", mp->is_passive);
  vat_json_object_add_uint (node, "long_timeout", mp->is_long_timeout);
}

static int
api_sw_interface_slave_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_slave_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 sw_if_index = ~0;
  u8 sw_if_index_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing vpp interface name. ");
      return -99;
    }

  print (vam->ofp,
	 "\n%-25s %-12s %-12s %s",
	 "slave interface name", "sw_if_index", "passive", "long_timeout");

  /* Get list of bond interfaces */
  M (SW_INTERFACE_SLAVE_DUMP, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void vl_api_mpls_tunnel_add_del_reply_t_handler
  (vl_api_mpls_tunnel_add_del_reply_t * mp)
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
  vam->regenerate_interface_table = 1;
}

static void vl_api_mpls_tunnel_add_del_reply_t_handler_json
  (vl_api_mpls_tunnel_add_del_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "tunnel_sw_if_index",
			    ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

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

static void vl_api_l2tpv3_create_tunnel_reply_t_handler_json
  (vl_api_l2tpv3_create_tunnel_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_gpe_add_del_fwd_entry_reply_t_handler
  (vl_api_gpe_add_del_fwd_entry_reply_t * mp)
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
      vam->result_ready = 1;
    }
}

static void vl_api_gpe_add_del_fwd_entry_reply_t_handler_json
  (vl_api_gpe_add_del_fwd_entry_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "fwd_entry_index",
			    clib_net_to_host_u32 (mp->fwd_entry_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

u8 *
format_lisp_transport_protocol (u8 * s, va_list * args)
{
  u32 proto = va_arg (*args, u32);

  switch (proto)
    {
    case 1:
      return format (s, "udp");
    case 2:
      return format (s, "api");
    default:
      return 0;
    }
  return 0;
}

static void vl_api_one_get_transport_protocol_reply_t_handler
  (vl_api_one_get_transport_protocol_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);
  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      u32 proto = mp->protocol;
      print (vam->ofp, "Transport protocol: %U",
	     format_lisp_transport_protocol, proto);
      vam->retval = retval;
      vam->result_ready = 1;
    }
}

static void vl_api_one_get_transport_protocol_reply_t_handler_json
  (vl_api_one_get_transport_protocol_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;
  u8 *s;

  s = format (0, "%U", format_lisp_transport_protocol, mp->protocol);
  vec_add1 (s, 0);

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_string_copy (&node, "transport-protocol", s);

  vec_free (s);
  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_one_add_del_locator_set_reply_t_handler
  (vl_api_one_add_del_locator_set_reply_t * mp)
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
      vam->result_ready = 1;
    }
}

static void vl_api_one_add_del_locator_set_reply_t_handler_json
  (vl_api_one_add_del_locator_set_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "locator_set_index", ntohl (mp->ls_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_vxlan_add_del_tunnel_reply_t_handler
  (vl_api_vxlan_add_del_tunnel_reply_t * mp)
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
  vam->regenerate_interface_table = 1;
}

static void vl_api_vxlan_add_del_tunnel_reply_t_handler_json
  (vl_api_vxlan_add_del_tunnel_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_vxlan_offload_rx_reply_t_handler
  (vl_api_vxlan_offload_rx_reply_t * mp)
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
      vam->result_ready = 1;
    }
}

static void vl_api_vxlan_offload_rx_reply_t_handler_json
  (vl_api_vxlan_offload_rx_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

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

static void vl_api_geneve_add_del_tunnel_reply_t_handler_json
  (vl_api_geneve_add_del_tunnel_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_vxlan_gpe_add_del_tunnel_reply_t_handler
  (vl_api_vxlan_gpe_add_del_tunnel_reply_t * mp)
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
  vam->regenerate_interface_table = 1;
}

static void vl_api_vxlan_gpe_add_del_tunnel_reply_t_handler_json
  (vl_api_vxlan_gpe_add_del_tunnel_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_gre_add_del_tunnel_reply_t_handler
  (vl_api_gre_add_del_tunnel_reply_t * mp)
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

static void vl_api_gre_add_del_tunnel_reply_t_handler_json
  (vl_api_gre_add_del_tunnel_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_create_vhost_user_if_reply_t_handler
  (vl_api_create_vhost_user_if_reply_t * mp)
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
  vam->regenerate_interface_table = 1;
}

static void vl_api_create_vhost_user_if_reply_t_handler_json
  (vl_api_create_vhost_user_if_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_dns_resolve_name_reply_t_handler
  (vl_api_dns_resolve_name_reply_t * mp)
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
      vam->result_ready = 1;

      if (retval == 0)
	{
	  if (mp->ip4_set)
	    clib_warning ("ip4 address %U", format_ip4_address,
			  (ip4_address_t *) mp->ip4_address);
	  if (mp->ip6_set)
	    clib_warning ("ip6 address %U", format_ip6_address,
			  (ip6_address_t *) mp->ip6_address);
	}
      else
	clib_warning ("retval %d", retval);
    }
}

static void vl_api_dns_resolve_name_reply_t_handler_json
  (vl_api_dns_resolve_name_reply_t * mp)
{
  clib_warning ("not implemented");
}

static void vl_api_dns_resolve_ip_reply_t_handler
  (vl_api_dns_resolve_ip_reply_t * mp)
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
      vam->result_ready = 1;

      if (retval == 0)
	{
	  clib_warning ("canonical name %s", mp->name);
	}
      else
	clib_warning ("retval %d", retval);
    }
}

static void vl_api_dns_resolve_ip_reply_t_handler_json
  (vl_api_dns_resolve_ip_reply_t * mp)
{
  clib_warning ("not implemented");
}


static void vl_api_ip_address_details_t_handler
  (vl_api_ip_address_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  static ip_address_details_t empty_ip_address_details = { {0} };
  ip_address_details_t *address = NULL;
  ip_details_t *current_ip_details = NULL;
  ip_details_t *details = NULL;

  details = vam->ip_details_by_sw_if_index[vam->is_ipv6];

  if (!details || vam->current_sw_if_index >= vec_len (details)
      || !details[vam->current_sw_if_index].present)
    {
      errmsg ("ip address details arrived but not stored");
      errmsg ("ip_dump should be called first");
      return;
    }

  current_ip_details = vec_elt_at_index (details, vam->current_sw_if_index);

#define addresses (current_ip_details->addr)

  vec_validate_init_empty (addresses, vec_len (addresses),
			   empty_ip_address_details);

  address = vec_elt_at_index (addresses, vec_len (addresses) - 1);

  clib_memcpy (&address->ip, &mp->ip, sizeof (address->ip));
  address->prefix_length = mp->prefix_length;
#undef addresses
}

static void vl_api_ip_address_details_t_handler_json
  (vl_api_ip_address_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;
  struct in6_addr ip6;
  struct in_addr ip4;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  if (vam->is_ipv6)
    {
      clib_memcpy (&ip6, mp->ip, sizeof (ip6));
      vat_json_object_add_ip6 (node, "ip", ip6);
    }
  else
    {
      clib_memcpy (&ip4, mp->ip, sizeof (ip4));
      vat_json_object_add_ip4 (node, "ip", ip4);
    }
  vat_json_object_add_uint (node, "prefix_length", mp->prefix_length);
}

static void
vl_api_ip_details_t_handler (vl_api_ip_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  static ip_details_t empty_ip_details = { 0 };
  ip_details_t *ip = NULL;
  u32 sw_if_index = ~0;

  sw_if_index = ntohl (mp->sw_if_index);

  vec_validate_init_empty (vam->ip_details_by_sw_if_index[vam->is_ipv6],
			   sw_if_index, empty_ip_details);

  ip = vec_elt_at_index (vam->ip_details_by_sw_if_index[vam->is_ipv6],
			 sw_if_index);

  ip->present = 1;
}

static void
vl_api_ip_details_t_handler_json (vl_api_ip_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  vat_json_array_add_uint (&vam->json_tree,
			   clib_net_to_host_u32 (mp->sw_if_index));
}

static void
vl_api_dhcp_compl_event_t_handler (vl_api_dhcp_compl_event_t * mp)
{
  errmsg ("DHCP compl event: pid %d %s hostname %s host_addr %U "
	  "router_addr %U host_mac %U",
	  ntohl (mp->pid), mp->lease.is_ipv6 ? "ipv6" : "ipv4",
	  mp->lease.hostname,
	  format_ip4_address, &mp->lease.host_address,
	  format_ip4_address, &mp->lease.router_address,
	  format_ethernet_address, mp->lease.host_mac);
}

static void vl_api_dhcp_compl_event_t_handler_json
  (vl_api_dhcp_compl_event_t * mp)
{
  /* JSON output not supported */
}

static void vl_api_get_first_msg_id_reply_t_handler
  (vl_api_get_first_msg_id_reply_t * mp)
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
      vam->result_ready = 1;
    }
  if (retval >= 0)
    {
      errmsg ("first message id %d", ntohs (mp->first_msg_id));
    }
}

static void vl_api_get_first_msg_id_reply_t_handler_json
  (vl_api_get_first_msg_id_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "first_msg_id",
			    (uint) ntohs (mp->first_msg_id));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_get_node_graph_reply_t_handler
  (vl_api_get_node_graph_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  api_main_t *am = &api_main;
  i32 retval = ntohl (mp->retval);
  u8 *pvt_copy, *reply;
  void *oldheap;
  vlib_node_t *node;
  int i;

  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      vam->result_ready = 1;
    }

  /* "Should never happen..." */
  if (retval != 0)
    return;

  reply = uword_to_pointer (mp->reply_in_shmem, u8 *);
  pvt_copy = vec_dup (reply);

  /* Toss the shared-memory original... */
  pthread_mutex_lock (&am->vlib_rp->mutex);
  oldheap = svm_push_data_heap (am->vlib_rp);

  vec_free (reply);

  svm_pop_heap (oldheap);
  pthread_mutex_unlock (&am->vlib_rp->mutex);

  if (vam->graph_nodes)
    {
      hash_free (vam->graph_node_index_by_name);

      for (i = 0; i < vec_len (vam->graph_nodes[0]); i++)
	{
	  node = vam->graph_nodes[0][i];
	  vec_free (node->name);
	  vec_free (node->next_nodes);
	  vec_free (node);
	}
      vec_free (vam->graph_nodes[0]);
      vec_free (vam->graph_nodes);
    }

  vam->graph_node_index_by_name = hash_create_string (0, sizeof (uword));
  vam->graph_nodes = vlib_node_unserialize (pvt_copy);
  vec_free (pvt_copy);

  for (i = 0; i < vec_len (vam->graph_nodes[0]); i++)
    {
      node = vam->graph_nodes[0][i];
      hash_set_mem (vam->graph_node_index_by_name, node->name, i);
    }
}

static void vl_api_get_node_graph_reply_t_handler_json
  (vl_api_get_node_graph_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  api_main_t *am = &api_main;
  void *oldheap;
  vat_json_node_t node;
  u8 *reply;

  /* $$$$ make this real? */
  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "reply_in_shmem", mp->reply_in_shmem);

  reply = uword_to_pointer (mp->reply_in_shmem, u8 *);

  /* Toss the shared-memory original... */
  pthread_mutex_lock (&am->vlib_rp->mutex);
  oldheap = svm_push_data_heap (am->vlib_rp);

  vec_free (reply);

  svm_pop_heap (oldheap);
  pthread_mutex_unlock (&am->vlib_rp->mutex);

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
vl_api_one_locator_details_t_handler (vl_api_one_locator_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u8 *s = 0;

  if (mp->local)
    {
      s = format (s, "%=16d%=16d%=16d",
		  ntohl (mp->sw_if_index), mp->priority, mp->weight);
    }
  else
    {
      s = format (s, "%=16U%=16d%=16d",
		  mp->is_ipv6 ? format_ip6_address :
		  format_ip4_address,
		  mp->ip_address, mp->priority, mp->weight);
    }

  print (vam->ofp, "%v", s);
  vec_free (s);
}

static void
vl_api_one_locator_details_t_handler_json (vl_api_one_locator_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;
  struct in6_addr ip6;
  struct in_addr ip4;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);
  vat_json_init_object (node);

  vat_json_object_add_uint (node, "local", mp->local ? 1 : 0);
  vat_json_object_add_uint (node, "priority", mp->priority);
  vat_json_object_add_uint (node, "weight", mp->weight);

  if (mp->local)
    vat_json_object_add_uint (node, "sw_if_index",
			      clib_net_to_host_u32 (mp->sw_if_index));
  else
    {
      if (mp->is_ipv6)
	{
	  clib_memcpy (&ip6, mp->ip_address, sizeof (ip6));
	  vat_json_object_add_ip6 (node, "address", ip6);
	}
      else
	{
	  clib_memcpy (&ip4, mp->ip_address, sizeof (ip4));
	  vat_json_object_add_ip4 (node, "address", ip4);
	}
    }
}

static void
vl_api_one_locator_set_details_t_handler (vl_api_one_locator_set_details_t *
					  mp)
{
  vat_main_t *vam = &vat_main;
  u8 *ls_name = 0;

  ls_name = format (0, "%s", mp->ls_name);

  print (vam->ofp, "%=10d%=15v", clib_net_to_host_u32 (mp->ls_index),
	 ls_name);
  vec_free (ls_name);
}

static void
  vl_api_one_locator_set_details_t_handler_json
  (vl_api_one_locator_set_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = 0;
  u8 *ls_name = 0;

  ls_name = format (0, "%s", mp->ls_name);
  vec_add1 (ls_name, 0);

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_string_copy (node, "ls_name", ls_name);
  vat_json_object_add_uint (node, "ls_index",
			    clib_net_to_host_u32 (mp->ls_index));
  vec_free (ls_name);
}

typedef struct
{
  u32 spi;
  u8 si;
} __attribute__ ((__packed__)) lisp_nsh_api_t;

uword
unformat_nsh_address (unformat_input_t * input, va_list * args)
{
  lisp_nsh_api_t *nsh = va_arg (*args, lisp_nsh_api_t *);
  return unformat (input, "SPI:%d SI:%d", &nsh->spi, &nsh->si);
}

u8 *
format_nsh_address_vat (u8 * s, va_list * args)
{
  nsh_t *a = va_arg (*args, nsh_t *);
  return format (s, "SPI:%d SI:%d", clib_net_to_host_u32 (a->spi), a->si);
}

static u8 *
format_lisp_flat_eid (u8 * s, va_list * args)
{
  u32 type = va_arg (*args, u32);
  u8 *eid = va_arg (*args, u8 *);
  u32 eid_len = va_arg (*args, u32);

  switch (type)
    {
    case 0:
      return format (s, "%U/%d", format_ip4_address, eid, eid_len);
    case 1:
      return format (s, "%U/%d", format_ip6_address, eid, eid_len);
    case 2:
      return format (s, "%U", format_ethernet_address, eid);
    case 3:
      return format (s, "%U", format_nsh_address_vat, eid);
    }
  return 0;
}

static u8 *
format_lisp_eid_vat (u8 * s, va_list * args)
{
  u32 type = va_arg (*args, u32);
  u8 *eid = va_arg (*args, u8 *);
  u32 eid_len = va_arg (*args, u32);
  u8 *seid = va_arg (*args, u8 *);
  u32 seid_len = va_arg (*args, u32);
  u32 is_src_dst = va_arg (*args, u32);

  if (is_src_dst)
    s = format (s, "%U|", format_lisp_flat_eid, type, seid, seid_len);

  s = format (s, "%U", format_lisp_flat_eid, type, eid, eid_len);

  return s;
}

static void
vl_api_one_eid_table_details_t_handler (vl_api_one_eid_table_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u8 *s = 0, *eid = 0;

  if (~0 == mp->locator_set_index)
    s = format (0, "action: %d", mp->action);
  else
    s = format (0, "%d", clib_net_to_host_u32 (mp->locator_set_index));

  eid = format (0, "%U", format_lisp_eid_vat,
		mp->eid_type,
		mp->eid,
		mp->eid_prefix_len,
		mp->seid, mp->seid_prefix_len, mp->is_src_dst);
  vec_add1 (eid, 0);

  print (vam->ofp, "[%d] %-35s%-20s%-30s%-20d%-20d%-10d%-20s",
	 clib_net_to_host_u32 (mp->vni),
	 eid,
	 mp->is_local ? "local" : "remote",
	 s, clib_net_to_host_u32 (mp->ttl), mp->authoritative,
	 clib_net_to_host_u16 (mp->key_id), mp->key);

  vec_free (s);
  vec_free (eid);
}

static void
vl_api_one_eid_table_details_t_handler_json (vl_api_one_eid_table_details_t
					     * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = 0;
  u8 *eid = 0;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  if (~0 == mp->locator_set_index)
    vat_json_object_add_uint (node, "action", mp->action);
  else
    vat_json_object_add_uint (node, "locator_set_index",
			      clib_net_to_host_u32 (mp->locator_set_index));

  vat_json_object_add_uint (node, "is_local", mp->is_local ? 1 : 0);
  if (mp->eid_type == 3)
    {
      vat_json_node_t *nsh_json = vat_json_object_add (node, "eid");
      vat_json_init_object (nsh_json);
      lisp_nsh_api_t *nsh = (lisp_nsh_api_t *) mp->eid;
      vat_json_object_add_uint (nsh_json, "spi",
				clib_net_to_host_u32 (nsh->spi));
      vat_json_object_add_uint (nsh_json, "si", nsh->si);
    }
  else
    {
      eid = format (0, "%U", format_lisp_eid_vat,
		    mp->eid_type,
		    mp->eid,
		    mp->eid_prefix_len,
		    mp->seid, mp->seid_prefix_len, mp->is_src_dst);
      vec_add1 (eid, 0);
      vat_json_object_add_string_copy (node, "eid", eid);
      vec_free (eid);
    }
  vat_json_object_add_uint (node, "vni", clib_net_to_host_u32 (mp->vni));
  vat_json_object_add_uint (node, "ttl", clib_net_to_host_u32 (mp->ttl));
  vat_json_object_add_uint (node, "authoritative", (mp->authoritative));

  if (mp->key_id)
    {
      vat_json_object_add_uint (node, "key_id",
				clib_net_to_host_u16 (mp->key_id));
      vat_json_object_add_string_copy (node, "key", mp->key);
    }
}

static void
vl_api_one_stats_details_t_handler (vl_api_one_stats_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u8 *seid = 0, *deid = 0;
  u8 *(*format_ip_address_fcn) (u8 *, va_list *) = 0;

  deid = format (0, "%U", format_lisp_eid_vat,
		 mp->eid_type, mp->deid, mp->deid_pref_len, 0, 0, 0);

  seid = format (0, "%U", format_lisp_eid_vat,
		 mp->eid_type, mp->seid, mp->seid_pref_len, 0, 0, 0);

  vec_add1 (deid, 0);
  vec_add1 (seid, 0);

  if (mp->is_ip4)
    format_ip_address_fcn = format_ip4_address;
  else
    format_ip_address_fcn = format_ip6_address;


  print (vam->ofp, "([%d] %s %s) (%U %U) %u %u",
	 clib_net_to_host_u32 (mp->vni),
	 seid, deid,
	 format_ip_address_fcn, mp->lloc,
	 format_ip_address_fcn, mp->rloc,
	 clib_net_to_host_u32 (mp->pkt_count),
	 clib_net_to_host_u32 (mp->bytes));

  vec_free (deid);
  vec_free (seid);
}

static void
vl_api_one_stats_details_t_handler_json (vl_api_one_stats_details_t * mp)
{
  struct in6_addr ip6;
  struct in_addr ip4;
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = 0;
  u8 *deid = 0, *seid = 0;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  deid = format (0, "%U", format_lisp_eid_vat,
		 mp->eid_type, mp->deid, mp->deid_pref_len, 0, 0, 0);

  seid = format (0, "%U", format_lisp_eid_vat,
		 mp->eid_type, mp->seid, mp->seid_pref_len, 0, 0, 0);

  vec_add1 (deid, 0);
  vec_add1 (seid, 0);

  vat_json_object_add_string_copy (node, "seid", seid);
  vat_json_object_add_string_copy (node, "deid", deid);
  vat_json_object_add_uint (node, "vni", clib_net_to_host_u32 (mp->vni));

  if (mp->is_ip4)
    {
      clib_memcpy (&ip4, mp->lloc, sizeof (ip4));
      vat_json_object_add_ip4 (node, "lloc", ip4);
      clib_memcpy (&ip4, mp->rloc, sizeof (ip4));
      vat_json_object_add_ip4 (node, "rloc", ip4);
    }
  else
    {
      clib_memcpy (&ip6, mp->lloc, sizeof (ip6));
      vat_json_object_add_ip6 (node, "lloc", ip6);
      clib_memcpy (&ip6, mp->rloc, sizeof (ip6));
      vat_json_object_add_ip6 (node, "rloc", ip6);
    }
  vat_json_object_add_uint (node, "pkt_count",
			    clib_net_to_host_u32 (mp->pkt_count));
  vat_json_object_add_uint (node, "bytes", clib_net_to_host_u32 (mp->bytes));

  vec_free (deid);
  vec_free (seid);
}

static void
  vl_api_one_eid_table_map_details_t_handler
  (vl_api_one_eid_table_map_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  u8 *line = format (0, "%=10d%=10d",
		     clib_net_to_host_u32 (mp->vni),
		     clib_net_to_host_u32 (mp->dp_table));
  print (vam->ofp, "%v", line);
  vec_free (line);
}

static void
  vl_api_one_eid_table_map_details_t_handler_json
  (vl_api_one_eid_table_map_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);
  vat_json_init_object (node);
  vat_json_object_add_uint (node, "dp_table",
			    clib_net_to_host_u32 (mp->dp_table));
  vat_json_object_add_uint (node, "vni", clib_net_to_host_u32 (mp->vni));
}

static void
  vl_api_one_eid_table_vni_details_t_handler
  (vl_api_one_eid_table_vni_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  u8 *line = format (0, "%d", clib_net_to_host_u32 (mp->vni));
  print (vam->ofp, "%v", line);
  vec_free (line);
}

static void
  vl_api_one_eid_table_vni_details_t_handler_json
  (vl_api_one_eid_table_vni_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);
  vat_json_init_object (node);
  vat_json_object_add_uint (node, "vni", clib_net_to_host_u32 (mp->vni));
}

static void
  vl_api_show_one_map_register_fallback_threshold_reply_t_handler
  (vl_api_show_one_map_register_fallback_threshold_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  int retval = clib_net_to_host_u32 (mp->retval);

  vl_api_show_one_map_register_fallback_threshold_reply_t_endian (mp);
  print (vam->ofp, "fallback threshold value: %d", mp->value);

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_show_one_map_register_fallback_threshold_reply_t_handler_json
  (vl_api_show_one_map_register_fallback_threshold_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t _node, *node = &_node;
  int retval = clib_net_to_host_u32 (mp->retval);

  vl_api_show_one_map_register_fallback_threshold_reply_t_endian (mp);
  vat_json_init_object (node);
  vat_json_object_add_uint (node, "value", mp->value);

  vat_json_print (vam->ofp, node);
  vat_json_free (node);

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_show_one_map_register_state_reply_t_handler
  (vl_api_show_one_map_register_state_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  int retval = clib_net_to_host_u32 (mp->retval);

  print (vam->ofp, "%s", mp->is_enabled ? "enabled" : "disabled");

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_show_one_map_register_state_reply_t_handler_json
  (vl_api_show_one_map_register_state_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t _node, *node = &_node;
  int retval = clib_net_to_host_u32 (mp->retval);

  u8 *s = format (0, "%s", mp->is_enabled ? "enabled" : "disabled");

  vat_json_init_object (node);
  vat_json_object_add_string_copy (node, "state", s);

  vat_json_print (vam->ofp, node);
  vat_json_free (node);

  vam->retval = retval;
  vam->result_ready = 1;
  vec_free (s);
}

static void
  vl_api_show_one_rloc_probe_state_reply_t_handler
  (vl_api_show_one_rloc_probe_state_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  int retval = clib_net_to_host_u32 (mp->retval);

  if (retval)
    goto end;

  print (vam->ofp, "%s", mp->is_enabled ? "enabled" : "disabled");
end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_show_one_rloc_probe_state_reply_t_handler_json
  (vl_api_show_one_rloc_probe_state_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t _node, *node = &_node;
  int retval = clib_net_to_host_u32 (mp->retval);

  u8 *s = format (0, "%s", mp->is_enabled ? "enabled" : "disabled");
  vat_json_init_object (node);
  vat_json_object_add_string_copy (node, "state", s);

  vat_json_print (vam->ofp, node);
  vat_json_free (node);

  vam->retval = retval;
  vam->result_ready = 1;
  vec_free (s);
}

static void
  vl_api_show_one_stats_enable_disable_reply_t_handler
  (vl_api_show_one_stats_enable_disable_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  int retval = clib_net_to_host_u32 (mp->retval);

  if (retval)
    goto end;

  print (vam->ofp, "%s", mp->is_en ? "enabled" : "disabled");
end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_show_one_stats_enable_disable_reply_t_handler_json
  (vl_api_show_one_stats_enable_disable_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t _node, *node = &_node;
  int retval = clib_net_to_host_u32 (mp->retval);

  u8 *s = format (0, "%s", mp->is_en ? "enabled" : "disabled");
  vat_json_init_object (node);
  vat_json_object_add_string_copy (node, "state", s);

  vat_json_print (vam->ofp, node);
  vat_json_free (node);

  vam->retval = retval;
  vam->result_ready = 1;
  vec_free (s);
}

static void
api_gpe_fwd_entry_net_to_host (vl_api_gpe_fwd_entry_t * e)
{
  e->dp_table = clib_net_to_host_u32 (e->dp_table);
  e->fwd_entry_index = clib_net_to_host_u32 (e->fwd_entry_index);
  e->vni = clib_net_to_host_u32 (e->vni);
}

static void
  gpe_fwd_entries_get_reply_t_net_to_host
  (vl_api_gpe_fwd_entries_get_reply_t * mp)
{
  u32 i;

  mp->count = clib_net_to_host_u32 (mp->count);
  for (i = 0; i < mp->count; i++)
    {
      api_gpe_fwd_entry_net_to_host (&mp->entries[i]);
    }
}

static u8 *
format_gpe_encap_mode (u8 * s, va_list * args)
{
  u32 mode = va_arg (*args, u32);

  switch (mode)
    {
    case 0:
      return format (s, "lisp");
    case 1:
      return format (s, "vxlan");
    }
  return 0;
}

static void
  vl_api_gpe_get_encap_mode_reply_t_handler
  (vl_api_gpe_get_encap_mode_reply_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "gpe mode: %U", format_gpe_encap_mode, mp->encap_mode);
  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
  vl_api_gpe_get_encap_mode_reply_t_handler_json
  (vl_api_gpe_get_encap_mode_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  u8 *encap_mode = format (0, "%U", format_gpe_encap_mode, mp->encap_mode);
  vec_add1 (encap_mode, 0);

  vat_json_init_object (&node);
  vat_json_object_add_string_copy (&node, "gpe_mode", encap_mode);

  vec_free (encap_mode);
  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
  vl_api_gpe_fwd_entry_path_details_t_handler
  (vl_api_gpe_fwd_entry_path_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u8 *(*format_ip_address_fcn) (u8 *, va_list *) = 0;

  if (mp->lcl_loc.is_ip4)
    format_ip_address_fcn = format_ip4_address;
  else
    format_ip_address_fcn = format_ip6_address;

  print (vam->ofp, "w:%d %30U %30U", mp->rmt_loc.weight,
	 format_ip_address_fcn, &mp->lcl_loc,
	 format_ip_address_fcn, &mp->rmt_loc);
}

static void
lisp_fill_locator_node (vat_json_node_t * n, vl_api_gpe_locator_t * loc)
{
  struct in6_addr ip6;
  struct in_addr ip4;

  if (loc->is_ip4)
    {
      clib_memcpy (&ip4, loc->addr, sizeof (ip4));
      vat_json_object_add_ip4 (n, "address", ip4);
    }
  else
    {
      clib_memcpy (&ip6, loc->addr, sizeof (ip6));
      vat_json_object_add_ip6 (n, "address", ip6);
    }
  vat_json_object_add_uint (n, "weight", loc->weight);
}

static void
  vl_api_gpe_fwd_entry_path_details_t_handler_json
  (vl_api_gpe_fwd_entry_path_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;
  vat_json_node_t *loc_node;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);
  vat_json_init_object (node);

  loc_node = vat_json_object_add (node, "local_locator");
  vat_json_init_object (loc_node);
  lisp_fill_locator_node (loc_node, &mp->lcl_loc);

  loc_node = vat_json_object_add (node, "remote_locator");
  vat_json_init_object (loc_node);
  lisp_fill_locator_node (loc_node, &mp->rmt_loc);
}

static void
  vl_api_gpe_fwd_entries_get_reply_t_handler
  (vl_api_gpe_fwd_entries_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 i;
  int retval = clib_net_to_host_u32 (mp->retval);
  vl_api_gpe_fwd_entry_t *e;

  if (retval)
    goto end;

  gpe_fwd_entries_get_reply_t_net_to_host (mp);

  for (i = 0; i < mp->count; i++)
    {
      e = &mp->entries[i];
      print (vam->ofp, "%10d %10d %U %40U", e->fwd_entry_index, e->dp_table,
	     format_lisp_flat_eid, e->eid_type, e->leid, e->leid_prefix_len,
	     format_lisp_flat_eid, e->eid_type, e->reid, e->reid_prefix_len);
    }

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_gpe_fwd_entries_get_reply_t_handler_json
  (vl_api_gpe_fwd_entries_get_reply_t * mp)
{
  u8 *s = 0;
  vat_main_t *vam = &vat_main;
  vat_json_node_t *e = 0, root;
  u32 i;
  int retval = clib_net_to_host_u32 (mp->retval);
  vl_api_gpe_fwd_entry_t *fwd;

  if (retval)
    goto end;

  gpe_fwd_entries_get_reply_t_net_to_host (mp);
  vat_json_init_array (&root);

  for (i = 0; i < mp->count; i++)
    {
      e = vat_json_array_add (&root);
      fwd = &mp->entries[i];

      vat_json_init_object (e);
      vat_json_object_add_int (e, "fwd_entry_index", fwd->fwd_entry_index);
      vat_json_object_add_int (e, "dp_table", fwd->dp_table);
      vat_json_object_add_int (e, "vni", fwd->vni);
      vat_json_object_add_int (e, "action", fwd->action);

      s = format (0, "%U", format_lisp_flat_eid, fwd->eid_type, fwd->leid,
		  fwd->leid_prefix_len);
      vec_add1 (s, 0);
      vat_json_object_add_string_copy (e, "leid", s);
      vec_free (s);

      s = format (0, "%U", format_lisp_flat_eid, fwd->eid_type, fwd->reid,
		  fwd->reid_prefix_len);
      vec_add1 (s, 0);
      vat_json_object_add_string_copy (e, "reid", s);
      vec_free (s);
    }

  vat_json_print (vam->ofp, &root);
  vat_json_free (&root);

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_gpe_native_fwd_rpaths_get_reply_t_handler
  (vl_api_gpe_native_fwd_rpaths_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);
  vl_api_gpe_native_fwd_rpath_t *r;

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);

  for (i = 0; i < n; i++)
    {
      r = &mp->entries[i];
      print (vam->ofp, "fib_index: %d sw_if_index %d nh %U",
	     clib_net_to_host_u32 (r->fib_index),
	     clib_net_to_host_u32 (r->nh_sw_if_index),
	     r->is_ip4 ? format_ip4_address : format_ip6_address, r->nh_addr);
    }

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_gpe_native_fwd_rpaths_get_reply_t_handler_json
  (vl_api_gpe_native_fwd_rpaths_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t root, *e;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);
  vl_api_gpe_native_fwd_rpath_t *r;
  u8 *s;

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);
  vat_json_init_array (&root);

  for (i = 0; i < n; i++)
    {
      e = vat_json_array_add (&root);
      vat_json_init_object (e);
      r = &mp->entries[i];
      s =
	format (0, "%U", r->is_ip4 ? format_ip4_address : format_ip6_address,
		r->nh_addr);
      vec_add1 (s, 0);
      vat_json_object_add_string_copy (e, "ip4", s);
      vec_free (s);

      vat_json_object_add_uint (e, "fib_index",
				clib_net_to_host_u32 (r->fib_index));
      vat_json_object_add_uint (e, "nh_sw_if_index",
				clib_net_to_host_u32 (r->nh_sw_if_index));
    }

  vat_json_print (vam->ofp, &root);
  vat_json_free (&root);

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_gpe_fwd_entry_vnis_get_reply_t_handler
  (vl_api_gpe_fwd_entry_vnis_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);

  for (i = 0; i < n; i++)
    print (vam->ofp, "%d", clib_net_to_host_u32 (mp->vnis[i]));

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_gpe_fwd_entry_vnis_get_reply_t_handler_json
  (vl_api_gpe_fwd_entry_vnis_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t root;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);
  vat_json_init_array (&root);

  for (i = 0; i < n; i++)
    vat_json_array_add_uint (&root, clib_net_to_host_u32 (mp->vnis[i]));

  vat_json_print (vam->ofp, &root);
  vat_json_free (&root);

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_one_ndp_entries_get_reply_t_handler
  (vl_api_one_ndp_entries_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);

  for (i = 0; i < n; i++)
    print (vam->ofp, "%U -> %U", format_ip6_address, &mp->entries[i].ip6,
	   format_ethernet_address, mp->entries[i].mac);

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_one_ndp_entries_get_reply_t_handler_json
  (vl_api_one_ndp_entries_get_reply_t * mp)
{
  u8 *s = 0;
  vat_main_t *vam = &vat_main;
  vat_json_node_t *e = 0, root;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);
  vl_api_one_ndp_entry_t *arp_entry;

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);
  vat_json_init_array (&root);

  for (i = 0; i < n; i++)
    {
      e = vat_json_array_add (&root);
      arp_entry = &mp->entries[i];

      vat_json_init_object (e);
      s = format (0, "%U", format_ethernet_address, arp_entry->mac);
      vec_add1 (s, 0);

      vat_json_object_add_string_copy (e, "mac", s);
      vec_free (s);

      s = format (0, "%U", format_ip6_address, &arp_entry->ip6);
      vec_add1 (s, 0);
      vat_json_object_add_string_copy (e, "ip6", s);
      vec_free (s);
    }

  vat_json_print (vam->ofp, &root);
  vat_json_free (&root);

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_one_l2_arp_entries_get_reply_t_handler
  (vl_api_one_l2_arp_entries_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);

  for (i = 0; i < n; i++)
    print (vam->ofp, "%U -> %U", format_ip4_address, &mp->entries[i].ip4,
	   format_ethernet_address, mp->entries[i].mac);

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_one_l2_arp_entries_get_reply_t_handler_json
  (vl_api_one_l2_arp_entries_get_reply_t * mp)
{
  u8 *s = 0;
  vat_main_t *vam = &vat_main;
  vat_json_node_t *e = 0, root;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);
  vl_api_one_l2_arp_entry_t *arp_entry;

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);
  vat_json_init_array (&root);

  for (i = 0; i < n; i++)
    {
      e = vat_json_array_add (&root);
      arp_entry = &mp->entries[i];

      vat_json_init_object (e);
      s = format (0, "%U", format_ethernet_address, arp_entry->mac);
      vec_add1 (s, 0);

      vat_json_object_add_string_copy (e, "mac", s);
      vec_free (s);

      s = format (0, "%U", format_ip4_address, &arp_entry->ip4);
      vec_add1 (s, 0);
      vat_json_object_add_string_copy (e, "ip4", s);
      vec_free (s);
    }

  vat_json_print (vam->ofp, &root);
  vat_json_free (&root);

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
vl_api_one_ndp_bd_get_reply_t_handler (vl_api_one_ndp_bd_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);

  for (i = 0; i < n; i++)
    {
      print (vam->ofp, "%d", clib_net_to_host_u32 (mp->bridge_domains[i]));
    }

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_one_ndp_bd_get_reply_t_handler_json
  (vl_api_one_ndp_bd_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t root;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);
  vat_json_init_array (&root);

  for (i = 0; i < n; i++)
    {
      vat_json_array_add_uint (&root,
			       clib_net_to_host_u32 (mp->bridge_domains[i]));
    }

  vat_json_print (vam->ofp, &root);
  vat_json_free (&root);

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_one_l2_arp_bd_get_reply_t_handler
  (vl_api_one_l2_arp_bd_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);

  for (i = 0; i < n; i++)
    {
      print (vam->ofp, "%d", clib_net_to_host_u32 (mp->bridge_domains[i]));
    }

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_one_l2_arp_bd_get_reply_t_handler_json
  (vl_api_one_l2_arp_bd_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t root;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);
  vat_json_init_array (&root);

  for (i = 0; i < n; i++)
    {
      vat_json_array_add_uint (&root,
			       clib_net_to_host_u32 (mp->bridge_domains[i]));
    }

  vat_json_print (vam->ofp, &root);
  vat_json_free (&root);

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_one_adjacencies_get_reply_t_handler
  (vl_api_one_adjacencies_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);
  vl_api_one_adjacency_t *a;

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);

  for (i = 0; i < n; i++)
    {
      a = &mp->adjacencies[i];
      print (vam->ofp, "%U %40U",
	     format_lisp_flat_eid, a->eid_type, a->leid, a->leid_prefix_len,
	     format_lisp_flat_eid, a->eid_type, a->reid, a->reid_prefix_len);
    }

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_one_adjacencies_get_reply_t_handler_json
  (vl_api_one_adjacencies_get_reply_t * mp)
{
  u8 *s = 0;
  vat_main_t *vam = &vat_main;
  vat_json_node_t *e = 0, root;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);
  vl_api_one_adjacency_t *a;

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);
  vat_json_init_array (&root);

  for (i = 0; i < n; i++)
    {
      e = vat_json_array_add (&root);
      a = &mp->adjacencies[i];

      vat_json_init_object (e);
      s = format (0, "%U", format_lisp_flat_eid, a->eid_type, a->leid,
		  a->leid_prefix_len);
      vec_add1 (s, 0);
      vat_json_object_add_string_copy (e, "leid", s);
      vec_free (s);

      s = format (0, "%U", format_lisp_flat_eid, a->eid_type, a->reid,
		  a->reid_prefix_len);
      vec_add1 (s, 0);
      vat_json_object_add_string_copy (e, "reid", s);
      vec_free (s);
    }

  vat_json_print (vam->ofp, &root);
  vat_json_free (&root);

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
vl_api_one_map_server_details_t_handler (vl_api_one_map_server_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%=20U",
	 mp->is_ipv6 ? format_ip6_address : format_ip4_address,
	 mp->ip_address);
}

static void
  vl_api_one_map_server_details_t_handler_json
  (vl_api_one_map_server_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;
  struct in6_addr ip6;
  struct in_addr ip4;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  if (mp->is_ipv6)
    {
      clib_memcpy (&ip6, mp->ip_address, sizeof (ip6));
      vat_json_object_add_ip6 (node, "map-server", ip6);
    }
  else
    {
      clib_memcpy (&ip4, mp->ip_address, sizeof (ip4));
      vat_json_object_add_ip4 (node, "map-server", ip4);
    }
}

static void
vl_api_one_map_resolver_details_t_handler (vl_api_one_map_resolver_details_t
					   * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%=20U",
	 mp->is_ipv6 ? format_ip6_address : format_ip4_address,
	 mp->ip_address);
}

static void
  vl_api_one_map_resolver_details_t_handler_json
  (vl_api_one_map_resolver_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;
  struct in6_addr ip6;
  struct in_addr ip4;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  if (mp->is_ipv6)
    {
      clib_memcpy (&ip6, mp->ip_address, sizeof (ip6));
      vat_json_object_add_ip6 (node, "map resolver", ip6);
    }
  else
    {
      clib_memcpy (&ip4, mp->ip_address, sizeof (ip4));
      vat_json_object_add_ip4 (node, "map resolver", ip4);
    }
}

static void
vl_api_show_one_status_reply_t_handler (vl_api_show_one_status_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (0 <= retval)
    {
      print (vam->ofp, "feature: %s\ngpe: %s",
	     mp->feature_status ? "enabled" : "disabled",
	     mp->gpe_status ? "enabled" : "disabled");
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_show_one_status_reply_t_handler_json
  (vl_api_show_one_status_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;
  u8 *gpe_status = NULL;
  u8 *feature_status = NULL;

  gpe_status = format (0, "%s", mp->gpe_status ? "enabled" : "disabled");
  feature_status = format (0, "%s",
			   mp->feature_status ? "enabled" : "disabled");
  vec_add1 (gpe_status, 0);
  vec_add1 (feature_status, 0);

  vat_json_init_object (&node);
  vat_json_object_add_string_copy (&node, "gpe_status", gpe_status);
  vat_json_object_add_string_copy (&node, "feature_status", feature_status);

  vec_free (gpe_status);
  vec_free (feature_status);

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
  vl_api_one_get_map_request_itr_rlocs_reply_t_handler
  (vl_api_one_get_map_request_itr_rlocs_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (retval >= 0)
    {
      print (vam->ofp, "%=20s", mp->locator_set_name);
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_one_get_map_request_itr_rlocs_reply_t_handler_json
  (vl_api_one_get_map_request_itr_rlocs_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_string_copy (node, "itr-rlocs", mp->locator_set_name);

  vat_json_print (vam->ofp, node);
  vat_json_free (node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static u8 *
format_lisp_map_request_mode (u8 * s, va_list * args)
{
  u32 mode = va_arg (*args, u32);

  switch (mode)
    {
    case 0:
      return format (0, "dst-only");
    case 1:
      return format (0, "src-dst");
    }
  return 0;
}

static void
  vl_api_show_one_map_request_mode_reply_t_handler
  (vl_api_show_one_map_request_mode_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (0 <= retval)
    {
      u32 mode = mp->mode;
      print (vam->ofp, "map_request_mode: %U",
	     format_lisp_map_request_mode, mode);
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_show_one_map_request_mode_reply_t_handler_json
  (vl_api_show_one_map_request_mode_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;
  u8 *s = 0;
  u32 mode;

  mode = mp->mode;
  s = format (0, "%U", format_lisp_map_request_mode, mode);
  vec_add1 (s, 0);

  vat_json_init_object (&node);
  vat_json_object_add_string_copy (&node, "map_request_mode", s);
  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vec_free (s);
  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
  vl_api_one_show_xtr_mode_reply_t_handler
  (vl_api_one_show_xtr_mode_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (0 <= retval)
    {
      print (vam->ofp, "%s\n", mp->is_en ? "enabled" : "disabled");
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_one_show_xtr_mode_reply_t_handler_json
  (vl_api_one_show_xtr_mode_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;
  u8 *status = 0;

  status = format (0, "%s", mp->is_en ? "enabled" : "disabled");
  vec_add1 (status, 0);

  vat_json_init_object (&node);
  vat_json_object_add_string_copy (&node, "status", status);

  vec_free (status);

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
  vl_api_one_show_pitr_mode_reply_t_handler
  (vl_api_one_show_pitr_mode_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (0 <= retval)
    {
      print (vam->ofp, "%s\n", mp->is_en ? "enabled" : "disabled");
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_one_show_pitr_mode_reply_t_handler_json
  (vl_api_one_show_pitr_mode_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;
  u8 *status = 0;

  status = format (0, "%s", mp->is_en ? "enabled" : "disabled");
  vec_add1 (status, 0);

  vat_json_init_object (&node);
  vat_json_object_add_string_copy (&node, "status", status);

  vec_free (status);

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
  vl_api_one_show_petr_mode_reply_t_handler
  (vl_api_one_show_petr_mode_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (0 <= retval)
    {
      print (vam->ofp, "%s\n", mp->is_en ? "enabled" : "disabled");
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_one_show_petr_mode_reply_t_handler_json
  (vl_api_one_show_petr_mode_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;
  u8 *status = 0;

  status = format (0, "%s", mp->is_en ? "enabled" : "disabled");
  vec_add1 (status, 0);

  vat_json_init_object (&node);
  vat_json_object_add_string_copy (&node, "status", status);

  vec_free (status);

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
  vl_api_show_one_use_petr_reply_t_handler
  (vl_api_show_one_use_petr_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (0 <= retval)
    {
      print (vam->ofp, "%s\n", mp->status ? "enabled" : "disabled");
      if (mp->status)
	{
	  print (vam->ofp, "Proxy-ETR address; %U",
		 mp->is_ip4 ? format_ip4_address : format_ip6_address,
		 mp->address);
	}
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_show_one_use_petr_reply_t_handler_json
  (vl_api_show_one_use_petr_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;
  u8 *status = 0;
  struct in_addr ip4;
  struct in6_addr ip6;

  status = format (0, "%s", mp->status ? "enabled" : "disabled");
  vec_add1 (status, 0);

  vat_json_init_object (&node);
  vat_json_object_add_string_copy (&node, "status", status);
  if (mp->status)
    {
      if (mp->is_ip4)
	{
	  clib_memcpy (&ip6, mp->address, sizeof (ip6));
	  vat_json_object_add_ip6 (&node, "address", ip6);
	}
      else
	{
	  clib_memcpy (&ip4, mp->address, sizeof (ip4));
	  vat_json_object_add_ip4 (&node, "address", ip4);
	}
    }

  vec_free (status);

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
  vl_api_show_one_nsh_mapping_reply_t_handler
  (vl_api_show_one_nsh_mapping_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (0 <= retval)
    {
      print (vam->ofp, "%-20s%-16s",
	     mp->is_set ? "set" : "not-set",
	     mp->is_set ? (char *) mp->locator_set_name : "");
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_show_one_nsh_mapping_reply_t_handler_json
  (vl_api_show_one_nsh_mapping_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;
  u8 *status = 0;

  status = format (0, "%s", mp->is_set ? "yes" : "no");
  vec_add1 (status, 0);

  vat_json_init_object (&node);
  vat_json_object_add_string_copy (&node, "is_set", status);
  if (mp->is_set)
    {
      vat_json_object_add_string_copy (&node, "locator_set",
				       mp->locator_set_name);
    }

  vec_free (status);

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
  vl_api_show_one_map_register_ttl_reply_t_handler
  (vl_api_show_one_map_register_ttl_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  vl_api_show_one_map_register_ttl_reply_t_endian (mp);

  if (0 <= retval)
    {
      print (vam->ofp, "ttl: %u", mp->ttl);
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_show_one_map_register_ttl_reply_t_handler_json
  (vl_api_show_one_map_register_ttl_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vl_api_show_one_map_register_ttl_reply_t_endian (mp);
  vat_json_init_object (&node);
  vat_json_object_add_uint (&node, "ttl", mp->ttl);

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
vl_api_show_one_pitr_reply_t_handler (vl_api_show_one_pitr_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (0 <= retval)
    {
      print (vam->ofp, "%-20s%-16s",
	     mp->status ? "enabled" : "disabled",
	     mp->status ? (char *) mp->locator_set_name : "");
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
vl_api_show_one_pitr_reply_t_handler_json (vl_api_show_one_pitr_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;
  u8 *status = 0;

  status = format (0, "%s", mp->status ? "enabled" : "disabled");
  vec_add1 (status, 0);

  vat_json_init_object (&node);
  vat_json_object_add_string_copy (&node, "status", status);
  if (mp->status)
    {
      vat_json_object_add_string_copy (&node, "locator_set",
				       mp->locator_set_name);
    }

  vec_free (status);

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static u8 *
format_policer_type (u8 * s, va_list * va)
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

static u8 *
format_policer_rate_type (u8 * s, va_list * va)
{
  u32 i = va_arg (*va, u32);

  if (i == SSE2_QOS_RATE_KBPS)
    s = format (s, "kbps");
  else if (i == SSE2_QOS_RATE_PPS)
    s = format (s, "pps");
  else
    s = format (s, "ILLEGAL");
  return s;
}

static u8 *
format_policer_round_type (u8 * s, va_list * va)
{
  u32 i = va_arg (*va, u32);

  if (i == SSE2_QOS_ROUND_TO_CLOSEST)
    s = format (s, "closest");
  else if (i == SSE2_QOS_ROUND_TO_UP)
    s = format (s, "up");
  else if (i == SSE2_QOS_ROUND_TO_DOWN)
    s = format (s, "down");
  else
    s = format (s, "ILLEGAL");
  return s;
}

static u8 *
format_policer_action_type (u8 * s, va_list * va)
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

static u8 *
format_dscp (u8 * s, va_list * va)
{
  u32 i = va_arg (*va, u32);
  char *t = 0;

  switch (i)
    {
#define _(v,f,str) case VNET_DSCP_##f: t = str; break;
      foreach_vnet_dscp
#undef _
    default:
      return format (s, "ILLEGAL");
    }
  s = format (s, "%s", t);
  return s;
}

static void
vl_api_policer_details_t_handler (vl_api_policer_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u8 *conform_dscp_str, *exceed_dscp_str, *violate_dscp_str;

  if (mp->conform_action_type == SSE2_QOS_ACTION_MARK_AND_TRANSMIT)
    conform_dscp_str = format (0, "%U", format_dscp, mp->conform_dscp);
  else
    conform_dscp_str = format (0, "");

  if (mp->exceed_action_type == SSE2_QOS_ACTION_MARK_AND_TRANSMIT)
    exceed_dscp_str = format (0, "%U", format_dscp, mp->exceed_dscp);
  else
    exceed_dscp_str = format (0, "");

  if (mp->violate_action_type == SSE2_QOS_ACTION_MARK_AND_TRANSMIT)
    violate_dscp_str = format (0, "%U", format_dscp, mp->violate_dscp);
  else
    violate_dscp_str = format (0, "");

  print (vam->ofp, "Name \"%s\", type %U, cir %u, eir %u, cb %u, eb %u, "
	 "rate type %U, round type %U, %s rate, %s color-aware, "
	 "cir %u tok/period, pir %u tok/period, scale %u, cur lim %u, "
	 "cur bkt %u, ext lim %u, ext bkt %u, last update %llu"
	 "conform action %U%s, exceed action %U%s, violate action %U%s",
	 mp->name,
	 format_policer_type, mp->type,
	 ntohl (mp->cir),
	 ntohl (mp->eir),
	 clib_net_to_host_u64 (mp->cb),
	 clib_net_to_host_u64 (mp->eb),
	 format_policer_rate_type, mp->rate_type,
	 format_policer_round_type, mp->round_type,
	 mp->single_rate ? "single" : "dual",
	 mp->color_aware ? "is" : "not",
	 ntohl (mp->cir_tokens_per_period),
	 ntohl (mp->pir_tokens_per_period),
	 ntohl (mp->scale),
	 ntohl (mp->current_limit),
	 ntohl (mp->current_bucket),
	 ntohl (mp->extended_limit),
	 ntohl (mp->extended_bucket),
	 clib_net_to_host_u64 (mp->last_update_time),
	 format_policer_action_type, mp->conform_action_type,
	 conform_dscp_str,
	 format_policer_action_type, mp->exceed_action_type,
	 exceed_dscp_str,
	 format_policer_action_type, mp->violate_action_type,
	 violate_dscp_str);

  vec_free (conform_dscp_str);
  vec_free (exceed_dscp_str);
  vec_free (violate_dscp_str);
}

static void vl_api_policer_details_t_handler_json
  (vl_api_policer_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node;
  u8 *rate_type_str, *round_type_str, *type_str;
  u8 *conform_action_str, *exceed_action_str, *violate_action_str;

  rate_type_str = format (0, "%U", format_policer_rate_type, mp->rate_type);
  round_type_str =
    format (0, "%U", format_policer_round_type, mp->round_type);
  type_str = format (0, "%U", format_policer_type, mp->type);
  conform_action_str = format (0, "%U", format_policer_action_type,
			       mp->conform_action_type);
  exceed_action_str = format (0, "%U", format_policer_action_type,
			      mp->exceed_action_type);
  violate_action_str = format (0, "%U", format_policer_action_type,
			       mp->violate_action_type);

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_string_copy (node, "name", mp->name);
  vat_json_object_add_uint (node, "cir", ntohl (mp->cir));
  vat_json_object_add_uint (node, "eir", ntohl (mp->eir));
  vat_json_object_add_uint (node, "cb", clib_net_to_host_u64 (mp->cb));
  vat_json_object_add_uint (node, "eb", clib_net_to_host_u64 (mp->eb));
  vat_json_object_add_string_copy (node, "rate_type", rate_type_str);
  vat_json_object_add_string_copy (node, "round_type", round_type_str);
  vat_json_object_add_string_copy (node, "type", type_str);
  vat_json_object_add_uint (node, "single_rate", mp->single_rate);
  vat_json_object_add_uint (node, "color_aware", mp->color_aware);
  vat_json_object_add_uint (node, "scale", ntohl (mp->scale));
  vat_json_object_add_uint (node, "cir_tokens_per_period",
			    ntohl (mp->cir_tokens_per_period));
  vat_json_object_add_uint (node, "eir_tokens_per_period",
			    ntohl (mp->pir_tokens_per_period));
  vat_json_object_add_uint (node, "current_limit", ntohl (mp->current_limit));
  vat_json_object_add_uint (node, "current_bucket",
			    ntohl (mp->current_bucket));
  vat_json_object_add_uint (node, "extended_limit",
			    ntohl (mp->extended_limit));
  vat_json_object_add_uint (node, "extended_bucket",
			    ntohl (mp->extended_bucket));
  vat_json_object_add_uint (node, "last_update_time",
			    ntohl (mp->last_update_time));
  vat_json_object_add_string_copy (node, "conform_action",
				   conform_action_str);
  if (mp->conform_action_type == SSE2_QOS_ACTION_MARK_AND_TRANSMIT)
    {
      u8 *dscp_str = format (0, "%U", format_dscp, mp->conform_dscp);
      vat_json_object_add_string_copy (node, "conform_dscp", dscp_str);
      vec_free (dscp_str);
    }
  vat_json_object_add_string_copy (node, "exceed_action", exceed_action_str);
  if (mp->exceed_action_type == SSE2_QOS_ACTION_MARK_AND_TRANSMIT)
    {
      u8 *dscp_str = format (0, "%U", format_dscp, mp->exceed_dscp);
      vat_json_object_add_string_copy (node, "exceed_dscp", dscp_str);
      vec_free (dscp_str);
    }
  vat_json_object_add_string_copy (node, "violate_action",
				   violate_action_str);
  if (mp->violate_action_type == SSE2_QOS_ACTION_MARK_AND_TRANSMIT)
    {
      u8 *dscp_str = format (0, "%U", format_dscp, mp->violate_dscp);
      vat_json_object_add_string_copy (node, "violate_dscp", dscp_str);
      vec_free (dscp_str);
    }

  vec_free (rate_type_str);
  vec_free (round_type_str);
  vec_free (type_str);
  vec_free (conform_action_str);
  vec_free (exceed_action_str);
  vec_free (violate_action_str);
}

static void
vl_api_classify_table_ids_reply_t_handler (vl_api_classify_table_ids_reply_t *
					   mp)
{
  vat_main_t *vam = &vat_main;
  int i, count = ntohl (mp->count);

  if (count > 0)
    print (vam->ofp, "classify table ids (%d) : ", count);
  for (i = 0; i < count; i++)
    {
      print (vam->ofp, "%d", ntohl (mp->ids[i]));
      print (vam->ofp, (i < count - 1) ? "," : "");
    }
  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
  vl_api_classify_table_ids_reply_t_handler_json
  (vl_api_classify_table_ids_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  int i, count = ntohl (mp->count);

  if (count > 0)
    {
      vat_json_node_t node;

      vat_json_init_object (&node);
      for (i = 0; i < count; i++)
	{
	  vat_json_object_add_uint (&node, "table_id", ntohl (mp->ids[i]));
	}
      vat_json_print (vam->ofp, &node);
      vat_json_free (&node);
    }
  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
  vl_api_classify_table_by_interface_reply_t_handler
  (vl_api_classify_table_by_interface_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 table_id;

  table_id = ntohl (mp->l2_table_id);
  if (table_id != ~0)
    print (vam->ofp, "l2 table id : %d", table_id);
  else
    print (vam->ofp, "l2 table id : No input ACL tables configured");
  table_id = ntohl (mp->ip4_table_id);
  if (table_id != ~0)
    print (vam->ofp, "ip4 table id : %d", table_id);
  else
    print (vam->ofp, "ip4 table id : No input ACL tables configured");
  table_id = ntohl (mp->ip6_table_id);
  if (table_id != ~0)
    print (vam->ofp, "ip6 table id : %d", table_id);
  else
    print (vam->ofp, "ip6 table id : No input ACL tables configured");
  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
  vl_api_classify_table_by_interface_reply_t_handler_json
  (vl_api_classify_table_by_interface_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);

  vat_json_object_add_int (&node, "l2_table_id", ntohl (mp->l2_table_id));
  vat_json_object_add_int (&node, "ip4_table_id", ntohl (mp->ip4_table_id));
  vat_json_object_add_int (&node, "ip6_table_id", ntohl (mp->ip6_table_id));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_policer_add_del_reply_t_handler
  (vl_api_policer_add_del_reply_t * mp)
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
      vam->result_ready = 1;
      if (retval == 0 && mp->policer_index != 0xFFFFFFFF)
	/*
	 * Note: this is just barely thread-safe, depends on
	 * the main thread spinning waiting for an answer...
	 */
	errmsg ("policer index %d", ntohl (mp->policer_index));
    }
}

static void vl_api_policer_add_del_reply_t_handler_json
  (vl_api_policer_add_del_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "policer_index",
			    ntohl (mp->policer_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

/* Format hex dump. */
u8 *
format_hex_bytes (u8 * s, va_list * va)
{
  u8 *bytes = va_arg (*va, u8 *);
  int n_bytes = va_arg (*va, int);
  uword i;

  /* Print short or long form depending on byte count. */
  uword short_form = n_bytes <= 32;
  u32 indent = format_get_indent (s);

  if (n_bytes == 0)
    return s;

  for (i = 0; i < n_bytes; i++)
    {
      if (!short_form && (i % 32) == 0)
	s = format (s, "%08x: ", i);
      s = format (s, "%02x", bytes[i]);
      if (!short_form && ((i + 1) % 32) == 0 && (i + 1) < n_bytes)
	s = format (s, "\n%U", format_white_space, indent);
    }

  return s;
}

static void
vl_api_classify_table_info_reply_t_handler (vl_api_classify_table_info_reply_t
					    * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);
  if (retval == 0)
    {
      print (vam->ofp, "classify table info :");
      print (vam->ofp, "sessions: %d nexttbl: %d nextnode: %d",
	     ntohl (mp->active_sessions), ntohl (mp->next_table_index),
	     ntohl (mp->miss_next_index));
      print (vam->ofp, "nbuckets: %d skip: %d match: %d",
	     ntohl (mp->nbuckets), ntohl (mp->skip_n_vectors),
	     ntohl (mp->match_n_vectors));
      print (vam->ofp, "mask: %U", format_hex_bytes, mp->mask,
	     ntohl (mp->mask_length));
    }
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_classify_table_info_reply_t_handler_json
  (vl_api_classify_table_info_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  i32 retval = ntohl (mp->retval);
  if (retval == 0)
    {
      vat_json_init_object (&node);

      vat_json_object_add_int (&node, "sessions",
			       ntohl (mp->active_sessions));
      vat_json_object_add_int (&node, "nexttbl",
			       ntohl (mp->next_table_index));
      vat_json_object_add_int (&node, "nextnode",
			       ntohl (mp->miss_next_index));
      vat_json_object_add_int (&node, "nbuckets", ntohl (mp->nbuckets));
      vat_json_object_add_int (&node, "skip", ntohl (mp->skip_n_vectors));
      vat_json_object_add_int (&node, "match", ntohl (mp->match_n_vectors));
      u8 *s = format (0, "%U%c", format_hex_bytes, mp->mask,
		      ntohl (mp->mask_length), 0);
      vat_json_object_add_string_copy (&node, "mask", s);

      vat_json_print (vam->ofp, &node);
      vat_json_free (&node);
    }
  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
vl_api_classify_session_details_t_handler (vl_api_classify_session_details_t *
					   mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "next_index: %d advance: %d opaque: %d ",
	 ntohl (mp->hit_next_index), ntohl (mp->advance),
	 ntohl (mp->opaque_index));
  print (vam->ofp, "mask: %U", format_hex_bytes, mp->match,
	 ntohl (mp->match_length));
}

static void
  vl_api_classify_session_details_t_handler_json
  (vl_api_classify_session_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_int (node, "next_index", ntohl (mp->hit_next_index));
  vat_json_object_add_int (node, "advance", ntohl (mp->advance));
  vat_json_object_add_int (node, "opaque", ntohl (mp->opaque_index));
  u8 *s =
    format (0, "%U%c", format_hex_bytes, mp->match, ntohl (mp->match_length),
	    0);
  vat_json_object_add_string_copy (node, "match", s);
}

static void vl_api_pg_create_interface_reply_t_handler
  (vl_api_pg_create_interface_reply_t * mp)
{
  vat_main_t *vam = &vat_main;

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_pg_create_interface_reply_t_handler_json
  (vl_api_pg_create_interface_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  i32 retval = ntohl (mp->retval);
  if (retval == 0)
    {
      vat_json_init_object (&node);

      vat_json_object_add_int (&node, "sw_if_index", ntohl (mp->sw_if_index));

      vat_json_print (vam->ofp, &node);
      vat_json_free (&node);
    }
  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_policer_classify_details_t_handler
  (vl_api_policer_classify_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%10d%20d", ntohl (mp->sw_if_index),
	 ntohl (mp->table_index));
}

static void vl_api_policer_classify_details_t_handler_json
  (vl_api_policer_classify_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  vat_json_object_add_uint (node, "table_index", ntohl (mp->table_index));
}

static void vl_api_ipsec_gre_add_del_tunnel_reply_t_handler
  (vl_api_ipsec_gre_add_del_tunnel_reply_t * mp)
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
  vam->regenerate_interface_table = 1;
}

static void vl_api_ipsec_gre_add_del_tunnel_reply_t_handler_json
  (vl_api_ipsec_gre_add_del_tunnel_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void vl_api_flow_classify_details_t_handler
  (vl_api_flow_classify_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%10d%20d", ntohl (mp->sw_if_index),
	 ntohl (mp->table_index));
}

static void vl_api_flow_classify_details_t_handler_json
  (vl_api_flow_classify_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  vat_json_object_add_uint (node, "table_index", ntohl (mp->table_index));
}

#define vl_api_one_adjacencies_get_reply_t_endian vl_noop_handler
#define vl_api_one_adjacencies_get_reply_t_print vl_noop_handler
#define vl_api_one_l2_arp_bd_get_reply_t_print vl_noop_handler
#define vl_api_one_l2_arp_entries_get_reply_t_endian vl_noop_handler
#define vl_api_one_l2_arp_entries_get_reply_t_print vl_noop_handler
#define vl_api_one_l2_arp_bd_get_reply_t_endian vl_noop_handler
#define vl_api_one_ndp_bd_get_reply_t_endian vl_noop_handler
#define vl_api_one_ndp_bd_get_reply_t_print vl_noop_handler
#define vl_api_one_ndp_entries_get_reply_t_print vl_noop_handler
#define vl_api_one_ndp_entries_get_reply_t_endian vl_noop_handler

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
_(sw_interface_set_rx_mode_reply)                       \
_(sw_interface_set_rx_placement_reply)                  \
_(sw_interface_set_table_reply)                         \
_(sw_interface_set_mpls_enable_reply)                   \
_(sw_interface_set_vpath_reply)                         \
_(sw_interface_set_vxlan_bypass_reply)                  \
_(sw_interface_set_geneve_bypass_reply)                 \
_(sw_interface_set_vxlan_gpe_bypass_reply)              \
_(sw_interface_set_l2_bridge_reply)                     \
_(bridge_domain_add_del_reply)                          \
_(sw_interface_set_l2_xconnect_reply)                   \
_(l2fib_add_del_reply)                                  \
_(l2fib_flush_int_reply)                                \
_(l2fib_flush_bd_reply)                                 \
_(ip_add_del_route_reply)                               \
_(ip_table_add_del_reply)                               \
_(ip_mroute_add_del_reply)                              \
_(mpls_route_add_del_reply)                             \
_(mpls_table_add_del_reply)                             \
_(mpls_ip_bind_unbind_reply)                            \
_(bier_route_add_del_reply)                             \
_(bier_table_add_del_reply)                             \
_(proxy_arp_add_del_reply)                              \
_(proxy_arp_intfc_enable_disable_reply)                 \
_(sw_interface_set_unnumbered_reply)                    \
_(ip_neighbor_add_del_reply)                            \
_(oam_add_del_reply)                                    \
_(reset_fib_reply)                                      \
_(dhcp_proxy_config_reply)                              \
_(dhcp_proxy_set_vss_reply)                             \
_(dhcp_client_config_reply)                             \
_(set_ip_flow_hash_reply)                               \
_(sw_interface_ip6_enable_disable_reply)                \
_(ip6nd_proxy_add_del_reply)                            \
_(sw_interface_ip6nd_ra_prefix_reply)                   \
_(sw_interface_ip6nd_ra_config_reply)                   \
_(set_arp_neighbor_limit_reply)                         \
_(l2_patch_add_del_reply)                               \
_(sr_mpls_policy_add_reply)                             \
_(sr_mpls_policy_mod_reply)                             \
_(sr_mpls_policy_del_reply)                             \
_(sr_policy_add_reply)                                  \
_(sr_policy_mod_reply)                                  \
_(sr_policy_del_reply)                                  \
_(sr_localsid_add_del_reply)                            \
_(sr_steering_add_del_reply)                            \
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
_(ip_probe_neighbor_reply)                              \
_(ip_scan_neighbor_enable_disable_reply)                \
_(want_ip4_arp_events_reply)                            \
_(want_ip6_nd_events_reply)                             \
_(want_l2_macs_events_reply)                            \
_(input_acl_set_interface_reply)                        \
_(ipsec_spd_add_del_reply)                              \
_(ipsec_interface_add_del_spd_reply)                    \
_(ipsec_spd_add_del_entry_reply)                        \
_(ipsec_sad_add_del_entry_reply)                        \
_(ipsec_sa_set_key_reply)                               \
_(ipsec_tunnel_if_add_del_reply)                        \
_(ipsec_tunnel_if_set_key_reply)                        \
_(ipsec_tunnel_if_set_sa_reply)                         \
_(ikev2_profile_add_del_reply)                          \
_(ikev2_profile_set_auth_reply)                         \
_(ikev2_profile_set_id_reply)                           \
_(ikev2_profile_set_ts_reply)                           \
_(ikev2_set_local_key_reply)                            \
_(ikev2_set_responder_reply)                            \
_(ikev2_set_ike_transforms_reply)                       \
_(ikev2_set_esp_transforms_reply)                       \
_(ikev2_set_sa_lifetime_reply)                          \
_(ikev2_initiate_sa_init_reply)                         \
_(ikev2_initiate_del_ike_sa_reply)                      \
_(ikev2_initiate_del_child_sa_reply)                    \
_(ikev2_initiate_rekey_child_sa_reply)                  \
_(delete_loopback_reply)                                \
_(bd_ip_mac_add_del_reply)                              \
_(bd_ip_mac_flush_reply)                                \
_(want_interface_events_reply)                          \
_(cop_interface_enable_disable_reply)			\
_(cop_whitelist_enable_disable_reply)                   \
_(sw_interface_clear_stats_reply)                       \
_(ioam_enable_reply)                                    \
_(ioam_disable_reply)                                   \
_(one_add_del_locator_reply)                            \
_(one_add_del_local_eid_reply)                          \
_(one_add_del_remote_mapping_reply)                     \
_(one_add_del_adjacency_reply)                          \
_(one_add_del_map_resolver_reply)                       \
_(one_add_del_map_server_reply)                         \
_(one_enable_disable_reply)                             \
_(one_rloc_probe_enable_disable_reply)                  \
_(one_map_register_enable_disable_reply)                \
_(one_map_register_set_ttl_reply)                       \
_(one_set_transport_protocol_reply)                     \
_(one_map_register_fallback_threshold_reply)            \
_(one_pitr_set_locator_set_reply)                       \
_(one_map_request_mode_reply)                           \
_(one_add_del_map_request_itr_rlocs_reply)              \
_(one_eid_table_add_del_map_reply)                      \
_(one_use_petr_reply)                                   \
_(one_stats_enable_disable_reply)                       \
_(one_add_del_l2_arp_entry_reply)                       \
_(one_add_del_ndp_entry_reply)                          \
_(one_stats_flush_reply)                                \
_(one_enable_disable_xtr_mode_reply)                    \
_(one_enable_disable_pitr_mode_reply)                   \
_(one_enable_disable_petr_mode_reply)                   \
_(gpe_enable_disable_reply)                             \
_(gpe_set_encap_mode_reply)                             \
_(gpe_add_del_iface_reply)                              \
_(gpe_add_del_native_fwd_rpath_reply)                   \
_(af_packet_delete_reply)                               \
_(policer_classify_set_interface_reply)                 \
_(netmap_create_reply)                                  \
_(netmap_delete_reply)                                  \
_(set_ipfix_exporter_reply)                             \
_(set_ipfix_classify_stream_reply)                      \
_(ipfix_classify_table_add_del_reply)                   \
_(flow_classify_set_interface_reply)                    \
_(sw_interface_span_enable_disable_reply)               \
_(pg_capture_reply)                                     \
_(pg_enable_disable_reply)                              \
_(ip_source_and_port_range_check_add_del_reply)         \
_(ip_source_and_port_range_check_interface_add_del_reply)\
_(delete_subif_reply)                                   \
_(l2_interface_pbb_tag_rewrite_reply)                   \
_(set_punt_reply)                                       \
_(feature_enable_disable_reply)				\
_(sw_interface_tag_add_del_reply)			\
_(hw_interface_set_mtu_reply)                           \
_(p2p_ethernet_add_reply)                               \
_(p2p_ethernet_del_reply)                               \
_(lldp_config_reply)                                    \
_(sw_interface_set_lldp_reply)				\
_(tcp_configure_src_addresses_reply)			\
_(dns_enable_disable_reply)                             \
_(dns_name_server_add_del_reply)			\
_(session_rule_add_del_reply)				\
_(ip_container_proxy_add_del_reply)                     \
_(output_acl_set_interface_reply)                       \
_(qos_record_enable_disable_reply)

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
_(CREATE_LOOPBACK_INSTANCE_REPLY, create_loopback_instance_reply)       \
_(SW_INTERFACE_DETAILS, sw_interface_details)                           \
_(SW_INTERFACE_SET_FLAGS_REPLY, sw_interface_set_flags_reply)           \
_(CONTROL_PING_REPLY, control_ping_reply)                               \
_(CLI_REPLY, cli_reply)                                                 \
_(CLI_INBAND_REPLY, cli_inband_reply)                                   \
_(SW_INTERFACE_ADD_DEL_ADDRESS_REPLY,                                   \
  sw_interface_add_del_address_reply)                                   \
_(SW_INTERFACE_SET_RX_MODE_REPLY, sw_interface_set_rx_mode_reply)       \
_(SW_INTERFACE_SET_RX_PLACEMENT_REPLY, sw_interface_set_rx_placement_reply)	\
_(SW_INTERFACE_RX_PLACEMENT_DETAILS, sw_interface_rx_placement_details)	\
_(SW_INTERFACE_SET_TABLE_REPLY, sw_interface_set_table_reply) 		\
_(SW_INTERFACE_SET_MPLS_ENABLE_REPLY, sw_interface_set_mpls_enable_reply) \
_(SW_INTERFACE_SET_VPATH_REPLY, sw_interface_set_vpath_reply) 		\
_(SW_INTERFACE_SET_VXLAN_BYPASS_REPLY, sw_interface_set_vxlan_bypass_reply) \
_(SW_INTERFACE_SET_GENEVE_BYPASS_REPLY, sw_interface_set_geneve_bypass_reply) \
_(SW_INTERFACE_SET_VXLAN_GPE_BYPASS_REPLY, sw_interface_set_vxlan_gpe_bypass_reply) \
_(SW_INTERFACE_SET_L2_XCONNECT_REPLY,                                   \
  sw_interface_set_l2_xconnect_reply)                                   \
_(SW_INTERFACE_SET_L2_BRIDGE_REPLY,                                     \
  sw_interface_set_l2_bridge_reply)                                     \
_(BRIDGE_DOMAIN_ADD_DEL_REPLY, bridge_domain_add_del_reply)             \
_(BRIDGE_DOMAIN_DETAILS, bridge_domain_details)                         \
_(BRIDGE_DOMAIN_SET_MAC_AGE_REPLY, bridge_domain_set_mac_age_reply)     \
_(L2FIB_ADD_DEL_REPLY, l2fib_add_del_reply)                             \
_(L2FIB_FLUSH_INT_REPLY, l2fib_flush_int_reply)                         \
_(L2FIB_FLUSH_BD_REPLY, l2fib_flush_bd_reply)                           \
_(L2_FLAGS_REPLY, l2_flags_reply)                                       \
_(BRIDGE_FLAGS_REPLY, bridge_flags_reply)                               \
_(TAP_CONNECT_REPLY, tap_connect_reply)					\
_(TAP_MODIFY_REPLY, tap_modify_reply)					\
_(TAP_DELETE_REPLY, tap_delete_reply)					\
_(SW_INTERFACE_TAP_DETAILS, sw_interface_tap_details)                   \
_(TAP_CREATE_V2_REPLY, tap_create_v2_reply)				\
_(TAP_DELETE_V2_REPLY, tap_delete_v2_reply)				\
_(SW_INTERFACE_TAP_V2_DETAILS, sw_interface_tap_v2_details)             \
_(BOND_CREATE_REPLY, bond_create_reply)	   			        \
_(BOND_DELETE_REPLY, bond_delete_reply)			  	        \
_(BOND_ENSLAVE_REPLY, bond_enslave_reply)				\
_(BOND_DETACH_SLAVE_REPLY, bond_detach_slave_reply)			\
_(SW_INTERFACE_BOND_DETAILS, sw_interface_bond_details)                 \
_(SW_INTERFACE_SLAVE_DETAILS, sw_interface_slave_details)               \
_(IP_ADD_DEL_ROUTE_REPLY, ip_add_del_route_reply)			\
_(IP_TABLE_ADD_DEL_REPLY, ip_table_add_del_reply)			\
_(IP_MROUTE_ADD_DEL_REPLY, ip_mroute_add_del_reply)			\
_(MPLS_TABLE_ADD_DEL_REPLY, mpls_table_add_del_reply)			\
_(MPLS_ROUTE_ADD_DEL_REPLY, mpls_route_add_del_reply)			\
_(MPLS_IP_BIND_UNBIND_REPLY, mpls_ip_bind_unbind_reply)			\
_(BIER_ROUTE_ADD_DEL_REPLY, bier_route_add_del_reply)			\
_(BIER_TABLE_ADD_DEL_REPLY, bier_table_add_del_reply)			\
_(PROXY_ARP_ADD_DEL_REPLY, proxy_arp_add_del_reply)                     \
_(PROXY_ARP_INTFC_ENABLE_DISABLE_REPLY,                                 \
  proxy_arp_intfc_enable_disable_reply)                                 \
_(MPLS_TUNNEL_ADD_DEL_REPLY, mpls_tunnel_add_del_reply)                 \
_(SW_INTERFACE_SET_UNNUMBERED_REPLY,                                    \
  sw_interface_set_unnumbered_reply)                                    \
_(IP_NEIGHBOR_ADD_DEL_REPLY, ip_neighbor_add_del_reply)                 \
_(CREATE_VLAN_SUBIF_REPLY, create_vlan_subif_reply)                     \
_(CREATE_SUBIF_REPLY, create_subif_reply)                     		\
_(OAM_ADD_DEL_REPLY, oam_add_del_reply)                                 \
_(RESET_FIB_REPLY, reset_fib_reply)                                     \
_(DHCP_PROXY_CONFIG_REPLY, dhcp_proxy_config_reply)                     \
_(DHCP_PROXY_SET_VSS_REPLY, dhcp_proxy_set_vss_reply)                   \
_(DHCP_PROXY_DETAILS, dhcp_proxy_details)                               \
_(DHCP_CLIENT_CONFIG_REPLY, dhcp_client_config_reply)                   \
_(SET_IP_FLOW_HASH_REPLY, set_ip_flow_hash_reply)                       \
_(SW_INTERFACE_IP6_ENABLE_DISABLE_REPLY,                                \
  sw_interface_ip6_enable_disable_reply)                                \
_(IP6ND_PROXY_ADD_DEL_REPLY, ip6nd_proxy_add_del_reply)                 \
_(IP6ND_PROXY_DETAILS, ip6nd_proxy_details)                             \
_(SW_INTERFACE_IP6ND_RA_PREFIX_REPLY,                                   \
  sw_interface_ip6nd_ra_prefix_reply)                                   \
_(SW_INTERFACE_IP6ND_RA_CONFIG_REPLY,                                   \
  sw_interface_ip6nd_ra_config_reply)                                   \
_(SET_ARP_NEIGHBOR_LIMIT_REPLY, set_arp_neighbor_limit_reply)           \
_(L2_PATCH_ADD_DEL_REPLY, l2_patch_add_del_reply)                       \
_(SR_MPLS_POLICY_ADD_REPLY, sr_mpls_policy_add_reply)                   \
_(SR_MPLS_POLICY_MOD_REPLY, sr_mpls_policy_mod_reply)                   \
_(SR_MPLS_POLICY_DEL_REPLY, sr_mpls_policy_del_reply)                   \
_(SR_POLICY_ADD_REPLY, sr_policy_add_reply)                             \
_(SR_POLICY_MOD_REPLY, sr_policy_mod_reply)                             \
_(SR_POLICY_DEL_REPLY, sr_policy_del_reply)                             \
_(SR_LOCALSID_ADD_DEL_REPLY, sr_localsid_add_del_reply)                 \
_(SR_STEERING_ADD_DEL_REPLY, sr_steering_add_del_reply)                 \
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
_(VXLAN_OFFLOAD_RX_REPLY, vxlan_offload_rx_reply)               \
_(GENEVE_ADD_DEL_TUNNEL_REPLY, geneve_add_del_tunnel_reply)             \
_(VXLAN_TUNNEL_DETAILS, vxlan_tunnel_details)                           \
_(GENEVE_TUNNEL_DETAILS, geneve_tunnel_details)                         \
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
_(SHOW_THREADS_REPLY, show_threads_reply)                               \
_(L2_FIB_TABLE_DETAILS, l2_fib_table_details)				\
_(VXLAN_GPE_ADD_DEL_TUNNEL_REPLY, vxlan_gpe_add_del_tunnel_reply)	\
_(VXLAN_GPE_TUNNEL_DETAILS, vxlan_gpe_tunnel_details)                   \
_(INTERFACE_NAME_RENUMBER_REPLY, interface_name_renumber_reply)		\
_(IP_PROBE_NEIGHBOR_REPLY, ip_probe_neighbor_reply)			\
_(IP_SCAN_NEIGHBOR_ENABLE_DISABLE_REPLY, ip_scan_neighbor_enable_disable_reply) \
_(WANT_IP4_ARP_EVENTS_REPLY, want_ip4_arp_events_reply)			\
_(IP4_ARP_EVENT, ip4_arp_event)                                         \
_(WANT_IP6_ND_EVENTS_REPLY, want_ip6_nd_events_reply)			\
_(IP6_ND_EVENT, ip6_nd_event)						\
_(WANT_L2_MACS_EVENTS_REPLY, want_l2_macs_events_reply)			\
_(L2_MACS_EVENT, l2_macs_event)						\
_(INPUT_ACL_SET_INTERFACE_REPLY, input_acl_set_interface_reply)         \
_(IP_ADDRESS_DETAILS, ip_address_details)                               \
_(IP_DETAILS, ip_details)                                               \
_(IPSEC_SPD_ADD_DEL_REPLY, ipsec_spd_add_del_reply)                     \
_(IPSEC_INTERFACE_ADD_DEL_SPD_REPLY, ipsec_interface_add_del_spd_reply) \
_(IPSEC_SPD_ADD_DEL_ENTRY_REPLY, ipsec_spd_add_del_entry_reply)         \
_(IPSEC_SAD_ADD_DEL_ENTRY_REPLY, ipsec_sad_add_del_entry_reply)         \
_(IPSEC_SA_DETAILS, ipsec_sa_details)                                   \
_(IPSEC_SA_SET_KEY_REPLY, ipsec_sa_set_key_reply)                       \
_(IPSEC_TUNNEL_IF_ADD_DEL_REPLY, ipsec_tunnel_if_add_del_reply)         \
_(IPSEC_TUNNEL_IF_SET_KEY_REPLY, ipsec_tunnel_if_set_key_reply)         \
_(IPSEC_TUNNEL_IF_SET_SA_REPLY, ipsec_tunnel_if_set_sa_reply)           \
_(IKEV2_PROFILE_ADD_DEL_REPLY, ikev2_profile_add_del_reply)             \
_(IKEV2_PROFILE_SET_AUTH_REPLY, ikev2_profile_set_auth_reply)           \
_(IKEV2_PROFILE_SET_ID_REPLY, ikev2_profile_set_id_reply)               \
_(IKEV2_PROFILE_SET_TS_REPLY, ikev2_profile_set_ts_reply)               \
_(IKEV2_SET_LOCAL_KEY_REPLY, ikev2_set_local_key_reply)                 \
_(IKEV2_SET_RESPONDER_REPLY, ikev2_set_responder_reply)                 \
_(IKEV2_SET_IKE_TRANSFORMS_REPLY, ikev2_set_ike_transforms_reply)       \
_(IKEV2_SET_ESP_TRANSFORMS_REPLY, ikev2_set_esp_transforms_reply)       \
_(IKEV2_SET_SA_LIFETIME_REPLY, ikev2_set_sa_lifetime_reply)             \
_(IKEV2_INITIATE_SA_INIT_REPLY, ikev2_initiate_sa_init_reply)           \
_(IKEV2_INITIATE_DEL_IKE_SA_REPLY, ikev2_initiate_del_ike_sa_reply)     \
_(IKEV2_INITIATE_DEL_CHILD_SA_REPLY, ikev2_initiate_del_child_sa_reply) \
_(IKEV2_INITIATE_REKEY_CHILD_SA_REPLY, ikev2_initiate_rekey_child_sa_reply) \
_(DELETE_LOOPBACK_REPLY, delete_loopback_reply)                         \
_(BD_IP_MAC_ADD_DEL_REPLY, bd_ip_mac_add_del_reply)                     \
_(BD_IP_MAC_FLUSH_REPLY, bd_ip_mac_flush_reply)                         \
_(BD_IP_MAC_DETAILS, bd_ip_mac_details)                                 \
_(DHCP_COMPL_EVENT, dhcp_compl_event)                                   \
_(WANT_INTERFACE_EVENTS_REPLY, want_interface_events_reply)             \
_(GET_FIRST_MSG_ID_REPLY, get_first_msg_id_reply)    			\
_(COP_INTERFACE_ENABLE_DISABLE_REPLY, cop_interface_enable_disable_reply) \
_(COP_WHITELIST_ENABLE_DISABLE_REPLY, cop_whitelist_enable_disable_reply) \
_(GET_NODE_GRAPH_REPLY, get_node_graph_reply)                           \
_(SW_INTERFACE_CLEAR_STATS_REPLY, sw_interface_clear_stats_reply)      \
_(IOAM_ENABLE_REPLY, ioam_enable_reply)                   \
_(IOAM_DISABLE_REPLY, ioam_disable_reply)                     \
_(ONE_ADD_DEL_LOCATOR_SET_REPLY, one_add_del_locator_set_reply)         \
_(ONE_ADD_DEL_LOCATOR_REPLY, one_add_del_locator_reply)                 \
_(ONE_ADD_DEL_LOCAL_EID_REPLY, one_add_del_local_eid_reply)             \
_(ONE_ADD_DEL_REMOTE_MAPPING_REPLY, one_add_del_remote_mapping_reply)   \
_(ONE_ADD_DEL_ADJACENCY_REPLY, one_add_del_adjacency_reply)             \
_(ONE_ADD_DEL_MAP_RESOLVER_REPLY, one_add_del_map_resolver_reply)       \
_(ONE_ADD_DEL_MAP_SERVER_REPLY, one_add_del_map_server_reply)           \
_(ONE_ENABLE_DISABLE_REPLY, one_enable_disable_reply)                   \
_(ONE_MAP_REGISTER_ENABLE_DISABLE_REPLY,                                \
  one_map_register_enable_disable_reply)                                \
_(ONE_MAP_REGISTER_SET_TTL_REPLY, one_map_register_set_ttl_reply)       \
_(ONE_SET_TRANSPORT_PROTOCOL_REPLY, one_set_transport_protocol_reply)   \
_(ONE_GET_TRANSPORT_PROTOCOL_REPLY, one_get_transport_protocol_reply)   \
_(ONE_MAP_REGISTER_FALLBACK_THRESHOLD_REPLY,                            \
  one_map_register_fallback_threshold_reply)                            \
_(ONE_RLOC_PROBE_ENABLE_DISABLE_REPLY,                                  \
  one_rloc_probe_enable_disable_reply)                                  \
_(ONE_PITR_SET_LOCATOR_SET_REPLY, one_pitr_set_locator_set_reply)       \
_(ONE_USE_PETR_REPLY, one_use_petr_reply)                               \
_(ONE_MAP_REQUEST_MODE_REPLY, one_map_request_mode_reply)               \
_(ONE_EID_TABLE_ADD_DEL_MAP_REPLY, one_eid_table_add_del_map_reply)     \
_(ONE_LOCATOR_SET_DETAILS, one_locator_set_details)                     \
_(ONE_LOCATOR_DETAILS, one_locator_details)                             \
_(ONE_EID_TABLE_DETAILS, one_eid_table_details)                         \
_(ONE_EID_TABLE_MAP_DETAILS, one_eid_table_map_details)                 \
_(ONE_EID_TABLE_VNI_DETAILS, one_eid_table_vni_details)                 \
_(ONE_MAP_RESOLVER_DETAILS, one_map_resolver_details)                   \
_(ONE_MAP_SERVER_DETAILS, one_map_server_details)                       \
_(ONE_ADJACENCIES_GET_REPLY, one_adjacencies_get_reply)                 \
_(ONE_STATS_DETAILS, one_stats_details)                                 \
_(ONE_STATS_FLUSH_REPLY, one_stats_flush_reply)                         \
_(ONE_STATS_ENABLE_DISABLE_REPLY, one_stats_enable_disable_reply)       \
_(SHOW_ONE_STATS_ENABLE_DISABLE_REPLY,                                  \
  show_one_stats_enable_disable_reply)                                  \
_(ONE_ADD_DEL_NDP_ENTRY_REPLY, one_add_del_ndp_entry_reply)             \
_(ONE_NDP_BD_GET_REPLY, one_ndp_bd_get_reply)                           \
_(ONE_NDP_ENTRIES_GET_REPLY, one_ndp_entries_get_reply)                 \
_(ONE_ADD_DEL_L2_ARP_ENTRY_REPLY, one_add_del_l2_arp_entry_reply)       \
_(ONE_L2_ARP_BD_GET_REPLY, one_l2_arp_bd_get_reply)                     \
_(ONE_L2_ARP_ENTRIES_GET_REPLY, one_l2_arp_entries_get_reply)           \
_(ONE_ENABLE_DISABLE_XTR_MODE_REPLY, one_enable_disable_xtr_mode_reply) \
_(ONE_ENABLE_DISABLE_PITR_MODE_REPLY,                                   \
  one_enable_disable_pitr_mode_reply)                                   \
_(ONE_ENABLE_DISABLE_PETR_MODE_REPLY,                                   \
  one_enable_disable_petr_mode_reply)                                   \
_(ONE_SHOW_XTR_MODE_REPLY, one_show_xtr_mode_reply)                     \
_(ONE_SHOW_PITR_MODE_REPLY, one_show_pitr_mode_reply)                   \
_(ONE_SHOW_PETR_MODE_REPLY, one_show_petr_mode_reply)                   \
_(GPE_SET_ENCAP_MODE_REPLY, gpe_set_encap_mode_reply)                   \
_(GPE_GET_ENCAP_MODE_REPLY, gpe_get_encap_mode_reply)                   \
_(GPE_ADD_DEL_IFACE_REPLY, gpe_add_del_iface_reply)                     \
_(GPE_ENABLE_DISABLE_REPLY, gpe_enable_disable_reply)                   \
_(GPE_ADD_DEL_FWD_ENTRY_REPLY, gpe_add_del_fwd_entry_reply)             \
_(GPE_FWD_ENTRY_VNIS_GET_REPLY, gpe_fwd_entry_vnis_get_reply)           \
_(GPE_FWD_ENTRIES_GET_REPLY, gpe_fwd_entries_get_reply)                 \
_(GPE_NATIVE_FWD_RPATHS_GET_REPLY, gpe_native_fwd_rpaths_get_reply)     \
_(GPE_ADD_DEL_NATIVE_FWD_RPATH_REPLY,                                   \
  gpe_add_del_native_fwd_rpath_reply)                                   \
_(GPE_FWD_ENTRY_PATH_DETAILS,                                           \
  gpe_fwd_entry_path_details)                                           \
_(SHOW_ONE_STATUS_REPLY, show_one_status_reply)                         \
_(ONE_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY,                              \
  one_add_del_map_request_itr_rlocs_reply)                              \
_(ONE_GET_MAP_REQUEST_ITR_RLOCS_REPLY,                                  \
  one_get_map_request_itr_rlocs_reply)                                  \
_(SHOW_ONE_NSH_MAPPING_REPLY, show_one_nsh_mapping_reply)               \
_(SHOW_ONE_PITR_REPLY, show_one_pitr_reply)                             \
_(SHOW_ONE_USE_PETR_REPLY, show_one_use_petr_reply)                     \
_(SHOW_ONE_MAP_REQUEST_MODE_REPLY, show_one_map_request_mode_reply)     \
_(SHOW_ONE_RLOC_PROBE_STATE_REPLY, show_one_rloc_probe_state_reply)     \
_(SHOW_ONE_MAP_REGISTER_STATE_REPLY,                                    \
  show_one_map_register_state_reply)                                    \
_(SHOW_ONE_MAP_REGISTER_TTL_REPLY, show_one_map_register_ttl_reply)     \
_(SHOW_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_REPLY,                       \
  show_one_map_register_fallback_threshold_reply)                       \
_(AF_PACKET_CREATE_REPLY, af_packet_create_reply)                       \
_(AF_PACKET_DELETE_REPLY, af_packet_delete_reply)                       \
_(AF_PACKET_DETAILS, af_packet_details)					\
_(POLICER_ADD_DEL_REPLY, policer_add_del_reply)                         \
_(POLICER_DETAILS, policer_details)                                     \
_(POLICER_CLASSIFY_SET_INTERFACE_REPLY, policer_classify_set_interface_reply) \
_(POLICER_CLASSIFY_DETAILS, policer_classify_details)                   \
_(NETMAP_CREATE_REPLY, netmap_create_reply)                             \
_(NETMAP_DELETE_REPLY, netmap_delete_reply)                             \
_(MPLS_TUNNEL_DETAILS, mpls_tunnel_details)                             \
_(MPLS_FIB_DETAILS, mpls_fib_details)                                   \
_(CLASSIFY_TABLE_IDS_REPLY, classify_table_ids_reply)                   \
_(CLASSIFY_TABLE_BY_INTERFACE_REPLY, classify_table_by_interface_reply) \
_(CLASSIFY_TABLE_INFO_REPLY, classify_table_info_reply)                 \
_(CLASSIFY_SESSION_DETAILS, classify_session_details)                   \
_(SET_IPFIX_EXPORTER_REPLY, set_ipfix_exporter_reply)                   \
_(IPFIX_EXPORTER_DETAILS, ipfix_exporter_details)                       \
_(SET_IPFIX_CLASSIFY_STREAM_REPLY, set_ipfix_classify_stream_reply)     \
_(IPFIX_CLASSIFY_STREAM_DETAILS, ipfix_classify_stream_details)         \
_(IPFIX_CLASSIFY_TABLE_ADD_DEL_REPLY, ipfix_classify_table_add_del_reply) \
_(IPFIX_CLASSIFY_TABLE_DETAILS, ipfix_classify_table_details)           \
_(FLOW_CLASSIFY_SET_INTERFACE_REPLY, flow_classify_set_interface_reply) \
_(FLOW_CLASSIFY_DETAILS, flow_classify_details)                         \
_(SW_INTERFACE_SPAN_ENABLE_DISABLE_REPLY, sw_interface_span_enable_disable_reply) \
_(SW_INTERFACE_SPAN_DETAILS, sw_interface_span_details)                 \
_(GET_NEXT_INDEX_REPLY, get_next_index_reply)                           \
_(PG_CREATE_INTERFACE_REPLY, pg_create_interface_reply)                 \
_(PG_CAPTURE_REPLY, pg_capture_reply)                                   \
_(PG_ENABLE_DISABLE_REPLY, pg_enable_disable_reply)                     \
_(IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL_REPLY,                         \
 ip_source_and_port_range_check_add_del_reply)                          \
_(IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL_REPLY,               \
 ip_source_and_port_range_check_interface_add_del_reply)                \
_(IPSEC_GRE_ADD_DEL_TUNNEL_REPLY, ipsec_gre_add_del_tunnel_reply)       \
_(IPSEC_GRE_TUNNEL_DETAILS, ipsec_gre_tunnel_details)                   \
_(DELETE_SUBIF_REPLY, delete_subif_reply)                               \
_(L2_INTERFACE_PBB_TAG_REWRITE_REPLY, l2_interface_pbb_tag_rewrite_reply) \
_(SET_PUNT_REPLY, set_punt_reply)                                       \
_(IP_FIB_DETAILS, ip_fib_details)                                       \
_(IP6_FIB_DETAILS, ip6_fib_details)                                     \
_(FEATURE_ENABLE_DISABLE_REPLY, feature_enable_disable_reply)           \
_(SW_INTERFACE_TAG_ADD_DEL_REPLY, sw_interface_tag_add_del_reply)     	\
_(L2_XCONNECT_DETAILS, l2_xconnect_details)                             \
_(HW_INTERFACE_SET_MTU_REPLY, hw_interface_set_mtu_reply)               \
_(IP_NEIGHBOR_DETAILS, ip_neighbor_details)                             \
_(SW_INTERFACE_GET_TABLE_REPLY, sw_interface_get_table_reply)           \
_(P2P_ETHERNET_ADD_REPLY, p2p_ethernet_add_reply)                       \
_(P2P_ETHERNET_DEL_REPLY, p2p_ethernet_del_reply)                       \
_(LLDP_CONFIG_REPLY, lldp_config_reply)                                 \
_(SW_INTERFACE_SET_LLDP_REPLY, sw_interface_set_lldp_reply)		\
_(TCP_CONFIGURE_SRC_ADDRESSES_REPLY, tcp_configure_src_addresses_reply)	\
_(APP_NAMESPACE_ADD_DEL_REPLY, app_namespace_add_del_reply)		\
_(DNS_ENABLE_DISABLE_REPLY, dns_enable_disable_reply)                   \
_(DNS_NAME_SERVER_ADD_DEL_REPLY, dns_name_server_add_del_reply)		\
_(DNS_RESOLVE_NAME_REPLY, dns_resolve_name_reply)			\
_(DNS_RESOLVE_IP_REPLY, dns_resolve_ip_reply)				\
_(SESSION_RULE_ADD_DEL_REPLY, session_rule_add_del_reply)		\
_(SESSION_RULES_DETAILS, session_rules_details)				\
_(IP_CONTAINER_PROXY_ADD_DEL_REPLY, ip_container_proxy_add_del_reply)	\
_(OUTPUT_ACL_SET_INTERFACE_REPLY, output_acl_set_interface_reply)       \
_(QOS_RECORD_ENABLE_DISABLE_REPLY, qos_record_enable_disable_reply)

#define foreach_standalone_reply_msg					\
_(SW_INTERFACE_EVENT, sw_interface_event)

typedef struct
{
  u8 *name;
  u32 value;
} name_sort_t;

#define STR_VTR_OP_CASE(op)     \
    case L2_VTR_ ## op:         \
        return "" # op;

static const char *
str_vtr_op (u32 vtr_op)
{
  switch (vtr_op)
    {
      STR_VTR_OP_CASE (DISABLED);
      STR_VTR_OP_CASE (PUSH_1);
      STR_VTR_OP_CASE (PUSH_2);
      STR_VTR_OP_CASE (POP_1);
      STR_VTR_OP_CASE (POP_2);
      STR_VTR_OP_CASE (TRANSLATE_1_1);
      STR_VTR_OP_CASE (TRANSLATE_1_2);
      STR_VTR_OP_CASE (TRANSLATE_2_1);
      STR_VTR_OP_CASE (TRANSLATE_2_2);
    }

  return "UNKNOWN";
}

static int
dump_sub_interface_table (vat_main_t * vam)
{
  const sw_interface_subif_t *sub = NULL;

  if (vam->json_output)
    {
      clib_warning
	("JSON output supported only for VPE API calls and dump_stats_table");
      return -99;
    }

  print (vam->ofp,
	 "%-30s%-12s%-11s%-7s%-5s%-9s%-9s%-6s%-8s%-10s%-10s",
	 "Interface", "sw_if_index",
	 "sub id", "dot1ad", "tags", "outer id",
	 "inner id", "exact", "default", "outer any", "inner any");

  vec_foreach (sub, vam->sw_if_subif_table)
  {
    print (vam->ofp,
	   "%-30s%-12d%-11d%-7s%-5d%-9d%-9d%-6d%-8d%-10d%-10d",
	   sub->interface_name,
	   sub->sw_if_index,
	   sub->sub_id, sub->sub_dot1ad ? "dot1ad" : "dot1q",
	   sub->sub_number_of_tags, sub->sub_outer_vlan_id,
	   sub->sub_inner_vlan_id, sub->sub_exact_match, sub->sub_default,
	   sub->sub_outer_vlan_id_any, sub->sub_inner_vlan_id_any);
    if (sub->vtr_op != L2_VTR_DISABLED)
      {
	print (vam->ofp,
	       "  vlan-tag-rewrite - op: %-14s [ dot1q: %d "
	       "tag1: %d tag2: %d ]",
	       str_vtr_op (sub->vtr_op), sub->vtr_push_dot1q,
	       sub->vtr_tag1, sub->vtr_tag2);
      }
  }

  return 0;
}

static int
name_sort_cmp (void *a1, void *a2)
{
  name_sort_t *n1 = a1;
  name_sort_t *n2 = a2;

  return strcmp ((char *) n1->name, (char *) n2->name);
}

static int
dump_interface_table (vat_main_t * vam)
{
  hash_pair_t *p;
  name_sort_t *nses = 0, *ns;

  if (vam->json_output)
    {
      clib_warning
	("JSON output supported only for VPE API calls and dump_stats_table");
      return -99;
    }

  /* *INDENT-OFF* */
  hash_foreach_pair (p, vam->sw_if_index_by_interface_name,
  ({
    vec_add2 (nses, ns, 1);
    ns->name = (u8 *)(p->key);
    ns->value = (u32) p->value[0];
  }));
  /* *INDENT-ON* */

  vec_sort_with_function (nses, name_sort_cmp);

  print (vam->ofp, "%-25s%-15s", "Interface", "sw_if_index");
  vec_foreach (ns, nses)
  {
    print (vam->ofp, "%-25s%-15d", ns->name, ns->value);
  }
  vec_free (nses);
  return 0;
}

static int
dump_ip_table (vat_main_t * vam, int is_ipv6)
{
  const ip_details_t *det = NULL;
  const ip_address_details_t *address = NULL;
  u32 i = ~0;

  print (vam->ofp, "%-12s", "sw_if_index");

  vec_foreach (det, vam->ip_details_by_sw_if_index[is_ipv6])
  {
    i++;
    if (!det->present)
      {
	continue;
      }
    print (vam->ofp, "%-12d", i);
    print (vam->ofp, "            %-30s%-13s", "Address", "Prefix length");
    if (!det->addr)
      {
	continue;
      }
    vec_foreach (address, det->addr)
    {
      print (vam->ofp,
	     "            %-30U%-13d",
	     is_ipv6 ? format_ip6_address : format_ip4_address,
	     address->ip, address->prefix_length);
    }
  }

  return 0;
}

static int
dump_ipv4_table (vat_main_t * vam)
{
  if (vam->json_output)
    {
      clib_warning
	("JSON output supported only for VPE API calls and dump_stats_table");
      return -99;
    }

  return dump_ip_table (vam, 0);
}

static int
dump_ipv6_table (vat_main_t * vam)
{
  if (vam->json_output)
    {
      clib_warning
	("JSON output supported only for VPE API calls and dump_stats_table");
      return -99;
    }

  return dump_ip_table (vam, 1);
}

/*
 * Pass CLI buffers directly in the CLI_INBAND API message,
 * instead of an additional shared memory area.
 */
static int
exec_inband (vat_main_t * vam)
{
  vl_api_cli_inband_t *mp;
  unformat_input_t *i = vam->input;
  int ret;

  if (vec_len (i->buffer) == 0)
    return -1;

  if (vam->exec_mode == 0 && unformat (i, "mode"))
    {
      vam->exec_mode = 1;
      return 0;
    }
  if (vam->exec_mode == 1 && (unformat (i, "exit") || unformat (i, "quit")))
    {
      vam->exec_mode = 0;
      return 0;
    }

  /*
   * In order for the CLI command to work, it
   * must be a vector ending in \n, not a C-string ending
   * in \n\0.
   */
  u32 len = vec_len (vam->input->buffer);
  M2 (CLI_INBAND, mp, len);
  vl_api_to_api_string (len - 1, (const char *) vam->input->buffer, &mp->cmd);

  S (mp);
  W (ret);
  /* json responses may or may not include a useful reply... */
  if (vec_len (vam->cmd_reply))
    print (vam->ofp, "%v", (char *) (vam->cmd_reply));
  return ret;
}

int
exec (vat_main_t * vam)
{
  return exec_inband (vam);
}

static int
api_create_loopback (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_create_loopback_t *mp;
  vl_api_create_loopback_instance_t *mp_lbi;
  u8 mac_address[6];
  u8 mac_set = 0;
  u8 is_specified = 0;
  u32 user_instance = 0;
  int ret;

  clib_memset (mac_address, 0, sizeof (mac_address));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "mac %U", unformat_ethernet_address, mac_address))
	mac_set = 1;
      if (unformat (i, "instance %d", &user_instance))
	is_specified = 1;
      else
	break;
    }

  if (is_specified)
    {
      M (CREATE_LOOPBACK_INSTANCE, mp_lbi);
      mp_lbi->is_specified = is_specified;
      if (is_specified)
	mp_lbi->user_instance = htonl (user_instance);
      if (mac_set)
	clib_memcpy (mp_lbi->mac_address, mac_address, sizeof (mac_address));
      S (mp_lbi);
    }
  else
    {
      /* Construct the API message */
      M (CREATE_LOOPBACK, mp);
      if (mac_set)
	clib_memcpy (mp->mac_address, mac_address, sizeof (mac_address));
      S (mp);
    }

  W (ret);
  return ret;
}

static int
api_delete_loopback (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_delete_loopback_t *mp;
  u32 sw_if_index = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (DELETE_LOOPBACK, mp);
  mp->sw_if_index = ntohl (sw_if_index);

  S (mp);
  W (ret);
  return ret;
}

static int
api_want_interface_events (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_want_interface_events_t *mp;
  int enable = -1;
  int ret;

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
      errmsg ("missing enable|disable");
      return -99;
    }

  M (WANT_INTERFACE_EVENTS, mp);
  mp->enable_disable = enable;

  vam->interface_event_display = enable;

  S (mp);
  W (ret);
  return ret;
}


/* Note: non-static, called once to set up the initial intfc table */
int
api_sw_interface_dump (vat_main_t * vam)
{
  vl_api_sw_interface_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  hash_pair_t *p;
  name_sort_t *nses = 0, *ns;
  sw_interface_subif_t *sub = NULL;
  int ret;

  /* Toss the old name table */
  /* *INDENT-OFF* */
  hash_foreach_pair (p, vam->sw_if_index_by_interface_name,
  ({
    vec_add2 (nses, ns, 1);
    ns->name = (u8 *)(p->key);
    ns->value = (u32) p->value[0];
  }));
  /* *INDENT-ON* */

  hash_free (vam->sw_if_index_by_interface_name);

  vec_foreach (ns, nses) vec_free (ns->name);

  vec_free (nses);

  vec_foreach (sub, vam->sw_if_subif_table)
  {
    vec_free (sub->interface_name);
  }
  vec_free (vam->sw_if_subif_table);

  /* recreate the interface name hash table */
  vam->sw_if_index_by_interface_name = hash_create_string (0, sizeof (uword));

  /*
   * Ask for all interface names. Otherwise, the epic catalog of
   * name filters becomes ridiculously long, and vat ends up needing
   * to be taught about new interface types.
   */
  M (SW_INTERFACE_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_sw_interface_set_flags (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_flags_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 admin_up = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "admin-up"))
	admin_up = 1;
      else if (unformat (i, "admin-down"))
	admin_up = 0;
      else
	if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_SET_FLAGS, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->admin_up_down = admin_up;

  /* send it... */
  S (mp);

  /* Wait for a reply, return the good/bad news... */
  W (ret);
  return ret;
}

static int
api_sw_interface_set_rx_mode (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_rx_mode_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  int ret;
  u8 queue_id_valid = 0;
  u32 queue_id;
  vnet_hw_interface_rx_mode mode = VNET_HW_INTERFACE_RX_MODE_UNKNOWN;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "queue %d", &queue_id))
	queue_id_valid = 1;
      else if (unformat (i, "polling"))
	mode = VNET_HW_INTERFACE_RX_MODE_POLLING;
      else if (unformat (i, "interrupt"))
	mode = VNET_HW_INTERFACE_RX_MODE_INTERRUPT;
      else if (unformat (i, "adaptive"))
	mode = VNET_HW_INTERFACE_RX_MODE_ADAPTIVE;
      else
	if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }
  if (mode == VNET_HW_INTERFACE_RX_MODE_UNKNOWN)
    {
      errmsg ("missing rx-mode");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_SET_RX_MODE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->mode = mode;
  mp->queue_id_valid = queue_id_valid;
  mp->queue_id = queue_id_valid ? ntohl (queue_id) : ~0;

  /* send it... */
  S (mp);

  /* Wait for a reply, return the good/bad news... */
  W (ret);
  return ret;
}

static int
api_sw_interface_set_rx_placement (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_rx_placement_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  int ret;
  u8 is_main = 0;
  u32 queue_id, thread_index;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "queue %d", &queue_id))
	;
      else if (unformat (i, "main"))
	is_main = 1;
      else if (unformat (i, "worker %d", &thread_index))
	;
      else
	if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (is_main)
    thread_index = 0;
  /* Construct the API message */
  M (SW_INTERFACE_SET_RX_PLACEMENT, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->worker_id = ntohl (thread_index);
  mp->queue_id = ntohl (queue_id);
  mp->is_main = is_main;

  /* send it... */
  S (mp);
  /* Wait for a reply, return the good/bad news... */
  W (ret);
  return ret;
}

static void vl_api_sw_interface_rx_placement_details_t_handler
  (vl_api_sw_interface_rx_placement_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 worker_id = ntohl (mp->worker_id);

  print (vam->ofp,
	 "\n%-11d %-11s %-6d %-5d %-9s",
	 ntohl (mp->sw_if_index), (worker_id == 0) ? "main" : "worker",
	 worker_id, ntohl (mp->queue_id),
	 (mp->mode ==
	  1) ? "polling" : ((mp->mode == 2) ? "interrupt" : "adaptive"));
}

static void vl_api_sw_interface_rx_placement_details_t_handler_json
  (vl_api_sw_interface_rx_placement_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  vat_json_object_add_uint (node, "worker_id", ntohl (mp->worker_id));
  vat_json_object_add_uint (node, "queue_id", ntohl (mp->queue_id));
  vat_json_object_add_uint (node, "mode", mp->mode);
}

static int
api_sw_interface_rx_placement_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_rx_placement_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set++;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set++;
      else
	break;
    }

  print (vam->ofp,
	 "\n%-11s %-11s %-6s %-5s %-4s",
	 "sw_if_index", "main/worker", "thread", "queue", "mode");

  /* Dump Interface rx placement */
  M (SW_INTERFACE_RX_PLACEMENT_DUMP, mp);

  if (sw_if_index_set)
    mp->sw_if_index = htonl (sw_if_index);
  else
    mp->sw_if_index = ~0;

  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_sw_interface_clear_stats (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_clear_stats_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	break;
    }

  /* Construct the API message */
  M (SW_INTERFACE_CLEAR_STATS, mp);

  if (sw_if_index_set == 1)
    mp->sw_if_index = ntohl (sw_if_index);
  else
    mp->sw_if_index = ~0;

  /* send it... */
  S (mp);

  /* Wait for a reply, return the good/bad news... */
  W (ret);
  return ret;
}

static int
api_sw_interface_add_del_address (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_add_del_address_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 is_add = 1, del_all = 0;
  u32 address_length = 0;
  u8 v4_address_set = 0;
  u8 v6_address_set = 0;
  ip4_address_t v4address;
  ip6_address_t v6address;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del-all"))
	del_all = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "%U/%d",
			 unformat_ip4_address, &v4address, &address_length))
	v4_address_set = 1;
      else if (unformat (i, "%U/%d",
			 unformat_ip6_address, &v6address, &address_length))
	v6_address_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }
  if (v4_address_set && v6_address_set)
    {
      errmsg ("both v4 and v6 addresses set");
      return -99;
    }
  if (!v4_address_set && !v6_address_set && !del_all)
    {
      errmsg ("no addresses set");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_ADD_DEL_ADDRESS, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_add = is_add;
  mp->del_all = del_all;
  if (v6_address_set)
    {
      mp->is_ipv6 = 1;
      clib_memcpy (mp->address, &v6address, sizeof (v6address));
    }
  else
    {
      clib_memcpy (mp->address, &v4address, sizeof (v4address));
    }
  mp->address_length = address_length;

  /* send it... */
  S (mp);

  /* Wait for a reply, return good/bad news  */
  W (ret);
  return ret;
}

static int
api_sw_interface_set_mpls_enable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_mpls_enable_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 enable = 1;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "disable"))
	enable = 0;
      else if (unformat (i, "dis"))
	enable = 0;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_SET_MPLS_ENABLE, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable = enable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_sw_interface_set_table (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_table_t *mp;
  u32 sw_if_index, vrf_id = 0;
  u8 sw_if_index_set = 0;
  u8 is_ipv6 = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
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

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_SET_TABLE, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_ipv6 = is_ipv6;
  mp->vrf_id = ntohl (vrf_id);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void vl_api_sw_interface_get_table_reply_t_handler
  (vl_api_sw_interface_get_table_reply_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%d", ntohl (mp->vrf_id));

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;

}

static void vl_api_sw_interface_get_table_reply_t_handler_json
  (vl_api_sw_interface_get_table_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_int (&node, "vrf_id", ntohl (mp->vrf_id));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static int
api_sw_interface_get_table (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_get_table_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 is_ipv6 = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (SW_INTERFACE_GET_TABLE, mp);
  mp->sw_if_index = htonl (sw_if_index);
  mp->is_ipv6 = is_ipv6;

  S (mp);
  W (ret);
  return ret;
}

static int
api_sw_interface_set_vpath (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_vpath_t *mp;
  u32 sw_if_index = 0;
  u8 sw_if_index_set = 0;
  u8 is_enable = 0;
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
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_SET_VPATH, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable = is_enable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_sw_interface_set_vxlan_bypass (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_vxlan_bypass_t *mp;
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
  M (SW_INTERFACE_SET_VXLAN_BYPASS, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable = is_enable;
  mp->is_ipv6 = is_ipv6;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
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

static int
api_sw_interface_set_l2_xconnect (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_l2_xconnect_t *mp;
  u32 rx_sw_if_index;
  u8 rx_sw_if_index_set = 0;
  u32 tx_sw_if_index;
  u8 tx_sw_if_index_set = 0;
  u8 enable = 1;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "rx_sw_if_index %d", &rx_sw_if_index))
	rx_sw_if_index_set = 1;
      else if (unformat (i, "tx_sw_if_index %d", &tx_sw_if_index))
	tx_sw_if_index_set = 1;
      else if (unformat (i, "rx"))
	{
	  if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (i, "%U", api_unformat_sw_if_index, vam,
			    &rx_sw_if_index))
		rx_sw_if_index_set = 1;
	    }
	  else
	    break;
	}
      else if (unformat (i, "tx"))
	{
	  if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (i, "%U", api_unformat_sw_if_index, vam,
			    &tx_sw_if_index))
		tx_sw_if_index_set = 1;
	    }
	  else
	    break;
	}
      else if (unformat (i, "enable"))
	enable = 1;
      else if (unformat (i, "disable"))
	enable = 0;
      else
	break;
    }

  if (rx_sw_if_index_set == 0)
    {
      errmsg ("missing rx interface name or rx_sw_if_index");
      return -99;
    }

  if (enable && (tx_sw_if_index_set == 0))
    {
      errmsg ("missing tx interface name or tx_sw_if_index");
      return -99;
    }

  M (SW_INTERFACE_SET_L2_XCONNECT, mp);

  mp->rx_sw_if_index = ntohl (rx_sw_if_index);
  mp->tx_sw_if_index = ntohl (tx_sw_if_index);
  mp->enable = enable;

  S (mp);
  W (ret);
  return ret;
}

static int
api_sw_interface_set_l2_bridge (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_l2_bridge_t *mp;
  vl_api_l2_port_type_t port_type;
  u32 rx_sw_if_index;
  u8 rx_sw_if_index_set = 0;
  u32 bd_id;
  u8 bd_id_set = 0;
  u32 shg = 0;
  u8 enable = 1;
  int ret;

  port_type = L2_API_PORT_TYPE_NORMAL;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &rx_sw_if_index))
	rx_sw_if_index_set = 1;
      else if (unformat (i, "bd_id %d", &bd_id))
	bd_id_set = 1;
      else
	if (unformat
	    (i, "%U", api_unformat_sw_if_index, vam, &rx_sw_if_index))
	rx_sw_if_index_set = 1;
      else if (unformat (i, "shg %d", &shg))
	;
      else if (unformat (i, "bvi"))
	port_type = L2_API_PORT_TYPE_BVI;
      else if (unformat (i, "uu-fwd"))
	port_type = L2_API_PORT_TYPE_UU_FWD;
      else if (unformat (i, "enable"))
	enable = 1;
      else if (unformat (i, "disable"))
	enable = 0;
      else
	break;
    }

  if (rx_sw_if_index_set == 0)
    {
      errmsg ("missing rx interface name or sw_if_index");
      return -99;
    }

  if (enable && (bd_id_set == 0))
    {
      errmsg ("missing bridge domain");
      return -99;
    }

  M (SW_INTERFACE_SET_L2_BRIDGE, mp);

  mp->rx_sw_if_index = ntohl (rx_sw_if_index);
  mp->bd_id = ntohl (bd_id);
  mp->shg = (u8) shg;
  mp->port_type = ntohl (port_type);
  mp->enable = enable;

  S (mp);
  W (ret);
  return ret;
}

static int
api_bridge_domain_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bridge_domain_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 bd_id = ~0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id))
	;
      else
	break;
    }

  M (BRIDGE_DOMAIN_DUMP, mp);
  mp->bd_id = ntohl (bd_id);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_bridge_domain_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bridge_domain_add_del_t *mp;
  u32 bd_id = ~0;
  u8 is_add = 1;
  u32 flood = 1, forward = 1, learn = 1, uu_flood = 1, arp_term = 0;
  u8 *bd_tag = NULL;
  u32 mac_age = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
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
      else if (unformat (i, "mac-age %d", &mac_age))
	;
      else if (unformat (i, "bd-tag %s", &bd_tag))
	;
      else if (unformat (i, "del"))
	{
	  is_add = 0;
	  flood = uu_flood = forward = learn = 0;
	}
      else
	break;
    }

  if (bd_id == ~0)
    {
      errmsg ("missing bridge domain");
      ret = -99;
      goto done;
    }

  if (mac_age > 255)
    {
      errmsg ("mac age must be less than 256 ");
      ret = -99;
      goto done;
    }

  if ((bd_tag) && (vec_len (bd_tag) > 63))
    {
      errmsg ("bd-tag cannot be longer than 63");
      ret = -99;
      goto done;
    }

  M (BRIDGE_DOMAIN_ADD_DEL, mp);

  mp->bd_id = ntohl (bd_id);
  mp->flood = flood;
  mp->uu_flood = uu_flood;
  mp->forward = forward;
  mp->learn = learn;
  mp->arp_term = arp_term;
  mp->is_add = is_add;
  mp->mac_age = (u8) mac_age;
  if (bd_tag)
    {
      clib_memcpy (mp->bd_tag, bd_tag, vec_len (bd_tag));
      mp->bd_tag[vec_len (bd_tag)] = 0;
    }
  S (mp);
  W (ret);

done:
  vec_free (bd_tag);
  return ret;
}

static int
api_l2fib_flush_bd (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_l2fib_flush_bd_t *mp;
  u32 bd_id = ~0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id));
      else
	break;
    }

  if (bd_id == ~0)
    {
      errmsg ("missing bridge domain");
      return -99;
    }

  M (L2FIB_FLUSH_BD, mp);

  mp->bd_id = htonl (bd_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_l2fib_flush_int (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_l2fib_flush_int_t *mp;
  u32 sw_if_index = ~0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index));
      else
	if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index));
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (L2FIB_FLUSH_INT, mp);

  mp->sw_if_index = ntohl (sw_if_index);

  S (mp);
  W (ret);
  return ret;
}

static int
api_l2fib_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_l2fib_add_del_t *mp;
  f64 timeout;
  u8 mac[6] = { 0 };
  u8 mac_set = 0;
  u32 bd_id;
  u8 bd_id_set = 0;
  u32 sw_if_index = 0;
  u8 sw_if_index_set = 0;
  u8 is_add = 1;
  u8 static_mac = 0;
  u8 filter_mac = 0;
  u8 bvi_mac = 0;
  int count = 1;
  f64 before = 0;
  int j;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "mac %U", unformat_ethernet_address, mac))
	mac_set = 1;
      else if (unformat (i, "bd_id %d", &bd_id))
	bd_id_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if"))
	{
	  if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat
		  (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
		sw_if_index_set = 1;
	    }
	  else
	    break;
	}
      else if (unformat (i, "static"))
	static_mac = 1;
      else if (unformat (i, "filter"))
	{
	  filter_mac = 1;
	  static_mac = 1;
	}
      else if (unformat (i, "bvi"))
	{
	  bvi_mac = 1;
	  static_mac = 1;
	}
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "count %d", &count))
	;
      else
	break;
    }

  if (mac_set == 0)
    {
      errmsg ("missing mac address");
      return -99;
    }

  if (bd_id_set == 0)
    {
      errmsg ("missing bridge domain");
      return -99;
    }

  if (is_add && sw_if_index_set == 0 && filter_mac == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (count > 1)
    {
      /* Turn on async mode */
      vam->async_mode = 1;
      vam->async_errors = 0;
      before = vat_time_now (vam);
    }

  for (j = 0; j < count; j++)
    {
      M (L2FIB_ADD_DEL, mp);

      clib_memcpy (mp->mac, mac, 6);
      mp->bd_id = ntohl (bd_id);
      mp->is_add = is_add;
      mp->sw_if_index = ntohl (sw_if_index);

      if (is_add)
	{
	  mp->static_mac = static_mac;
	  mp->filter_mac = filter_mac;
	  mp->bvi_mac = bvi_mac;
	}
      increment_mac_address (mac);
      /* send it... */
      S (mp);
    }

  if (count > 1)
    {
      vl_api_control_ping_t *mp_ping;
      f64 after;

      /* Shut off async mode */
      vam->async_mode = 0;

      MPING (CONTROL_PING, mp_ping);
      S (mp_ping);

      timeout = vat_time_now (vam) + 1.0;
      while (vat_time_now (vam) < timeout)
	if (vam->result_ready == 1)
	  goto out;
      vam->retval = -99;

    out:
      if (vam->retval == -99)
	errmsg ("timeout");

      if (vam->async_errors > 0)
	{
	  errmsg ("%d asynchronous errors", vam->async_errors);
	  vam->retval = -98;
	}
      vam->async_errors = 0;
      after = vat_time_now (vam);

      print (vam->ofp, "%d routes in %.6f secs, %.2f routes/sec",
	     count, after - before, count / (after - before));
    }
  else
    {
      int ret;

      /* Wait for a reply... */
      W (ret);
      return ret;
    }
  /* Return the good/bad news */
  return (vam->retval);
}

static int
api_bridge_domain_set_mac_age (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bridge_domain_set_mac_age_t *mp;
  u32 bd_id = ~0;
  u32 mac_age = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id));
      else if (unformat (i, "mac-age %d", &mac_age));
      else
	break;
    }

  if (bd_id == ~0)
    {
      errmsg ("missing bridge domain");
      return -99;
    }

  if (mac_age > 255)
    {
      errmsg ("mac age must be less than 256 ");
      return -99;
    }

  M (BRIDGE_DOMAIN_SET_MAC_AGE, mp);

  mp->bd_id = htonl (bd_id);
  mp->mac_age = (u8) mac_age;

  S (mp);
  W (ret);
  return ret;
}

static int
api_l2_flags (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_l2_flags_t *mp;
  u32 sw_if_index;
  u32 flags = 0;
  u8 sw_if_index_set = 0;
  u8 is_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if"))
	{
	  if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat
		  (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
		sw_if_index_set = 1;
	    }
	  else
	    break;
	}
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

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (L2_FLAGS, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->feature_bitmap = ntohl (flags);
  mp->is_set = is_set;

  S (mp);
  W (ret);
  return ret;
}

static int
api_bridge_flags (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bridge_flags_t *mp;
  u32 bd_id;
  u8 bd_id_set = 0;
  u8 is_set = 1;
  bd_flags_t flags = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id))
	bd_id_set = 1;
      else if (unformat (i, "learn"))
	flags |= BRIDGE_API_FLAG_LEARN;
      else if (unformat (i, "forward"))
	flags |= BRIDGE_API_FLAG_FWD;
      else if (unformat (i, "flood"))
	flags |= BRIDGE_API_FLAG_FLOOD;
      else if (unformat (i, "uu-flood"))
	flags |= BRIDGE_API_FLAG_UU_FLOOD;
      else if (unformat (i, "arp-term"))
	flags |= BRIDGE_API_FLAG_ARP_TERM;
      else if (unformat (i, "off"))
	is_set = 0;
      else if (unformat (i, "disable"))
	is_set = 0;
      else
	break;
    }

  if (bd_id_set == 0)
    {
      errmsg ("missing bridge domain");
      return -99;
    }

  M (BRIDGE_FLAGS, mp);

  mp->bd_id = ntohl (bd_id);
  mp->flags = ntohl (flags);
  mp->is_set = is_set;

  S (mp);
  W (ret);
  return ret;
}

static int
api_bd_ip_mac_add_del (vat_main_t * vam)
{
  vl_api_address_t ip = VL_API_ZERO_ADDRESS;
  vl_api_mac_address_t mac = { 0 };
  unformat_input_t *i = vam->input;
  vl_api_bd_ip_mac_add_del_t *mp;
  ip46_type_t type;
  u32 bd_id;
  u8 is_ipv6 = 0;
  u8 is_add = 1;
  u8 bd_id_set = 0;
  u8 ip_set = 0;
  u8 mac_set = 0;
  u8 macaddr[6];
  int ret;


  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id))
	{
	  bd_id_set++;
	}
      else if (unformat (i, "%U", unformat_vl_api_address, &ip))
	{
	  ip_set++;
	}
      else if (unformat (i, "%U", unformat_vl_api_mac_address, &mac))
	{
	  mac_set++;
	}
      else if (unformat (i, "del"))
	is_add = 0;
      else
	break;
    }

  if (bd_id_set == 0)
    {
      errmsg ("missing bridge domain");
      return -99;
    }
  else if (ip_set == 0)
    {
      errmsg ("missing IP address");
      return -99;
    }
  else if (mac_set == 0)
    {
      errmsg ("missing MAC address");
      return -99;
    }

  M (BD_IP_MAC_ADD_DEL, mp);

  mp->bd_id = ntohl (bd_id);
  mp->is_add = is_add;

  clib_memcpy (&mp->ip, &ip, sizeof (ip));
  clib_memcpy (&mp->mac, &mac, sizeof (mac));

  S (mp);
  W (ret);
  return ret;
}

static int
api_bd_ip_mac_flush (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bd_ip_mac_flush_t *mp;
  u32 bd_id;
  u8 bd_id_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id))
	{
	  bd_id_set++;
	}
      else
	break;
    }

  if (bd_id_set == 0)
    {
      errmsg ("missing bridge domain");
      return -99;
    }

  M (BD_IP_MAC_FLUSH, mp);

  mp->bd_id = ntohl (bd_id);

  S (mp);
  W (ret);
  return ret;
}

static void vl_api_bd_ip_mac_details_t_handler
  (vl_api_bd_ip_mac_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u8 *ip = 0;

  if (!mp->is_ipv6)
    ip =
      format (0, "%U", format_ip4_address, (ip4_address_t *) mp->ip_address);
  else
    ip =
      format (0, "%U", format_ip6_address, (ip6_address_t *) mp->ip_address);

  print (vam->ofp,
	 "\n%-5d %-7s %-20U %-30s",
	 ntohl (mp->bd_id), mp->is_ipv6 ? "ip6" : "ip4",
	 format_ethernet_address, mp->mac_address, ip);

  vec_free (ip);
}

static void vl_api_bd_ip_mac_details_t_handler_json
  (vl_api_bd_ip_mac_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "bd_id", ntohl (mp->bd_id));
  vat_json_object_add_uint (node, "is_ipv6", mp->is_ipv6);
  vat_json_object_add_string_copy (node, "mac_address",
				   format (0, "%U", format_ethernet_address,
					   &mp->mac_address));
  u8 *ip = 0;

  if (!mp->is_ipv6)
    ip =
      format (0, "%U", format_ip4_address, (ip4_address_t *) mp->ip_address);
  else
    ip =
      format (0, "%U", format_ip6_address, (ip6_address_t *) mp->ip_address);
  vat_json_object_add_string_copy (node, "ip_address", ip);
  vec_free (ip);
}

static int
api_bd_ip_mac_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bd_ip_mac_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;
  u32 bd_id;
  u8 bd_id_set = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id))
	{
	  bd_id_set++;
	}
      else
	break;
    }

  print (vam->ofp,
	 "\n%-5s %-7s %-20s %-30s",
	 "bd_id", "is_ipv6", "mac_address", "ip_address");

  /* Dump Bridge Domain Ip to Mac entries */
  M (BD_IP_MAC_DUMP, mp);

  if (bd_id_set)
    mp->bd_id = htonl (bd_id);
  else
    mp->bd_id = ~0;

  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_tap_connect (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_tap_connect_t *mp;
  u8 mac_address[6];
  u8 random_mac = 1;
  u8 name_set = 0;
  u8 *tap_name;
  u8 *tag = 0;
  ip4_address_t ip4_address;
  u32 ip4_mask_width;
  int ip4_address_set = 0;
  ip6_address_t ip6_address;
  u32 ip6_mask_width;
  int ip6_address_set = 0;
  int ret;

  clib_memset (mac_address, 0, sizeof (mac_address));

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "mac %U", unformat_ethernet_address, mac_address))
	{
	  random_mac = 0;
	}
      else if (unformat (i, "random-mac"))
	random_mac = 1;
      else if (unformat (i, "tapname %s", &tap_name))
	name_set = 1;
      else if (unformat (i, "tag %s", &tag))
	;
      else if (unformat (i, "address %U/%d",
			 unformat_ip4_address, &ip4_address, &ip4_mask_width))
	ip4_address_set = 1;
      else if (unformat (i, "address %U/%d",
			 unformat_ip6_address, &ip6_address, &ip6_mask_width))
	ip6_address_set = 1;
      else
	break;
    }

  if (name_set == 0)
    {
      errmsg ("missing tap name");
      return -99;
    }
  if (vec_len (tap_name) > 63)
    {
      errmsg ("tap name too long");
      return -99;
    }
  vec_add1 (tap_name, 0);

  if (vec_len (tag) > 63)
    {
      errmsg ("tag too long");
      return -99;
    }

  /* Construct the API message */
  M (TAP_CONNECT, mp);

  mp->use_random_mac = random_mac;
  clib_memcpy (mp->mac_address, mac_address, 6);
  clib_memcpy (mp->tap_name, tap_name, vec_len (tap_name));
  if (tag)
    clib_memcpy (mp->tag, tag, vec_len (tag));

  if (ip4_address_set)
    {
      mp->ip4_address_set = 1;
      clib_memcpy (mp->ip4_address, &ip4_address, sizeof (mp->ip4_address));
      mp->ip4_mask_width = ip4_mask_width;
    }
  if (ip6_address_set)
    {
      mp->ip6_address_set = 1;
      clib_memcpy (mp->ip6_address, &ip6_address, sizeof (mp->ip6_address));
      mp->ip6_mask_width = ip6_mask_width;
    }

  vec_free (tap_name);
  vec_free (tag);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_tap_modify (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_tap_modify_t *mp;
  u8 mac_address[6];
  u8 random_mac = 1;
  u8 name_set = 0;
  u8 *tap_name;
  u32 sw_if_index = ~0;
  u8 sw_if_index_set = 0;
  int ret;

  clib_memset (mac_address, 0, sizeof (mac_address));

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "mac %U", unformat_ethernet_address, mac_address))
	{
	  random_mac = 0;
	}
      else if (unformat (i, "random-mac"))
	random_mac = 1;
      else if (unformat (i, "tapname %s", &tap_name))
	name_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing vpp interface name");
      return -99;
    }
  if (name_set == 0)
    {
      errmsg ("missing tap name");
      return -99;
    }
  if (vec_len (tap_name) > 63)
    {
      errmsg ("tap name too long");
    }
  vec_add1 (tap_name, 0);

  /* Construct the API message */
  M (TAP_MODIFY, mp);

  mp->use_random_mac = random_mac;
  mp->sw_if_index = ntohl (sw_if_index);
  clib_memcpy (mp->mac_address, mac_address, 6);
  clib_memcpy (mp->tap_name, tap_name, vec_len (tap_name));
  vec_free (tap_name);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_tap_delete (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_tap_delete_t *mp;
  u32 sw_if_index = ~0;
  u8 sw_if_index_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing vpp interface name");
      return -99;
    }

  /* Construct the API message */
  M (TAP_DELETE, mp);

  mp->sw_if_index = ntohl (sw_if_index);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_tap_create_v2 (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_tap_create_v2_t *mp;
  u8 mac_address[6];
  u8 random_mac = 1;
  u32 id = ~0;
  u8 *host_if_name = 0;
  u8 *host_ns = 0;
  u8 host_mac_addr[6];
  u8 host_mac_addr_set = 0;
  u8 *host_bridge = 0;
  ip4_address_t host_ip4_addr;
  ip4_address_t host_ip4_gw;
  u8 host_ip4_gw_set = 0;
  u32 host_ip4_prefix_len = 0;
  ip6_address_t host_ip6_addr;
  ip6_address_t host_ip6_gw;
  u8 host_ip6_gw_set = 0;
  u32 host_ip6_prefix_len = 0;
  int ret;
  u32 rx_ring_sz = 0, tx_ring_sz = 0;

  clib_memset (mac_address, 0, sizeof (mac_address));

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "hw-addr %U", unformat_ethernet_address, mac_address))
	{
	  random_mac = 0;
	}
      else if (unformat (i, "id %u", &id))
	;
      else if (unformat (i, "host-if-name %s", &host_if_name))
	;
      else if (unformat (i, "host-ns %s", &host_ns))
	;
      else if (unformat (i, "host-mac-addr %U", unformat_ethernet_address,
			 host_mac_addr))
	host_mac_addr_set = 1;
      else if (unformat (i, "host-bridge %s", &host_bridge))
	;
      else if (unformat (i, "host-ip4-addr %U/%d", unformat_ip4_address,
			 &host_ip4_addr, &host_ip4_prefix_len))
	;
      else if (unformat (i, "host-ip6-addr %U/%d", unformat_ip6_address,
			 &host_ip6_addr, &host_ip6_prefix_len))
	;
      else if (unformat (i, "host-ip4-gw %U", unformat_ip4_address,
			 &host_ip4_gw))
	host_ip4_gw_set = 1;
      else if (unformat (i, "host-ip6-gw %U", unformat_ip6_address,
			 &host_ip6_gw))
	host_ip6_gw_set = 1;
      else if (unformat (i, "rx-ring-size %d", &rx_ring_sz))
	;
      else if (unformat (i, "tx-ring-size %d", &tx_ring_sz))
	;
      else
	break;
    }

  if (vec_len (host_if_name) > 63)
    {
      errmsg ("tap name too long. ");
      return -99;
    }
  if (vec_len (host_ns) > 63)
    {
      errmsg ("host name space too long. ");
      return -99;
    }
  if (vec_len (host_bridge) > 63)
    {
      errmsg ("host bridge name too long. ");
      return -99;
    }
  if (host_ip4_prefix_len > 32)
    {
      errmsg ("host ip4 prefix length not valid. ");
      return -99;
    }
  if (host_ip6_prefix_len > 128)
    {
      errmsg ("host ip6 prefix length not valid. ");
      return -99;
    }
  if (!is_pow2 (rx_ring_sz))
    {
      errmsg ("rx ring size must be power of 2. ");
      return -99;
    }
  if (rx_ring_sz > 32768)
    {
      errmsg ("rx ring size must be 32768 or lower. ");
      return -99;
    }
  if (!is_pow2 (tx_ring_sz))
    {
      errmsg ("tx ring size must be power of 2. ");
      return -99;
    }
  if (tx_ring_sz > 32768)
    {
      errmsg ("tx ring size must be 32768 or lower. ");
      return -99;
    }

  /* Construct the API message */
  M (TAP_CREATE_V2, mp);

  mp->use_random_mac = random_mac;

  mp->id = ntohl (id);
  mp->host_namespace_set = host_ns != 0;
  mp->host_bridge_set = host_bridge != 0;
  mp->host_ip4_addr_set = host_ip4_prefix_len != 0;
  mp->host_ip6_addr_set = host_ip6_prefix_len != 0;
  mp->rx_ring_sz = ntohs (rx_ring_sz);
  mp->tx_ring_sz = ntohs (tx_ring_sz);

  if (random_mac == 0)
    clib_memcpy (mp->mac_address, mac_address, 6);
  if (host_mac_addr_set)
    clib_memcpy (mp->host_mac_addr, host_mac_addr, 6);
  if (host_if_name)
    clib_memcpy (mp->host_if_name, host_if_name, vec_len (host_if_name));
  if (host_ns)
    clib_memcpy (mp->host_namespace, host_ns, vec_len (host_ns));
  if (host_bridge)
    clib_memcpy (mp->host_bridge, host_bridge, vec_len (host_bridge));
  if (host_ip4_prefix_len)
    clib_memcpy (mp->host_ip4_addr, &host_ip4_addr, 4);
  if (host_ip6_prefix_len)
    clib_memcpy (mp->host_ip6_addr, &host_ip6_addr, 16);
  if (host_ip4_gw_set)
    clib_memcpy (mp->host_ip4_gw, &host_ip4_gw, 4);
  if (host_ip6_gw_set)
    clib_memcpy (mp->host_ip6_gw, &host_ip6_gw, 16);

  vec_free (host_ns);
  vec_free (host_if_name);
  vec_free (host_bridge);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_tap_delete_v2 (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_tap_delete_v2_t *mp;
  u32 sw_if_index = ~0;
  u8 sw_if_index_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing vpp interface name. ");
      return -99;
    }

  /* Construct the API message */
  M (TAP_DELETE_V2, mp);

  mp->sw_if_index = ntohl (sw_if_index);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_bond_create (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bond_create_t *mp;
  u8 mac_address[6];
  u8 custom_mac = 0;
  int ret;
  u8 mode;
  u8 lb;
  u8 mode_is_set = 0;
  u32 instance = ~0;

  clib_memset (mac_address, 0, sizeof (mac_address));
  lb = BOND_LB_L2;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "mode %U", unformat_bond_mode, &mode))
	mode_is_set = 1;
      else if (((mode == BOND_MODE_LACP) || (mode == BOND_MODE_XOR))
	       && unformat (i, "lb %U", unformat_bond_load_balance, &lb))
	;
      else if (unformat (i, "hw-addr %U", unformat_ethernet_address,
			 mac_address))
	custom_mac = 1;
      else if (unformat (i, "instance %d", &instance))
	;
      else
	break;
    }

  if (mode_is_set == 0)
    {
      errmsg ("Missing bond mode. ");
      return -99;
    }

  /* Construct the API message */
  M (BOND_CREATE, mp);

  mp->use_custom_mac = custom_mac;

  mp->mode = mode;
  mp->lb = lb;
  mp->instance = htonl (instance);

  if (custom_mac)
    clib_memcpy (mp->mac_address, mac_address, 6);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_bond_delete (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bond_delete_t *mp;
  u32 sw_if_index = ~0;
  u8 sw_if_index_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing vpp interface name. ");
      return -99;
    }

  /* Construct the API message */
  M (BOND_DELETE, mp);

  mp->sw_if_index = ntohl (sw_if_index);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_bond_enslave (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bond_enslave_t *mp;
  u32 bond_sw_if_index;
  int ret;
  u8 is_passive;
  u8 is_long_timeout;
  u32 bond_sw_if_index_is_set = 0;
  u32 sw_if_index;
  u8 sw_if_index_is_set = 0;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_is_set = 1;
      else if (unformat (i, "bond %u", &bond_sw_if_index))
	bond_sw_if_index_is_set = 1;
      else if (unformat (i, "passive %d", &is_passive))
	;
      else if (unformat (i, "long-timeout %d", &is_long_timeout))
	;
      else
	break;
    }

  if (bond_sw_if_index_is_set == 0)
    {
      errmsg ("Missing bond sw_if_index. ");
      return -99;
    }
  if (sw_if_index_is_set == 0)
    {
      errmsg ("Missing slave sw_if_index. ");
      return -99;
    }

  /* Construct the API message */
  M (BOND_ENSLAVE, mp);

  mp->bond_sw_if_index = ntohl (bond_sw_if_index);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_long_timeout = is_long_timeout;
  mp->is_passive = is_passive;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_bond_detach_slave (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bond_detach_slave_t *mp;
  u32 sw_if_index = ~0;
  u8 sw_if_index_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing vpp interface name. ");
      return -99;
    }

  /* Construct the API message */
  M (BOND_DETACH_SLAVE, mp);

  mp->sw_if_index = ntohl (sw_if_index);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_ip_table_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_table_add_del_t *mp;
  u32 table_id = ~0;
  u8 is_ipv6 = 0;
  u8 is_add = 1;
  int ret = 0;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "table %d", &table_id))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (~0 == table_id)
    {
      errmsg ("missing table-ID");
      return -99;
    }

  /* Construct the API message */
  M (IP_TABLE_ADD_DEL, mp);

  mp->table_id = ntohl (table_id);
  mp->is_ipv6 = is_ipv6;
  mp->is_add = is_add;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

static int
api_ip_add_del_route (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_add_del_route_t *mp;
  u32 sw_if_index = ~0, vrf_id = 0;
  u8 is_ipv6 = 0;
  u8 is_local = 0, is_drop = 0;
  u8 is_unreach = 0, is_prohibit = 0;
  u8 is_add = 1;
  u32 next_hop_weight = 1;
  u8 is_multipath = 0;
  u8 address_set = 0;
  u8 address_length_set = 0;
  u32 next_hop_table_id = 0;
  u32 resolve_attempts = 0;
  u32 dst_address_length = 0;
  u8 next_hop_set = 0;
  ip4_address_t v4_dst_address, v4_next_hop_address;
  ip6_address_t v6_dst_address, v6_next_hop_address;
  int count = 1;
  int j;
  f64 before = 0;
  u32 random_add_del = 0;
  u32 *random_vector = 0;
  uword *random_hash;
  u32 random_seed = 0xdeaddabe;
  u32 classify_table_index = ~0;
  u8 is_classify = 0;
  u8 resolve_host = 0, resolve_attached = 0;
  vl_api_fib_mpls_label_t *next_hop_out_label_stack = NULL;
  mpls_label_t next_hop_out_label = MPLS_LABEL_INVALID;
  mpls_label_t next_hop_via_label = MPLS_LABEL_INVALID;

  clib_memset (&v4_next_hop_address, 0, sizeof (ip4_address_t));
  clib_memset (&v6_next_hop_address, 0, sizeof (ip6_address_t));
  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "%U", unformat_ip4_address, &v4_dst_address))
	{
	  address_set = 1;
	  is_ipv6 = 0;
	}
      else if (unformat (i, "%U", unformat_ip6_address, &v6_dst_address))
	{
	  address_set = 1;
	  is_ipv6 = 1;
	}
      else if (unformat (i, "/%d", &dst_address_length))
	{
	  address_length_set = 1;
	}

      else if (is_ipv6 == 0 && unformat (i, "via %U", unformat_ip4_address,
					 &v4_next_hop_address))
	{
	  next_hop_set = 1;
	}
      else if (is_ipv6 == 1 && unformat (i, "via %U", unformat_ip6_address,
					 &v6_next_hop_address))
	{
	  next_hop_set = 1;
	}
      else
	if (unformat
	    (i, "via %U", api_unformat_sw_if_index, vam, &sw_if_index))
	{
	  next_hop_set = 1;
	}
      else if (unformat (i, "via sw_if_index %d", &sw_if_index))
	{
	  next_hop_set = 1;
	}
      else if (unformat (i, "resolve-attempts %d", &resolve_attempts))
	;
      else if (unformat (i, "weight %d", &next_hop_weight))
	;
      else if (unformat (i, "drop"))
	{
	  is_drop = 1;
	}
      else if (unformat (i, "null-send-unreach"))
	{
	  is_unreach = 1;
	}
      else if (unformat (i, "null-send-prohibit"))
	{
	  is_prohibit = 1;
	}
      else if (unformat (i, "local"))
	{
	  is_local = 1;
	}
      else if (unformat (i, "classify %d", &classify_table_index))
	{
	  is_classify = 1;
	}
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "resolve-via-host"))
	resolve_host = 1;
      else if (unformat (i, "resolve-via-attached"))
	resolve_attached = 1;
      else if (unformat (i, "multipath"))
	is_multipath = 1;
      else if (unformat (i, "vrf %d", &vrf_id))
	;
      else if (unformat (i, "count %d", &count))
	;
      else if (unformat (i, "lookup-in-vrf %d", &next_hop_table_id))
	;
      else if (unformat (i, "next-hop-table %d", &next_hop_table_id))
	;
      else if (unformat (i, "out-label %d", &next_hop_out_label))
	{
	  vl_api_fib_mpls_label_t fib_label = {
	    .label = ntohl (next_hop_out_label),
	    .ttl = 64,
	    .exp = 0,
	  };
	  vec_add1 (next_hop_out_label_stack, fib_label);
	}
      else if (unformat (i, "via via-label %d", &next_hop_via_label))
	;
      else if (unformat (i, "random"))
	random_add_del = 1;
      else if (unformat (i, "seed %d", &random_seed))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!next_hop_set && !is_drop && !is_local &&
      !is_classify && !is_unreach && !is_prohibit &&
      MPLS_LABEL_INVALID == next_hop_via_label)
    {
      errmsg
	("next hop / local / drop / unreach / prohibit / classify not set");
      return -99;
    }

  if (next_hop_set && MPLS_LABEL_INVALID != next_hop_via_label)
    {
      errmsg ("next hop and next-hop via label set");
      return -99;
    }
  if (address_set == 0)
    {
      errmsg ("missing addresses");
      return -99;
    }

  if (address_length_set == 0)
    {
      errmsg ("missing address length");
      return -99;
    }

  /* Generate a pile of unique, random routes */
  if (random_add_del)
    {
      u32 this_random_address;
      random_hash = hash_create (count, sizeof (uword));

      hash_set (random_hash, v4_next_hop_address.as_u32, 1);
      for (j = 0; j <= count; j++)
	{
	  do
	    {
	      this_random_address = random_u32 (&random_seed);
	      this_random_address =
		clib_host_to_net_u32 (this_random_address);
	    }
	  while (hash_get (random_hash, this_random_address));
	  vec_add1 (random_vector, this_random_address);
	  hash_set (random_hash, this_random_address, 1);
	}
      hash_free (random_hash);
      v4_dst_address.as_u32 = random_vector[0];
    }

  if (count > 1)
    {
      /* Turn on async mode */
      vam->async_mode = 1;
      vam->async_errors = 0;
      before = vat_time_now (vam);
    }

  for (j = 0; j < count; j++)
    {
      /* Construct the API message */
      M2 (IP_ADD_DEL_ROUTE, mp, sizeof (vl_api_fib_mpls_label_t) *
	  vec_len (next_hop_out_label_stack));

      mp->next_hop_sw_if_index = ntohl (sw_if_index);
      mp->table_id = ntohl (vrf_id);

      mp->is_add = is_add;
      mp->is_drop = is_drop;
      mp->is_unreach = is_unreach;
      mp->is_prohibit = is_prohibit;
      mp->is_ipv6 = is_ipv6;
      mp->is_local = is_local;
      mp->is_classify = is_classify;
      mp->is_multipath = is_multipath;
      mp->is_resolve_host = resolve_host;
      mp->is_resolve_attached = resolve_attached;
      mp->next_hop_weight = next_hop_weight;
      mp->next_hop_preference = 0;
      mp->dst_address_length = dst_address_length;
      mp->next_hop_table_id = ntohl (next_hop_table_id);
      mp->classify_table_index = ntohl (classify_table_index);
      mp->next_hop_via_label = ntohl (next_hop_via_label);
      mp->next_hop_n_out_labels = vec_len (next_hop_out_label_stack);
      if (0 != mp->next_hop_n_out_labels)
	{
	  memcpy (mp->next_hop_out_label_stack,
		  next_hop_out_label_stack,
		  (vec_len (next_hop_out_label_stack) *
		   sizeof (vl_api_fib_mpls_label_t)));
	  vec_free (next_hop_out_label_stack);
	}

      if (is_ipv6)
	{
	  clib_memcpy (mp->dst_address, &v6_dst_address,
		       sizeof (v6_dst_address));
	  if (next_hop_set)
	    clib_memcpy (mp->next_hop_address, &v6_next_hop_address,
			 sizeof (v6_next_hop_address));
	  increment_v6_address (&v6_dst_address);
	}
      else
	{
	  clib_memcpy (mp->dst_address, &v4_dst_address,
		       sizeof (v4_dst_address));
	  if (next_hop_set)
	    clib_memcpy (mp->next_hop_address, &v4_next_hop_address,
			 sizeof (v4_next_hop_address));
	  if (random_add_del)
	    v4_dst_address.as_u32 = random_vector[j + 1];
	  else
	    increment_v4_address (&v4_dst_address);
	}
      /* send it... */
      S (mp);
      /* If we receive SIGTERM, stop now... */
      if (vam->do_exit)
	break;
    }

  /* When testing multiple add/del ops, use a control-ping to sync */
  if (count > 1)
    {
      vl_api_control_ping_t *mp_ping;
      f64 after;
      f64 timeout;

      /* Shut off async mode */
      vam->async_mode = 0;

      MPING (CONTROL_PING, mp_ping);
      S (mp_ping);

      timeout = vat_time_now (vam) + 1.0;
      while (vat_time_now (vam) < timeout)
	if (vam->result_ready == 1)
	  goto out;
      vam->retval = -99;

    out:
      if (vam->retval == -99)
	errmsg ("timeout");

      if (vam->async_errors > 0)
	{
	  errmsg ("%d asynchronous errors", vam->async_errors);
	  vam->retval = -98;
	}
      vam->async_errors = 0;
      after = vat_time_now (vam);

      /* slim chance, but we might have eaten SIGTERM on the first iteration */
      if (j > 0)
	count = j;

      print (vam->ofp, "%d routes in %.6f secs, %.2f routes/sec",
	     count, after - before, count / (after - before));
    }
  else
    {
      int ret;

      /* Wait for a reply... */
      W (ret);
      return ret;
    }

  /* Return the good/bad news */
  return (vam->retval);
}

static int
api_ip_mroute_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_mroute_add_del_t *mp;
  u32 sw_if_index = ~0, vrf_id = 0;
  u8 is_ipv6 = 0;
  u8 is_local = 0;
  u8 is_add = 1;
  u8 address_set = 0;
  u32 grp_address_length = 0;
  ip4_address_t v4_grp_address, v4_src_address;
  ip6_address_t v6_grp_address, v6_src_address;
  mfib_itf_flags_t iflags = 0;
  mfib_entry_flags_t eflags = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "%U %U",
			 unformat_ip4_address, &v4_src_address,
			 unformat_ip4_address, &v4_grp_address))
	{
	  grp_address_length = 64;
	  address_set = 1;
	  is_ipv6 = 0;
	}
      else if (unformat (i, "%U %U",
			 unformat_ip6_address, &v6_src_address,
			 unformat_ip6_address, &v6_grp_address))
	{
	  grp_address_length = 256;
	  address_set = 1;
	  is_ipv6 = 1;
	}
      else if (unformat (i, "%U", unformat_ip4_address, &v4_grp_address))
	{
	  clib_memset (&v4_src_address, 0, sizeof (v4_src_address));
	  grp_address_length = 32;
	  address_set = 1;
	  is_ipv6 = 0;
	}
      else if (unformat (i, "%U", unformat_ip6_address, &v6_grp_address))
	{
	  clib_memset (&v6_src_address, 0, sizeof (v6_src_address));
	  grp_address_length = 128;
	  address_set = 1;
	  is_ipv6 = 1;
	}
      else if (unformat (i, "/%d", &grp_address_length))
	;
      else if (unformat (i, "local"))
	{
	  is_local = 1;
	}
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "vrf %d", &vrf_id))
	;
      else if (unformat (i, "%U", unformat_mfib_itf_flags, &iflags))
	;
      else if (unformat (i, "%U", unformat_mfib_entry_flags, &eflags))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (address_set == 0)
    {
      errmsg ("missing addresses\n");
      return -99;
    }

  /* Construct the API message */
  M (IP_MROUTE_ADD_DEL, mp);

  mp->next_hop_sw_if_index = ntohl (sw_if_index);
  mp->table_id = ntohl (vrf_id);

  mp->is_add = is_add;
  mp->is_ipv6 = is_ipv6;
  mp->is_local = is_local;
  mp->itf_flags = ntohl (iflags);
  mp->entry_flags = ntohl (eflags);
  mp->grp_address_length = grp_address_length;
  mp->grp_address_length = ntohs (mp->grp_address_length);

  if (is_ipv6)
    {
      clib_memcpy (mp->grp_address, &v6_grp_address, sizeof (v6_grp_address));
      clib_memcpy (mp->src_address, &v6_src_address, sizeof (v6_src_address));
    }
  else
    {
      clib_memcpy (mp->grp_address, &v4_grp_address, sizeof (v4_grp_address));
      clib_memcpy (mp->src_address, &v4_src_address, sizeof (v4_src_address));

    }

  /* send it... */
  S (mp);
  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_mpls_table_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_mpls_table_add_del_t *mp;
  u32 table_id = ~0;
  u8 is_add = 1;
  int ret = 0;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "table %d", &table_id))
	;
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	is_add = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (~0 == table_id)
    {
      errmsg ("missing table-ID");
      return -99;
    }

  /* Construct the API message */
  M (MPLS_TABLE_ADD_DEL, mp);

  mp->mt_table_id = ntohl (table_id);
  mp->mt_is_add = is_add;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

static int
api_mpls_route_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_mpls_route_add_del_t *mp;
  u32 sw_if_index = ~0, table_id = 0;
  u8 is_add = 1;
  u32 next_hop_weight = 1;
  u8 is_multipath = 0;
  u32 next_hop_table_id = 0;
  u8 next_hop_set = 0;
  ip4_address_t v4_next_hop_address = {
    .as_u32 = 0,
  };
  ip6_address_t v6_next_hop_address = { {0} };
  int count = 1;
  int j;
  f64 before = 0;
  u32 classify_table_index = ~0;
  u8 is_classify = 0;
  u8 resolve_host = 0, resolve_attached = 0;
  u8 is_interface_rx = 0;
  mpls_label_t next_hop_via_label = MPLS_LABEL_INVALID;
  mpls_label_t next_hop_out_label = MPLS_LABEL_INVALID;
  vl_api_fib_mpls_label_t *next_hop_out_label_stack = NULL;
  mpls_label_t local_label = MPLS_LABEL_INVALID;
  u8 is_eos = 0;
  dpo_proto_t next_hop_proto = DPO_PROTO_MPLS;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "%d", &local_label))
	;
      else if (unformat (i, "eos"))
	is_eos = 1;
      else if (unformat (i, "non-eos"))
	is_eos = 0;
      else if (unformat (i, "via %U", unformat_ip4_address,
			 &v4_next_hop_address))
	{
	  next_hop_set = 1;
	  next_hop_proto = DPO_PROTO_IP4;
	}
      else if (unformat (i, "via %U", unformat_ip6_address,
			 &v6_next_hop_address))
	{
	  next_hop_set = 1;
	  next_hop_proto = DPO_PROTO_IP6;
	}
      else if (unformat (i, "weight %d", &next_hop_weight))
	;
      else if (unformat (i, "classify %d", &classify_table_index))
	{
	  is_classify = 1;
	}
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "resolve-via-host"))
	resolve_host = 1;
      else if (unformat (i, "resolve-via-attached"))
	resolve_attached = 1;
      else if (unformat (i, "multipath"))
	is_multipath = 1;
      else if (unformat (i, "count %d", &count))
	;
      else if (unformat (i, "via lookup-in-ip4-table %d", &next_hop_table_id))
	{
	  next_hop_set = 1;
	  next_hop_proto = DPO_PROTO_IP4;
	}
      else if (unformat (i, "via lookup-in-ip6-table %d", &next_hop_table_id))
	{
	  next_hop_set = 1;
	  next_hop_proto = DPO_PROTO_IP6;
	}
      else
	if (unformat
	    (i, "via l2-input-on %U", api_unformat_sw_if_index, vam,
	     &sw_if_index))
	{
	  next_hop_set = 1;
	  next_hop_proto = DPO_PROTO_ETHERNET;
	  is_interface_rx = 1;
	}
      else if (unformat (i, "via l2-input-on sw_if_index %d", &sw_if_index))
	{
	  next_hop_set = 1;
	  next_hop_proto = DPO_PROTO_ETHERNET;
	  is_interface_rx = 1;
	}
      else if (unformat (i, "via next-hop-table %d", &next_hop_table_id))
	next_hop_set = 1;
      else if (unformat (i, "via via-label %d", &next_hop_via_label))
	next_hop_set = 1;
      else if (unformat (i, "out-label %d", &next_hop_out_label))
	{
	  vl_api_fib_mpls_label_t fib_label = {
	    .label = ntohl (next_hop_out_label),
	    .ttl = 64,
	    .exp = 0,
	  };
	  vec_add1 (next_hop_out_label_stack, fib_label);
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!next_hop_set && !is_classify)
    {
      errmsg ("next hop / classify not set");
      return -99;
    }

  if (MPLS_LABEL_INVALID == local_label)
    {
      errmsg ("missing label");
      return -99;
    }

  if (count > 1)
    {
      /* Turn on async mode */
      vam->async_mode = 1;
      vam->async_errors = 0;
      before = vat_time_now (vam);
    }

  for (j = 0; j < count; j++)
    {
      /* Construct the API message */
      M2 (MPLS_ROUTE_ADD_DEL, mp, sizeof (vl_api_fib_mpls_label_t) *
	  vec_len (next_hop_out_label_stack));

      mp->mr_next_hop_sw_if_index = ntohl (sw_if_index);
      mp->mr_table_id = ntohl (table_id);

      mp->mr_is_add = is_add;
      mp->mr_next_hop_proto = next_hop_proto;
      mp->mr_is_classify = is_classify;
      mp->mr_is_multipath = is_multipath;
      mp->mr_is_resolve_host = resolve_host;
      mp->mr_is_resolve_attached = resolve_attached;
      mp->mr_is_interface_rx = is_interface_rx;
      mp->mr_next_hop_weight = next_hop_weight;
      mp->mr_next_hop_preference = 0;
      mp->mr_next_hop_table_id = ntohl (next_hop_table_id);
      mp->mr_classify_table_index = ntohl (classify_table_index);
      mp->mr_next_hop_via_label = ntohl (next_hop_via_label);
      mp->mr_label = ntohl (local_label);
      mp->mr_eos = is_eos;

      mp->mr_next_hop_n_out_labels = vec_len (next_hop_out_label_stack);
      if (0 != mp->mr_next_hop_n_out_labels)
	{
	  memcpy (mp->mr_next_hop_out_label_stack,
		  next_hop_out_label_stack,
		  vec_len (next_hop_out_label_stack) *
		  sizeof (vl_api_fib_mpls_label_t));
	  vec_free (next_hop_out_label_stack);
	}

      if (next_hop_set)
	{
	  if (DPO_PROTO_IP4 == next_hop_proto)
	    {
	      clib_memcpy (mp->mr_next_hop,
			   &v4_next_hop_address,
			   sizeof (v4_next_hop_address));
	    }
	  else if (DPO_PROTO_IP6 == next_hop_proto)

	    {
	      clib_memcpy (mp->mr_next_hop,
			   &v6_next_hop_address,
			   sizeof (v6_next_hop_address));
	    }
	}
      local_label++;

      /* send it... */
      S (mp);
      /* If we receive SIGTERM, stop now... */
      if (vam->do_exit)
	break;
    }

  /* When testing multiple add/del ops, use a control-ping to sync */
  if (count > 1)
    {
      vl_api_control_ping_t *mp_ping;
      f64 after;
      f64 timeout;

      /* Shut off async mode */
      vam->async_mode = 0;

      MPING (CONTROL_PING, mp_ping);
      S (mp_ping);

      timeout = vat_time_now (vam) + 1.0;
      while (vat_time_now (vam) < timeout)
	if (vam->result_ready == 1)
	  goto out;
      vam->retval = -99;

    out:
      if (vam->retval == -99)
	errmsg ("timeout");

      if (vam->async_errors > 0)
	{
	  errmsg ("%d asynchronous errors", vam->async_errors);
	  vam->retval = -98;
	}
      vam->async_errors = 0;
      after = vat_time_now (vam);

      /* slim chance, but we might have eaten SIGTERM on the first iteration */
      if (j > 0)
	count = j;

      print (vam->ofp, "%d routes in %.6f secs, %.2f routes/sec",
	     count, after - before, count / (after - before));
    }
  else
    {
      int ret;

      /* Wait for a reply... */
      W (ret);
      return ret;
    }

  /* Return the good/bad news */
  return (vam->retval);
}

static int
api_mpls_ip_bind_unbind (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_mpls_ip_bind_unbind_t *mp;
  u32 ip_table_id = 0;
  u8 is_bind = 1;
  u8 is_ip4 = 1;
  ip4_address_t v4_address;
  ip6_address_t v6_address;
  u32 address_length;
  u8 address_set = 0;
  mpls_label_t local_label = MPLS_LABEL_INVALID;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U/%d", unformat_ip4_address,
		    &v4_address, &address_length))
	{
	  is_ip4 = 1;
	  address_set = 1;
	}
      else if (unformat (i, "%U/%d", unformat_ip6_address,
			 &v6_address, &address_length))
	{
	  is_ip4 = 0;
	  address_set = 1;
	}
      else if (unformat (i, "%d", &local_label))
	;
      else if (unformat (i, "table-id %d", &ip_table_id))
	;
      else if (unformat (i, "unbind"))
	is_bind = 0;
      else if (unformat (i, "bind"))
	is_bind = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!address_set)
    {
      errmsg ("IP address not set");
      return -99;
    }

  if (MPLS_LABEL_INVALID == local_label)
    {
      errmsg ("missing label");
      return -99;
    }

  /* Construct the API message */
  M (MPLS_IP_BIND_UNBIND, mp);

  mp->mb_is_bind = is_bind;
  mp->mb_is_ip4 = is_ip4;
  mp->mb_ip_table_id = ntohl (ip_table_id);
  mp->mb_mpls_table_id = 0;
  mp->mb_label = ntohl (local_label);
  mp->mb_address_length = address_length;

  if (is_ip4)
    clib_memcpy (mp->mb_address, &v4_address, sizeof (v4_address));
  else
    clib_memcpy (mp->mb_address, &v6_address, sizeof (v6_address));

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_sr_mpls_policy_add (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sr_mpls_policy_add_t *mp;
  u32 bsid = 0;
  u32 weight = 1;
  u8 type = 0;
  u8 n_segments = 0;
  u32 sid;
  u32 *segments = NULL;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bsid %d", &bsid))
	;
      else if (unformat (i, "weight %d", &weight))
	;
      else if (unformat (i, "spray"))
	type = 1;
      else if (unformat (i, "next %d", &sid))
	{
	  n_segments += 1;
	  vec_add1 (segments, htonl (sid));
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (bsid == 0)
    {
      errmsg ("bsid not set");
      return -99;
    }

  if (n_segments == 0)
    {
      errmsg ("no sid in segment stack");
      return -99;
    }

  /* Construct the API message */
  M2 (SR_MPLS_POLICY_ADD, mp, sizeof (u32) * n_segments);

  mp->bsid = htonl (bsid);
  mp->weight = htonl (weight);
  mp->type = type;
  mp->n_segments = n_segments;
  memcpy (mp->segments, segments, sizeof (u32) * n_segments);
  vec_free (segments);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_sr_mpls_policy_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sr_mpls_policy_del_t *mp;
  u32 bsid = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bsid %d", &bsid))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (bsid == 0)
    {
      errmsg ("bsid not set");
      return -99;
    }

  /* Construct the API message */
  M (SR_MPLS_POLICY_DEL, mp);

  mp->bsid = htonl (bsid);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_bier_table_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bier_table_add_del_t *mp;
  u8 is_add = 1;
  u32 set = 0, sub_domain = 0, hdr_len = 3;
  mpls_label_t local_label = MPLS_LABEL_INVALID;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sub-domain %d", &sub_domain))
	;
      else if (unformat (i, "set %d", &set))
	;
      else if (unformat (i, "label %d", &local_label))
	;
      else if (unformat (i, "hdr-len %d", &hdr_len))
	;
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (MPLS_LABEL_INVALID == local_label)
    {
      errmsg ("missing label\n");
      return -99;
    }

  /* Construct the API message */
  M (BIER_TABLE_ADD_DEL, mp);

  mp->bt_is_add = is_add;
  mp->bt_label = ntohl (local_label);
  mp->bt_tbl_id.bt_set = set;
  mp->bt_tbl_id.bt_sub_domain = sub_domain;
  mp->bt_tbl_id.bt_hdr_len_id = hdr_len;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return (ret);
}

static int
api_bier_route_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bier_route_add_del_t *mp;
  u8 is_add = 1;
  u32 set = 0, sub_domain = 0, hdr_len = 3, bp = 0;
  ip4_address_t v4_next_hop_address;
  ip6_address_t v6_next_hop_address;
  u8 next_hop_set = 0;
  u8 next_hop_proto_is_ip4 = 1;
  mpls_label_t next_hop_out_label = MPLS_LABEL_INVALID;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_ip4_address, &v4_next_hop_address))
	{
	  next_hop_proto_is_ip4 = 1;
	  next_hop_set = 1;
	}
      else if (unformat (i, "%U", unformat_ip6_address, &v6_next_hop_address))
	{
	  next_hop_proto_is_ip4 = 0;
	  next_hop_set = 1;
	}
      if (unformat (i, "sub-domain %d", &sub_domain))
	;
      else if (unformat (i, "set %d", &set))
	;
      else if (unformat (i, "hdr-len %d", &hdr_len))
	;
      else if (unformat (i, "bp %d", &bp))
	;
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "out-label %d", &next_hop_out_label))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!next_hop_set || (MPLS_LABEL_INVALID == next_hop_out_label))
    {
      errmsg ("next hop / label set\n");
      return -99;
    }
  if (0 == bp)
    {
      errmsg ("bit=position not set\n");
      return -99;
    }

  /* Construct the API message */
  M2 (BIER_ROUTE_ADD_DEL, mp, sizeof (vl_api_fib_path_t));

  mp->br_is_add = is_add;
  mp->br_tbl_id.bt_set = set;
  mp->br_tbl_id.bt_sub_domain = sub_domain;
  mp->br_tbl_id.bt_hdr_len_id = hdr_len;
  mp->br_bp = ntohs (bp);
  mp->br_n_paths = 1;
  mp->br_paths[0].n_labels = 1;
  mp->br_paths[0].label_stack[0].label = ntohl (next_hop_out_label);
  mp->br_paths[0].afi = (next_hop_proto_is_ip4 ? 0 : 1);

  if (next_hop_proto_is_ip4)
    {
      clib_memcpy (mp->br_paths[0].next_hop,
		   &v4_next_hop_address, sizeof (v4_next_hop_address));
    }
  else
    {
      clib_memcpy (mp->br_paths[0].next_hop,
		   &v6_next_hop_address, sizeof (v6_next_hop_address));
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return (ret);
}

static int
api_proxy_arp_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_proxy_arp_add_del_t *mp;
  u32 vrf_id = 0;
  u8 is_add = 1;
  ip4_address_t lo, hi;
  u8 range_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "vrf %d", &vrf_id))
	;
      else if (unformat (i, "%U - %U", unformat_ip4_address, &lo,
			 unformat_ip4_address, &hi))
	range_set = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (range_set == 0)
    {
      errmsg ("address range not set");
      return -99;
    }

  M (PROXY_ARP_ADD_DEL, mp);

  mp->proxy.vrf_id = ntohl (vrf_id);
  mp->is_add = is_add;
  clib_memcpy (mp->proxy.low_address, &lo, sizeof (mp->proxy.low_address));
  clib_memcpy (mp->proxy.hi_address, &hi, sizeof (mp->proxy.hi_address));

  S (mp);
  W (ret);
  return ret;
}

static int
api_proxy_arp_intfc_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_proxy_arp_intfc_enable_disable_t *mp;
  u32 sw_if_index;
  u8 enable = 1;
  u8 sw_if_index_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "enable"))
	enable = 1;
      else if (unformat (i, "disable"))
	enable = 0;
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

  M (PROXY_ARP_INTFC_ENABLE_DISABLE, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable_disable = enable;

  S (mp);
  W (ret);
  return ret;
}

static int
api_mpls_tunnel_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_mpls_tunnel_add_del_t *mp;

  u8 is_add = 1;
  u8 l2_only = 0;
  u32 sw_if_index = ~0;
  u32 next_hop_sw_if_index = ~0;
  u32 next_hop_proto_is_ip4 = 1;

  u32 next_hop_table_id = 0;
  ip4_address_t v4_next_hop_address = {
    .as_u32 = 0,
  };
  ip6_address_t v6_next_hop_address = { {0} };
  vl_api_fib_mpls_label_t *next_hop_out_label_stack = NULL;
  mpls_label_t next_hop_via_label = MPLS_LABEL_INVALID;
  mpls_label_t next_hop_out_label = MPLS_LABEL_INVALID;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "add"))
	is_add = 1;
      else
	if (unformat
	    (i, "del %U", api_unformat_sw_if_index, vam, &sw_if_index))
	is_add = 0;
      else if (unformat (i, "del sw_if_index %d", &sw_if_index))
	is_add = 0;
      else if (unformat (i, "via %U",
			 unformat_ip4_address, &v4_next_hop_address))
	{
	  next_hop_proto_is_ip4 = 1;
	}
      else if (unformat (i, "via %U",
			 unformat_ip6_address, &v6_next_hop_address))
	{
	  next_hop_proto_is_ip4 = 0;
	}
      else if (unformat (i, "via-label %d", &next_hop_via_label))
	;
      else
	if (unformat
	    (i, "%U", api_unformat_sw_if_index, vam, &next_hop_sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &next_hop_sw_if_index))
	;
      else if (unformat (i, "l2-only"))
	l2_only = 1;
      else if (unformat (i, "next-hop-table %d", &next_hop_table_id))
	;
      else if (unformat (i, "out-label %d", &next_hop_out_label))
	{
	  vl_api_fib_mpls_label_t fib_label = {
	    .label = ntohl (next_hop_out_label),
	    .ttl = 64,
	    .exp = 0,
	  };
	  vec_add1 (next_hop_out_label_stack, fib_label);
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M2 (MPLS_TUNNEL_ADD_DEL, mp, sizeof (vl_api_fib_mpls_label_t) *
      vec_len (next_hop_out_label_stack));

  mp->mt_next_hop_sw_if_index = ntohl (next_hop_sw_if_index);
  mp->mt_sw_if_index = ntohl (sw_if_index);
  mp->mt_is_add = is_add;
  mp->mt_l2_only = l2_only;
  mp->mt_next_hop_table_id = ntohl (next_hop_table_id);
  mp->mt_next_hop_proto_is_ip4 = next_hop_proto_is_ip4;
  mp->mt_next_hop_via_label = ntohl (next_hop_via_label);
  mp->mt_next_hop_weight = 1;
  mp->mt_next_hop_preference = 0;

  mp->mt_next_hop_n_out_labels = vec_len (next_hop_out_label_stack);

  if (0 != mp->mt_next_hop_n_out_labels)
    {
      clib_memcpy (mp->mt_next_hop_out_label_stack,
		   next_hop_out_label_stack,
		   (vec_len (next_hop_out_label_stack) *
		    sizeof (vl_api_fib_mpls_label_t)));
      vec_free (next_hop_out_label_stack);
    }

  if (next_hop_proto_is_ip4)
    {
      clib_memcpy (mp->mt_next_hop,
		   &v4_next_hop_address, sizeof (v4_next_hop_address));
    }
  else
    {
      clib_memcpy (mp->mt_next_hop,
		   &v6_next_hop_address, sizeof (v6_next_hop_address));
    }

  S (mp);
  W (ret);
  return ret;
}

static int
api_sw_interface_set_unnumbered (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_unnumbered_t *mp;
  u32 sw_if_index;
  u32 unnum_sw_index = ~0;
  u8 is_add = 1;
  u8 sw_if_index_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "unnum_if_index %d", &unnum_sw_index))
	;
      else if (unformat (i, "del"))
	is_add = 0;
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

  M (SW_INTERFACE_SET_UNNUMBERED, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->unnumbered_sw_if_index = ntohl (unnum_sw_index);
  mp->is_add = is_add;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ip_neighbor_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_neighbor_add_del_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 is_add = 1;
  u8 is_static = 0;
  u8 is_no_fib_entry = 0;
  u8 mac_address[6];
  u8 mac_set = 0;
  u8 v4_address_set = 0;
  u8 v6_address_set = 0;
  ip4_address_t v4address;
  ip6_address_t v6address;
  int ret;

  clib_memset (mac_address, 0, sizeof (mac_address));

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "mac %U", unformat_ethernet_address, mac_address))
	{
	  mac_set = 1;
	}
      else if (unformat (i, "del"))
	is_add = 0;
      else
	if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "is_static"))
	is_static = 1;
      else if (unformat (i, "no-fib-entry"))
	is_no_fib_entry = 1;
      else if (unformat (i, "dst %U", unformat_ip4_address, &v4address))
	v4_address_set = 1;
      else if (unformat (i, "dst %U", unformat_ip6_address, &v6address))
	v6_address_set = 1;
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
  if (v4_address_set && v6_address_set)
    {
      errmsg ("both v4 and v6 addresses set");
      return -99;
    }
  if (!v4_address_set && !v6_address_set)
    {
      errmsg ("no address set");
      return -99;
    }

  /* Construct the API message */
  M (IP_NEIGHBOR_ADD_DEL, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_add = is_add;
  mp->is_static = is_static;
  mp->is_no_adj_fib = is_no_fib_entry;
  if (mac_set)
    clib_memcpy (mp->mac_address, mac_address, 6);
  if (v6_address_set)
    {
      mp->is_ipv6 = 1;
      clib_memcpy (mp->dst_address, &v6address, sizeof (v6address));
    }
  else
    {
      /* mp->is_ipv6 = 0; via clib_memset in M macro above */
      clib_memcpy (mp->dst_address, &v4address, sizeof (v4address));
    }

  /* send it... */
  S (mp);

  /* Wait for a reply, return good/bad news  */
  W (ret);
  return ret;
}

static int
api_create_vlan_subif (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_create_vlan_subif_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u32 vlan_id;
  u8 vlan_id_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "vlan %d", &vlan_id))
	vlan_id_set = 1;
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

  if (vlan_id_set == 0)
    {
      errmsg ("missing vlan_id");
      return -99;
    }
  M (CREATE_VLAN_SUBIF, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->vlan_id = ntohl (vlan_id);

  S (mp);
  W (ret);
  return ret;
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

static int
api_create_subif (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_create_subif_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u32 sub_id;
  u8 sub_id_set = 0;
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
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
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

  if (sub_id_set == 0)
    {
      errmsg ("missing sub_id");
      return -99;
    }
  M (CREATE_SUBIF, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->sub_id = ntohl (sub_id);

#define _(a) mp->a = a;
  foreach_create_subif_bit;
#undef _

  mp->outer_vlan_id = ntohs (outer_vlan_id);
  mp->inner_vlan_id = ntohs (inner_vlan_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_oam_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_oam_add_del_t *mp;
  u32 vrf_id = 0;
  u8 is_add = 1;
  ip4_address_t src, dst;
  u8 src_set = 0;
  u8 dst_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "vrf %d", &vrf_id))
	;
      else if (unformat (i, "src %U", unformat_ip4_address, &src))
	src_set = 1;
      else if (unformat (i, "dst %U", unformat_ip4_address, &dst))
	dst_set = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (src_set == 0)
    {
      errmsg ("missing src addr");
      return -99;
    }

  if (dst_set == 0)
    {
      errmsg ("missing dst addr");
      return -99;
    }

  M (OAM_ADD_DEL, mp);

  mp->vrf_id = ntohl (vrf_id);
  mp->is_add = is_add;
  clib_memcpy (mp->src_address, &src, sizeof (mp->src_address));
  clib_memcpy (mp->dst_address, &dst, sizeof (mp->dst_address));

  S (mp);
  W (ret);
  return ret;
}

static int
api_reset_fib (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_reset_fib_t *mp;
  u32 vrf_id = 0;
  u8 is_ipv6 = 0;
  u8 vrf_id_set = 0;

  int ret;
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "vrf %d", &vrf_id))
	vrf_id_set = 1;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (vrf_id_set == 0)
    {
      errmsg ("missing vrf id");
      return -99;
    }

  M (RESET_FIB, mp);

  mp->vrf_id = ntohl (vrf_id);
  mp->is_ipv6 = is_ipv6;

  S (mp);
  W (ret);
  return ret;
}

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
      mp->is_ipv6 = 1;
      clib_memcpy (mp->dhcp_server, &v6address, sizeof (v6address));
      clib_memcpy (mp->dhcp_src_address, &v6srcaddress, sizeof (v6address));
    }
  else
    {
      clib_memcpy (mp->dhcp_server, &v4address, sizeof (v4address));
      clib_memcpy (mp->dhcp_src_address, &v4srcaddress, sizeof (v4address));
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

static void vl_api_dhcp_proxy_details_t_handler_json
  (vl_api_dhcp_proxy_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;
  u32 i, count = mp->count;
  struct in_addr ip4;
  struct in6_addr ip6;
  vl_api_dhcp_server_t *s;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "rx-table-id", ntohl (mp->rx_vrf_id));
  vat_json_object_add_bytes (node, "vss-type", &mp->vss_type,
			     sizeof (mp->vss_type));
  vat_json_object_add_string_copy (node, "vss-vpn-ascii-id",
				   mp->vss_vpn_ascii_id);
  vat_json_object_add_uint (node, "vss-fib-id", ntohl (mp->vss_fib_id));
  vat_json_object_add_uint (node, "vss-oui", ntohl (mp->vss_oui));

  if (mp->is_ipv6)
    {
      clib_memcpy (&ip6, &mp->dhcp_src_address, sizeof (ip6));
      vat_json_object_add_ip6 (node, "src_address", ip6);
    }
  else
    {
      clib_memcpy (&ip4, &mp->dhcp_src_address, sizeof (ip4));
      vat_json_object_add_ip4 (node, "src_address", ip4);
    }

  for (i = 0; i < count; i++)
    {
      s = &mp->servers[i];

      vat_json_object_add_uint (node, "server-table-id",
				ntohl (s->server_vrf_id));

      if (mp->is_ipv6)
	{
	  clib_memcpy (&ip4, &s->dhcp_server, sizeof (ip4));
	  vat_json_object_add_ip4 (node, "src_address", ip4);
	}
      else
	{
	  clib_memcpy (&ip6, &s->dhcp_server, sizeof (ip6));
	  vat_json_object_add_ip6 (node, "server_address", ip6);
	}
    }
}

static int
api_dhcp_proxy_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_control_ping_t *mp_ping;
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
  MPING (CONTROL_PING, mp_ping);
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
      else
	if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
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
api_set_ip_flow_hash (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_set_ip_flow_hash_t *mp;
  u32 vrf_id = 0;
  u8 is_ipv6 = 0;
  u8 vrf_id_set = 0;
  u8 src = 0;
  u8 dst = 0;
  u8 sport = 0;
  u8 dport = 0;
  u8 proto = 0;
  u8 reverse = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
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

      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (vrf_id_set == 0)
    {
      errmsg ("missing vrf id");
      return -99;
    }

  M (SET_IP_FLOW_HASH, mp);
  mp->src = src;
  mp->dst = dst;
  mp->sport = sport;
  mp->dport = dport;
  mp->proto = proto;
  mp->reverse = reverse;
  mp->vrf_id = ntohl (vrf_id);
  mp->is_ipv6 = is_ipv6;

  S (mp);
  W (ret);
  return ret;
}

static int
api_sw_interface_ip6_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_ip6_enable_disable_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 enable = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "enable"))
	enable = 1;
      else if (unformat (i, "disable"))
	enable = 0;
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

  M (SW_INTERFACE_IP6_ENABLE_DISABLE, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable = enable;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ip6nd_proxy_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip6nd_proxy_add_del_t *mp;
  u32 sw_if_index = ~0;
  u8 v6_address_set = 0;
  ip6_address_t v6address;
  u8 is_del = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "%U", unformat_ip6_address, &v6address))
	v6_address_set = 1;
      if (unformat (i, "del"))
	is_del = 1;
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

  mp->is_del = is_del;
  mp->sw_if_index = ntohl (sw_if_index);
  clib_memcpy (mp->address, &v6address, sizeof (v6address));

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
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void vl_api_ip6nd_proxy_details_t_handler
  (vl_api_ip6nd_proxy_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "host %U sw_if_index %d",
	 format_ip6_address, mp->address, ntohl (mp->sw_if_index));
}

static void vl_api_ip6nd_proxy_details_t_handler_json
  (vl_api_ip6nd_proxy_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  struct in6_addr ip6;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));

  clib_memcpy (&ip6, mp->address, sizeof (ip6));
  vat_json_object_add_ip6 (node, "host", ip6);
}

static int
api_sw_interface_ip6nd_ra_prefix (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_ip6nd_ra_prefix_t *mp;
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
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "%U/%d",
			 unformat_ip6_address, &v6address, &address_length))
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
  clib_memcpy (mp->address, &v6address, sizeof (v6address));
  mp->address_length = address_length;
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
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
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

static int
api_set_arp_neighbor_limit (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_set_arp_neighbor_limit_t *mp;
  u32 arp_nbr_limit;
  u8 limit_set = 0;
  u8 is_ipv6 = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "arp_nbr_limit %d", &arp_nbr_limit))
	limit_set = 1;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (limit_set == 0)
    {
      errmsg ("missing limit value");
      return -99;
    }

  M (SET_ARP_NEIGHBOR_LIMIT, mp);

  mp->arp_neighbor_limit = ntohl (arp_nbr_limit);
  mp->is_ipv6 = is_ipv6;

  S (mp);
  W (ret);
  return ret;
}

static int
api_l2_patch_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_l2_patch_add_del_t *mp;
  u32 rx_sw_if_index;
  u8 rx_sw_if_index_set = 0;
  u32 tx_sw_if_index;
  u8 tx_sw_if_index_set = 0;
  u8 is_add = 1;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "rx_sw_if_index %d", &rx_sw_if_index))
	rx_sw_if_index_set = 1;
      else if (unformat (i, "tx_sw_if_index %d", &tx_sw_if_index))
	tx_sw_if_index_set = 1;
      else if (unformat (i, "rx"))
	{
	  if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (i, "%U", api_unformat_sw_if_index, vam,
			    &rx_sw_if_index))
		rx_sw_if_index_set = 1;
	    }
	  else
	    break;
	}
      else if (unformat (i, "tx"))
	{
	  if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (i, "%U", api_unformat_sw_if_index, vam,
			    &tx_sw_if_index))
		tx_sw_if_index_set = 1;
	    }
	  else
	    break;
	}
      else if (unformat (i, "del"))
	is_add = 0;
      else
	break;
    }

  if (rx_sw_if_index_set == 0)
    {
      errmsg ("missing rx interface name or rx_sw_if_index");
      return -99;
    }

  if (tx_sw_if_index_set == 0)
    {
      errmsg ("missing tx interface name or tx_sw_if_index");
      return -99;
    }

  M (L2_PATCH_ADD_DEL, mp);

  mp->rx_sw_if_index = ntohl (rx_sw_if_index);
  mp->tx_sw_if_index = ntohl (tx_sw_if_index);
  mp->is_add = is_add;

  S (mp);
  W (ret);
  return ret;
}

u8 is_del;
u8 localsid_addr[16];
u8 end_psp;
u8 behavior;
u32 sw_if_index;
u32 vlan_index;
u32 fib_table;
u8 nh_addr[16];

static int
api_sr_localsid_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sr_localsid_add_del_t *mp;

  u8 is_del;
  ip6_address_t localsid;
  u8 end_psp = 0;
  u8 behavior = ~0;
  u32 sw_if_index;
  u32 fib_table = ~(u32) 0;
  ip6_address_t nh_addr6;
  ip4_address_t nh_addr4;
  clib_memset (&nh_addr6, 0, sizeof (ip6_address_t));
  clib_memset (&nh_addr4, 0, sizeof (ip4_address_t));

  bool nexthop_set = 0;

  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_del = 1;
      else if (unformat (i, "address %U", unformat_ip6_address, &localsid));
      else if (unformat (i, "next-hop %U", unformat_ip4_address, &nh_addr4))
	nexthop_set = 1;
      else if (unformat (i, "next-hop %U", unformat_ip6_address, &nh_addr6))
	nexthop_set = 1;
      else if (unformat (i, "behavior %u", &behavior));
      else if (unformat (i, "sw_if_index %u", &sw_if_index));
      else if (unformat (i, "fib-table %u", &fib_table));
      else if (unformat (i, "end.psp %u", &behavior));
      else
	break;
    }

  M (SR_LOCALSID_ADD_DEL, mp);

  clib_memcpy (mp->localsid.addr, &localsid, sizeof (mp->localsid));
  if (nexthop_set)
    {
      clib_memcpy (mp->nh_addr6, &nh_addr6, sizeof (mp->nh_addr6));
      clib_memcpy (mp->nh_addr4, &nh_addr4, sizeof (mp->nh_addr4));
    }
  mp->behavior = behavior;
  mp->sw_if_index = ntohl (sw_if_index);
  mp->fib_table = ntohl (fib_table);
  mp->end_psp = end_psp;
  mp->is_del = is_del;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ioam_enable (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_ioam_enable_t *mp;
  u32 id = 0;
  int has_trace_option = 0;
  int has_pot_option = 0;
  int has_seqno_option = 0;
  int has_analyse_option = 0;
  int ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "trace"))
	has_trace_option = 1;
      else if (unformat (input, "pot"))
	has_pot_option = 1;
      else if (unformat (input, "seqno"))
	has_seqno_option = 1;
      else if (unformat (input, "analyse"))
	has_analyse_option = 1;
      else
	break;
    }
  M (IOAM_ENABLE, mp);
  mp->id = htons (id);
  mp->seqno = has_seqno_option;
  mp->analyse = has_analyse_option;
  mp->pot_enable = has_pot_option;
  mp->trace_enable = has_trace_option;

  S (mp);
  W (ret);
  return ret;
}


static int
api_ioam_disable (vat_main_t * vam)
{
  vl_api_ioam_disable_t *mp;
  int ret;

  M (IOAM_DISABLE, mp);
  S (mp);
  W (ret);
  return ret;
}

#define foreach_tcp_proto_field                 \
_(src_port)                                     \
_(dst_port)

#define foreach_udp_proto_field                 \
_(src_port)                                     \
_(dst_port)

#define foreach_ip4_proto_field                 \
_(src_address)                                  \
_(dst_address)                                  \
_(tos)                                          \
_(length)                                       \
_(fragment_id)                                  \
_(ttl)                                          \
_(protocol)                                     \
_(checksum)

typedef struct
{
  u16 src_port, dst_port;
} tcpudp_header_t;

#if VPP_API_TEST_BUILTIN == 0
uword
unformat_tcp_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u8 *mask = 0;
  u8 found_something = 0;
  tcp_header_t *tcp;

#define _(a) u8 a=0;
  foreach_tcp_proto_field;
#undef _

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0);
#define _(a) else if (unformat (input, #a)) a=1;
      foreach_tcp_proto_field
#undef _
	else
	break;
    }

#define _(a) found_something += a;
  foreach_tcp_proto_field;
#undef _

  if (found_something == 0)
    return 0;

  vec_validate (mask, sizeof (*tcp) - 1);

  tcp = (tcp_header_t *) mask;

#define _(a) if (a) clib_memset (&tcp->a, 0xff, sizeof (tcp->a));
  foreach_tcp_proto_field;
#undef _

  *maskp = mask;
  return 1;
}

uword
unformat_udp_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u8 *mask = 0;
  u8 found_something = 0;
  udp_header_t *udp;

#define _(a) u8 a=0;
  foreach_udp_proto_field;
#undef _

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0);
#define _(a) else if (unformat (input, #a)) a=1;
      foreach_udp_proto_field
#undef _
	else
	break;
    }

#define _(a) found_something += a;
  foreach_udp_proto_field;
#undef _

  if (found_something == 0)
    return 0;

  vec_validate (mask, sizeof (*udp) - 1);

  udp = (udp_header_t *) mask;

#define _(a) if (a) clib_memset (&udp->a, 0xff, sizeof (udp->a));
  foreach_udp_proto_field;
#undef _

  *maskp = mask;
  return 1;
}

uword
unformat_l4_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u16 src_port = 0, dst_port = 0;
  tcpudp_header_t *tcpudp;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tcp %U", unformat_tcp_mask, maskp))
	return 1;
      else if (unformat (input, "udp %U", unformat_udp_mask, maskp))
	return 1;
      else if (unformat (input, "src_port"))
	src_port = 0xFFFF;
      else if (unformat (input, "dst_port"))
	dst_port = 0xFFFF;
      else
	return 0;
    }

  if (!src_port && !dst_port)
    return 0;

  u8 *mask = 0;
  vec_validate (mask, sizeof (tcpudp_header_t) - 1);

  tcpudp = (tcpudp_header_t *) mask;
  tcpudp->src_port = src_port;
  tcpudp->dst_port = dst_port;

  *maskp = mask;

  return 1;
}

uword
unformat_ip4_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u8 *mask = 0;
  u8 found_something = 0;
  ip4_header_t *ip;

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

#define _(a) if (a) clib_memset (&ip->a, 0xff, sizeof (ip->a));
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

uword
unformat_ip6_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u8 *mask = 0;
  u8 found_something = 0;
  ip6_header_t *ip;
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

#define _(a) if (a) clib_memset (&ip->a, 0xff, sizeof (ip->a));
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

uword
unformat_l3_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ip4 %U", unformat_ip4_mask, maskp))
	return 1;
      else if (unformat (input, "ip6 %U", unformat_ip6_mask, maskp))
	return 1;
      else
	break;
    }
  return 0;
}

uword
unformat_l2_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u8 *mask = 0;
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

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
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

  vec_validate (mask, len - 1);

  if (dst)
    clib_memset (mask, 0xff, 6);

  if (src)
    clib_memset (mask + 6, 0xff, 6);

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
	mask[21] = mask[20] = 0xff;
      if (tag1)
	{
	  mask[15] = 0xff;
	  mask[14] = 0x0f;
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
	  mask[15] = 0xff;
	  mask[14] = 0x0f;
	}
      if (cos1)
	mask[14] |= 0xe0;
      if (proto)
	mask[16] = mask[17] = 0xff;

      *maskp = mask;
      return 1;
    }
  if (cos2)
    mask[18] |= 0xe0;
  if (cos1)
    mask[14] |= 0xe0;
  if (proto)
    mask[12] = mask[13] = 0xff;

  *maskp = mask;
  return 1;
}

uword
unformat_classify_mask (unformat_input_t * input, va_list * args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u32 *skipp = va_arg (*args, u32 *);
  u32 *matchp = va_arg (*args, u32 *);
  u32 match;
  u8 *mask = 0;
  u8 *l2 = 0;
  u8 *l3 = 0;
  u8 *l4 = 0;
  int i;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "hex %U", unformat_hex_string, &mask))
	;
      else if (unformat (input, "l2 %U", unformat_l2_mask, &l2))
	;
      else if (unformat (input, "l3 %U", unformat_l3_mask, &l3))
	;
      else if (unformat (input, "l4 %U", unformat_l4_mask, &l4))
	;
      else
	break;
    }

  if (l4 && !l3)
    {
      vec_free (mask);
      vec_free (l2);
      vec_free (l4);
      return 0;
    }

  if (mask || l2 || l3 || l4)
    {
      if (l2 || l3 || l4)
	{
	  /* "With a free Ethernet header in every package" */
	  if (l2 == 0)
	    vec_validate (l2, 13);
	  mask = l2;
	  if (vec_len (l3))
	    {
	      vec_append (mask, l3);
	      vec_free (l3);
	    }
	  if (vec_len (l4))
	    {
	      vec_append (mask, l4);
	      vec_free (l4);
	    }
	}

      /* Scan forward looking for the first significant mask octet */
      for (i = 0; i < vec_len (mask); i++)
	if (mask[i])
	  break;

      /* compute (skip, match) params */
      *skipp = i / sizeof (u32x4);
      vec_delete (mask, *skipp * sizeof (u32x4), 0);

      /* Pad mask to an even multiple of the vector size */
      while (vec_len (mask) % sizeof (u32x4))
	vec_add1 (mask, 0);

      match = vec_len (mask) / sizeof (u32x4);

      for (i = match * sizeof (u32x4); i > 0; i -= sizeof (u32x4))
	{
	  u64 *tmp = (u64 *) (mask + (i - sizeof (u32x4)));
	  if (*tmp || *(tmp + 1))
	    break;
	  match--;
	}
      if (match == 0)
	clib_warning ("BUG: match 0");

      _vec_len (mask) = match * sizeof (u32x4);

      *matchp = match;
      *maskp = mask;

      return 1;
    }

  return 0;
}
#endif /* VPP_API_TEST_BUILTIN */

#define foreach_l2_next                         \
_(drop, DROP)                                   \
_(ethernet, ETHERNET_INPUT)                     \
_(ip4, IP4_INPUT)                               \
_(ip6, IP6_INPUT)

uword
unformat_l2_next_index (unformat_input_t * input, va_list * args)
{
  u32 *miss_next_indexp = va_arg (*args, u32 *);
  u32 next_index = 0;
  u32 tmp;

#define _(n,N) \
  if (unformat (input, #n)) { next_index = L2_INPUT_CLASSIFY_NEXT_##N; goto out;}
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
_(drop, DROP)                                   \
_(local, LOCAL)                                 \
_(rewrite, REWRITE)

uword
api_unformat_ip_next_index (unformat_input_t * input, va_list * args)
{
  u32 *miss_next_indexp = va_arg (*args, u32 *);
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

uword
api_unformat_acl_next_index (unformat_input_t * input, va_list * args)
{
  u32 *miss_next_indexp = va_arg (*args, u32 *);
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

uword
unformat_policer_precolor (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (unformat (input, "conform-color"))
    *r = POLICE_CONFORM;
  else if (unformat (input, "exceed-color"))
    *r = POLICE_EXCEED;
  else
    return 0;

  return 1;
}

static int
api_classify_add_del_table (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_classify_add_del_table_t *mp;

  u32 nbuckets = 2;
  u32 skip = ~0;
  u32 match = ~0;
  int is_add = 1;
  int del_chain = 0;
  u32 table_index = ~0;
  u32 next_table_index = ~0;
  u32 miss_next_index = ~0;
  u32 memory_size = 32 << 20;
  u8 *mask = 0;
  u32 current_data_flag = 0;
  int current_data_offset = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "del-chain"))
	{
	  is_add = 0;
	  del_chain = 1;
	}
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
      else if (unformat (i, "miss-next %U", api_unformat_ip_next_index,
			 &miss_next_index))
	;
      else if (unformat (i, "l2-miss-next %U", unformat_l2_next_index,
			 &miss_next_index))
	;
      else if (unformat (i, "acl-miss-next %U", api_unformat_acl_next_index,
			 &miss_next_index))
	;
      else if (unformat (i, "current-data-flag %d", &current_data_flag))
	;
      else if (unformat (i, "current-data-offset %d", &current_data_offset))
	;
      else
	break;
    }

  if (is_add && mask == 0)
    {
      errmsg ("Mask required");
      return -99;
    }

  if (is_add && skip == ~0)
    {
      errmsg ("skip count required");
      return -99;
    }

  if (is_add && match == ~0)
    {
      errmsg ("match count required");
      return -99;
    }

  if (!is_add && table_index == ~0)
    {
      errmsg ("table index required for delete");
      return -99;
    }

  M2 (CLASSIFY_ADD_DEL_TABLE, mp, vec_len (mask));

  mp->is_add = is_add;
  mp->del_chain = del_chain;
  mp->table_index = ntohl (table_index);
  mp->nbuckets = ntohl (nbuckets);
  mp->memory_size = ntohl (memory_size);
  mp->skip_n_vectors = ntohl (skip);
  mp->match_n_vectors = ntohl (match);
  mp->next_table_index = ntohl (next_table_index);
  mp->miss_next_index = ntohl (miss_next_index);
  mp->current_data_flag = ntohl (current_data_flag);
  mp->current_data_offset = ntohl (current_data_offset);
  mp->mask_len = ntohl (vec_len (mask));
  clib_memcpy (mp->mask, mask, vec_len (mask));

  vec_free (mask);

  S (mp);
  W (ret);
  return ret;
}

#if VPP_API_TEST_BUILTIN == 0
uword
unformat_l4_match (unformat_input_t * input, va_list * args)
{
  u8 **matchp = va_arg (*args, u8 **);

  u8 *proto_header = 0;
  int src_port = 0;
  int dst_port = 0;

  tcpudp_header_t h;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "src_port %d", &src_port))
	;
      else if (unformat (input, "dst_port %d", &dst_port))
	;
      else
	return 0;
    }

  h.src_port = clib_host_to_net_u16 (src_port);
  h.dst_port = clib_host_to_net_u16 (dst_port);
  vec_validate (proto_header, sizeof (h) - 1);
  memcpy (proto_header, &h, sizeof (h));

  *matchp = proto_header;

  return 1;
}

uword
unformat_ip4_match (unformat_input_t * input, va_list * args)
{
  u8 **matchp = va_arg (*args, u8 **);
  u8 *match = 0;
  ip4_header_t *ip;
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
  vec_validate_aligned (match, sizeof (*ip) - 1, sizeof (u32x4));

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
    ip->ip_version_and_header_length |= (version_val & 0xF) << 4;

  if (hdr_length)
    ip->ip_version_and_header_length |= (hdr_length_val & 0xF);

  if (tos)
    ip->tos = tos_val;

  if (length)
    ip->length = clib_host_to_net_u16 (length_val);

  if (ttl)
    ip->ttl = ttl_val;

  if (checksum)
    ip->checksum = clib_host_to_net_u16 (checksum_val);

  *matchp = match;
  return 1;
}

uword
unformat_ip6_match (unformat_input_t * input, va_list * args)
{
  u8 **matchp = va_arg (*args, u8 **);
  u8 *match = 0;
  ip6_header_t *ip;
  int version = 0;
  u32 version_val;
  u8 traffic_class = 0;
  u32 traffic_class_val = 0;
  u8 flow_label = 0;
  u8 flow_label_val;
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
  vec_validate_aligned (match, sizeof (*ip) - 1, sizeof (u32x4));

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
    ip_version_traffic_class_and_flow_label |=
      (traffic_class_val & 0xFF) << 20;

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

uword
unformat_l3_match (unformat_input_t * input, va_list * args)
{
  u8 **matchp = va_arg (*args, u8 **);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ip4 %U", unformat_ip4_match, matchp))
	return 1;
      else if (unformat (input, "ip6 %U", unformat_ip6_match, matchp))
	return 1;
      else
	break;
    }
  return 0;
}

uword
unformat_vlan_tag (unformat_input_t * input, va_list * args)
{
  u8 *tagp = va_arg (*args, u8 *);
  u32 tag;

  if (unformat (input, "%d", &tag))
    {
      tagp[0] = (tag >> 8) & 0x0F;
      tagp[1] = tag & 0xFF;
      return 1;
    }

  return 0;
}

uword
unformat_l2_match (unformat_input_t * input, va_list * args)
{
  u8 **matchp = va_arg (*args, u8 **);
  u8 *match = 0;
  u8 src = 0;
  u8 src_val[6];
  u8 dst = 0;
  u8 dst_val[6];
  u8 proto = 0;
  u16 proto_val;
  u8 tag1 = 0;
  u8 tag1_val[2];
  u8 tag2 = 0;
  u8 tag2_val[2];
  int len = 14;
  u8 ignore_tag1 = 0;
  u8 ignore_tag2 = 0;
  u8 cos1 = 0;
  u8 cos2 = 0;
  u32 cos1_val = 0;
  u32 cos2_val = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "src %U", unformat_ethernet_address, &src_val))
	src = 1;
      else
	if (unformat (input, "dst %U", unformat_ethernet_address, &dst_val))
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

  vec_validate_aligned (match, len - 1, sizeof (u32x4));

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
	match[18] |= (cos2_val & 0x7) << 5;
      if (proto)
	{
	  match[21] = proto_val & 0xff;
	  match[20] = proto_val >> 8;
	}
      if (tag1)
	{
	  match[15] = tag1_val[1];
	  match[14] = tag1_val[0];
	}
      if (cos1)
	match[14] |= (cos1_val & 0x7) << 5;
      *matchp = match;
      return 1;
    }
  if (tag1)
    {
      match[15] = tag1_val[1];
      match[14] = tag1_val[0];
      if (proto)
	{
	  match[17] = proto_val & 0xff;
	  match[16] = proto_val >> 8;
	}
      if (cos1)
	match[14] |= (cos1_val & 0x7) << 5;

      *matchp = match;
      return 1;
    }
  if (cos2)
    match[18] |= (cos2_val & 0x7) << 5;
  if (cos1)
    match[14] |= (cos1_val & 0x7) << 5;
  if (proto)
    {
      match[13] = proto_val & 0xff;
      match[12] = proto_val >> 8;
    }

  *matchp = match;
  return 1;
}

uword
unformat_qos_source (unformat_input_t * input, va_list * args)
{
  int *qs = va_arg (*args, int *);

  if (unformat (input, "ip"))
    *qs = QOS_SOURCE_IP;
  else if (unformat (input, "mpls"))
    *qs = QOS_SOURCE_MPLS;
  else if (unformat (input, "ext"))
    *qs = QOS_SOURCE_EXT;
  else if (unformat (input, "vlan"))
    *qs = QOS_SOURCE_VLAN;
  else
    return 0;

  return 1;
}
#endif

uword
api_unformat_classify_match (unformat_input_t * input, va_list * args)
{
  u8 **matchp = va_arg (*args, u8 **);
  u32 skip_n_vectors = va_arg (*args, u32);
  u32 match_n_vectors = va_arg (*args, u32);

  u8 *match = 0;
  u8 *l2 = 0;
  u8 *l3 = 0;
  u8 *l4 = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "hex %U", unformat_hex_string, &match))
	;
      else if (unformat (input, "l2 %U", unformat_l2_match, &l2))
	;
      else if (unformat (input, "l3 %U", unformat_l3_match, &l3))
	;
      else if (unformat (input, "l4 %U", unformat_l4_match, &l4))
	;
      else
	break;
    }

  if (l4 && !l3)
    {
      vec_free (match);
      vec_free (l2);
      vec_free (l4);
      return 0;
    }

  if (match || l2 || l3 || l4)
    {
      if (l2 || l3 || l4)
	{
	  /* "Win a free Ethernet header in every packet" */
	  if (l2 == 0)
	    vec_validate_aligned (l2, 13, sizeof (u32x4));
	  match = l2;
	  if (vec_len (l3))
	    {
	      vec_append_aligned (match, l3, sizeof (u32x4));
	      vec_free (l3);
	    }
	  if (vec_len (l4))
	    {
	      vec_append_aligned (match, l4, sizeof (u32x4));
	      vec_free (l4);
	    }
	}

      /* Make sure the vector is big enough even if key is all 0's */
      vec_validate_aligned
	(match, ((match_n_vectors + skip_n_vectors) * sizeof (u32x4)) - 1,
	 sizeof (u32x4));

      /* Set size, include skipped vectors */
      _vec_len (match) = (match_n_vectors + skip_n_vectors) * sizeof (u32x4);

      *matchp = match;

      return 1;
    }

  return 0;
}

static int
api_classify_add_del_session (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_classify_add_del_session_t *mp;
  int is_add = 1;
  u32 table_index = ~0;
  u32 hit_next_index = ~0;
  u32 opaque_index = ~0;
  u8 *match = 0;
  i32 advance = 0;
  u32 skip_n_vectors = 0;
  u32 match_n_vectors = 0;
  u32 action = 0;
  u32 metadata = 0;
  int ret;

  /*
   * Warning: you have to supply skip_n and match_n
   * because the API client cant simply look at the classify
   * table object.
   */

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "hit-next %U", api_unformat_ip_next_index,
			 &hit_next_index))
	;
      else if (unformat (i, "l2-hit-next %U", unformat_l2_next_index,
			 &hit_next_index))
	;
      else if (unformat (i, "acl-hit-next %U", api_unformat_acl_next_index,
			 &hit_next_index))
	;
      else if (unformat (i, "policer-hit-next %d", &hit_next_index))
	;
      else if (unformat (i, "%U", unformat_policer_precolor, &opaque_index))
	;
      else if (unformat (i, "opaque-index %d", &opaque_index))
	;
      else if (unformat (i, "skip_n %d", &skip_n_vectors))
	;
      else if (unformat (i, "match_n %d", &match_n_vectors))
	;
      else if (unformat (i, "match %U", api_unformat_classify_match,
			 &match, skip_n_vectors, match_n_vectors))
	;
      else if (unformat (i, "advance %d", &advance))
	;
      else if (unformat (i, "table-index %d", &table_index))
	;
      else if (unformat (i, "action set-ip4-fib-id %d", &metadata))
	action = 1;
      else if (unformat (i, "action set-ip6-fib-id %d", &metadata))
	action = 2;
      else if (unformat (i, "action %d", &action))
	;
      else if (unformat (i, "metadata %d", &metadata))
	;
      else
	break;
    }

  if (table_index == ~0)
    {
      errmsg ("Table index required");
      return -99;
    }

  if (is_add && match == 0)
    {
      errmsg ("Match value required");
      return -99;
    }

  M2 (CLASSIFY_ADD_DEL_SESSION, mp, vec_len (match));

  mp->is_add = is_add;
  mp->table_index = ntohl (table_index);
  mp->hit_next_index = ntohl (hit_next_index);
  mp->opaque_index = ntohl (opaque_index);
  mp->advance = ntohl (advance);
  mp->action = action;
  mp->metadata = ntohl (metadata);
  mp->match_len = ntohl (vec_len (match));
  clib_memcpy (mp->match, match, vec_len (match));
  vec_free (match);

  S (mp);
  W (ret);
  return ret;
}

static int
api_classify_set_interface_ip_table (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_classify_set_interface_ip_table_t *mp;
  u32 sw_if_index;
  int sw_if_index_set;
  u32 table_index = ~0;
  u8 is_ipv6 = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "table %d", &table_index))
	;
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


  M (CLASSIFY_SET_INTERFACE_IP_TABLE, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->table_index = ntohl (table_index);
  mp->is_ipv6 = is_ipv6;

  S (mp);
  W (ret);
  return ret;
}

static int
api_classify_set_interface_l2_tables (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_classify_set_interface_l2_tables_t *mp;
  u32 sw_if_index;
  int sw_if_index_set;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  u32 other_table_index = ~0;
  u32 is_input = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "ip4-table %d", &ip4_table_index))
	;
      else if (unformat (i, "ip6-table %d", &ip6_table_index))
	;
      else if (unformat (i, "other-table %d", &other_table_index))
	;
      else if (unformat (i, "is-input %d", &is_input))
	;
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


  M (CLASSIFY_SET_INTERFACE_L2_TABLES, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->ip4_table_index = ntohl (ip4_table_index);
  mp->ip6_table_index = ntohl (ip6_table_index);
  mp->other_table_index = ntohl (other_table_index);
  mp->is_input = (u8) is_input;

  S (mp);
  W (ret);
  return ret;
}

static int
api_set_ipfix_exporter (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_set_ipfix_exporter_t *mp;
  ip4_address_t collector_address;
  u8 collector_address_set = 0;
  u32 collector_port = ~0;
  ip4_address_t src_address;
  u8 src_address_set = 0;
  u32 vrf_id = ~0;
  u32 path_mtu = ~0;
  u32 template_interval = ~0;
  u8 udp_checksum = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
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
      else if (unformat (i, "udp_checksum"))
	udp_checksum = 1;
      else
	break;
    }

  if (collector_address_set == 0)
    {
      errmsg ("collector_address required");
      return -99;
    }

  if (src_address_set == 0)
    {
      errmsg ("src_address required");
      return -99;
    }

  M (SET_IPFIX_EXPORTER, mp);

  memcpy (mp->collector_address, collector_address.data,
	  sizeof (collector_address.data));
  mp->collector_port = htons ((u16) collector_port);
  memcpy (mp->src_address, src_address.data, sizeof (src_address.data));
  mp->vrf_id = htonl (vrf_id);
  mp->path_mtu = htonl (path_mtu);
  mp->template_interval = htonl (template_interval);
  mp->udp_checksum = udp_checksum;

  S (mp);
  W (ret);
  return ret;
}

static int
api_set_ipfix_classify_stream (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_set_ipfix_classify_stream_t *mp;
  u32 domain_id = 0;
  u32 src_port = UDP_DST_PORT_ipfix;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "domain %d", &domain_id))
	;
      else if (unformat (i, "src_port %d", &src_port))
	;
      else
	{
	  errmsg ("unknown input `%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (SET_IPFIX_CLASSIFY_STREAM, mp);

  mp->domain_id = htonl (domain_id);
  mp->src_port = htons ((u16) src_port);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ipfix_classify_table_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipfix_classify_table_add_del_t *mp;
  int is_add = -1;
  u32 classify_table_index = ~0;
  u8 ip_version = 0;
  u8 transport_protocol = 255;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "table %d", &classify_table_index))
	;
      else if (unformat (i, "ip4"))
	ip_version = 4;
      else if (unformat (i, "ip6"))
	ip_version = 6;
      else if (unformat (i, "tcp"))
	transport_protocol = 6;
      else if (unformat (i, "udp"))
	transport_protocol = 17;
      else
	{
	  errmsg ("unknown input `%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (is_add == -1)
    {
      errmsg ("expecting: add|del");
      return -99;
    }
  if (classify_table_index == ~0)
    {
      errmsg ("classifier table not specified");
      return -99;
    }
  if (ip_version == 0)
    {
      errmsg ("IP version not specified");
      return -99;
    }

  M (IPFIX_CLASSIFY_TABLE_ADD_DEL, mp);

  mp->is_add = is_add;
  mp->table_id = htonl (classify_table_index);
  mp->ip_version = ip_version;
  mp->transport_protocol = transport_protocol;

  S (mp);
  W (ret);
  return ret;
}

static int
api_get_node_index (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_get_node_index_t *mp;
  u8 *name = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "node %s", &name))
	;
      else
	break;
    }
  if (name == 0)
    {
      errmsg ("node name required");
      return -99;
    }
  if (vec_len (name) >= ARRAY_LEN (mp->node_name))
    {
      errmsg ("node name too long, max %d", ARRAY_LEN (mp->node_name));
      return -99;
    }

  M (GET_NODE_INDEX, mp);
  clib_memcpy (mp->node_name, name, vec_len (name));
  vec_free (name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_get_next_index (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_get_next_index_t *mp;
  u8 *node_name = 0, *next_node_name = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "node-name %s", &node_name))
	;
      else if (unformat (i, "next-node-name %s", &next_node_name))
	break;
    }

  if (node_name == 0)
    {
      errmsg ("node name required");
      return -99;
    }
  if (vec_len (node_name) >= ARRAY_LEN (mp->node_name))
    {
      errmsg ("node name too long, max %d", ARRAY_LEN (mp->node_name));
      return -99;
    }

  if (next_node_name == 0)
    {
      errmsg ("next node name required");
      return -99;
    }
  if (vec_len (next_node_name) >= ARRAY_LEN (mp->next_name))
    {
      errmsg ("next node name too long, max %d", ARRAY_LEN (mp->next_name));
      return -99;
    }

  M (GET_NEXT_INDEX, mp);
  clib_memcpy (mp->node_name, node_name, vec_len (node_name));
  clib_memcpy (mp->next_name, next_node_name, vec_len (next_node_name));
  vec_free (node_name);
  vec_free (next_node_name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_add_node_next (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_add_node_next_t *mp;
  u8 *name = 0;
  u8 *next = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "node %s", &name))
	;
      else if (unformat (i, "next %s", &next))
	;
      else
	break;
    }
  if (name == 0)
    {
      errmsg ("node name required");
      return -99;
    }
  if (vec_len (name) >= ARRAY_LEN (mp->node_name))
    {
      errmsg ("node name too long, max %d", ARRAY_LEN (mp->node_name));
      return -99;
    }
  if (next == 0)
    {
      errmsg ("next node required");
      return -99;
    }
  if (vec_len (next) >= ARRAY_LEN (mp->next_name))
    {
      errmsg ("next name too long, max %d", ARRAY_LEN (mp->next_name));
      return -99;
    }

  M (ADD_NODE_NEXT, mp);
  clib_memcpy (mp->node_name, name, vec_len (name));
  clib_memcpy (mp->next_name, next, vec_len (next));
  vec_free (name);
  vec_free (next);

  S (mp);
  W (ret);
  return ret;
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

  clib_memcpy (mp->client_address, client_address.as_u8,
	       sizeof (mp->client_address));

  clib_memcpy (mp->our_address, our_address.as_u8, sizeof (mp->our_address));

  mp->local_session_id = ntohl (local_session_id);
  mp->remote_session_id = ntohl (remote_session_id);
  mp->local_cookie = clib_host_to_net_u64 (local_cookie);
  mp->remote_cookie = clib_host_to_net_u64 (remote_cookie);
  mp->l2_sublayer_present = l2_sublayer_present;
  mp->is_ipv6 = 1;

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
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
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
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
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

static void vl_api_sw_if_l2tpv3_tunnel_details_t_handler_json
  (vl_api_sw_if_l2tpv3_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;
  struct in6_addr addr;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);

  clib_memcpy (&addr, mp->our_address, sizeof (addr));
  vat_json_object_add_ip6 (node, "our_address", addr);
  clib_memcpy (&addr, mp->client_address, sizeof (addr));
  vat_json_object_add_ip6 (node, "client_address", addr);

  vat_json_node_t *lc = vat_json_object_add (node, "local_cookie");
  vat_json_init_array (lc);
  vat_json_array_add_uint (lc, clib_net_to_host_u64 (mp->local_cookie[0]));
  vat_json_array_add_uint (lc, clib_net_to_host_u64 (mp->local_cookie[1]));
  vat_json_object_add_uint (node, "remote_cookie",
			    clib_net_to_host_u64 (mp->remote_cookie));

  printf ("local id: %u", clib_net_to_host_u32 (mp->local_session_id));
  vat_json_object_add_uint (node, "local_session_id",
			    clib_net_to_host_u32 (mp->local_session_id));
  vat_json_object_add_uint (node, "remote_session_id",
			    clib_net_to_host_u32 (mp->remote_session_id));
  vat_json_object_add_string_copy (node, "l2_sublayer",
				   mp->l2_sublayer_present ? (u8 *) "present"
				   : (u8 *) "absent");
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
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}


static void vl_api_sw_interface_tap_details_t_handler
  (vl_api_sw_interface_tap_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%-16s %d",
	 mp->dev_name, clib_net_to_host_u32 (mp->sw_if_index));
}

static void vl_api_sw_interface_tap_details_t_handler_json
  (vl_api_sw_interface_tap_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  vat_json_object_add_string_copy (node, "dev_name", mp->dev_name);
}

static int
api_sw_interface_tap_dump (vat_main_t * vam)
{
  vl_api_sw_interface_tap_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  print (vam->ofp, "\n%-16s %s", "dev_name", "sw_if_index");
  /* Get list of tap interfaces */
  M (SW_INTERFACE_TAP_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void vl_api_sw_interface_tap_v2_details_t_handler
  (vl_api_sw_interface_tap_v2_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  u8 *ip4 = format (0, "%U/%d", format_ip4_address, mp->host_ip4_addr,
		    mp->host_ip4_prefix_len);
  u8 *ip6 = format (0, "%U/%d", format_ip6_address, mp->host_ip6_addr,
		    mp->host_ip6_prefix_len);

  print (vam->ofp,
	 "\n%-16s %-12d %-5d %-12d %-12d %-14U %-30s %-20s %-20s %-30s 0x%-08x",
	 mp->dev_name, ntohl (mp->sw_if_index), ntohl (mp->id),
	 ntohs (mp->rx_ring_sz), ntohs (mp->tx_ring_sz),
	 format_ethernet_address, mp->host_mac_addr, mp->host_namespace,
	 mp->host_bridge, ip4, ip6, ntohl (mp->tap_flags));

  vec_free (ip4);
  vec_free (ip6);
}

static void vl_api_sw_interface_tap_v2_details_t_handler_json
  (vl_api_sw_interface_tap_v2_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "id", ntohl (mp->id));
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  vat_json_object_add_uint (node, "tap_flags", ntohl (mp->tap_flags));
  vat_json_object_add_string_copy (node, "dev_name", mp->dev_name);
  vat_json_object_add_uint (node, "rx_ring_sz", ntohs (mp->rx_ring_sz));
  vat_json_object_add_uint (node, "tx_ring_sz", ntohs (mp->tx_ring_sz));
  vat_json_object_add_string_copy (node, "host_mac_addr",
				   format (0, "%U", format_ethernet_address,
					   &mp->host_mac_addr));
  vat_json_object_add_string_copy (node, "host_namespace",
				   mp->host_namespace);
  vat_json_object_add_string_copy (node, "host_bridge", mp->host_bridge);
  vat_json_object_add_string_copy (node, "host_ip4_addr",
				   format (0, "%U/%d", format_ip4_address,
					   mp->host_ip4_addr,
					   mp->host_ip4_prefix_len));
  vat_json_object_add_string_copy (node, "host_ip6_addr",
				   format (0, "%U/%d", format_ip6_address,
					   mp->host_ip6_addr,
					   mp->host_ip6_prefix_len));

}

static int
api_sw_interface_tap_v2_dump (vat_main_t * vam)
{
  vl_api_sw_interface_tap_v2_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  print (vam->ofp,
	 "\n%-16s %-12s %-5s %-12s %-12s %-14s %-30s %-20s %-20s %-30s",
	 "dev_name", "sw_if_index", "id", "rx_ring_sz", "tx_ring_sz",
	 "host_mac_addr", "host_namespace", "host_bridge", "host_ip4_addr",
	 "host_ip6_addr");

  /* Get list of tap interfaces */
  M (SW_INTERFACE_TAP_V2_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_vxlan_offload_rx (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_vxlan_offload_rx_t *mp;
  u32 hw_if_index = ~0, rx_if_index = ~0;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "hw %U", api_unformat_hw_if_index, vam,
			 &hw_if_index))
	;
      else if (unformat (line_input, "hw hw_if_index %u", &hw_if_index))
	;
      else if (unformat (line_input, "rx %U", api_unformat_sw_if_index, vam,
			 &rx_if_index))
	;
      else if (unformat (line_input, "rx sw_if_index %u", &rx_if_index))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, line_input);
	  return -99;
	}
    }

  if (hw_if_index == ~0)
    {
      errmsg ("no hw interface");
      return -99;
    }

  if (rx_if_index == ~0)
    {
      errmsg ("no rx tunnel");
      return -99;
    }

  M (VXLAN_OFFLOAD_RX, mp);

  mp->hw_if_index = ntohl (hw_if_index);
  mp->sw_if_index = ntohl (rx_if_index);
  mp->enable = is_add;

  S (mp);
  W (ret);
  return ret;
}

static uword unformat_vxlan_decap_next
  (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);
  u32 tmp;

  if (unformat (input, "l2"))
    *result = VXLAN_INPUT_NEXT_L2_INPUT;
  else if (unformat (input, "%d", &tmp))
    *result = tmp;
  else
    return 0;
  return 1;
}

static int
api_vxlan_add_del_tunnel (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_vxlan_add_del_tunnel_t *mp;
  ip46_address_t src, dst;
  u8 is_add = 1;
  u8 ipv4_set = 0, ipv6_set = 0;
  u8 src_set = 0;
  u8 dst_set = 0;
  u8 grp_set = 0;
  u32 instance = ~0;
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
      else if (unformat (line_input, "instance %d", &instance))
	;
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
			 unformat_vxlan_decap_next, &decap_next_index))
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

  M (VXLAN_ADD_DEL_TUNNEL, mp);

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

  mp->instance = htonl (instance);
  mp->encap_vrf_id = ntohl (encap_vrf_id);
  mp->decap_next_index = ntohl (decap_next_index);
  mp->mcast_sw_if_index = ntohl (mcast_sw_if_index);
  mp->vni = ntohl (vni);
  mp->is_add = is_add;
  mp->is_ipv6 = ipv6_set;

  S (mp);
  W (ret);
  return ret;
}

static void vl_api_vxlan_tunnel_details_t_handler
  (vl_api_vxlan_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  ip46_address_t src = to_ip46 (mp->is_ipv6, mp->dst_address);
  ip46_address_t dst = to_ip46 (mp->is_ipv6, mp->src_address);

  print (vam->ofp, "%11d%11d%24U%24U%14d%18d%13d%19d",
	 ntohl (mp->sw_if_index),
	 ntohl (mp->instance),
	 format_ip46_address, &src, IP46_TYPE_ANY,
	 format_ip46_address, &dst, IP46_TYPE_ANY,
	 ntohl (mp->encap_vrf_id),
	 ntohl (mp->decap_next_index), ntohl (mp->vni),
	 ntohl (mp->mcast_sw_if_index));
}

static void vl_api_vxlan_tunnel_details_t_handler_json
  (vl_api_vxlan_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));

  vat_json_object_add_uint (node, "instance", ntohl (mp->instance));

  if (mp->is_ipv6)
    {
      struct in6_addr ip6;

      clib_memcpy (&ip6, mp->src_address, sizeof (ip6));
      vat_json_object_add_ip6 (node, "src_address", ip6);
      clib_memcpy (&ip6, mp->dst_address, sizeof (ip6));
      vat_json_object_add_ip6 (node, "dst_address", ip6);
    }
  else
    {
      struct in_addr ip4;

      clib_memcpy (&ip4, mp->src_address, sizeof (ip4));
      vat_json_object_add_ip4 (node, "src_address", ip4);
      clib_memcpy (&ip4, mp->dst_address, sizeof (ip4));
      vat_json_object_add_ip4 (node, "dst_address", ip4);
    }
  vat_json_object_add_uint (node, "encap_vrf_id", ntohl (mp->encap_vrf_id));
  vat_json_object_add_uint (node, "decap_next_index",
			    ntohl (mp->decap_next_index));
  vat_json_object_add_uint (node, "vni", ntohl (mp->vni));
  vat_json_object_add_uint (node, "is_ipv6", mp->is_ipv6 ? 1 : 0);
  vat_json_object_add_uint (node, "mcast_sw_if_index",
			    ntohl (mp->mcast_sw_if_index));
}

static int
api_vxlan_tunnel_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_vxlan_tunnel_dump_t *mp;
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
      print (vam->ofp, "%11s%11s%24s%24s%14s%18s%13s%19s",
	     "sw_if_index", "instance", "src_address", "dst_address",
	     "encap_vrf_id", "decap_next_index", "vni", "mcast_sw_if_index");
    }

  /* Get list of vxlan-tunnel interfaces */
  M (VXLAN_TUNNEL_DUMP, mp);

  mp->sw_if_index = htonl (sw_if_index);

  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

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
      clib_memcpy (mp->local_address, &src.ip6, sizeof (src.ip6));
      clib_memcpy (mp->remote_address, &dst.ip6, sizeof (dst.ip6));
    }
  else
    {
      clib_memcpy (mp->local_address, &src.ip4, sizeof (src.ip4));
      clib_memcpy (mp->remote_address, &dst.ip4, sizeof (dst.ip4));
    }
  mp->encap_vrf_id = ntohl (encap_vrf_id);
  mp->decap_next_index = ntohl (decap_next_index);
  mp->mcast_sw_if_index = ntohl (mcast_sw_if_index);
  mp->vni = ntohl (vni);
  mp->is_add = is_add;
  mp->is_ipv6 = ipv6_set;

  S (mp);
  W (ret);
  return ret;
}

static void vl_api_geneve_tunnel_details_t_handler
  (vl_api_geneve_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  ip46_address_t src = to_ip46 (mp->is_ipv6, mp->dst_address);
  ip46_address_t dst = to_ip46 (mp->is_ipv6, mp->src_address);

  print (vam->ofp, "%11d%24U%24U%14d%18d%13d%19d",
	 ntohl (mp->sw_if_index),
	 format_ip46_address, &src, IP46_TYPE_ANY,
	 format_ip46_address, &dst, IP46_TYPE_ANY,
	 ntohl (mp->encap_vrf_id),
	 ntohl (mp->decap_next_index), ntohl (mp->vni),
	 ntohl (mp->mcast_sw_if_index));
}

static void vl_api_geneve_tunnel_details_t_handler_json
  (vl_api_geneve_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  if (mp->is_ipv6)
    {
      struct in6_addr ip6;

      clib_memcpy (&ip6, mp->src_address, sizeof (ip6));
      vat_json_object_add_ip6 (node, "src_address", ip6);
      clib_memcpy (&ip6, mp->dst_address, sizeof (ip6));
      vat_json_object_add_ip6 (node, "dst_address", ip6);
    }
  else
    {
      struct in_addr ip4;

      clib_memcpy (&ip4, mp->src_address, sizeof (ip4));
      vat_json_object_add_ip4 (node, "src_address", ip4);
      clib_memcpy (&ip4, mp->dst_address, sizeof (ip4));
      vat_json_object_add_ip4 (node, "dst_address", ip4);
    }
  vat_json_object_add_uint (node, "encap_vrf_id", ntohl (mp->encap_vrf_id));
  vat_json_object_add_uint (node, "decap_next_index",
			    ntohl (mp->decap_next_index));
  vat_json_object_add_uint (node, "vni", ntohl (mp->vni));
  vat_json_object_add_uint (node, "is_ipv6", mp->is_ipv6 ? 1 : 0);
  vat_json_object_add_uint (node, "mcast_sw_if_index",
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
  M (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_gre_add_del_tunnel (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_gre_add_del_tunnel_t *mp;
  ip4_address_t src4, dst4;
  ip6_address_t src6, dst6;
  u8 is_add = 1;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  u8 t_type = GRE_TUNNEL_TYPE_L3;
  u8 src_set = 0;
  u8 dst_set = 0;
  u32 outer_fib_id = 0;
  u32 session_id = 0;
  u32 instance = ~0;
  int ret;

  clib_memset (&src4, 0, sizeof src4);
  clib_memset (&dst4, 0, sizeof dst4);
  clib_memset (&src6, 0, sizeof src6);
  clib_memset (&dst6, 0, sizeof dst6);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "instance %d", &instance))
	;
      else if (unformat (line_input, "src %U", unformat_ip4_address, &src4))
	{
	  src_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "dst %U", unformat_ip4_address, &dst4))
	{
	  dst_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "src %U", unformat_ip6_address, &src6))
	{
	  src_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "dst %U", unformat_ip6_address, &dst6))
	{
	  dst_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "outer-fib-id %d", &outer_fib_id))
	;
      else if (unformat (line_input, "teb"))
	t_type = GRE_TUNNEL_TYPE_TEB;
      else if (unformat (line_input, "erspan %d", &session_id))
	t_type = GRE_TUNNEL_TYPE_ERSPAN;
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
  if (ipv4_set && ipv6_set)
    {
      errmsg ("both IPv4 and IPv6 addresses specified");
      return -99;
    }


  M (GRE_ADD_DEL_TUNNEL, mp);

  if (ipv4_set)
    {
      clib_memcpy (&mp->src_address, &src4, 4);
      clib_memcpy (&mp->dst_address, &dst4, 4);
    }
  else
    {
      clib_memcpy (&mp->src_address, &src6, 16);
      clib_memcpy (&mp->dst_address, &dst6, 16);
    }
  mp->instance = htonl (instance);
  mp->outer_fib_id = htonl (outer_fib_id);
  mp->is_add = is_add;
  mp->session_id = htons ((u16) session_id);
  mp->tunnel_type = t_type;
  mp->is_ipv6 = ipv6_set;

  S (mp);
  W (ret);
  return ret;
}

static void vl_api_gre_tunnel_details_t_handler
  (vl_api_gre_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  ip46_address_t src = to_ip46 (mp->is_ipv6, mp->src_address);
  ip46_address_t dst = to_ip46 (mp->is_ipv6, mp->dst_address);

  print (vam->ofp, "%11d%11d%24U%24U%13d%14d%12d",
	 ntohl (mp->sw_if_index),
	 ntohl (mp->instance),
	 format_ip46_address, &src, IP46_TYPE_ANY,
	 format_ip46_address, &dst, IP46_TYPE_ANY,
	 mp->tunnel_type, ntohl (mp->outer_fib_id), ntohl (mp->session_id));
}

static void vl_api_gre_tunnel_details_t_handler_json
  (vl_api_gre_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;
  struct in_addr ip4;
  struct in6_addr ip6;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  vat_json_object_add_uint (node, "instance", ntohl (mp->instance));
  if (!mp->is_ipv6)
    {
      clib_memcpy (&ip4, &mp->src_address, sizeof (ip4));
      vat_json_object_add_ip4 (node, "src_address", ip4);
      clib_memcpy (&ip4, &mp->dst_address, sizeof (ip4));
      vat_json_object_add_ip4 (node, "dst_address", ip4);
    }
  else
    {
      clib_memcpy (&ip6, &mp->src_address, sizeof (ip6));
      vat_json_object_add_ip6 (node, "src_address", ip6);
      clib_memcpy (&ip6, &mp->dst_address, sizeof (ip6));
      vat_json_object_add_ip6 (node, "dst_address", ip6);
    }
  vat_json_object_add_uint (node, "tunnel_type", mp->tunnel_type);
  vat_json_object_add_uint (node, "outer_fib_id", ntohl (mp->outer_fib_id));
  vat_json_object_add_uint (node, "is_ipv6", mp->is_ipv6);
  vat_json_object_add_uint (node, "session_id", mp->session_id);
}

static int
api_gre_tunnel_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_gre_tunnel_dump_t *mp;
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
      print (vam->ofp, "%11s%11s%24s%24s%13s%14s%12s",
	     "sw_if_index", "instance", "src_address", "dst_address",
	     "tunnel_type", "outer_fib_id", "session_id");
    }

  /* Get list of gre-tunnel interfaces */
  M (GRE_TUNNEL_DUMP, mp);

  mp->sw_if_index = htonl (sw_if_index);

  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_l2_fib_clear_table (vat_main_t * vam)
{
//  unformat_input_t * i = vam->input;
  vl_api_l2_fib_clear_table_t *mp;
  int ret;

  M (L2_FIB_CLEAR_TABLE, mp);

  S (mp);
  W (ret);
  return ret;
}

static int
api_l2_interface_efp_filter (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_l2_interface_efp_filter_t *mp;
  u32 sw_if_index;
  u8 enable = 1;
  u8 sw_if_index_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "enable"))
	enable = 1;
      else if (unformat (i, "disable"))
	enable = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing sw_if_index");
      return -99;
    }

  M (L2_INTERFACE_EFP_FILTER, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable_disable = enable;

  S (mp);
  W (ret);
  return ret;
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

static int
api_l2_interface_vlan_tag_rewrite (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_l2_interface_vlan_tag_rewrite_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 vtr_op_set = 0;
  u32 vtr_op = 0;
  u32 push_dot1q = 1;
  u32 tag1 = ~0;
  u32 tag2 = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
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
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if ((sw_if_index_set == 0) || (vtr_op_set == 0))
    {
      errmsg ("missing vtr operation or sw_if_index");
      return -99;
    }

  M (L2_INTERFACE_VLAN_TAG_REWRITE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->vtr_op = ntohl (vtr_op);
  mp->push_dot1q = ntohl (push_dot1q);
  mp->tag1 = ntohl (tag1);
  mp->tag2 = ntohl (tag2);

  S (mp);
  W (ret);
  return ret;
}

static int
api_create_vhost_user_if (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_create_vhost_user_if_t *mp;
  u8 *file_name;
  u8 is_server = 0;
  u8 file_name_set = 0;
  u32 custom_dev_instance = ~0;
  u8 hwaddr[6];
  u8 use_custom_mac = 0;
  u8 disable_mrg_rxbuf = 0;
  u8 disable_indirect_desc = 0;
  u8 *tag = 0;
  int ret;

  /* Shut up coverity */
  clib_memset (hwaddr, 0, sizeof (hwaddr));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "socket %s", &file_name))
	{
	  file_name_set = 1;
	}
      else if (unformat (i, "renumber %" PRIu32, &custom_dev_instance))
	;
      else if (unformat (i, "mac %U", unformat_ethernet_address, hwaddr))
	use_custom_mac = 1;
      else if (unformat (i, "server"))
	is_server = 1;
      else if (unformat (i, "disable_mrg_rxbuf"))
	disable_mrg_rxbuf = 1;
      else if (unformat (i, "disable_indirect_desc"))
	disable_indirect_desc = 1;
      else if (unformat (i, "tag %s", &tag))
	;
      else
	break;
    }

  if (file_name_set == 0)
    {
      errmsg ("missing socket file name");
      return -99;
    }

  if (vec_len (file_name) > 255)
    {
      errmsg ("socket file name too long");
      return -99;
    }
  vec_add1 (file_name, 0);

  M (CREATE_VHOST_USER_IF, mp);

  mp->is_server = is_server;
  mp->disable_mrg_rxbuf = disable_mrg_rxbuf;
  mp->disable_indirect_desc = disable_indirect_desc;
  clib_memcpy (mp->sock_filename, file_name, vec_len (file_name));
  vec_free (file_name);
  if (custom_dev_instance != ~0)
    {
      mp->renumber = 1;
      mp->custom_dev_instance = ntohl (custom_dev_instance);
    }

  mp->use_custom_mac = use_custom_mac;
  clib_memcpy (mp->mac_address, hwaddr, 6);
  if (tag)
    strncpy ((char *) mp->tag, (char *) tag, ARRAY_LEN (mp->tag) - 1);
  vec_free (tag);

  S (mp);
  W (ret);
  return ret;
}

static int
api_modify_vhost_user_if (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_modify_vhost_user_if_t *mp;
  u8 *file_name;
  u8 is_server = 0;
  u8 file_name_set = 0;
  u32 custom_dev_instance = ~0;
  u8 sw_if_index_set = 0;
  u32 sw_if_index = (u32) ~ 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "socket %s", &file_name))
	{
	  file_name_set = 1;
	}
      else if (unformat (i, "renumber %" PRIu32, &custom_dev_instance))
	;
      else if (unformat (i, "server"))
	is_server = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing sw_if_index or interface name");
      return -99;
    }

  if (file_name_set == 0)
    {
      errmsg ("missing socket file name");
      return -99;
    }

  if (vec_len (file_name) > 255)
    {
      errmsg ("socket file name too long");
      return -99;
    }
  vec_add1 (file_name, 0);

  M (MODIFY_VHOST_USER_IF, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_server = is_server;
  clib_memcpy (mp->sock_filename, file_name, vec_len (file_name));
  vec_free (file_name);
  if (custom_dev_instance != ~0)
    {
      mp->renumber = 1;
      mp->custom_dev_instance = ntohl (custom_dev_instance);
    }

  S (mp);
  W (ret);
  return ret;
}

static int
api_delete_vhost_user_if (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_delete_vhost_user_if_t *mp;
  u32 sw_if_index = ~0;
  u8 sw_if_index_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing sw_if_index or interface name");
      return -99;
    }


  M (DELETE_VHOST_USER_IF, mp);

  mp->sw_if_index = ntohl (sw_if_index);

  S (mp);
  W (ret);
  return ret;
}

static void vl_api_sw_interface_vhost_user_details_t_handler
  (vl_api_sw_interface_vhost_user_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%-25s %3" PRIu32 " %6" PRIu32 " %8x %6d %7d %s",
	 (char *) mp->interface_name,
	 ntohl (mp->sw_if_index), ntohl (mp->virtio_net_hdr_sz),
	 clib_net_to_host_u64 (mp->features), mp->is_server,
	 ntohl (mp->num_regions), (char *) mp->sock_filename);
  print (vam->ofp, "    Status: '%s'", strerror (ntohl (mp->sock_errno)));
}

static void vl_api_sw_interface_vhost_user_details_t_handler_json
  (vl_api_sw_interface_vhost_user_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  vat_json_object_add_string_copy (node, "interface_name",
				   mp->interface_name);
  vat_json_object_add_uint (node, "virtio_net_hdr_sz",
			    ntohl (mp->virtio_net_hdr_sz));
  vat_json_object_add_uint (node, "features",
			    clib_net_to_host_u64 (mp->features));
  vat_json_object_add_uint (node, "is_server", mp->is_server);
  vat_json_object_add_string_copy (node, "sock_filename", mp->sock_filename);
  vat_json_object_add_uint (node, "num_regions", ntohl (mp->num_regions));
  vat_json_object_add_uint (node, "sock_errno", ntohl (mp->sock_errno));
}

static int
api_sw_interface_vhost_user_dump (vat_main_t * vam)
{
  vl_api_sw_interface_vhost_user_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;
  print (vam->ofp,
	 "Interface name            idx hdr_sz features server regions filename");

  /* Get list of vhost-user interfaces */
  M (SW_INTERFACE_VHOST_USER_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_show_version (vat_main_t * vam)
{
  vl_api_show_version_t *mp;
  int ret;

  M (SHOW_VERSION, mp);

  S (mp);
  W (ret);
  return ret;
}


static int
api_vxlan_gpe_add_del_tunnel (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_vxlan_gpe_add_del_tunnel_t *mp;
  ip4_address_t local4, remote4;
  ip6_address_t local6, remote6;
  u8 is_add = 1;
  u8 ipv4_set = 0, ipv6_set = 0;
  u8 local_set = 0;
  u8 remote_set = 0;
  u8 grp_set = 0;
  u32 mcast_sw_if_index = ~0;
  u32 encap_vrf_id = 0;
  u32 decap_vrf_id = 0;
  u8 protocol = ~0;
  u32 vni;
  u8 vni_set = 0;
  int ret;

  /* Can't "universally zero init" (={0}) due to GCC bug 53119 */
  clib_memset (&local4, 0, sizeof local4);
  clib_memset (&remote4, 0, sizeof remote4);
  clib_memset (&local6, 0, sizeof local6);
  clib_memset (&remote6, 0, sizeof remote6);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
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
      else if (unformat (line_input, "group %U %U",
			 unformat_ip4_address, &remote4,
			 api_unformat_sw_if_index, vam, &mcast_sw_if_index))
	{
	  grp_set = remote_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "group %U",
			 unformat_ip4_address, &remote4))
	{
	  grp_set = remote_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "group %U %U",
			 unformat_ip6_address, &remote6,
			 api_unformat_sw_if_index, vam, &mcast_sw_if_index))
	{
	  grp_set = remote_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "group %U",
			 unformat_ip6_address, &remote6))
	{
	  grp_set = remote_set = 1;
	  ipv6_set = 1;
	}
      else
	if (unformat (line_input, "mcast_sw_if_index %u", &mcast_sw_if_index))
	;
      else if (unformat (line_input, "encap-vrf-id %d", &encap_vrf_id))
	;
      else if (unformat (line_input, "decap-vrf-id %d", &decap_vrf_id))
	;
      else if (unformat (line_input, "vni %d", &vni))
	vni_set = 1;
      else if (unformat (line_input, "next-ip4"))
	protocol = 1;
      else if (unformat (line_input, "next-ip6"))
	protocol = 2;
      else if (unformat (line_input, "next-ethernet"))
	protocol = 3;
      else if (unformat (line_input, "next-nsh"))
	protocol = 4;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, line_input);
	  return -99;
	}
    }

  if (local_set == 0)
    {
      errmsg ("tunnel local address not specified");
      return -99;
    }
  if (remote_set == 0)
    {
      errmsg ("tunnel remote address not specified");
      return -99;
    }
  if (grp_set && mcast_sw_if_index == ~0)
    {
      errmsg ("tunnel nonexistent multicast device");
      return -99;
    }
  if (ipv4_set && ipv6_set)
    {
      errmsg ("both IPv4 and IPv6 addresses specified");
      return -99;
    }

  if (vni_set == 0)
    {
      errmsg ("vni not specified");
      return -99;
    }

  M (VXLAN_GPE_ADD_DEL_TUNNEL, mp);


  if (ipv6_set)
    {
      clib_memcpy (&mp->local, &local6, sizeof (local6));
      clib_memcpy (&mp->remote, &remote6, sizeof (remote6));
    }
  else
    {
      clib_memcpy (&mp->local, &local4, sizeof (local4));
      clib_memcpy (&mp->remote, &remote4, sizeof (remote4));
    }

  mp->mcast_sw_if_index = ntohl (mcast_sw_if_index);
  mp->encap_vrf_id = ntohl (encap_vrf_id);
  mp->decap_vrf_id = ntohl (decap_vrf_id);
  mp->protocol = protocol;
  mp->vni = ntohl (vni);
  mp->is_add = is_add;
  mp->is_ipv6 = ipv6_set;

  S (mp);
  W (ret);
  return ret;
}

static void vl_api_vxlan_gpe_tunnel_details_t_handler
  (vl_api_vxlan_gpe_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  ip46_address_t local = to_ip46 (mp->is_ipv6, mp->local);
  ip46_address_t remote = to_ip46 (mp->is_ipv6, mp->remote);

  print (vam->ofp, "%11d%24U%24U%13d%12d%19d%14d%14d",
	 ntohl (mp->sw_if_index),
	 format_ip46_address, &local, IP46_TYPE_ANY,
	 format_ip46_address, &remote, IP46_TYPE_ANY,
	 ntohl (mp->vni), mp->protocol,
	 ntohl (mp->mcast_sw_if_index),
	 ntohl (mp->encap_vrf_id), ntohl (mp->decap_vrf_id));
}


static void vl_api_vxlan_gpe_tunnel_details_t_handler_json
  (vl_api_vxlan_gpe_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;
  struct in_addr ip4;
  struct in6_addr ip6;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  if (mp->is_ipv6)
    {
      clib_memcpy (&ip6, &(mp->local[0]), sizeof (ip6));
      vat_json_object_add_ip6 (node, "local", ip6);
      clib_memcpy (&ip6, &(mp->remote[0]), sizeof (ip6));
      vat_json_object_add_ip6 (node, "remote", ip6);
    }
  else
    {
      clib_memcpy (&ip4, &(mp->local[0]), sizeof (ip4));
      vat_json_object_add_ip4 (node, "local", ip4);
      clib_memcpy (&ip4, &(mp->remote[0]), sizeof (ip4));
      vat_json_object_add_ip4 (node, "remote", ip4);
    }
  vat_json_object_add_uint (node, "vni", ntohl (mp->vni));
  vat_json_object_add_uint (node, "protocol", ntohl (mp->protocol));
  vat_json_object_add_uint (node, "mcast_sw_if_index",
			    ntohl (mp->mcast_sw_if_index));
  vat_json_object_add_uint (node, "encap_vrf_id", ntohl (mp->encap_vrf_id));
  vat_json_object_add_uint (node, "decap_vrf_id", ntohl (mp->decap_vrf_id));
  vat_json_object_add_uint (node, "is_ipv6", mp->is_ipv6 ? 1 : 0);
}

static int
api_vxlan_gpe_tunnel_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_vxlan_gpe_tunnel_dump_t *mp;
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
      print (vam->ofp, "%11s%24s%24s%13s%15s%19s%14s%14s",
	     "sw_if_index", "local", "remote", "vni",
	     "protocol", "mcast_sw_if_index", "encap_vrf_id", "decap_vrf_id");
    }

  /* Get list of vxlan-tunnel interfaces */
  M (VXLAN_GPE_TUNNEL_DUMP, mp);

  mp->sw_if_index = htonl (sw_if_index);

  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void vl_api_l2_fib_table_details_t_handler
  (vl_api_l2_fib_table_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%3" PRIu32 "    %U    %3" PRIu32
	 "       %d       %d     %d",
	 ntohl (mp->bd_id), format_ethernet_address, mp->mac,
	 ntohl (mp->sw_if_index), mp->static_mac, mp->filter_mac,
	 mp->bvi_mac);
}

static void vl_api_l2_fib_table_details_t_handler_json
  (vl_api_l2_fib_table_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "bd_id", ntohl (mp->bd_id));
  vat_json_object_add_bytes (node, "mac", mp->mac, 6);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  vat_json_object_add_uint (node, "static_mac", mp->static_mac);
  vat_json_object_add_uint (node, "filter_mac", mp->filter_mac);
  vat_json_object_add_uint (node, "bvi_mac", mp->bvi_mac);
}

static int
api_l2_fib_table_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_l2_fib_table_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 bd_id;
  u8 bd_id_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id))
	bd_id_set = 1;
      else
	break;
    }

  if (bd_id_set == 0)
    {
      errmsg ("missing bridge domain");
      return -99;
    }

  print (vam->ofp, "BD-ID     Mac Address      sw-ndx  Static  Filter  BVI");

  /* Get list of l2 fib entries */
  M (L2_FIB_TABLE_DUMP, mp);

  mp->bd_id = ntohl (bd_id);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}


static int
api_interface_name_renumber (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_interface_name_renumber_t *mp;
  u32 sw_if_index = ~0;
  u32 new_show_dev_instance = ~0;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", api_unformat_sw_if_index, vam,
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

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (new_show_dev_instance == ~0)
    {
      errmsg ("missing new_show_dev_instance");
      return -99;
    }

  M (INTERFACE_NAME_RENUMBER, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->new_show_dev_instance = ntohl (new_show_dev_instance);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ip_probe_neighbor (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_probe_neighbor_t *mp;
  u8 int_set = 0;
  u8 adr_set = 0;
  u8 is_ipv6 = 0;
  u8 dst_adr[16];
  u32 sw_if_index;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	int_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	int_set = 1;
      else if (unformat (i, "address %U", unformat_ip4_address, dst_adr))
	adr_set = 1;
      else if (unformat (i, "address %U", unformat_ip6_address, dst_adr))
	{
	  adr_set = 1;
	  is_ipv6 = 1;
	}
      else
	break;
    }

  if (int_set == 0)
    {
      errmsg ("missing interface");
      return -99;
    }

  if (adr_set == 0)
    {
      errmsg ("missing addresses");
      return -99;
    }

  M (IP_PROBE_NEIGHBOR, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_ipv6 = is_ipv6;
  clib_memcpy (mp->dst_address, dst_adr, sizeof (dst_adr));

  S (mp);
  W (ret);
  return ret;
}

static int
api_ip_scan_neighbor_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_scan_neighbor_enable_disable_t *mp;
  u8 mode = IP_SCAN_V46_NEIGHBORS;
  u32 interval = 0, time = 0, update = 0, delay = 0, stale = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "ip4"))
	mode = IP_SCAN_V4_NEIGHBORS;
      else if (unformat (i, "ip6"))
	mode = IP_SCAN_V6_NEIGHBORS;
      if (unformat (i, "both"))
	mode = IP_SCAN_V46_NEIGHBORS;
      else if (unformat (i, "disable"))
	mode = IP_SCAN_DISABLED;
      else if (unformat (i, "interval %d", &interval))
	;
      else if (unformat (i, "max-time %d", &time))
	;
      else if (unformat (i, "max-update %d", &update))
	;
      else if (unformat (i, "delay %d", &delay))
	;
      else if (unformat (i, "stale %d", &stale))
	;
      else
	break;
    }

  if (interval > 255)
    {
      errmsg ("interval cannot exceed 255 minutes.");
      return -99;
    }
  if (time > 255)
    {
      errmsg ("max-time cannot exceed 255 usec.");
      return -99;
    }
  if (update > 255)
    {
      errmsg ("max-update cannot exceed 255.");
      return -99;
    }
  if (delay > 255)
    {
      errmsg ("delay cannot exceed 255 msec.");
      return -99;
    }
  if (stale > 255)
    {
      errmsg ("stale cannot exceed 255 minutes.");
      return -99;
    }

  M (IP_SCAN_NEIGHBOR_ENABLE_DISABLE, mp);
  mp->mode = mode;
  mp->scan_interval = interval;
  mp->max_proc_time = time;
  mp->max_update = update;
  mp->scan_int_delay = delay;
  mp->stale_threshold = stale;

  S (mp);
  W (ret);
  return ret;
}

static int
api_want_ip4_arp_events (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_want_ip4_arp_events_t *mp;
  ip4_address_t address;
  int address_set = 0;
  u32 enable_disable = 1;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "address %U", unformat_ip4_address, &address))
	address_set = 1;
      else if (unformat (line_input, "del"))
	enable_disable = 0;
      else
	break;
    }

  if (address_set == 0)
    {
      errmsg ("missing addresses");
      return -99;
    }

  M (WANT_IP4_ARP_EVENTS, mp);
  mp->enable_disable = enable_disable;
  mp->pid = htonl (getpid ());
  mp->address = address.as_u32;

  S (mp);
  W (ret);
  return ret;
}

static int
api_want_ip6_nd_events (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_want_ip6_nd_events_t *mp;
  ip6_address_t address;
  int address_set = 0;
  u32 enable_disable = 1;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "address %U", unformat_ip6_address, &address))
	address_set = 1;
      else if (unformat (line_input, "del"))
	enable_disable = 0;
      else
	break;
    }

  if (address_set == 0)
    {
      errmsg ("missing addresses");
      return -99;
    }

  M (WANT_IP6_ND_EVENTS, mp);
  mp->enable_disable = enable_disable;
  mp->pid = htonl (getpid ());
  clib_memcpy (mp->address, &address, sizeof (ip6_address_t));

  S (mp);
  W (ret);
  return ret;
}

static int
api_want_l2_macs_events (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_want_l2_macs_events_t *mp;
  u8 enable_disable = 1;
  u32 scan_delay = 0;
  u32 max_macs_in_event = 0;
  u32 learn_limit = 0;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "learn-limit %d", &learn_limit))
	;
      else if (unformat (line_input, "scan-delay %d", &scan_delay))
	;
      else if (unformat (line_input, "max-entries %d", &max_macs_in_event))
	;
      else if (unformat (line_input, "disable"))
	enable_disable = 0;
      else
	break;
    }

  M (WANT_L2_MACS_EVENTS, mp);
  mp->enable_disable = enable_disable;
  mp->pid = htonl (getpid ());
  mp->learn_limit = htonl (learn_limit);
  mp->scan_delay = (u8) scan_delay;
  mp->max_macs_in_event = (u8) (max_macs_in_event / 10);
  S (mp);
  W (ret);
  return ret;
}

static int
api_input_acl_set_interface (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_input_acl_set_interface_t *mp;
  u32 sw_if_index;
  int sw_if_index_set;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  u32 l2_table_index = ~0;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
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

  M (INPUT_ACL_SET_INTERFACE, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->ip4_table_index = ntohl (ip4_table_index);
  mp->ip6_table_index = ntohl (ip6_table_index);
  mp->l2_table_index = ntohl (l2_table_index);
  mp->is_add = is_add;

  S (mp);
  W (ret);
  return ret;
}

static int
api_output_acl_set_interface (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_output_acl_set_interface_t *mp;
  u32 sw_if_index;
  int sw_if_index_set;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  u32 l2_table_index = ~0;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
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

  M (OUTPUT_ACL_SET_INTERFACE, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->ip4_table_index = ntohl (ip4_table_index);
  mp->ip6_table_index = ntohl (ip6_table_index);
  mp->l2_table_index = ntohl (l2_table_index);
  mp->is_add = is_add;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ip_address_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_address_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 sw_if_index = ~0;
  u8 sw_if_index_set = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "ipv4"))
	ipv4_set = 1;
      else if (unformat (i, "ipv6"))
	ipv6_set = 1;
      else
	break;
    }

  if (ipv4_set && ipv6_set)
    {
      errmsg ("ipv4 and ipv6 flags cannot be both set");
      return -99;
    }

  if ((!ipv4_set) && (!ipv6_set))
    {
      errmsg ("no ipv4 nor ipv6 flag set");
      return -99;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  vam->current_sw_if_index = sw_if_index;
  vam->is_ipv6 = ipv6_set;

  M (IP_ADDRESS_DUMP, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_ipv6 = ipv6_set;
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_ip_dump (vat_main_t * vam)
{
  vl_api_ip_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  unformat_input_t *in = vam->input;
  int ipv4_set = 0;
  int ipv6_set = 0;
  int is_ipv6;
  int i;
  int ret;

  while (unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (in, "ipv4"))
	ipv4_set = 1;
      else if (unformat (in, "ipv6"))
	ipv6_set = 1;
      else
	break;
    }

  if (ipv4_set && ipv6_set)
    {
      errmsg ("ipv4 and ipv6 flags cannot be both set");
      return -99;
    }

  if ((!ipv4_set) && (!ipv6_set))
    {
      errmsg ("no ipv4 nor ipv6 flag set");
      return -99;
    }

  is_ipv6 = ipv6_set;
  vam->is_ipv6 = is_ipv6;

  /* free old data */
  for (i = 0; i < vec_len (vam->ip_details_by_sw_if_index[is_ipv6]); i++)
    {
      vec_free (vam->ip_details_by_sw_if_index[is_ipv6][i].addr);
    }
  vec_free (vam->ip_details_by_sw_if_index[is_ipv6]);

  M (IP_DUMP, mp);
  mp->is_ipv6 = ipv6_set;
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_ipsec_spd_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_spd_add_del_t *mp;
  u32 spd_id = ~0;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "spd_id %d", &spd_id))
	;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }
  if (spd_id == ~0)
    {
      errmsg ("spd_id must be set");
      return -99;
    }

  M (IPSEC_SPD_ADD_DEL, mp);

  mp->spd_id = ntohl (spd_id);
  mp->is_add = is_add;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ipsec_interface_add_del_spd (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_interface_add_del_spd_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u32 spd_id = (u32) ~ 0;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "spd_id %d", &spd_id))
	;
      else
	if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}

    }

  if (spd_id == (u32) ~ 0)
    {
      errmsg ("spd_id must be set");
      return -99;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (IPSEC_INTERFACE_ADD_DEL_SPD, mp);

  mp->spd_id = ntohl (spd_id);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_add = is_add;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ipsec_spd_add_del_entry (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_spd_add_del_entry_t *mp;
  u8 is_add = 1, is_outbound = 0, is_ipv6 = 0, is_ip_any = 1;
  u32 spd_id = 0, sa_id = 0, protocol = 0, policy = 0;
  i32 priority = 0;
  u32 rport_start = 0, rport_stop = (u32) ~ 0;
  u32 lport_start = 0, lport_stop = (u32) ~ 0;
  ip4_address_t laddr4_start, laddr4_stop, raddr4_start, raddr4_stop;
  ip6_address_t laddr6_start, laddr6_stop, raddr6_start, raddr6_stop;
  int ret;

  laddr4_start.as_u32 = raddr4_start.as_u32 = 0;
  laddr4_stop.as_u32 = raddr4_stop.as_u32 = (u32) ~ 0;
  laddr6_start.as_u64[0] = raddr6_start.as_u64[0] = 0;
  laddr6_start.as_u64[1] = raddr6_start.as_u64[1] = 0;
  laddr6_stop.as_u64[0] = raddr6_stop.as_u64[0] = (u64) ~ 0;
  laddr6_stop.as_u64[1] = raddr6_stop.as_u64[1] = (u64) ~ 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
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
      else
	if (unformat
	    (i, "laddr_start %U", unformat_ip4_address, &laddr4_start))
	{
	  is_ipv6 = 0;
	  is_ip_any = 0;
	}
      else
	if (unformat (i, "laddr_stop %U", unformat_ip4_address, &laddr4_stop))
	{
	  is_ipv6 = 0;
	  is_ip_any = 0;
	}
      else
	if (unformat
	    (i, "raddr_start %U", unformat_ip4_address, &raddr4_start))
	{
	  is_ipv6 = 0;
	  is_ip_any = 0;
	}
      else
	if (unformat (i, "raddr_stop %U", unformat_ip4_address, &raddr4_stop))
	{
	  is_ipv6 = 0;
	  is_ip_any = 0;
	}
      else
	if (unformat
	    (i, "laddr_start %U", unformat_ip6_address, &laddr6_start))
	{
	  is_ipv6 = 1;
	  is_ip_any = 0;
	}
      else
	if (unformat (i, "laddr_stop %U", unformat_ip6_address, &laddr6_stop))
	{
	  is_ipv6 = 1;
	  is_ip_any = 0;
	}
      else
	if (unformat
	    (i, "raddr_start %U", unformat_ip6_address, &raddr6_start))
	{
	  is_ipv6 = 1;
	  is_ip_any = 0;
	}
      else
	if (unformat (i, "raddr_stop %U", unformat_ip6_address, &raddr6_stop))
	{
	  is_ipv6 = 1;
	  is_ip_any = 0;
	}
      else
	if (unformat (i, "action %U", unformat_ipsec_policy_action, &policy))
	{
	  if (policy == IPSEC_POLICY_ACTION_RESOLVE)
	    {
	      clib_warning ("unsupported action: 'resolve'");
	      return -99;
	    }
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}

    }

  M (IPSEC_SPD_ADD_DEL_ENTRY, mp);

  mp->spd_id = ntohl (spd_id);
  mp->priority = ntohl (priority);
  mp->is_outbound = is_outbound;

  mp->is_ipv6 = is_ipv6;
  if (is_ipv6 || is_ip_any)
    {
      clib_memcpy (mp->remote_address_start, &raddr6_start,
		   sizeof (ip6_address_t));
      clib_memcpy (mp->remote_address_stop, &raddr6_stop,
		   sizeof (ip6_address_t));
      clib_memcpy (mp->local_address_start, &laddr6_start,
		   sizeof (ip6_address_t));
      clib_memcpy (mp->local_address_stop, &laddr6_stop,
		   sizeof (ip6_address_t));
    }
  else
    {
      clib_memcpy (mp->remote_address_start, &raddr4_start,
		   sizeof (ip4_address_t));
      clib_memcpy (mp->remote_address_stop, &raddr4_stop,
		   sizeof (ip4_address_t));
      clib_memcpy (mp->local_address_start, &laddr4_start,
		   sizeof (ip4_address_t));
      clib_memcpy (mp->local_address_stop, &laddr4_stop,
		   sizeof (ip4_address_t));
    }
  mp->protocol = (u8) protocol;
  mp->local_port_start = ntohs ((u16) lport_start);
  mp->local_port_stop = ntohs ((u16) lport_stop);
  mp->remote_port_start = ntohs ((u16) rport_start);
  mp->remote_port_stop = ntohs ((u16) rport_stop);
  mp->policy = (u8) policy;
  mp->sa_id = ntohl (sa_id);
  mp->is_add = is_add;
  mp->is_ip_any = is_ip_any;
  S (mp);
  W (ret);
  return ret;
}

static int
api_ipsec_sad_add_del_entry (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_sad_add_del_entry_t *mp;
  u32 sad_id = 0, spi = 0;
  u8 *ck = 0, *ik = 0;
  u8 is_add = 1;

  u8 protocol = IPSEC_PROTOCOL_AH;
  u8 is_tunnel = 0, is_tunnel_ipv6 = 0;
  u32 crypto_alg = 0, integ_alg = 0;
  ip4_address_t tun_src4;
  ip4_address_t tun_dst4;
  ip6_address_t tun_src6;
  ip6_address_t tun_dst6;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "sad_id %d", &sad_id))
	;
      else if (unformat (i, "spi %d", &spi))
	;
      else if (unformat (i, "esp"))
	protocol = IPSEC_PROTOCOL_ESP;
      else if (unformat (i, "tunnel_src %U", unformat_ip4_address, &tun_src4))
	{
	  is_tunnel = 1;
	  is_tunnel_ipv6 = 0;
	}
      else if (unformat (i, "tunnel_dst %U", unformat_ip4_address, &tun_dst4))
	{
	  is_tunnel = 1;
	  is_tunnel_ipv6 = 0;
	}
      else if (unformat (i, "tunnel_src %U", unformat_ip6_address, &tun_src6))
	{
	  is_tunnel = 1;
	  is_tunnel_ipv6 = 1;
	}
      else if (unformat (i, "tunnel_dst %U", unformat_ip6_address, &tun_dst6))
	{
	  is_tunnel = 1;
	  is_tunnel_ipv6 = 1;
	}
      else
	if (unformat
	    (i, "crypto_alg %U", unformat_ipsec_crypto_alg, &crypto_alg))
	{
	  if (crypto_alg >= IPSEC_CRYPTO_N_ALG)
	    {
	      clib_warning ("unsupported crypto-alg: '%U'",
			    format_ipsec_crypto_alg, crypto_alg);
	      return -99;
	    }
	}
      else if (unformat (i, "crypto_key %U", unformat_hex_string, &ck))
	;
      else
	if (unformat
	    (i, "integ_alg %U", unformat_ipsec_integ_alg, &integ_alg))
	{
	  if (integ_alg >= IPSEC_INTEG_N_ALG)
	    {
	      clib_warning ("unsupported integ-alg: '%U'",
			    format_ipsec_integ_alg, integ_alg);
	      return -99;
	    }
	}
      else if (unformat (i, "integ_key %U", unformat_hex_string, &ik))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}

    }

  M (IPSEC_SAD_ADD_DEL_ENTRY, mp);

  mp->sad_id = ntohl (sad_id);
  mp->is_add = is_add;
  mp->protocol = protocol;
  mp->spi = ntohl (spi);
  mp->is_tunnel = is_tunnel;
  mp->is_tunnel_ipv6 = is_tunnel_ipv6;
  mp->crypto_algorithm = crypto_alg;
  mp->integrity_algorithm = integ_alg;
  mp->crypto_key_length = vec_len (ck);
  mp->integrity_key_length = vec_len (ik);

  if (mp->crypto_key_length > sizeof (mp->crypto_key))
    mp->crypto_key_length = sizeof (mp->crypto_key);

  if (mp->integrity_key_length > sizeof (mp->integrity_key))
    mp->integrity_key_length = sizeof (mp->integrity_key);

  if (ck)
    clib_memcpy (mp->crypto_key, ck, mp->crypto_key_length);
  if (ik)
    clib_memcpy (mp->integrity_key, ik, mp->integrity_key_length);

  if (is_tunnel)
    {
      if (is_tunnel_ipv6)
	{
	  clib_memcpy (mp->tunnel_src_address, &tun_src6,
		       sizeof (ip6_address_t));
	  clib_memcpy (mp->tunnel_dst_address, &tun_dst6,
		       sizeof (ip6_address_t));
	}
      else
	{
	  clib_memcpy (mp->tunnel_src_address, &tun_src4,
		       sizeof (ip4_address_t));
	  clib_memcpy (mp->tunnel_dst_address, &tun_dst4,
		       sizeof (ip4_address_t));
	}
    }

  S (mp);
  W (ret);
  return ret;
}

static int
api_ipsec_sa_set_key (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_sa_set_key_t *mp;
  u32 sa_id;
  u8 *ck = 0, *ik = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sa_id %d", &sa_id))
	;
      else if (unformat (i, "crypto_key %U", unformat_hex_string, &ck))
	;
      else if (unformat (i, "integ_key %U", unformat_hex_string, &ik))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IPSEC_SA_SET_KEY, mp);

  mp->sa_id = ntohl (sa_id);
  mp->crypto_key_length = vec_len (ck);
  mp->integrity_key_length = vec_len (ik);

  if (mp->crypto_key_length > sizeof (mp->crypto_key))
    mp->crypto_key_length = sizeof (mp->crypto_key);

  if (mp->integrity_key_length > sizeof (mp->integrity_key))
    mp->integrity_key_length = sizeof (mp->integrity_key);

  if (ck)
    clib_memcpy (mp->crypto_key, ck, mp->crypto_key_length);
  if (ik)
    clib_memcpy (mp->integrity_key, ik, mp->integrity_key_length);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ipsec_tunnel_if_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_tunnel_if_add_del_t *mp;
  u32 local_spi = 0, remote_spi = 0;
  u32 crypto_alg = 0, integ_alg = 0;
  u8 *lck = NULL, *rck = NULL;
  u8 *lik = NULL, *rik = NULL;
  ip4_address_t local_ip = { {0} };
  ip4_address_t remote_ip = { {0} };
  u8 is_add = 1;
  u8 esn = 0;
  u8 anti_replay = 0;
  u8 renumber = 0;
  u32 instance = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "esn"))
	esn = 1;
      else if (unformat (i, "anti_replay"))
	anti_replay = 1;
      else if (unformat (i, "local_spi %d", &local_spi))
	;
      else if (unformat (i, "remote_spi %d", &remote_spi))
	;
      else if (unformat (i, "local_ip %U", unformat_ip4_address, &local_ip))
	;
      else if (unformat (i, "remote_ip %U", unformat_ip4_address, &remote_ip))
	;
      else if (unformat (i, "local_crypto_key %U", unformat_hex_string, &lck))
	;
      else
	if (unformat (i, "remote_crypto_key %U", unformat_hex_string, &rck))
	;
      else if (unformat (i, "local_integ_key %U", unformat_hex_string, &lik))
	;
      else if (unformat (i, "remote_integ_key %U", unformat_hex_string, &rik))
	;
      else
	if (unformat
	    (i, "crypto_alg %U", unformat_ipsec_crypto_alg, &crypto_alg))
	{
	  if (crypto_alg >= IPSEC_CRYPTO_N_ALG)
	    {
	      errmsg ("unsupported crypto-alg: '%U'\n",
		      format_ipsec_crypto_alg, crypto_alg);
	      return -99;
	    }
	}
      else
	if (unformat
	    (i, "integ_alg %U", unformat_ipsec_integ_alg, &integ_alg))
	{
	  if (integ_alg >= IPSEC_INTEG_N_ALG)
	    {
	      errmsg ("unsupported integ-alg: '%U'\n",
		      format_ipsec_integ_alg, integ_alg);
	      return -99;
	    }
	}
      else if (unformat (i, "instance %u", &instance))
	renumber = 1;
      else
	{
	  errmsg ("parse error '%U'\n", format_unformat_error, i);
	  return -99;
	}
    }

  M (IPSEC_TUNNEL_IF_ADD_DEL, mp);

  mp->is_add = is_add;
  mp->esn = esn;
  mp->anti_replay = anti_replay;

  clib_memcpy (mp->local_ip, &local_ip, sizeof (ip4_address_t));
  clib_memcpy (mp->remote_ip, &remote_ip, sizeof (ip4_address_t));

  mp->local_spi = htonl (local_spi);
  mp->remote_spi = htonl (remote_spi);
  mp->crypto_alg = (u8) crypto_alg;

  mp->local_crypto_key_len = 0;
  if (lck)
    {
      mp->local_crypto_key_len = vec_len (lck);
      if (mp->local_crypto_key_len > sizeof (mp->local_crypto_key))
	mp->local_crypto_key_len = sizeof (mp->local_crypto_key);
      clib_memcpy (mp->local_crypto_key, lck, mp->local_crypto_key_len);
    }

  mp->remote_crypto_key_len = 0;
  if (rck)
    {
      mp->remote_crypto_key_len = vec_len (rck);
      if (mp->remote_crypto_key_len > sizeof (mp->remote_crypto_key))
	mp->remote_crypto_key_len = sizeof (mp->remote_crypto_key);
      clib_memcpy (mp->remote_crypto_key, rck, mp->remote_crypto_key_len);
    }

  mp->integ_alg = (u8) integ_alg;

  mp->local_integ_key_len = 0;
  if (lik)
    {
      mp->local_integ_key_len = vec_len (lik);
      if (mp->local_integ_key_len > sizeof (mp->local_integ_key))
	mp->local_integ_key_len = sizeof (mp->local_integ_key);
      clib_memcpy (mp->local_integ_key, lik, mp->local_integ_key_len);
    }

  mp->remote_integ_key_len = 0;
  if (rik)
    {
      mp->remote_integ_key_len = vec_len (rik);
      if (mp->remote_integ_key_len > sizeof (mp->remote_integ_key))
	mp->remote_integ_key_len = sizeof (mp->remote_integ_key);
      clib_memcpy (mp->remote_integ_key, rik, mp->remote_integ_key_len);
    }

  if (renumber)
    {
      mp->renumber = renumber;
      mp->show_instance = ntohl (instance);
    }

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_ipsec_sa_details_t_handler (vl_api_ipsec_sa_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "sa_id %u sw_if_index %u spi %u proto %u crypto_alg %u "
	 "crypto_key %U integ_alg %u integ_key %U use_esn %u "
	 "use_anti_replay %u is_tunnel %u is_tunnel_ip6 %u "
	 "tunnel_src_addr %U tunnel_dst_addr %U "
	 "salt %u seq_outbound %lu last_seq_inbound %lu "
	 "replay_window %lu total_data_size %lu\n",
	 ntohl (mp->sa_id), ntohl (mp->sw_if_index), ntohl (mp->spi),
	 mp->protocol,
	 mp->crypto_alg, format_hex_bytes, mp->crypto_key, mp->crypto_key_len,
	 mp->integ_alg, format_hex_bytes, mp->integ_key, mp->integ_key_len,
	 mp->use_esn, mp->use_anti_replay, mp->is_tunnel, mp->is_tunnel_ip6,
	 (mp->is_tunnel_ip6) ? format_ip6_address : format_ip4_address,
	 mp->tunnel_src_addr,
	 (mp->is_tunnel_ip6) ? format_ip6_address : format_ip4_address,
	 mp->tunnel_dst_addr,
	 ntohl (mp->salt),
	 clib_net_to_host_u64 (mp->seq_outbound),
	 clib_net_to_host_u64 (mp->last_seq_inbound),
	 clib_net_to_host_u64 (mp->replay_window),
	 clib_net_to_host_u64 (mp->total_data_size));
}

#define vl_api_ipsec_sa_details_t_endian vl_noop_handler
#define vl_api_ipsec_sa_details_t_print vl_noop_handler

static void vl_api_ipsec_sa_details_t_handler_json
  (vl_api_ipsec_sa_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;
  struct in_addr src_ip4, dst_ip4;
  struct in6_addr src_ip6, dst_ip6;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sa_id", ntohl (mp->sa_id));
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  vat_json_object_add_uint (node, "spi", ntohl (mp->spi));
  vat_json_object_add_uint (node, "proto", mp->protocol);
  vat_json_object_add_uint (node, "crypto_alg", mp->crypto_alg);
  vat_json_object_add_uint (node, "integ_alg", mp->integ_alg);
  vat_json_object_add_uint (node, "use_esn", mp->use_esn);
  vat_json_object_add_uint (node, "use_anti_replay", mp->use_anti_replay);
  vat_json_object_add_uint (node, "is_tunnel", mp->is_tunnel);
  vat_json_object_add_uint (node, "is_tunnel_ip6", mp->is_tunnel_ip6);
  vat_json_object_add_bytes (node, "crypto_key", mp->crypto_key,
			     mp->crypto_key_len);
  vat_json_object_add_bytes (node, "integ_key", mp->integ_key,
			     mp->integ_key_len);
  if (mp->is_tunnel_ip6)
    {
      clib_memcpy (&src_ip6, mp->tunnel_src_addr, sizeof (src_ip6));
      vat_json_object_add_ip6 (node, "tunnel_src_addr", src_ip6);
      clib_memcpy (&dst_ip6, mp->tunnel_dst_addr, sizeof (dst_ip6));
      vat_json_object_add_ip6 (node, "tunnel_dst_addr", dst_ip6);
    }
  else
    {
      clib_memcpy (&src_ip4, mp->tunnel_src_addr, sizeof (src_ip4));
      vat_json_object_add_ip4 (node, "tunnel_src_addr", src_ip4);
      clib_memcpy (&dst_ip4, mp->tunnel_dst_addr, sizeof (dst_ip4));
      vat_json_object_add_ip4 (node, "tunnel_dst_addr", dst_ip4);
    }
  vat_json_object_add_uint (node, "replay_window",
			    clib_net_to_host_u64 (mp->replay_window));
  vat_json_object_add_uint (node, "total_data_size",
			    clib_net_to_host_u64 (mp->total_data_size));

}

static int
api_ipsec_sa_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_sa_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 sa_id = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sa_id %d", &sa_id))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IPSEC_SA_DUMP, mp);

  mp->sa_id = ntohl (sa_id);

  S (mp);

  /* Use a control ping for synchronization */
  M (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_ipsec_tunnel_if_set_key (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_tunnel_if_set_key_t *mp;
  u32 sw_if_index = ~0;
  u8 key_type = IPSEC_IF_SET_KEY_TYPE_NONE;
  u8 *key = 0;
  u32 alg = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else
	if (unformat (i, "local crypto %U", unformat_ipsec_crypto_alg, &alg))
	key_type = IPSEC_IF_SET_KEY_TYPE_LOCAL_CRYPTO;
      else
	if (unformat (i, "remote crypto %U", unformat_ipsec_crypto_alg, &alg))
	key_type = IPSEC_IF_SET_KEY_TYPE_REMOTE_CRYPTO;
      else if (unformat (i, "local integ %U", unformat_ipsec_integ_alg, &alg))
	key_type = IPSEC_IF_SET_KEY_TYPE_LOCAL_INTEG;
      else
	if (unformat (i, "remote integ %U", unformat_ipsec_integ_alg, &alg))
	key_type = IPSEC_IF_SET_KEY_TYPE_REMOTE_INTEG;
      else if (unformat (i, "%U", unformat_hex_string, &key))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (sw_if_index == ~0)
    {
      errmsg ("interface must be specified");
      return -99;
    }

  if (key_type == IPSEC_IF_SET_KEY_TYPE_NONE)
    {
      errmsg ("key type must be specified");
      return -99;
    }

  if (alg == ~0)
    {
      errmsg ("algorithm must be specified");
      return -99;
    }

  if (vec_len (key) == 0)
    {
      errmsg ("key must be specified");
      return -99;
    }

  M (IPSEC_TUNNEL_IF_SET_KEY, mp);

  mp->sw_if_index = htonl (sw_if_index);
  mp->alg = alg;
  mp->key_type = key_type;
  mp->key_len = vec_len (key);
  clib_memcpy (mp->key, key, vec_len (key));

  S (mp);
  W (ret);

  return ret;
}

static int
api_ipsec_tunnel_if_set_sa (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_tunnel_if_set_sa_t *mp;
  u32 sw_if_index = ~0;
  u32 sa_id = ~0;
  u8 is_outbound = (u8) ~ 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sa_id %d", &sa_id))
	;
      else if (unformat (i, "outbound"))
	is_outbound = 1;
      else if (unformat (i, "inbound"))
	is_outbound = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (sw_if_index == ~0)
    {
      errmsg ("interface must be specified");
      return -99;
    }

  if (sa_id == ~0)
    {
      errmsg ("SA ID must be specified");
      return -99;
    }

  M (IPSEC_TUNNEL_IF_SET_SA, mp);

  mp->sw_if_index = htonl (sw_if_index);
  mp->sa_id = htonl (sa_id);
  mp->is_outbound = is_outbound;

  S (mp);
  W (ret);

  return ret;
}

static int
api_ikev2_profile_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_profile_add_del_t *mp;
  u8 is_add = 1;
  u8 *name = 0;
  int ret;

  const char *valid_chars = "a-zA-Z0-9_";

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "name %U", unformat_token, valid_chars, &name))
	vec_add1 (name, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_PROFILE_ADD_DEL, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  mp->is_add = is_add;
  vec_free (name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_profile_set_auth (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_profile_set_auth_t *mp;
  u8 *name = 0;
  u8 *data = 0;
  u32 auth_method = 0;
  u8 is_hex = 0;
  int ret;

  const char *valid_chars = "a-zA-Z0-9_";

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "name %U", unformat_token, valid_chars, &name))
	vec_add1 (name, 0);
      else if (unformat (i, "auth_method %U",
			 unformat_ikev2_auth_method, &auth_method))
	;
      else if (unformat (i, "auth_data 0x%U", unformat_hex_string, &data))
	is_hex = 1;
      else if (unformat (i, "auth_data %v", &data))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  if (!vec_len (data))
    {
      errmsg ("auth_data must be specified");
      return -99;
    }

  if (!auth_method)
    {
      errmsg ("auth_method must be specified");
      return -99;
    }

  M (IKEV2_PROFILE_SET_AUTH, mp);

  mp->is_hex = is_hex;
  mp->auth_method = (u8) auth_method;
  mp->data_len = vec_len (data);
  clib_memcpy (mp->name, name, vec_len (name));
  clib_memcpy (mp->data, data, vec_len (data));
  vec_free (name);
  vec_free (data);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_profile_set_id (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_profile_set_id_t *mp;
  u8 *name = 0;
  u8 *data = 0;
  u8 is_local = 0;
  u32 id_type = 0;
  ip4_address_t ip4;
  int ret;

  const char *valid_chars = "a-zA-Z0-9_";

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "name %U", unformat_token, valid_chars, &name))
	vec_add1 (name, 0);
      else if (unformat (i, "id_type %U", unformat_ikev2_id_type, &id_type))
	;
      else if (unformat (i, "id_data %U", unformat_ip4_address, &ip4))
	{
	  data = vec_new (u8, 4);
	  clib_memcpy (data, ip4.as_u8, 4);
	}
      else if (unformat (i, "id_data 0x%U", unformat_hex_string, &data))
	;
      else if (unformat (i, "id_data %v", &data))
	;
      else if (unformat (i, "local"))
	is_local = 1;
      else if (unformat (i, "remote"))
	is_local = 0;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  if (!vec_len (data))
    {
      errmsg ("id_data must be specified");
      return -99;
    }

  if (!id_type)
    {
      errmsg ("id_type must be specified");
      return -99;
    }

  M (IKEV2_PROFILE_SET_ID, mp);

  mp->is_local = is_local;
  mp->id_type = (u8) id_type;
  mp->data_len = vec_len (data);
  clib_memcpy (mp->name, name, vec_len (name));
  clib_memcpy (mp->data, data, vec_len (data));
  vec_free (name);
  vec_free (data);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_profile_set_ts (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_profile_set_ts_t *mp;
  u8 *name = 0;
  u8 is_local = 0;
  u32 proto = 0, start_port = 0, end_port = (u32) ~ 0;
  ip4_address_t start_addr, end_addr;

  const char *valid_chars = "a-zA-Z0-9_";
  int ret;

  start_addr.as_u32 = 0;
  end_addr.as_u32 = (u32) ~ 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "name %U", unformat_token, valid_chars, &name))
	vec_add1 (name, 0);
      else if (unformat (i, "protocol %d", &proto))
	;
      else if (unformat (i, "start_port %d", &start_port))
	;
      else if (unformat (i, "end_port %d", &end_port))
	;
      else
	if (unformat (i, "start_addr %U", unformat_ip4_address, &start_addr))
	;
      else if (unformat (i, "end_addr %U", unformat_ip4_address, &end_addr))
	;
      else if (unformat (i, "local"))
	is_local = 1;
      else if (unformat (i, "remote"))
	is_local = 0;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_PROFILE_SET_TS, mp);

  mp->is_local = is_local;
  mp->proto = (u8) proto;
  mp->start_port = (u16) start_port;
  mp->end_port = (u16) end_port;
  mp->start_addr = start_addr.as_u32;
  mp->end_addr = end_addr.as_u32;
  clib_memcpy (mp->name, name, vec_len (name));
  vec_free (name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_set_local_key (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_set_local_key_t *mp;
  u8 *file = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "file %v", &file))
	vec_add1 (file, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (file))
    {
      errmsg ("RSA key file must be specified");
      return -99;
    }

  if (vec_len (file) > 256)
    {
      errmsg ("file name too long");
      return -99;
    }

  M (IKEV2_SET_LOCAL_KEY, mp);

  clib_memcpy (mp->key_file, file, vec_len (file));
  vec_free (file);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_set_responder (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_set_responder_t *mp;
  int ret;
  u8 *name = 0;
  u32 sw_if_index = ~0;
  ip4_address_t address;

  const char *valid_chars = "a-zA-Z0-9_";

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (i, "%U interface %d address %U", unformat_token, valid_chars,
	   &name, &sw_if_index, unformat_ip4_address, &address))
	vec_add1 (name, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_SET_RESPONDER, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  vec_free (name);

  mp->sw_if_index = sw_if_index;
  clib_memcpy (mp->address, &address, sizeof (address));

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_set_ike_transforms (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_set_ike_transforms_t *mp;
  int ret;
  u8 *name = 0;
  u32 crypto_alg, crypto_key_size, integ_alg, dh_group;

  const char *valid_chars = "a-zA-Z0-9_";

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U %d %d %d %d", unformat_token, valid_chars, &name,
		    &crypto_alg, &crypto_key_size, &integ_alg, &dh_group))
	vec_add1 (name, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_SET_IKE_TRANSFORMS, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  vec_free (name);
  mp->crypto_alg = crypto_alg;
  mp->crypto_key_size = crypto_key_size;
  mp->integ_alg = integ_alg;
  mp->dh_group = dh_group;

  S (mp);
  W (ret);
  return ret;
}


static int
api_ikev2_set_esp_transforms (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_set_esp_transforms_t *mp;
  int ret;
  u8 *name = 0;
  u32 crypto_alg, crypto_key_size, integ_alg, dh_group;

  const char *valid_chars = "a-zA-Z0-9_";

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U %d %d %d %d", unformat_token, valid_chars, &name,
		    &crypto_alg, &crypto_key_size, &integ_alg, &dh_group))
	vec_add1 (name, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_SET_ESP_TRANSFORMS, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  vec_free (name);
  mp->crypto_alg = crypto_alg;
  mp->crypto_key_size = crypto_key_size;
  mp->integ_alg = integ_alg;
  mp->dh_group = dh_group;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_set_sa_lifetime (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_set_sa_lifetime_t *mp;
  int ret;
  u8 *name = 0;
  u64 lifetime, lifetime_maxdata;
  u32 lifetime_jitter, handover;

  const char *valid_chars = "a-zA-Z0-9_";

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U %lu %u %u %lu", unformat_token, valid_chars, &name,
		    &lifetime, &lifetime_jitter, &handover,
		    &lifetime_maxdata))
	vec_add1 (name, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_SET_SA_LIFETIME, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  vec_free (name);
  mp->lifetime = lifetime;
  mp->lifetime_jitter = lifetime_jitter;
  mp->handover = handover;
  mp->lifetime_maxdata = lifetime_maxdata;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_initiate_sa_init (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_initiate_sa_init_t *mp;
  int ret;
  u8 *name = 0;

  const char *valid_chars = "a-zA-Z0-9_";

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_token, valid_chars, &name))
	vec_add1 (name, 0);
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vec_len (name))
    {
      errmsg ("profile name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("profile name too long");
      return -99;
    }

  M (IKEV2_INITIATE_SA_INIT, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  vec_free (name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_initiate_del_ike_sa (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_initiate_del_ike_sa_t *mp;
  int ret;
  u64 ispi;


  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%lx", &ispi))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IKEV2_INITIATE_DEL_IKE_SA, mp);

  mp->ispi = ispi;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_initiate_del_child_sa (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_initiate_del_child_sa_t *mp;
  int ret;
  u32 ispi;


  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%x", &ispi))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IKEV2_INITIATE_DEL_CHILD_SA, mp);

  mp->ispi = ispi;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ikev2_initiate_rekey_child_sa (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ikev2_initiate_rekey_child_sa_t *mp;
  int ret;
  u32 ispi;


  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%x", &ispi))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IKEV2_INITIATE_REKEY_CHILD_SA, mp);

  mp->ispi = ispi;

  S (mp);
  W (ret);
  return ret;
}

static int
api_get_first_msg_id (vat_main_t * vam)
{
  vl_api_get_first_msg_id_t *mp;
  unformat_input_t *i = vam->input;
  u8 *name;
  u8 name_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "client %s", &name))
	name_set = 1;
      else
	break;
    }

  if (name_set == 0)
    {
      errmsg ("missing client name");
      return -99;
    }
  vec_add1 (name, 0);

  if (vec_len (name) > 63)
    {
      errmsg ("client name too long");
      return -99;
    }

  M (GET_FIRST_MSG_ID, mp);
  clib_memcpy (mp->name, name, vec_len (name));
  S (mp);
  W (ret);
  return ret;
}

static int
api_cop_interface_enable_disable (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_cop_interface_enable_disable_t *mp;
  u32 sw_if_index = ~0;
  u8 enable_disable = 1;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "disable"))
	enable_disable = 0;
      if (unformat (line_input, "enable"))
	enable_disable = 1;
      else if (unformat (line_input, "%U", api_unformat_sw_if_index,
			 vam, &sw_if_index))
	;
      else if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (COP_INTERFACE_ENABLE_DISABLE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable_disable = enable_disable;

  /* send it... */
  S (mp);
  /* Wait for the reply */
  W (ret);
  return ret;
}

static int
api_cop_whitelist_enable_disable (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_cop_whitelist_enable_disable_t *mp;
  u32 sw_if_index = ~0;
  u8 ip4 = 0, ip6 = 0, default_cop = 0;
  u32 fib_id = 0;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "ip4"))
	ip4 = 1;
      else if (unformat (line_input, "ip6"))
	ip6 = 1;
      else if (unformat (line_input, "default"))
	default_cop = 1;
      else if (unformat (line_input, "%U", api_unformat_sw_if_index,
			 vam, &sw_if_index))
	;
      else if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "fib-id %d", &fib_id))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (COP_WHITELIST_ENABLE_DISABLE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->fib_id = ntohl (fib_id);
  mp->ip4 = ip4;
  mp->ip6 = ip6;
  mp->default_cop = default_cop;

  /* send it... */
  S (mp);
  /* Wait for the reply */
  W (ret);
  return ret;
}

static int
api_get_node_graph (vat_main_t * vam)
{
  vl_api_get_node_graph_t *mp;
  int ret;

  M (GET_NODE_GRAPH, mp);

  /* send it... */
  S (mp);
  /* Wait for the reply */
  W (ret);
  return ret;
}

/* *INDENT-OFF* */
/** Used for parsing LISP eids */
typedef CLIB_PACKED(struct{
  u8 addr[16];   /**< eid address */
  u32 len;       /**< prefix length if IP */
  u8 type;      /**< type of eid */
}) lisp_eid_vat_t;
/* *INDENT-ON* */

static uword
unformat_lisp_eid_vat (unformat_input_t * input, va_list * args)
{
  lisp_eid_vat_t *a = va_arg (*args, lisp_eid_vat_t *);

  clib_memset (a, 0, sizeof (a[0]));

  if (unformat (input, "%U/%d", unformat_ip4_address, a->addr, &a->len))
    {
      a->type = 0;		/* ipv4 type */
    }
  else if (unformat (input, "%U/%d", unformat_ip6_address, a->addr, &a->len))
    {
      a->type = 1;		/* ipv6 type */
    }
  else if (unformat (input, "%U", unformat_ethernet_address, a->addr))
    {
      a->type = 2;		/* mac type */
    }
  else if (unformat (input, "%U", unformat_nsh_address, a->addr))
    {
      a->type = 3;		/* NSH type */
      lisp_nsh_api_t *nsh = (lisp_nsh_api_t *) a->addr;
      nsh->spi = clib_host_to_net_u32 (nsh->spi);
    }
  else
    {
      return 0;
    }

  if ((a->type == 0 && a->len > 32) || (a->type == 1 && a->len > 128))
    {
      return 0;
    }

  return 1;
}

static int
lisp_eid_size_vat (u8 type)
{
  switch (type)
    {
    case 0:
      return 4;
    case 1:
      return 16;
    case 2:
      return 6;
    case 3:
      return 5;
    }
  return 0;
}

static void
lisp_eid_put_vat (u8 * dst, u8 eid[16], u8 type)
{
  clib_memcpy (dst, eid, lisp_eid_size_vat (type));
}

static int
api_one_add_del_locator_set (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_add_del_locator_set_t *mp;
  u8 is_add = 1;
  u8 *locator_set_name = NULL;
  u8 locator_set_name_set = 0;
  vl_api_local_locator_t locator, *locators = 0;
  u32 sw_if_index, priority, weight;
  u32 data_len = 0;

  int ret;
  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "locator-set %s", &locator_set_name))
	{
	  locator_set_name_set = 1;
	}
      else if (unformat (input, "sw_if_index %u p %u w %u",
			 &sw_if_index, &priority, &weight))
	{
	  locator.sw_if_index = htonl (sw_if_index);
	  locator.priority = priority;
	  locator.weight = weight;
	  vec_add1 (locators, locator);
	}
      else
	if (unformat
	    (input, "iface %U p %u w %u", api_unformat_sw_if_index, vam,
	     &sw_if_index, &priority, &weight))
	{
	  locator.sw_if_index = htonl (sw_if_index);
	  locator.priority = priority;
	  locator.weight = weight;
	  vec_add1 (locators, locator);
	}
      else
	break;
    }

  if (locator_set_name_set == 0)
    {
      errmsg ("missing locator-set name");
      vec_free (locators);
      return -99;
    }

  if (vec_len (locator_set_name) > 64)
    {
      errmsg ("locator-set name too long");
      vec_free (locator_set_name);
      vec_free (locators);
      return -99;
    }
  vec_add1 (locator_set_name, 0);

  data_len = sizeof (vl_api_local_locator_t) * vec_len (locators);

  /* Construct the API message */
  M2 (ONE_ADD_DEL_LOCATOR_SET, mp, data_len);

  mp->is_add = is_add;
  clib_memcpy (mp->locator_set_name, locator_set_name,
	       vec_len (locator_set_name));
  vec_free (locator_set_name);

  mp->locator_num = clib_host_to_net_u32 (vec_len (locators));
  if (locators)
    clib_memcpy (mp->locators, locators, data_len);
  vec_free (locators);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_add_del_locator_set api_one_add_del_locator_set

static int
api_one_add_del_locator (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_add_del_locator_t *mp;
  u32 tmp_if_index = ~0;
  u32 sw_if_index = ~0;
  u8 sw_if_index_set = 0;
  u8 sw_if_index_if_name_set = 0;
  u32 priority = ~0;
  u8 priority_set = 0;
  u32 weight = ~0;
  u8 weight_set = 0;
  u8 is_add = 1;
  u8 *locator_set_name = NULL;
  u8 locator_set_name_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "locator-set %s", &locator_set_name))
	{
	  locator_set_name_set = 1;
	}
      else if (unformat (input, "iface %U", api_unformat_sw_if_index, vam,
			 &tmp_if_index))
	{
	  sw_if_index_if_name_set = 1;
	  sw_if_index = tmp_if_index;
	}
      else if (unformat (input, "sw_if_index %d", &tmp_if_index))
	{
	  sw_if_index_set = 1;
	  sw_if_index = tmp_if_index;
	}
      else if (unformat (input, "p %d", &priority))
	{
	  priority_set = 1;
	}
      else if (unformat (input, "w %d", &weight))
	{
	  weight_set = 1;
	}
      else
	break;
    }

  if (locator_set_name_set == 0)
    {
      errmsg ("missing locator-set name");
      return -99;
    }

  if (sw_if_index_set == 0 && sw_if_index_if_name_set == 0)
    {
      errmsg ("missing sw_if_index");
      vec_free (locator_set_name);
      return -99;
    }

  if (sw_if_index_set != 0 && sw_if_index_if_name_set != 0)
    {
      errmsg ("cannot use both params interface name and sw_if_index");
      vec_free (locator_set_name);
      return -99;
    }

  if (priority_set == 0)
    {
      errmsg ("missing locator-set priority");
      vec_free (locator_set_name);
      return -99;
    }

  if (weight_set == 0)
    {
      errmsg ("missing locator-set weight");
      vec_free (locator_set_name);
      return -99;
    }

  if (vec_len (locator_set_name) > 64)
    {
      errmsg ("locator-set name too long");
      vec_free (locator_set_name);
      return -99;
    }
  vec_add1 (locator_set_name, 0);

  /* Construct the API message */
  M (ONE_ADD_DEL_LOCATOR, mp);

  mp->is_add = is_add;
  mp->sw_if_index = ntohl (sw_if_index);
  mp->priority = priority;
  mp->weight = weight;
  clib_memcpy (mp->locator_set_name, locator_set_name,
	       vec_len (locator_set_name));
  vec_free (locator_set_name);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_add_del_locator api_one_add_del_locator

uword
unformat_hmac_key_id (unformat_input_t * input, va_list * args)
{
  u32 *key_id = va_arg (*args, u32 *);
  u8 *s = 0;

  if (unformat (input, "%s", &s))
    {
      if (!strcmp ((char *) s, "sha1"))
	key_id[0] = HMAC_SHA_1_96;
      else if (!strcmp ((char *) s, "sha256"))
	key_id[0] = HMAC_SHA_256_128;
      else
	{
	  clib_warning ("invalid key_id: '%s'", s);
	  key_id[0] = HMAC_NO_KEY;
	}
    }
  else
    return 0;

  vec_free (s);
  return 1;
}

static int
api_one_add_del_local_eid (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_add_del_local_eid_t *mp;
  u8 is_add = 1;
  u8 eid_set = 0;
  lisp_eid_vat_t _eid, *eid = &_eid;
  u8 *locator_set_name = 0;
  u8 locator_set_name_set = 0;
  u32 vni = 0;
  u16 key_id = 0;
  u8 *key = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "vni %d", &vni))
	{
	  ;
	}
      else if (unformat (input, "eid %U", unformat_lisp_eid_vat, eid))
	{
	  eid_set = 1;
	}
      else if (unformat (input, "locator-set %s", &locator_set_name))
	{
	  locator_set_name_set = 1;
	}
      else if (unformat (input, "key-id %U", unformat_hmac_key_id, &key_id))
	;
      else if (unformat (input, "secret-key %_%v%_", &key))
	;
      else
	break;
    }

  if (locator_set_name_set == 0)
    {
      errmsg ("missing locator-set name");
      return -99;
    }

  if (0 == eid_set)
    {
      errmsg ("EID address not set!");
      vec_free (locator_set_name);
      return -99;
    }

  if (key && (0 == key_id))
    {
      errmsg ("invalid key_id!");
      return -99;
    }

  if (vec_len (key) > 64)
    {
      errmsg ("key too long");
      vec_free (key);
      return -99;
    }

  if (vec_len (locator_set_name) > 64)
    {
      errmsg ("locator-set name too long");
      vec_free (locator_set_name);
      return -99;
    }
  vec_add1 (locator_set_name, 0);

  /* Construct the API message */
  M (ONE_ADD_DEL_LOCAL_EID, mp);

  mp->is_add = is_add;
  lisp_eid_put_vat (mp->eid, eid->addr, eid->type);
  mp->eid_type = eid->type;
  mp->prefix_len = eid->len;
  mp->vni = clib_host_to_net_u32 (vni);
  mp->key_id = clib_host_to_net_u16 (key_id);
  clib_memcpy (mp->locator_set_name, locator_set_name,
	       vec_len (locator_set_name));
  clib_memcpy (mp->key, key, vec_len (key));

  vec_free (locator_set_name);
  vec_free (key);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_add_del_local_eid api_one_add_del_local_eid

static int
api_lisp_gpe_add_del_fwd_entry (vat_main_t * vam)
{
  u32 dp_table = 0, vni = 0;;
  unformat_input_t *input = vam->input;
  vl_api_gpe_add_del_fwd_entry_t *mp;
  u8 is_add = 1;
  lisp_eid_vat_t _rmt_eid, *rmt_eid = &_rmt_eid;
  lisp_eid_vat_t _lcl_eid, *lcl_eid = &_lcl_eid;
  u8 rmt_eid_set = 0, lcl_eid_set = 0;
  u32 action = ~0, w;
  ip4_address_t rmt_rloc4, lcl_rloc4;
  ip6_address_t rmt_rloc6, lcl_rloc6;
  vl_api_gpe_locator_t *rmt_locs = 0, *lcl_locs = 0, rloc, *curr_rloc = 0;
  int ret;

  clib_memset (&rloc, 0, sizeof (rloc));

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "reid %U", unformat_lisp_eid_vat, rmt_eid))
	{
	  rmt_eid_set = 1;
	}
      else if (unformat (input, "leid %U", unformat_lisp_eid_vat, lcl_eid))
	{
	  lcl_eid_set = 1;
	}
      else if (unformat (input, "vrf %d", &dp_table))
	;
      else if (unformat (input, "bd %d", &dp_table))
	;
      else if (unformat (input, "vni %d", &vni))
	;
      else if (unformat (input, "w %d", &w))
	{
	  if (!curr_rloc)
	    {
	      errmsg ("No RLOC configured for setting priority/weight!");
	      return -99;
	    }
	  curr_rloc->weight = w;
	}
      else if (unformat (input, "loc-pair %U %U", unformat_ip4_address,
			 &lcl_rloc4, unformat_ip4_address, &rmt_rloc4))
	{
	  rloc.is_ip4 = 1;

	  clib_memcpy (&rloc.addr, &lcl_rloc4, sizeof (lcl_rloc4));
	  rloc.weight = 0;
	  vec_add1 (lcl_locs, rloc);

	  clib_memcpy (&rloc.addr, &rmt_rloc4, sizeof (rmt_rloc4));
	  vec_add1 (rmt_locs, rloc);
	  /* weight saved in rmt loc */
	  curr_rloc = &rmt_locs[vec_len (rmt_locs) - 1];
	}
      else if (unformat (input, "loc-pair %U %U", unformat_ip6_address,
			 &lcl_rloc6, unformat_ip6_address, &rmt_rloc6))
	{
	  rloc.is_ip4 = 0;
	  clib_memcpy (&rloc.addr, &lcl_rloc6, sizeof (lcl_rloc6));
	  rloc.weight = 0;
	  vec_add1 (lcl_locs, rloc);

	  clib_memcpy (&rloc.addr, &rmt_rloc6, sizeof (rmt_rloc6));
	  vec_add1 (rmt_locs, rloc);
	  /* weight saved in rmt loc */
	  curr_rloc = &rmt_locs[vec_len (rmt_locs) - 1];
	}
      else if (unformat (input, "action %d", &action))
	{
	  ;
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!rmt_eid_set)
    {
      errmsg ("remote eid addresses not set");
      return -99;
    }

  if (lcl_eid_set && rmt_eid->type != lcl_eid->type)
    {
      errmsg ("eid types don't match");
      return -99;
    }

  if (0 == rmt_locs && (u32) ~ 0 == action)
    {
      errmsg ("action not set for negative mapping");
      return -99;
    }

  /* Construct the API message */
  M2 (GPE_ADD_DEL_FWD_ENTRY, mp,
      sizeof (vl_api_gpe_locator_t) * vec_len (rmt_locs) * 2);

  mp->is_add = is_add;
  lisp_eid_put_vat (mp->rmt_eid, rmt_eid->addr, rmt_eid->type);
  lisp_eid_put_vat (mp->lcl_eid, lcl_eid->addr, lcl_eid->type);
  mp->eid_type = rmt_eid->type;
  mp->dp_table = clib_host_to_net_u32 (dp_table);
  mp->vni = clib_host_to_net_u32 (vni);
  mp->rmt_len = rmt_eid->len;
  mp->lcl_len = lcl_eid->len;
  mp->action = action;

  if (0 != rmt_locs && 0 != lcl_locs)
    {
      mp->loc_num = clib_host_to_net_u32 (vec_len (rmt_locs) * 2);
      clib_memcpy (mp->locs, lcl_locs,
		   (sizeof (vl_api_gpe_locator_t) * vec_len (lcl_locs)));

      u32 offset = sizeof (vl_api_gpe_locator_t) * vec_len (lcl_locs);
      clib_memcpy (((u8 *) mp->locs) + offset, rmt_locs,
		   (sizeof (vl_api_gpe_locator_t) * vec_len (rmt_locs)));
    }
  vec_free (lcl_locs);
  vec_free (rmt_locs);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_one_add_del_map_server (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_add_del_map_server_t *mp;
  u8 is_add = 1;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  ip4_address_t ipv4;
  ip6_address_t ipv6;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "%U", unformat_ip4_address, &ipv4))
	{
	  ipv4_set = 1;
	}
      else if (unformat (input, "%U", unformat_ip6_address, &ipv6))
	{
	  ipv6_set = 1;
	}
      else
	break;
    }

  if (ipv4_set && ipv6_set)
    {
      errmsg ("both eid v4 and v6 addresses set");
      return -99;
    }

  if (!ipv4_set && !ipv6_set)
    {
      errmsg ("eid addresses not set");
      return -99;
    }

  /* Construct the API message */
  M (ONE_ADD_DEL_MAP_SERVER, mp);

  mp->is_add = is_add;
  if (ipv6_set)
    {
      mp->is_ipv6 = 1;
      clib_memcpy (mp->ip_address, &ipv6, sizeof (ipv6));
    }
  else
    {
      mp->is_ipv6 = 0;
      clib_memcpy (mp->ip_address, &ipv4, sizeof (ipv4));
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_add_del_map_server api_one_add_del_map_server

static int
api_one_add_del_map_resolver (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_add_del_map_resolver_t *mp;
  u8 is_add = 1;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  ip4_address_t ipv4;
  ip6_address_t ipv6;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "%U", unformat_ip4_address, &ipv4))
	{
	  ipv4_set = 1;
	}
      else if (unformat (input, "%U", unformat_ip6_address, &ipv6))
	{
	  ipv6_set = 1;
	}
      else
	break;
    }

  if (ipv4_set && ipv6_set)
    {
      errmsg ("both eid v4 and v6 addresses set");
      return -99;
    }

  if (!ipv4_set && !ipv6_set)
    {
      errmsg ("eid addresses not set");
      return -99;
    }

  /* Construct the API message */
  M (ONE_ADD_DEL_MAP_RESOLVER, mp);

  mp->is_add = is_add;
  if (ipv6_set)
    {
      mp->is_ipv6 = 1;
      clib_memcpy (mp->ip_address, &ipv6, sizeof (ipv6));
    }
  else
    {
      mp->is_ipv6 = 0;
      clib_memcpy (mp->ip_address, &ipv4, sizeof (ipv4));
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_add_del_map_resolver api_one_add_del_map_resolver

static int
api_lisp_gpe_enable_disable (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_gpe_enable_disable_t *mp;
  u8 is_set = 0;
  u8 is_en = 1;
  int ret;

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
	  is_en = 0;
	}
      else
	break;
    }

  if (is_set == 0)
    {
      errmsg ("Value not set");
      return -99;
    }

  /* Construct the API message */
  M (GPE_ENABLE_DISABLE, mp);

  mp->is_en = is_en;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_one_rloc_probe_enable_disable (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_rloc_probe_enable_disable_t *mp;
  u8 is_set = 0;
  u8 is_en = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	{
	  is_set = 1;
	  is_en = 1;
	}
      else if (unformat (input, "disable"))
	is_set = 1;
      else
	break;
    }

  if (!is_set)
    {
      errmsg ("Value not set");
      return -99;
    }

  /* Construct the API message */
  M (ONE_RLOC_PROBE_ENABLE_DISABLE, mp);

  mp->is_enabled = is_en;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_rloc_probe_enable_disable api_one_rloc_probe_enable_disable

static int
api_one_map_register_enable_disable (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_map_register_enable_disable_t *mp;
  u8 is_set = 0;
  u8 is_en = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	{
	  is_set = 1;
	  is_en = 1;
	}
      else if (unformat (input, "disable"))
	is_set = 1;
      else
	break;
    }

  if (!is_set)
    {
      errmsg ("Value not set");
      return -99;
    }

  /* Construct the API message */
  M (ONE_MAP_REGISTER_ENABLE_DISABLE, mp);

  mp->is_enabled = is_en;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_map_register_enable_disable api_one_map_register_enable_disable

static int
api_one_enable_disable (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_enable_disable_t *mp;
  u8 is_set = 0;
  u8 is_en = 0;
  int ret;

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
      errmsg ("Value not set");
      return -99;
    }

  /* Construct the API message */
  M (ONE_ENABLE_DISABLE, mp);

  mp->is_en = is_en;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_enable_disable api_one_enable_disable

static int
api_one_enable_disable_xtr_mode (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_enable_disable_xtr_mode_t *mp;
  u8 is_set = 0;
  u8 is_en = 0;
  int ret;

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
      errmsg ("Value not set");
      return -99;
    }

  /* Construct the API message */
  M (ONE_ENABLE_DISABLE_XTR_MODE, mp);

  mp->is_en = is_en;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_one_show_xtr_mode (vat_main_t * vam)
{
  vl_api_one_show_xtr_mode_t *mp;
  int ret;

  /* Construct the API message */
  M (ONE_SHOW_XTR_MODE, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_one_enable_disable_pitr_mode (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_enable_disable_pitr_mode_t *mp;
  u8 is_set = 0;
  u8 is_en = 0;
  int ret;

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
      errmsg ("Value not set");
      return -99;
    }

  /* Construct the API message */
  M (ONE_ENABLE_DISABLE_PITR_MODE, mp);

  mp->is_en = is_en;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_one_show_pitr_mode (vat_main_t * vam)
{
  vl_api_one_show_pitr_mode_t *mp;
  int ret;

  /* Construct the API message */
  M (ONE_SHOW_PITR_MODE, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_one_enable_disable_petr_mode (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_enable_disable_petr_mode_t *mp;
  u8 is_set = 0;
  u8 is_en = 0;
  int ret;

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
      errmsg ("Value not set");
      return -99;
    }

  /* Construct the API message */
  M (ONE_ENABLE_DISABLE_PETR_MODE, mp);

  mp->is_en = is_en;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_one_show_petr_mode (vat_main_t * vam)
{
  vl_api_one_show_petr_mode_t *mp;
  int ret;

  /* Construct the API message */
  M (ONE_SHOW_PETR_MODE, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_show_one_map_register_state (vat_main_t * vam)
{
  vl_api_show_one_map_register_state_t *mp;
  int ret;

  M (SHOW_ONE_MAP_REGISTER_STATE, mp);

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

#define api_show_lisp_map_register_state api_show_one_map_register_state

static int
api_show_one_rloc_probe_state (vat_main_t * vam)
{
  vl_api_show_one_rloc_probe_state_t *mp;
  int ret;

  M (SHOW_ONE_RLOC_PROBE_STATE, mp);

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

#define api_show_lisp_rloc_probe_state api_show_one_rloc_probe_state

static int
api_one_add_del_ndp_entry (vat_main_t * vam)
{
  vl_api_one_add_del_ndp_entry_t *mp;
  unformat_input_t *input = vam->input;
  u8 is_add = 1;
  u8 mac_set = 0;
  u8 bd_set = 0;
  u8 ip_set = 0;
  u8 mac[6] = { 0, };
  u8 ip6[16] = { 0, };
  u32 bd = ~0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "mac %U", unformat_ethernet_address, mac))
	mac_set = 1;
      else if (unformat (input, "ip %U", unformat_ip6_address, ip6))
	ip_set = 1;
      else if (unformat (input, "bd %d", &bd))
	bd_set = 1;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!bd_set || !ip_set || (!mac_set && is_add))
    {
      errmsg ("Missing BD, IP or MAC!");
      return -99;
    }

  M (ONE_ADD_DEL_NDP_ENTRY, mp);
  mp->is_add = is_add;
  clib_memcpy (mp->mac, mac, 6);
  mp->bd = clib_host_to_net_u32 (bd);
  clib_memcpy (mp->ip6, ip6, sizeof (mp->ip6));

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

static int
api_one_add_del_l2_arp_entry (vat_main_t * vam)
{
  vl_api_one_add_del_l2_arp_entry_t *mp;
  unformat_input_t *input = vam->input;
  u8 is_add = 1;
  u8 mac_set = 0;
  u8 bd_set = 0;
  u8 ip_set = 0;
  u8 mac[6] = { 0, };
  u32 ip4 = 0, bd = ~0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "mac %U", unformat_ethernet_address, mac))
	mac_set = 1;
      else if (unformat (input, "ip %U", unformat_ip4_address, &ip4))
	ip_set = 1;
      else if (unformat (input, "bd %d", &bd))
	bd_set = 1;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!bd_set || !ip_set || (!mac_set && is_add))
    {
      errmsg ("Missing BD, IP or MAC!");
      return -99;
    }

  M (ONE_ADD_DEL_L2_ARP_ENTRY, mp);
  mp->is_add = is_add;
  clib_memcpy (mp->mac, mac, 6);
  mp->bd = clib_host_to_net_u32 (bd);
  mp->ip4 = ip4;

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

static int
api_one_ndp_bd_get (vat_main_t * vam)
{
  vl_api_one_ndp_bd_get_t *mp;
  int ret;

  M (ONE_NDP_BD_GET, mp);

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

static int
api_one_ndp_entries_get (vat_main_t * vam)
{
  vl_api_one_ndp_entries_get_t *mp;
  unformat_input_t *input = vam->input;
  u8 bd_set = 0;
  u32 bd = ~0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "bd %d", &bd))
	bd_set = 1;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!bd_set)
    {
      errmsg ("Expected bridge domain!");
      return -99;
    }

  M (ONE_NDP_ENTRIES_GET, mp);
  mp->bd = clib_host_to_net_u32 (bd);

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

static int
api_one_l2_arp_bd_get (vat_main_t * vam)
{
  vl_api_one_l2_arp_bd_get_t *mp;
  int ret;

  M (ONE_L2_ARP_BD_GET, mp);

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

static int
api_one_l2_arp_entries_get (vat_main_t * vam)
{
  vl_api_one_l2_arp_entries_get_t *mp;
  unformat_input_t *input = vam->input;
  u8 bd_set = 0;
  u32 bd = ~0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "bd %d", &bd))
	bd_set = 1;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!bd_set)
    {
      errmsg ("Expected bridge domain!");
      return -99;
    }

  M (ONE_L2_ARP_ENTRIES_GET, mp);
  mp->bd = clib_host_to_net_u32 (bd);

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

static int
api_one_stats_enable_disable (vat_main_t * vam)
{
  vl_api_one_stats_enable_disable_t *mp;
  unformat_input_t *input = vam->input;
  u8 is_set = 0;
  u8 is_en = 0;
  int ret;

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
      errmsg ("Value not set");
      return -99;
    }

  M (ONE_STATS_ENABLE_DISABLE, mp);
  mp->is_en = is_en;

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

static int
api_show_one_stats_enable_disable (vat_main_t * vam)
{
  vl_api_show_one_stats_enable_disable_t *mp;
  int ret;

  M (SHOW_ONE_STATS_ENABLE_DISABLE, mp);

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

static int
api_show_one_map_request_mode (vat_main_t * vam)
{
  vl_api_show_one_map_request_mode_t *mp;
  int ret;

  M (SHOW_ONE_MAP_REQUEST_MODE, mp);

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

#define api_show_lisp_map_request_mode api_show_one_map_request_mode

static int
api_one_map_request_mode (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_map_request_mode_t *mp;
  u8 mode = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "dst-only"))
	mode = 0;
      else if (unformat (input, "src-dst"))
	mode = 1;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  M (ONE_MAP_REQUEST_MODE, mp);

  mp->mode = mode;

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

#define api_lisp_map_request_mode api_one_map_request_mode

/**
 * Enable/disable ONE proxy ITR.
 *
 * @param vam vpp API test context
 * @return return code
 */
static int
api_one_pitr_set_locator_set (vat_main_t * vam)
{
  u8 ls_name_set = 0;
  unformat_input_t *input = vam->input;
  vl_api_one_pitr_set_locator_set_t *mp;
  u8 is_add = 1;
  u8 *ls_name = 0;
  int ret;

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

  M (ONE_PITR_SET_LOCATOR_SET, mp);

  mp->is_add = is_add;
  clib_memcpy (mp->ls_name, ls_name, vec_len (ls_name));
  vec_free (ls_name);

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

#define api_lisp_pitr_set_locator_set api_one_pitr_set_locator_set

static int
api_one_nsh_set_locator_set (vat_main_t * vam)
{
  u8 ls_name_set = 0;
  unformat_input_t *input = vam->input;
  vl_api_one_nsh_set_locator_set_t *mp;
  u8 is_add = 1;
  u8 *ls_name = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "ls %s", &ls_name))
	ls_name_set = 1;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!ls_name_set && is_add)
    {
      errmsg ("locator-set name not set!");
      return -99;
    }

  M (ONE_NSH_SET_LOCATOR_SET, mp);

  mp->is_add = is_add;
  clib_memcpy (mp->ls_name, ls_name, vec_len (ls_name));
  vec_free (ls_name);

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

static int
api_show_one_pitr (vat_main_t * vam)
{
  vl_api_show_one_pitr_t *mp;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%=20s", "lisp status:");
    }

  M (SHOW_ONE_PITR, mp);
  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_show_lisp_pitr api_show_one_pitr

static int
api_one_use_petr (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_use_petr_t *mp;
  u8 is_add = 0;
  ip_address_t ip;
  int ret;

  clib_memset (&ip, 0, sizeof (ip));

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	is_add = 0;
      else
	if (unformat (input, "%U", unformat_ip4_address, &ip_addr_v4 (&ip)))
	{
	  is_add = 1;
	  ip_addr_version (&ip) = IP4;
	}
      else
	if (unformat (input, "%U", unformat_ip6_address, &ip_addr_v6 (&ip)))
	{
	  is_add = 1;
	  ip_addr_version (&ip) = IP6;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  M (ONE_USE_PETR, mp);

  mp->is_add = is_add;
  if (is_add)
    {
      mp->is_ip4 = ip_addr_version (&ip) == IP4 ? 1 : 0;
      if (mp->is_ip4)
	clib_memcpy (mp->address, &ip, 4);
      else
	clib_memcpy (mp->address, &ip, 16);
    }

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

#define api_lisp_use_petr api_one_use_petr

static int
api_show_one_nsh_mapping (vat_main_t * vam)
{
  vl_api_show_one_use_petr_t *mp;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%=20s", "local ONE NSH mapping:");
    }

  M (SHOW_ONE_NSH_MAPPING, mp);
  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_show_one_use_petr (vat_main_t * vam)
{
  vl_api_show_one_use_petr_t *mp;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%=20s", "Proxy-ETR status:");
    }

  M (SHOW_ONE_USE_PETR, mp);
  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_show_lisp_use_petr api_show_one_use_petr

/**
 * Add/delete mapping between vni and vrf
 */
static int
api_one_eid_table_add_del_map (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_eid_table_add_del_map_t *mp;
  u8 is_add = 1, vni_set = 0, vrf_set = 0, bd_index_set = 0;
  u32 vni, vrf, bd_index;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "vrf %d", &vrf))
	vrf_set = 1;
      else if (unformat (input, "bd_index %d", &bd_index))
	bd_index_set = 1;
      else if (unformat (input, "vni %d", &vni))
	vni_set = 1;
      else
	break;
    }

  if (!vni_set || (!vrf_set && !bd_index_set))
    {
      errmsg ("missing arguments!");
      return -99;
    }

  if (vrf_set && bd_index_set)
    {
      errmsg ("error: both vrf and bd entered!");
      return -99;
    }

  M (ONE_EID_TABLE_ADD_DEL_MAP, mp);

  mp->is_add = is_add;
  mp->vni = htonl (vni);
  mp->dp_table = vrf_set ? htonl (vrf) : htonl (bd_index);
  mp->is_l2 = bd_index_set;

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

#define api_lisp_eid_table_add_del_map api_one_eid_table_add_del_map

uword
unformat_negative_mapping_action (unformat_input_t * input, va_list * args)
{
  u32 *action = va_arg (*args, u32 *);
  u8 *s = 0;

  if (unformat (input, "%s", &s))
    {
      if (!strcmp ((char *) s, "no-action"))
	action[0] = 0;
      else if (!strcmp ((char *) s, "natively-forward"))
	action[0] = 1;
      else if (!strcmp ((char *) s, "send-map-request"))
	action[0] = 2;
      else if (!strcmp ((char *) s, "drop"))
	action[0] = 3;
      else
	{
	  clib_warning ("invalid action: '%s'", s);
	  action[0] = 3;
	}
    }
  else
    return 0;

  vec_free (s);
  return 1;
}

/**
 * Add/del remote mapping to/from ONE control plane
 *
 * @param vam vpp API test context
 * @return return code
 */
static int
api_one_add_del_remote_mapping (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_add_del_remote_mapping_t *mp;
  u32 vni = 0;
  lisp_eid_vat_t _eid, *eid = &_eid;
  lisp_eid_vat_t _seid, *seid = &_seid;
  u8 is_add = 1, del_all = 0, eid_set = 0, seid_set = 0;
  u32 action = ~0, p, w, data_len;
  ip4_address_t rloc4;
  ip6_address_t rloc6;
  vl_api_remote_locator_t *rlocs = 0, rloc, *curr_rloc = 0;
  int ret;

  clib_memset (&rloc, 0, sizeof (rloc));

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del-all"))
	{
	  del_all = 1;
	}
      else if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "add"))
	{
	  is_add = 1;
	}
      else if (unformat (input, "eid %U", unformat_lisp_eid_vat, eid))
	{
	  eid_set = 1;
	}
      else if (unformat (input, "seid %U", unformat_lisp_eid_vat, seid))
	{
	  seid_set = 1;
	}
      else if (unformat (input, "vni %d", &vni))
	{
	  ;
	}
      else if (unformat (input, "p %d w %d", &p, &w))
	{
	  if (!curr_rloc)
	    {
	      errmsg ("No RLOC configured for setting priority/weight!");
	      return -99;
	    }
	  curr_rloc->priority = p;
	  curr_rloc->weight = w;
	}
      else if (unformat (input, "rloc %U", unformat_ip4_address, &rloc4))
	{
	  rloc.is_ip4 = 1;
	  clib_memcpy (&rloc.addr, &rloc4, sizeof (rloc4));
	  vec_add1 (rlocs, rloc);
	  curr_rloc = &rlocs[vec_len (rlocs) - 1];
	}
      else if (unformat (input, "rloc %U", unformat_ip6_address, &rloc6))
	{
	  rloc.is_ip4 = 0;
	  clib_memcpy (&rloc.addr, &rloc6, sizeof (rloc6));
	  vec_add1 (rlocs, rloc);
	  curr_rloc = &rlocs[vec_len (rlocs) - 1];
	}
      else if (unformat (input, "action %U",
			 unformat_negative_mapping_action, &action))
	{
	  ;
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (0 == eid_set)
    {
      errmsg ("missing params!");
      return -99;
    }

  if (is_add && (~0 == action) && 0 == vec_len (rlocs))
    {
      errmsg ("no action set for negative map-reply!");
      return -99;
    }

  data_len = vec_len (rlocs) * sizeof (vl_api_remote_locator_t);

  M2 (ONE_ADD_DEL_REMOTE_MAPPING, mp, data_len);
  mp->is_add = is_add;
  mp->vni = htonl (vni);
  mp->action = (u8) action;
  mp->is_src_dst = seid_set;
  mp->eid_len = eid->len;
  mp->seid_len = seid->len;
  mp->del_all = del_all;
  mp->eid_type = eid->type;
  lisp_eid_put_vat (mp->eid, eid->addr, eid->type);
  lisp_eid_put_vat (mp->seid, seid->addr, seid->type);

  mp->rloc_num = clib_host_to_net_u32 (vec_len (rlocs));
  clib_memcpy (mp->rlocs, rlocs, data_len);
  vec_free (rlocs);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_add_del_remote_mapping api_one_add_del_remote_mapping

/**
 * Add/del ONE adjacency. Saves mapping in ONE control plane and updates
 * forwarding entries in data-plane accordingly.
 *
 * @param vam vpp API test context
 * @return return code
 */
static int
api_one_add_del_adjacency (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_add_del_adjacency_t *mp;
  u32 vni = 0;
  ip4_address_t leid4, reid4;
  ip6_address_t leid6, reid6;
  u8 reid_mac[6] = { 0 };
  u8 leid_mac[6] = { 0 };
  u8 reid_type, leid_type;
  u32 leid_len = 0, reid_len = 0, len;
  u8 is_add = 1;
  int ret;

  leid_type = reid_type = (u8) ~ 0;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "add"))
	{
	  is_add = 1;
	}
      else if (unformat (input, "reid %U/%d", unformat_ip4_address,
			 &reid4, &len))
	{
	  reid_type = 0;	/* ipv4 */
	  reid_len = len;
	}
      else if (unformat (input, "reid %U/%d", unformat_ip6_address,
			 &reid6, &len))
	{
	  reid_type = 1;	/* ipv6 */
	  reid_len = len;
	}
      else if (unformat (input, "reid %U", unformat_ethernet_address,
			 reid_mac))
	{
	  reid_type = 2;	/* mac */
	}
      else if (unformat (input, "leid %U/%d", unformat_ip4_address,
			 &leid4, &len))
	{
	  leid_type = 0;	/* ipv4 */
	  leid_len = len;
	}
      else if (unformat (input, "leid %U/%d", unformat_ip6_address,
			 &leid6, &len))
	{
	  leid_type = 1;	/* ipv6 */
	  leid_len = len;
	}
      else if (unformat (input, "leid %U", unformat_ethernet_address,
			 leid_mac))
	{
	  leid_type = 2;	/* mac */
	}
      else if (unformat (input, "vni %d", &vni))
	{
	  ;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if ((u8) ~ 0 == reid_type)
    {
      errmsg ("missing params!");
      return -99;
    }

  if (leid_type != reid_type)
    {
      errmsg ("remote and local EIDs are of different types!");
      return -99;
    }

  M (ONE_ADD_DEL_ADJACENCY, mp);
  mp->is_add = is_add;
  mp->vni = htonl (vni);
  mp->leid_len = leid_len;
  mp->reid_len = reid_len;
  mp->eid_type = reid_type;

  switch (mp->eid_type)
    {
    case 0:
      clib_memcpy (mp->leid, &leid4, sizeof (leid4));
      clib_memcpy (mp->reid, &reid4, sizeof (reid4));
      break;
    case 1:
      clib_memcpy (mp->leid, &leid6, sizeof (leid6));
      clib_memcpy (mp->reid, &reid6, sizeof (reid6));
      break;
    case 2:
      clib_memcpy (mp->leid, leid_mac, 6);
      clib_memcpy (mp->reid, reid_mac, 6);
      break;
    default:
      errmsg ("unknown EID type %d!", mp->eid_type);
      return 0;
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_add_del_adjacency api_one_add_del_adjacency

uword
unformat_gpe_encap_mode (unformat_input_t * input, va_list * args)
{
  u32 *mode = va_arg (*args, u32 *);

  if (unformat (input, "lisp"))
    *mode = 0;
  else if (unformat (input, "vxlan"))
    *mode = 1;
  else
    return 0;

  return 1;
}

static int
api_gpe_get_encap_mode (vat_main_t * vam)
{
  vl_api_gpe_get_encap_mode_t *mp;
  int ret;

  /* Construct the API message */
  M (GPE_GET_ENCAP_MODE, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_gpe_set_encap_mode (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_gpe_set_encap_mode_t *mp;
  int ret;
  u32 mode = 0;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_gpe_encap_mode, &mode))
	;
      else
	break;
    }

  /* Construct the API message */
  M (GPE_SET_ENCAP_MODE, mp);

  mp->mode = mode;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_lisp_gpe_add_del_iface (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_gpe_add_del_iface_t *mp;
  u8 action_set = 0, is_add = 1, is_l2 = 0, dp_table_set = 0, vni_set = 0;
  u32 dp_table = 0, vni = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "up"))
	{
	  action_set = 1;
	  is_add = 1;
	}
      else if (unformat (input, "down"))
	{
	  action_set = 1;
	  is_add = 0;
	}
      else if (unformat (input, "table_id %d", &dp_table))
	{
	  dp_table_set = 1;
	}
      else if (unformat (input, "bd_id %d", &dp_table))
	{
	  dp_table_set = 1;
	  is_l2 = 1;
	}
      else if (unformat (input, "vni %d", &vni))
	{
	  vni_set = 1;
	}
      else
	break;
    }

  if (action_set == 0)
    {
      errmsg ("Action not set");
      return -99;
    }
  if (dp_table_set == 0 || vni_set == 0)
    {
      errmsg ("vni and dp_table must be set");
      return -99;
    }

  /* Construct the API message */
  M (GPE_ADD_DEL_IFACE, mp);

  mp->is_add = is_add;
  mp->dp_table = clib_host_to_net_u32 (dp_table);
  mp->is_l2 = is_l2;
  mp->vni = clib_host_to_net_u32 (vni);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_one_map_register_fallback_threshold (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_map_register_fallback_threshold_t *mp;
  u32 value = 0;
  u8 is_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%u", &value))
	is_set = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!is_set)
    {
      errmsg ("fallback threshold value is missing!");
      return -99;
    }

  M (ONE_MAP_REGISTER_FALLBACK_THRESHOLD, mp);
  mp->value = clib_host_to_net_u32 (value);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_show_one_map_register_fallback_threshold (vat_main_t * vam)
{
  vl_api_show_one_map_register_fallback_threshold_t *mp;
  int ret;

  M (SHOW_ONE_MAP_REGISTER_FALLBACK_THRESHOLD, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

uword
unformat_lisp_transport_protocol (unformat_input_t * input, va_list * args)
{
  u32 *proto = va_arg (*args, u32 *);

  if (unformat (input, "udp"))
    *proto = 1;
  else if (unformat (input, "api"))
    *proto = 2;
  else
    return 0;

  return 1;
}

static int
api_one_set_transport_protocol (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_set_transport_protocol_t *mp;
  u8 is_set = 0;
  u32 protocol = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_lisp_transport_protocol, &protocol))
	is_set = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!is_set)
    {
      errmsg ("Transport protocol missing!");
      return -99;
    }

  M (ONE_SET_TRANSPORT_PROTOCOL, mp);
  mp->protocol = (u8) protocol;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_one_get_transport_protocol (vat_main_t * vam)
{
  vl_api_one_get_transport_protocol_t *mp;
  int ret;

  M (ONE_GET_TRANSPORT_PROTOCOL, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_one_map_register_set_ttl (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_map_register_set_ttl_t *mp;
  u32 ttl = 0;
  u8 is_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%u", &ttl))
	is_set = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!is_set)
    {
      errmsg ("TTL value missing!");
      return -99;
    }

  M (ONE_MAP_REGISTER_SET_TTL, mp);
  mp->ttl = clib_host_to_net_u32 (ttl);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_show_one_map_register_ttl (vat_main_t * vam)
{
  vl_api_show_one_map_register_ttl_t *mp;
  int ret;

  M (SHOW_ONE_MAP_REGISTER_TTL, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/**
 * Add/del map request itr rlocs from ONE control plane and updates
 *
 * @param vam vpp API test context
 * @return return code
 */
static int
api_one_add_del_map_request_itr_rlocs (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_add_del_map_request_itr_rlocs_t *mp;
  u8 *locator_set_name = 0;
  u8 locator_set_name_set = 0;
  u8 is_add = 1;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "%_%v%_", &locator_set_name))
	{
	  locator_set_name_set = 1;
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (is_add && !locator_set_name_set)
    {
      errmsg ("itr-rloc is not set!");
      return -99;
    }

  if (is_add && vec_len (locator_set_name) > 64)
    {
      errmsg ("itr-rloc locator-set name too long");
      vec_free (locator_set_name);
      return -99;
    }

  M (ONE_ADD_DEL_MAP_REQUEST_ITR_RLOCS, mp);
  mp->is_add = is_add;
  if (is_add)
    {
      clib_memcpy (mp->locator_set_name, locator_set_name,
		   vec_len (locator_set_name));
    }
  else
    {
      clib_memset (mp->locator_set_name, 0, sizeof (mp->locator_set_name));
    }
  vec_free (locator_set_name);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_add_del_map_request_itr_rlocs api_one_add_del_map_request_itr_rlocs

static int
api_one_locator_dump (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_one_locator_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u8 is_index_set = 0, is_name_set = 0;
  u8 *ls_name = 0;
  u32 ls_index = ~0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ls_name %_%v%_", &ls_name))
	{
	  is_name_set = 1;
	}
      else if (unformat (input, "ls_index %d", &ls_index))
	{
	  is_index_set = 1;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!is_index_set && !is_name_set)
    {
      errmsg ("error: expected one of index or name!");
      return -99;
    }

  if (is_index_set && is_name_set)
    {
      errmsg ("error: only one param expected!");
      return -99;
    }

  if (vec_len (ls_name) > 62)
    {
      errmsg ("error: locator set name too long!");
      return -99;
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "%=16s%=16s%=16s", "locator", "priority", "weight");
    }

  M (ONE_LOCATOR_DUMP, mp);
  mp->is_index_set = is_index_set;

  if (is_index_set)
    mp->ls_index = clib_host_to_net_u32 (ls_index);
  else
    {
      vec_add1 (ls_name, 0);
      strncpy ((char *) mp->ls_name, (char *) ls_name,
	       sizeof (mp->ls_name) - 1);
    }

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_locator_dump api_one_locator_dump

static int
api_one_locator_set_dump (vat_main_t * vam)
{
  vl_api_one_locator_set_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  unformat_input_t *input = vam->input;
  u8 filter = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "local"))
	{
	  filter = 1;
	}
      else if (unformat (input, "remote"))
	{
	  filter = 2;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "%=10s%=15s", "ls_index", "ls_name");
    }

  M (ONE_LOCATOR_SET_DUMP, mp);

  mp->filter = filter;

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_locator_set_dump api_one_locator_set_dump

static int
api_one_eid_table_map_dump (vat_main_t * vam)
{
  u8 is_l2 = 0;
  u8 mode_set = 0;
  unformat_input_t *input = vam->input;
  vl_api_one_eid_table_map_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "l2"))
	{
	  is_l2 = 1;
	  mode_set = 1;
	}
      else if (unformat (input, "l3"))
	{
	  is_l2 = 0;
	  mode_set = 1;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!mode_set)
    {
      errmsg ("expected one of 'l2' or 'l3' parameter!");
      return -99;
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "%=10s%=10s", "VNI", is_l2 ? "BD" : "VRF");
    }

  M (ONE_EID_TABLE_MAP_DUMP, mp);
  mp->is_l2 = is_l2;

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_eid_table_map_dump api_one_eid_table_map_dump

static int
api_one_eid_table_vni_dump (vat_main_t * vam)
{
  vl_api_one_eid_table_vni_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "VNI");
    }

  M (ONE_EID_TABLE_VNI_DUMP, mp);

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_eid_table_vni_dump api_one_eid_table_vni_dump

static int
api_one_eid_table_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_one_eid_table_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  struct in_addr ip4;
  struct in6_addr ip6;
  u8 mac[6];
  u8 eid_type = ~0, eid_set = 0;
  u32 prefix_length = ~0, t, vni = 0;
  u8 filter = 0;
  int ret;
  lisp_nsh_api_t nsh;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "eid %U/%d", unformat_ip4_address, &ip4, &t))
	{
	  eid_set = 1;
	  eid_type = 0;
	  prefix_length = t;
	}
      else if (unformat (i, "eid %U/%d", unformat_ip6_address, &ip6, &t))
	{
	  eid_set = 1;
	  eid_type = 1;
	  prefix_length = t;
	}
      else if (unformat (i, "eid %U", unformat_ethernet_address, mac))
	{
	  eid_set = 1;
	  eid_type = 2;
	}
      else if (unformat (i, "eid %U", unformat_nsh_address, &nsh))
	{
	  eid_set = 1;
	  eid_type = 3;
	}
      else if (unformat (i, "vni %d", &t))
	{
	  vni = t;
	}
      else if (unformat (i, "local"))
	{
	  filter = 1;
	}
      else if (unformat (i, "remote"))
	{
	  filter = 2;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "%-35s%-20s%-30s%-20s%-20s%-10s%-20s", "EID",
	     "type", "ls_index", "ttl", "authoritative", "key_id", "key");
    }

  M (ONE_EID_TABLE_DUMP, mp);

  mp->filter = filter;
  if (eid_set)
    {
      mp->eid_set = 1;
      mp->vni = htonl (vni);
      mp->eid_type = eid_type;
      switch (eid_type)
	{
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
	case 3:
	  clib_memcpy (mp->eid, &nsh, sizeof (nsh));
	  break;
	default:
	  errmsg ("unknown EID type %d!", eid_type);
	  return -99;
	}
    }

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_eid_table_dump api_one_eid_table_dump

static int
api_lisp_gpe_fwd_entries_get (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_gpe_fwd_entries_get_t *mp;
  u8 vni_set = 0;
  u32 vni = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "vni %d", &vni))
	{
	  vni_set = 1;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vni_set)
    {
      errmsg ("vni not set!");
      return -99;
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "%10s %10s %s %40s", "fwd_index", "dp_table",
	     "leid", "reid");
    }

  M (GPE_FWD_ENTRIES_GET, mp);
  mp->vni = clib_host_to_net_u32 (vni);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define vl_api_gpe_native_fwd_rpaths_get_reply_t_endian vl_noop_handler
#define vl_api_gpe_native_fwd_rpaths_get_reply_t_print vl_noop_handler
#define vl_api_gpe_fwd_entry_vnis_get_reply_t_endian vl_noop_handler
#define vl_api_gpe_fwd_entry_vnis_get_reply_t_print vl_noop_handler
#define vl_api_gpe_fwd_entries_get_reply_t_endian vl_noop_handler
#define vl_api_gpe_fwd_entries_get_reply_t_print vl_noop_handler
#define vl_api_gpe_fwd_entry_path_details_t_endian vl_noop_handler
#define vl_api_gpe_fwd_entry_path_details_t_print vl_noop_handler

static int
api_one_adjacencies_get (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_one_adjacencies_get_t *mp;
  u8 vni_set = 0;
  u32 vni = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "vni %d", &vni))
	{
	  vni_set = 1;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vni_set)
    {
      errmsg ("vni not set!");
      return -99;
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "%s %40s", "leid", "reid");
    }

  M (ONE_ADJACENCIES_GET, mp);
  mp->vni = clib_host_to_net_u32 (vni);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_adjacencies_get api_one_adjacencies_get

static int
api_gpe_native_fwd_rpaths_get (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_gpe_native_fwd_rpaths_get_t *mp;
  int ret;
  u8 ip_family_set = 0, is_ip4 = 1;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "ip4"))
	{
	  ip_family_set = 1;
	  is_ip4 = 1;
	}
      else if (unformat (i, "ip6"))
	{
	  ip_family_set = 1;
	  is_ip4 = 0;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!ip_family_set)
    {
      errmsg ("ip family not set!");
      return -99;
    }

  M (GPE_NATIVE_FWD_RPATHS_GET, mp);
  mp->is_ip4 = is_ip4;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_gpe_fwd_entry_vnis_get (vat_main_t * vam)
{
  vl_api_gpe_fwd_entry_vnis_get_t *mp;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "VNIs");
    }

  M (GPE_FWD_ENTRY_VNIS_GET, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_gpe_add_del_native_fwd_rpath (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_gpe_add_del_native_fwd_rpath_t *mp;
  int ret = 0;
  u8 is_add = 1, ip_set = 0, is_ip4 = 1;
  struct in_addr ip4;
  struct in6_addr ip6;
  u32 table_id = 0, nh_sw_if_index = ~0;

  clib_memset (&ip4, 0, sizeof (ip4));
  clib_memset (&ip6, 0, sizeof (ip6));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "via %U %U", unformat_ip4_address, &ip4,
			 api_unformat_sw_if_index, vam, &nh_sw_if_index))
	{
	  ip_set = 1;
	  is_ip4 = 1;
	}
      else if (unformat (i, "via %U %U", unformat_ip6_address, &ip6,
			 api_unformat_sw_if_index, vam, &nh_sw_if_index))
	{
	  ip_set = 1;
	  is_ip4 = 0;
	}
      else if (unformat (i, "via %U", unformat_ip4_address, &ip4))
	{
	  ip_set = 1;
	  is_ip4 = 1;
	  nh_sw_if_index = ~0;
	}
      else if (unformat (i, "via %U", unformat_ip6_address, &ip6))
	{
	  ip_set = 1;
	  is_ip4 = 0;
	  nh_sw_if_index = ~0;
	}
      else if (unformat (i, "table %d", &table_id))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!ip_set)
    {
      errmsg ("nh addr not set!");
      return -99;
    }

  M (GPE_ADD_DEL_NATIVE_FWD_RPATH, mp);
  mp->is_add = is_add;
  mp->table_id = clib_host_to_net_u32 (table_id);
  mp->nh_sw_if_index = clib_host_to_net_u32 (nh_sw_if_index);
  mp->is_ip4 = is_ip4;
  if (is_ip4)
    clib_memcpy (mp->nh_addr, &ip4, sizeof (ip4));
  else
    clib_memcpy (mp->nh_addr, &ip6, sizeof (ip6));

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_one_map_server_dump (vat_main_t * vam)
{
  vl_api_one_map_server_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%=20s", "Map server");
    }

  M (ONE_MAP_SERVER_DUMP, mp);
  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_map_server_dump api_one_map_server_dump

static int
api_one_map_resolver_dump (vat_main_t * vam)
{
  vl_api_one_map_resolver_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%=20s", "Map resolver");
    }

  M (ONE_MAP_RESOLVER_DUMP, mp);
  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_map_resolver_dump api_one_map_resolver_dump

static int
api_one_stats_flush (vat_main_t * vam)
{
  vl_api_one_stats_flush_t *mp;
  int ret = 0;

  M (ONE_STATS_FLUSH, mp);
  S (mp);
  W (ret);
  return ret;
}

static int
api_one_stats_dump (vat_main_t * vam)
{
  vl_api_one_stats_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  M (ONE_STATS_DUMP, mp);
  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_show_one_status (vat_main_t * vam)
{
  vl_api_show_one_status_t *mp;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%-20s%-16s", "ONE status", "locator-set");
    }

  M (SHOW_ONE_STATUS, mp);
  /* send it... */
  S (mp);
  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_show_lisp_status api_show_one_status

static int
api_lisp_gpe_fwd_entry_path_dump (vat_main_t * vam)
{
  vl_api_gpe_fwd_entry_path_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  unformat_input_t *i = vam->input;
  u32 fwd_entry_index = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "index %d", &fwd_entry_index))
	;
      else
	break;
    }

  if (~0 == fwd_entry_index)
    {
      errmsg ("no index specified!");
      return -99;
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "first line");
    }

  M (GPE_FWD_ENTRY_PATH_DUMP, mp);

  /* send it... */
  S (mp);
  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_one_get_map_request_itr_rlocs (vat_main_t * vam)
{
  vl_api_one_get_map_request_itr_rlocs_t *mp;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%=20s", "itr-rlocs:");
    }

  M (ONE_GET_MAP_REQUEST_ITR_RLOCS, mp);
  /* send it... */
  S (mp);
  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define api_lisp_get_map_request_itr_rlocs api_one_get_map_request_itr_rlocs

static int
api_af_packet_create (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_af_packet_create_t *mp;
  u8 *host_if_name = 0;
  u8 hw_addr[6];
  u8 random_hw_addr = 1;
  int ret;

  clib_memset (hw_addr, 0, sizeof (hw_addr));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "name %s", &host_if_name))
	vec_add1 (host_if_name, 0);
      else if (unformat (i, "hw_addr %U", unformat_ethernet_address, hw_addr))
	random_hw_addr = 0;
      else
	break;
    }

  if (!vec_len (host_if_name))
    {
      errmsg ("host-interface name must be specified");
      return -99;
    }

  if (vec_len (host_if_name) > 64)
    {
      errmsg ("host-interface name too long");
      return -99;
    }

  M (AF_PACKET_CREATE, mp);

  clib_memcpy (mp->host_if_name, host_if_name, vec_len (host_if_name));
  clib_memcpy (mp->hw_addr, hw_addr, 6);
  mp->use_random_hw_addr = random_hw_addr;
  vec_free (host_if_name);

  S (mp);

  /* *INDENT-OFF* */
  W2 (ret,
      ({
        if (ret == 0)
          fprintf (vam->ofp ? vam->ofp : stderr,
                   " new sw_if_index = %d\n", vam->sw_if_index);
      }));
  /* *INDENT-ON* */
  return ret;
}

static int
api_af_packet_delete (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_af_packet_delete_t *mp;
  u8 *host_if_name = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "name %s", &host_if_name))
	vec_add1 (host_if_name, 0);
      else
	break;
    }

  if (!vec_len (host_if_name))
    {
      errmsg ("host-interface name must be specified");
      return -99;
    }

  if (vec_len (host_if_name) > 64)
    {
      errmsg ("host-interface name too long");
      return -99;
    }

  M (AF_PACKET_DELETE, mp);

  clib_memcpy (mp->host_if_name, host_if_name, vec_len (host_if_name));
  vec_free (host_if_name);

  S (mp);
  W (ret);
  return ret;
}

static void vl_api_af_packet_details_t_handler
  (vl_api_af_packet_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%-16s %d",
	 mp->host_if_name, clib_net_to_host_u32 (mp->sw_if_index));
}

static void vl_api_af_packet_details_t_handler_json
  (vl_api_af_packet_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  vat_json_object_add_string_copy (node, "dev_name", mp->host_if_name);
}

static int
api_af_packet_dump (vat_main_t * vam)
{
  vl_api_af_packet_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  print (vam->ofp, "\n%-16s %s", "dev_name", "sw_if_index");
  /* Get list of tap interfaces */
  M (AF_PACKET_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_policer_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_policer_add_del_t *mp;
  u8 is_add = 1;
  u8 *name = 0;
  u32 cir = 0;
  u32 eir = 0;
  u64 cb = 0;
  u64 eb = 0;
  u8 rate_type = 0;
  u8 round_type = 0;
  u8 type = 0;
  u8 color_aware = 0;
  sse2_qos_pol_action_params_st conform_action, exceed_action, violate_action;
  int ret;

  conform_action.action_type = SSE2_QOS_ACTION_TRANSMIT;
  conform_action.dscp = 0;
  exceed_action.action_type = SSE2_QOS_ACTION_MARK_AND_TRANSMIT;
  exceed_action.dscp = 0;
  violate_action.action_type = SSE2_QOS_ACTION_DROP;
  violate_action.dscp = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
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
      else if (unformat (i, "color-aware"))
	color_aware = 1;
      else
	break;
    }

  if (!vec_len (name))
    {
      errmsg ("policer name must be specified");
      return -99;
    }

  if (vec_len (name) > 64)
    {
      errmsg ("policer name too long");
      return -99;
    }

  M (POLICER_ADD_DEL, mp);

  clib_memcpy (mp->name, name, vec_len (name));
  vec_free (name);
  mp->is_add = is_add;
  mp->cir = ntohl (cir);
  mp->eir = ntohl (eir);
  mp->cb = clib_net_to_host_u64 (cb);
  mp->eb = clib_net_to_host_u64 (eb);
  mp->rate_type = rate_type;
  mp->round_type = round_type;
  mp->type = type;
  mp->conform_action_type = conform_action.action_type;
  mp->conform_dscp = conform_action.dscp;
  mp->exceed_action_type = exceed_action.action_type;
  mp->exceed_dscp = exceed_action.dscp;
  mp->violate_action_type = violate_action.action_type;
  mp->violate_dscp = violate_action.dscp;
  mp->color_aware = color_aware;

  S (mp);
  W (ret);
  return ret;
}

static int
api_policer_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_policer_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u8 *match_name = 0;
  u8 match_name_valid = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "name %s", &match_name))
	{
	  vec_add1 (match_name, 0);
	  match_name_valid = 1;
	}
      else
	break;
    }

  M (POLICER_DUMP, mp);
  mp->match_name_valid = match_name_valid;
  clib_memcpy (mp->match_name, match_name, vec_len (match_name));
  vec_free (match_name);
  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_policer_classify_set_interface (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_policer_classify_set_interface_t *mp;
  u32 sw_if_index;
  int sw_if_index_set;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  u32 l2_table_index = ~0;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
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

  M (POLICER_CLASSIFY_SET_INTERFACE, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->ip4_table_index = ntohl (ip4_table_index);
  mp->ip6_table_index = ntohl (ip6_table_index);
  mp->l2_table_index = ntohl (l2_table_index);
  mp->is_add = is_add;

  S (mp);
  W (ret);
  return ret;
}

static int
api_policer_classify_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_policer_classify_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u8 type = POLICER_CLASSIFY_N_TABLES;
  int ret;

  if (unformat (i, "type %U", unformat_policer_classify_table_type, &type))
    ;
  else
    {
      errmsg ("classify table type must be specified");
      return -99;
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "%10s%20s", "Intfc idx", "Classify table");
    }

  M (POLICER_CLASSIFY_DUMP, mp);
  mp->type = type;
  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_netmap_create (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_netmap_create_t *mp;
  u8 *if_name = 0;
  u8 hw_addr[6];
  u8 random_hw_addr = 1;
  u8 is_pipe = 0;
  u8 is_master = 0;
  int ret;

  clib_memset (hw_addr, 0, sizeof (hw_addr));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
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

  if (!vec_len (if_name))
    {
      errmsg ("interface name must be specified");
      return -99;
    }

  if (vec_len (if_name) > 64)
    {
      errmsg ("interface name too long");
      return -99;
    }

  M (NETMAP_CREATE, mp);

  clib_memcpy (mp->netmap_if_name, if_name, vec_len (if_name));
  clib_memcpy (mp->hw_addr, hw_addr, 6);
  mp->use_random_hw_addr = random_hw_addr;
  mp->is_pipe = is_pipe;
  mp->is_master = is_master;
  vec_free (if_name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_netmap_delete (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_netmap_delete_t *mp;
  u8 *if_name = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "name %s", &if_name))
	vec_add1 (if_name, 0);
      else
	break;
    }

  if (!vec_len (if_name))
    {
      errmsg ("interface name must be specified");
      return -99;
    }

  if (vec_len (if_name) > 64)
    {
      errmsg ("interface name too long");
      return -99;
    }

  M (NETMAP_DELETE, mp);

  clib_memcpy (mp->netmap_if_name, if_name, vec_len (if_name));
  vec_free (if_name);

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_mpls_fib_path_print (vat_main_t * vam, vl_api_fib_path_t * fp)
{
  if (fp->afi == IP46_TYPE_IP6)
    print (vam->ofp,
	   "  weight %d, sw_if_index %d, is_local %d, is_drop %d, "
	   "is_unreach %d, is_prohitbit %d, afi %d, next_hop %U",
	   fp->weight, ntohl (fp->sw_if_index), fp->is_local,
	   fp->is_drop, fp->is_unreach, fp->is_prohibit, fp->afi,
	   format_ip6_address, fp->next_hop);
  else if (fp->afi == IP46_TYPE_IP4)
    print (vam->ofp,
	   "  weight %d, sw_if_index %d, is_local %d, is_drop %d, "
	   "is_unreach %d, is_prohitbit %d, afi %d, next_hop %U",
	   fp->weight, ntohl (fp->sw_if_index), fp->is_local,
	   fp->is_drop, fp->is_unreach, fp->is_prohibit, fp->afi,
	   format_ip4_address, fp->next_hop);
}

static void
vl_api_mpls_fib_path_json_print (vat_json_node_t * node,
				 vl_api_fib_path_t * fp)
{
  struct in_addr ip4;
  struct in6_addr ip6;

  vat_json_object_add_uint (node, "weight", ntohl (fp->weight));
  vat_json_object_add_uint (node, "sw_if_index", ntohl (fp->sw_if_index));
  vat_json_object_add_uint (node, "is_local", fp->is_local);
  vat_json_object_add_uint (node, "is_drop", fp->is_drop);
  vat_json_object_add_uint (node, "is_unreach", fp->is_unreach);
  vat_json_object_add_uint (node, "is_prohibit", fp->is_prohibit);
  vat_json_object_add_uint (node, "next_hop_afi", fp->afi);
  if (fp->afi == IP46_TYPE_IP4)
    {
      clib_memcpy (&ip4, &fp->next_hop, sizeof (ip4));
      vat_json_object_add_ip4 (node, "next_hop", ip4);
    }
  else if (fp->afi == IP46_TYPE_IP6)
    {
      clib_memcpy (&ip6, &fp->next_hop, sizeof (ip6));
      vat_json_object_add_ip6 (node, "next_hop", ip6);
    }
}

static void
vl_api_mpls_tunnel_details_t_handler (vl_api_mpls_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  int count = ntohl (mp->mt_count);
  vl_api_fib_path_t *fp;
  i32 i;

  print (vam->ofp, "[%d]: sw_if_index %d via:",
	 ntohl (mp->mt_tunnel_index), ntohl (mp->mt_sw_if_index));
  fp = mp->mt_paths;
  for (i = 0; i < count; i++)
    {
      vl_api_mpls_fib_path_print (vam, fp);
      fp++;
    }

  print (vam->ofp, "");
}

#define vl_api_mpls_tunnel_details_t_endian vl_noop_handler
#define vl_api_mpls_tunnel_details_t_print vl_noop_handler

static void
vl_api_mpls_tunnel_details_t_handler_json (vl_api_mpls_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;
  int count = ntohl (mp->mt_count);
  vl_api_fib_path_t *fp;
  i32 i;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "tunnel_index",
			    ntohl (mp->mt_tunnel_index));
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->mt_sw_if_index));

  vat_json_object_add_uint (node, "l2_only", mp->mt_l2_only);

  fp = mp->mt_paths;
  for (i = 0; i < count; i++)
    {
      vl_api_mpls_fib_path_json_print (node, fp);
      fp++;
    }
}

static int
api_mpls_tunnel_dump (vat_main_t * vam)
{
  vl_api_mpls_tunnel_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 sw_if_index = ~0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (vam->input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (vam->input, "sw_if_index %d", &sw_if_index))
	;
    }

  print (vam->ofp, "  sw_if_index %d", sw_if_index);

  M (MPLS_TUNNEL_DUMP, mp);
  mp->sw_if_index = htonl (sw_if_index);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

#define vl_api_mpls_fib_details_t_endian vl_noop_handler
#define vl_api_mpls_fib_details_t_print vl_noop_handler


static void
vl_api_mpls_fib_details_t_handler (vl_api_mpls_fib_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  int count = ntohl (mp->count);
  vl_api_fib_path_t *fp;
  int i;

  print (vam->ofp,
	 "table-id %d, label %u, ess_bit %u",
	 ntohl (mp->table_id), ntohl (mp->label), mp->eos_bit);
  fp = mp->path;
  for (i = 0; i < count; i++)
    {
      vl_api_mpls_fib_path_print (vam, fp);
      fp++;
    }
}

static void vl_api_mpls_fib_details_t_handler_json
  (vl_api_mpls_fib_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  int count = ntohl (mp->count);
  vat_json_node_t *node = NULL;
  vl_api_fib_path_t *fp;
  int i;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "table", ntohl (mp->table_id));
  vat_json_object_add_uint (node, "s_bit", mp->eos_bit);
  vat_json_object_add_uint (node, "label", ntohl (mp->label));
  vat_json_object_add_uint (node, "path_count", count);
  fp = mp->path;
  for (i = 0; i < count; i++)
    {
      vl_api_mpls_fib_path_json_print (node, fp);
      fp++;
    }
}

static int
api_mpls_fib_dump (vat_main_t * vam)
{
  vl_api_mpls_fib_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  M (MPLS_FIB_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

#define vl_api_ip_fib_details_t_endian vl_noop_handler
#define vl_api_ip_fib_details_t_print vl_noop_handler

static void
vl_api_ip_fib_details_t_handler (vl_api_ip_fib_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  int count = ntohl (mp->count);
  vl_api_fib_path_t *fp;
  int i;

  print (vam->ofp,
	 "table-id %d, prefix %U/%d stats-index %d",
	 ntohl (mp->table_id), format_ip4_address, mp->address,
	 mp->address_length, ntohl (mp->stats_index));
  fp = mp->path;
  for (i = 0; i < count; i++)
    {
      if (fp->afi == IP46_TYPE_IP6)
	print (vam->ofp,
	       "  weight %d, sw_if_index %d, is_local %d, is_drop %d, "
	       "is_unreach %d, is_prohitbit %d, afi %d, next_hop %U, "
	       "next_hop_table %d",
	       ntohl (fp->weight), ntohl (fp->sw_if_index), fp->is_local,
	       fp->is_drop, fp->is_unreach, fp->is_prohibit, fp->afi,
	       format_ip6_address, fp->next_hop, ntohl (fp->table_id));
      else if (fp->afi == IP46_TYPE_IP4)
	print (vam->ofp,
	       "  weight %d, sw_if_index %d, is_local %d, is_drop %d, "
	       "is_unreach %d, is_prohitbit %d, afi %d, next_hop %U, "
	       "next_hop_table %d",
	       ntohl (fp->weight), ntohl (fp->sw_if_index), fp->is_local,
	       fp->is_drop, fp->is_unreach, fp->is_prohibit, fp->afi,
	       format_ip4_address, fp->next_hop, ntohl (fp->table_id));
      fp++;
    }
}

static void vl_api_ip_fib_details_t_handler_json
  (vl_api_ip_fib_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  int count = ntohl (mp->count);
  vat_json_node_t *node = NULL;
  struct in_addr ip4;
  struct in6_addr ip6;
  vl_api_fib_path_t *fp;
  int i;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "table", ntohl (mp->table_id));
  clib_memcpy (&ip4, &mp->address, sizeof (ip4));
  vat_json_object_add_ip4 (node, "prefix", ip4);
  vat_json_object_add_uint (node, "mask_length", mp->address_length);
  vat_json_object_add_uint (node, "path_count", count);
  fp = mp->path;
  for (i = 0; i < count; i++)
    {
      vat_json_object_add_uint (node, "weight", ntohl (fp->weight));
      vat_json_object_add_uint (node, "sw_if_index", ntohl (fp->sw_if_index));
      vat_json_object_add_uint (node, "is_local", fp->is_local);
      vat_json_object_add_uint (node, "is_drop", fp->is_drop);
      vat_json_object_add_uint (node, "is_unreach", fp->is_unreach);
      vat_json_object_add_uint (node, "is_prohibit", fp->is_prohibit);
      vat_json_object_add_uint (node, "next_hop_afi", fp->afi);
      if (fp->afi == IP46_TYPE_IP4)
	{
	  clib_memcpy (&ip4, &fp->next_hop, sizeof (ip4));
	  vat_json_object_add_ip4 (node, "next_hop", ip4);
	}
      else if (fp->afi == IP46_TYPE_IP6)
	{
	  clib_memcpy (&ip6, &fp->next_hop, sizeof (ip6));
	  vat_json_object_add_ip6 (node, "next_hop", ip6);
	}
    }
}

static int
api_ip_fib_dump (vat_main_t * vam)
{
  vl_api_ip_fib_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  M (IP_FIB_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_ip_mfib_dump (vat_main_t * vam)
{
  vl_api_ip_mfib_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  M (IP_MFIB_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void vl_api_ip_neighbor_details_t_handler
  (vl_api_ip_neighbor_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%c %U %U",
	 (mp->is_static) ? 'S' : 'D',
	 format_ethernet_address, &mp->mac_address,
	 (mp->is_ipv6) ? format_ip6_address : format_ip4_address,
	 &mp->ip_address);
}

static void vl_api_ip_neighbor_details_t_handler_json
  (vl_api_ip_neighbor_details_t * mp)
{

  vat_main_t *vam = &vat_main;
  vat_json_node_t *node;
  struct in_addr ip4;
  struct in6_addr ip6;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_string_copy (node, "flag",
				   (mp->is_static) ? (u8 *) "static" : (u8 *)
				   "dynamic");

  vat_json_object_add_string_copy (node, "link_layer",
				   format (0, "%U", format_ethernet_address,
					   &mp->mac_address));

  if (mp->is_ipv6)
    {
      clib_memcpy (&ip6, &mp->ip_address, sizeof (ip6));
      vat_json_object_add_ip6 (node, "ip_address", ip6);
    }
  else
    {
      clib_memcpy (&ip4, &mp->ip_address, sizeof (ip4));
      vat_json_object_add_ip4 (node, "ip_address", ip4);
    }
}

static int
api_ip_neighbor_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_neighbor_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u8 is_ipv6 = 0;
  u32 sw_if_index = ~0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "ip6"))
	is_ipv6 = 1;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (IP_NEIGHBOR_DUMP, mp);
  mp->is_ipv6 = (u8) is_ipv6;
  mp->sw_if_index = ntohl (sw_if_index);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

#define vl_api_ip6_fib_details_t_endian vl_noop_handler
#define vl_api_ip6_fib_details_t_print vl_noop_handler

static void
vl_api_ip6_fib_details_t_handler (vl_api_ip6_fib_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  int count = ntohl (mp->count);
  vl_api_fib_path_t *fp;
  int i;

  print (vam->ofp,
	 "table-id %d, prefix %U/%d stats-index %d",
	 ntohl (mp->table_id), format_ip6_address, mp->address,
	 mp->address_length, ntohl (mp->stats_index));
  fp = mp->path;
  for (i = 0; i < count; i++)
    {
      if (fp->afi == IP46_TYPE_IP6)
	print (vam->ofp,
	       "  weight %d, sw_if_index %d, is_local %d, is_drop %d, "
	       "is_unreach %d, is_prohitbit %d, afi %d, next_hop %U",
	       ntohl (fp->weight), ntohl (fp->sw_if_index), fp->is_local,
	       fp->is_drop, fp->is_unreach, fp->is_prohibit, fp->afi,
	       format_ip6_address, fp->next_hop);
      else if (fp->afi == IP46_TYPE_IP4)
	print (vam->ofp,
	       "  weight %d, sw_if_index %d, is_local %d, is_drop %d, "
	       "is_unreach %d, is_prohitbit %d, afi %d, next_hop %U",
	       ntohl (fp->weight), ntohl (fp->sw_if_index), fp->is_local,
	       fp->is_drop, fp->is_unreach, fp->is_prohibit, fp->afi,
	       format_ip4_address, fp->next_hop);
      fp++;
    }
}

static void vl_api_ip6_fib_details_t_handler_json
  (vl_api_ip6_fib_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  int count = ntohl (mp->count);
  vat_json_node_t *node = NULL;
  struct in_addr ip4;
  struct in6_addr ip6;
  vl_api_fib_path_t *fp;
  int i;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "table", ntohl (mp->table_id));
  clib_memcpy (&ip6, &mp->address, sizeof (ip6));
  vat_json_object_add_ip6 (node, "prefix", ip6);
  vat_json_object_add_uint (node, "mask_length", mp->address_length);
  vat_json_object_add_uint (node, "path_count", count);
  fp = mp->path;
  for (i = 0; i < count; i++)
    {
      vat_json_object_add_uint (node, "weight", ntohl (fp->weight));
      vat_json_object_add_uint (node, "sw_if_index", ntohl (fp->sw_if_index));
      vat_json_object_add_uint (node, "is_local", fp->is_local);
      vat_json_object_add_uint (node, "is_drop", fp->is_drop);
      vat_json_object_add_uint (node, "is_unreach", fp->is_unreach);
      vat_json_object_add_uint (node, "is_prohibit", fp->is_prohibit);
      vat_json_object_add_uint (node, "next_hop_afi", fp->afi);
      if (fp->afi == IP46_TYPE_IP4)
	{
	  clib_memcpy (&ip4, &fp->next_hop, sizeof (ip4));
	  vat_json_object_add_ip4 (node, "next_hop", ip4);
	}
      else if (fp->afi == IP46_TYPE_IP6)
	{
	  clib_memcpy (&ip6, &fp->next_hop, sizeof (ip6));
	  vat_json_object_add_ip6 (node, "next_hop", ip6);
	}
    }
}

static int
api_ip6_fib_dump (vat_main_t * vam)
{
  vl_api_ip6_fib_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  M (IP6_FIB_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_ip6_mfib_dump (vat_main_t * vam)
{
  vl_api_ip6_mfib_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  M (IP6_MFIB_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

int
api_classify_table_ids (vat_main_t * vam)
{
  vl_api_classify_table_ids_t *mp;
  int ret;

  /* Construct the API message */
  M (CLASSIFY_TABLE_IDS, mp);
  mp->context = 0;

  S (mp);
  W (ret);
  return ret;
}

int
api_classify_table_by_interface (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_classify_table_by_interface_t *mp;

  u32 sw_if_index = ~0;
  int ret;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (input, "sw_if_index %d", &sw_if_index))
	;
      else
	break;
    }
  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (CLASSIFY_TABLE_BY_INTERFACE, mp);
  mp->context = 0;
  mp->sw_if_index = ntohl (sw_if_index);

  S (mp);
  W (ret);
  return ret;
}

int
api_classify_table_info (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_classify_table_info_t *mp;

  u32 table_id = ~0;
  int ret;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table_id %d", &table_id))
	;
      else
	break;
    }
  if (table_id == ~0)
    {
      errmsg ("missing table id");
      return -99;
    }

  /* Construct the API message */
  M (CLASSIFY_TABLE_INFO, mp);
  mp->context = 0;
  mp->table_id = ntohl (table_id);

  S (mp);
  W (ret);
  return ret;
}

int
api_classify_session_dump (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_classify_session_dump_t *mp;
  vl_api_control_ping_t *mp_ping;

  u32 table_id = ~0;
  int ret;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table_id %d", &table_id))
	;
      else
	break;
    }
  if (table_id == ~0)
    {
      errmsg ("missing table id");
      return -99;
    }

  /* Construct the API message */
  M (CLASSIFY_SESSION_DUMP, mp);
  mp->context = 0;
  mp->table_id = ntohl (table_id);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void
vl_api_ipfix_exporter_details_t_handler (vl_api_ipfix_exporter_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "collector_address %U, collector_port %d, "
	 "src_address %U, vrf_id %d, path_mtu %u, "
	 "template_interval %u, udp_checksum %d",
	 format_ip4_address, mp->collector_address,
	 ntohs (mp->collector_port),
	 format_ip4_address, mp->src_address,
	 ntohl (mp->vrf_id), ntohl (mp->path_mtu),
	 ntohl (mp->template_interval), mp->udp_checksum);

  vam->retval = 0;
  vam->result_ready = 1;
}

static void
  vl_api_ipfix_exporter_details_t_handler_json
  (vl_api_ipfix_exporter_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;
  struct in_addr collector_address;
  struct in_addr src_address;

  vat_json_init_object (&node);
  clib_memcpy (&collector_address, &mp->collector_address,
	       sizeof (collector_address));
  vat_json_object_add_ip4 (&node, "collector_address", collector_address);
  vat_json_object_add_uint (&node, "collector_port",
			    ntohs (mp->collector_port));
  clib_memcpy (&src_address, &mp->src_address, sizeof (src_address));
  vat_json_object_add_ip4 (&node, "src_address", src_address);
  vat_json_object_add_int (&node, "vrf_id", ntohl (mp->vrf_id));
  vat_json_object_add_uint (&node, "path_mtu", ntohl (mp->path_mtu));
  vat_json_object_add_uint (&node, "template_interval",
			    ntohl (mp->template_interval));
  vat_json_object_add_int (&node, "udp_checksum", mp->udp_checksum);

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);
  vam->retval = 0;
  vam->result_ready = 1;
}

int
api_ipfix_exporter_dump (vat_main_t * vam)
{
  vl_api_ipfix_exporter_dump_t *mp;
  int ret;

  /* Construct the API message */
  M (IPFIX_EXPORTER_DUMP, mp);
  mp->context = 0;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ipfix_classify_stream_dump (vat_main_t * vam)
{
  vl_api_ipfix_classify_stream_dump_t *mp;
  int ret;

  /* Construct the API message */
  M (IPFIX_CLASSIFY_STREAM_DUMP, mp);
  mp->context = 0;

  S (mp);
  W (ret);
  return ret;
  /* NOTREACHED */
  return 0;
}

static void
  vl_api_ipfix_classify_stream_details_t_handler
  (vl_api_ipfix_classify_stream_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  print (vam->ofp, "domain_id %d, src_port %d",
	 ntohl (mp->domain_id), ntohs (mp->src_port));
  vam->retval = 0;
  vam->result_ready = 1;
}

static void
  vl_api_ipfix_classify_stream_details_t_handler_json
  (vl_api_ipfix_classify_stream_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_uint (&node, "domain_id", ntohl (mp->domain_id));
  vat_json_object_add_uint (&node, "src_port", ntohs (mp->src_port));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);
  vam->retval = 0;
  vam->result_ready = 1;
}

static int
api_ipfix_classify_table_dump (vat_main_t * vam)
{
  vl_api_ipfix_classify_table_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%15s%15s%20s", "table_id", "ip_version",
	     "transport_protocol");
    }

  /* Construct the API message */
  M (IPFIX_CLASSIFY_TABLE_DUMP, mp);

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void
  vl_api_ipfix_classify_table_details_t_handler
  (vl_api_ipfix_classify_table_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  print (vam->ofp, "%15d%15d%20d", ntohl (mp->table_id), mp->ip_version,
	 mp->transport_protocol);
}

static void
  vl_api_ipfix_classify_table_details_t_handler_json
  (vl_api_ipfix_classify_table_details_t * mp)
{
  vat_json_node_t *node = NULL;
  vat_main_t *vam = &vat_main;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }

  node = vat_json_array_add (&vam->json_tree);
  vat_json_init_object (node);

  vat_json_object_add_uint (node, "table_id", ntohl (mp->table_id));
  vat_json_object_add_uint (node, "ip_version", mp->ip_version);
  vat_json_object_add_uint (node, "transport_protocol",
			    mp->transport_protocol);
}

static int
api_sw_interface_span_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_span_enable_disable_t *mp;
  u32 src_sw_if_index = ~0;
  u32 dst_sw_if_index = ~0;
  u8 state = 3;
  int ret;
  u8 is_l2 = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (i, "src %U", api_unformat_sw_if_index, vam, &src_sw_if_index))
	;
      else if (unformat (i, "src_sw_if_index %d", &src_sw_if_index))
	;
      else
	if (unformat
	    (i, "dst %U", api_unformat_sw_if_index, vam, &dst_sw_if_index))
	;
      else if (unformat (i, "dst_sw_if_index %d", &dst_sw_if_index))
	;
      else if (unformat (i, "disable"))
	state = 0;
      else if (unformat (i, "rx"))
	state = 1;
      else if (unformat (i, "tx"))
	state = 2;
      else if (unformat (i, "both"))
	state = 3;
      else if (unformat (i, "l2"))
	is_l2 = 1;
      else
	break;
    }

  M (SW_INTERFACE_SPAN_ENABLE_DISABLE, mp);

  mp->sw_if_index_from = htonl (src_sw_if_index);
  mp->sw_if_index_to = htonl (dst_sw_if_index);
  mp->state = state;
  mp->is_l2 = is_l2;

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_sw_interface_span_details_t_handler (vl_api_sw_interface_span_details_t
					    * mp)
{
  vat_main_t *vam = &vat_main;
  u8 *sw_if_from_name = 0;
  u8 *sw_if_to_name = 0;
  u32 sw_if_index_from = ntohl (mp->sw_if_index_from);
  u32 sw_if_index_to = ntohl (mp->sw_if_index_to);
  char *states[] = { "none", "rx", "tx", "both" };
  hash_pair_t *p;

  /* *INDENT-OFF* */
  hash_foreach_pair (p, vam->sw_if_index_by_interface_name,
  ({
    if ((u32) p->value[0] == sw_if_index_from)
      {
        sw_if_from_name = (u8 *)(p->key);
        if (sw_if_to_name)
          break;
      }
    if ((u32) p->value[0] == sw_if_index_to)
      {
        sw_if_to_name = (u8 *)(p->key);
        if (sw_if_from_name)
          break;
      }
  }));
  /* *INDENT-ON* */
  print (vam->ofp, "%20s => %20s (%s) %s",
	 sw_if_from_name, sw_if_to_name, states[mp->state],
	 mp->is_l2 ? "l2" : "device");
}

static void
  vl_api_sw_interface_span_details_t_handler_json
  (vl_api_sw_interface_span_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;
  u8 *sw_if_from_name = 0;
  u8 *sw_if_to_name = 0;
  u32 sw_if_index_from = ntohl (mp->sw_if_index_from);
  u32 sw_if_index_to = ntohl (mp->sw_if_index_to);
  hash_pair_t *p;

  /* *INDENT-OFF* */
  hash_foreach_pair (p, vam->sw_if_index_by_interface_name,
  ({
    if ((u32) p->value[0] == sw_if_index_from)
      {
        sw_if_from_name = (u8 *)(p->key);
        if (sw_if_to_name)
          break;
      }
    if ((u32) p->value[0] == sw_if_index_to)
      {
        sw_if_to_name = (u8 *)(p->key);
        if (sw_if_from_name)
          break;
      }
  }));
  /* *INDENT-ON* */

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "src-if-index", sw_if_index_from);
  vat_json_object_add_string_copy (node, "src-if-name", sw_if_from_name);
  vat_json_object_add_uint (node, "dst-if-index", sw_if_index_to);
  if (0 != sw_if_to_name)
    {
      vat_json_object_add_string_copy (node, "dst-if-name", sw_if_to_name);
    }
  vat_json_object_add_uint (node, "state", mp->state);
  vat_json_object_add_uint (node, "is-l2", mp->is_l2);
}

static int
api_sw_interface_span_dump (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_sw_interface_span_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u8 is_l2 = 0;
  int ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "l2"))
	is_l2 = 1;
      else
	break;
    }

  M (SW_INTERFACE_SPAN_DUMP, mp);
  mp->is_l2 = is_l2;
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

int
api_pg_create_interface (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_pg_create_interface_t *mp;

  u32 if_id = ~0;
  int ret;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "if_id %d", &if_id))
	;
      else
	break;
    }
  if (if_id == ~0)
    {
      errmsg ("missing pg interface index");
      return -99;
    }

  /* Construct the API message */
  M (PG_CREATE_INTERFACE, mp);
  mp->context = 0;
  mp->interface_id = ntohl (if_id);

  S (mp);
  W (ret);
  return ret;
}

int
api_pg_capture (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_pg_capture_t *mp;

  u32 if_id = ~0;
  u8 enable = 1;
  u32 count = 1;
  u8 pcap_file_set = 0;
  u8 *pcap_file = 0;
  int ret;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
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
  if (if_id == ~0)
    {
      errmsg ("missing pg interface index");
      return -99;
    }
  if (pcap_file_set > 0)
    {
      if (vec_len (pcap_file) > 255)
	{
	  errmsg ("pcap file name is too long");
	  return -99;
	}
    }

  u32 name_len = vec_len (pcap_file);
  /* Construct the API message */
  M (PG_CAPTURE, mp);
  mp->context = 0;
  mp->interface_id = ntohl (if_id);
  mp->is_enabled = enable;
  mp->count = ntohl (count);
  mp->pcap_name_length = ntohl (name_len);
  if (pcap_file_set != 0)
    {
      clib_memcpy (mp->pcap_file_name, pcap_file, name_len);
    }
  vec_free (pcap_file);

  S (mp);
  W (ret);
  return ret;
}

int
api_pg_enable_disable (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_pg_enable_disable_t *mp;

  u8 enable = 1;
  u8 stream_name_set = 0;
  u8 *stream_name = 0;
  int ret;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "stream %s", &stream_name))
	stream_name_set = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else
	break;
    }

  if (stream_name_set > 0)
    {
      if (vec_len (stream_name) > 255)
	{
	  errmsg ("stream name too long");
	  return -99;
	}
    }

  u32 name_len = vec_len (stream_name);
  /* Construct the API message */
  M (PG_ENABLE_DISABLE, mp);
  mp->context = 0;
  mp->is_enabled = enable;
  if (stream_name_set != 0)
    {
      mp->stream_name_length = ntohl (name_len);
      clib_memcpy (mp->stream_name, stream_name, name_len);
    }
  vec_free (stream_name);

  S (mp);
  W (ret);
  return ret;
}

int
api_ip_source_and_port_range_check_add_del (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_ip_source_and_port_range_check_add_del_t *mp;

  u16 *low_ports = 0;
  u16 *high_ports = 0;
  u16 this_low;
  u16 this_hi;
  ip4_address_t ip4_addr;
  ip6_address_t ip6_addr;
  u32 length;
  u32 tmp, tmp2;
  u8 prefix_set = 0;
  u32 vrf_id = ~0;
  u8 is_add = 1;
  u8 is_ipv6 = 0;
  int ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U/%d", unformat_ip4_address, &ip4_addr, &length))
	{
	  prefix_set = 1;
	}
      else
	if (unformat
	    (input, "%U/%d", unformat_ip6_address, &ip6_addr, &length))
	{
	  prefix_set = 1;
	  is_ipv6 = 1;
	}
      else if (unformat (input, "vrf %d", &vrf_id))
	;
      else if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "port %d", &tmp))
	{
	  if (tmp == 0 || tmp > 65535)
	    {
	      errmsg ("port %d out of range", tmp);
	      return -99;
	    }
	  this_low = tmp;
	  this_hi = this_low + 1;
	  vec_add1 (low_ports, this_low);
	  vec_add1 (high_ports, this_hi);
	}
      else if (unformat (input, "range %d - %d", &tmp, &tmp2))
	{
	  if ((tmp > tmp2) || (tmp == 0) || (tmp2 > 65535))
	    {
	      errmsg ("incorrect range parameters");
	      return -99;
	    }
	  this_low = tmp;
	  /* Note: in debug CLI +1 is added to high before
	     passing to real fn that does "the work"
	     (ip_source_and_port_range_check_add_del).
	     This fn is a wrapper around the binary API fn a
	     control plane will call, which expects this increment
	     to have occurred. Hence letting the binary API control
	     plane fn do the increment for consistency between VAT
	     and other control planes.
	   */
	  this_hi = tmp2;
	  vec_add1 (low_ports, this_low);
	  vec_add1 (high_ports, this_hi);
	}
      else
	break;
    }

  if (prefix_set == 0)
    {
      errmsg ("<address>/<mask> not specified");
      return -99;
    }

  if (vrf_id == ~0)
    {
      errmsg ("VRF ID required, not specified");
      return -99;
    }

  if (vrf_id == 0)
    {
      errmsg
	("VRF ID should not be default. Should be distinct VRF for this purpose.");
      return -99;
    }

  if (vec_len (low_ports) == 0)
    {
      errmsg ("At least one port or port range required");
      return -99;
    }

  M (IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL, mp);

  mp->is_add = is_add;

  if (is_ipv6)
    {
      mp->is_ipv6 = 1;
      clib_memcpy (mp->address, &ip6_addr, sizeof (ip6_addr));
    }
  else
    {
      mp->is_ipv6 = 0;
      clib_memcpy (mp->address, &ip4_addr, sizeof (ip4_addr));
    }

  mp->mask_length = length;
  mp->number_of_ranges = vec_len (low_ports);

  clib_memcpy (mp->low_ports, low_ports, vec_len (low_ports));
  vec_free (low_ports);

  clib_memcpy (mp->high_ports, high_ports, vec_len (high_ports));
  vec_free (high_ports);

  mp->vrf_id = ntohl (vrf_id);

  S (mp);
  W (ret);
  return ret;
}

int
api_ip_source_and_port_range_check_interface_add_del (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_ip_source_and_port_range_check_interface_add_del_t *mp;
  u32 sw_if_index = ~0;
  int vrf_set = 0;
  u32 tcp_out_vrf_id = ~0, udp_out_vrf_id = ~0;
  u32 tcp_in_vrf_id = ~0, udp_in_vrf_id = ~0;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (input, "tcp-out-vrf %d", &tcp_out_vrf_id))
	vrf_set = 1;
      else if (unformat (input, "udp-out-vrf %d", &udp_out_vrf_id))
	vrf_set = 1;
      else if (unformat (input, "tcp-in-vrf %d", &tcp_in_vrf_id))
	vrf_set = 1;
      else if (unformat (input, "udp-in-vrf %d", &udp_in_vrf_id))
	vrf_set = 1;
      else if (unformat (input, "del"))
	is_add = 0;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("Interface required but not specified");
      return -99;
    }

  if (vrf_set == 0)
    {
      errmsg ("VRF ID required but not specified");
      return -99;
    }

  if (tcp_out_vrf_id == 0
      || udp_out_vrf_id == 0 || tcp_in_vrf_id == 0 || udp_in_vrf_id == 0)
    {
      errmsg
	("VRF ID should not be default. Should be distinct VRF for this purpose.");
      return -99;
    }

  /* Construct the API message */
  M (IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_add = is_add;
  mp->tcp_out_vrf_id = ntohl (tcp_out_vrf_id);
  mp->udp_out_vrf_id = ntohl (udp_out_vrf_id);
  mp->tcp_in_vrf_id = ntohl (tcp_in_vrf_id);
  mp->udp_in_vrf_id = ntohl (udp_in_vrf_id);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_ipsec_gre_add_del_tunnel (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_gre_add_del_tunnel_t *mp;
  u32 local_sa_id = 0;
  u32 remote_sa_id = 0;
  ip4_address_t src_address;
  ip4_address_t dst_address;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "local_sa %d", &local_sa_id))
	;
      else if (unformat (i, "remote_sa %d", &remote_sa_id))
	;
      else if (unformat (i, "src %U", unformat_ip4_address, &src_address))
	;
      else if (unformat (i, "dst %U", unformat_ip4_address, &dst_address))
	;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IPSEC_GRE_ADD_DEL_TUNNEL, mp);

  mp->local_sa_id = ntohl (local_sa_id);
  mp->remote_sa_id = ntohl (remote_sa_id);
  clib_memcpy (mp->src_address, &src_address, sizeof (src_address));
  clib_memcpy (mp->dst_address, &dst_address, sizeof (dst_address));
  mp->is_add = is_add;

  S (mp);
  W (ret);
  return ret;
}

static int
api_set_punt (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_set_punt_t *mp;
  u32 ipv = ~0;
  u32 protocol = ~0;
  u32 port = ~0;
  int is_add = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "ip %d", &ipv))
	;
      else if (unformat (i, "protocol %d", &protocol))
	;
      else if (unformat (i, "port %d", &port))
	;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (SET_PUNT, mp);

  mp->is_add = (u8) is_add;
  mp->punt.ipv = (u8) ipv;
  mp->punt.l4_protocol = (u8) protocol;
  mp->punt.l4_port = htons ((u16) port);

  S (mp);
  W (ret);
  return ret;
}

static void vl_api_ipsec_gre_tunnel_details_t_handler
  (vl_api_ipsec_gre_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%11d%15U%15U%14d%14d",
	 ntohl (mp->sw_if_index),
	 format_ip4_address, &mp->src_address,
	 format_ip4_address, &mp->dst_address,
	 ntohl (mp->local_sa_id), ntohl (mp->remote_sa_id));
}

static void vl_api_ipsec_gre_tunnel_details_t_handler_json
  (vl_api_ipsec_gre_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;
  struct in_addr ip4;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  clib_memcpy (&ip4, &mp->src_address, sizeof (ip4));
  vat_json_object_add_ip4 (node, "src_address", ip4);
  clib_memcpy (&ip4, &mp->dst_address, sizeof (ip4));
  vat_json_object_add_ip4 (node, "dst_address", ip4);
  vat_json_object_add_uint (node, "local_sa_id", ntohl (mp->local_sa_id));
  vat_json_object_add_uint (node, "remote_sa_id", ntohl (mp->remote_sa_id));
}

static int
api_ipsec_gre_tunnel_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_gre_tunnel_dump_t *mp;
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
      print (vam->ofp, "%11s%15s%15s%14s%14s",
	     "sw_if_index", "src_address", "dst_address",
	     "local_sa_id", "remote_sa_id");
    }

  /* Get list of gre-tunnel interfaces */
  M (IPSEC_GRE_TUNNEL_DUMP, mp);

  mp->sw_if_index = htonl (sw_if_index);

  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_delete_subif (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_delete_subif_t *mp;
  u32 sw_if_index = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (DELETE_SUBIF, mp);
  mp->sw_if_index = ntohl (sw_if_index);

  S (mp);
  W (ret);
  return ret;
}

#define foreach_pbb_vtr_op      \
_("disable",  L2_VTR_DISABLED)  \
_("pop",  L2_VTR_POP_2)         \
_("push",  L2_VTR_PUSH_2)

static int
api_l2_interface_pbb_tag_rewrite (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_l2_interface_pbb_tag_rewrite_t *mp;
  u32 sw_if_index = ~0, vtr_op = ~0;
  u16 outer_tag = ~0;
  u8 dmac[6], smac[6];
  u8 dmac_set = 0, smac_set = 0;
  u16 vlanid = 0;
  u32 sid = ~0;
  u32 tmp;
  int ret;

  /* Shut up coverity */
  clib_memset (dmac, 0, sizeof (dmac));
  clib_memset (smac, 0, sizeof (smac));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "vtr_op %d", &vtr_op))
	;
#define _(n,v) else if (unformat(i, n)) {vtr_op = v;}
      foreach_pbb_vtr_op
#undef _
	else if (unformat (i, "translate_pbb_stag"))
	{
	  if (unformat (i, "%d", &tmp))
	    {
	      vtr_op = L2_VTR_TRANSLATE_2_1;
	      outer_tag = tmp;
	    }
	  else
	    {
	      errmsg
		("translate_pbb_stag operation requires outer tag definition");
	      return -99;
	    }
	}
      else if (unformat (i, "dmac %U", unformat_ethernet_address, dmac))
	dmac_set++;
      else if (unformat (i, "smac %U", unformat_ethernet_address, smac))
	smac_set++;
      else if (unformat (i, "sid %d", &sid))
	;
      else if (unformat (i, "vlanid %d", &tmp))
	vlanid = tmp;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if ((sw_if_index == ~0) || (vtr_op == ~0))
    {
      errmsg ("missing sw_if_index or vtr operation");
      return -99;
    }
  if (((vtr_op == L2_VTR_PUSH_2) || (vtr_op == L2_VTR_TRANSLATE_2_2))
      && ((dmac_set == 0) || (smac_set == 0) || (sid == ~0)))
    {
      errmsg
	("push and translate_qinq operations require dmac, smac, sid and optionally vlanid");
      return -99;
    }

  M (L2_INTERFACE_PBB_TAG_REWRITE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->vtr_op = ntohl (vtr_op);
  mp->outer_tag = ntohs (outer_tag);
  clib_memcpy (mp->b_dmac, dmac, sizeof (dmac));
  clib_memcpy (mp->b_smac, smac, sizeof (smac));
  mp->b_vlanid = ntohs (vlanid);
  mp->i_sid = ntohl (sid);

  S (mp);
  W (ret);
  return ret;
}

static int
api_flow_classify_set_interface (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_flow_classify_set_interface_t *mp;
  u32 sw_if_index;
  int sw_if_index_set;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "ip4-table %d", &ip4_table_index))
	;
      else if (unformat (i, "ip6-table %d", &ip6_table_index))
	;
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

  M (FLOW_CLASSIFY_SET_INTERFACE, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->ip4_table_index = ntohl (ip4_table_index);
  mp->ip6_table_index = ntohl (ip6_table_index);
  mp->is_add = is_add;

  S (mp);
  W (ret);
  return ret;
}

static int
api_flow_classify_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_flow_classify_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u8 type = FLOW_CLASSIFY_N_TABLES;
  int ret;

  if (unformat (i, "type %U", unformat_flow_classify_table_type, &type))
    ;
  else
    {
      errmsg ("classify table type must be specified");
      return -99;
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "%10s%20s", "Intfc idx", "Classify table");
    }

  M (FLOW_CLASSIFY_DUMP, mp);
  mp->type = type;
  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_feature_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_feature_enable_disable_t *mp;
  u8 *arc_name = 0;
  u8 *feature_name = 0;
  u32 sw_if_index = ~0;
  u8 enable = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "arc_name %s", &arc_name))
	;
      else if (unformat (i, "feature_name %s", &feature_name))
	;
      else
	if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "disable"))
	enable = 0;
      else
	break;
    }

  if (arc_name == 0)
    {
      errmsg ("missing arc name");
      return -99;
    }
  if (vec_len (arc_name) > 63)
    {
      errmsg ("arc name too long");
    }

  if (feature_name == 0)
    {
      errmsg ("missing feature name");
      return -99;
    }
  if (vec_len (feature_name) > 63)
    {
      errmsg ("feature name too long");
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (FEATURE_ENABLE_DISABLE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable = enable;
  clib_memcpy (mp->arc_name, arc_name, vec_len (arc_name));
  clib_memcpy (mp->feature_name, feature_name, vec_len (feature_name));
  vec_free (arc_name);
  vec_free (feature_name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_sw_interface_tag_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_tag_add_del_t *mp;
  u32 sw_if_index = ~0;
  u8 *tag = 0;
  u8 enable = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "tag %s", &tag))
	;
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "del"))
	enable = 0;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (enable && (tag == 0))
    {
      errmsg ("no tag specified");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_TAG_ADD_DEL, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_add = enable;
  if (enable)
    strncpy ((char *) mp->tag, (char *) tag, ARRAY_LEN (mp->tag) - 1);
  vec_free (tag);

  S (mp);
  W (ret);
  return ret;
}

static void vl_api_l2_xconnect_details_t_handler
  (vl_api_l2_xconnect_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%15d%15d",
	 ntohl (mp->rx_sw_if_index), ntohl (mp->tx_sw_if_index));
}

static void vl_api_l2_xconnect_details_t_handler_json
  (vl_api_l2_xconnect_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "rx_sw_if_index",
			    ntohl (mp->rx_sw_if_index));
  vat_json_object_add_uint (node, "tx_sw_if_index",
			    ntohl (mp->tx_sw_if_index));
}

static int
api_l2_xconnect_dump (vat_main_t * vam)
{
  vl_api_l2_xconnect_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%15s%15s", "rx_sw_if_index", "tx_sw_if_index");
    }

  M (L2_XCONNECT_DUMP, mp);

  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_hw_interface_set_mtu (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_hw_interface_set_mtu_t *mp;
  u32 sw_if_index = ~0;
  u32 mtu = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "mtu %d", &mtu))
	;
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (mtu == 0)
    {
      errmsg ("no mtu specified");
      return -99;
    }

  /* Construct the API message */
  M (HW_INTERFACE_SET_MTU, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->mtu = ntohs ((u16) mtu);

  S (mp);
  W (ret);
  return ret;
}

static int
api_p2p_ethernet_add (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_p2p_ethernet_add_t *mp;
  u32 parent_if_index = ~0;
  u32 sub_id = ~0;
  u8 remote_mac[6];
  u8 mac_set = 0;
  int ret;

  clib_memset (remote_mac, 0, sizeof (remote_mac));
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &parent_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &parent_if_index))
	;
      else
	if (unformat
	    (i, "remote_mac %U", unformat_ethernet_address, remote_mac))
	mac_set++;
      else if (unformat (i, "sub_id %d", &sub_id))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (parent_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }
  if (mac_set == 0)
    {
      errmsg ("missing remote mac address");
      return -99;
    }
  if (sub_id == ~0)
    {
      errmsg ("missing sub-interface id");
      return -99;
    }

  M (P2P_ETHERNET_ADD, mp);
  mp->parent_if_index = ntohl (parent_if_index);
  mp->subif_id = ntohl (sub_id);
  clib_memcpy (mp->remote_mac, remote_mac, sizeof (remote_mac));

  S (mp);
  W (ret);
  return ret;
}

static int
api_p2p_ethernet_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_p2p_ethernet_del_t *mp;
  u32 parent_if_index = ~0;
  u8 remote_mac[6];
  u8 mac_set = 0;
  int ret;

  clib_memset (remote_mac, 0, sizeof (remote_mac));
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &parent_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &parent_if_index))
	;
      else
	if (unformat
	    (i, "remote_mac %U", unformat_ethernet_address, remote_mac))
	mac_set++;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (parent_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }
  if (mac_set == 0)
    {
      errmsg ("missing remote mac address");
      return -99;
    }

  M (P2P_ETHERNET_DEL, mp);
  mp->parent_if_index = ntohl (parent_if_index);
  clib_memcpy (mp->remote_mac, remote_mac, sizeof (remote_mac));

  S (mp);
  W (ret);
  return ret;
}

static int
api_lldp_config (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_lldp_config_t *mp;
  int tx_hold = 0;
  int tx_interval = 0;
  u8 *sys_name = NULL;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "system-name %s", &sys_name))
	;
      else if (unformat (i, "tx-hold %d", &tx_hold))
	;
      else if (unformat (i, "tx-interval %d", &tx_interval))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  vec_add1 (sys_name, 0);

  M (LLDP_CONFIG, mp);
  mp->tx_hold = htonl (tx_hold);
  mp->tx_interval = htonl (tx_interval);
  clib_memcpy (mp->system_name, sys_name, vec_len (sys_name));
  vec_free (sys_name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_sw_interface_set_lldp (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_lldp_t *mp;
  u32 sw_if_index = ~0;
  u32 enable = 1;
  u8 *port_desc = NULL, *mgmt_oid = NULL;
  ip4_address_t ip4_addr;
  ip6_address_t ip6_addr;
  int ret;

  clib_memset (&ip4_addr, 0, sizeof (ip4_addr));
  clib_memset (&ip6_addr, 0, sizeof (ip6_addr));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "disable"))
	enable = 0;
      else
	if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "port-desc %s", &port_desc))
	;
      else if (unformat (i, "mgmt-ip4 %U", unformat_ip4_address, &ip4_addr))
	;
      else if (unformat (i, "mgmt-ip6 %U", unformat_ip6_address, &ip6_addr))
	;
      else if (unformat (i, "mgmt-oid %s", &mgmt_oid))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  /* Construct the API message */
  vec_add1 (port_desc, 0);
  vec_add1 (mgmt_oid, 0);
  M (SW_INTERFACE_SET_LLDP, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable = enable;
  clib_memcpy (mp->port_desc, port_desc, vec_len (port_desc));
  clib_memcpy (mp->mgmt_oid, mgmt_oid, vec_len (mgmt_oid));
  clib_memcpy (mp->mgmt_ip4, &ip4_addr, sizeof (ip4_addr));
  clib_memcpy (mp->mgmt_ip6, &ip6_addr, sizeof (ip6_addr));
  vec_free (port_desc);
  vec_free (mgmt_oid);

  S (mp);
  W (ret);
  return ret;
}

static int
api_tcp_configure_src_addresses (vat_main_t * vam)
{
  vl_api_tcp_configure_src_addresses_t *mp;
  unformat_input_t *i = vam->input;
  ip4_address_t v4first, v4last;
  ip6_address_t v6first, v6last;
  u8 range_set = 0;
  u32 vrf_id = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U - %U",
		    unformat_ip4_address, &v4first,
		    unformat_ip4_address, &v4last))
	{
	  if (range_set)
	    {
	      errmsg ("one range per message (range already set)");
	      return -99;
	    }
	  range_set = 1;
	}
      else if (unformat (i, "%U - %U",
			 unformat_ip6_address, &v6first,
			 unformat_ip6_address, &v6last))
	{
	  if (range_set)
	    {
	      errmsg ("one range per message (range already set)");
	      return -99;
	    }
	  range_set = 2;
	}
      else if (unformat (i, "vrf %d", &vrf_id))
	;
      else
	break;
    }

  if (range_set == 0)
    {
      errmsg ("address range not set");
      return -99;
    }

  M (TCP_CONFIGURE_SRC_ADDRESSES, mp);
  mp->vrf_id = ntohl (vrf_id);
  /* ipv6? */
  if (range_set == 2)
    {
      mp->is_ipv6 = 1;
      clib_memcpy (mp->first_address, &v6first, sizeof (v6first));
      clib_memcpy (mp->last_address, &v6last, sizeof (v6last));
    }
  else
    {
      mp->is_ipv6 = 0;
      clib_memcpy (mp->first_address, &v4first, sizeof (v4first));
      clib_memcpy (mp->last_address, &v4last, sizeof (v4last));
    }
  S (mp);
  W (ret);
  return ret;
}

static void vl_api_app_namespace_add_del_reply_t_handler
  (vl_api_app_namespace_add_del_reply_t * mp)
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
      if (retval == 0)
	errmsg ("app ns index %d\n", ntohl (mp->appns_index));
      vam->result_ready = 1;
    }
}

static void vl_api_app_namespace_add_del_reply_t_handler_json
  (vl_api_app_namespace_add_del_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "appns_index", ntohl (mp->appns_index));

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static int
api_app_namespace_add_del (vat_main_t * vam)
{
  vl_api_app_namespace_add_del_t *mp;
  unformat_input_t *i = vam->input;
  u8 *ns_id = 0, secret_set = 0, sw_if_index_set = 0;
  u32 sw_if_index, ip4_fib_id, ip6_fib_id;
  u64 secret;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "id %_%v%_", &ns_id))
	;
      else if (unformat (i, "secret %lu", &secret))
	secret_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "ip4_fib_id %d", &ip4_fib_id))
	;
      else if (unformat (i, "ip6_fib_id %d", &ip6_fib_id))
	;
      else
	break;
    }
  if (!ns_id || !secret_set || !sw_if_index_set)
    {
      errmsg ("namespace id, secret and sw_if_index must be set");
      return -99;
    }
  if (vec_len (ns_id) > 64)
    {
      errmsg ("namespace id too long");
      return -99;
    }
  M (APP_NAMESPACE_ADD_DEL, mp);

  clib_memcpy (mp->namespace_id, ns_id, vec_len (ns_id));
  mp->namespace_id_len = vec_len (ns_id);
  mp->secret = clib_host_to_net_u64 (secret);
  mp->sw_if_index = clib_host_to_net_u32 (sw_if_index);
  mp->ip4_fib_id = clib_host_to_net_u32 (ip4_fib_id);
  mp->ip6_fib_id = clib_host_to_net_u32 (ip6_fib_id);
  vec_free (ns_id);
  S (mp);
  W (ret);
  return ret;
}

static int
api_sock_init_shm (vat_main_t * vam)
{
#if VPP_API_TEST_BUILTIN == 0
  unformat_input_t *i = vam->input;
  vl_api_shm_elem_config_t *config = 0;
  u64 size = 64 << 20;
  int rv;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "size %U", unformat_memory_size, &size))
	;
      else
	break;
    }

  /*
   * Canned custom ring allocator config.
   * Should probably parse all of this
   */
  vec_validate (config, 6);
  config[0].type = VL_API_VLIB_RING;
  config[0].size = 256;
  config[0].count = 32;

  config[1].type = VL_API_VLIB_RING;
  config[1].size = 1024;
  config[1].count = 16;

  config[2].type = VL_API_VLIB_RING;
  config[2].size = 4096;
  config[2].count = 2;

  config[3].type = VL_API_CLIENT_RING;
  config[3].size = 256;
  config[3].count = 32;

  config[4].type = VL_API_CLIENT_RING;
  config[4].size = 1024;
  config[4].count = 16;

  config[5].type = VL_API_CLIENT_RING;
  config[5].size = 4096;
  config[5].count = 2;

  config[6].type = VL_API_QUEUE;
  config[6].count = 128;
  config[6].size = sizeof (uword);

  rv = vl_socket_client_init_shm (config);
  if (!rv)
    vam->client_index_invalid = 1;
  return rv;
#else
  return -99;
#endif
}

static int
api_dns_enable_disable (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_dns_enable_disable_t *mp;
  u8 enable_disable = 1;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "disable"))
	enable_disable = 0;
      if (unformat (line_input, "enable"))
	enable_disable = 1;
      else
	break;
    }

  /* Construct the API message */
  M (DNS_ENABLE_DISABLE, mp);
  mp->enable = enable_disable;

  /* send it... */
  S (mp);
  /* Wait for the reply */
  W (ret);
  return ret;
}

static int
api_dns_resolve_name (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_dns_resolve_name_t *mp;
  u8 *name = 0;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%s", &name))
	;
      else
	break;
    }

  if (vec_len (name) > 127)
    {
      errmsg ("name too long");
      return -99;
    }

  /* Construct the API message */
  M (DNS_RESOLVE_NAME, mp);
  memcpy (mp->name, name, vec_len (name));
  vec_free (name);

  /* send it... */
  S (mp);
  /* Wait for the reply */
  W (ret);
  return ret;
}

static int
api_dns_resolve_ip (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_dns_resolve_ip_t *mp;
  int is_ip6 = -1;
  ip4_address_t addr4;
  ip6_address_t addr6;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip6_address, &addr6))
	is_ip6 = 1;
      else if (unformat (line_input, "%U", unformat_ip4_address, &addr4))
	is_ip6 = 0;
      else
	break;
    }

  if (is_ip6 == -1)
    {
      errmsg ("missing address");
      return -99;
    }

  /* Construct the API message */
  M (DNS_RESOLVE_IP, mp);
  mp->is_ip6 = is_ip6;
  if (is_ip6)
    memcpy (mp->address, &addr6, sizeof (addr6));
  else
    memcpy (mp->address, &addr4, sizeof (addr4));

  /* send it... */
  S (mp);
  /* Wait for the reply */
  W (ret);
  return ret;
}

static int
api_dns_name_server_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_dns_name_server_add_del_t *mp;
  u8 is_add = 1;
  ip6_address_t ip6_server;
  ip4_address_t ip4_server;
  int ip6_set = 0;
  int ip4_set = 0;
  int ret = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_ip6_address, &ip6_server))
	ip6_set = 1;
      else if (unformat (i, "%U", unformat_ip4_address, &ip4_server))
	ip4_set = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (ip4_set && ip6_set)
    {
      errmsg ("Only one server address allowed per message");
      return -99;
    }
  if ((ip4_set + ip6_set) == 0)
    {
      errmsg ("Server address required");
      return -99;
    }

  /* Construct the API message */
  M (DNS_NAME_SERVER_ADD_DEL, mp);

  if (ip6_set)
    {
      memcpy (mp->server_address, &ip6_server, sizeof (ip6_address_t));
      mp->is_ip6 = 1;
    }
  else
    {
      memcpy (mp->server_address, &ip4_server, sizeof (ip4_address_t));
      mp->is_ip6 = 0;
    }

  mp->is_add = is_add;

  /* send it... */
  S (mp);

  /* Wait for a reply, return good/bad news  */
  W (ret);
  return ret;
}

static void
vl_api_session_rules_details_t_handler (vl_api_session_rules_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  if (mp->is_ip4)
    {
      print (vam->ofp,
	     "appns %u tp %u scope %d %U/%d %d %U/%d %d action: %d tag: %s",
	     clib_net_to_host_u32 (mp->appns_index), mp->transport_proto,
	     mp->scope, format_ip4_address, &mp->lcl_ip, mp->lcl_plen,
	     clib_net_to_host_u16 (mp->lcl_port), format_ip4_address,
	     &mp->rmt_ip, mp->rmt_plen, clib_net_to_host_u16 (mp->rmt_port),
	     clib_net_to_host_u32 (mp->action_index), mp->tag);
    }
  else
    {
      print (vam->ofp,
	     "appns %u tp %u scope %d %U/%d %d %U/%d %d action: %d tag: %s",
	     clib_net_to_host_u32 (mp->appns_index), mp->transport_proto,
	     mp->scope, format_ip6_address, &mp->lcl_ip, mp->lcl_plen,
	     clib_net_to_host_u16 (mp->lcl_port), format_ip6_address,
	     &mp->rmt_ip, mp->rmt_plen, clib_net_to_host_u16 (mp->rmt_port),
	     clib_net_to_host_u32 (mp->action_index), mp->tag);
    }
}

static void
vl_api_session_rules_details_t_handler_json (vl_api_session_rules_details_t *
					     mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;
  struct in6_addr ip6;
  struct in_addr ip4;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);
  vat_json_init_object (node);

  vat_json_object_add_uint (node, "is_ip4", mp->is_ip4 ? 1 : 0);
  vat_json_object_add_uint (node, "appns_index",
			    clib_net_to_host_u32 (mp->appns_index));
  vat_json_object_add_uint (node, "transport_proto", mp->transport_proto);
  vat_json_object_add_uint (node, "scope", mp->scope);
  vat_json_object_add_uint (node, "action_index",
			    clib_net_to_host_u32 (mp->action_index));
  vat_json_object_add_uint (node, "lcl_port",
			    clib_net_to_host_u16 (mp->lcl_port));
  vat_json_object_add_uint (node, "rmt_port",
			    clib_net_to_host_u16 (mp->rmt_port));
  vat_json_object_add_uint (node, "lcl_plen", mp->lcl_plen);
  vat_json_object_add_uint (node, "rmt_plen", mp->rmt_plen);
  vat_json_object_add_string_copy (node, "tag", mp->tag);
  if (mp->is_ip4)
    {
      clib_memcpy (&ip4, mp->lcl_ip, sizeof (ip4));
      vat_json_object_add_ip4 (node, "lcl_ip", ip4);
      clib_memcpy (&ip4, mp->rmt_ip, sizeof (ip4));
      vat_json_object_add_ip4 (node, "rmt_ip", ip4);
    }
  else
    {
      clib_memcpy (&ip6, mp->lcl_ip, sizeof (ip6));
      vat_json_object_add_ip6 (node, "lcl_ip", ip6);
      clib_memcpy (&ip6, mp->rmt_ip, sizeof (ip6));
      vat_json_object_add_ip6 (node, "rmt_ip", ip6);
    }
}

static int
api_session_rule_add_del (vat_main_t * vam)
{
  vl_api_session_rule_add_del_t *mp;
  unformat_input_t *i = vam->input;
  u32 proto = ~0, lcl_port, rmt_port, action = 0, lcl_plen, rmt_plen;
  u32 appns_index = 0, scope = 0;
  ip4_address_t lcl_ip4, rmt_ip4;
  ip6_address_t lcl_ip6, rmt_ip6;
  u8 is_ip4 = 1, conn_set = 0;
  u8 is_add = 1, *tag = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	;
      else if (unformat (i, "proto tcp"))
	proto = 0;
      else if (unformat (i, "proto udp"))
	proto = 1;
      else if (unformat (i, "appns %d", &appns_index))
	;
      else if (unformat (i, "scope %d", &scope))
	;
      else if (unformat (i, "tag %_%v%_", &tag))
	;
      else
	if (unformat
	    (i, "%U/%d %d %U/%d %d", unformat_ip4_address, &lcl_ip4,
	     &lcl_plen, &lcl_port, unformat_ip4_address, &rmt_ip4, &rmt_plen,
	     &rmt_port))
	{
	  is_ip4 = 1;
	  conn_set = 1;
	}
      else
	if (unformat
	    (i, "%U/%d %d %U/%d %d", unformat_ip6_address, &lcl_ip6,
	     &lcl_plen, &lcl_port, unformat_ip6_address, &rmt_ip6, &rmt_plen,
	     &rmt_port))
	{
	  is_ip4 = 0;
	  conn_set = 1;
	}
      else if (unformat (i, "action %d", &action))
	;
      else
	break;
    }
  if (proto == ~0 || !conn_set || action == ~0)
    {
      errmsg ("transport proto, connection and action must be set");
      return -99;
    }

  if (scope > 3)
    {
      errmsg ("scope should be 0-3");
      return -99;
    }

  M (SESSION_RULE_ADD_DEL, mp);

  mp->is_ip4 = is_ip4;
  mp->transport_proto = proto;
  mp->lcl_port = clib_host_to_net_u16 ((u16) lcl_port);
  mp->rmt_port = clib_host_to_net_u16 ((u16) rmt_port);
  mp->lcl_plen = lcl_plen;
  mp->rmt_plen = rmt_plen;
  mp->action_index = clib_host_to_net_u32 (action);
  mp->appns_index = clib_host_to_net_u32 (appns_index);
  mp->scope = scope;
  mp->is_add = is_add;
  if (is_ip4)
    {
      clib_memcpy (mp->lcl_ip, &lcl_ip4, sizeof (lcl_ip4));
      clib_memcpy (mp->rmt_ip, &rmt_ip4, sizeof (rmt_ip4));
    }
  else
    {
      clib_memcpy (mp->lcl_ip, &lcl_ip6, sizeof (lcl_ip6));
      clib_memcpy (mp->rmt_ip, &rmt_ip6, sizeof (rmt_ip6));
    }
  if (tag)
    {
      clib_memcpy (mp->tag, tag, vec_len (tag));
      vec_free (tag);
    }

  S (mp);
  W (ret);
  return ret;
}

static int
api_session_rules_dump (vat_main_t * vam)
{
  vl_api_session_rules_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%=20s", "Session Rules");
    }

  M (SESSION_RULES_DUMP, mp);
  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_ip_container_proxy_add_del (vat_main_t * vam)
{
  vl_api_ip_container_proxy_add_del_t *mp;
  unformat_input_t *i = vam->input;
  u32 plen = ~0, sw_if_index = ~0;
  ip4_address_t ip4;
  ip6_address_t ip6;
  u8 is_ip4 = 1;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	;
      if (unformat (i, "%U", unformat_ip4_address, &ip4))
	{
	  is_ip4 = 1;
	  plen = 32;
	}
      else if (unformat (i, "%U", unformat_ip6_address, &ip6))
	{
	  is_ip4 = 0;
	  plen = 128;
	}
      else if (unformat (i, "sw_if_index %u", &sw_if_index))
	;
      else
	break;
    }
  if (sw_if_index == ~0 || plen == ~0)
    {
      errmsg ("address and sw_if_index must be set");
      return -99;
    }

  M (IP_CONTAINER_PROXY_ADD_DEL, mp);

  mp->is_ip4 = is_ip4;
  mp->sw_if_index = clib_host_to_net_u32 (sw_if_index);
  mp->plen = plen;
  mp->is_add = is_add;
  if (is_ip4)
    clib_memcpy (mp->ip, &ip4, sizeof (ip4));
  else
    clib_memcpy (mp->ip, &ip6, sizeof (ip6));

  S (mp);
  W (ret);
  return ret;
}

static int
api_qos_record_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_qos_record_enable_disable_t *mp;
  u32 sw_if_index, qs = 0xff;
  u8 sw_if_index_set = 0;
  u8 enable = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "%U", unformat_qos_source, &qs))
	;
      else if (unformat (i, "disable"))
	enable = 0;
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
  if (qs == 0xff)
    {
      errmsg ("input location must be specified");
      return -99;
    }

  M (QOS_RECORD_ENABLE_DISABLE, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->input_source = qs;
  mp->enable = enable;

  S (mp);
  W (ret);
  return ret;
}


static int
q_or_quit (vat_main_t * vam)
{
#if VPP_API_TEST_BUILTIN == 0
  longjmp (vam->jump_buf, 1);
#endif
  return 0;			/* not so much */
}

static int
q (vat_main_t * vam)
{
  return q_or_quit (vam);
}

static int
quit (vat_main_t * vam)
{
  return q_or_quit (vam);
}

static int
comment (vat_main_t * vam)
{
  return 0;
}

static int
statseg (vat_main_t * vam)
{
  ssvm_private_t *ssvmp = &vam->stat_segment;
  ssvm_shared_header_t *shared_header = ssvmp->sh;
  vlib_counter_t **counters;
  u64 thread0_index1_packets;
  u64 thread0_index1_bytes;
  f64 vector_rate, input_rate;
  uword *p;

  uword *counter_vector_by_name;
  if (vam->stat_segment_lockp == 0)
    {
      errmsg ("Stat segment not mapped...");
      return -99;
    }

  /* look up "/if/rx for sw_if_index 1 as a test */

  clib_spinlock_lock (vam->stat_segment_lockp);

  counter_vector_by_name = (uword *) shared_header->opaque[1];

  p = hash_get_mem (counter_vector_by_name, "/if/rx");
  if (p == 0)
    {
      clib_spinlock_unlock (vam->stat_segment_lockp);
      errmsg ("/if/tx not found?");
      return -99;
    }

  /* Fish per-thread vector of combined counters from shared memory */
  counters = (vlib_counter_t **) p[0];

  if (vec_len (counters[0]) < 2)
    {
      clib_spinlock_unlock (vam->stat_segment_lockp);
      errmsg ("/if/tx vector length %d", vec_len (counters[0]));
      return -99;
    }

  /* Read thread 0 sw_if_index 1 counter */
  thread0_index1_packets = counters[0][1].packets;
  thread0_index1_bytes = counters[0][1].bytes;

  p = hash_get_mem (counter_vector_by_name, "vector_rate");
  if (p == 0)
    {
      clib_spinlock_unlock (vam->stat_segment_lockp);
      errmsg ("vector_rate not found?");
      return -99;
    }

  vector_rate = *(f64 *) (p[0]);
  p = hash_get_mem (counter_vector_by_name, "input_rate");
  if (p == 0)
    {
      clib_spinlock_unlock (vam->stat_segment_lockp);
      errmsg ("input_rate not found?");
      return -99;
    }
  input_rate = *(f64 *) (p[0]);

  clib_spinlock_unlock (vam->stat_segment_lockp);

  print (vam->ofp, "vector_rate %.2f input_rate %.2f",
	 vector_rate, input_rate);
  print (vam->ofp, "thread 0 sw_if_index 1 rx pkts %lld, bytes %lld",
	 thread0_index1_packets, thread0_index1_bytes);

  return 0;
}

static int
cmd_cmp (void *a1, void *a2)
{
  u8 **c1 = a1;
  u8 **c2 = a2;

  return strcmp ((char *) (c1[0]), (char *) (c2[0]));
}

static int
help (vat_main_t * vam)
{
  u8 **cmds = 0;
  u8 *name = 0;
  hash_pair_t *p;
  unformat_input_t *i = vam->input;
  int j;

  if (unformat (i, "%s", &name))
    {
      uword *hs;

      vec_add1 (name, 0);

      hs = hash_get_mem (vam->help_by_name, name);
      if (hs)
	print (vam->ofp, "usage: %s %s", name, hs[0]);
      else
	print (vam->ofp, "No such msg / command '%s'", name);
      vec_free (name);
      return 0;
    }

  print (vam->ofp, "Help is available for the following:");

    /* *INDENT-OFF* */
    hash_foreach_pair (p, vam->function_by_name,
    ({
      vec_add1 (cmds, (u8 *)(p->key));
    }));
    /* *INDENT-ON* */

  vec_sort_with_function (cmds, cmd_cmp);

  for (j = 0; j < vec_len (cmds); j++)
    print (vam->ofp, "%s", cmds[j]);

  vec_free (cmds);
  return 0;
}

static int
set (vat_main_t * vam)
{
  u8 *name = 0, *value = 0;
  unformat_input_t *i = vam->input;

  if (unformat (i, "%s", &name))
    {
      /* The input buffer is a vector, not a string. */
      value = vec_dup (i->buffer);
      vec_delete (value, i->index, 0);
      /* Almost certainly has a trailing newline */
      if (value[vec_len (value) - 1] == '\n')
	value[vec_len (value) - 1] = 0;
      /* Make sure it's a proper string, one way or the other */
      vec_add1 (value, 0);
      (void) clib_macro_set_value (&vam->macro_main,
				   (char *) name, (char *) value);
    }
  else
    errmsg ("usage: set <name> <value>");

  vec_free (name);
  vec_free (value);
  return 0;
}

static int
unset (vat_main_t * vam)
{
  u8 *name = 0;

  if (unformat (vam->input, "%s", &name))
    if (clib_macro_unset (&vam->macro_main, (char *) name) == 1)
      errmsg ("unset: %s wasn't set", name);
  vec_free (name);
  return 0;
}

typedef struct
{
  u8 *name;
  u8 *value;
} macro_sort_t;


static int
macro_sort_cmp (void *a1, void *a2)
{
  macro_sort_t *s1 = a1;
  macro_sort_t *s2 = a2;

  return strcmp ((char *) (s1->name), (char *) (s2->name));
}

static int
dump_macro_table (vat_main_t * vam)
{
  macro_sort_t *sort_me = 0, *sm;
  int i;
  hash_pair_t *p;

    /* *INDENT-OFF* */
    hash_foreach_pair (p, vam->macro_main.the_value_table_hash,
    ({
      vec_add2 (sort_me, sm, 1);
      sm->name = (u8 *)(p->key);
      sm->value = (u8 *) (p->value[0]);
    }));
    /* *INDENT-ON* */

  vec_sort_with_function (sort_me, macro_sort_cmp);

  if (vec_len (sort_me))
    print (vam->ofp, "%-15s%s", "Name", "Value");
  else
    print (vam->ofp, "The macro table is empty...");

  for (i = 0; i < vec_len (sort_me); i++)
    print (vam->ofp, "%-15s%s", sort_me[i].name, sort_me[i].value);
  return 0;
}

static int
dump_node_table (vat_main_t * vam)
{
  int i, j;
  vlib_node_t *node, *next_node;

  if (vec_len (vam->graph_nodes) == 0)
    {
      print (vam->ofp, "Node table empty, issue get_node_graph...");
      return 0;
    }

  for (i = 0; i < vec_len (vam->graph_nodes[0]); i++)
    {
      node = vam->graph_nodes[0][i];
      print (vam->ofp, "[%d] %s", i, node->name);
      for (j = 0; j < vec_len (node->next_nodes); j++)
	{
	  if (node->next_nodes[j] != ~0)
	    {
	      next_node = vam->graph_nodes[0][node->next_nodes[j]];
	      print (vam->ofp, "  [%d] %s", j, next_node->name);
	    }
	}
    }
  return 0;
}

static int
value_sort_cmp (void *a1, void *a2)
{
  name_sort_t *n1 = a1;
  name_sort_t *n2 = a2;

  if (n1->value < n2->value)
    return -1;
  if (n1->value > n2->value)
    return 1;
  return 0;
}


static int
dump_msg_api_table (vat_main_t * vam)
{
  api_main_t *am = &api_main;
  name_sort_t *nses = 0, *ns;
  hash_pair_t *hp;
  int i;

  /* *INDENT-OFF* */
  hash_foreach_pair (hp, am->msg_index_by_name_and_crc,
  ({
    vec_add2 (nses, ns, 1);
    ns->name = (u8 *)(hp->key);
    ns->value = (u32) hp->value[0];
  }));
  /* *INDENT-ON* */

  vec_sort_with_function (nses, value_sort_cmp);

  for (i = 0; i < vec_len (nses); i++)
    print (vam->ofp, " [%d]: %s", nses[i].value, nses[i].name);
  vec_free (nses);
  return 0;
}

static int
get_msg_id (vat_main_t * vam)
{
  u8 *name_and_crc;
  u32 message_index;

  if (unformat (vam->input, "%s", &name_and_crc))
    {
      message_index = vl_msg_api_get_msg_index (name_and_crc);
      if (message_index == ~0)
	{
	  print (vam->ofp, " '%s' not found", name_and_crc);
	  return 0;
	}
      print (vam->ofp, " '%s' has message index %d",
	     name_and_crc, message_index);
      return 0;
    }
  errmsg ("name_and_crc required...");
  return 0;
}

static int
search_node_table (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  u8 *node_to_find;
  int j;
  vlib_node_t *node, *next_node;
  uword *p;

  if (vam->graph_node_index_by_name == 0)
    {
      print (vam->ofp, "Node table empty, issue get_node_graph...");
      return 0;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%s", &node_to_find))
	{
	  vec_add1 (node_to_find, 0);
	  p = hash_get_mem (vam->graph_node_index_by_name, node_to_find);
	  if (p == 0)
	    {
	      print (vam->ofp, "%s not found...", node_to_find);
	      goto out;
	    }
	  node = vam->graph_nodes[0][p[0]];
	  print (vam->ofp, "[%d] %s", p[0], node->name);
	  for (j = 0; j < vec_len (node->next_nodes); j++)
	    {
	      if (node->next_nodes[j] != ~0)
		{
		  next_node = vam->graph_nodes[0][node->next_nodes[j]];
		  print (vam->ofp, "  [%d] %s", j, next_node->name);
		}
	    }
	}

      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error,
			line_input);
	  return -99;
	}

    out:
      vec_free (node_to_find);

    }

  return 0;
}


static int
script (vat_main_t * vam)
{
#if (VPP_API_TEST_BUILTIN==0)
  u8 *s = 0;
  char *save_current_file;
  unformat_input_t save_input;
  jmp_buf save_jump_buf;
  u32 save_line_number;

  FILE *new_fp, *save_ifp;

  if (unformat (vam->input, "%s", &s))
    {
      new_fp = fopen ((char *) s, "r");
      if (new_fp == 0)
	{
	  errmsg ("Couldn't open script file %s", s);
	  vec_free (s);
	  return -99;
	}
    }
  else
    {
      errmsg ("Missing script name");
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

  clib_memcpy (&vam->input, &save_input, sizeof (save_input));
  clib_memcpy (&vam->jump_buf, &save_jump_buf, sizeof (save_jump_buf));
  vam->ifp = save_ifp;
  vam->input_line_number = save_line_number;
  vam->current_file = (u8 *) save_current_file;
  vec_free (s);

  return 0;
#else
  clib_warning ("use the exec command...");
  return -99;
#endif
}

static int
echo (vat_main_t * vam)
{
  print (vam->ofp, "%v", vam->input->buffer);
  return 0;
}

/* List of API message constructors, CLI names map to api_xxx */
#define foreach_vpe_api_msg                                             \
_(create_loopback,"[mac <mac-addr>] [instance <instance>]")             \
_(sw_interface_dump,"")                                                 \
_(sw_interface_set_flags,                                               \
  "<intfc> | sw_if_index <id> admin-up | admin-down link-up | link down") \
_(sw_interface_add_del_address,                                         \
  "<intfc> | sw_if_index <id> <ip4-address> | <ip6-address> [del] [del-all] ") \
_(sw_interface_set_rx_mode,                                             \
  "<intfc> | sw_if_index <id> [queue <id>] <polling | interrupt | adaptive>") \
_(sw_interface_set_rx_placement,                                        \
  "<intfc> | sw_if_index <id> [queue <id>] [worker <id> | main]")       \
_(sw_interface_rx_placement_dump,                                       \
  "[<intfc> | sw_if_index <id>]")                                         \
_(sw_interface_set_table,                                               \
  "<intfc> | sw_if_index <id> vrf <table-id> [ipv6]")                   \
_(sw_interface_set_mpls_enable,                                         \
  "<intfc> | sw_if_index [disable | dis]")                              \
_(sw_interface_set_vpath,                                               \
  "<intfc> | sw_if_index <id> enable | disable")                        \
_(sw_interface_set_vxlan_bypass,                                        \
  "<intfc> | sw_if_index <id> [ip4 | ip6] [enable | disable]")          \
_(sw_interface_set_geneve_bypass,                                       \
  "<intfc> | sw_if_index <id> [ip4 | ip6] [enable | disable]")          \
_(sw_interface_set_l2_xconnect,                                         \
  "rx <intfc> | rx_sw_if_index <id> tx <intfc> | tx_sw_if_index <id>\n" \
  "enable | disable")                                                   \
_(sw_interface_set_l2_bridge,                                           \
  "{<intfc> | sw_if_index <id>} bd_id <bridge-domain-id>\n"             \
  "[shg <split-horizon-group>] [bvi]\n"                                 \
  "enable | disable")                                                   \
_(bridge_domain_set_mac_age, "bd_id <bridge-domain-id> mac-age 0-255")  \
_(bridge_domain_add_del,                                                \
  "bd_id <bridge-domain-id> [flood 1|0] [uu-flood 1|0] [forward 1|0] [learn 1|0] [arp-term 1|0] [mac-age 0-255] [bd-tag <text>] [del]\n") \
_(bridge_domain_dump, "[bd_id <bridge-domain-id>]\n")                   \
_(l2fib_add_del,                                                        \
  "mac <mac-addr> bd_id <bridge-domain-id> [del] | sw_if <intfc> | sw_if_index <id> [static] [filter] [bvi] [count <nn>]\n") \
_(l2fib_flush_bd, "bd_id <bridge-domain-id>")                           \
_(l2fib_flush_int, "<intfc> | sw_if_index <id>")                        \
_(l2_flags,                                                             \
  "sw_if <intfc> | sw_if_index <id> [learn] [forward] [uu-flood] [flood] [arp-term] [disable]\n") \
_(bridge_flags,                                                         \
  "bd_id <bridge-domain-id> [learn] [forward] [uu-flood] [flood] [arp-term] [disable]\n") \
_(tap_connect,                                                          \
  "tapname <name> mac <mac-addr> | random-mac [tag <string>]")          \
_(tap_modify,                                                           \
  "<vpp-if-name> | sw_if_index <id> tapname <name> mac <mac-addr> | random-mac") \
_(tap_delete,                                                           \
  "<vpp-if-name> | sw_if_index <id>")                                   \
_(sw_interface_tap_dump, "")                                            \
_(tap_create_v2,                                                        \
  "id <num> [hw-addr <mac-addr>] [host-ns <name>] [rx-ring-size <num> [tx-ring-size <num>]") \
_(tap_delete_v2,                                                        \
  "<vpp-if-name> | sw_if_index <id>")                                   \
_(sw_interface_tap_v2_dump, "")                                         \
_(bond_create,                                                          \
  "[hw-addr <mac-addr>] {round-robin | active-backup | "                \
  "broadcast | {lacp | xor} [load-balance { l2 | l23 | l34 }]} "        \
  "[instance <instance>]")                                              \
_(bond_delete,                                                          \
  "<vpp-if-name> | sw_if_index <id>")                                   \
_(bond_enslave,                                                         \
  "sw_if_index <n> bond <sw_if_index> [is_passive] [is_long_timeout]")	\
_(bond_detach_slave,                                                    \
  "sw_if_index <n>")							\
_(sw_interface_bond_dump, "")                                           \
_(sw_interface_slave_dump,                                              \
  "<vpp-if-name> | sw_if_index <id>")                                   \
_(ip_table_add_del,                                                     \
  "table <n> [ipv6] [add | del]\n")                                     \
_(ip_add_del_route,                                                     \
  "<addr>/<mask> via <<addr>|<intfc>|sw_if_index <id>|via-label <n>>\n" \
  "[table-id <n>] [<intfc> | sw_if_index <id>] [resolve-attempts <n>]\n"\
  "[weight <n>] [drop] [local] [classify <n>]  [out-label <n>]\n"       \
  "[multipath] [count <n>] [del]")                                      \
_(ip_mroute_add_del,                                                    \
  "<src> <grp>/<mask> [table-id <n>]\n"                                 \
  "[<intfc> | sw_if_index <id>] [local] [del]")                         \
_(mpls_table_add_del,                                                   \
  "table <n> [add | del]\n")                                            \
_(mpls_route_add_del,                                                   \
  "<label> <eos> via <addr | next-hop-table <n> | via-label <n> |\n"    \
  "lookup-ip4-table <n> | lookup-in-ip6-table <n> |\n"                  \
  "l2-input-on <intfc> | l2-input-on sw_if_index <id>>\n"               \
  "[<intfc> | sw_if_index <id>] [resolve-attempts <n>] [weight <n>]\n"  \
  "[drop] [local] [classify <n>] [out-label <n>] [multipath]\n"         \
  "[count <n>] [del]")                                                  \
_(mpls_ip_bind_unbind,                                                  \
  "<label> <addr/len>")                                                 \
_(mpls_tunnel_add_del,                                                  \
  "[add | del <intfc | sw_if_index <id>>] via <addr | via-label <n>>\n" \
  "[<intfc> | sw_if_index <id> | next-hop-table <id>]\n"                \
  "[l2-only]  [out-label <n>]")                                         \
_(sr_mpls_policy_add,                                                   \
  "bsid <id> [weight <n>] [spray] next <sid> [next <sid>]")             \
_(sr_mpls_policy_del,                                                   \
  "bsid <id>")                                                          \
_(bier_table_add_del,                                                   \
  "<label> <sub-domain> <set> <bsl> [del]")                             \
_(bier_route_add_del,                                                   \
  "<bit-position> <sub-domain> <set> <bsl> via <addr> [table-id <n>]\n" \
  "[<intfc> | sw_if_index <id>]"                                        \
  "[weight <n>] [del] [multipath]")                                     \
_(proxy_arp_add_del,                                                    \
  "<lo-ip4-addr> - <hi-ip4-addr> [vrf <n>] [del]")                      \
_(proxy_arp_intfc_enable_disable,                                       \
  "<intfc> | sw_if_index <id> enable | disable")                        \
_(sw_interface_set_unnumbered,                                          \
  "<intfc> | sw_if_index <id> unnum_if_index <id> [del]")               \
_(ip_neighbor_add_del,                                                  \
  "(<intfc> | sw_if_index <id>) dst <ip46-address> "                    \
  "[mac <mac-addr>] [vrf <vrf-id>] [is_static] [del]")                  \
_(create_vlan_subif, "<intfc> | sw_if_index <id> vlan <n>")             \
_(create_subif, "<intfc> | sw_if_index <id> sub_id <n>\n"               \
  "[outer_vlan_id <n>][inner_vlan_id <n>]\n"                            \
  "[no_tags][one_tag][two_tags][dot1ad][exact_match][default_sub]\n"    \
  "[outer_vlan_id_any][inner_vlan_id_any]")                             \
_(oam_add_del, "src <ip4-address> dst <ip4-address> [vrf <n>] [del]")   \
_(reset_fib, "vrf <n> [ipv6]")                                          \
_(dhcp_proxy_config,                                                    \
  "svr <v46-address> src <v46-address>\n"                               \
   "rx_vrf_id <nn> server_vrf_id <nn>  [del]")                          \
_(dhcp_proxy_set_vss,                                                   \
  "tbl_id <n> [fib_id <n> oui <n> | vpn_ascii_id <text>] [ipv6] [del]") \
_(dhcp_proxy_dump, "ip6")                                               \
_(dhcp_client_config,                                                   \
  "<intfc> | sw_if_index <id> [hostname <name>] [disable_event] [del]") \
_(set_ip_flow_hash,                                                     \
  "vrf <n> [src] [dst] [sport] [dport] [proto] [reverse] [ipv6]")       \
_(sw_interface_ip6_enable_disable,                                      \
  "<intfc> | sw_if_index <id> enable | disable")                        \
_(ip6nd_proxy_add_del,                                                  \
  "<intfc> | sw_if_index <id> <ip6-address>")                           \
_(ip6nd_proxy_dump, "")                                                 \
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
_(sr_localsid_add_del,                                                  \
  "(del) address <addr> next_hop <addr> behavior <beh>\n"               \
  "fib-table <num> (end.psp) sw_if_index <num>")                        \
_(classify_add_del_table,                                               \
  "buckets <nn> [skip <n>] [match <n>] [memory_size <nn-bytes>]\n"	\
  " [del] [del-chain] mask <mask-value>\n"                              \
  " [l2-miss-next | miss-next | acl-miss-next] <name|nn>\n" 		\
  " [current-data-flag <n>] [current-data-offset <nn>] [table <nn>]")   \
_(classify_add_del_session,                                             \
  "[hit-next|l2-hit-next|acl-hit-next|policer-hit-next] <name|nn>\n"    \
  "  table-index <nn> skip_n <nn> match_n <nn> match [hex] [l2]\n"      \
  "  [l3 [ip4|ip6]] [action set-ip4-fib-id <nn>]\n"                     \
  "  [action set-ip6-fib-id <nn> | action <n> metadata <nn>] [del]")    \
_(classify_set_interface_ip_table,                                      \
  "<intfc> | sw_if_index <nn> table <nn>")				\
_(classify_set_interface_l2_tables,                                     \
  "<intfc> | sw_if_index <nn> [ip4-table <nn>] [ip6-table <nn>]\n"      \
  "  [other-table <nn>]")                                               \
_(get_node_index, "node <node-name")                                    \
_(add_node_next, "node <node-name> next <next-node-name>")              \
_(l2tpv3_create_tunnel,                                                 \
  "client_address <ip6-addr> our_address <ip6-addr>\n"                  \
  "[local_session_id <nn>][remote_session_id <nn>][local_cookie <nn>]\n" \
  "[remote_cookie <nn>]\n[l2-sublayer-preset]\n")                       \
_(l2tpv3_set_tunnel_cookies,                                            \
  "<intfc> | sw_if_index <nn> [new_local_cookie <nn>]\n"                \
  "[new_remote_cookie <nn>]\n")                                         \
_(l2tpv3_interface_enable_disable,                                      \
  "<intfc> | sw_if_index <nn> enable | disable")                        \
_(l2tpv3_set_lookup_key,                                                \
  "lookup_v6_src | lookup_v6_dst | lookup_session_id")                  \
_(sw_if_l2tpv3_tunnel_dump, "")                                         \
_(vxlan_offload_rx,                                                     \
  "hw { <interface name> | hw_if_index <nn>} "                          \
  "rx { <vxlan tunnel name> | sw_if_index <nn> } [del]")                \
_(vxlan_add_del_tunnel,                                                 \
  "src <ip-addr> { dst <ip-addr> | group <mcast-ip-addr>\n"             \
  "{ <intfc> | mcast_sw_if_index <nn> } [instance <id>]}\n"		\
  "vni <vni> [encap-vrf-id <nn>] [decap-next <l2|nn>] [del]")           \
_(geneve_add_del_tunnel,                                                \
  "src <ip-addr> { dst <ip-addr> | group <mcast-ip-addr>\n"             \
  "{ <intfc> | mcast_sw_if_index <nn> } }\n"                            \
  "vni <vni> [encap-vrf-id <nn>] [decap-next <l2|nn>] [del]")           \
_(vxlan_tunnel_dump, "[<intfc> | sw_if_index <nn>]")                    \
_(geneve_tunnel_dump, "[<intfc> | sw_if_index <nn>]")                   \
_(gre_add_del_tunnel,                                                   \
  "src <ip-addr> dst <ip-addr> [outer-fib-id <nn>] [instance <n>]\n"    \
  "[teb | erspan <session-id>] [del]")                                	\
_(gre_tunnel_dump, "[<intfc> | sw_if_index <nn>]")                      \
_(l2_fib_clear_table, "")                                               \
_(l2_interface_efp_filter, "sw_if_index <nn> enable | disable")         \
_(l2_interface_vlan_tag_rewrite,                                        \
  "<intfc> | sw_if_index <nn> \n"                                       \
  "[disable][push-[1|2]][pop-[1|2]][translate-1-[1|2]] \n"              \
  "[translate-2-[1|2]] [push_dot1q 0] tag1 <nn> tag2 <nn>")             \
_(create_vhost_user_if,                                                 \
        "socket <filename> [server] [renumber <dev_instance>] "         \
        "[disable_mrg_rxbuf] [disable_indirect_desc] "                  \
        "[mac <mac_address>]")                                          \
_(modify_vhost_user_if,                                                 \
        "<intfc> | sw_if_index <nn> socket <filename>\n"                \
        "[server] [renumber <dev_instance>]")                           \
_(delete_vhost_user_if, "<intfc> | sw_if_index <nn>")                   \
_(sw_interface_vhost_user_dump, "")                                     \
_(show_version, "")                                                     \
_(show_threads, "")                                                     \
_(vxlan_gpe_add_del_tunnel,                                             \
  "local <addr> remote <addr>  | group <mcast-ip-addr>\n"               \
  "{ <intfc> | mcast_sw_if_index <nn> } }\n"                            \
  "vni <nn> [encap-vrf-id <nn>] [decap-vrf-id <nn>]\n"                  \
  "[next-ip4][next-ip6][next-ethernet] [next-nsh] [del]\n")             \
_(vxlan_gpe_tunnel_dump, "[<intfc> | sw_if_index <nn>]")                \
_(l2_fib_table_dump, "bd_id <bridge-domain-id>")			\
_(interface_name_renumber,                                              \
  "<intfc> | sw_if_index <nn> new_show_dev_instance <nn>")		\
_(input_acl_set_interface,                                              \
  "<intfc> | sw_if_index <nn> [ip4-table <nn>] [ip6-table <nn>]\n"      \
  "  [l2-table <nn>] [del]")                                            \
_(ip_probe_neighbor, "(<intc> | sw_if_index <nn>) address <ip4|ip6-addr>") \
_(ip_scan_neighbor_enable_disable, "[ip4|ip6|both|disable] [interval <n-min>]\n" \
  "  [max-time <n-usec>] [max-update <n>] [delay <n-msec>] [stale <n-min>]") \
_(want_ip4_arp_events, "address <ip4-address> [del]")                   \
_(want_ip6_nd_events, "address <ip6-address> [del]")                    \
_(want_l2_macs_events, "[disable] [learn-limit <n>] [scan-delay <n>] [max-entries <n>]") \
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
  "  [lport_start <n> lport_stop <n>] [rport_start <n> rport_stop <n>]" ) \
_(ipsec_sa_set_key, "sa_id <n> crypto_key <hex> integ_key <hex>")       \
_(ipsec_tunnel_if_add_del, "local_spi <n> remote_spi <n>\n"             \
  "  crypto_alg <alg> local_crypto_key <hex> remote_crypto_key <hex>\n" \
  "  integ_alg <alg> local_integ_key <hex> remote_integ_key <hex>\n"    \
  "  local_ip <addr> remote_ip <addr> [esn] [anti_replay] [del]\n"      \
  "  [instance <n>]")     \
_(ipsec_sa_dump, "[sa_id <n>]")                                         \
_(ipsec_tunnel_if_set_key, "<intfc> <local|remote> <crypto|integ>\n"    \
  "  <alg> <hex>\n")                                                    \
_(ipsec_tunnel_if_set_sa, "<intfc> sa_id <n> <inbound|outbound>\n")     \
_(ikev2_profile_add_del, "name <profile_name> [del]")                   \
_(ikev2_profile_set_auth, "name <profile_name> auth_method <method>\n"  \
  "(auth_data 0x<data> | auth_data <data>)")                            \
_(ikev2_profile_set_id, "name <profile_name> id_type <type>\n"          \
  "(id_data 0x<data> | id_data <data>) (local|remote)")                 \
_(ikev2_profile_set_ts, "name <profile_name> protocol <proto>\n"        \
  "start_port <port> end_port <port> start_addr <ip4> end_addr <ip4>\n" \
  "(local|remote)")                                                     \
_(ikev2_set_local_key, "file <absolute_file_path>")                     \
_(ikev2_set_responder, "<profile_name> interface <interface> address <addr>") \
_(ikev2_set_ike_transforms, "<profile_name> <crypto alg> <key size> <integrity alg> <DH group>") \
_(ikev2_set_esp_transforms, "<profile_name> <crypto alg> <key size> <integrity alg> <DH group>") \
_(ikev2_set_sa_lifetime, "<profile_name> <seconds> <jitter> <handover> <max bytes>") \
_(ikev2_initiate_sa_init, "<profile_name>")                             \
_(ikev2_initiate_del_ike_sa, "<ispi>")                                  \
_(ikev2_initiate_del_child_sa, "<ispi>")                                \
_(ikev2_initiate_rekey_child_sa, "<ispi>")                              \
_(delete_loopback,"sw_if_index <nn>")                                   \
_(bd_ip_mac_add_del, "bd_id <bridge-domain-id> <ip4/6-addr> <mac-addr> [del]") \
_(bd_ip_mac_flush, "bd_id <bridge-domain-id>")                          \
_(bd_ip_mac_dump, "[bd_id] <bridge-domain-id>")                         \
_(want_interface_events,  "enable|disable")                             \
_(get_first_msg_id, "client <name>")					\
_(cop_interface_enable_disable, "<intfc> | sw_if_index <nn> [disable]") \
_(cop_whitelist_enable_disable, "<intfc> | sw_if_index <nn>\n"		\
  "fib-id <nn> [ip4][ip6][default]")					\
_(get_node_graph, " ")                                                  \
_(sw_interface_clear_stats,"<intfc> | sw_if_index <nn>")                \
_(ioam_enable, "[trace] [pow] [ppc <encap|decap>]")                     \
_(ioam_disable, "")                                                     \
_(one_add_del_locator_set, "locator-set <locator_name> [iface <intf> |" \
                            " sw_if_index <sw_if_index> p <priority> "  \
                            "w <weight>] [del]")                        \
_(one_add_del_locator, "locator-set <locator_name> "                    \
                        "iface <intf> | sw_if_index <sw_if_index> "     \
                        "p <priority> w <weight> [del]")                \
_(one_add_del_local_eid,"vni <vni> eid "                                \
                         "<ipv4|ipv6>/<prefix> | <L2 address> "         \
                         "locator-set <locator_name> [del]"             \
                         "[key-id sha1|sha256 secret-key <secret-key>]")\
_(one_add_del_map_resolver, "<ip4|6-addr> [del]")                       \
_(one_add_del_map_server, "<ip4|6-addr> [del]")                         \
_(one_enable_disable, "enable|disable")                                 \
_(one_map_register_enable_disable, "enable|disable")                    \
_(one_map_register_fallback_threshold, "<value>")                       \
_(one_rloc_probe_enable_disable, "enable|disable")                      \
_(one_add_del_remote_mapping, "add|del vni <vni> eid <dest-eid> "       \
                               "[seid <seid>] "                         \
                               "rloc <locator> p <prio> "               \
                               "w <weight> [rloc <loc> ... ] "          \
                               "action <action> [del-all]")             \
_(one_add_del_adjacency, "add|del vni <vni> reid <remote-eid> leid "    \
                          "<local-eid>")                                \
_(one_pitr_set_locator_set, "locator-set <loc-set-name> | del")         \
_(one_use_petr, "ip-address> | disable")                                \
_(one_map_request_mode, "src-dst|dst-only")                             \
_(one_add_del_map_request_itr_rlocs, "<loc-set-name> [del]")            \
_(one_eid_table_add_del_map, "[del] vni <vni> vrf <vrf>")               \
_(one_locator_set_dump, "[local | remote]")                             \
_(one_locator_dump, "ls_index <index> | ls_name <name>")                \
_(one_eid_table_dump, "[eid <ipv4|ipv6>/<prefix> | <mac>] [vni] "       \
                       "[local] | [remote]")                            \
_(one_add_del_ndp_entry, "[del] mac <mac> bd <bd> ip6 <ip6>")           \
_(one_ndp_bd_get, "")                                                   \
_(one_ndp_entries_get, "bd <bridge-domain>")                            \
_(one_add_del_l2_arp_entry, "[del] mac <mac> bd <bd> ip4 <ip4>")        \
_(one_l2_arp_bd_get, "")                                                \
_(one_l2_arp_entries_get, "bd <bridge-domain>")                         \
_(one_stats_enable_disable, "enable|disable")                           \
_(show_one_stats_enable_disable, "")                                    \
_(one_eid_table_vni_dump, "")                                           \
_(one_eid_table_map_dump, "l2|l3")                                      \
_(one_map_resolver_dump, "")                                            \
_(one_map_server_dump, "")                                              \
_(one_adjacencies_get, "vni <vni>")                                     \
_(one_nsh_set_locator_set, "[del] ls <locator-set-name>")               \
_(show_one_rloc_probe_state, "")                                        \
_(show_one_map_register_state, "")                                      \
_(show_one_status, "")                                                  \
_(one_stats_dump, "")                                                   \
_(one_stats_flush, "")                                                  \
_(one_get_map_request_itr_rlocs, "")                                    \
_(one_map_register_set_ttl, "<ttl>")                                    \
_(one_set_transport_protocol, "udp|api")                                \
_(one_get_transport_protocol, "")                                       \
_(one_enable_disable_xtr_mode, "enable|disable")                        \
_(one_show_xtr_mode, "")                                                \
_(one_enable_disable_pitr_mode, "enable|disable")                       \
_(one_show_pitr_mode, "")                                               \
_(one_enable_disable_petr_mode, "enable|disable")                       \
_(one_show_petr_mode, "")                                               \
_(show_one_nsh_mapping, "")                                             \
_(show_one_pitr, "")                                                    \
_(show_one_use_petr, "")                                                \
_(show_one_map_request_mode, "")                                        \
_(show_one_map_register_ttl, "")                                        \
_(show_one_map_register_fallback_threshold, "")                         \
_(lisp_add_del_locator_set, "locator-set <locator_name> [iface <intf> |"\
                            " sw_if_index <sw_if_index> p <priority> "  \
                            "w <weight>] [del]")                        \
_(lisp_add_del_locator, "locator-set <locator_name> "                   \
                        "iface <intf> | sw_if_index <sw_if_index> "     \
                        "p <priority> w <weight> [del]")                \
_(lisp_add_del_local_eid,"vni <vni> eid "                               \
                         "<ipv4|ipv6>/<prefix> | <L2 address> "         \
                         "locator-set <locator_name> [del]"             \
                         "[key-id sha1|sha256 secret-key <secret-key>]") \
_(lisp_add_del_map_resolver, "<ip4|6-addr> [del]")                      \
_(lisp_add_del_map_server, "<ip4|6-addr> [del]")                        \
_(lisp_enable_disable, "enable|disable")                                \
_(lisp_map_register_enable_disable, "enable|disable")                   \
_(lisp_rloc_probe_enable_disable, "enable|disable")                     \
_(lisp_add_del_remote_mapping, "add|del vni <vni> eid <dest-eid> "      \
                               "[seid <seid>] "                         \
                               "rloc <locator> p <prio> "               \
                               "w <weight> [rloc <loc> ... ] "          \
                               "action <action> [del-all]")             \
_(lisp_add_del_adjacency, "add|del vni <vni> reid <remote-eid> leid "   \
                          "<local-eid>")                                \
_(lisp_pitr_set_locator_set, "locator-set <loc-set-name> | del")        \
_(lisp_use_petr, "<ip-address> | disable")                              \
_(lisp_map_request_mode, "src-dst|dst-only")                            \
_(lisp_add_del_map_request_itr_rlocs, "<loc-set-name> [del]")           \
_(lisp_eid_table_add_del_map, "[del] vni <vni> vrf <vrf>")              \
_(lisp_locator_set_dump, "[local | remote]")                            \
_(lisp_locator_dump, "ls_index <index> | ls_name <name>")               \
_(lisp_eid_table_dump, "[eid <ipv4|ipv6>/<prefix> | <mac>] [vni] "      \
                       "[local] | [remote]")                            \
_(lisp_eid_table_vni_dump, "")                                          \
_(lisp_eid_table_map_dump, "l2|l3")                                     \
_(lisp_map_resolver_dump, "")                                           \
_(lisp_map_server_dump, "")                                             \
_(lisp_adjacencies_get, "vni <vni>")                                    \
_(gpe_fwd_entry_vnis_get, "")                                           \
_(gpe_native_fwd_rpaths_get, "ip4 | ip6")                               \
_(gpe_add_del_native_fwd_rpath, "[del] via <nh-ip-addr> [iface] "       \
                                "[table <table-id>]")                   \
_(lisp_gpe_fwd_entries_get, "vni <vni>")                                \
_(lisp_gpe_fwd_entry_path_dump, "index <fwd_entry_index>")              \
_(gpe_set_encap_mode, "lisp|vxlan")                                     \
_(gpe_get_encap_mode, "")                                               \
_(lisp_gpe_add_del_iface, "up|down")                                    \
_(lisp_gpe_enable_disable, "enable|disable")                            \
_(lisp_gpe_add_del_fwd_entry, "reid <eid> [leid <eid>] vni <vni>"       \
  "vrf/bd <dp_table> loc-pair <lcl_loc> <rmt_loc> w <weight>... [del]") \
_(show_lisp_rloc_probe_state, "")                                       \
_(show_lisp_map_register_state, "")                                     \
_(show_lisp_status, "")                                                 \
_(lisp_get_map_request_itr_rlocs, "")                                   \
_(show_lisp_pitr, "")                                                   \
_(show_lisp_use_petr, "")                                               \
_(show_lisp_map_request_mode, "")                                       \
_(af_packet_create, "name <host interface name> [hw_addr <mac>]")       \
_(af_packet_delete, "name <host interface name>")                       \
_(af_packet_dump, "")							\
_(policer_add_del, "name <policer name> <params> [del]")                \
_(policer_dump, "[name <policer name>]")                                \
_(policer_classify_set_interface,                                       \
  "<intfc> | sw_if_index <nn> [ip4-table <nn>] [ip6-table <nn>]\n"      \
  "  [l2-table <nn>] [del]")                                            \
_(policer_classify_dump, "type [ip4|ip6|l2]")                           \
_(netmap_create, "name <interface name> [hw-addr <mac>] [pipe] "        \
    "[master|slave]")                                                   \
_(netmap_delete, "name <interface name>")                               \
_(mpls_tunnel_dump, "tunnel_index <tunnel-id>")                         \
_(mpls_fib_dump, "")                                                    \
_(classify_table_ids, "")                                               \
_(classify_table_by_interface, "sw_if_index <sw_if_index>")             \
_(classify_table_info, "table_id <nn>")                                 \
_(classify_session_dump, "table_id <nn>")                               \
_(set_ipfix_exporter, "collector_address <ip4> [collector_port <nn>] "  \
    "src_address <ip4> [vrf_id <nn>] [path_mtu <nn>] "                  \
    "[template_interval <nn>] [udp_checksum]")                          \
_(ipfix_exporter_dump, "")                                              \
_(set_ipfix_classify_stream, "[domain <domain-id>] [src_port <src-port>]") \
_(ipfix_classify_stream_dump, "")                                       \
_(ipfix_classify_table_add_del, "table <table-index> ip4|ip6 [tcp|udp]") \
_(ipfix_classify_table_dump, "")                                        \
_(sw_interface_span_enable_disable, "[l2] [src <intfc> | src_sw_if_index <id>] [disable | [[dst <intfc> | dst_sw_if_index <id>] [both|rx|tx]]]") \
_(sw_interface_span_dump, "[l2]")                                           \
_(get_next_index, "node-name <node-name> next-node-name <node-name>")   \
_(pg_create_interface, "if_id <nn>")                                    \
_(pg_capture, "if_id <nnn> pcap <file_name> count <nnn> [disable]")     \
_(pg_enable_disable, "[stream <id>] disable")                           \
_(ip_source_and_port_range_check_add_del,                               \
  "<ip-addr>/<mask> range <nn>-<nn> vrf <id>")                          \
_(ip_source_and_port_range_check_interface_add_del,                     \
  "<intf> | sw_if_index <nn> [tcp-out-vrf <id>] [tcp-in-vrf <id>]"      \
  "[udp-in-vrf <id>] [udp-out-vrf <id>]")                               \
_(ipsec_gre_add_del_tunnel,                                             \
  "src <addr> dst <addr> local_sa <sa-id> remote_sa <sa-id> [del]")     \
_(ipsec_gre_tunnel_dump, "[sw_if_index <nn>]")                          \
_(delete_subif,"<intfc> | sw_if_index <nn>")                            \
_(l2_interface_pbb_tag_rewrite,                                         \
  "<intfc> | sw_if_index <nn> \n"                                       \
  "[disable | push | pop | translate_pbb_stag <outer_tag>] \n"          \
  "dmac <mac> smac <mac> sid <nn> [vlanid <nn>]")                       \
_(set_punt, "protocol <l4-protocol> [ip <ver>] [port <l4-port>] [del]")     \
_(flow_classify_set_interface,                                          \
  "<intfc> | sw_if_index <nn> [ip4-table <nn>] [ip6-table <nn>] [del]") \
_(flow_classify_dump, "type [ip4|ip6]")                                 \
_(ip_fib_dump, "")                                                      \
_(ip_mfib_dump, "")                                                     \
_(ip6_fib_dump, "")                                                     \
_(ip6_mfib_dump, "")                                                    \
_(feature_enable_disable, "arc_name <arc_name> "                        \
  "feature_name <feature_name> <intfc> | sw_if_index <nn> [disable]")	\
_(sw_interface_tag_add_del, "<intfc> | sw_if_index <nn> tag <text>"	\
"[disable]")                                                        	\
_(l2_xconnect_dump, "")                                             	\
_(hw_interface_set_mtu, "<intfc> | hw_if_index <nn> mtu <nn>")        \
_(ip_neighbor_dump, "[ip6] <intfc> | sw_if_index <nn>")                 \
_(sw_interface_get_table, "<intfc> | sw_if_index <id> [ipv6]")          \
_(p2p_ethernet_add, "<intfc> | sw_if_index <nn> remote_mac <mac-address> sub_id <id>") \
_(p2p_ethernet_del, "<intfc> | sw_if_index <nn> remote_mac <mac-address>") \
_(lldp_config, "system-name <name> tx-hold <nn> tx-interval <nn>") \
_(sw_interface_set_lldp, "<intfc> | sw_if_index <nn> [port-desc <description>]\n" \
  " [mgmt-ip4 <ip4>] [mgmt-ip6 <ip6>] [mgmt-oid <object id>] [disable]") \
_(tcp_configure_src_addresses, "<ip4|6>first-<ip4|6>last [vrf <id>]")	\
_(sock_init_shm, "size <nnn>")						\
_(app_namespace_add_del, "[add] id <ns-id> secret <nn> sw_if_index <nn>")\
_(dns_enable_disable, "[enable][disable]")				\
_(dns_name_server_add_del, "<ip-address> [del]")			\
_(dns_resolve_name, "<hostname>")					\
_(dns_resolve_ip, "<ip4|ip6>")						\
_(dns_name_server_add_del, "<ip-address> [del]")			\
_(dns_resolve_name, "<hostname>")					\
_(session_rule_add_del, "[add|del] proto <tcp/udp> <lcl-ip>/<plen> "	\
  "<lcl-port> <rmt-ip>/<plen> <rmt-port> action <nn>")			\
_(session_rules_dump, "")						\
_(ip_container_proxy_add_del, "[add|del] <address> <sw_if_index>")	\
_(output_acl_set_interface,                                             \
  "<intfc> | sw_if_index <nn> [ip4-table <nn>] [ip6-table <nn>]\n"      \
  "  [l2-table <nn>] [del]")                                            \
_(qos_record_enable_disable, "<record-source> <intfc> | sw_if_index <id> [disable]")

/* List of command functions, CLI names map directly to functions */
#define foreach_cli_function                                    \
_(comment, "usage: comment <ignore-rest-of-line>")		\
_(dump_interface_table, "usage: dump_interface_table")          \
_(dump_sub_interface_table, "usage: dump_sub_interface_table")  \
_(dump_ipv4_table, "usage: dump_ipv4_table")                    \
_(dump_ipv6_table, "usage: dump_ipv6_table")                    \
_(dump_macro_table, "usage: dump_macro_table ")                 \
_(dump_node_table, "usage: dump_node_table")			\
_(dump_msg_api_table, "usage: dump_msg_api_table")		\
_(get_msg_id, "usage: get_msg_id name_and_crc")			\
_(echo, "usage: echo <message>")				\
_(exec, "usage: exec <vpe-debug-CLI-command>")                  \
_(exec_inband, "usage: exec_inband <vpe-debug-CLI-command>")    \
_(help, "usage: help")                                          \
_(q, "usage: quit")                                             \
_(quit, "usage: quit")                                          \
_(search_node_table, "usage: search_node_table <name>...")	\
_(set, "usage: set <variable-name> <value>")                    \
_(script, "usage: script <file-name>")                          \
_(statseg, "usage: statseg");                                   \
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
#if VPP_API_TEST_BUILTIN == 0
foreach_standalone_reply_msg;
#endif
#undef _

void
vat_api_hookup (vat_main_t * vam)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler_uni,          \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_reply_msg;
#if VPP_API_TEST_BUILTIN == 0
  foreach_standalone_reply_msg;
#endif
#undef _

#if (VPP_API_TEST_BUILTIN==0)
  vl_msg_api_set_first_available_msg_id (VL_MSG_FIRST_AVAILABLE);

  vam->sw_if_index_by_interface_name = hash_create_string (0, sizeof (uword));

  vam->function_by_name = hash_create_string (0, sizeof (uword));

  vam->help_by_name = hash_create_string (0, sizeof (uword));
#endif

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

#if VPP_API_TEST_BUILTIN
static clib_error_t *
vat_api_hookup_shim (vlib_main_t * vm)
{
  vat_api_hookup (&vat_main);
  return 0;
}

VLIB_API_INIT_FUNCTION (vat_api_hookup_shim);
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
