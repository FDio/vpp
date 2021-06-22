/*
 *------------------------------------------------------------------
 * api_format.c
 *
 * Copyright (c) 2014-2020 Cisco and/or its affiliates.
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
#include <vlib/pci/pci.h>
#include <vpp/api/types.h>
#include <vppinfra/socket.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip.h>
#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/l2/l2_input.h>
#include <vnet/udp/udp_local.h>

#include <vpp/api/vpe_msg_enum.h>
#include <vnet/l2/l2_classify.h>
#include <vnet/l2/l2_vtr.h>
#include <vnet/classify/in_out_acl.h>
#include <vnet/classify/policer_classify.h>
#include <vnet/classify/flow_classify.h>
#include <vnet/mpls/mpls.h>
#include <vnet/ipsec/ipsec.h>
#include <inttypes.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/ip/ip_source_and_port_range_check.h>
#include <vnet/policer/xlate.h>
#include <vnet/span/span.h>
#include <vnet/policer/policer.h>
#include <vnet/policer/police.h>
#include <vnet/mfib/mfib_types.h>
#include <vnet/bonding/node.h>
#include <vnet/qos/qos_types.h>
#include <vnet/ethernet/ethernet_types_api.h>
#include <vnet/ip/ip_types_api.h>
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
#if VPP_API_TEST_BUILTIN == 0
#define vl_print(handle, ...)
#else
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#endif
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun

#define __plugin_msg_base 0
#include <vlibapi/vat_helper_macros.h>

void vl_api_set_elog_main (elog_main_t * m);
int vl_api_set_elog_trace_api_messages (int enable);

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
  api_main_t *am = vlibapi_get_main ();
  vam->socket_client_main = &socket_client_main;
  if ((rv = vl_socket_client_connect ((char *) vam->socket_name,
				      "vpp_api_test",
				      0 /* default socket rx, tx buffer */ )))
    return rv;

  /* vpp expects the client index in network order */
  vam->my_client_index = htonl (socket_client_main.client_index);
  am->my_client_index = vam->my_client_index;
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
    else
      fformat (vam->ofp, "%s\n", (char *) s);
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

/* Parse an IP46 address. */
uword
unformat_ip46_address (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  ip46_type_t type = va_arg (*args, ip46_type_t);
  if ((type != IP46_TYPE_IP6) &&
      unformat (input, "%U", unformat_ip4_address, &ip46->ip4))
    {
      ip46_address_mask_ip4 (ip46);
      return 1;
    }
  else if ((type != IP46_TYPE_IP4) &&
	   unformat (input, "%U", unformat_ip6_address, &ip46->ip6))
    {
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

#else /* VPP_API_TEST_BUILTIN == 1 */
static uword
api_unformat_sw_if_index (unformat_input_t * input, va_list * args)
{
  vat_main_t *vam __clib_unused = va_arg (*args, vat_main_t *);
  vnet_main_t *vnm = vnet_get_main ();
  u32 *result = va_arg (*args, u32 *);

  return unformat (input, "%U", unformat_vnet_sw_interface, vnm, result);
}

#endif /* VPP_API_TEST_BUILTIN */

#if (VPP_API_TEST_BUILTIN==0)

static const char *mfib_flag_names[] = MFIB_ENTRY_NAMES_SHORT;
static const char *mfib_flag_long_names[] = MFIB_ENTRY_NAMES_LONG;
static const char *mfib_itf_flag_long_names[] = MFIB_ITF_NAMES_LONG;
static const char *mfib_itf_flag_names[] = MFIB_ITF_NAMES_SHORT;

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
increment_v4_address (vl_api_ip4_address_t * i)
{
  ip4_address_t *a = (ip4_address_t *) i;
  u32 v;

  v = ntohl (a->as_u32) + 1;
  a->as_u32 = ntohl (v);
}

static void
increment_v6_address (vl_api_ip6_address_t * i)
{
  ip6_address_t *a = (ip6_address_t *) i;
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
increment_address (vl_api_address_t * a)
{
  if (a->af == ADDRESS_IP4)
    increment_v4_address (&a->un.ip4);
  else if (a->af == ADDRESS_IP6)
    increment_v6_address (&a->un.ip6);
}

static void
set_ip4_address (vl_api_address_t * a, u32 v)
{
  if (a->af == ADDRESS_IP4)
    {
      ip4_address_t *i = (ip4_address_t *) & a->un.ip4;
      i->as_u32 = v;
    }
}

void
ip_set (ip46_address_t * dst, void *src, u8 is_ip4)
{
  if (is_ip4)
    dst->ip4.as_u32 = ((ip4_address_t *) src)->as_u32;
  else
    clib_memcpy_fast (&dst->ip6, (ip6_address_t *) src,
		      sizeof (ip6_address_t));
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

static void
vat_json_object_add_address (vat_json_node_t * node,
			     const char *str, const vl_api_address_t * addr)
{
  if (ADDRESS_IP6 == addr->af)
    {
      struct in6_addr ip6;

      clib_memcpy (&ip6, &addr->un.ip6, sizeof (ip6));
      vat_json_object_add_ip6 (node, str, ip6);
    }
  else
    {
      struct in_addr ip4;

      clib_memcpy (&ip4, &addr->un.ip4, sizeof (ip4));
      vat_json_object_add_ip4 (node, str, ip4);
    }
}

static void
vat_json_object_add_prefix (vat_json_node_t * node,
			    const vl_api_prefix_t * prefix)
{
  vat_json_object_add_uint (node, "len", prefix->len);
  vat_json_object_add_address (node, "address", &prefix->address);
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

      sub->raw_flags = ntohl (mp->sub_if_flags & SUB_IF_API_FLAG_MASK_VNET);

      sub->sub_number_of_tags = mp->sub_number_of_tags;
      sub->sub_outer_vlan_id = ntohs (mp->sub_outer_vlan_id);
      sub->sub_inner_vlan_id = ntohs (mp->sub_inner_vlan_id);

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
  vat_json_object_add_bytes (node, "l2_address", mp->l2_address,
			     sizeof (mp->l2_address));
  vat_json_object_add_string_copy (node, "interface_name",
				   mp->interface_name);
  vat_json_object_add_string_copy (node, "interface_dev_type",
				   mp->interface_dev_type);
  vat_json_object_add_uint (node, "flags", mp->flags);
  vat_json_object_add_uint (node, "link_duplex", mp->link_duplex);
  vat_json_object_add_uint (node, "link_speed", mp->link_speed);
  vat_json_object_add_uint (node, "mtu", ntohs (mp->link_mtu));
  vat_json_object_add_uint (node, "sub_id", ntohl (mp->sub_id));
  vat_json_object_add_uint (node, "sub_number_of_tags",
			    mp->sub_number_of_tags);
  vat_json_object_add_uint (node, "sub_outer_vlan_id",
			    ntohs (mp->sub_outer_vlan_id));
  vat_json_object_add_uint (node, "sub_inner_vlan_id",
			    ntohs (mp->sub_inner_vlan_id));
  vat_json_object_add_uint (node, "sub_if_flags", ntohl (mp->sub_if_flags));
  vat_json_object_add_uint (node, "vtr_op", ntohl (mp->vtr_op));
  vat_json_object_add_uint (node, "vtr_push_dot1q",
			    ntohl (mp->vtr_push_dot1q));
  vat_json_object_add_uint (node, "vtr_tag1", ntohl (mp->vtr_tag1));
  vat_json_object_add_uint (node, "vtr_tag2", ntohl (mp->vtr_tag2));
  if (ntohl (mp->sub_if_flags) & SUB_IF_API_FLAG_DOT1AH)
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
	    ((ntohl (mp->flags)) & IF_STATUS_API_FLAG_ADMIN_UP) ?
	    "admin-up" : "admin-down",
	    ((ntohl (mp->flags)) & IF_STATUS_API_FLAG_LINK_UP) ?
	    "link-up" : "link-down");
}
#endif

__clib_unused static void
vl_api_sw_interface_event_t_handler_json (vl_api_sw_interface_event_t * mp)
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
  void *oldheap;
  u8 *reply;

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "reply_in_shmem",
			    ntohl (mp->reply_in_shmem));
  /* Toss the shared-memory original... */
  oldheap = vl_msg_push_heap ();

  reply = uword_to_pointer (mp->reply_in_shmem, u8 *);
  vec_free (reply);

  vl_msg_pop_heap (oldheap);

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

  vec_reset_length (vam->cmd_reply);

  vam->retval = retval;
  if (retval == 0)
    vam->cmd_reply = vl_api_from_api_to_new_vec (mp, &mp->reply);
  vam->result_ready = 1;
}

static void
vl_api_cli_inband_reply_t_handler_json (vl_api_cli_inband_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t node;
  u8 *reply = 0;		/* reply vector */

  reply = vl_api_from_api_to_new_vec (mp, &mp->reply);
  vec_reset_length (vam->cmd_reply);

  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_string_copy (&node, "reply", reply);

  vat_json_print (vam->ofp, &node);
  vat_json_free (&node);
  vec_free (reply);

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
      errmsg ("        program: %s", mp->program);
      errmsg ("        version: %s", mp->version);
      errmsg ("     build date: %s", mp->build_date);
      errmsg ("build directory: %s", mp->build_directory);
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
  vat_json_object_add_string_copy (&node, "program", mp->program);
  vat_json_object_add_string_copy (&node, "version", mp->version);
  vat_json_object_add_string_copy (&node, "build_date", mp->build_date);
  vat_json_object_add_string_copy (&node, "build_directory",
				   mp->build_directory);

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

static void
vl_api_virtio_pci_create_reply_t_handler (vl_api_virtio_pci_create_reply_t *
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
      vam->sw_if_index = ntohl (mp->sw_if_index);
      vam->result_ready = 1;
    }
}

static void vl_api_virtio_pci_create_reply_t_handler_json
  (vl_api_virtio_pci_create_reply_t * mp)
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
  vl_api_virtio_pci_create_v2_reply_t_handler
  (vl_api_virtio_pci_create_v2_reply_t * mp)
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

static void vl_api_virtio_pci_create_v2_reply_t_handler_json
  (vl_api_virtio_pci_create_v2_reply_t * mp)
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
vl_api_virtio_pci_delete_reply_t_handler (vl_api_virtio_pci_delete_reply_t *
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

static void vl_api_virtio_pci_delete_reply_t_handler_json
  (vl_api_virtio_pci_delete_reply_t * mp)
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

  clib_memcpy (&address->ip, &mp->prefix.address.un, sizeof (address->ip));
  address->prefix_length = mp->prefix.len;
#undef addresses
}

static void vl_api_ip_address_details_t_handler_json
  (vl_api_ip_address_details_t * mp)
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
  vat_json_object_add_prefix (node, &mp->prefix);
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
  oldheap = vl_msg_push_heap ();

  vec_free (reply);

  vl_msg_pop_heap (oldheap);

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
  void *oldheap;
  vat_json_node_t node;
  u8 *reply;

  /* $$$$ make this real? */
  vat_json_init_object (&node);
  vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
  vat_json_object_add_uint (&node, "reply_in_shmem", mp->reply_in_shmem);

  reply = uword_to_pointer (mp->reply_in_shmem, u8 *);

  /* Toss the shared-memory original... */
  oldheap = vl_msg_push_heap ();

  vec_free (reply);

  vl_msg_pop_heap (oldheap);

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
_(sw_interface_set_l2_bridge_reply)                     \
_(bridge_domain_add_del_reply)                          \
_(sw_interface_set_l2_xconnect_reply)                   \
_(l2fib_add_del_reply)                                  \
_(l2fib_flush_int_reply)                                \
_(l2fib_flush_bd_reply)                                 \
_(ip_route_add_del_reply)                               \
_(ip_table_add_del_reply)                               \
_(ip_table_replace_begin_reply)                         \
_(ip_table_flush_reply)                                 \
_(ip_table_replace_end_reply)                           \
_(ip_mroute_add_del_reply)                              \
_(mpls_route_add_del_reply)                             \
_(mpls_table_add_del_reply)                             \
_(mpls_ip_bind_unbind_reply)                            \
_(sw_interface_set_unnumbered_reply)                    \
_(set_ip_flow_hash_reply)                               \
_(sw_interface_ip6_enable_disable_reply)                \
_(l2_patch_add_del_reply)                               \
_(l2_fib_clear_table_reply)                             \
_(l2_interface_efp_filter_reply)                        \
_(l2_interface_vlan_tag_rewrite_reply)                  \
_(want_l2_macs_events_reply)                            \
_(delete_loopback_reply)                                \
_(bd_ip_mac_add_del_reply)                              \
_(bd_ip_mac_flush_reply)                                \
_(want_interface_events_reply)                          \
_(sw_interface_clear_stats_reply)                       \
_(ioam_enable_reply)                                    \
_(ioam_disable_reply)                                   \
_(ip_source_and_port_range_check_add_del_reply)         \
_(ip_source_and_port_range_check_interface_add_del_reply)\
_(delete_subif_reply)                                   \
_(l2_interface_pbb_tag_rewrite_reply)                   \
_(sw_interface_tag_add_del_reply)			\
_(sw_interface_add_del_mac_address_reply)		\
_(hw_interface_set_mtu_reply)                           \
_(session_rule_add_del_reply)				\
_(ip_container_proxy_add_del_reply)                     \

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
_(VIRTIO_PCI_CREATE_REPLY, virtio_pci_create_reply)			\
_(VIRTIO_PCI_CREATE_V2_REPLY, virtio_pci_create_v2_reply)		\
_(VIRTIO_PCI_DELETE_REPLY, virtio_pci_delete_reply)			\
_(SW_INTERFACE_VIRTIO_PCI_DETAILS, sw_interface_virtio_pci_details)     \
_(IP_ROUTE_ADD_DEL_REPLY, ip_route_add_del_reply)			\
_(IP_TABLE_ADD_DEL_REPLY, ip_table_add_del_reply)			\
_(IP_TABLE_REPLACE_BEGIN_REPLY, ip_table_replace_begin_reply)           \
_(IP_TABLE_FLUSH_REPLY, ip_table_flush_reply)                           \
_(IP_TABLE_REPLACE_END_REPLY, ip_table_replace_end_reply)               \
_(IP_MROUTE_ADD_DEL_REPLY, ip_mroute_add_del_reply)			\
_(MPLS_TABLE_ADD_DEL_REPLY, mpls_table_add_del_reply)			\
_(MPLS_ROUTE_ADD_DEL_REPLY, mpls_route_add_del_reply)			\
_(MPLS_IP_BIND_UNBIND_REPLY, mpls_ip_bind_unbind_reply)			\
_(MPLS_TUNNEL_ADD_DEL_REPLY, mpls_tunnel_add_del_reply)                 \
_(SW_INTERFACE_SET_UNNUMBERED_REPLY,                                    \
  sw_interface_set_unnumbered_reply)                                    \
_(CREATE_VLAN_SUBIF_REPLY, create_vlan_subif_reply)                     \
_(CREATE_SUBIF_REPLY, create_subif_reply)                     		\
_(SET_IP_FLOW_HASH_REPLY, set_ip_flow_hash_reply)                       \
_(SW_INTERFACE_IP6_ENABLE_DISABLE_REPLY,                                \
  sw_interface_ip6_enable_disable_reply)                                \
_(L2_PATCH_ADD_DEL_REPLY, l2_patch_add_del_reply)                       \
_(GET_NODE_INDEX_REPLY, get_node_index_reply)                           \
_(ADD_NODE_NEXT_REPLY, add_node_next_reply)                             \
_(L2_FIB_CLEAR_TABLE_REPLY, l2_fib_clear_table_reply)                   \
_(L2_INTERFACE_EFP_FILTER_REPLY, l2_interface_efp_filter_reply)         \
_(L2_INTERFACE_VLAN_TAG_REWRITE_REPLY, l2_interface_vlan_tag_rewrite_reply) \
_(SHOW_VERSION_REPLY, show_version_reply)                               \
_(SHOW_THREADS_REPLY, show_threads_reply)                               \
_(L2_FIB_TABLE_DETAILS, l2_fib_table_details)				\
_(INTERFACE_NAME_RENUMBER_REPLY, interface_name_renumber_reply)		\
_(WANT_L2_MACS_EVENTS_REPLY, want_l2_macs_events_reply)			\
_(L2_MACS_EVENT, l2_macs_event)						\
_(IP_ADDRESS_DETAILS, ip_address_details)                               \
_(IP_DETAILS, ip_details)                                               \
_(DELETE_LOOPBACK_REPLY, delete_loopback_reply)                         \
_(BD_IP_MAC_ADD_DEL_REPLY, bd_ip_mac_add_del_reply)                     \
_(BD_IP_MAC_FLUSH_REPLY, bd_ip_mac_flush_reply)                         \
_(BD_IP_MAC_DETAILS, bd_ip_mac_details)                                 \
_(WANT_INTERFACE_EVENTS_REPLY, want_interface_events_reply)             \
_(GET_FIRST_MSG_ID_REPLY, get_first_msg_id_reply)    			\
_(GET_NODE_GRAPH_REPLY, get_node_graph_reply)                           \
_(SW_INTERFACE_CLEAR_STATS_REPLY, sw_interface_clear_stats_reply)      \
_(IOAM_ENABLE_REPLY, ioam_enable_reply)                   \
_(IOAM_DISABLE_REPLY, ioam_disable_reply)                     \
_(MPLS_TUNNEL_DETAILS, mpls_tunnel_details)                             \
_(MPLS_TABLE_DETAILS, mpls_table_details)                               \
_(MPLS_ROUTE_DETAILS, mpls_route_details)                               \
_(GET_NEXT_INDEX_REPLY, get_next_index_reply)                           \
_(IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL_REPLY,                         \
 ip_source_and_port_range_check_add_del_reply)                          \
_(IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL_REPLY,               \
 ip_source_and_port_range_check_interface_add_del_reply)                \
_(DELETE_SUBIF_REPLY, delete_subif_reply)                               \
_(L2_INTERFACE_PBB_TAG_REWRITE_REPLY, l2_interface_pbb_tag_rewrite_reply) \
_(IP_TABLE_DETAILS, ip_table_details)                                   \
_(IP_ROUTE_DETAILS, ip_route_details)                                   \
_(SW_INTERFACE_TAG_ADD_DEL_REPLY, sw_interface_tag_add_del_reply)     	\
_(SW_INTERFACE_ADD_DEL_MAC_ADDRESS_REPLY, sw_interface_add_del_mac_address_reply) \
_(L2_XCONNECT_DETAILS, l2_xconnect_details)                             \
_(HW_INTERFACE_SET_MTU_REPLY, hw_interface_set_mtu_reply)               \
_(SW_INTERFACE_GET_TABLE_REPLY, sw_interface_get_table_reply)           \
_(APP_NAMESPACE_ADD_DEL_REPLY, app_namespace_add_del_reply)		\
_(SESSION_RULE_ADD_DEL_REPLY, session_rule_add_del_reply)		\
_(SESSION_RULES_DETAILS, session_rules_details)				\
_(IP_CONTAINER_PROXY_ADD_DEL_REPLY, ip_container_proxy_add_del_reply)	\

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
  M2 (CLI_INBAND, mp, vec_len (vam->input->buffer));
  vl_api_vec_to_api_string (vam->input->buffer, &mp->cmd);

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
  mp->flags = ntohl ((admin_up) ? IF_STATUS_API_FLAG_ADMIN_UP : 0);

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
  vnet_hw_if_rx_mode mode = VNET_HW_IF_RX_MODE_UNKNOWN;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "queue %d", &queue_id))
	queue_id_valid = 1;
      else if (unformat (i, "polling"))
	mode = VNET_HW_IF_RX_MODE_POLLING;
      else if (unformat (i, "interrupt"))
	mode = VNET_HW_IF_RX_MODE_INTERRUPT;
      else if (unformat (i, "adaptive"))
	mode = VNET_HW_IF_RX_MODE_ADAPTIVE;
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
  if (mode == VNET_HW_IF_RX_MODE_UNKNOWN)
    {
      errmsg ("missing rx-mode");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_SET_RX_MODE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->mode = (vl_api_rx_mode_t) mode;
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
      mp->prefix.address.af = ADDRESS_IP6;
      clib_memcpy (mp->prefix.address.un.ip6, &v6address, sizeof (v6address));
    }
  else
    {
      mp->prefix.address.af = ADDRESS_IP4;
      clib_memcpy (mp->prefix.address.un.ip4, &v4address, sizeof (v4address));
    }
  mp->prefix.len = address_length;

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
  u32 bd_id;
  u8 is_add = 1;
  u8 bd_id_set = 0;
  u8 ip_set = 0;
  u8 mac_set = 0;
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

  mp->entry.bd_id = ntohl (bd_id);
  mp->is_add = is_add;

  clib_memcpy (&mp->entry.ip, &ip, sizeof (ip));
  clib_memcpy (&mp->entry.mac, &mac, sizeof (mac));

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

  print (vam->ofp,
	 "\n%-5d %U %U",
	 ntohl (mp->entry.bd_id),
	 format_vl_api_mac_address, mp->entry.mac,
	 format_vl_api_address, &mp->entry.ip);
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
  vat_json_object_add_uint (node, "bd_id", ntohl (mp->entry.bd_id));
  vat_json_object_add_string_copy (node, "mac_address",
				   format (0, "%U", format_vl_api_mac_address,
					   &mp->entry.mac));
  u8 *ip = 0;

  ip = format (0, "%U", format_vl_api_address, &mp->entry.ip);
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

uword
unformat_vlib_pci_addr (unformat_input_t * input, va_list * args)
{
  vlib_pci_addr_t *addr = va_arg (*args, vlib_pci_addr_t *);
  u32 x[4];

  if (!unformat (input, "%x:%x:%x.%x", &x[0], &x[1], &x[2], &x[3]))
    return 0;

  addr->domain = x[0];
  addr->bus = x[1];
  addr->slot = x[2];
  addr->function = x[3];

  return 1;
}

static int
api_virtio_pci_create_v2 (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_virtio_pci_create_v2_t *mp;
  u8 mac_address[6];
  u8 random_mac = 1;
  u32 pci_addr = 0;
  u64 features = (u64) ~ (0ULL);
  u32 virtio_flags = 0;
  int ret;

  clib_memset (mac_address, 0, sizeof (mac_address));

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "hw-addr %U", unformat_ethernet_address, mac_address))
	{
	  random_mac = 0;
	}
      else if (unformat (i, "pci-addr %U", unformat_vlib_pci_addr, &pci_addr))
	;
      else if (unformat (i, "features 0x%llx", &features))
	;
      else if (unformat (i, "gso-enabled"))
	virtio_flags |= VIRTIO_API_FLAG_GSO;
      else if (unformat (i, "csum-offload-enabled"))
	virtio_flags |= VIRTIO_API_FLAG_CSUM_OFFLOAD;
      else if (unformat (i, "gro-coalesce"))
	virtio_flags |= VIRTIO_API_FLAG_GRO_COALESCE;
      else if (unformat (i, "packed"))
	virtio_flags |= VIRTIO_API_FLAG_PACKED;
      else if (unformat (i, "in-order"))
	virtio_flags |= VIRTIO_API_FLAG_IN_ORDER;
      else if (unformat (i, "buffering"))
	virtio_flags |= VIRTIO_API_FLAG_BUFFERING;
      else
	break;
    }

  if (pci_addr == 0)
    {
      errmsg ("pci address must be non zero. ");
      return -99;
    }

  /* Construct the API message */
  M (VIRTIO_PCI_CREATE_V2, mp);

  mp->use_random_mac = random_mac;

  mp->pci_addr.domain = htons (((vlib_pci_addr_t) pci_addr).domain);
  mp->pci_addr.bus = ((vlib_pci_addr_t) pci_addr).bus;
  mp->pci_addr.slot = ((vlib_pci_addr_t) pci_addr).slot;
  mp->pci_addr.function = ((vlib_pci_addr_t) pci_addr).function;

  mp->features = clib_host_to_net_u64 (features);
  mp->virtio_flags = clib_host_to_net_u32 (virtio_flags);

  if (random_mac == 0)
    clib_memcpy (mp->mac_address, mac_address, 6);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_virtio_pci_delete (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_virtio_pci_delete_t *mp;
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
  M (VIRTIO_PCI_DELETE, mp);

  mp->sw_if_index = htonl (sw_if_index);

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

  mp->table.table_id = ntohl (table_id);
  mp->table.is_ip6 = is_ipv6;
  mp->is_add = is_add;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

uword
unformat_fib_path (unformat_input_t * input, va_list * args)
{
  vat_main_t *vam = va_arg (*args, vat_main_t *);
  vl_api_fib_path_t *path = va_arg (*args, vl_api_fib_path_t *);
  u32 weight, preference;
  mpls_label_t out_label;

  clib_memset (path, 0, sizeof (*path));
  path->weight = 1;
  path->sw_if_index = ~0;
  path->rpf_id = ~0;
  path->n_labels = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U %U",
		    unformat_vl_api_ip4_address,
		    &path->nh.address.ip4,
		    api_unformat_sw_if_index, vam, &path->sw_if_index))
	{
	  path->proto = FIB_API_PATH_NH_PROTO_IP4;
	}
      else if (unformat (input, "%U %U",
			 unformat_vl_api_ip6_address,
			 &path->nh.address.ip6,
			 api_unformat_sw_if_index, vam, &path->sw_if_index))
	{
	  path->proto = FIB_API_PATH_NH_PROTO_IP6;
	}
      else if (unformat (input, "weight %u", &weight))
	{
	  path->weight = weight;
	}
      else if (unformat (input, "preference %u", &preference))
	{
	  path->preference = preference;
	}
      else if (unformat (input, "%U next-hop-table %d",
			 unformat_vl_api_ip4_address,
			 &path->nh.address.ip4, &path->table_id))
	{
	  path->proto = FIB_API_PATH_NH_PROTO_IP4;
	}
      else if (unformat (input, "%U next-hop-table %d",
			 unformat_vl_api_ip6_address,
			 &path->nh.address.ip6, &path->table_id))
	{
	  path->proto = FIB_API_PATH_NH_PROTO_IP6;
	}
      else if (unformat (input, "%U",
			 unformat_vl_api_ip4_address, &path->nh.address.ip4))
	{
	  /*
	   * the recursive next-hops are by default in the default table
	   */
	  path->table_id = 0;
	  path->sw_if_index = ~0;
	  path->proto = FIB_API_PATH_NH_PROTO_IP4;
	}
      else if (unformat (input, "%U",
			 unformat_vl_api_ip6_address, &path->nh.address.ip6))
	{
	  /*
	   * the recursive next-hops are by default in the default table
	   */
	  path->table_id = 0;
	  path->sw_if_index = ~0;
	  path->proto = FIB_API_PATH_NH_PROTO_IP6;
	}
      else if (unformat (input, "resolve-via-host"))
	{
	  path->flags |= FIB_API_PATH_FLAG_RESOLVE_VIA_HOST;
	}
      else if (unformat (input, "resolve-via-attached"))
	{
	  path->flags |= FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED;
	}
      else if (unformat (input, "ip4-lookup-in-table %d", &path->table_id))
	{
	  path->type = FIB_API_PATH_TYPE_LOCAL;
	  path->sw_if_index = ~0;
	  path->proto = FIB_API_PATH_NH_PROTO_IP4;
	}
      else if (unformat (input, "ip6-lookup-in-table %d", &path->table_id))
	{
	  path->type = FIB_API_PATH_TYPE_LOCAL;
	  path->sw_if_index = ~0;
	  path->proto = FIB_API_PATH_NH_PROTO_IP6;
	}
      else if (unformat (input, "sw_if_index %d", &path->sw_if_index))
	;
      else if (unformat (input, "via-label %d", &path->nh.via_label))
	{
	  path->proto = FIB_API_PATH_NH_PROTO_MPLS;
	  path->sw_if_index = ~0;
	}
      else if (unformat (input, "l2-input-on %d", &path->sw_if_index))
	{
	  path->proto = FIB_API_PATH_NH_PROTO_ETHERNET;
	  path->type = FIB_API_PATH_TYPE_INTERFACE_RX;
	}
      else if (unformat (input, "local"))
	{
	  path->type = FIB_API_PATH_TYPE_LOCAL;
	}
      else if (unformat (input, "out-labels"))
	{
	  while (unformat (input, "%d", &out_label))
	    {
	      path->label_stack[path->n_labels].label = out_label;
	      path->label_stack[path->n_labels].is_uniform = 0;
	      path->label_stack[path->n_labels].ttl = 64;
	      path->n_labels++;
	    }
	}
      else if (unformat (input, "via"))
	{
	  /* new path, back up and return */
	  unformat_put_input (input);
	  unformat_put_input (input);
	  unformat_put_input (input);
	  unformat_put_input (input);
	  break;
	}
      else
	{
	  return (0);
	}
    }

  path->proto = ntohl (path->proto);
  path->type = ntohl (path->type);
  path->flags = ntohl (path->flags);
  path->table_id = ntohl (path->table_id);
  path->sw_if_index = ntohl (path->sw_if_index);

  return (1);
}

static int
api_ip_route_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_route_add_del_t *mp;
  u32 vrf_id = 0;
  u8 is_add = 1;
  u8 is_multipath = 0;
  u8 prefix_set = 0;
  u8 path_count = 0;
  vl_api_prefix_t pfx = { };
  vl_api_fib_path_t paths[8];
  int count = 1;
  int j;
  f64 before = 0;
  u32 random_add_del = 0;
  u32 *random_vector = 0;
  u32 random_seed = 0xdeaddabe;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_vl_api_prefix, &pfx))
	prefix_set = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "vrf %d", &vrf_id))
	;
      else if (unformat (i, "count %d", &count))
	;
      else if (unformat (i, "random"))
	random_add_del = 1;
      else if (unformat (i, "multipath"))
	is_multipath = 1;
      else if (unformat (i, "seed %d", &random_seed))
	;
      else
	if (unformat
	    (i, "via %U", unformat_fib_path, vam, &paths[path_count]))
	{
	  path_count++;
	  if (8 == path_count)
	    {
	      errmsg ("max 8 paths");
	      return -99;
	    }
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!path_count)
    {
      errmsg ("specify a path; via ...");
      return -99;
    }
  if (prefix_set == 0)
    {
      errmsg ("missing prefix");
      return -99;
    }

  /* Generate a pile of unique, random routes */
  if (random_add_del)
    {
      ip4_address_t *i = (ip4_address_t *) & paths[0].nh.address.ip4;
      u32 this_random_address;
      uword *random_hash;

      random_hash = hash_create (count, sizeof (uword));

      hash_set (random_hash, i->as_u32, 1);
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
      set_ip4_address (&pfx.address, random_vector[0]);
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
      M2 (IP_ROUTE_ADD_DEL, mp, sizeof (vl_api_fib_path_t) * path_count);

      mp->is_add = is_add;
      mp->is_multipath = is_multipath;

      clib_memcpy (&mp->route.prefix, &pfx, sizeof (pfx));
      mp->route.table_id = ntohl (vrf_id);
      mp->route.n_paths = path_count;

      clib_memcpy (&mp->route.paths, &paths, sizeof (paths[0]) * path_count);

      if (random_add_del)
	set_ip4_address (&pfx.address, random_vector[j + 1]);
      else
	increment_address (&pfx.address);
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
  u8 path_set = 0, prefix_set = 0, is_add = 1;
  vl_api_ip_mroute_add_del_t *mp;
  mfib_entry_flags_t eflags = 0;
  vl_api_mfib_path_t path;
  vl_api_mprefix_t pfx = { };
  u32 vrf_id = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_vl_api_mprefix, &pfx))
	{
	  prefix_set = 1;
	  pfx.grp_address_length = htons (pfx.grp_address_length);
	}
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "vrf %d", &vrf_id))
	;
      else if (unformat (i, "%U", unformat_mfib_itf_flags, &path.itf_flags))
	path.itf_flags = htonl (path.itf_flags);
      else if (unformat (i, "%U", unformat_mfib_entry_flags, &eflags))
	;
      else if (unformat (i, "via %U", unformat_fib_path, vam, &path.path))
	path_set = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (prefix_set == 0)
    {
      errmsg ("missing addresses\n");
      return -99;
    }
  if (path_set == 0)
    {
      errmsg ("missing path\n");
      return -99;
    }

  /* Construct the API message */
  M (IP_MROUTE_ADD_DEL, mp);

  mp->is_add = is_add;
  mp->is_multipath = 1;

  clib_memcpy (&mp->route.prefix, &pfx, sizeof (pfx));
  mp->route.table_id = htonl (vrf_id);
  mp->route.n_paths = 1;
  mp->route.entry_flags = htonl (eflags);

  clib_memcpy (&mp->route.paths, &path, sizeof (path));

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

  mp->mt_table.mt_table_id = ntohl (table_id);
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
  u8 is_add = 1, path_count = 0, is_multipath = 0, is_eos = 0;
  mpls_label_t local_label = MPLS_LABEL_INVALID;
  unformat_input_t *i = vam->input;
  vl_api_mpls_route_add_del_t *mp;
  vl_api_fib_path_t paths[8];
  int count = 1, j;
  f64 before = 0;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%d", &local_label))
	;
      else if (unformat (i, "eos"))
	is_eos = 1;
      else if (unformat (i, "non-eos"))
	is_eos = 0;
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "multipath"))
	is_multipath = 1;
      else if (unformat (i, "count %d", &count))
	;
      else
	if (unformat
	    (i, "via %U", unformat_fib_path, vam, &paths[path_count]))
	{
	  path_count++;
	  if (8 == path_count)
	    {
	      errmsg ("max 8 paths");
	      return -99;
	    }
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!path_count)
    {
      errmsg ("specify a path; via ...");
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
      M2 (MPLS_ROUTE_ADD_DEL, mp, sizeof (vl_api_fib_path_t) * path_count);

      mp->mr_is_add = is_add;
      mp->mr_is_multipath = is_multipath;

      mp->mr_route.mr_label = local_label;
      mp->mr_route.mr_eos = is_eos;
      mp->mr_route.mr_table_id = 0;
      mp->mr_route.mr_n_paths = path_count;

      clib_memcpy (&mp->mr_route.mr_paths, paths,
		   sizeof (paths[0]) * path_count);

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
  return (0);
}

static int
api_mpls_ip_bind_unbind (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_mpls_ip_bind_unbind_t *mp;
  u32 ip_table_id = 0;
  u8 is_bind = 1;
  vl_api_prefix_t pfx;
  u8 prefix_set = 0;
  mpls_label_t local_label = MPLS_LABEL_INVALID;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_vl_api_prefix, &pfx))
	prefix_set = 1;
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

  if (!prefix_set)
    {
      errmsg ("IP prefix not set");
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
  mp->mb_ip_table_id = ntohl (ip_table_id);
  mp->mb_mpls_table_id = 0;
  mp->mb_label = ntohl (local_label);
  clib_memcpy (&mp->mb_prefix, &pfx, sizeof (pfx));

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
  return (0);
}

static int
api_mpls_tunnel_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_mpls_tunnel_add_del_t *mp;

  vl_api_fib_path_t paths[8];
  u32 sw_if_index = ~0;
  u8 path_count = 0;
  u8 l2_only = 0;
  u8 is_add = 1;
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
      else if (unformat (i, "l2-only"))
	l2_only = 1;
      else
	if (unformat
	    (i, "via %U", unformat_fib_path, vam, &paths[path_count]))
	{
	  path_count++;
	  if (8 == path_count)
	    {
	      errmsg ("max 8 paths");
	      return -99;
	    }
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M2 (MPLS_TUNNEL_ADD_DEL, mp, sizeof (vl_api_fib_path_t) * path_count);

  mp->mt_is_add = is_add;
  mp->mt_tunnel.mt_sw_if_index = ntohl (sw_if_index);
  mp->mt_tunnel.mt_l2_only = l2_only;
  mp->mt_tunnel.mt_is_multicast = 0;
  mp->mt_tunnel.mt_n_paths = path_count;

  clib_memcpy (&mp->mt_tunnel.mt_paths, &paths,
	       sizeof (paths[0]) * path_count);

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

#define foreach_create_subif_flag		\
_(0, "no_tags")					\
_(1, "one_tag")					\
_(2, "two_tags")				\
_(3, "dot1ad")					\
_(4, "exact_match")				\
_(5, "default_sub")				\
_(6, "outer_vlan_id_any")			\
_(7, "inner_vlan_id_any")

static int
api_create_subif (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_create_subif_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u32 sub_id;
  u8 sub_id_set = 0;
  u32 __attribute__ ((unused)) no_tags = 0;
  u32 __attribute__ ((unused)) one_tag = 0;
  u32 __attribute__ ((unused)) two_tags = 0;
  u32 __attribute__ ((unused)) dot1ad = 0;
  u32 __attribute__ ((unused)) exact_match = 0;
  u32 __attribute__ ((unused)) default_sub = 0;
  u32 __attribute__ ((unused)) outer_vlan_id_any = 0;
  u32 __attribute__ ((unused)) inner_vlan_id_any = 0;
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

#define _(a,b) mp->sub_if_flags |= (1 << a);
  foreach_create_subif_flag;
#undef _

  mp->outer_vlan_id = ntohs (outer_vlan_id);
  mp->inner_vlan_id = ntohs (inner_vlan_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ip_table_replace_begin (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_table_replace_begin_t *mp;
  u32 table_id = 0;
  u8 is_ipv6 = 0;

  int ret;
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "table %d", &table_id))
	;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IP_TABLE_REPLACE_BEGIN, mp);

  mp->table.table_id = ntohl (table_id);
  mp->table.is_ip6 = is_ipv6;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ip_table_flush (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_table_flush_t *mp;
  u32 table_id = 0;
  u8 is_ipv6 = 0;

  int ret;
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "table %d", &table_id))
	;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IP_TABLE_FLUSH, mp);

  mp->table.table_id = ntohl (table_id);
  mp->table.is_ip6 = is_ipv6;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ip_table_replace_end (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_table_replace_end_t *mp;
  u32 table_id = 0;
  u8 is_ipv6 = 0;

  int ret;
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "table %d", &table_id))
	;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IP_TABLE_REPLACE_END, mp);

  mp->table.table_id = ntohl (table_id);
  mp->table.is_ip6 = is_ipv6;

  S (mp);
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

static void vl_api_sw_interface_virtio_pci_details_t_handler
  (vl_api_sw_interface_virtio_pci_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  typedef union
  {
    struct
    {
      u16 domain;
      u8 bus;
      u8 slot:5;
      u8 function:3;
    };
    u32 as_u32;
  } pci_addr_t;
  pci_addr_t addr;

  addr.domain = ntohs (mp->pci_addr.domain);
  addr.bus = mp->pci_addr.bus;
  addr.slot = mp->pci_addr.slot;
  addr.function = mp->pci_addr.function;

  u8 *pci_addr = format (0, "%04x:%02x:%02x.%x", addr.domain, addr.bus,
			 addr.slot, addr.function);

  print (vam->ofp,
	 "\n%-12s %-12d %-12d %-12d %-17U 0x%-08llx",
	 pci_addr, ntohl (mp->sw_if_index),
	 ntohs (mp->rx_ring_sz), ntohs (mp->tx_ring_sz),
	 format_ethernet_address, mp->mac_addr,
	 clib_net_to_host_u64 (mp->features));
  vec_free (pci_addr);
}

static void vl_api_sw_interface_virtio_pci_details_t_handler_json
  (vl_api_sw_interface_virtio_pci_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  vat_json_node_t *node = NULL;
  vlib_pci_addr_t pci_addr;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  pci_addr.domain = ntohs (mp->pci_addr.domain);
  pci_addr.bus = mp->pci_addr.bus;
  pci_addr.slot = mp->pci_addr.slot;
  pci_addr.function = mp->pci_addr.function;

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "pci-addr", pci_addr.as_u32);
  vat_json_object_add_uint (node, "sw_if_index", ntohl (mp->sw_if_index));
  vat_json_object_add_uint (node, "rx_ring_sz", ntohs (mp->rx_ring_sz));
  vat_json_object_add_uint (node, "tx_ring_sz", ntohs (mp->tx_ring_sz));
  vat_json_object_add_uint (node, "features",
			    clib_net_to_host_u64 (mp->features));
  vat_json_object_add_string_copy (node, "mac_addr",
				   format (0, "%U", format_ethernet_address,
					   &mp->mac_addr));
}

static int
api_sw_interface_virtio_pci_dump (vat_main_t * vam)
{
  vl_api_sw_interface_virtio_pci_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  print (vam->ofp,
	 "\n%-12s %-12s %-12s %-12s %-17s %-08s",
	 "pci_addr", "sw_if_index", "rx_ring_sz", "tx_ring_sz",
	 "mac_addr", "features");

  /* Get list of tap interfaces */
  M (SW_INTERFACE_VIRTIO_PCI_DUMP, mp);
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
api_show_version (vat_main_t *vam)
{
  vl_api_show_version_t *mp;
  int ret;

  M (SHOW_VERSION, mp);

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_l2_fib_table_details_t_handler (vl_api_l2_fib_table_details_t *mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp,
	 "%3" PRIu32 "    %U    %3" PRIu32 "       %d       %d     %d",
	 ntohl (mp->bd_id), format_ethernet_address, mp->mac,
	 ntohl (mp->sw_if_index), mp->static_mac, mp->filter_mac, mp->bvi_mac);
}

static void
vl_api_l2_fib_table_details_t_handler_json (vl_api_l2_fib_table_details_t *mp)
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
api_l2_fib_table_dump (vat_main_t *vam)
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
api_interface_name_renumber (vat_main_t *vam)
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
api_want_l2_macs_events (vat_main_t *vam)
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
api_ip_address_dump (vat_main_t *vam)
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
      else if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
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

static u8 *
format_fib_api_path_nh_proto (u8 * s, va_list * args)
{
  vl_api_fib_path_nh_proto_t proto =
    va_arg (*args, vl_api_fib_path_nh_proto_t);

  switch (proto)
    {
    case FIB_API_PATH_NH_PROTO_IP4:
      s = format (s, "ip4");
      break;
    case FIB_API_PATH_NH_PROTO_IP6:
      s = format (s, "ip6");
      break;
    case FIB_API_PATH_NH_PROTO_MPLS:
      s = format (s, "mpls");
      break;
    case FIB_API_PATH_NH_PROTO_BIER:
      s = format (s, "bier");
      break;
    case FIB_API_PATH_NH_PROTO_ETHERNET:
      s = format (s, "ethernet");
      break;
    }

  return (s);
}

static u8 *
format_vl_api_ip_address_union (u8 * s, va_list * args)
{
  vl_api_address_family_t af = va_arg (*args, int);
  const vl_api_address_union_t *u = va_arg (*args, vl_api_address_union_t *);

  switch (af)
    {
    case ADDRESS_IP4:
      s = format (s, "%U", format_ip4_address, u->ip4);
      break;
    case ADDRESS_IP6:
      s = format (s, "%U", format_ip6_address, u->ip6);
      break;
    }
  return (s);
}

static u8 *
format_vl_api_fib_path_type (u8 * s, va_list * args)
{
  vl_api_fib_path_type_t t = va_arg (*args, vl_api_fib_path_type_t);

  switch (t)
    {
    case FIB_API_PATH_TYPE_NORMAL:
      s = format (s, "normal");
      break;
    case FIB_API_PATH_TYPE_LOCAL:
      s = format (s, "local");
      break;
    case FIB_API_PATH_TYPE_DROP:
      s = format (s, "drop");
      break;
    case FIB_API_PATH_TYPE_UDP_ENCAP:
      s = format (s, "udp-encap");
      break;
    case FIB_API_PATH_TYPE_BIER_IMP:
      s = format (s, "bier-imp");
      break;
    case FIB_API_PATH_TYPE_ICMP_UNREACH:
      s = format (s, "unreach");
      break;
    case FIB_API_PATH_TYPE_ICMP_PROHIBIT:
      s = format (s, "prohibit");
      break;
    case FIB_API_PATH_TYPE_SOURCE_LOOKUP:
      s = format (s, "src-lookup");
      break;
    case FIB_API_PATH_TYPE_DVR:
      s = format (s, "dvr");
      break;
    case FIB_API_PATH_TYPE_INTERFACE_RX:
      s = format (s, "interface-rx");
      break;
    case FIB_API_PATH_TYPE_CLASSIFY:
      s = format (s, "classify");
      break;
    }

  return (s);
}

static void
vl_api_fib_path_print (vat_main_t * vam, vl_api_fib_path_t * fp)
{
  print (vam->ofp,
	 "  weight %d, sw_if_index %d, type %U, afi %U, next_hop %U",
	 ntohl (fp->weight), ntohl (fp->sw_if_index),
	 format_vl_api_fib_path_type, fp->type,
	 format_fib_api_path_nh_proto, fp->proto,
	 format_vl_api_ip_address_union, &fp->nh.address);
}

static void
vl_api_mpls_fib_path_json_print (vat_json_node_t * node,
				 vl_api_fib_path_t * fp)
{
  struct in_addr ip4;
  struct in6_addr ip6;

  vat_json_object_add_uint (node, "weight", ntohl (fp->weight));
  vat_json_object_add_uint (node, "sw_if_index", ntohl (fp->sw_if_index));
  vat_json_object_add_uint (node, "type", fp->type);
  vat_json_object_add_uint (node, "next_hop_proto", fp->proto);
  if (fp->proto == FIB_API_PATH_NH_PROTO_IP4)
    {
      clib_memcpy (&ip4, &fp->nh.address.ip4, sizeof (ip4));
      vat_json_object_add_ip4 (node, "next_hop", ip4);
    }
  else if (fp->proto == FIB_API_PATH_NH_PROTO_IP6)
    {
      clib_memcpy (&ip6, &fp->nh.address.ip6, sizeof (ip6));
      vat_json_object_add_ip6 (node, "next_hop", ip6);
    }
}

static void
vl_api_mpls_tunnel_details_t_handler (vl_api_mpls_tunnel_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  int count = ntohl (mp->mt_tunnel.mt_n_paths);
  vl_api_fib_path_t *fp;
  i32 i;

  print (vam->ofp, "sw_if_index %d via:",
	 ntohl (mp->mt_tunnel.mt_sw_if_index));
  fp = mp->mt_tunnel.mt_paths;
  for (i = 0; i < count; i++)
    {
      vl_api_fib_path_print (vam, fp);
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
  int count = ntohl (mp->mt_tunnel.mt_n_paths);
  vl_api_fib_path_t *fp;
  i32 i;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);

  vat_json_init_object (node);
  vat_json_object_add_uint (node, "sw_if_index",
			    ntohl (mp->mt_tunnel.mt_sw_if_index));

  vat_json_object_add_uint (node, "l2_only", mp->mt_tunnel.mt_l2_only);

  fp = mp->mt_tunnel.mt_paths;
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
  int ret;

  M (MPLS_TUNNEL_DUMP, mp);

  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

#define vl_api_mpls_table_details_t_endian vl_noop_handler
#define vl_api_mpls_table_details_t_print vl_noop_handler


static void
vl_api_mpls_table_details_t_handler (vl_api_mpls_table_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "table-id %d,", ntohl (mp->mt_table.mt_table_id));
}

static void vl_api_mpls_table_details_t_handler_json
  (vl_api_mpls_table_details_t * mp)
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
  vat_json_object_add_uint (node, "table", ntohl (mp->mt_table.mt_table_id));
}

static int
api_mpls_table_dump (vat_main_t * vam)
{
  vl_api_mpls_table_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  M (MPLS_TABLE_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

#define vl_api_mpls_route_details_t_endian vl_noop_handler
#define vl_api_mpls_route_details_t_print vl_noop_handler

static void
vl_api_mpls_route_details_t_handler (vl_api_mpls_route_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  int count = (int) clib_net_to_host_u32 (mp->mr_route.mr_n_paths);
  vl_api_fib_path_t *fp;
  int i;

  print (vam->ofp,
	 "table-id %d, label %u, ess_bit %u",
	 ntohl (mp->mr_route.mr_table_id),
	 ntohl (mp->mr_route.mr_label), mp->mr_route.mr_eos);
  fp = mp->mr_route.mr_paths;
  for (i = 0; i < count; i++)
    {
      vl_api_fib_path_print (vam, fp);
      fp++;
    }
}

static void vl_api_mpls_route_details_t_handler_json
  (vl_api_mpls_route_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  int count = (int) clib_host_to_net_u32 (mp->mr_route.mr_n_paths);
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
  vat_json_object_add_uint (node, "table", ntohl (mp->mr_route.mr_table_id));
  vat_json_object_add_uint (node, "s_bit", mp->mr_route.mr_eos);
  vat_json_object_add_uint (node, "label", ntohl (mp->mr_route.mr_label));
  vat_json_object_add_uint (node, "path_count", count);
  fp = mp->mr_route.mr_paths;
  for (i = 0; i < count; i++)
    {
      vl_api_mpls_fib_path_json_print (node, fp);
      fp++;
    }
}

static int
api_mpls_route_dump (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_mpls_route_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 table_id;
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

  M (MPLS_ROUTE_DUMP, mp);

  mp->table.mt_table_id = ntohl (table_id);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

#define vl_api_ip_table_details_t_endian vl_noop_handler
#define vl_api_ip_table_details_t_print vl_noop_handler

static void
vl_api_ip_table_details_t_handler (vl_api_ip_table_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp,
	 "%s; table-id %d, prefix %U/%d",
	 mp->table.name, ntohl (mp->table.table_id));
}


static void vl_api_ip_table_details_t_handler_json
  (vl_api_ip_table_details_t * mp)
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
  vat_json_object_add_uint (node, "table", ntohl (mp->table.table_id));
}

static int
api_ip_table_dump (vat_main_t * vam)
{
  vl_api_ip_table_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  M (IP_TABLE_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_ip_mtable_dump (vat_main_t * vam)
{
  vl_api_ip_mtable_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  M (IP_MTABLE_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_ip_mroute_dump (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_control_ping_t *mp_ping;
  vl_api_ip_mroute_dump_t *mp;
  int ret, is_ip6;
  u32 table_id;

  is_ip6 = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table_id %d", &table_id))
	;
      else if (unformat (input, "ip6"))
	is_ip6 = 1;
      else if (unformat (input, "ip4"))
	is_ip6 = 0;
      else
	break;
    }
  if (table_id == ~0)
    {
      errmsg ("missing table id");
      return -99;
    }

  M (IP_MROUTE_DUMP, mp);
  mp->table.table_id = table_id;
  mp->table.is_ip6 = is_ip6;
  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

#define vl_api_ip_route_details_t_endian vl_noop_handler
#define vl_api_ip_route_details_t_print vl_noop_handler

static void
vl_api_ip_route_details_t_handler (vl_api_ip_route_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u8 count = mp->route.n_paths;
  vl_api_fib_path_t *fp;
  int i;

  print (vam->ofp,
	 "table-id %d, prefix %U/%d",
	 ntohl (mp->route.table_id),
	 format_ip46_address, mp->route.prefix.address, mp->route.prefix.len);
  for (i = 0; i < count; i++)
    {
      fp = &mp->route.paths[i];

      vl_api_fib_path_print (vam, fp);
      fp++;
    }
}

static void vl_api_ip_route_details_t_handler_json
  (vl_api_ip_route_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u8 count = mp->route.n_paths;
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
  vat_json_object_add_uint (node, "table", ntohl (mp->route.table_id));
  if (ADDRESS_IP6 == mp->route.prefix.address.af)
    {
      clib_memcpy (&ip6, &mp->route.prefix.address.un.ip6, sizeof (ip6));
      vat_json_object_add_ip6 (node, "prefix", ip6);
    }
  else
    {
      clib_memcpy (&ip4, &mp->route.prefix.address.un.ip4, sizeof (ip4));
      vat_json_object_add_ip4 (node, "prefix", ip4);
    }
  vat_json_object_add_uint (node, "mask_length", mp->route.prefix.len);
  vat_json_object_add_uint (node, "path_count", count);
  for (i = 0; i < count; i++)
    {
      fp = &mp->route.paths[i];
      vl_api_mpls_fib_path_json_print (node, fp);
    }
}

static int
api_ip_route_dump (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_ip_route_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 table_id;
  u8 is_ip6;
  int ret;

  is_ip6 = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table_id %d", &table_id))
	;
      else if (unformat (input, "ip6"))
	is_ip6 = 1;
      else if (unformat (input, "ip4"))
	is_ip6 = 0;
      else
	break;
    }
  if (table_id == ~0)
    {
      errmsg ("missing table id");
      return -99;
    }

  M (IP_ROUTE_DUMP, mp);

  mp->table.table_id = table_id;
  mp->table.is_ip6 = is_ip6;

  S (mp);

  /* Use a control ping for synchronization */
  MPING (CONTROL_PING, mp_ping);
  S (mp_ping);

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
  vl_api_prefix_t prefix;
  u32 tmp, tmp2;
  u8 prefix_set = 0;
  u32 vrf_id = ~0;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vl_api_prefix, &prefix))
	prefix_set = 1;
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

  clib_memcpy (&mp->prefix, &prefix, sizeof (prefix));

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

static int
api_sw_interface_add_del_mac_address (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_mac_address_t mac = { 0 };
  vl_api_sw_interface_add_del_mac_address_t *mp;
  u32 sw_if_index = ~0;
  u8 is_add = 1;
  u8 mac_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "%U", unformat_vl_api_mac_address, &mac))
	mac_set++;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (!mac_set)
    {
      errmsg ("missing MAC address");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_ADD_DEL_MAC_ADDRESS, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_add = is_add;
  clib_memcpy (&mp->addr, &mac, sizeof (mac));

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

  vl_api_vec_to_api_string (ns_id, &mp->namespace_id);
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

  rv = vl_socket_client_init_shm (config, 1 /* want_pthread */ );
  if (!rv)
    vam->client_index_invalid = 1;
  return rv;
#else
  return -99;
#endif
}

static void
vl_api_session_rules_details_t_handler (vl_api_session_rules_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  fib_prefix_t lcl, rmt;

  ip_prefix_decode (&mp->lcl, &lcl);
  ip_prefix_decode (&mp->rmt, &rmt);

  if (lcl.fp_proto == FIB_PROTOCOL_IP4)
    {
      print (vam->ofp,
	     "appns %u tp %u scope %d %U/%d %d %U/%d %d action: %d tag: %s",
	     clib_net_to_host_u32 (mp->appns_index), mp->transport_proto,
	     mp->scope, format_ip4_address, &lcl.fp_addr.ip4, lcl.fp_len,
	     clib_net_to_host_u16 (mp->lcl_port), format_ip4_address,
	     &rmt.fp_addr.ip4, rmt.fp_len,
	     clib_net_to_host_u16 (mp->rmt_port),
	     clib_net_to_host_u32 (mp->action_index), mp->tag);
    }
  else
    {
      print (vam->ofp,
	     "appns %u tp %u scope %d %U/%d %d %U/%d %d action: %d tag: %s",
	     clib_net_to_host_u32 (mp->appns_index), mp->transport_proto,
	     mp->scope, format_ip6_address, &lcl.fp_addr.ip6, lcl.fp_len,
	     clib_net_to_host_u16 (mp->lcl_port), format_ip6_address,
	     &rmt.fp_addr.ip6, rmt.fp_len,
	     clib_net_to_host_u16 (mp->rmt_port),
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

  fib_prefix_t lcl, rmt;

  ip_prefix_decode (&mp->lcl, &lcl);
  ip_prefix_decode (&mp->rmt, &rmt);

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }
  node = vat_json_array_add (&vam->json_tree);
  vat_json_init_object (node);

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
  vat_json_object_add_uint (node, "lcl_plen", lcl.fp_len);
  vat_json_object_add_uint (node, "rmt_plen", rmt.fp_len);
  vat_json_object_add_string_copy (node, "tag", mp->tag);
  if (lcl.fp_proto == FIB_PROTOCOL_IP4)
    {
      clib_memcpy (&ip4, &lcl.fp_addr.ip4, sizeof (ip4));
      vat_json_object_add_ip4 (node, "lcl_ip", ip4);
      clib_memcpy (&ip4, &rmt.fp_addr.ip4, sizeof (ip4));
      vat_json_object_add_ip4 (node, "rmt_ip", ip4);
    }
  else
    {
      clib_memcpy (&ip6, &lcl.fp_addr.ip6, sizeof (ip6));
      vat_json_object_add_ip6 (node, "lcl_ip", ip6);
      clib_memcpy (&ip6, &rmt.fp_addr.ip6, sizeof (ip6));
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
  fib_prefix_t lcl, rmt;

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

  clib_memset (&lcl, 0, sizeof (lcl));
  clib_memset (&rmt, 0, sizeof (rmt));
  if (is_ip4)
    {
      ip_set (&lcl.fp_addr, &lcl_ip4, 1);
      ip_set (&rmt.fp_addr, &rmt_ip4, 1);
      lcl.fp_len = lcl_plen;
      rmt.fp_len = rmt_plen;
    }
  else
    {
      ip_set (&lcl.fp_addr, &lcl_ip6, 0);
      ip_set (&rmt.fp_addr, &rmt_ip6, 0);
      lcl.fp_len = lcl_plen;
      rmt.fp_len = rmt_plen;
    }


  ip_prefix_encode (&lcl, &mp->lcl);
  ip_prefix_encode (&rmt, &mp->rmt);
  mp->lcl_port = clib_host_to_net_u16 ((u16) lcl_port);
  mp->rmt_port = clib_host_to_net_u16 ((u16) rmt_port);
  mp->transport_proto =
    proto ? TRANSPORT_PROTO_API_UDP : TRANSPORT_PROTO_API_TCP;
  mp->action_index = clib_host_to_net_u32 (action);
  mp->appns_index = clib_host_to_net_u32 (appns_index);
  mp->scope = scope;
  mp->is_add = is_add;
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
  u32 sw_if_index = ~0;
  vl_api_prefix_t pfx = { };
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	;
      if (unformat (i, "%U", unformat_vl_api_prefix, &pfx))
	;
      else if (unformat (i, "sw_if_index %u", &sw_if_index))
	;
      else
	break;
    }
  if (sw_if_index == ~0 || pfx.len == 0)
    {
      errmsg ("address and sw_if_index must be set");
      return -99;
    }

  M (IP_CONTAINER_PROXY_ADD_DEL, mp);

  mp->sw_if_index = clib_host_to_net_u32 (sw_if_index);
  mp->is_add = is_add;
  clib_memcpy (&mp->pfx, &pfx, sizeof (pfx));

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
elog_save (vat_main_t * vam)
{
#if VPP_API_TEST_BUILTIN == 0
  elog_main_t *em = &vam->elog_main;
  unformat_input_t *i = vam->input;
  char *file, *chroot_file;
  clib_error_t *error;

  if (!unformat (i, "%s", &file))
    {
      errmsg ("expected file name, got `%U'", format_unformat_error, i);
      return 0;
    }

  /* It's fairly hard to get "../oopsie" through unformat; just in case */
  if (strstr (file, "..") || index (file, '/'))
    {
      errmsg ("illegal characters in filename '%s'", file);
      return 0;
    }

  chroot_file = (char *) format (0, "/tmp/%s%c", file, 0);

  vec_free (file);

  errmsg ("Saving %wd of %wd events to %s",
	  elog_n_events_in_buffer (em),
	  elog_buffer_capacity (em), chroot_file);

  error = elog_write_file (em, chroot_file, 1 /* flush ring */ );
  vec_free (chroot_file);

  if (error)
    clib_error_report (error);
#else
  errmsg ("Use the vpp event loger...");
#endif

  return 0;
}

static int
elog_setup (vat_main_t * vam)
{
#if VPP_API_TEST_BUILTIN == 0
  elog_main_t *em = &vam->elog_main;
  unformat_input_t *i = vam->input;
  u32 nevents = 128 << 10;

  (void) unformat (i, "nevents %d", &nevents);

  elog_init (em, nevents);
  vl_api_set_elog_main (em);
  vl_api_set_elog_trace_api_messages (1);
  errmsg ("Event logger initialized with %u events", nevents);
#else
  errmsg ("Use the vpp event loger...");
#endif
  return 0;
}

static int
elog_enable (vat_main_t * vam)
{
#if VPP_API_TEST_BUILTIN == 0
  elog_main_t *em = &vam->elog_main;

  elog_enable_disable (em, 1 /* enable */ );
  vl_api_set_elog_trace_api_messages (1);
  errmsg ("Event logger enabled...");
#else
  errmsg ("Use the vpp event loger...");
#endif
  return 0;
}

static int
elog_disable (vat_main_t * vam)
{
#if VPP_API_TEST_BUILTIN == 0
  elog_main_t *em = &vam->elog_main;

  elog_enable_disable (em, 0 /* enable */ );
  vl_api_set_elog_trace_api_messages (1);
  errmsg ("Event logger disabled...");
#else
  errmsg ("Use the vpp event loger...");
#endif
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
  api_main_t *am = vlibapi_get_main ();
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
_(virtio_pci_create_v2,                                                    \
  "pci-addr <pci-address> [use_random_mac | hw-addr <mac-addr>] [features <hex-value>] [gso-enabled [gro-coalesce] | csum-offload-enabled] [packed] [in-order] [buffering]") \
_(virtio_pci_delete,                                                    \
  "<vpp-if-name> | sw_if_index <id>")                                   \
_(sw_interface_virtio_pci_dump, "")                                     \
_(ip_table_add_del,                                                     \
  "table <n> [ipv6] [add | del]\n")                                     \
_(ip_route_add_del,                                                     \
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
_(sw_interface_set_unnumbered,                                          \
  "<intfc> | sw_if_index <id> unnum_if_index <id> [del]")               \
_(create_vlan_subif, "<intfc> | sw_if_index <id> vlan <n>")             \
_(create_subif, "<intfc> | sw_if_index <id> sub_id <n>\n"               \
  "[outer_vlan_id <n>][inner_vlan_id <n>]\n"                            \
  "[no_tags][one_tag][two_tags][dot1ad][exact_match][default_sub]\n"    \
  "[outer_vlan_id_any][inner_vlan_id_any]")                             \
_(ip_table_replace_begin, "table <n> [ipv6]")                           \
_(ip_table_flush, "table <n> [ipv6]")                                   \
_(ip_table_replace_end, "table <n> [ipv6]")                             \
_(set_ip_flow_hash,                                                     \
  "vrf <n> [src] [dst] [sport] [dport] [proto] [reverse] [ipv6]")       \
_(sw_interface_ip6_enable_disable,                                      \
  "<intfc> | sw_if_index <id> enable | disable")                        \
_(l2_patch_add_del,                                                     \
  "rx <intfc> | rx_sw_if_index <id> tx <intfc> | tx_sw_if_index <id>\n" \
  "enable | disable")                                                   \
_(get_node_index, "node <node-name")                                    \
_(add_node_next, "node <node-name> next <next-node-name>")              \
_(l2_fib_clear_table, "")                                               \
_(l2_interface_efp_filter, "sw_if_index <nn> enable | disable")         \
_(l2_interface_vlan_tag_rewrite,                                        \
  "<intfc> | sw_if_index <nn> \n"                                       \
  "[disable][push-[1|2]][pop-[1|2]][translate-1-[1|2]] \n"              \
  "[translate-2-[1|2]] [push_dot1q 0] tag1 <nn> tag2 <nn>")             \
_(show_version, "")                                                     \
_(show_threads, "")                                                     \
_(l2_fib_table_dump, "bd_id <bridge-domain-id>")			\
_(interface_name_renumber,                                              \
  "<intfc> | sw_if_index <nn> new_show_dev_instance <nn>")		\
_(want_l2_macs_events, "[disable] [learn-limit <n>] [scan-delay <n>] [max-entries <n>]") \
_(ip_address_dump, "(ipv4 | ipv6) (<intfc> | sw_if_index <id>)")        \
_(ip_dump, "ipv4 | ipv6")                                               \
_(delete_loopback,"sw_if_index <nn>")                                   \
_(bd_ip_mac_add_del, "bd_id <bridge-domain-id> <ip4/6-addr> <mac-addr> [del]") \
_(bd_ip_mac_flush, "bd_id <bridge-domain-id>")                          \
_(bd_ip_mac_dump, "[bd_id] <bridge-domain-id>")                         \
_(want_interface_events,  "enable|disable")                             \
_(get_first_msg_id, "client <name>")					\
_(get_node_graph, " ")                                                  \
_(sw_interface_clear_stats,"<intfc> | sw_if_index <nn>")                \
_(ioam_enable, "[trace] [pow] [ppc <encap|decap>]")                     \
_(ioam_disable, "")                                                     \
_(mpls_tunnel_dump, "tunnel_index <tunnel-id>")                         \
_(mpls_table_dump, "")                                                  \
_(mpls_route_dump, "table-id <ID>")                                     \
_(get_next_index, "node-name <node-name> next-node-name <node-name>")   \
_(ip_source_and_port_range_check_add_del,                               \
  "<ip-addr>/<mask> range <nn>-<nn> vrf <id>")                          \
_(ip_source_and_port_range_check_interface_add_del,                     \
  "<intf> | sw_if_index <nn> [tcp-out-vrf <id>] [tcp-in-vrf <id>]"      \
  "[udp-in-vrf <id>] [udp-out-vrf <id>]")                               \
_(delete_subif,"<intfc> | sw_if_index <nn>")                            \
_(l2_interface_pbb_tag_rewrite,                                         \
  "<intfc> | sw_if_index <nn> \n"                                       \
  "[disable | push | pop | translate_pbb_stag <outer_tag>] \n"          \
  "dmac <mac> smac <mac> sid <nn> [vlanid <nn>]")                       \
_(ip_table_dump, "")                                                    \
_(ip_route_dump, "table-id [ip4|ip6]")                                  \
_(ip_mtable_dump, "")                                                   \
_(ip_mroute_dump, "table-id [ip4|ip6]")                                 \
_(sw_interface_tag_add_del, "<intfc> | sw_if_index <nn> tag <text>"	\
"[disable]")                                                        	\
_(sw_interface_add_del_mac_address, "<intfc> | sw_if_index <nn> "	\
  "mac <mac-address> [del]")                                            \
_(l2_xconnect_dump, "")                                             	\
_(hw_interface_set_mtu, "<intfc> | hw_if_index <nn> mtu <nn>")        \
_(sw_interface_get_table, "<intfc> | sw_if_index <id> [ipv6]")          \
_(sock_init_shm, "size <nnn>")						\
_(app_namespace_add_del, "[add] id <ns-id> secret <nn> sw_if_index <nn>")\
_(session_rule_add_del, "[add|del] proto <tcp/udp> <lcl-ip>/<plen> "	\
  "<lcl-port> <rmt-ip>/<plen> <rmt-port> action <nn>")			\
_(session_rules_dump, "")						\
_(ip_container_proxy_add_del, "[add|del] <address> <sw_if_index>")	\

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
_(elog_setup, "usage: elog_setup [nevents, default 128K]")      \
_(elog_disable, "usage: elog_disable")                          \
_(elog_enable, "usage: elog_enable")                            \
_(elog_save, "usage: elog_save <filename>")                     \
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
_(statseg, "usage: statseg")                                    \
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
