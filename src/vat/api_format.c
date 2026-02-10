/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2014-2020 Cisco and/or its affiliates.
 */

/*
 * api_format.c
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
#include <vnet/span/span.h>
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

#include <vlibmemory/memclnt.api_enum.h>
#include <vlibmemory/memclnt.api_types.h>
#include <vlibmemory/memclnt.api_tojson.h>
#include <vlibmemory/memclnt.api_fromjson.h>

#define vl_endianfun		/* define message structures */
#include <vlibmemory/memclnt.api.h>
#undef vl_endianfun

#define vl_calcsizefun
#include <vlibmemory/memclnt.api.h>
#undef vl_calcsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include <vlibmemory/memclnt.api.h>
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

void
ip_set (ip46_address_t * dst, void *src, u8 is_ip4)
{
  if (is_ip4)
    dst->ip4.as_u32 = ((ip4_address_t *) src)->as_u32;
  else
    clib_memcpy_fast (&dst->ip6, (ip6_address_t *) src,
		      sizeof (ip6_address_t));
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
vl_api_control_ping_reply_t_handler (vl_api_control_ping_reply_t *mp)
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

static void
vl_api_control_ping_reply_t_handler_json (vl_api_control_ping_reply_t *mp)
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

/*
 * Generate boilerplate reply handlers, which
 * dig the return value out of the xxx_reply_t API message,
 * stick it into vam->retval, and set vam->result_ready
 *
 * Could also do this by pointing N message decode slots at
 * a single function, but that could break in subtle ways.
 */

#define foreach_standard_reply_retval_handler

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

#define foreach_vpe_api_reply_msg                                             \
  _ (GET_FIRST_MSG_ID_REPLY, get_first_msg_id_reply)                          \
  _ (CONTROL_PING_REPLY, control_ping_reply)

#define foreach_standalone_reply_msg					\

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

uword
unformat_vlib_pci_addr (unformat_input_t *input, va_list *args)
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

uword
unformat_fib_path (unformat_input_t *input, va_list *args)
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
      if (unformat (input, "%U %U", unformat_vl_api_ip4_address,
		    &path->nh.address.ip4, api_unformat_sw_if_index, vam,
		    &path->sw_if_index))
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


#define foreach_tcp_proto_field                                               \
  _ (src_port)                                                                \
  _ (dst_port)

#define foreach_udp_proto_field                                               \
  _ (src_port)                                                                \
  _ (dst_port)

#define foreach_ip4_proto_field                                               \
  _ (src_address)                                                             \
  _ (dst_address)                                                             \
  _ (tos)                                                                     \
  _ (length)                                                                  \
  _ (fragment_id)                                                             \
  _ (ttl)                                                                     \
  _ (protocol)                                                                \
  _ (checksum)

typedef struct
{
  u16 src_port, dst_port;
} tcpudp_header_t;

#if VPP_API_TEST_BUILTIN == 0
uword
unformat_tcp_mask (unformat_input_t *input, va_list *args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u8 *mask = 0;
  u8 found_something = 0;
  tcp_header_t *tcp;

#define _(a) u8 a = 0;
  foreach_tcp_proto_field;
#undef _

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0)
	;
#define _(a) else if (unformat (input, #a)) a = 1;
      foreach_tcp_proto_field
#undef _
	else break;
    }

#define _(a) found_something += a;
  foreach_tcp_proto_field;
#undef _

  if (found_something == 0)
    return 0;

  vec_validate (mask, sizeof (*tcp) - 1);

  tcp = (tcp_header_t *) mask;

#define _(a)                                                                  \
  if (a)                                                                      \
    clib_memset (&tcp->a, 0xff, sizeof (tcp->a));
  foreach_tcp_proto_field;
#undef _

  *maskp = mask;
  return 1;
}

uword
unformat_udp_mask (unformat_input_t *input, va_list *args)
{
  u8 **maskp = va_arg (*args, u8 **);
  u8 *mask = 0;
  u8 found_something = 0;
  udp_header_t *udp;

#define _(a) u8 a = 0;
  foreach_udp_proto_field;
#undef _

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0)
	;
#define _(a) else if (unformat (input, #a)) a = 1;
      foreach_udp_proto_field
#undef _
	else break;
    }

#define _(a) found_something += a;
  foreach_udp_proto_field;
#undef _

  if (found_something == 0)
    return 0;

  vec_validate (mask, sizeof (*udp) - 1);

  udp = (udp_header_t *) mask;

#define _(a)                                                                  \
  if (a)                                                                      \
    clib_memset (&udp->a, 0xff, sizeof (udp->a));
  foreach_udp_proto_field;
#undef _

  *maskp = mask;
  return 1;
}

uword
unformat_l4_mask (unformat_input_t *input, va_list *args)
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

      vec_set_len (mask, match * sizeof (u32x4));

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
      vec_set_len (match, (match_n_vectors + skip_n_vectors) * sizeof (u32x4));

      *matchp = match;

      return 1;
    }

  return 0;
}

#define foreach_vtr_op                                                        \
  _ ("disable", L2_VTR_DISABLED)                                              \
  _ ("push-1", L2_VTR_PUSH_1)                                                 \
  _ ("push-2", L2_VTR_PUSH_2)                                                 \
  _ ("pop-1", L2_VTR_POP_1)                                                   \
  _ ("pop-2", L2_VTR_POP_2)                                                   \
  _ ("translate-1-1", L2_VTR_TRANSLATE_1_1)                                   \
  _ ("translate-1-2", L2_VTR_TRANSLATE_1_2)                                   \
  _ ("translate-2-1", L2_VTR_TRANSLATE_2_1)                                   \
  _ ("translate-2-2", L2_VTR_TRANSLATE_2_2)

static int
api_get_first_msg_id (vat_main_t *vam)
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

#define foreach_pbb_vtr_op      \
_("disable",  L2_VTR_DISABLED)  \
_("pop",  L2_VTR_POP_2)         \
_("push",  L2_VTR_PUSH_2)

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
  if (strstr (file, "..") || strchr (file, '/'))
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

    hash_foreach_pair (p, vam->function_by_name,
    ({
      vec_add1 (cmds, (u8 *)(p->key));
    }));

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

  hash_foreach_pair (p, vam->macro_main.the_value_table_hash, ({
		       vec_add2 (sort_me, sm, 1);
		       sm->name = (u8 *) (p->key);
		       sm->value = (u8 *) (p->value[0]);
		     }));

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

  hash_foreach_pair (hp, am->msg_index_by_name_and_crc,
  ({
    vec_add2 (nses, ns, 1);
    ns->name = (u8 *)(hp->key);
    ns->value = (u32) hp->value[0];
  }));

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

int exec (vat_main_t *vam) __attribute__ ((weak));
int
exec (vat_main_t *vam)
{
  return -1;
}

static int
name_sort_cmp (void *a1, void *a2)
{
  name_sort_t *n1 = a1;
  name_sort_t *n2 = a2;

  return strcmp ((char *) n1->name, (char *) n2->name);
}

static int
dump_interface_table (vat_main_t *vam)
{
  hash_pair_t *p;
  name_sort_t *nses = 0, *ns;

  if (vam->json_output)
    {
      clib_warning (
	"JSON output supported only for VPE API calls and dump_stats_table");
      return -99;
    }

  hash_foreach_pair (p, vam->sw_if_index_by_interface_name, ({
		       vec_add2 (nses, ns, 1);
		       ns->name = (u8 *) (p->key);
		       ns->value = (u32) p->value[0];
		     }));

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
dump_sub_interface_table (vat_main_t *vam)
{
  const sw_interface_subif_t *sub = NULL;

  if (vam->json_output)
    {
      clib_warning (
	"JSON output supported only for VPE API calls and dump_stats_table");
      return -99;
    }

  print (vam->ofp, "%-30s%-12s%-11s%-7s%-5s%-9s%-9s%-6s%-8s%-10s%-10s",
	 "Interface", "sw_if_index", "sub id", "dot1ad", "tags", "outer id",
	 "inner id", "exact", "default", "outer any", "inner any");

  vec_foreach (sub, vam->sw_if_subif_table)
    {
      print (vam->ofp, "%-30s%-12d%-11d%-7s%-5d%-9d%-9d%-6d%-8d%-10d%-10d",
	     sub->interface_name, sub->sw_if_index, sub->sub_id,
	     sub->sub_dot1ad ? "dot1ad" : "dot1q", sub->sub_number_of_tags,
	     sub->sub_outer_vlan_id, sub->sub_inner_vlan_id,
	     sub->sub_exact_match, sub->sub_default,
	     sub->sub_outer_vlan_id_any, sub->sub_inner_vlan_id_any);
      if (sub->vtr_op != L2_VTR_DISABLED)
	{
	  print (vam->ofp,
		 "  vlan-tag-rewrite - op: %-14s [ dot1q: %d "
		 "tag1: %d tag2: %d ]",
		 str_vtr_op (sub->vtr_op), sub->vtr_push_dot1q, sub->vtr_tag1,
		 sub->vtr_tag2);
	}
    }

  return 0;
}

/* List of API message constructors, CLI names map to api_xxx */
#define foreach_vpe_api_msg                                             \
_(get_first_msg_id, "client <name>")					\
_(sock_init_shm, "size <nnn>")						\
/* List of command functions, CLI names map directly to functions */
#define foreach_cli_function                                                  \
  _ (comment, "usage: comment <ignore-rest-of-line>")                         \
  _ (dump_interface_table, "usage: dump_interface_table")                     \
  _ (dump_sub_interface_table, "usage: dump_sub_interface_table")             \
  _ (dump_macro_table, "usage: dump_macro_table ")                            \
  _ (dump_msg_api_table, "usage: dump_msg_api_table")                         \
  _ (elog_setup, "usage: elog_setup [nevents, default 128K]")                 \
  _ (elog_disable, "usage: elog_disable")                                     \
  _ (elog_enable, "usage: elog_enable")                                       \
  _ (elog_save, "usage: elog_save <filename>")                                \
  _ (get_msg_id, "usage: get_msg_id name_and_crc")                            \
  _ (echo, "usage: echo <message>")                                           \
  _ (help, "usage: help")                                                     \
  _ (q, "usage: quit")                                                        \
  _ (quit, "usage: quit")                                                     \
  _ (search_node_table, "usage: search_node_table <name>...")                 \
  _ (set, "usage: set <variable-name> <value>")                               \
  _ (script, "usage: script <file-name>")                                     \
  _ (statseg, "usage: statseg")                                               \
  _ (unset, "usage: unset <variable-name>")

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
#define _(N, n)                                                               \
  vl_msg_api_config (&(vl_msg_api_msg_config_t){                              \
    .id = VL_API_##N + 1,                                                     \
    .name = #n,                                                               \
    .handler = vl_api_##n##_t_handler_uni,                                    \
    .endian = vl_api_##n##_t_endian,                                          \
    .format_fn = vl_api_##n##_t_format,                                       \
    .size = sizeof (vl_api_##n##_t),                                          \
    .traced = 1,                                                              \
    .tojson = vl_api_##n##_t_tojson,                                          \
    .fromjson = vl_api_##n##_t_fromjson,                                      \
    .calc_size = vl_api_##n##_t_calc_size,                                    \
  });
  foreach_vpe_api_reply_msg;
#if VPP_API_TEST_BUILTIN == 0
  foreach_standalone_reply_msg;
#endif
#undef _

#if (VPP_API_TEST_BUILTIN==0)
  vl_msg_api_set_first_available_msg_id (VL_MSG_MEMCLNT_LAST + 1);

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
