/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/devices/devices.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/flow/flow.h>

static format_function_t format_flow;

uword
unformat_ip_port_and_mask (unformat_input_t * input, va_list * args)
{
  ip_port_and_mask_t *pm = va_arg (*args, ip_port_and_mask_t *);
  u32 port = 0, mask = 0;

  if (unformat (input, "any"))
    ;
  else if (unformat (input, "%u/%u", &port, &mask))
    ;
  else if (unformat (input, "%u/0x%x", &port, &mask))
    ;
  else if (unformat (input, "%u", &port))
    mask = 0xffff;
  else
    return 0;

  if (port > 0xffff || mask > 0xffff)
    return 0;

  pm->port = port;
  pm->mask = mask;
  return 1;
}

u8 *
format_ip_port_and_mask (u8 * s, va_list * args)
{
  ip_port_and_mask_t *pm = va_arg (*args, ip_port_and_mask_t *);

  if (pm->port == 0 && pm->mask == 0)
    return format (s, "any");

  if (pm->mask == 0xffff)
    return format (s, "%u", pm->port);

  return format (s, "%u/0x%x", pm->port, pm->mask);
}

u8 *
format_flow_error (u8 * s, va_list * args)
{
  int error = va_arg (*args, int);

  if (error == 0)
    return format (s, "no error");

#define _(v,n,str) if (error == v) return format (s, #str);
  foreach_flow_error;
#undef _

  return format (s, "unknown error (%d)", error);
}

u8 *
format_flow_actions (u8 * s, va_list * args)
{
  u32 actions = va_arg (*args, u32);
  u8 *t = 0;

#define _(a, b, c) if (actions & (1 << a)) \
  t = format (t, "%s%s", t ? " ":"", c);
  foreach_flow_action
#undef _
    s = format (s, "%v", t);
  vec_free (t);
  return s;
}

u8 *
format_flow_enabled_hw (u8 * s, va_list * args)
{
  u32 flow_index = va_arg (*args, u32);
  vnet_flow_t *f = vnet_get_flow (flow_index);
  if (f == 0)
    return format (s, "not found");

  u8 *t = 0;
  u32 hw_if_index;
  uword private_data;
  vnet_main_t *vnm = vnet_get_main ();
  /* *INDENT-OFF* */
  hash_foreach (hw_if_index, private_data, f->private_data,
    ({
     t = format (t, "%s%U", t ? ", " : "",
                 format_vnet_hw_if_index_name, vnm, hw_if_index);
     }));
  /* *INDENT-ON* */
  s = format (s, "%v", t);
  vec_free (t);
  return s;
}

static const char *flow_type_strings[] = { 0,
#define _(a,b,c) c,
  foreach_flow_type
#undef _
};

static clib_error_t *
show_flow_entry (vlib_main_t * vm, unformat_input_t * input,
		 vlib_cli_command_t * cmd_arg)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_flow_main_t *fm = &flow_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  vnet_flow_t *f;
  uword private_data;
  u32 index = ~0, hw_if_index;

  if (!unformat_user (input, unformat_line_input, line_input))
    goto no_args;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "index %u", &index))
	;
      else
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (index != ~0)
    {
      if ((f = vnet_get_flow (index)) == 0)
	return clib_error_return (0, "no such flow");

      vlib_cli_output (vm, "%-10s: %u", "index", f->index);
      vlib_cli_output (vm, "%-10s: %s", "type", flow_type_strings[f->type]);
      vlib_cli_output (vm, "%-10s: %U", "match", format_flow, f);
      /* *INDENT-OFF* */
      hash_foreach (hw_if_index, private_data, f->private_data,
        ({
	 hi = vnet_get_hw_interface (vnm, hw_if_index);
	  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
	  vlib_cli_output (vm,  "interface %U\n",
			   format_vnet_hw_if_index_name, vnm, hw_if_index);
	  if (dev_class->format_flow)
	    vlib_cli_output (vm,  "  %U\n", dev_class->format_flow,
			     hi->dev_instance, f->index, private_data);
         }));
      /* *INDENT-ON* */
      return 0;
    }

no_args:
  /* *INDENT-OFF* */
  pool_foreach (f, fm->global_flow_pool,
    {
      vlib_cli_output (vm, "%U\n", format_flow, f);
    });
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_flow_entry_command, static) = {
    .path = "show flow entry",
    .short_help = "show flow entry [index <index>]",
    .function = show_flow_entry,
};
/* *INDENT-ON* */

static clib_error_t *
show_flow_ranges (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd_arg)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_range_t *r = 0;

  vlib_cli_output (vm, "%8s  %8s  %s", "Start", "Count", "Owner");

  /* *INDENT-OFF* */
  vec_foreach (r, fm->ranges)
    {
      vlib_cli_output (vm, "%8u  %8u  %s", r->start, r->count, r->owner);
    };
  /* *INDENT-ON* */
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_flow_ranges_command, static) = {
    .path = "show flow ranges",
    .short_help = "show flow ranges",
    .function = show_flow_ranges,
};
/* *INDENT-ON* */

static clib_error_t *
show_flow_interface (vlib_main_t * vm, unformat_input_t * input,
		     vlib_cli_command_t * cmd_arg)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 hw_if_index = ~0;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "%U",
			unformat_vnet_hw_interface, vnm, &hw_if_index))
	    ;
	  else
	    return clib_error_return (0, "parse error: '%U'",
				      format_unformat_error, line_input);
	}
      unformat_free (line_input);
    }

  if (hw_if_index == ~0)
    return clib_error_return (0, "please specify interface");

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
  if (dev_class->format_flow == 0)
    return clib_error_return (0, "not supported");

  vlib_cli_output (vm, "%U", dev_class->format_flow, hi->dev_instance, ~0, 0);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_flow_interface_command, static) = {
    .path = "show flow interface",
    .short_help = "show flow interface <interface name>",
    .function = show_flow_interface,
};
/* *INDENT-ON* */

static clib_error_t *
test_flow (vlib_main_t * vm, unformat_input_t * input,
	   vlib_cli_command_t * cmd_arg)
{
  vnet_flow_t flow;
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  enum
  {
    FLOW_UNKNOWN_ACTION,
    FLOW_ADD,
    FLOW_DEL,
    FLOW_ENABLE,
    FLOW_DISABLE
  } action = FLOW_UNKNOWN_ACTION;
  u32 hw_if_index = ~0, flow_index = ~0;
  int rv;
  u32 prot = 0, teid = 0;
  vnet_flow_type_t type = VNET_FLOW_TYPE_IP4_N_TUPLE;
  bool is_gtpc_set = false;
  bool is_gtpu_set = false;
  vnet_flow_type_t outer_type = VNET_FLOW_TYPE_UNKNOWN;
  vnet_flow_type_t inner_type = VNET_FLOW_TYPE_UNKNOWN;
  bool outer_ip4_set = false, inner_ip4_set = false;
  bool outer_ip6_set = false, inner_ip6_set = false;
  ip4_address_and_mask_t ip4s = { };
  ip4_address_and_mask_t ip4d = { };
  ip4_address_and_mask_t inner_ip4s = { };
  ip4_address_and_mask_t inner_ip4d = { };
  ip6_address_and_mask_t ip6s = { };
  ip6_address_and_mask_t ip6d = { };
  ip6_address_and_mask_t inner_ip6s = { };
  ip6_address_and_mask_t inner_ip6d = { };
  ip_port_and_mask_t sport = { };
  ip_port_and_mask_t dport = { };

  clib_memset (&flow, 0, sizeof (vnet_flow_t));
  flow.index = ~0;
  flow.actions = 0;
  flow.ip4_n_tuple.protocol = ~0;
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	action = FLOW_ADD;
      else if (unformat (line_input, "del"))
	action = FLOW_DEL;
      else if (unformat (line_input, "enable"))
	action = FLOW_ENABLE;
      else if (unformat (line_input, "disable"))
	action = FLOW_DISABLE;
      else if (unformat (line_input, "src-ip %U",
			 unformat_ip4_address_and_mask, &ip4s))
	outer_ip4_set = true;
      else if (unformat (line_input, "dst-ip %U",
			 unformat_ip4_address_and_mask, &ip4d))
	outer_ip4_set = true;
      else if (unformat (line_input, "ip6-src-ip %U",
			 unformat_ip6_address_and_mask, &ip6s))
	outer_ip6_set = true;
      else if (unformat (line_input, "ip6-dst-ip %U",
			 unformat_ip6_address_and_mask, &ip6d))
	outer_ip6_set = true;
      else if (unformat (line_input, "inner-src-ip %U",
			 unformat_ip4_address_and_mask, &inner_ip4s))
	inner_ip4_set = true;
      else if (unformat (line_input, "inner-dst-ip %U",
			 unformat_ip4_address_and_mask, &inner_ip4d))
	inner_ip4_set = true;
      else if (unformat (line_input, "inner-ip6-src-ip %U",
			 unformat_ip6_address_and_mask, &inner_ip6s))
	inner_ip6_set = true;
      else if (unformat (line_input, "inner-ip6-dst-ip %U",
			 unformat_ip6_address_and_mask, &inner_ip6d))
	inner_ip6_set = true;

      else if (unformat (line_input, "src-port %U", unformat_ip_port_and_mask,
			 &sport))
	;
      else if (unformat (line_input, "dst-port %U", unformat_ip_port_and_mask,
			 &dport))
	;
      else if (unformat (line_input, "proto %U", unformat_ip_protocol, &prot))
	;
      else if (unformat (line_input, "proto %u", &prot))
	;
      else if (unformat (line_input, "gtpc teid %u", &teid))
	is_gtpc_set = true;
      else if (unformat (line_input, "gtpu teid %u", &teid))
	is_gtpu_set = true;
      else if (unformat (line_input, "index %u", &flow_index))
	;
      else if (unformat (line_input, "next-node %U", unformat_vlib_node, vm,
			 &flow.redirect_node_index))
	flow.actions |= VNET_FLOW_ACTION_REDIRECT_TO_NODE;
      else if (unformat (line_input, "mark %d", &flow.mark_flow_id))
	flow.actions |= VNET_FLOW_ACTION_MARK;
      else if (unformat (line_input, "buffer-advance %d",
			 &flow.buffer_advance))
	flow.actions |= VNET_FLOW_ACTION_BUFFER_ADVANCE;
      else if (unformat (line_input, "redirect-to-queue %d",
			 &flow.redirect_queue))
	flow.actions |= VNET_FLOW_ACTION_REDIRECT_TO_QUEUE;
      else if (unformat (line_input, "drop"))
	flow.actions |= VNET_FLOW_ACTION_DROP;
      else if (unformat (line_input, "%U", unformat_vnet_hw_interface, vnm,
			 &hw_if_index))
	;
      else
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (hw_if_index == ~0 && (action == FLOW_ENABLE || action == FLOW_DISABLE))
    return clib_error_return (0, "Please specify interface name");

  if (flow_index == ~0 && (action == FLOW_ENABLE || action == FLOW_DISABLE ||
			   action == FLOW_DEL))
    return clib_error_return (0, "Please specify flow index");

  switch (action)
    {
    case FLOW_ADD:
      if (flow.actions == 0)
	return clib_error_return (0, "Please specify at least one action");

      /* Adjust the flow type */
      if (outer_ip4_set == true)
	outer_type = VNET_FLOW_TYPE_IP4_N_TUPLE;
      else if (outer_ip6_set == true)
	outer_type = VNET_FLOW_TYPE_IP6_N_TUPLE;
      if (inner_ip4_set == true)
	inner_type = VNET_FLOW_TYPE_IP4_N_TUPLE;
      else if (inner_ip6_set == true)
	inner_type = VNET_FLOW_TYPE_IP6_N_TUPLE;

      if (outer_type == VNET_FLOW_TYPE_UNKNOWN)
	return clib_error_return (0, "Please specify a supported flow type");

      if (outer_type == VNET_FLOW_TYPE_IP4_N_TUPLE)
	{
	  type = VNET_FLOW_TYPE_IP4_N_TUPLE;

	  if (inner_type == VNET_FLOW_TYPE_UNKNOWN)
	    {
	      if (is_gtpc_set)
		type = VNET_FLOW_TYPE_IP4_GTPC;
	      else if (is_gtpu_set)
		type = VNET_FLOW_TYPE_IP4_GTPU;
	    }
	  else if (inner_type == VNET_FLOW_TYPE_IP4_N_TUPLE)
	    {
	      if (is_gtpu_set)
		type = VNET_FLOW_TYPE_IP4_GTPU_IP4;
	    }
	  else if (inner_type == VNET_FLOW_TYPE_IP6_N_TUPLE)
	    {
	      if (is_gtpu_set)
		type = VNET_FLOW_TYPE_IP4_GTPU_IP6;
	    }
	}
      else if (outer_type == VNET_FLOW_TYPE_IP6_N_TUPLE)
	{
	  type = VNET_FLOW_TYPE_IP6_N_TUPLE;

	  if (inner_type == VNET_FLOW_TYPE_UNKNOWN)
	    {
	      if (is_gtpc_set)
		type = VNET_FLOW_TYPE_IP6_GTPC;
	      else if (is_gtpu_set)
		type = VNET_FLOW_TYPE_IP6_GTPU;
	    }
	  else if (inner_type == VNET_FLOW_TYPE_IP4_N_TUPLE)
	    {
	      if (is_gtpu_set)
		type = VNET_FLOW_TYPE_IP6_GTPU_IP4;
	    }
	  else if (inner_type == VNET_FLOW_TYPE_IP6_N_TUPLE)
	    {
	      if (is_gtpu_set)
		type = VNET_FLOW_TYPE_IP6_GTPU_IP6;
	    }
	}

      //assign specific field values per flow type
      switch (type)
	{
	case VNET_FLOW_TYPE_IP4_N_TUPLE:
	case VNET_FLOW_TYPE_IP4_GTPC:
	case VNET_FLOW_TYPE_IP4_GTPU:
	case VNET_FLOW_TYPE_IP4_GTPU_IP4:
	case VNET_FLOW_TYPE_IP4_GTPU_IP6:
	  clib_memcpy (&flow.ip4_n_tuple.src_addr, &ip4s,
		       sizeof (ip4_address_and_mask_t));
	  clib_memcpy (&flow.ip4_n_tuple.dst_addr, &ip4d,
		       sizeof (ip4_address_and_mask_t));
	  clib_memcpy (&flow.ip4_n_tuple.src_port, &sport,
		       sizeof (ip_port_and_mask_t));
	  clib_memcpy (&flow.ip4_n_tuple.dst_port, &dport,
		       sizeof (ip_port_and_mask_t));
	  flow.ip4_n_tuple.protocol = prot;

	  if (type == VNET_FLOW_TYPE_IP4_GTPC)
	    flow.ip4_gtpc.teid = teid;
	  else if (type == VNET_FLOW_TYPE_IP4_GTPU)
	    flow.ip4_gtpu.teid = teid;
	  else if (type == VNET_FLOW_TYPE_IP4_GTPU_IP4)
	    {
	      flow.ip4_gtpu_ip4.teid = teid;
	      clib_memcpy (&flow.ip4_gtpu_ip4.inner_src_addr, &inner_ip4s,
			   sizeof (ip4_address_and_mask_t));
	      clib_memcpy (&flow.ip4_gtpu_ip4.inner_dst_addr, &inner_ip4d,
			   sizeof (ip4_address_and_mask_t));
	    }
	  else if (type == VNET_FLOW_TYPE_IP4_GTPU_IP6)
	    {
	      flow.ip4_gtpu_ip6.teid = teid;
	      clib_memcpy (&flow.ip4_gtpu_ip6.inner_src_addr, &inner_ip6s,
			   sizeof (ip6_address_and_mask_t));
	      clib_memcpy (&flow.ip4_gtpu_ip6.inner_dst_addr, &inner_ip6d,
			   sizeof (ip6_address_and_mask_t));
	    }

	  if (flow.ip4_n_tuple.protocol == (ip_protocol_t) ~ 0)
	    return clib_error_return (0, "Please specify ip protocol");
	  if ((type != VNET_FLOW_TYPE_IP4_N_TUPLE) &&
	      (flow.ip4_n_tuple.protocol != IP_PROTOCOL_UDP))
	    return clib_error_return (0,
				      "For GTP related flow, ip protocol must be UDP");
	  break;

	case VNET_FLOW_TYPE_IP6_N_TUPLE:
	case VNET_FLOW_TYPE_IP6_GTPC:
	case VNET_FLOW_TYPE_IP6_GTPU:
	case VNET_FLOW_TYPE_IP6_GTPU_IP4:
	case VNET_FLOW_TYPE_IP6_GTPU_IP6:
	  clib_memcpy (&flow.ip6_n_tuple.src_addr, &ip6s,
		       sizeof (ip6_address_and_mask_t));
	  clib_memcpy (&flow.ip6_n_tuple.dst_addr, &ip6d,
		       sizeof (ip6_address_and_mask_t));
	  clib_memcpy (&flow.ip6_n_tuple.src_port, &sport,
		       sizeof (ip_port_and_mask_t));
	  clib_memcpy (&flow.ip6_n_tuple.dst_port, &dport,
		       sizeof (ip_port_and_mask_t));
	  flow.ip6_n_tuple.protocol = prot;

	  if (type == VNET_FLOW_TYPE_IP6_GTPC)
	    flow.ip6_gtpc.teid = teid;
	  else if (type == VNET_FLOW_TYPE_IP6_GTPU)
	    flow.ip6_gtpu.teid = teid;
	  else if (type == VNET_FLOW_TYPE_IP6_GTPU_IP4)
	    {
	      flow.ip6_gtpu_ip4.teid = teid;
	      clib_memcpy (&flow.ip6_gtpu_ip4.inner_src_addr, &inner_ip4s,
			   sizeof (ip4_address_and_mask_t));
	      clib_memcpy (&flow.ip6_gtpu_ip4.inner_dst_addr, &inner_ip4d,
			   sizeof (ip4_address_and_mask_t));
	    }
	  else if (type == VNET_FLOW_TYPE_IP6_GTPU_IP6)
	    {
	      flow.ip6_gtpu_ip6.teid = teid;
	      clib_memcpy (&flow.ip6_gtpu_ip6.inner_src_addr, &inner_ip6s,
			   sizeof (ip6_address_and_mask_t));
	      clib_memcpy (&flow.ip6_gtpu_ip6.inner_dst_addr, &inner_ip6d,
			   sizeof (ip6_address_and_mask_t));
	    }

	  if (flow.ip6_n_tuple.protocol == (ip_protocol_t) ~ 0)
	    return clib_error_return (0, "Please specify ip protocol");
	  if ((type != VNET_FLOW_TYPE_IP4_N_TUPLE) &&
	      (flow.ip6_n_tuple.protocol != IP_PROTOCOL_UDP))
	    return clib_error_return (0,
				      "For GTP related flow, ip protocol must be UDP");
	  break;

	default:
	  break;
	}

      flow.type = type;
      rv = vnet_flow_add (vnm, &flow, &flow_index);
      if (!rv)
	printf ("flow %u added\n", flow_index);

      break;
    case FLOW_DEL:
      rv = vnet_flow_del (vnm, flow_index);
      break;
    case FLOW_ENABLE:
      rv = vnet_flow_enable (vnm, flow_index, hw_if_index);
      break;
    case FLOW_DISABLE:
      rv = vnet_flow_disable (vnm, flow_index, hw_if_index);
      break;
    default:
      return clib_error_return (0, "please specify action (add, del, enable,"
				" disable)");
    }

  if (rv < 0)
    return clib_error_return (0, "flow error: %U", format_flow_error, rv);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_flow_command, static) = {
    .path = "test flow",
    .short_help = "test flow add [src-ip <ip-addr/mask>] [dst-ip "
      "<ip-addr/mask>] [src-port <port/mask>] [dst-port <port/mask>] "
      "[proto <ip-proto>",
    .function = test_flow,
};
/* *INDENT-ON* */


static u8 *
format_flow_match_element (u8 * s, va_list * args)
{
  char *type = va_arg (*args, char *);
  void *ptr = va_arg (*args, void *);

  if (strncmp (type, "u8", 2) == 0)
    return format (s, "%d", *(u8 *) ptr);

  if (strncmp (type, "u16", 3) == 0)
    return format (s, "%d", *(u16 *) ptr);

  if (strncmp (type, "u32", 3) == 0)
    return format (s, "%d", *(u32 *) ptr);

  if (strncmp (type, "ip4_address_t", 13) == 0)
    return format (s, "%U", format_ip4_address, ptr);

  if (strncmp (type, "ip4_address_and_mask_t", 13) == 0)
    return format (s, "%U", format_ip4_address_and_mask, ptr);

  if (strncmp (type, "ip6_address_t", 13) == 0)
    return format (s, "%U", format_ip6_address, ptr);

  if (strncmp (type, "ip6_address_and_mask_t", 13) == 0)
    return format (s, "%U", format_ip6_address_and_mask, ptr);

  if (strncmp (type, "ip_protocol_t", 13) == 0)
    return format (s, "%U", format_ip_protocol, *(ip_protocol_t *) ptr);

  if (strncmp (type, "ip_port_and_mask_t", 18) == 0)
    return format (s, "%U", format_ip_port_and_mask, ptr);

  s = format (s, "unknown type '%s'", type);
  return s;
}

#define _fe(a,b) s2 = format (s2, "%s%s %U", s2 ? ", ":"", #b, \
			      format_flow_match_element, #a, &f->b);
#define _(a,b,c) \
u8 * format_flow_match_##b (u8 * s, va_list * args)			\
{									\
  vnet_flow_##b##_t *f = __builtin_va_arg (*args, vnet_flow_##b##_t *); \
  u8 *s2 = 0; \
foreach_flow_entry_##b \
  s = format (s, "%v", s2);; \
  vec_free (s2); \
return s; \
}
foreach_flow_type
#undef _
#undef _fe
static u8 *
format_flow_match (u8 * s, va_list * args)
{
  vnet_flow_t *f = va_arg (*args, vnet_flow_t *);

#define _(a,b,c) \
  if (f->type == VNET_FLOW_TYPE_##a) \
    return format (s, "%U", format_flow_match_##b, &f->b);
  foreach_flow_type;
#undef _

  return s;
}

static u8 *
format_flow (u8 * s, va_list * args)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_flow_t *f = va_arg (*args, vnet_flow_t *);
  u32 indent = format_get_indent (s);
  u8 *t = 0;

  s = format (s, "flow-index %u type %s active %u",
	      f->index, flow_type_strings[f->type],
	      hash_elts (f->private_data)),
    s = format (s, "\n%Umatch: %U", format_white_space, indent + 2,
		format_flow_match, f);
  s = format (s, "\n%Uaction: %U", format_white_space, indent + 2,
	      format_flow_actions, f->actions);

  if (f->actions & VNET_FLOW_ACTION_MARK)
    t = format (t, "%smark %u", t ? ", " : "", f->mark_flow_id);

  if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
    t = format (t, "%snext-node %U", t ? ", " : "",
		format_vlib_node_name, vm, f->redirect_node_index);

  if (f->actions & VNET_FLOW_ACTION_BUFFER_ADVANCE)
    t = format (t, "%sbuffer-advance %d", t ? ", " : "", f->buffer_advance);

  if (t)
    {
      s = format (s, "\n%U%v", format_white_space, indent + 4, t);
      vec_free (t);
    }

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
