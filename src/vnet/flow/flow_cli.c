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
#include <stddef.h>

#include <vnet/vnet.h>
#include <vnet/devices/devices.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
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

uword
unformat_ip_protocol_and_mask (unformat_input_t * input, va_list * args)
{
  ip_prot_and_mask_t *pm = va_arg (*args, ip_prot_and_mask_t *);
  u32 prot = 0, mask = 0;

  if (unformat (input, "any"))
    ;
  else if (unformat (input, "%U", unformat_ip_protocol, &prot))
    mask = 0xFF;
  else if (unformat (input, "%u", &prot))
    mask = 0xFF;
  else
    return 0;

  if (prot > 0XFF || mask > 0xFF)
    return 0;

  pm->prot = prot;
  pm->mask = mask;
  return 1;
}

u8 *
format_ip_protocol_and_mask (u8 * s, va_list * args)
{
  ip_prot_and_mask_t *pm = va_arg (*args, ip_prot_and_mask_t *);

  if (pm->prot == 0 && pm->mask == 0)
    return format (s, "any");

  return format (s, "%U", format_ip_protocol, pm->prot);
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

u8 *
format_rss_function (u8 * s, va_list * args)
{
  vnet_rss_function_t func = va_arg (*args, vnet_rss_function_t);

  if (0)
    ;
#undef _
#define _(f, n) \
      else if (func == VNET_RSS_FUNC_##f) \
        return format (s, n);

  foreach_rss_function
#undef _
    return format (s, "unknown");
}

u8 *
format_rss_types (u8 * s, va_list * args)
{
  u64 type = va_arg (*args, u64);

#undef _
#define _(a,b,c)     \
  if (type & (1UL<<a)) \
    s = format (s, "%s ", c);

  foreach_flow_rss_types
#undef _
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
  pool_foreach (f, fm->global_flow_pool)
    {
      vlib_cli_output (vm, "%U\n", format_flow, f);
    }
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
  enum
  {
    FLOW_UNKNOWN_CLASS,
    FLOW_ETHERNET_CLASS,
    FLOW_IPV4_CLASS,
    FLOW_IPV6_CLASS,
  } flow_class = FLOW_UNKNOWN_CLASS;

  u32 hw_if_index = ~0, flow_index = ~0;
  int rv;
  u32 teid = 0, session_id = 0, spi = 0;
  u32 vni = 0;
  vnet_flow_type_t type = VNET_FLOW_TYPE_UNKNOWN;
  ip4_address_and_mask_t ip4s = { };
  ip4_address_and_mask_t ip4d = { };
  ip6_address_and_mask_t ip6s = { };
  ip6_address_and_mask_t ip6d = { };
  ip_port_and_mask_t sport = { };
  ip_port_and_mask_t dport = { };
  ip_prot_and_mask_t protocol = { };
  u16 eth_type;
  bool tcp_udp_port_set = false;
  bool gtpc_set = false;
  bool gtpu_set = false;
  bool vni_set = false;
  bool l2tpv3oip_set = false;
  bool ipsec_esp_set = false, ipsec_ah_set = false;
  u8 *rss_type[3] = { };
  u8 *type_str = NULL;
  u8 *spec = NULL;
  u8 *mask = NULL;

  clib_memset (&flow, 0, sizeof (vnet_flow_t));
  flow.index = ~0;
  flow.actions = 0;

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
      else if (unformat (line_input, "spec %s", &spec))
	;
      else if (unformat (line_input, "mask %s", &mask))
	;
      else if (unformat (line_input, "eth-type %U",
			 unformat_ethernet_type_host_byte_order, &eth_type))
	flow_class = FLOW_ETHERNET_CLASS;
      else if (unformat (line_input, "src-ip %U",
			 unformat_ip4_address_and_mask, &ip4s))
	flow_class = FLOW_IPV4_CLASS;
      else if (unformat (line_input, "dst-ip %U",
			 unformat_ip4_address_and_mask, &ip4d))
	flow_class = FLOW_IPV4_CLASS;
      else if (unformat (line_input, "ip6-src-ip %U",
			 unformat_ip6_address_and_mask, &ip6s))
	flow_class = FLOW_IPV6_CLASS;
      else if (unformat (line_input, "ip6-dst-ip %U",
			 unformat_ip6_address_and_mask, &ip6d))
	flow_class = FLOW_IPV6_CLASS;
      else if (unformat (line_input, "src-port %U", unformat_ip_port_and_mask,
			 &sport))
	tcp_udp_port_set = true;
      else if (unformat (line_input, "dst-port %U", unformat_ip_port_and_mask,
			 &dport))
	tcp_udp_port_set = true;
      else
	if (unformat
	    (line_input, "proto %U", unformat_ip_protocol_and_mask,
	     &protocol))
	;
      else if (unformat (line_input, "gtpc teid %u", &teid))
	gtpc_set = true;
      else if (unformat (line_input, "gtpu teid %u", &teid))
	gtpu_set = true;
      else if (unformat (line_input, "vxlan vni %u", &vni))
	vni_set = true;
      else if (unformat (line_input, "session id %u", &session_id))
	{
	  if (protocol.prot == IP_PROTOCOL_L2TP)
	    l2tpv3oip_set = true;
	}
      else if (unformat (line_input, "spi %u", &spi))
	{
	  if (protocol.prot == IP_PROTOCOL_IPSEC_ESP)
	    ipsec_esp_set = true;
	  else if (protocol.prot == IP_PROTOCOL_IPSEC_AH)
	    ipsec_ah_set = true;
	}
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
      else if (unformat (line_input, "rss function"))
	{
	  if (0)
	    ;
#undef _
#define _(f, s) \
      else if (unformat (line_input, s)) \
      flow.rss_fun = VNET_RSS_FUNC_##f;

	  foreach_rss_function
#undef _
	    else
	    {
	      return clib_error_return (0, "unknown input `%U'",
					format_unformat_error, line_input);
	    }

	  flow.actions |= VNET_FLOW_ACTION_RSS;
	}
      else if (unformat (line_input, "rss types"))
	{
	  rss_type[0] = NULL;
	  rss_type[1] = NULL;
	  rss_type[2] = NULL;
	  type_str = NULL;

	  if (unformat (line_input, "%s use %s and %s",
			&rss_type[0], &rss_type[1], &rss_type[2]))
	    ;
	  else if (unformat
		   (line_input, "%s use %s", &rss_type[0], &rss_type[1]))
	    ;
	  else if (unformat (line_input, "%s", &rss_type[0]))
	    ;

#undef _
#define _(a,b,c)     \
      else if (!clib_strcmp(c, (const char *)type_str)) \
        flow.rss_types |= (1ULL<<a);

#define check_rss_types(_str)     \
      if (_str != NULL) {\
        type_str = _str;\
        if (0) \
          ; \
        foreach_flow_rss_types \
        else \
        { \
          return clib_error_return (0, "parse error: '%U'", \
          format_unformat_error, line_input); \
        } \
      }

	  check_rss_types (rss_type[0])
	    check_rss_types (rss_type[1]) check_rss_types (rss_type[2])
#undef _
	    flow.actions |= VNET_FLOW_ACTION_RSS;
	}
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
      switch (flow_class)
	{
	case FLOW_ETHERNET_CLASS:
	  type = VNET_FLOW_TYPE_ETHERNET;
	  break;

	case FLOW_IPV4_CLASS:
	  if (gtpc_set)
	    {
	      type = VNET_FLOW_TYPE_IP4_GTPC;
	      protocol.prot = IP_PROTOCOL_UDP;
	    }
	  else if (gtpu_set)
	    {
	      type = VNET_FLOW_TYPE_IP4_GTPU;
	      protocol.prot = IP_PROTOCOL_UDP;
	    }
	  else if (vni_set)
	    {
	      type = VNET_FLOW_TYPE_IP4_VXLAN;
	      protocol.prot = IP_PROTOCOL_UDP;
	    }
	  else if (l2tpv3oip_set)
	    type = VNET_FLOW_TYPE_IP4_L2TPV3OIP;
	  else if (ipsec_esp_set)
	    type = VNET_FLOW_TYPE_IP4_IPSEC_ESP;
	  else if (ipsec_ah_set)
	    type = VNET_FLOW_TYPE_IP4_IPSEC_AH;
	  else if (tcp_udp_port_set)
	    type = VNET_FLOW_TYPE_IP4_N_TUPLE;
	  else
	    type = VNET_FLOW_TYPE_IP4;
	  break;
	case FLOW_IPV6_CLASS:
	  if (tcp_udp_port_set)
	    type = VNET_FLOW_TYPE_IP6_N_TUPLE;
	  else if (vni_set)
	    type = VNET_FLOW_TYPE_IP6_VXLAN;
	  else
	    type = VNET_FLOW_TYPE_IP6;
	  break;

	default:
	  if (spec && mask)
	    {
	      type = VNET_FLOW_TYPE_GENERIC;
	      break;
	    }
	  return clib_error_return (0,
				    "Please specify a supported flow type");
	}

      /* Assign specific field values per flow type */
      if (flow_class == FLOW_ETHERNET_CLASS)
	{
	  flow.ethernet.eth_hdr.type = eth_type;
	}
      else if (flow_class == FLOW_IPV4_CLASS)
	{
	  vnet_flow_ip4_t *ip4_ptr = &flow.ip4;

	  clib_memcpy (&ip4_ptr->src_addr, &ip4s,
		       sizeof (ip4_address_and_mask_t));
	  clib_memcpy (&ip4_ptr->dst_addr, &ip4d,
		       sizeof (ip4_address_and_mask_t));
	  ip4_ptr->protocol.prot = protocol.prot;

	  /* In this cli, we use the protocol.mask only when the flow type is
	   * VNET_FLOW_TYPE_IP4/IP6. For other cases, the IP protocol is just
	   * used to identify the next layer type: e.g. UDP/TCP or IPSEC_ESP
	   */
	  if (type == VNET_FLOW_TYPE_IP4)
	    ip4_ptr->protocol.mask = protocol.mask;

	  switch (protocol.prot)
	    {
	      /* ip4-n-tuple */
	    case IP_PROTOCOL_TCP:
	    case IP_PROTOCOL_UDP:
	      flow.ip4_n_tuple.src_port = sport;
	      flow.ip4_n_tuple.dst_port = dport;

	      if (type == VNET_FLOW_TYPE_IP4_GTPC)
		flow.ip4_gtpc.teid = teid;
	      else if (type == VNET_FLOW_TYPE_IP4_GTPU)
		flow.ip4_gtpu.teid = teid;
	      else if (type == VNET_FLOW_TYPE_IP4_VXLAN)
		flow.ip4_vxlan.vni = vni;
	      break;
	    case IP_PROTOCOL_L2TP:
	      flow.ip4_l2tpv3oip.session_id = session_id;
	      break;
	    case IP_PROTOCOL_IPSEC_ESP:
	      flow.ip4_ipsec_esp.spi = spi;
	      break;
	    case IP_PROTOCOL_IPSEC_AH:
	      flow.ip4_ipsec_esp.spi = spi;
	      break;
	    default:
	      break;
	    }
	}
      else if (flow_class == FLOW_IPV6_CLASS)
	{
	  vnet_flow_ip6_t *ip6_ptr = &flow.ip6;

	  clib_memcpy (&flow.ip6_n_tuple.src_addr, &ip6s,
		       sizeof (ip6_address_and_mask_t));
	  clib_memcpy (&flow.ip6_n_tuple.dst_addr, &ip6d,
		       sizeof (ip6_address_and_mask_t));

	  ip6_ptr->protocol.prot = protocol.prot;

	  /* In this cli, we use the protocol.mask only when the flow type is
	   * VNET_FLOW_TYPE_IP4/IP6. For other cases, the IP protocol is just
	   * used to identify the next layer type: e.g. UDP/TCP or IPSEC_ESP
	   */
	  if (type == VNET_FLOW_TYPE_IP6)
	    ip6_ptr->protocol.mask = protocol.mask;

	  switch (protocol.prot)
	    {
	      /* ip6-n-tuple */
	    case IP_PROTOCOL_TCP:
	    case IP_PROTOCOL_UDP:
	      flow.ip6_n_tuple.src_port = sport;
	      flow.ip6_n_tuple.dst_port = dport;

	      if (type == VNET_FLOW_TYPE_IP6_VXLAN)
		flow.ip6_vxlan.vni = vni;
	      break;
	    default:
	      break;
	    }
	}
      if (type == VNET_FLOW_TYPE_GENERIC)
	{
	  clib_memcpy (flow.generic.pattern.spec, spec,
		       sizeof (flow.generic.pattern.spec));
	  clib_memcpy (flow.generic.pattern.mask, mask,
		       sizeof (flow.generic.pattern.mask));
	}

      flow.type = type;
      rv = vnet_flow_add (vnm, &flow, &flow_index);
      if (!rv)
	vlib_cli_output (vm, "flow %u added", flow_index);

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
    .short_help = "test flow [add|del|enable|disable] [index <id>] "
        "[src-ip <ip-addr/mask>] [dst-ip <ip-addr/mask>] "
        "[ip6-src-ip <ip-addr/mask>] [ip6-dst-ip <ip-addr/mask>] "
        "[src-port <port/mask>] [dst-port <port/mask>] "
        "[proto <ip-proto>] "
        "[gtpc teid <teid>] [gtpu teid <teid>] [vxlan <vni>] "
        "[session id <session>] [spi <spi>]"
        "[next-node <node>] [mark <id>] [buffer-advance <len>] "
        "[redirect-to-queue <queue>] [drop] "
        "[rss function <name>] [rss types <flow type>]",
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

  if (strncmp (type, "ethernet_header_t", 13) == 0)
    {
      ethernet_max_header_t m;
      memset (&m, 0, sizeof (m));
      m.ethernet = *(ethernet_header_t *) ptr;
      /* convert the ethernet type to net order */
      m.ethernet.type = clib_host_to_net_u16 (m.ethernet.type);
      return format (s, "%U", format_ethernet_header, &m);
    }

  if (strncmp (type, "ip4_address_t", 13) == 0)
    return format (s, "%U", format_ip4_address, ptr);

  if (strncmp (type, "ip4_address_and_mask_t", 13) == 0)
    return format (s, "%U", format_ip4_address_and_mask, ptr);

  if (strncmp (type, "ip6_address_t", 13) == 0)
    return format (s, "%U", format_ip6_address, ptr);

  if (strncmp (type, "ip6_address_and_mask_t", 13) == 0)
    return format (s, "%U", format_ip6_address_and_mask, ptr);

  if (strncmp (type, "ip_prot_and_mask_t", 13) == 0)
    return format (s, "%U", format_ip_protocol_and_mask, ptr);

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

  if (f->actions & VNET_FLOW_ACTION_DROP)
    t = format (t, "%sdrop", t ? ", " : "");

  if (f->actions & VNET_FLOW_ACTION_MARK)
    t = format (t, "%smark %u", t ? ", " : "", f->mark_flow_id);

  if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    t =
      format (t, "%sredirect-to-queue %u", t ? ", " : "", f->redirect_queue);

  if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
    t = format (t, "%snext-node %U", t ? ", " : "",
		format_vlib_node_name, vm, f->redirect_node_index);

  if (f->actions & VNET_FLOW_ACTION_BUFFER_ADVANCE)
    t = format (t, "%sbuffer-advance %d", t ? ", " : "", f->buffer_advance);

  if (f->actions & VNET_FLOW_ACTION_RSS)
    {
      t = format (t, "%srss function %U", t ? ", " : "",
		  format_rss_function, f->rss_fun);
      t = format (t, "%srss types %U", t ? ", " : "",
		  format_rss_types, f->rss_types);
    }

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
