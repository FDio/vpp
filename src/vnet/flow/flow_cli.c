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
static u32 next_test_flow_id = ~0;

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

static const char *flow_type_strings[] = { 0,
#define _(a,b,c) c,
  foreach_flow_type
#undef _
};

static clib_error_t *
show_flow_id (vlib_main_t * vm, unformat_input_t * input,
	      vlib_cli_command_t * cmd_arg)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_flow_main_t *fm = &flow_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_flow_t *f;
  u32 id = 0, hw_if_index;

  if (!unformat_user (input, unformat_line_input, line_input))
    goto no_args;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "id %u", &id))
	;
      else
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (id)
    {
      if ((f = vnet_get_flow (id)) == 0)
	return clib_error_return (0, "no such flow");

      vlib_cli_output (vm, "%-10s: %u", "id", f->id);
      vlib_cli_output (vm, "%-10s: %s", "type", flow_type_strings[f->id]);
      vlib_cli_output (vm, "%-10s: %U", "match", format_flow, f);
      /* *INDENT-OFF* */
      clib_bitmap_foreach (hw_if_index, f->hw_if_bmp,
        ({
	  vnet_flow_hw_if_t *hwif;
          hwif = vec_elt_at_index (fm->interfaces, hw_if_index);
	  vlib_cli_output (vm,  "interface %U\n",
			   format_vnet_hw_if_index_name, vnm, hw_if_index);
	  vlib_cli_output (vm,  "  %U\n", hwif->format_interface_flow,
			   hw_if_index, f->id);
         }));
      /* *INDENT-ON* */
      return 0;
    }

no_args:
  vlib_cli_output (vm, "%8s  %-15s %-6s  %s",
		   "ID", "Type", "Active", "Description");

  /* *INDENT-OFF* */
  pool_foreach (f, fm->global_flow_pool,
    {
      vlib_cli_output (vm, "%8u  %-15s %6u  %U", f->id,
		       flow_type_strings[f->type],
                       clib_bitmap_count_set_bits(f->hw_if_bmp),
		       format_flow, f);
    });
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_flow_id_command, static) = {
    .path = "show flow id",
    .short_help = "show flow id",
    .function = show_flow_id,
};
/* *INDENT-ON* */

static clib_error_t *
show_flow_ranges (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd_arg)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_range_t *r;

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
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_hw_if_t *hwif;
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

  if (vec_len (fm->interfaces) <= hw_if_index)
    return clib_error_return (0, "not enabled");

  hwif = vec_elt_at_index (fm->interfaces, hw_if_index);
  if (hwif->format_interface_flow == 0)
    return clib_error_return (0, "not enabled");

  vlib_cli_output (vm, "%U", hwif->format_interface_flow, hw_if_index, 0);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_flow_interface_command, static) = {
    .path = "show flow interface",
    .short_help = "show flow interface",
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
  u32 hw_if_index = ~0, tmp;
  int rv;
  u8 prot;

  memset (&flow, 0, sizeof (vnet_flow_t));
  flow.id = ~0;
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
			 unformat_ip4_address_and_mask,
			 &flow.ip4_n_tuple.src_addr))
	;
      else if (unformat (line_input, "dst-ip %U",
			 unformat_ip4_address_and_mask,
			 &flow.ip4_n_tuple.dst_addr))
	;
      else if (unformat (line_input, "src-port %U", unformat_ip_port_and_mask,
			 &flow.ip4_n_tuple.src_port))
	;
      else if (unformat (line_input, "dst-port %U", unformat_ip_port_and_mask,
			 &flow.ip4_n_tuple.dst_port))
	;
      else if (unformat (line_input, "proto %U", unformat_ip_protocol, &prot))
	flow.ip4_n_tuple.protocol = prot;
      else if (unformat (line_input, "proto %u", &tmp))
	flow.ip4_n_tuple.protocol = tmp;
      else if (unformat (line_input, "id %u", &tmp))
	flow.id = tmp;
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

  if (flow.id == ~0 && (action == FLOW_ENABLE || action == FLOW_DISABLE ||
			action == FLOW_DEL))
    return clib_error_return (0, "Please specify flow id");

  if (next_test_flow_id == ~0)
    vnet_flow_get_range ("Test CLI", 1000, &next_test_flow_id);

  switch (action)
    {
    case FLOW_ADD:
      if (flow.ip4_n_tuple.protocol == (ip_protocol_t) ~ 0)
	return clib_error_return (0, "Please specify ip protocol");

      flow.type = VNET_FLOW_TYPE_IP4_N_TUPLE;
      flow.id = next_test_flow_id++;
      rv = vnet_flow_add (&flow);
      break;
    case FLOW_DEL:
      rv = vnet_flow_del (flow.id);
      break;
    case FLOW_ENABLE:
      rv = vnet_flow_enable (flow.id, hw_if_index);
      break;
    case FLOW_DISABLE:
      rv = vnet_flow_disable (flow.id, hw_if_index);
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
format_flow_entry (u8 * s, va_list * args)
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
			      format_flow_entry, #a, &f->b);
#define _(a,b,c) \
u8 * format_flow_##b (u8 * s, va_list * args)			\
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
format_flow (u8 * s, va_list * args)
{
  vnet_flow_t *f = va_arg (*args, vnet_flow_t *);

#define _(a,b,c) \
  if (f->type == VNET_FLOW_TYPE_##a) \
    return format (s, "%U", format_flow_##b, &f->b);
  foreach_flow_type;
#undef _

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
