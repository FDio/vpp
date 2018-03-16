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

static format_function_t format_device_flow;
static u32 next_test_flow_id = ~0;

static clib_error_t *
show_device_flow (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd_arg)
{
  vnet_device_main_t *dm = &device_main;
  vnet_device_flow_t *f;

  const char *flow_type_strings[] = { 0,
#define _(a,b,c) c,
    foreach_device_flow_type
#undef _
  };

  vlib_cli_output (vm, "%5s  %-15s  %s", "ID", "Type", "Description");
  /* *INDENT-OFF* */
  pool_foreach (f, dm->global_flow_pool,
    {
      vlib_cli_output (vm, "%5u  %-15s  %U", f->id, flow_type_strings[f->type],
                       format_device_flow, f);
    });
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_device_flow_command, static) = {
    .path = "show device flow",
    .short_help = "show device flow",
    .function = show_device_flow,
};
/* *INDENT-ON* */

static clib_error_t *
test_device_flow (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd_arg)
{
  vnet_device_flow_t flow;
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

  memset (&flow, 0xff, sizeof (vnet_device_flow_t));

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
      else if (unformat (line_input, "src-ip %U", unformat_ip4_address,
			 &flow.ip4_5tuple.src_addr))
	;
      else if (unformat (line_input, "dst-ip %U", unformat_ip4_address,
			 &flow.ip4_5tuple.dst_addr))
	;
      else if (unformat (line_input, "src-port %u", &tmp))
	flow.ip4_5tuple.src_port = tmp;
      else if (unformat (line_input, "dst-port %u", &tmp))
	flow.ip4_5tuple.dst_port = tmp;
      else if (unformat (line_input, "proto %U", unformat_ip_protocol, &tmp))
	flow.ip4_5tuple.protocol = tmp;
      else if (unformat (line_input, "proto %u", &tmp))
	flow.ip4_5tuple.protocol = tmp;
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
    next_test_flow_id = vnet_device_flow_request_range (1000);

  switch (action)
    {
    case FLOW_ADD:
      if (flow.ip4_5tuple.src_addr.as_u32 == ~0)
	return clib_error_return (0, "Please specify source ip address");
      if (flow.ip4_5tuple.dst_addr.as_u32 == ~0)
	return clib_error_return (0, "Please specify destination ip address");
      if (flow.ip4_5tuple.src_port == (u16) ~0)
	return clib_error_return (0, "Please specify source port");
      if (flow.ip4_5tuple.dst_port == (u16) ~0)
	return clib_error_return (0, "Please specify destination port");
      if (flow.ip4_5tuple.protocol == (ip_protocol_t) ~0)
	return clib_error_return (0, "Please specify ip protocol");

      flow.type = VNET_DEVICE_FLOW_TYPE_IP4_5TUPLE;
      flow.id = next_test_flow_id++;
      vnet_device_flow_add (&flow);
      break;
    case FLOW_DEL:
      vnet_device_flow_del (flow.id);
      break;
    case FLOW_ENABLE:
      vnet_device_flow_enable (flow.id, hw_if_index);
      break;
    case FLOW_DISABLE:
      vnet_device_flow_enable (flow.id, hw_if_index);
      break;
    default:
      return clib_error_return (0, "please specify action (add, del, enable, "
				 "disable)");
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_device_flow_command, static) = {
    .path = "test device flow",
    .short_help = "test device flow add 5-touple src-ip <ip-addr> "
      "dst-ip <ip-addr> src-port <port> dst-port <port> proto <ip-proto>",
    .function = test_device_flow,
};
/* *INDENT-ON* */


static u8 *
format_device_flow_entry (u8 * s, va_list * args)
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

  if (strncmp (type, "ip6_address_t", 13) == 0)
    return format (s, "%U", format_ip6_address, ptr);

  if (strncmp (type, "ip_protocol_t", 13) == 0)
    return format (s, "%U", format_ip_protocol, * (ip_protocol_t *) ptr);

  s = format (s, "unknown type '%s'", type);
  return s;
}

#define _fe(a,b) s2 = format (s2, "%s%s %U", s2 ? ", ":"", #b, \
			      format_device_flow_entry, #a, &f->b);
#define _(a,b,c) \
u8 * format_device_flow_##b (u8 * s, va_list * args)			\
{									\
  vnet_device_flow_##b##_t *f = __builtin_va_arg (*args, vnet_device_flow_##b##_t *); \
  u8 *s2 = 0; \
foreach_device_flow_entry_##b \
  s = format (s, "%v", s2);; \
  vec_free (s2); \
return s; \
}
foreach_device_flow_type
#undef _
#undef _fe
static u8 *
format_device_flow (u8 * s, va_list * args)
{
  vnet_device_flow_t *f = va_arg (*args, vnet_device_flow_t *);

#define _(a,b,c) \
  if (f->type == VNET_DEVICE_FLOW_TYPE_##a) \
    return format (s, "%U", format_device_flow_##b, &f->b);
  foreach_device_flow_type;
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
