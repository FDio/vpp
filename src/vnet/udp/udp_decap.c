/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vnet/udp/udp.h>

uword
unformat_next_node (unformat_input_t *input, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  u32 *node_index = va_arg (*args, u32 *);
  if (unformat (input, "mpls"))
    *node_index = vlib_get_node_by_name (vm, (u8 *) "mpls-input")->index;
  else if (unformat (input, "ip4"))
    *node_index = vlib_get_node_by_name (vm, (u8 *) "ip4-input")->index;
  else if (unformat (input, "ip6"))
    *node_index = vlib_get_node_by_name (vm, (u8 *) "ip6-input")->index;
  else
    return 0;
  return 1;
}

static clib_error_t *
udp_decap_cli (vlib_main_t *vm, unformat_input_t *input,
	       vlib_cli_command_t *cmd_arg)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 is_add = 1, is_ip4 = 1;
  int i = 0;
  u16 port = 0;
  u32 node_index = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "ipv4"))
	is_ip4 = 1;
      else if (unformat (line_input, "ipv6"))
	is_ip4 = 0;
      else if (unformat (line_input, "%d", &i))
	port = i;
      else if (unformat (line_input, "next-proto %U", unformat_next_node, vm,
			 &node_index))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }
  if (port == 0)
    {
      error = clib_error_return (0, "missing port");
      goto done;
    }
  if (is_add && node_index == ~0)
    {
      error = clib_error_return (0, "missing protocol");
      goto done;
    }
  if (is_add)
    udp_register_dst_port (vm, port, node_index, is_ip4);
  else
    udp_unregister_dst_port (vm, port, is_ip4);

done:
  unformat_free (line_input);
  return error;
}

/*?
 * Register a port to decapsulate incoming UDP encapsulated packets.
 *
 * @cliexpar
 * @clistart
 * udp decap add ipv4 1234 next-proto mpls
 * @cliend
 * @cliexcmd{udp decap [add|del] [ipv4|ipv6] <dst-port> next-proto
<inner-protocol>}
?*/

VLIB_CLI_COMMAND (udp_decap_add_command, static) = {
  .path = "udp decap",
  .short_help =
    "udp decap [add|del] [ipv4|ipv6] <dst-port> next-proto <inner-protocol>",
  .function = udp_decap_cli,
};