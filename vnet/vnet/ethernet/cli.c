/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * cli.c: ethernet CLI
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>

VLIB_CLI_COMMAND (vlib_cli_ethernet_command, static) = {
  .path = "ethernet",
  .short_help = "Ethernet commands",
};

static clib_error_t *
promiscuous_cmd (vlib_main_t * vm,
                 unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  u32 hw_if_index;
  u32 flags = ETHERNET_INTERFACE_FLAG_ACCEPT_ALL;

  if (unformat (input, "on %U",
                unformat_ethernet_interface, vnm, &hw_if_index))
    {
      ethernet_set_flags (vnm, hw_if_index, flags);
    }
  else if (unformat (input, "off %U",
                     unformat_ethernet_interface, vnm, &hw_if_index))
    {
      flags = 0;
      ethernet_set_flags (vnm, hw_if_index, flags);
    }
  else
    return clib_error_return (0, "unknown input `%U'",
                              format_unformat_error, input);
  return 0;
}

VLIB_CLI_COMMAND (ethernet_promiscuous_command, static) = {
  .path = "ethernet promiscuous",
  .short_help = "ethernet promiscuous [on | off] <intfc>",
  .function = promiscuous_cmd,
};

static clib_error_t *
mtu_cmd (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  u32 hw_if_index, mtu;
  u32 flags = ETHERNET_INTERFACE_FLAG_MTU;

  if (unformat (input, "%d %U", &mtu,
                unformat_ethernet_interface, vnm, &hw_if_index))
    {
      vnet_hw_interface_t * hi = vnet_get_hw_interface (vnm, hw_if_index);

      if (mtu < ETHERNET_MIN_PACKET_BYTES)
	return clib_error_return (0, "Invalid mtu (%d): "
				  "must be >= min pkt bytes (%d)", mtu,
				  hi->min_packet_bytes);
	
      if (mtu > ETHERNET_MAX_PACKET_BYTES)
	return clib_error_return (0, "Invalid mtu (%d): must be <= 9216", mtu);
	
      if (hi->max_packet_bytes != mtu)
	{
	  hi->max_packet_bytes = mtu;
	  ethernet_set_flags (vnm, hw_if_index, flags);
	}
    }
  else
    return clib_error_return (0, "unknown input `%U'",
                              format_unformat_error, input);
  return 0;
}

VLIB_CLI_COMMAND (ethernet_mtu_command, static) = {
  .path = "ethernet mtu",
  .short_help = "ethernet mtu <64-9216> <intfc>",
  .function = mtu_cmd,
};

clib_error_t *
ethernet_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ethernet_cli_init);
