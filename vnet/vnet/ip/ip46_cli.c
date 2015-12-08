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
 * ip/ip4_cli.c: ip4 commands
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

#include <vnet/ip/ip.h>

int ip4_address_compare (ip4_address_t * a1, ip4_address_t * a2)
{ return clib_net_to_host_u32 (a1->data_u32) - clib_net_to_host_u32 (a2->data_u32); }

int ip6_address_compare (ip6_address_t * a1, ip6_address_t * a2)
{
  int i;
  for (i = 0; i < ARRAY_LEN (a1->as_u16); i++)
    {
      int cmp = clib_net_to_host_u16 (a1->as_u16[i]) - clib_net_to_host_u16 (a2->as_u16[i]);
      if (cmp != 0)
	return cmp;
    }
  return 0;
}

VLIB_CLI_COMMAND (set_interface_ip_command, static) = {
  .path = "set interface ip",
  .short_help = "IP4/IP6 commands",
};

void ip_del_all_interface_addresses (vlib_main_t *vm, u32 sw_if_index)
{
  ip4_main_t * im4 = &ip4_main;
  ip4_address_t * ip4_addrs = 0;
  u32 *ip4_masks = 0;
  ip6_main_t * im6 = &ip6_main;
  ip6_address_t * ip6_addrs = 0;
  u32 *ip6_masks = 0;
  ip_interface_address_t * ia;
  int i;

  foreach_ip_interface_address (&im4->lookup_main, ia, sw_if_index, 
                                0 /* honor unnumbered */,
  ({
    ip4_address_t * x = (ip4_address_t *)
      ip_interface_address_get_address (&im4->lookup_main, ia);
    vec_add1 (ip4_addrs, x[0]);
    vec_add1 (ip4_masks, ia->address_length);
  }));

  foreach_ip_interface_address (&im6->lookup_main, ia, sw_if_index, 
                                0 /* honor unnumbered */,
  ({
    ip6_address_t * x = (ip6_address_t *)
      ip_interface_address_get_address (&im6->lookup_main, ia);
    vec_add1 (ip6_addrs, x[0]);
    vec_add1 (ip6_masks, ia->address_length);
  }));

  for (i = 0; i < vec_len (ip4_addrs); i++)
    ip4_add_del_interface_address (vm, sw_if_index, &ip4_addrs[i], 
                                   ip4_masks[i], 1 /* is_del */);
  for (i = 0; i < vec_len (ip6_addrs); i++)
    ip6_add_del_interface_address (vm, sw_if_index, &ip6_addrs[i], 
                                   ip6_masks[i], 1 /* is_del */);

  vec_free (ip4_addrs);
  vec_free (ip4_masks);
  vec_free (ip6_addrs);
  vec_free (ip6_masks);
}

static clib_error_t *
add_del_ip_address (vlib_main_t * vm,
		    unformat_input_t * input,
		    vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  ip4_address_t a4;
  ip6_address_t a6;
  clib_error_t * error = 0;
  u32 sw_if_index, length, is_del;

  sw_if_index = ~0;
  is_del = 0;

  if (unformat (input, "del"))
    is_del = 1;

  if (! unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (is_del && unformat (input, "all"))
    ip_del_all_interface_addresses (vm, sw_if_index);
  else if (unformat (input, "%U/%d", unformat_ip4_address, &a4, &length))
    error = ip4_add_del_interface_address (vm, sw_if_index, &a4, length,
					   is_del);
  else if (unformat (input, "%U/%d", unformat_ip6_address, &a6, &length))
    error = ip6_add_del_interface_address (vm, sw_if_index, &a6, length,
					   is_del);
  else
    {
      error = clib_error_return (0, "expected IP4/IP6 address/length `%U'",
				 format_unformat_error, input);
      goto done;
    }


 done:
  return error;
}

VLIB_CLI_COMMAND (set_interface_ip_address_command, static) = {
  .path = "set interface ip address",
  .function = add_del_ip_address,
  .short_help = "Add/delete IP4/IP6 address for interface",
};

/* Dummy init function to get us linked in. */
static clib_error_t * ip4_cli_init (vlib_main_t * vm)
{ return 0; }

VLIB_INIT_FUNCTION (ip4_cli_init);
