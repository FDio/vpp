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
 * ip/ip_format.c: ip generic (4 or 6) formatting
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

/* Format IP protocol. */
u8 *
format_ip_protocol (u8 * s, va_list * args)
{
  ip_protocol_t protocol = va_arg (*args, ip_protocol_t);
  ip_main_t *im = &ip_main;
  ip_protocol_info_t *pi = ip_get_protocol_info (im, protocol);

  if (pi)
    return format (s, "%s", pi->name);
  else
    return format (s, "unknown %d", protocol);
}

uword
unformat_ip_protocol (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  ip_main_t *im = &ip_main;
  ip_protocol_info_t *pi;
  int i;

  if (!unformat_user (input, unformat_vlib_number_by_name,
		      im->protocol_info_by_name, &i))
    return 0;

  pi = vec_elt_at_index (im->protocol_infos, i);
  *result = pi->protocol;
  return 1;
}

u8 *
format_tcp_udp_port (u8 * s, va_list * args)
{
  int port = va_arg (*args, int);
  ip_main_t *im = &ip_main;
  tcp_udp_port_info_t *pi;

  pi = ip_get_tcp_udp_port_info (im, port);
  if (pi)
    s = format (s, "%s", pi->name);
  else
    s = format (s, "%d", clib_net_to_host_u16 (port));

  return s;
}

uword
unformat_tcp_udp_port (unformat_input_t * input, va_list * args)
{
  u16 *result = va_arg (*args, u16 *);
  ip_main_t *im = &ip_main;
  tcp_udp_port_info_t *pi;
  u32 i, port;


  if (unformat_user (input, unformat_vlib_number_by_name,
		     im->port_info_by_name, &i))
    {
      pi = vec_elt_at_index (im->port_infos, i);
      port = pi->port;
    }
  else if (unformat_user (input, unformat_vlib_number, &port)
	   && port < (1 << 16))
    port = clib_host_to_net_u16 (port);

  else
    return 0;

  *result = port;
  return 1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
