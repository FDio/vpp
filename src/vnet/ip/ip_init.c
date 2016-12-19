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
 * ip/ip_init.c: ip generic initialization
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

ip_main_t ip_main;

clib_error_t *
ip_main_init (vlib_main_t * vm)
{
  ip_main_t *im = &ip_main;
  clib_error_t *error = 0;

  memset (im, 0, sizeof (im[0]));

  {
    ip_protocol_info_t *pi;
    u32 i;

#define ip_protocol(n,s)			\
do {						\
  vec_add2 (im->protocol_infos, pi, 1);		\
  pi->protocol = n;				\
  pi->name = (u8 *) #s;				\
} while (0);

#include "protocols.def"

#undef ip_protocol

    im->protocol_info_by_name = hash_create_string (0, sizeof (uword));
    for (i = 0; i < vec_len (im->protocol_infos); i++)
      {
	pi = im->protocol_infos + i;

	hash_set_mem (im->protocol_info_by_name, pi->name, i);
	hash_set (im->protocol_info_by_protocol, pi->protocol, i);
      }
  }

  {
    tcp_udp_port_info_t *pi;
    u32 i;
    static char *port_names[] = {
#define ip_port(s,n) #s,
#include "ports.def"
#undef ip_port
    };
    static u16 ports[] = {
#define ip_port(s,n) n,
#include "ports.def"
#undef ip_port
    };

    vec_resize (im->port_infos, ARRAY_LEN (port_names));
    im->port_info_by_name = hash_create_string (0, sizeof (uword));

    for (i = 0; i < vec_len (im->port_infos); i++)
      {
	pi = im->port_infos + i;
	pi->port = clib_host_to_net_u16 (ports[i]);
	pi->name = (u8 *) port_names[i];
	hash_set_mem (im->port_info_by_name, pi->name, i);
	hash_set (im->port_info_by_port, pi->port, i);
      }
  }

  if ((error = vlib_call_init_function (vm, vnet_main_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip4_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip6_init)))
    return error;

  if ((error = vlib_call_init_function (vm, icmp4_init)))
    return error;

  if ((error = vlib_call_init_function (vm, icmp6_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip6_hop_by_hop_init)))
    return error;

  if ((error = vlib_call_init_function (vm, udp_local_init)))
    return error;

  if ((error = vlib_call_init_function (vm, udp_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip_classify_init)))
    return error;

  if ((error = vlib_call_init_function (vm, input_acl_init)))
    return error;

  if ((error = vlib_call_init_function (vm, policer_classify_init)))
    return error;

  if ((error = vlib_call_init_function (vm, flow_classify_init)))
    return error;

  return error;
}

VLIB_INIT_FUNCTION (ip_main_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
