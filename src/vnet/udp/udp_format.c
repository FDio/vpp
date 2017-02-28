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
 * ip/udp_format.c: udp formatting
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

/* Format UDP header. */
u8 *
format_udp_header (u8 * s, va_list * args)
{
  udp_header_t *udp = va_arg (*args, udp_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  uword indent;
  u32 header_bytes = sizeof (udp[0]);

  /* Nothing to do. */
  if (max_header_bytes < sizeof (udp[0]))
    return format (s, "UDP header truncated");

  indent = format_get_indent (s);
  indent += 2;

  s = format (s, "UDP: %d -> %d",
	      clib_net_to_host_u16 (udp->src_port),
	      clib_net_to_host_u16 (udp->dst_port));

  s = format (s, "\n%Ulength %d, checksum 0x%04x",
	      format_white_space, indent,
	      clib_net_to_host_u16 (udp->length),
	      clib_net_to_host_u16 (udp->checksum));

  /* Recurse into next protocol layer. */
  if (max_header_bytes != 0 && header_bytes < max_header_bytes)
    {
      ip_main_t *im = &ip_main;
      tcp_udp_port_info_t *pi;

      pi = ip_get_tcp_udp_port_info (im, udp->dst_port);

      if (pi && pi->format_header)
	s = format (s, "\n%U%U",
		    format_white_space, indent - 2, pi->format_header,
		    /* next protocol header */ (udp + 1),
		    max_header_bytes - sizeof (udp[0]));
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
