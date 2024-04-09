/*
 * Copyright (c) 2015-2019 Cisco and/or its affiliates.
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
 * tcp/tcp_format.c: tcp formatting
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
#include <vnet/tcp/tcp.h>

u8 *
format_tcp_flags (u8 * s, va_list * args)
{
  int flags = va_arg (*args, int);

  s = format (s, "0x%02x", flags);
#define _(f) if (flags & TCP_FLAG_##f) s = format (s, " %s", #f);
  foreach_tcp_flag
#undef _
    return s;
}

u8 *
format_tcp_options (u8 *s, va_list *args)
{
  tcp_options_t *opts = va_arg (*args, tcp_options_t *);
  u32 indent, n_opts = 0;
  int i;

  if (!opts->flags)
    return s;

  indent = format_get_indent (s);
  indent += 2;

  s = format (s, "options:\n%U", format_white_space, indent);

  if (tcp_opts_mss (opts))
    {
      s = format (s, "mss %d", opts->mss);
      n_opts++;
    }
  if (tcp_opts_wscale (opts))
    {
      s = format (s, "%swindow scale %d", n_opts > 0 ? ", " : "",
		  format_white_space, indent, opts->wscale);
      n_opts++;
    }
  if (tcp_opts_tstamp (opts))
    {
      s = format (s, "%stimestamp %d, echo/reflected timestamp",
		  n_opts > 0 ? ", " : "", format_white_space, indent,
		  opts->tsval, opts->tsecr);
      n_opts++;
    }
  if (tcp_opts_sack_permitted (opts))
    {
      s = format (s, "%ssack permitted", n_opts > 0 ? ", " : "",
		  format_white_space, indent);
      n_opts++;
    }
  if (tcp_opts_sack (opts))
    {
      s = format (s, "%ssacks:", n_opts > 0 ? ", " : "", format_white_space,
		  indent);
      for (i = 0; i < opts->n_sack_blocks; ++i)
	{
	  s = format (s, "\n%Ublock %d: start %d, end %d", format_white_space,
		      indent + 2, i + 1, opts->sacks[i].start,
		      opts->sacks[i].end);
	}
      n_opts++;
    }

  return s;
}

/* Format TCP header. */
u8 *
format_tcp_header (u8 * s, va_list * args)
{
  tcp_header_t *tcp = va_arg (*args, tcp_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  tcp_options_t opts = { .flags = 0 };
  u32 header_bytes;
  u32 indent;

  /* Nothing to do. */
  if (max_header_bytes < sizeof (tcp[0]))
    return format (s, "TCP header truncated");

  indent = format_get_indent (s);
  indent += 2;
  header_bytes = tcp_header_bytes (tcp);

  s = format (s, "TCP: %d -> %d", clib_net_to_host_u16 (tcp->src),
	      clib_net_to_host_u16 (tcp->dst));

  s = format (s, "\n%Useq. 0x%08x ack 0x%08x", format_white_space, indent,
	      clib_net_to_host_u32 (tcp->seq_number),
	      clib_net_to_host_u32 (tcp->ack_number));

  s = format (s, "\n%Uflags %U, tcp header: %d bytes", format_white_space,
	      indent, format_tcp_flags, tcp->flags, header_bytes);

  s = format (s, "\n%Uwindow %d, checksum 0x%04x", format_white_space, indent,
	      clib_net_to_host_u16 (tcp->window),
	      clib_net_to_host_u16 (tcp->checksum));

  if (header_bytes > max_header_bytes)
    s = format (s, "\n%Uoptions: truncated", format_white_space, indent);
  else if (tcp_options_parse (tcp, &opts, tcp_is_syn (tcp)) < 0)
    s = format (s, "\n%Uoptions: parsing failed", format_white_space, indent);
  else
    s = format (s, "\n%U%U", format_white_space, indent, format_tcp_options,
		&opts);

  /* Recurse into next protocol layer. */
  if (max_header_bytes != 0 && header_bytes < max_header_bytes)
    {
      ip_main_t *im = &ip_main;
      tcp_udp_port_info_t *pi;

      pi = ip_get_tcp_udp_port_info (im, tcp->dst);

      if (pi && pi->format_header)
	s = format (s, "\n%U%U", format_white_space, indent - 2,
		    pi->format_header,
		    /* next protocol header */ (void *) tcp + header_bytes,
		    max_header_bytes - header_bytes);
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
