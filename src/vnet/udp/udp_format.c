/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015-2019 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ip/udp_format.c: udp formatting */

#include <vnet/ip/ip.h>

/* Format UDP header. */
u8 *
format_udp_header (u8 * s, va_list * args)
{
  udp_header_t *udp = va_arg (*args, udp_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  u32 indent;
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

uword
unformat_udp_port (unformat_input_t * input, va_list * args)
{
  u16 *result = va_arg (*args, u16 *);
  int port;

  /* Numeric type. */
  if (unformat (input, "0x%x", &port) || unformat (input, "%d", &port))
    {
      if (port <= 0 || port >= (1 << 16))
	return 0;
      *result = port;
      return 1;
    }
  return 0;
}
