/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ip/ip_format.c: ip generic (4 or 6) formatting */

#include <vnet/ip/ip.h>

/* Format IP protocol. */
u8 *
format_ip_protocol (u8 * s, va_list * args)
{
  ip_protocol_t protocol = va_arg (*args, int);	// int promo of ip_protocol_t);
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
