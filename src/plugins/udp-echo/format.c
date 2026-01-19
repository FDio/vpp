/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <udp-echo/udp_echo.h>

u8 *
format_udp_echo_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  udp_echo_trace_t *t = va_arg (*args, udp_echo_trace_t *);

  s = format (s, "%U:%d <=> %U:%d", format_ip4_address, &t->src, clib_net_to_host_u16 (t->src_port),
	      format_ip4_address, &t->dst, clib_net_to_host_u16 (t->dst_port));
  return s;
}
