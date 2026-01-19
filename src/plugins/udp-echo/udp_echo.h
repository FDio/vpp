/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __included_udp_echo_h__
#define __included_udp_echo_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/udp/udp_local.h>
#include <vlib/vlib.h>

typedef struct
{
  ip4_address_t src;
  ip4_address_t dst;
  u16 src_port;
  u16 dst_port;
} udp_echo_trace_t;

format_function_t format_udp_echo_trace;

typedef struct
{
  /* Registered port */
  u16 port;
  u8 enabled;
} udp_echo_main_t;

extern udp_echo_main_t udp_echo_main;

extern vlib_node_registration_t udp_echo_node;

#endif /* __included_udp_echo_h__ */
