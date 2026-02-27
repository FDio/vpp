/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#pragma once

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
  u8 n_clones;
  u8 linearize;
  u8 regen_udp_cksum;
  u8 regen_ip_cksum;
} udp_echo_main_t;

extern udp_echo_main_t udp_echo_main;

extern vlib_node_registration_t udp_echo_node;
