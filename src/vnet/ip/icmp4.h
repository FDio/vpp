/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#ifndef included_vnet_icmp4_h
#define included_vnet_icmp4_h

typedef struct
{
  u8 packet_data[64];
} icmp_input_trace_t;

format_function_t format_icmp4_input_trace;
void ip4_icmp_register_type (vlib_main_t * vm, icmp4_type_t type,
			     u32 node_index);

static_always_inline void
icmp4_error_set_vnet_buffer (vlib_buffer_t * b, u8 type, u8 code, u32 data)
{
  vnet_buffer (b)->ip.icmp.type = type;
  vnet_buffer (b)->ip.icmp.code = code;
  vnet_buffer (b)->ip.icmp.data = data;
}

extern vlib_node_registration_t ip4_icmp_input_node;

#endif /* included_vnet_icmp4_h */
