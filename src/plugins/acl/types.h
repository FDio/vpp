/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef included_acl_types_h
#define included_acl_types_h

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

typedef struct
{
  u8 is_permit;
  u8 is_ipv6;
  ip46_address_t src;
  u8 src_prefixlen;
  ip46_address_t dst;
  u8 dst_prefixlen;
  u8 proto;
  u16 src_port_or_type_first;
  u16 src_port_or_type_last;
  u16 dst_port_or_code_first;
  u16 dst_port_or_code_last;
  u8 tcp_flags_value;
  u8 tcp_flags_mask;
} acl_rule_t;


#endif // included_acl_types_h

