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

#define ACL_RULE_EXT_L3_ONLY_NONFIRST (1 << 0)
#define ACL_RULE_EXT_CALLER_CHECK     (1 << 1)

typedef struct
{
  u8 flags;
  u8 dscp_value;
  u8 dscp_mask;
  u8 frag_value;
  u8 frag_mask;
  u16 pkt_len_first;
  u16 pkt_len_last;
} acl_rule_ext_t;

typedef int (*acl_plugin_add_replace_rules_ext_fn_t) (u32 *acl_index, acl_rule_t *rules,
						      acl_rule_ext_t *ext, u8 *tag);

#endif // included_acl_types_h

