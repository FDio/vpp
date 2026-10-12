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
  /* optional fields, only checked when has_ext is set */
  u8 has_ext;
  u8 nonfirst_frag_mode;
  u16 pkt_len_first;
  u16 pkt_len_last;
  u8 dscp_value;
  u8 dscp_mask;
  u8 frag_value;
  u8 frag_mask;
} acl_rule_t;

/* how a rule treats non-initial fragments */
typedef enum
{
  /* follow l4-match-nonfirst-fragment */
  ACL_NONFIRST_FRAG_GLOBAL = 0,
  /* match only if the rule constrains no L4 field */
  ACL_NONFIRST_FRAG_L3_ONLY = 1,
} acl_nonfirst_frag_mode_t;

#endif // included_acl_types_h

