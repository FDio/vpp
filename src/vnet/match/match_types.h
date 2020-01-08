/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __MATCH_TYPES_H__
#define __MATCH_TYPES_H__

#include <vnet/ethernet/packet.h>
#include <vnet/ethernet/mac_address.h>
#include <vnet/ip/ip_types.h>

typedef struct match_ip_prefix_t_
{
  ip_address_t mip_ip;
  u8 mip_len;
} match_ip_prefix_t;

extern u8 *format_match_ip_prefix (u8 * s, va_list * args);

typedef struct match_mac_mask_t_
{
  mac_address_t mmm_mac;
  mac_address_t mmm_mask;
} match_mac_mask_t;

extern u8 *format_match_mac_mask (u8 * s, va_list * args);

typedef struct match_vlan_mask_t_
{
  u16 mvm_mac;
  u16 mvm_mask;
} match_vlan_mask_t;

typedef struct match_port_range_t_
{
  u16 mpe_begin;
  u16 mpe_end;
} match_port_range_t;

/**
 * The types of tuples to match on
 *  - this is in sorted order of 'difficulty'
 */
#define foreach_match_type                      \
  _(EXACT_SRC_IP_MAC, "exact-src-ip-mac")       \
  _(MASK_SRC_IP_MAC,  "mask-src-ip-mac")        \
  _(MASK_DST_IP_MAC,  "mask-dst-ip-mac")        \

typedef enum match_type_t_
{
#define _(a,b) MATCH_TYPE_##a,
  foreach_match_type
#undef _
} match_type_t;

#define MATCH_TYPE_EASIEST MATCH_TYPE_EXACT_SRC_IP_MAC
#define MATCH_TYPE_HARDEST MATCH_TYPE_MASK_DST_IP_MAC
#define MATCH_N_TYPES (MATCH_TYPE_HARDEST+1)

extern u8 *format_match_type (u8 * s, va_list * args);

typedef struct match_exact_ip_mac_t_
{
  ip_address_t me_ip;
  ip_address_t me_mac;
} match_exact_ip_mac_t;

typedef struct match_mask_ip_mac_t_
{
  match_ip_prefix_t mm_ip;
  match_mac_mask_t mm_mac;
} match_mask_ip_mac_t;


/**
 * A match rule
 *  A description of a class of traffic to match against
 */
typedef struct match_rule_t_
{
  match_type_t mr_type;
  /* Which ethernet protocol to match against -
     sensible values are ARP and IP[4|6]. */
  ethernet_type_t mr_proto;

  u32 mr_index;
  union
  {
    match_mask_ip_mac_t mr_mask_src_ip_mac;
    match_mask_ip_mac_t mr_mask_dst_ip_mac;
  };
  u8 *mr_tag;
} match_rule_t;

extern u8 *format_match_rule (u8 * s, va_list * args);
extern u8 *format_match_rule_w_action (u8 * s, va_list * args);

/**
 * Match list
 *  A sorted sequence of rules. It is the uses responsibility
 *  to sort the rules in the order they wish them to be matched
 *  (but see the match_semantic_t)
 */
typedef struct match_list_t_
{
  /** Pretty name for the list */
  u8 *ml_tag;

  /** The ordered list of rules */
  match_rule_t *ml_rules;
} match_list_t;

extern u8 *format_match_list (u8 * s, va_list * args);
extern u8 *format_match_list_w_action (u8 * s, va_list * args);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
