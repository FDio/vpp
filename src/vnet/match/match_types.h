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

typedef enum match_orientation_t_
{
  MATCH_SOURCE,
  MATCH_SRC = MATCH_SOURCE,
  MATCH_DESTINATION,
  MATCH_DST = MATCH_DESTINATION,
  MATCH_BOTH,
} __clib_packed match_orientation_t;

#define FOR_EACH_MATCH_ORIENTATION(_mo)         \
  for (_mo = MATCH_SRC; _mo < MATCH_BOTH; _mo++)

extern u8 *format_match_orientation (u8 * s, va_list * args);
extern uword unformat_match_orientation (unformat_input_t * input,
					 va_list * args);

typedef struct match_ip_prefix_t_
{
  ip_prefix_t mip_ip;
  ip_address_t mip_mask;
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
  u16 mpr_begin;
  u16 mpr_end;
} match_port_range_t;

extern u8 *format_match_port_range (u8 * s, va_list * args);

typedef struct match_icmp_code_range_t_
{
  u8 micr_begin;
  u8 micr_end;
} match_icmp_code_range_t;

extern u8 *format_match_icmp_code_range (u8 * s, va_list * args);

typedef struct match_icmp_type_range_t_
{
  u8 mitr_begin;
  u8 mitr_end;
} match_icmp_type_range_t;

extern u8 *format_match_icmp_type_range (u8 * s, va_list * args);

typedef struct match_icmp_t_
{
  u8 mi_type;
  u8 mi_code;
} match_icmp_t;

extern u8 *format_match_icmp (u8 * s, va_list * args);

typedef union match_l4_t_
{
  match_icmp_t ml_icmp;
  u16 ml_port;
} match_l4_t;

typedef struct match_tcp_flags_t_
{
  u8 mtf_flags;
  u8 mtf_mask;
} match_tcp_flags_t;

extern u8 *format_match_tcp_flags (u8 * s, va_list * args);

/**
 * The types of tuples to match on
 *  - this is in sorted order of 'difficulty'
 */
#define foreach_match_type                       \
  _(EXACT_IP,         "exact-ip")                \
  _(EXACT_IP_L4,      "exact-ip-l4")             \
  _(MASK_IP,          "mask-ip")                 \
  _(MASK_IP_MAC,      "mask-ip-mac")             \
  _(MASK_N_TUPLE,     "mask-n-tuple")            \
  _(SETS,             "sets")                    \

typedef enum match_type_t_
{
#define _(a,b) MATCH_TYPE_##a,
  foreach_match_type
#undef _
} __clib_packed match_type_t;

#define MATCH_N_TYPES (MATCH_TYPE_SETS+1)

#define FOR_EACH_MATCH_TYPE(_t) \
  for (_t = MATCH_TYPE_EXACT_IP; _t < MATCH_N_TYPES; _t++)

extern u8 *format_match_type (u8 * s, va_list * args);
extern uword unformat_match_type (unformat_input_t * input, va_list * args);

typedef struct match_mask_ip_mac_t_
{
  match_ip_prefix_t mmim_ip;
  match_mac_mask_t mmim_mac;
} match_mask_ip_mac_t;

typedef struct match_exact_ip_l4_t_
{
  ip_address_t meil_ip;
  ip_protocol_t meil_proto;
  match_l4_t meil_l4;
} match_exact_ip_l4_t;

extern u8 *format_match_exact_ip_l4 (u8 * s, va_list * args);

typedef struct match_sets_t_
{
  index_t mss_set[MATCH_BOTH];
} match_sets_t;

extern u8 *format_match_sets (u8 * s, va_list * args);

/**
 * n-tuple match
 */
typedef struct match_mask_n_tuple_t_
{
  match_ip_prefix_t mnt_src_ip;
  match_ip_prefix_t mnt_dst_ip;

  ip_protocol_t mnt_ip_proto;

  union
  {
    struct
    {
      match_icmp_type_range_t mnt_icmp_type;
      match_icmp_code_range_t mnt_icmp_code;
    };
    struct
    {
      match_port_range_t mnt_src_port;
      match_port_range_t mnt_dst_port;
      match_tcp_flags_t mnt_tcp;
    };
  };
} match_mask_n_tuple_t;

extern u8 *format_match_mask_n_tuple (u8 * s, va_list * args);

/**
 * When a rule matches this is the client's context that is returned
 */
typedef u64 match_result_t;

#define MATCH_RESULT_MISS (~(0ULL))

extern u8 *format_match_result (u8 * s, va_list * args);

/**
 * A match rule
 *  A description of a class of traffic to match against
 */
typedef struct match_rule_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  match_type_t mr_type;
  match_orientation_t mr_orientation;
  /* Which ethernet protocol to match against -
     sensible values are ARP and IP[4|6]. */
  ethernet_type_t mr_proto;

  u32 mr_index;

  match_result_t mr_result;

  union
  {
    match_mask_ip_mac_t mr_mask_ip_mac;
    match_mask_n_tuple_t mr_mask_n_tuple;
    match_exact_ip_l4_t mr_exact_ip_l4;
    match_ip_prefix_t mr_mask_ip;
    ip_address_t mr_exact_ip;
    match_sets_t mr_sets;
  };
  u8 *mr_tag;
} match_rule_t;

STATIC_ASSERT_SIZEOF (match_rule_t, 2 * CLIB_CACHE_LINE_BYTES);

extern uword unformat_match_rule (unformat_input_t * input, va_list * args);
extern u8 *format_match_rule (u8 * s, va_list * args);
extern u8 *format_match_rule_w_result (u8 * s, va_list * args);

extern int match_rule_cmp (const match_rule_t * mr1,
			   const match_rule_t * mr2);

extern ip_address_family_t match_rule_get_af (const match_rule_t * mr);

extern void match_ip_prefix_set (match_ip_prefix_t * mip,
				 const ip_prefix_t * ip);
extern bool match_icmp_code_range_is_any (const match_icmp_code_range_t *
					  micr);
extern bool match_icmp_type_range_is_any (const match_icmp_type_range_t *
					  micr);
extern bool match_port_range_is_any (const match_port_range_t * mpr);
extern bool match_port_range_is_one (const match_port_range_t * mpr);
extern u16 match_port_range_size (const match_port_range_t * mpr);

#define FOR_EACH_MATCH_PORT_RANGE(_mpr, _port)                          \
  for (_port = _mpr->mpr_begin; _port <= _mpr->mpr_end; _port++)


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
extern u8 *format_match_list_w_result (u8 * s, va_list * args);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
