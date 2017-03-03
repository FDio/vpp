/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#ifndef included_acl_h
#define included_acl_h

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_output.h>


#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#define  ACL_PLUGIN_VERSION_MAJOR 1
#define  ACL_PLUGIN_VERSION_MINOR 1

extern vlib_node_registration_t acl_in_node;
extern vlib_node_registration_t acl_out_node;

void input_acl_packet_match(u32 sw_if_index, vlib_buffer_t * b0, u32 *nextp, u32 *acl_match_p, u32 *rule_match_p, u32 *trace_bitmap);
void output_acl_packet_match(u32 sw_if_index, vlib_buffer_t * b0, u32 *nextp, u32 *acl_match_p, u32 *rule_match_p, u32 *trace_bitmap);

enum address_e { IP4, IP6 };
typedef struct
{
  enum address_e type;
  union {
    ip6_address_t ip6;
    ip4_address_t ip4;
  } addr;
} address_t;

/*
 * ACL rules
 */
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

typedef struct
{
  u8 is_permit;
  u8 is_ipv6;
  u8 src_mac[6];
  u8 src_mac_mask[6];
  ip46_address_t src_ip_addr;
  u8 src_prefixlen;
} macip_acl_rule_t;

/*
 * ACL
 */
typedef struct
{
  u8 tag[64];
  u32 count;
  acl_rule_t *rules;
} acl_list_t;

typedef struct
{
  u8 tag[64];
  u32 count;
  macip_acl_rule_t *rules;
  /* References to the classifier tables that will enforce the rules */
  u32 ip4_table_index;
  u32 ip6_table_index;
  u32 l2_table_index;
} macip_acl_list_t;

typedef struct {
  /* API message ID base */
  u16 msg_id_base;

  acl_list_t *acls;	/* Pool of ACLs */
  macip_acl_list_t *macip_acls;	/* Pool of MAC-IP ACLs */

  /* ACLs associated with interfaces */
  u32 **input_acl_vec_by_sw_if_index;
  u32 **output_acl_vec_by_sw_if_index;

  /*
   * Classify tables used to grab the packets for the ACL check,
   * and serving as the 5-tuple session tables at the same time
   */
  u32 *acl_ip4_input_classify_table_by_sw_if_index;
  u32 *acl_ip6_input_classify_table_by_sw_if_index;
  u32 *acl_ip4_output_classify_table_by_sw_if_index;
  u32 *acl_ip6_output_classify_table_by_sw_if_index;

  /* MACIP (input) ACLs associated with the interfaces */
  u32 *macip_acl_by_sw_if_index;

  /* next indices for our nodes in the l2-classify tables */
  u32 l2_input_classify_next_acl;
  u32 l2_output_classify_next_acl;

  /* next node indices for feature bitmap */
  u32 acl_in_node_feat_next_node_index[32];
  u32 acl_out_node_feat_next_node_index[32];

  /* ACL match actions (must be coherent across in/out ACLs to next indices (can differ) */

  u32 acl_in_ip4_match_next[256];
  u32 acl_in_ip6_match_next[256];
  u32 acl_out_ip4_match_next[256];
  u32 acl_out_ip6_match_next[256];
  u32 n_match_actions;


  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} acl_main_t;

extern acl_main_t acl_main;


#endif
