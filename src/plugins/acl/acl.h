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
#include <vppinfra/bitmap.h>
#include <vppinfra/elog.h>
#include "bihash_40_8.h"
#include "fa_node.h"

#define  ACL_PLUGIN_VERSION_MAJOR 1
#define  ACL_PLUGIN_VERSION_MINOR 2

extern vlib_node_registration_t acl_in_node;
extern vlib_node_registration_t acl_out_node;

void input_acl_packet_match(u32 sw_if_index, vlib_buffer_t * b0, u32 *nextp, u32 *acl_match_p, u32 *rule_match_p, u32 *trace_bitmap);
void output_acl_packet_match(u32 sw_if_index, vlib_buffer_t * b0, u32 *nextp, u32 *acl_match_p, u32 *rule_match_p, u32 *trace_bitmap);

enum acl_timeout_e {
  ACL_TIMEOUT_UDP_IDLE = 0,
  ACL_TIMEOUT_TCP_IDLE,
  ACL_TIMEOUT_TCP_TRANSIENT,
  ACL_N_TIMEOUTS
};


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
  u32 l2_input_classify_next_acl_old;
  u32 l2_output_classify_next_acl_old;

  /* next node indices for feature bitmap */
  u32 acl_in_node_feat_next_node_index[32];
  u32 acl_out_node_feat_next_node_index[32];

  /* ACL match actions (must be coherent across in/out ACLs to next indices (can differ) */

  u32 acl_in_ip4_match_next[256];
  u32 acl_in_ip6_match_next[256];
  u32 acl_out_ip4_match_next[256];
  u32 acl_out_ip6_match_next[256];
  u32 n_match_actions;

  /* bitmaps when set the processing is enabled on the interface */
  uword *fa_in_acl_on_sw_if_index;
  uword *fa_out_acl_on_sw_if_index;
  /* bitmap, when set the hash is initialized */
  uword *fa_sessions_on_sw_if_index;
  clib_bihash_40_8_t *fa_sessions_by_sw_if_index;
  /* pool for FA session data. See fa_node.h */
  fa_session_t *fa_sessions_pool;
  /* The process node which is responsible to deleting the sessions */
  u32 fa_cleaner_node_index;
  /* FA session timeouts, in seconds */
  u32 session_timeout_sec[ACL_N_TIMEOUTS];
  /* session add/delete counters */
  u64 *fa_session_adds_by_sw_if_index;
  u64 *fa_session_dels_by_sw_if_index;

  /* L2 datapath glue */

  /* active next indices within L2 classifiers - switch old/new path */
  u32 l2_input_classify_next_acl_ip4;
  u32 l2_input_classify_next_acl_ip6;
  u32 l2_output_classify_next_acl_ip4;
  u32 l2_output_classify_next_acl_ip6;
  /* saved next indices within L2 classifiers for ip4/ip6 fa L2 nodes */
  u32 fa_l2_input_classify_next_acl_ip4;
  u32 fa_l2_input_classify_next_acl_ip6;
  u32 fa_l2_output_classify_next_acl_ip4;
  u32 fa_l2_output_classify_next_acl_ip6;
  /* next node indices for L2 dispatch */
  u32 fa_acl_in_ip4_l2_node_feat_next_node_index[32];
  u32 fa_acl_in_ip6_l2_node_feat_next_node_index[32];
  u32 fa_acl_out_ip4_l2_node_feat_next_node_index[32];
  u32 fa_acl_out_ip6_l2_node_feat_next_node_index[32];

  /* EH values that we can skip over */
  uword *fa_ipv6_known_eh_bitmap;

  /* whether to match L4 ACEs with ports on the non-initial fragment */
  int l4_match_nonfirst_fragment;

  /* conn table per-interface conn table parameters */
  u32 fa_conn_table_hash_num_buckets;
  uword fa_conn_table_hash_memory_size;
  u64 fa_conn_table_max_entries;

  /*
   * If the cleaner has to delete more than this number
   * of connections, it halves the sleep time.
   */

#define ACL_FA_DEFAULT_MAX_DELETED_SESSIONS_PER_INTERVAL 100
  u64 fa_max_deleted_sessions_per_interval;

  /*
   * If the cleaner deletes less than these connections,
   * it increases the wait time by the "increment"
   */

#define ACL_FA_DEFAULT_MIN_DELETED_SESSIONS_PER_INTERVAL 1
  u64 fa_min_deleted_sessions_per_interval;

#define ACL_FA_DEFAULT_CLEANER_WAIT_TIME_INCREMENT 0.1
  f64 fa_cleaner_wait_time_increment;

  u64 fa_current_cleaner_timer_wait_interval;
  u32 fa_conn_list_head[ACL_N_TIMEOUTS];
  u32 fa_conn_list_tail[ACL_N_TIMEOUTS];

  /* Counters for the cleaner thread */

#define foreach_fa_cleaner_counter                                         \
  _(fa_cleaner_cnt_delete_by_sw_index, "delete_by_sw_index events")        \
  _(fa_cleaner_cnt_delete_by_sw_index_ok, "delete_by_sw_index handled ok") \
  _(fa_cleaner_cnt_unknown_event, "unknown events received")               \
  _(fa_cleaner_cnt_deleted_sessions, "sessions deleted")                   \
  _(fa_cleaner_cnt_timer_restarted, "session idle timers restarted")       \
  _(fa_cleaner_cnt_wait_with_timeout, "event wait with timeout called")    \
  _(fa_cleaner_cnt_wait_without_timeout, "event wait w/o timeout called")  \
  _(fa_cleaner_cnt_event_cycles, "total event cycles")                     \
  _(fa_cleaner_cnt_already_deleted, "try to delete already deleted conn")  \
/* end of counters */
#define _(id, desc) u32 id;
  foreach_fa_cleaner_counter
#undef _

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} acl_main_t;

#define foreach_acl_eh                                          \
   _(HOPBYHOP , 0  , "IPv6ExtHdrHopByHop")                      \
   _(ROUTING  , 43 , "IPv6ExtHdrRouting")                       \
   _(DESTOPT  , 60 , "IPv6ExtHdrDestOpt")                       \
   _(FRAGMENT , 44 , "IPv6ExtHdrFragment")                      \
   _(MOBILITY , 135, "Mobility Header")                         \
   _(HIP      , 139, "Experimental use Host Identity Protocol") \
   _(SHIM6    , 140, "Shim6 Protocol")                          \
   _(EXP1     , 253, "Use for experimentation and testing")     \
   _(EXP2     , 254, "Use for experimentation and testing")

/*

 "No Next Header" is not a header.
 Also, Fragment header needs special processing.

   _(NONEXT   , 59 , "NoNextHdr")                               \


ESP is hiding its internal format, so no point in trying to go past it.

   _(ESP      , 50 , "EncapsulatingSecurityPayload")            \


AH has a special treatment of its length, it is in 32-bit words, not 64-bit words like the rest.

   _(AUTH     , 51 , "Authentication Header")                   \


*/


 typedef enum {
 #define _(N, v, s) ACL_EH_##N = v,
	 foreach_acl_eh
 #undef _
 } acl_eh_t;



extern acl_main_t acl_main;


#endif
