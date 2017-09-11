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
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/bihash_40_8.h>

#include "fa_node.h"
#include "hash_lookup_types.h"

#define  ACL_PLUGIN_VERSION_MAJOR 1
#define  ACL_PLUGIN_VERSION_MINOR 3

#define UDP_SESSION_IDLE_TIMEOUT_SEC 600
#define TCP_SESSION_IDLE_TIMEOUT_SEC (3600*24)
#define TCP_SESSION_TRANSIENT_TIMEOUT_SEC 120

#define ACL_FA_DEFAULT_HEAP_SIZE (2 << 29)

#define ACL_PLUGIN_HASH_LOOKUP_HEAP_SIZE (2 << 25)
#define ACL_PLUGIN_HASH_LOOKUP_HASH_BUCKETS 65536
#define ACL_PLUGIN_HASH_LOOKUP_HASH_MEMORY (2 << 25)

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

/*
 * An element describing a particular configuration fo the mask,
 * and how many times it has been used.
 */
typedef struct
{
  fa_5tuple_t mask;
  u32 refcount;
} ace_mask_type_entry_t;

typedef struct {
  /* mheap to hold all the ACL module related allocations, other than hash */
  void *acl_mheap;
  u32 acl_mheap_size;

  /* API message ID base */
  u16 msg_id_base;

  acl_list_t *acls;	/* Pool of ACLs */
  hash_acl_info_t *hash_acl_infos; /* corresponding hash matching housekeeping info */
  clib_bihash_48_8_t acl_lookup_hash; /* ACL lookup hash table. */
  u32 hash_lookup_hash_buckets;
  u32 hash_lookup_hash_memory;

  /* mheap to hold all the miscellaneous allocations related to hash-based lookups */
  void *hash_lookup_mheap;
  u32 hash_lookup_mheap_size;
  int acl_lookup_hash_initialized;
  applied_hash_ace_entry_t **input_hash_entry_vec_by_sw_if_index;
  applied_hash_ace_entry_t **output_hash_entry_vec_by_sw_if_index;
  applied_hash_acl_info_t *input_applied_hash_acl_info_by_sw_if_index;
  applied_hash_acl_info_t *output_applied_hash_acl_info_by_sw_if_index;

  macip_acl_list_t *macip_acls;	/* Pool of MAC-IP ACLs */

  /* ACLs associated with interfaces */
  u32 **input_acl_vec_by_sw_if_index;
  u32 **output_acl_vec_by_sw_if_index;

  /* interfaces on which given ACLs are applied */
  u32 **input_sw_if_index_vec_by_acl;
  u32 **output_sw_if_index_vec_by_acl;

  /* Total count of interface+direction pairs enabled */
  u32 fa_total_enabled_count;

  /* Do we use hash-based ACL matching or linear */
  int use_hash_acl_matching;

  /* a pool of all mask types present in all ACEs */
  ace_mask_type_entry_t *ace_mask_type_pool;

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

  /* bitmaps when set the processing is enabled on the interface */
  uword *fa_in_acl_on_sw_if_index;
  uword *fa_out_acl_on_sw_if_index;
  /* bihash holding all of the sessions */
  int fa_sessions_hash_is_initialized;
  clib_bihash_40_8_t fa_sessions_hash;
  /* The process node which orcherstrates the cleanup */
  u32 fa_cleaner_node_index;
  /* FA session timeouts, in seconds */
  u32 session_timeout_sec[ACL_N_TIMEOUTS];
  /* total session adds/dels */
  u64 fa_session_total_adds;
  u64 fa_session_total_dels;

  /* L2 datapath glue */

  /* next indices within L2 classifiers for ip4/ip6 fa L2 nodes */
  u32 l2_input_classify_next_acl_ip4;
  u32 l2_input_classify_next_acl_ip6;
  u32 l2_output_classify_next_acl_ip4;
  u32 l2_output_classify_next_acl_ip6;
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

  int fa_interrupt_generation;

  /* per-worker data related t conn management */
  acl_fa_per_worker_data_t *per_worker_data;

  /* Configured session timeout */
  u64 session_timeout[ACL_N_TIMEOUTS];


  /* Counters for the cleaner thread */

#define foreach_fa_cleaner_counter                                         \
  _(fa_cleaner_cnt_delete_by_sw_index, "delete_by_sw_index events")        \
  _(fa_cleaner_cnt_delete_by_sw_index_ok, "delete_by_sw_index handled ok") \
  _(fa_cleaner_cnt_unknown_event, "unknown events received")               \
  _(fa_cleaner_cnt_timer_restarted, "session idle timers restarted")       \
  _(fa_cleaner_cnt_wait_with_timeout, "event wait with timeout called")    \
  _(fa_cleaner_cnt_wait_without_timeout, "event wait w/o timeout called")  \
  _(fa_cleaner_cnt_event_cycles, "total event cycles")                     \
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
