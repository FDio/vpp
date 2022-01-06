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

// test


#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/elog.h>
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_16_8.h>
#include <vlib/counter.h>

#include "types.h"
#include "fa_node.h"
#include "hash_lookup_types.h"
#include "lookup_context.h"

#define  ACL_PLUGIN_VERSION_MAJOR 1
#define  ACL_PLUGIN_VERSION_MINOR 4

#define UDP_SESSION_IDLE_TIMEOUT_SEC 600
#define TCP_SESSION_IDLE_TIMEOUT_SEC (3600*24)
#define TCP_SESSION_TRANSIENT_TIMEOUT_SEC 120

#define SESSION_PURGATORY_TIMEOUT_USEC 10

#define ACL_PLUGIN_HASH_LOOKUP_HASH_BUCKETS 65536
#define ACL_PLUGIN_HASH_LOOKUP_HASH_MEMORY (2 << 25)

extern vlib_node_registration_t acl_in_node;
extern vlib_node_registration_t acl_out_node;

void input_acl_packet_match(u32 sw_if_index, vlib_buffer_t * b0, u32 *nextp, u32 *acl_match_p, u32 *rule_match_p, u32 *trace_bitmap);
void output_acl_packet_match(u32 sw_if_index, vlib_buffer_t * b0, u32 *nextp, u32 *acl_match_p, u32 *rule_match_p, u32 *trace_bitmap);

enum acl_timeout_e {
  ACL_TIMEOUT_UNUSED = 0,
  ACL_TIMEOUT_UDP_IDLE,
  ACL_TIMEOUT_TCP_IDLE,
  ACL_TIMEOUT_TCP_TRANSIENT,
  ACL_N_USER_TIMEOUTS,
  ACL_TIMEOUT_PURGATORY = ACL_N_USER_TIMEOUTS, /* a special-case queue for deletion-in-progress sessions */
  ACL_N_TIMEOUTS
};

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
  /** Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
  u8 tag[64];
  acl_rule_t *rules;
} acl_list_t;

typedef struct
{
  /** Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
  u8 tag[64];
  u32 count;
  macip_acl_rule_t *rules;
  /* References to the classifier tables that will enforce the rules */
  u32 ip4_table_index;
  u32 ip6_table_index;
  u32 l2_table_index;
  /* outacl classifier tables */
  u32 out_ip4_table_index;
  u32 out_ip6_table_index;
  u32 out_l2_table_index;
} macip_acl_list_t;

/*
 * An element describing a particular configuration fo the mask,
 * and how many times it has been used.
 */
typedef struct
{
  /** Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
  fa_5tuple_t mask;
  u32 refcount;
  u8 from_tm;
} ace_mask_type_entry_t;

typedef struct {
  /* API message ID base */
  u16 msg_id_base;

  /* The pool of users of ACL lookup contexts */
  acl_lookup_context_user_t *acl_users;
  /* The pool of ACL lookup contexts */
  acl_lookup_context_t *acl_lookup_contexts;

  acl_list_t *acls;	/* Pool of ACLs */
  hash_acl_info_t *hash_acl_infos; /* corresponding hash matching housekeeping info */
  clib_bihash_48_8_t acl_lookup_hash; /* ACL lookup hash table. */
  u32 hash_lookup_hash_buckets;
  uword hash_lookup_hash_memory;

  int acl_lookup_hash_initialized;
/*
  applied_hash_ace_entry_t **input_hash_entry_vec_by_sw_if_index;
  applied_hash_ace_entry_t **output_hash_entry_vec_by_sw_if_index;
  applied_hash_acl_info_t *input_applied_hash_acl_info_by_sw_if_index;
  applied_hash_acl_info_t *output_applied_hash_acl_info_by_sw_if_index;
*/
  applied_hash_ace_entry_t **hash_entry_vec_by_lc_index;
  applied_hash_acl_info_t *applied_hash_acl_info_by_lc_index;

  /* Corresponding lookup context indices for in/out lookups per sw_if_index */
  u32 *input_lc_index_by_sw_if_index;
  u32 *output_lc_index_by_sw_if_index;
  /* context user id for interface ACLs */
  u32 interface_acl_user_id;

  macip_acl_list_t *macip_acls;	/* Pool of MAC-IP ACLs */

  /* ACLs associated with interfaces */
  u32 **input_acl_vec_by_sw_if_index;
  u32 **output_acl_vec_by_sw_if_index;

  /* interfaces on which given ACLs are applied */
  u32 **input_sw_if_index_vec_by_acl;
  u32 **output_sw_if_index_vec_by_acl;

  /* bitmaps 1=sw_if_index has in/out ACL processing enabled */
  uword *in_acl_on_sw_if_index;
  uword *out_acl_on_sw_if_index;

  /* lookup contexts where a given ACL is used */
  u32 **lc_index_vec_by_acl;

  /* input and output policy epochs by interface */
  u32 *input_policy_epoch_by_sw_if_index;
  u32 *output_policy_epoch_by_sw_if_index;

  /* whether we need to take the epoch of the session into account */
  int reclassify_sessions;



  /* Total count of interface+direction pairs enabled */
  u32 fa_total_enabled_count;

  /* Do we use hash-based ACL matching or linear */
  int use_hash_acl_matching;

  /* Do we use the TupleMerge for hash ACLs or not */
  int use_tuple_merge;

  /* Max collision vector length before splitting the tuple */
#define TM_SPLIT_THRESHOLD 39
  int tuple_merge_split_threshold;

  /* a pool of all mask types present in all ACEs */
  ace_mask_type_entry_t *ace_mask_type_pool;

  /* vec of vectors of all info of all mask types present in ACEs contained in each lc_index */
  hash_applied_mask_info_t **hash_applied_mask_info_vec_by_lc_index;

  /*
   * Classify tables used to grab the packets for the ACL check,
   * and serving as the 5-tuple session tables at the same time
   */
  u32 *acl_ip4_input_classify_table_by_sw_if_index;
  u32 *acl_ip6_input_classify_table_by_sw_if_index;
  u32 *acl_ip4_output_classify_table_by_sw_if_index;
  u32 *acl_ip6_output_classify_table_by_sw_if_index;

  u32 *acl_dot1q_input_classify_table_by_sw_if_index;
  u32 *acl_dot1ad_input_classify_table_by_sw_if_index;
  u32 *acl_dot1q_output_classify_table_by_sw_if_index;
  u32 *acl_dot1ad_output_classify_table_by_sw_if_index;

  u32 *acl_etype_input_classify_table_by_sw_if_index;
  u32 *acl_etype_output_classify_table_by_sw_if_index;

  u16 **input_etype_whitelist_by_sw_if_index;
  u16 **output_etype_whitelist_by_sw_if_index;

  /* MACIP (input) ACLs associated with the interfaces */
  u32 *macip_acl_by_sw_if_index;

  /* Vector of interfaces on which given MACIP ACLs are applied */
  u32 **sw_if_index_vec_by_macip_acl;

  /* bitmaps when set the processing is enabled on the interface */
  uword *fa_in_acl_on_sw_if_index;
  uword *fa_out_acl_on_sw_if_index;
  /* bihash holding all of the sessions */
  int fa_sessions_hash_is_initialized;
  clib_bihash_40_8_t fa_ip6_sessions_hash;
  clib_bihash_16_8_t fa_ip4_sessions_hash;
  /* The process node which orchestrates the cleanup */
  u32 fa_cleaner_node_index;
  /* FA session timeouts, in seconds */
  u32 session_timeout_sec[ACL_N_TIMEOUTS];
  /* total session adds/dels */
  u64 fa_session_total_adds;
  u64 fa_session_total_dels;
  /* how many sessions went into purgatory */
  u64 fa_session_total_deactivations;

  /* EH values that we can skip over */
  uword *fa_ipv6_known_eh_bitmap;

  /* whether to match L4 ACEs with ports on the non-initial fragment */
  int l4_match_nonfirst_fragment;

  /* conn table per-interface conn table parameters */
  u32 fa_conn_table_hash_num_buckets;
  uword fa_conn_table_hash_memory_size;
  u64 fa_conn_table_max_entries;

  int trace_sessions;
  int trace_acl;

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
  /* logging */
  vlib_log_class_t log_default;
  /* acl counters exposed via stats segment */
  volatile u32 *acl_counter_lock;
  vlib_combined_counter_main_t *combined_acl_counters;
  /* enable/disable ACL counters for interface processing */
  u32 interface_acl_counters_enabled;
} acl_main_t;

#define acl_log_err(...) \
  vlib_log(VLIB_LOG_LEVEL_ERR, acl_main.log_default, __VA_ARGS__)
#define acl_log_warn(...) \
  vlib_log(VLIB_LOG_LEVEL_WARNING, acl_main.log_default, __VA_ARGS__)
#define acl_log_notice(...) \
  vlib_log(VLIB_LOG_LEVEL_NOTICE, acl_main.log_default, __VA_ARGS__)
#define acl_log_info(...) \
  vlib_log(VLIB_LOG_LEVEL_INFO, acl_main.log_default, __VA_ARGS__)


static inline void
acl_plugin_counter_lock (acl_main_t * am)
{
  if (am->acl_counter_lock)
    while (clib_atomic_test_and_set (am->acl_counter_lock))
      /* zzzz */ ;
}

static inline void
acl_plugin_counter_unlock (acl_main_t * am)
{
  if (am->acl_counter_lock)
    clib_atomic_release (am->acl_counter_lock);
}


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

typedef enum {
  ACL_FA_REQ_SESS_RESCHEDULE = 0,
  ACL_FA_N_REQ,
} acl_fa_sess_req_t;

void aclp_post_session_change_request(acl_main_t *am, u32 target_thread, u32 target_session, acl_fa_sess_req_t request_type);
void aclp_swap_wip_and_pending_session_change_requests(acl_main_t *am, u32 target_thread);

#endif
