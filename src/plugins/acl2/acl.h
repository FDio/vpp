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
#include <acl2/macip.h>
#include <acl2/types.h>
#include <acl2/fa_node.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/elog.h>
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_16_8.h>
#include <vlib/counter.h>


#define  ACL_PLUGIN_VERSION_MAJOR 1
#define  ACL_PLUGIN_VERSION_MINOR 4

#define UDP_SESSION_IDLE_TIMEOUT_SEC 600
#define TCP_SESSION_IDLE_TIMEOUT_SEC (3600*24)
#define TCP_SESSION_TRANSIENT_TIMEOUT_SEC 120

#define SESSION_PURGATORY_TIMEOUT_USEC 10

#define ACL_PLUGIN_HASH_LOOKUP_HEAP_SIZE (2 << 25)
#define ACL_PLUGIN_HASH_LOOKUP_HASH_BUCKETS 65536
#define ACL_PLUGIN_HASH_LOOKUP_HASH_MEMORY (2 << 25)

typedef enum acl_timeout_e
{
  ACL_TIMEOUT_UNUSED = 0,
  ACL_TIMEOUT_UDP_IDLE,
  ACL_TIMEOUT_TCP_IDLE,
  ACL_TIMEOUT_TCP_TRANSIENT,
  ACL_N_USER_TIMEOUTS,
  /* a special-case queue for deletion-in-progress sessions */
  ACL_TIMEOUT_PURGATORY = ACL_N_USER_TIMEOUTS,
  ACL_N_TIMEOUTS
} acl_timeout_e;

typedef enum acl_format_flag_t_
{
  ACL_FORMAT_BRIEF = 0,
  ACL_FORMAT_DETAIL = (1 << 0),
  ACL_FORMAT_VERBOSE = (1 << 1),
} acl_format_flag_t;

/*
 * ACL
 */
typedef struct
{
  u8 tag[64];
  acl_rule_t *rules;
} acl_list_t;

extern u8 *format_acl (u8 * s, va_list * a);

typedef struct acl_match_list_t_
{
  match_handle_t aml_hdl;
  match_list_t aml_list;
  acl_action_t *aml_actions;
} acl_match_list_t;

typedef struct acl_list_hdl_t_
{
  u32 acl_index;
  acl_match_list_t acl_match[N_AF];
} acl_list_hdl_t;

extern u8 *format_acl_list_hdl (u8 * s, va_list * a);

typedef enum acl_itf_layer_t_
{
  ACL_ITF_LAYER_L2,
  ACL_ITF_LAYER_L3,
} acl_itf_layer_t;

#define ACL_ITF_N_LAYERS (ACL_ITF_LAYER_L3+1)

typedef struct acl_itf_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 sw_if_index;
  u32 policy_epoch;
  acl_list_hdl_t *acls;
  match_set_app_t match_apps[N_AF];

  index_t match_set[N_AF];
  bool acl_feat_enabled;
  vlib_dir_t dir;
  acl_itf_layer_t layer;
} acl_itf_t;

extern u8 *format_acl_itf (u8 * s, va_list * a);

typedef struct
{
  /* mheap to hold all the ACL module related allocations, other than hash */
  void *acl_mheap;
  uword acl_mheap_size;

  /* API message ID base */
  u16 msg_id_base;

  /* Pool of ACLs */
  acl_list_t *acls;

  /* mheap to hold all the miscellaneous allocations related to hash-based lookups */
  void *hash_lookup_mheap;
  uword hash_lookup_mheap_size;
  int acl_lookup_hash_initialized;

  /* Per interface information */
  acl_itf_t *itf_pool;
  index_t *interfaces[VLIB_N_RX_TX];

  /* interfaces on which given ACLs are applied */
  index_t **interfaces_by_acl;

  /* input and output policy epochs by interface */
  /* u32 *input_policy_epoch_by_sw_if_index; */
  /* u32 *output_policy_epoch_by_sw_if_index; */

  /* whether we need to take the epoch of the session into account */
  int reclassify_sessions;

  /* Total count of interface+direction pairs enabled */
  u32 fa_total_enabled_count;

  /* Do we use hash-based ACL matching or linear */
  int use_hash_acl_matching;

  u32 *acl_etype_input_classify_table_by_sw_if_index;
  u32 *acl_etype_output_classify_table_by_sw_if_index;

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
  vnet_main_t *vnet_main;
  /* logging */
  vlib_log_class_t log_default;
  /* acl counters exposed via stats segment */
  volatile u32 *acl_counter_lock;
  vlib_combined_counter_main_t *combined_acl_counters;
  /* enable/disable ACL counters */
  u32 counters_enabled;
} acl_main_t;

#define acl_log_err(...) \
  vlib_log(VLIB_LOG_LEVEL_ERR, acl_main.log_default, __VA_ARGS__)
#define acl_log_warn(...) \
  vlib_log(VLIB_LOG_LEVEL_WARNING, acl_main.log_default, __VA_ARGS__)
#define acl_log_notice(...) \
  vlib_log(VLIB_LOG_LEVEL_NOTICE, acl_main.log_default, __VA_ARGS__)
#define acl_log_info(...) \
  vlib_log(VLIB_LOG_LEVEL_NOTICE, acl_main.log_default, __VA_ARGS__)
#define acl_log_debug(...) \
  vlib_log(VLIB_LOG_LEVEL_DEBUG, acl_main.log_default, __VA_ARGS__)


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


typedef enum
{
#define _(N, v, s) ACL_EH_##N = v,
  foreach_acl_eh
#undef _
} acl_eh_t;



extern acl_main_t acl_main;

void *acl_mk_heap (void);

typedef enum
{
  ACL_FA_REQ_SESS_RESCHEDULE = 0,
  ACL_FA_N_REQ,
} acl_fa_sess_req_t;

void aclp_post_session_change_request (acl_main_t * am, u32 target_thread,
				       u32 target_session,
				       acl_fa_sess_req_t request_type);
void aclp_swap_wip_and_pending_session_change_requests (acl_main_t * am,
							u32 target_thread);

//
//
// MINE FIXME
//
//

extern int acl_stats_update (int enable);

extern int acl_list_update (index_t * ai, acl_rule_t * rules, u8 * tag);
extern int acl_list_del (index_t ai);

extern int acl_bind (acl_main_t * am,
                     u32 sw_if_index,
                     vlib_dir_t dir,
                     u32 * vec_acl_list_index,
                     int *may_clear_sessions);
extern acl_itf_t *acl_itf_find (u32 sw_if_index, vlib_dir_t dir);

static inline int
acl_is_not_defined (acl_main_t * am, u32 acl_list_index)
{
  return (pool_is_free_index (am->acls, acl_list_index));
}

//
// more me
//

static_always_inline acl_itf_t *
acl_itf_get (u32 sw_if_index, vlib_dir_t dir)
{
  return (pool_elt_at_index (acl_main.itf_pool,
			     acl_main.interfaces[dir][sw_if_index]));
}

static_always_inline acl_itf_t *
acl_itf_get_i (index_t ai)
{
  return (pool_elt_at_index (acl_main.itf_pool, ai));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
