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
#ifndef __ACL2_H__
#define __ACL2_H__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/match/match_set.h>
#include <vnet/conntrack/conntrack.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/elog.h>
#include <vlib/counter.h>


#define  ACL2_PLUGIN_VERSION_MAJOR 1
#define  ACL2_PLUGIN_VERSION_MINOR 0

#include <vnet/match/match_types.h>

/**
 * ACL Actions
 *
 * deny - drop the packet
 * permit - allow the packet to pass
 * track - permit and create a connection in the connection tracking DB
 */
#define foreach_acl2_action                     \
  _(DENY, "deny")                               \
  _(PERMIT, "permit")                           \
  _(TRACK, "track")                             \

typedef enum acl2_action_t_
{
#define _(a,b) ACL2_ACTION_##a,
  foreach_acl2_action
#undef _
} __clib_packed acl2_action_t;

#define ACL2_N_ACTIONS (ACL2_ACTION_TRACK+1)

extern u8 *format_acl2_action (u8 * s, va_list * a);
extern uword unformat_acl2_action (unformat_input_t * input, va_list * args);

/**
 * The network layer at which the ACL is applied
 */
typedef enum acl2_itf_layer_t_
{
  ACL2_ITF_LAYER_L2,
  ACL2_ITF_LAYER_L3,
} acl2_itf_layer_t;

#define ACL2_ITF_N_LAYERS (ACL2_ITF_LAYER_L3+1)

extern u8 *format_acl2_itf_layer (u8 * s, va_list * args);

/**
 * Flags that apply to the ACL binding
 */
#define foreach_acl2_itf_flag                 \
  _(FEATURE_ON, 1, "feature-on")              \

typedef enum acl2_itf_flags_t_
{
#define _(a,b,c) ACL2_ITF_FLAG_##a = b,
  foreach_acl2_itf_flag
#undef _
} acl2_itf_flags_t;

extern u8 *format_acl2_itf_flags (u8 * s, va_list * args);

/**
 * An Access Control Entry
 */
typedef struct ace2_t_
{
  acl2_action_t ace_action;
  match_rule_t ace_rule;
  conn_owner_t *ace_conn_owner;
} ace2_t;

extern u8 *format_ace2 (u8 * s, va_list * a);

/**
 * Per-AF data kept for each ACL
 */
typedef struct acl2_per_af_t_
{
  /** the match type that all the rules have */
  match_type_t apf_mtype;

  /** the match orientation that all the rules have */
  match_orientation_t apf_mo;

  /** The match list derived from the ACL's list that includes
   * only this AF */
  match_list_t apf_list;
} acl2_per_af_t;

extern u8 *format_acl2_per_af (u8 * s, va_list * a);

/**
 * An Acess Control List
 */
typedef struct acl2_t_
{
  /** the user's tag/name for this ACL */
  u8 acl_tag[64];

  /** vector of ACEs that the list is comprised of */
  index_t *acl_aces;

  /** separate per-AF data held for the ACL */
  acl2_per_af_t acl_per_af[N_AF];
} acl2_t;

extern u8 *format_acl2 (u8 * s, va_list * a);

typedef enum acl2_format_flag_t_
{
  ACL2_FORMAT_BRIEF = 0,
  ACL2_FORMAT_DETAIL = (1 << 0),
  ACL2_FORMAT_VERBOSE = (1 << 1),
} acl2_format_flag_t;

typedef struct acl2_hdl_t_
{
  u32 ah_acl;
  match_handle_t ah_hdl[N_AF];
} acl2_hdl_t;

extern u8 *format_acl2_hdl (u8 * s, va_list * a);

/**
 * The result of a match lookup.
 *  this must fit in the u64 provided by the match infra
 */
typedef struct acl2_result_t_
{
  union
  {
    struct
    {
      /** The ACE that match */
      index_t ar_ace;

      /** The action of the ACE. cached here so we need not load the
       * ACE in the DP */
      acl2_action_t ar_action;
    };
    u64 ar_u64;
  };
} acl2_result_t;

STATIC_ASSERT_SIZEOF (acl2_result_t, sizeof (match_result_t));

extern u8 *format_acl2_result (u8 * s, va_list * a);

/**
 * Per AF data held for an ACL binding
 */
typedef struct acl2_itf_af_t_
{
  match_set_app_t match_app;
  index_t match_set;
  index_t conn_db;
  u32 n_trackers;
  acl2_itf_flags_t flags;
} acl2_itf_af_t;

/**
 * Fits neatly into half a cache-line
 */
STATIC_ASSERT_SIZEOF (acl2_itf_af_t, 32);

typedef struct acl2_itf_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /**
   * first cacheline has the members accessed in the DP
   */
  acl2_itf_af_t per_af[N_AF];

    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  u32 sw_if_index;
  acl2_hdl_t *acls;
  u32 n_conns;
  vlib_dir_t dir;
  acl2_itf_layer_t layer;
} acl2_itf_t;

/**
 * 2 cachelines => always cache-line aligned
 */
STATIC_ASSERT_SIZEOF (acl2_itf_t, 2 * CLIB_CACHE_LINE_BYTES);

extern u8 *format_acl2_itf (u8 * s, va_list * a);

typedef struct acl2_conn_db_owner_t_
{
  index_t conn_db;
  bool conn_owners[VLIB_N_DIR];
} acl2_conn_db_owner_t;

#define ACL2_N_CONNECTIONS_PER_WORKER (1 << 18)

typedef struct
{
  /* Pool of ACLs, ACEs and interfaces */
  acl2_t *acl_pool;
  ace2_t *ace_pool;
  acl2_itf_t *itf_pool;

  /* Binding lookup per-direction, per-interface */
  index_t *interfaces[VLIB_N_RX_TX];

  /** registered conntrack user id */
  conn_user_t conn_user;

  /** connection tracking DBs per-AF, per-interface */
  acl2_conn_db_owner_t *conn_dbs[N_AF];

  /* interfaces on which given ACLs are applied */
  index_t **interfaces_by_acl;

  /* enable/disable ACL counters */
  u32 counters_enabled;

  /* heap size - if non-Zero then a heap
   * is created for use with the match infra */
  uword heap_size;
  void *heap;
} acl2_main_t;

/** per-ACE counters exposed via stats segment */
extern vlib_combined_counter_main_t ace_counters;

/** Global variables */
extern acl2_main_t acl2_main;

/**
 * @brief Update the status for per-ACE stats collection
 *
 * @param enable - Enable/Disable the stats
 */
extern int acl2_stats_update (int enable);

extern int acl2_update (index_t * ai, index_t * aces, u8 * tag);
extern int acl2_del (index_t ai);

extern int acl2_bind (u32 sw_if_index,
		      vlib_dir_t dir, u32 * vec_acl_list_index, u32 n_conns);
extern acl2_itf_t *acl2_itf_find (u32 sw_if_index, vlib_dir_t dir);
extern bool acl2_is_valid (index_t ai);

typedef walk_rc_t (*acl2_walk_fn_t) (index_t acl, index_t ace, void *arg);
extern void acl2_walk (index_t acl, acl2_walk_fn_t fn, void *arg);

static_always_inline acl2_itf_t *
acl2_itf_get (u32 sw_if_index, vlib_dir_t dir)
{
  return (pool_elt_at_index (acl2_main.itf_pool,
			     acl2_main.interfaces[dir][sw_if_index]));
}

static_always_inline acl2_itf_t *
acl2_itf_get_i (index_t ai)
{
  return (pool_elt_at_index (acl2_main.itf_pool, ai));
}

static_always_inline ace2_t *
ace2_get (index_t acei)
{
  return (pool_elt_at_index (acl2_main.ace_pool, acei));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
