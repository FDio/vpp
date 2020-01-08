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
#include <vnet/match/match_set.h>
#include <acl2/acl2_types.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/elog.h>
#include <vlib/counter.h>


#define  ACL2_PLUGIN_VERSION_MAJOR 1
#define  ACL2_PLUGIN_VERSION_MINOR 4

typedef enum acl2_format_flag_t_
{
  ACL2_FORMAT_BRIEF = 0,
  ACL2_FORMAT_DETAIL = (1 << 0),
  ACL2_FORMAT_VERBOSE = (1 << 1),
} acl2_format_flag_t;


typedef struct acl2_match_list_t_
{
  match_handle_t aml_hdl;
  match_list_t aml_list;
} acl2_match_list_t;

typedef struct acl2_hdl_t_
{
  u32 acl_index;
  acl2_match_list_t acl_match[N_AF];
} acl2_hdl_t;

extern u8 *format_acl2_hdl (u8 * s, va_list * a);

typedef struct acl2_result_t_
{
  union
  {
    struct
    {
      index_t ar_ace;
      acl2_action_t ar_action;
    };
    u64 ar_u64;
  };
} acl2_result_t;

STATIC_ASSERT_SIZEOF (acl2_result_t, sizeof (match_result_t));

extern u8 *format_acl2_result (u8 * s, va_list * a);

typedef enum acl2_itf_layer_t_
{
  ACL2_ITF_LAYER_L2,
  ACL2_ITF_LAYER_L3,
} acl2_itf_layer_t;

#define ACL2_ITF_N_LAYERS (ACL2_ITF_LAYER_L3+1)

typedef struct acl2_itf_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 sw_if_index;
  u32 policy_epoch;
  acl2_hdl_t *acls;
  match_set_app_t match_apps[N_AF];

  index_t match_set[N_AF];
  bool acl_feat_enabled;
  vlib_dir_t dir;
  acl2_itf_layer_t layer;
} acl2_itf_t;

extern u8 *format_acl2_itf (u8 * s, va_list * a);

typedef struct
{
  /* Pool of ACLs */
  acl2_t *acl_pool;
  ace2_t *ace_pool;

  /* Per interface information */
  acl2_itf_t *itf_pool;
  index_t *interfaces[VLIB_N_RX_TX];

  /* interfaces on which given ACLs are applied */
  index_t **interfaces_by_acl;

  /* logging */
  vlib_log_class_t log_default;

  /* enable/disable ACL counters */
  u32 counters_enabled;

  /* heap size - if non-Zero then a heap
   * is created for use with the match infra */
  uword heap_size;
  void *heap;
} acl2_main_t;

/* pr-ACE counters exposed via stats segment */
extern vlib_combined_counter_main_t ace_counters;

extern acl2_main_t acl2_main;

extern int acl2_stats_update (int enable);

extern int acl2_update (index_t * ai, index_t * aces, u8 * tag);
extern int acl2_del (index_t ai);

extern int acl2_bind (u32 sw_if_index,
		      vlib_dir_t dir, u32 * vec_acl_list_index);
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
