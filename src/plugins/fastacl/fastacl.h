/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#ifndef __included_fastacl_h__
#define __included_fastacl_h__

#include <vppinfra/bitmap.h>

#include <fastacl/fastacl_types.h>
#include <fastacl/fastacl_tss.h>
#include <fastacl/fastacl_match_inline.h>
#include <fastacl/fastacl_flowspec.h>

struct fastacl_main_t_
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  fastacl_rule_t *rules;

  fastacl_per_worker_t *per_worker;

  fastacl_aggregate_counters_t counters;

  vlib_combined_counter_main_t rule_counters;

  u32 rule_counter_len;

  u32 rule_gen_stat_index;
  u32 rule_gen_len;

  uword *enabled_interfaces;

  u8 psample_enabled;
  u32 n_sample_rules;
  fastacl_psample_main_t psample;

  fastacl_tuple_t *tuples;
  uword *tuple_by_mask;
  u32 *tuple_index_v4;
  u32 *tuple_index_v6;
  fastacl_chain_t *chains;

  u32 tss_buckets;
  u8 rule_stats_enabled;
  u8 tss_bulk_mode;

  u16 msg_id_base;

  vlib_log_class_t log_class;
};

extern fastacl_main_t fastacl_main;

static inline int
fastacl_rule_order_cmp (const void *a, const void *b)
{
  fastacl_main_t *fsm = &fastacl_main;
  u32 ai = *(const u32 *) a, bi = *(const u32 *) b;
  return fastacl_rule_precedence_cmp (pool_elt_at_index (fsm->rules, ai), ai,
				      pool_elt_at_index (fsm->rules, bi), bi);
}

extern vlib_node_registration_t fastacl_filter_node;
extern vlib_node_registration_t fastacl_filter_l2_node;

typedef enum
{
  FASTACL_NEXT_DROP,
  FASTACL_N_NEXT,
} fastacl_next_t;

int fastacl_psample_init (void);
int fastacl_psample_enable_disable (int enable);
int fastacl_psample_worker_open (fastacl_psample_worker_t *w);
void fastacl_psample_worker_close (fastacl_psample_worker_t *w);
int fastacl_psample_send (fastacl_psample_worker_t *w, u32 group, u32 rate, u32 iifindex,
			  u32 origsize, const u8 *data, u32 len);

int fastacl_rule_check (const fastacl_match_t *match, const fastacl_action_t *action);
int fastacl_rule_add (u32 order, const fastacl_match_t *match, const fastacl_action_t *action,
		      u32 *rule_index_out);
u32 fastacl_rule_add_batch (const u32 *orders, const fastacl_match_t *matches,
			    const fastacl_action_t *actions, u32 count);
int fastacl_rule_del (u32 rule_index);
int fastacl_rule_del_all (void);
void fastacl_clear_counters (void);
void fastacl_update_rates (vlib_main_t *vm);
void fastacl_update_aggregate_rates (vlib_main_t *vm);

#define foreach_fastacl_per_worker(pw, fsm)                                                        \
  for (fastacl_per_worker_t * (pw) = (fsm)->per_worker; (pw) < vec_end ((fsm)->per_worker); (pw)++)

void fastacl_per_worker_rule_vecs_validate (fastacl_main_t *fsm, u32 max_index);
void fastacl_per_worker_rule_reset (fastacl_main_t *fsm, u32 rule_index);
void fastacl_rule_gen_bump (fastacl_main_t *fsm, u32 rule_index);
u64 fastacl_rule_gen_get (fastacl_main_t *fsm, u32 rule_index);
void fastacl_per_worker_rule_sample_sum (fastacl_main_t *fsm, u32 rule_index, u64 *sampled,
					 u64 *missed);

int fastacl_interface_enable_disable (u32 sw_if_index, int enable_disable);

#endif
