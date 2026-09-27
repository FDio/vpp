/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <fastacl/fastacl.h>

static int
fastacl_match_valid (const fastacl_match_t *m)
{
  u8 max_plen = fastacl_max_prefix_len (m->flags & FASTACL_MATCH_IS_IP6);

  if (((m->flags & FASTACL_MATCH_DST_PREFIX) && m->dst_prefix_len > max_plen) ||
      ((m->flags & FASTACL_MATCH_SRC_PREFIX) && m->src_prefix_len > max_plen))
    return 0;
  if ((m->flags & FASTACL_MATCH_FRAGMENT) && m->fragment_mask == 0 && m->fragment_flags == 0)
    return 0;
  return 1;
}

int
fastacl_rule_check (const fastacl_match_t *match, const fastacl_action_t *action)
{
  if (action->type != FASTACL_ACTION_TYPE_DROP && action->type != FASTACL_ACTION_TYPE_PERMIT)
    return VNET_API_ERROR_INVALID_VALUE;

  if (!fastacl_match_valid (match))
    return VNET_API_ERROR_INVALID_VALUE;

  return 0;
}

static u32
fastacl_rule_alloc (fastacl_main_t *fsm, u32 order, const fastacl_match_t *match,
		    const fastacl_action_t *action)
{
  fastacl_rule_t *rule;

  pool_get_zero (fsm->rules, rule);
  rule->index = rule - fsm->rules;
  rule->order = order;
  rule->match = *match;
  rule->action = *action;

  fastacl_per_worker_rule_vecs_validate (fsm, rule->index);
  fastacl_rule_gen_bump (fsm, rule->index);

  if (rule->action.sample_ratio)
    fsm->n_sample_rules++;

  return rule->index;
}

int
fastacl_rule_add (u32 order, const fastacl_match_t *match, const fastacl_action_t *action,
		  u32 *rule_index_out)
{
  fastacl_main_t *fsm = &fastacl_main;
  u32 rule_index;
  int rv;

  if ((rv = fastacl_rule_check (match, action)))
    return rv;

  if (fastacl_tss_rule_exists (fsm, order, match))
    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

  rule_index = fastacl_rule_alloc (fsm, order, match, action);
  fastacl_tss_insert_rule (fsm, rule_index);

  if (rule_index_out)
    *rule_index_out = rule_index;

  vlib_log_info (fsm->log_class, "rule add: index=%u order=%u", rule_index, order);

  return 0;
}

u32
fastacl_rule_add_batch (const u32 *orders, const fastacl_match_t *matches,
			const fastacl_action_t *actions, u32 count)
{
  fastacl_main_t *fsm = &fastacl_main;
  u32 n_added = 0;

  fsm->tss_bulk_mode = 1;

  for (u32 i = 0; i < count; i++)
    if (fastacl_rule_add (orders[i], &matches[i], &actions[i], 0) == 0)
      n_added++;

  fsm->tss_bulk_mode = 0;
  fastacl_tss_finalize (fsm);

  vlib_log_info (fsm->log_class, "rule add batch: %u of %u added", n_added, count);

  return n_added;
}

int
fastacl_rule_del (u32 rule_index)
{
  fastacl_main_t *fsm = &fastacl_main;
  fastacl_rule_t *rule;

  if (pool_is_free_index (fsm->rules, rule_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  rule = pool_elt_at_index (fsm->rules, rule_index);

  if (rule->action.sample_ratio && fsm->n_sample_rules)
    fsm->n_sample_rules--;

  fastacl_tss_remove_rule (fsm, rule_index);
  pool_put (fsm->rules, rule);

  fastacl_per_worker_rule_reset (fsm, rule_index);
  fastacl_rule_gen_bump (fsm, rule_index);

  vlib_log_info (fsm->log_class, "rule del: index=%u", rule_index);

  return 0;
}

int
fastacl_rule_del_all (void)
{
  fastacl_main_t *fsm = &fastacl_main;
  fastacl_rule_t *rule;

  pool_foreach (rule, fsm->rules)
    {
      fastacl_per_worker_rule_reset (fsm, rule->index);
      fastacl_rule_gen_bump (fsm, rule->index);
    }

  pool_free (fsm->rules);
  fsm->n_sample_rules = 0;
  fastacl_tss_clear (fsm);

  vlib_log_info (fsm->log_class, "rule del all: all rules removed");

  return 0;
}
