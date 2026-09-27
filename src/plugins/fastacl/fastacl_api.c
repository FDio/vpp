/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#include <vnet/vnet.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <fastacl/fastacl.h>

#include <fastacl.api_enum.h>
#include <fastacl.api_types.h>

#define REPLY_MSG_ID_BASE (fastacl_main.msg_id_base)
#include <vlibapi/api_helper_macros.h>

static void
fastacl_api_match_decode (const vl_api_fastacl_match_t *in, fastacl_match_t *out)
{
  clib_memset (out, 0, sizeof (*out));
  out->flags = in->flags;

  ip_address_decode (&in->dst_addr, &out->dst_addr);
  ip_address_decode (&in->src_addr, &out->src_addr);

  out->dst_prefix_len = in->dst_prefix_len;
  out->src_prefix_len = in->src_prefix_len;

#define _(t, f) out->f = in->f;
  foreach_fastacl_match_scalar_field
#undef _
}

static void
fastacl_api_match_encode (const fastacl_match_t *in, vl_api_fastacl_match_t *out)
{
  ip46_type_t type = (in->flags & FASTACL_MATCH_IS_IP6) ? IP46_TYPE_IP6 : IP46_TYPE_IP4;

  clib_memset (out, 0, sizeof (*out));
  out->flags = in->flags;

  ip_address_encode (&in->dst_addr, type, &out->dst_addr);
  ip_address_encode (&in->src_addr, type, &out->src_addr);

  out->dst_prefix_len = in->dst_prefix_len;
  out->src_prefix_len = in->src_prefix_len;

#define _(t, f) out->f = in->f;
  foreach_fastacl_match_scalar_field
#undef _
}

static void
fastacl_api_action_decode (const vl_api_fastacl_action_t *in, fastacl_action_t *out)
{
  clib_memset (out, 0, sizeof (*out));
#define _(f) out->f = in->f;
  foreach_fastacl_action_field
#undef _
}

static void
fastacl_api_action_encode (const fastacl_action_t *in, vl_api_fastacl_action_t *out)
{
#define _(f) out->f = in->f;
  foreach_fastacl_action_field
#undef _
}

static void
vl_api_fastacl_interface_enable_disable_t_handler (vl_api_fastacl_interface_enable_disable_t *mp)
{
  vl_api_fastacl_interface_enable_disable_reply_t *rmp;
  int rv = 0;

  if (!vnet_sw_if_index_is_api_valid (mp->sw_if_index))
    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
  else
    rv = fastacl_interface_enable_disable (mp->sw_if_index, mp->enable_disable);

  REPLY_MACRO_END (VL_API_FASTACL_INTERFACE_ENABLE_DISABLE_REPLY);
}

static void
vl_api_fastacl_psample_enable_t_handler (vl_api_fastacl_psample_enable_t *mp)
{
  vl_api_fastacl_psample_enable_reply_t *rmp;
  int rv = fastacl_psample_enable_disable (mp->enable);
  REPLY_MACRO_END (VL_API_FASTACL_PSAMPLE_ENABLE_REPLY);
}

static void
vl_api_fastacl_rule_add_t_handler (vl_api_fastacl_rule_add_t *mp)
{
  vl_api_fastacl_rule_add_reply_t *rmp;
  fastacl_match_t match;
  fastacl_action_t action;
  int rv;

  fastacl_api_match_decode (&mp->match, &match);
  fastacl_api_action_decode (&mp->action, &action);
  rv = fastacl_rule_add (mp->order, &match, &action, 0);

  REPLY_MACRO_END (VL_API_FASTACL_RULE_ADD_REPLY);
}

static int
fastacl_api_batch_decode (vl_api_fastacl_rule_add_batch_t *mp, u32 count, u32 **orders,
			  fastacl_match_t **matches, fastacl_action_t **actions)
{
  for (u32 i = 0; i < count; i++)
    {
      fastacl_match_t match;
      fastacl_action_t action;

      fastacl_api_match_decode (&mp->rules[i].match, &match);
      fastacl_api_action_decode (&mp->rules[i].action, &action);
      if (fastacl_rule_check (&match, &action))
	return VNET_API_ERROR_INVALID_VALUE;

      vec_add1 (*orders, mp->rules[i].order);
      vec_add1 (*matches, match);
      vec_add1 (*actions, action);
    }

  return 0;
}

static int
fastacl_api_batch_count_fits (vl_api_fastacl_rule_add_batch_t *mp, u32 count)
{
  u32 msg_len = vl_msg_api_get_msg_length (mp);

  if (msg_len < sizeof (*mp))
    return 0;
  return count <= (msg_len - sizeof (*mp)) / sizeof (mp->rules[0]);
}

static void
vl_api_fastacl_rule_add_batch_t_handler (vl_api_fastacl_rule_add_batch_t *mp)
{
  vl_api_fastacl_rule_add_batch_reply_t *rmp;
  u32 count = mp->count;
  u32 n_added = 0;
  u32 *orders = 0;
  fastacl_match_t *matches = 0;
  fastacl_action_t *actions = 0;

  int rv = fastacl_api_batch_count_fits (mp, count) ?
	     fastacl_api_batch_decode (mp, count, &orders, &matches, &actions) :
	     VNET_API_ERROR_INVALID_VALUE;

  if (!rv)
    n_added = fastacl_rule_add_batch (orders, matches, actions, count);

  vec_free (orders);
  vec_free (matches);
  vec_free (actions);

  REPLY_MACRO2_END (VL_API_FASTACL_RULE_ADD_BATCH_REPLY, ({ rmp->n_added = n_added; }));
}

static void
vl_api_fastacl_rule_del_t_handler (vl_api_fastacl_rule_del_t *mp)
{
  vl_api_fastacl_rule_del_reply_t *rmp;
  int rv;

  rv = fastacl_rule_del (mp->rule_index);

  REPLY_MACRO_END (VL_API_FASTACL_RULE_DEL_REPLY);
}

static void
vl_api_fastacl_rule_dump_t_handler (vl_api_fastacl_rule_dump_t *mp)
{
  vl_api_registration_t *reg;
  fastacl_main_t *fsm = &fastacl_main;
  fastacl_rule_t *rule;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  u32 context = mp->context;

  fastacl_update_rates (fsm->vlib_main);

  pool_foreach (rule, fsm->rules)
    {
      vl_api_fastacl_rule_details_t *rmp;
      rmp = vl_msg_api_alloc (sizeof (*rmp));
      REPLY_MACRO_DETAILS4_END (VL_API_FASTACL_RULE_DETAILS, reg, context, ({
				  rmp->rule_index = rule->index;
				  rmp->order = rule->order;
				  rmp->packet_count = rule->packet_count;
				  rmp->byte_count = rule->byte_count;
				  rmp->pps = rule->rate_snap.pps;
				  rmp->l3_bps = rule->rate_snap.l3_bps;
				  rmp->l1_bps = rule->rate_snap.l1_bps;

				  fastacl_api_match_encode (&rule->match, &rmp->match);
				  fastacl_api_action_encode (&rule->action, &rmp->action);

				  u64 sampled, missed;
				  fastacl_per_worker_rule_sample_sum (fsm, rule->index, &sampled,
								      &missed);
				  rmp->sample_count = sampled;
				  rmp->sample_missed = missed;

				  rmp->generation = fastacl_rule_gen_get (fsm, rule->index);
				}));
    }
}

static void
vl_api_fastacl_counters_clear_t_handler (vl_api_fastacl_counters_clear_t *mp)
{
  vl_api_fastacl_counters_clear_reply_t *rmp;
  int rv = 0;

  fastacl_clear_counters ();

  REPLY_MACRO_END (VL_API_FASTACL_COUNTERS_CLEAR_REPLY);
}

static void
vl_api_fastacl_counters_get_t_handler (vl_api_fastacl_counters_get_t *mp)
{
  vl_api_fastacl_counters_get_reply_t *rmp;
  fastacl_main_t *fsm = &fastacl_main;
  int rv = 0;

  fastacl_update_rates (fsm->vlib_main);

  u32 n_hit_rules = 0;
  fastacl_rule_t *rule;
  pool_foreach (rule, fsm->rules)
    {
      if (rule->packet_count > 0)
	n_hit_rules++;
    }

  REPLY_MACRO2_END (VL_API_FASTACL_COUNTERS_GET_REPLY, ({
		      rmp->total_bytes_processed = fsm->counters.total_bytes_processed;
		      rmp->total_bytes_dropped = fsm->counters.total_bytes_dropped;
		      rmp->total_processed = fsm->counters.total_processed;
		      rmp->total_dropped = fsm->counters.total_dropped;
		      rmp->total_pps = fsm->counters.processed_rate.pps;
		      rmp->dropped_pps = fsm->counters.dropped_rate.pps;
		      rmp->total_l3_bps = fsm->counters.processed_rate.l3_bps;
		      rmp->total_l1_bps = fsm->counters.processed_rate.l1_bps;
		      rmp->dropped_l3_bps = fsm->counters.dropped_rate.l3_bps;
		      rmp->dropped_l1_bps = fsm->counters.dropped_rate.l1_bps;
		      rmp->n_hit_rules = n_hit_rules;
		    }));
}

static void
vl_api_fastacl_rule_del_all_t_handler (vl_api_fastacl_rule_del_all_t *mp)
{
  vl_api_fastacl_rule_del_all_reply_t *rmp;
  int rv = fastacl_rule_del_all ();

  REPLY_MACRO_END (VL_API_FASTACL_RULE_DEL_ALL_REPLY);
}

static void
vl_api_fastacl_rule_stats_set_t_handler (vl_api_fastacl_rule_stats_set_t *mp)
{
  vl_api_fastacl_rule_stats_set_reply_t *rmp;
  fastacl_main_t *fsm = &fastacl_main;
  int rv = 0;

  fsm->rule_stats_enabled = mp->enable != 0;

  REPLY_MACRO_END (VL_API_FASTACL_RULE_STATS_SET_REPLY);
}

#include <vnet/ip/ip_format_fns.h>

#include <fastacl.api.c>

static clib_error_t *
fastacl_api_init (vlib_main_t *vm)
{
  fastacl_main_t *fsm = &fastacl_main;
  fsm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (fastacl_api_init);
