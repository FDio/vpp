/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __POLICER_PUNT_DROP_H__
#define __POLICER_PUNT_DROP_H__

#include <policer/policer.h>
#include <policer/police_inlines.h>
#include <policer/policer_op.h>

/**
 * IP4 punt policer configuration
 *   we police the punt rate to prevent overloading the host
 */
typedef struct ip_punt_policer_t_
{
  u32 policer_index;
  u32 fq_index;
} ip_punt_policer_t;

typedef enum ip_punt_policer_next_t_
{
  IP_PUNT_POLICER_NEXT_DROP,
  IP_PUNT_POLICER_NEXT_HANDOFF,
  IP_PUNT_POLICER_N_NEXT,
} ip_punt_policer_next_t;

typedef struct ip_punt_policer_trace_t_
{
  u32 policer_index;
  u32 next;
} ip_punt_policer_trace_t;

#define foreach_ip_punt_policer_error _ (DROP, "ip punt policer drop")

typedef enum
{
#define _(sym, str) IP_PUNT_POLICER_ERROR_##sym,
  foreach_ip_punt_policer_error
#undef _
    IP4_PUNT_POLICER_N_ERROR,
} ip_punt_policer_error_t;

extern u8 *format_ip_punt_policer_trace (u8 *s, va_list *args);
extern vlib_node_registration_t ip4_punt_policer_node;
extern ip_punt_policer_t ip4_punt_policer_cfg;
extern vlib_node_registration_t ip6_punt_policer_node;
extern ip_punt_policer_t ip6_punt_policer_cfg;

int ip4_punt_policer_add_del (u8 is_add, u32 policer_index);
int ip6_punt_policer_add_del (u8 is_add, u32 policer_index);

static_always_inline int
ip46_punt_policer_add_del (u8 is_add, u32 policer_index, u8 is_v6)
{
  const char *ip_punt_feature_name = is_v6 ? "ip6-punt" : "ip4-punt";
  const char *ip_punt_node_name = is_v6 ? "ip6-punt-policer" : "ip4-punt-policer";
  ip_punt_policer_t *ip_punt_policer_cfg = is_v6 ? &ip6_punt_policer_cfg : &ip4_punt_policer_cfg;
  int call_feature_enable_disable = 1;

  if (is_add)
    {
      int err = policer_lock (policer_index);
      if (err < 0)
	return err;

      if (ip_punt_policer_cfg->policer_index != ~0)
	{
	  policer_unlock (ip_punt_policer_cfg->policer_index);
	  call_feature_enable_disable = 0;
	}

      ip_punt_policer_cfg->policer_index = policer_index;
    }
  else if (ip_punt_policer_cfg->policer_index != ~0)
    {
      int err = policer_unlock (ip_punt_policer_cfg->policer_index);
      if (err < 0)
	return err;

      ip_punt_policer_cfg->policer_index = ~0;
    }
  else
    {
      call_feature_enable_disable = 0;
    }

  if (call_feature_enable_disable)
    vnet_feature_enable_disable (ip_punt_feature_name, ip_punt_node_name, 0, is_add, 0, 0);

  return 0;
}

/**
 * IP punt policing node function
 */
always_inline uword
ip_punt_policer (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 arc_index,
		 u32 policer_index)
{
  u32 *from, *to_next, n_left_from, n_left_to_next, next_index;
  u64 time_in_policer_periods;
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm = &fm->feature_config_mains[arc_index];

  time_in_policer_periods = clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  u8 act0, act1;
	  u32 bi0, bi1;

	  next0 = next1 = 0;
	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  act0 = policer_police (vm, b0, policer_index, time_in_policer_periods, POLICE_CONFORM,
				 true, 0);
	  act1 = policer_police (vm, b1, policer_index, time_in_policer_periods, POLICE_CONFORM,
				 true, 0);

	  if (PREDICT_FALSE (act0 == QOS_ACTION_HANDOFF))
	    {
	      next0 = next1 = IP_PUNT_POLICER_NEXT_HANDOFF;
	    }
	  else
	    {

	      vnet_get_config_data (&cm->config_main, &b0->current_config_index, &next0, 0);
	      vnet_get_config_data (&cm->config_main, &b1->current_config_index, &next1, 0);

	      if (PREDICT_FALSE (act0 == QOS_ACTION_DROP))
		{
		  next0 = IP_PUNT_POLICER_NEXT_DROP;
		  b0->error = node->errors[IP_PUNT_POLICER_ERROR_DROP];
		}
	      if (PREDICT_FALSE (act1 == QOS_ACTION_DROP))
		{
		  next1 = IP_PUNT_POLICER_NEXT_DROP;
		  b1->error = node->errors[IP_PUNT_POLICER_ERROR_DROP];
		}

	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  ip_punt_policer_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->next = next0;
		  t->policer_index = policer_index;
		}
	      if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
		{
		  ip_punt_policer_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->next = next1;
		  t->policer_index = policer_index;
		}
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next, n_left_to_next, bi0, bi1,
					   next0, next1);
	}
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 bi0;
	  u8 act0;

	  next0 = 0;
	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  act0 = policer_police (vm, b0, policer_index, time_in_policer_periods, POLICE_CONFORM,
				 true, 0);
	  if (PREDICT_FALSE (act0 == QOS_ACTION_HANDOFF))
	    {
	      next0 = IP_PUNT_POLICER_NEXT_HANDOFF;
	    }
	  else
	    {
	      vnet_get_config_data (&cm->config_main, &b0->current_config_index, &next0, 0);

	      if (PREDICT_FALSE (act0 == QOS_ACTION_DROP))
		{
		  next0 = IP_PUNT_POLICER_NEXT_DROP;
		  b0->error = node->errors[IP_PUNT_POLICER_ERROR_DROP];
		}

	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  ip_punt_policer_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->next = next0;
		  t->policer_index = policer_index;
		}
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

#endif /* __POLICER_PUNT_DROP_H__ */
