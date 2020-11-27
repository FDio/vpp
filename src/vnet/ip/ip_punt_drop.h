/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef __IP_PUNT_DROP_H__
#define __IP_PUNT_DROP_H__

#include <vnet/ip/ip.h>
#include <vnet/policer/policer.h>
#include <vnet/policer/police_inlines.h>

/**
 * IP4 punt policer configuration
 *   we police the punt rate to prevent overloading the host
 */
typedef struct ip_punt_policer_t_
{
  u32 policer_index;
} ip_punt_policer_t;

typedef enum ip_punt_policer_next_t_
{
  IP_PUNT_POLICER_NEXT_DROP,
  IP_PUNT_POLICER_N_NEXT,
} ip_punt_policer_next_t;

typedef struct ip_punt_policer_trace_t_
{
  u32 policer_index;
  u32 next;
} ip_punt_policer_trace_t;

#define foreach_ip_punt_policer_error          \
_(DROP, "ip punt policer drop")

typedef enum
{
#define _(sym,str) IP_PUNT_POLICER_ERROR_##sym,
  foreach_ip_punt_policer_error
#undef _
    IP4_PUNT_POLICER_N_ERROR,
} ip_punt_policer_error_t;

extern u8 *format_ip_punt_policer_trace (u8 * s, va_list * args);

/**
 * IP punt policing node function
 */
always_inline uword
ip_punt_policer (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * frame, u8 arc_index, u32 policer_index)
{
  u32 *from, *to_next, n_left_from, n_left_to_next, next_index;
  u64 time_in_policer_periods;
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm = &fm->feature_config_mains[arc_index];

  time_in_policer_periods =
    clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;

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

	  vnet_get_config_data (&cm->config_main,
				&b0->current_config_index, &next0, 0);
	  vnet_get_config_data (&cm->config_main,
				&b1->current_config_index, &next1, 0);

	  act0 = vnet_policer_police (vm, b0,
				      policer_index,
				      time_in_policer_periods,
				      POLICE_CONFORM);
	  act1 = vnet_policer_police (vm, b1,
				      policer_index,
				      time_in_policer_periods,
				      POLICE_CONFORM);

	  if (PREDICT_FALSE (act0 == SSE2_QOS_ACTION_DROP))
	    {
	      next0 = IP_PUNT_POLICER_NEXT_DROP;
	      b0->error = node->errors[IP_PUNT_POLICER_ERROR_DROP];
	    }
	  if (PREDICT_FALSE (act1 == SSE2_QOS_ACTION_DROP))
	    {
	      next1 = IP_PUNT_POLICER_NEXT_DROP;
	      b1->error = node->errors[IP_PUNT_POLICER_ERROR_DROP];
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ip_punt_policer_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next = next0;
	      t->policer_index = policer_index;
	    }
	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ip_punt_policer_trace_t *t =
		vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->next = next1;
	      t->policer_index = policer_index;
	    }
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next,
					   bi0, bi1, next0, next1);
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

	  vnet_get_config_data (&cm->config_main,
				&b0->current_config_index, &next0, 0);

	  act0 = vnet_policer_police (vm, b0,
				      policer_index,
				      time_in_policer_periods,
				      POLICE_CONFORM);
	  if (PREDICT_FALSE (act0 == SSE2_QOS_ACTION_DROP))
	    {
	      next0 = IP_PUNT_POLICER_NEXT_DROP;
	      b0->error = node->errors[IP_PUNT_POLICER_ERROR_DROP];
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ip_punt_policer_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next = next0;
	      t->policer_index = policer_index;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/**
 * IP4 punt redirect per-rx interface configuration
 *   redirect punted traffic to another location.
 */
typedef struct ip_punt_redirect_rx_t_
{
  /**
   * Node linkage into the FIB graph
   */
  fib_node_t node;

  fib_protocol_t fproto;
  fib_forward_chain_type_t payload_type;
  fib_node_index_t pl;
  u32 sibling;

  /**
   * redirect forwarding
   */
  dpo_id_t dpo;
} ip_punt_redirect_rx_t;

/**
 * IP punt redirect configuration
 */
typedef struct ip_punt_redirect_t_
{
  ip_punt_redirect_rx_t *pool;

  /**
   * per-RX interface configuration.
   *  sw_if_index = 0 (from which packets are never received) is used to
   *  indicate 'from-any'
   */
  index_t *redirect_by_rx_sw_if_index[FIB_PROTOCOL_IP_MAX];
} ip_punt_redirect_cfg_t;

extern ip_punt_redirect_cfg_t ip_punt_redirect_cfg;

/**
 * IP punt redirect next nodes
 */
typedef enum ip_punt_redirect_next_t_
{
  IP_PUNT_REDIRECT_NEXT_DROP,
  IP_PUNT_REDIRECT_NEXT_TX,
  IP_PUNT_REDIRECT_NEXT_ARP,
  IP_PUNT_REDIRECT_N_NEXT,
} ip_punt_redirect_next_t;

/**
 * IP Punt redirect trace
 */
typedef struct ip4_punt_redirect_trace_t_
{
  index_t rrxi;
  u32 next;
} ip_punt_redirect_trace_t;

/**
 * Add a punt redirect entry
 */
extern void ip_punt_redirect_add (fib_protocol_t fproto,
				  u32 rx_sw_if_index,
				  fib_forward_chain_type_t ct,
				  fib_route_path_t * rpaths);

extern void ip_punt_redirect_del (fib_protocol_t fproto, u32 rx_sw_if_index);
extern index_t ip_punt_redirect_find (fib_protocol_t fproto,
				      u32 rx_sw_if_index);
extern u8 *format_ip_punt_redirect (u8 * s, va_list * args);

extern u8 *format_ip_punt_redirect_trace (u8 * s, va_list * args);

typedef walk_rc_t (*ip_punt_redirect_walk_cb_t) (u32 rx_sw_if_index,
						 const ip_punt_redirect_rx_t *
						 redirect, void *arg);
extern void ip_punt_redirect_walk (fib_protocol_t fproto,
				   ip_punt_redirect_walk_cb_t cb, void *ctx);

static_always_inline ip_punt_redirect_rx_t *
ip_punt_redirect_get (index_t rrxi)
{
  return (pool_elt_at_index (ip_punt_redirect_cfg.pool, rrxi));
}

always_inline uword
ip_punt_redirect (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame, u8 arc_index, fib_protocol_t fproto)
{
  u32 *from, *to_next, n_left_from, n_left_to_next, next_index;
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm = &fm->feature_config_mains[arc_index];
  index_t *redirects;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  redirects = ip_punt_redirect_cfg.redirect_by_rx_sw_if_index[fproto];

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 rx_sw_if_index0, rrxi0;
	  ip_punt_redirect_rx_t *rrx0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 bi0;

	  rrxi0 = INDEX_INVALID;
	  next0 = 0;
	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  vnet_get_config_data (&cm->config_main,
				&b0->current_config_index, &next0, 0);

	  rx_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  /*
	   * If config exists for this particular RX interface use it,
	   * else use the default (at RX = 0)
	   */
	  if (vec_len (redirects) > rx_sw_if_index0)
	    {
	      rrxi0 = redirects[rx_sw_if_index0];
	      if (INDEX_INVALID == rrxi0)
		rrxi0 = redirects[0];
	    }
	  else if (vec_len (redirects) >= 1)
	    rrxi0 = redirects[0];

	  if (PREDICT_TRUE (INDEX_INVALID != rrxi0))
	    {
	      rrx0 = ip_punt_redirect_get (rrxi0);
	      vnet_buffer (b0)->ip.adj_index = rrx0->dpo.dpoi_index;
	      next0 = rrx0->dpo.dpoi_next_node;
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ip_punt_redirect_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next = next0;
	      t->rrxi = rrxi0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

always_inline uword
ip_drop_or_punt (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * frame, u8 arc_index)
{
  u32 *from, *to_next, n_left_from, n_left_to_next, next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
	  vlib_buffer_t *b0, *b1, *b2, *b3;
	  u32 next0, next1, next2, next3;
	  u32 bi0, bi1, bi2, bi3;

	  next0 = next1 = next2 = next3 = 0;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p4, *p5, *p6, *p7;

	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);
	    p6 = vlib_get_buffer (vm, from[6]);
	    p7 = vlib_get_buffer (vm, from[7]);

	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);
	    vlib_prefetch_buffer_header (p6, LOAD);
	    vlib_prefetch_buffer_header (p7, LOAD);
	  }

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];
	  bi2 = to_next[2] = from[2];
	  bi3 = to_next[3] = from[3];

	  from += 4;
	  n_left_from -= 4;
	  to_next += 4;
	  n_left_to_next -= 4;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  /* punt and drop features are not associated with a given interface
	   * so the special index 0 is used */
	  vnet_feature_arc_start (arc_index, 0, &next0, b0);
	  vnet_feature_arc_start (arc_index, 0, &next1, b1);
	  vnet_feature_arc_start (arc_index, 0, &next2, b2);
	  vnet_feature_arc_start (arc_index, 0, &next3, b3);

	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 bi0;

	  next0 = 0;
	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  vnet_feature_arc_start (arc_index, 0, &next0, b0);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
