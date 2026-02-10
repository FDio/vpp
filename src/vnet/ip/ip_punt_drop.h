/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#ifndef __IP_PUNT_DROP_H__
#define __IP_PUNT_DROP_H__

#include <vnet/ip/ip.h>

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
extern void ip_punt_redirect_add (fib_protocol_t fproto, u32 rx_sw_if_index,
				  fib_forward_chain_type_t ct,
				  const fib_route_path_t *rpaths);

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
	      /* prevent ttl decrement on forward */
	      b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	      rrx0 = ip_punt_redirect_get (rrxi0);
	      vnet_buffer (b0)->ip.adj_index[VLIB_TX] = rrx0->dpo.dpoi_index;
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
