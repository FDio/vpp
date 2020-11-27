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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <srv6-am/am.h>


/******************************* Packet tracing *******************************/

typedef struct
{
  u32 localsid_index;
} srv6_am_localsid_trace_t;

typedef struct
{
  ip6_address_t src, dst;
} srv6_am_rewrite_trace_t;

static u8 *
format_srv6_am_localsid_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_am_localsid_trace_t *t = va_arg (*args, srv6_am_localsid_trace_t *);

  return format (s, "SRv6-AM-localsid: localsid_index %d", t->localsid_index);
}

static u8 *
format_srv6_am_rewrite_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_am_rewrite_trace_t *t = va_arg (*args, srv6_am_rewrite_trace_t *);

  return format (s, "SRv6-AM-rewrite: src %U dst %U",
		 format_ip6_address, &t->src, format_ip6_address, &t->dst);
}


/***************************** Node registration ******************************/

vlib_node_registration_t srv6_am_rewrite_node;


/****************************** Packet counters *******************************/

#define foreach_srv6_am_rewrite_counter \
_(PROCESSED, "srv6-am rewritten packets") \
_(NO_SRH, "(Error) No SRH.")

typedef enum
{
#define _(sym,str) SRV6_AM_REWRITE_COUNTER_##sym,
  foreach_srv6_am_rewrite_counter
#undef _
    SRV6_AM_REWRITE_N_COUNTERS,
} srv6_am_rewrite_counters;

static char *srv6_am_rewrite_counter_strings[] = {
#define _(sym,string) string,
  foreach_srv6_am_rewrite_counter
#undef _
};


/********************************* Next nodes *********************************/

typedef enum
{
  SRV6_AM_LOCALSID_NEXT_ERROR,
  SRV6_AM_LOCALSID_NEXT_REWRITE,
  SRV6_AM_LOCALSID_N_NEXT,
} srv6_am_localsid_next_t;

typedef enum
{
  SRV6_AM_REWRITE_NEXT_ERROR,
  SRV6_AM_REWRITE_NEXT_LOOKUP,
  SRV6_AM_REWRITE_N_NEXT,
} srv6_am_rewrite_next_t;


/******************************* Local SID node *******************************/

/**
 * @brief SRv6 masquerading.
 */
static_always_inline void
end_am_processing (vlib_buffer_t * b0,
		   ip6_header_t * ip0,
		   ip6_sr_header_t * sr0,
		   ip6_sr_localsid_t * ls0, u32 * next0)
{
  ip6_address_t *new_dst0;

  if (PREDICT_FALSE (ip0->protocol != IP_PROTOCOL_IPV6_ROUTE ||
		     sr0->type != ROUTING_HEADER_TYPE_SR))
    {
      *next0 = SRV6_AM_LOCALSID_NEXT_ERROR;
      return;
    }

  if (PREDICT_FALSE (sr0->segments_left == 0))
    {
      *next0 = SRV6_AM_LOCALSID_NEXT_ERROR;
      return;
    }

  /* Decrement Segments Left */
  sr0->segments_left -= 1;

  /* Set Destination Address to Last Segment (index 0) */
  new_dst0 = (ip6_address_t *) (sr0->segments);
  ip0->dst_address.as_u64[0] = new_dst0->as_u64[0];
  ip0->dst_address.as_u64[1] = new_dst0->as_u64[1];

  /* Set Xconnect adjacency to VNF */
  vnet_buffer (b0)->ip.adj_index = ls0->nh_adj;
}

/**
 * @brief Graph node for applying SRv6 masquerading.
 */
static uword
srv6_am_localsid_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ip6_sr_main_t *sm = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;
  u32 cnt_packets = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u32 thread_index = vm->thread_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* TODO: Dual/quad loop */

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0;
	  ip6_sr_header_t *sr0;
	  ip6_sr_localsid_t *ls0;
	  u32 next0 = SRV6_AM_LOCALSID_NEXT_REWRITE;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);
	  sr0 = (ip6_sr_header_t *) (ip0 + 1);

	  /* Lookup the SR End behavior based on IP DA (adj) */
	  ls0 = pool_elt_at_index (sm->localsids,
				   vnet_buffer (b0)->ip.adj_index);

	  /* SRH processing */
	  end_am_processing (b0, ip0, sr0, ls0, &next0);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srv6_am_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof *tr);
	      tr->localsid_index = ls0 - sm->localsids;
	    }

	  /* This increments the SRv6 per LocalSID counters. */
	  vlib_increment_combined_counter (((next0 ==
					     SRV6_AM_LOCALSID_NEXT_ERROR) ?
					    &(sm->sr_ls_invalid_counters) :
					    &(sm->sr_ls_valid_counters)),
					   thread_index, ls0 - sm->localsids,
					   1, vlib_buffer_length_in_chain (vm,
									   b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  cnt_packets++;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (srv6_am_localsid_node) = {
  .function = srv6_am_localsid_fn,
  .name = "srv6-am-localsid",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_am_localsid_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = SRV6_AM_LOCALSID_N_NEXT,
  .next_nodes = {
    [SRV6_AM_LOCALSID_NEXT_REWRITE] = "ip6-rewrite",
    [SRV6_AM_LOCALSID_NEXT_ERROR] = "error-drop",
  },
};
/* *INDENT-ON* */


/******************************* Rewriting node *******************************/

/**
 * @brief SRv6 de-masquerading.
 */
static_always_inline void
end_am_rewriting (vlib_node_runtime_t * node,
		  vlib_buffer_t * b0,
		  ip6_header_t * ip0, ip6_sr_header_t * sr0, u32 * next0)
{
  if (PREDICT_FALSE (ip0->protocol != IP_PROTOCOL_IPV6_ROUTE ||
		     sr0->type != ROUTING_HEADER_TYPE_SR))
    {
      b0->error = node->errors[SRV6_AM_REWRITE_COUNTER_NO_SRH];
      *next0 = SRV6_AM_REWRITE_NEXT_ERROR;
      return;
    }

  /* Restore Destination Address to active segment (index SL) */
  if (sr0->segments_left != 0)
    {
      ip6_address_t *new_dst0;
      new_dst0 = (ip6_address_t *) (sr0->segments) + sr0->segments_left;
      ip0->dst_address.as_u64[0] = new_dst0->as_u64[0];
      ip0->dst_address.as_u64[1] = new_dst0->as_u64[1];
    }
}

/**
 * @brief Graph node for applying SRv6 de-masquerading.
 */
static uword
srv6_am_rewrite_fn (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  u32 cnt_packets = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* TODO: Dual/quad loop */

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0;
	  ip6_sr_header_t *sr0;
	  u32 next0 = SRV6_AM_REWRITE_NEXT_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);
	  sr0 = (ip6_sr_header_t *) (ip0 + 1);

	  /* SRH processing */
	  end_am_rewriting (node, b0, ip0, sr0, &next0);

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srv6_am_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof *tr);
	      clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				sizeof tr->src.as_u8);
	      clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				sizeof tr->dst.as_u8);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  cnt_packets++;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, srv6_am_rewrite_node.index,
			       SRV6_AM_REWRITE_COUNTER_PROCESSED,
			       cnt_packets);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (srv6_am_rewrite_node) = {
  .function = srv6_am_rewrite_fn,
  .name = "srv6-am-rewrite",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_am_rewrite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SRV6_AM_REWRITE_N_COUNTERS,
  .error_strings = srv6_am_rewrite_counter_strings,
  .n_next_nodes = SRV6_AM_REWRITE_N_NEXT,
  .next_nodes = {
      [SRV6_AM_REWRITE_NEXT_LOOKUP] = "ip6-lookup",
      [SRV6_AM_REWRITE_NEXT_ERROR] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
