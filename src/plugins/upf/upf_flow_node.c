/*
 * Copyright (c) 2016 Qosmos and/or its affiliates.
 * Copyright (c) 2018 Travelping GmbH
 *
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

#include <vppinfra/dlist.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vnet/ip/ip4_packet.h>

#include "upf.h"
#include "upf_pfcp.h"
#include "flowtable.h"
#include "flowtable_tcp.h"

#if CLIB_DEBUG > 1
#define flow_debug clib_warning
#else
#define flow_debug(...)				\
  do { } while (0)
#endif

typedef struct
{
  u32 session_index;
  u64 cp_seid;
  flow_key_t key;
  u32 flow_idx;
  u32 sw_if_index;
  u32 next_index;
  u8 packet_data[64 - 1 * sizeof (u32)];
}
flow_trace_t;

static u8 *
format_get_flowinfo (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  flow_trace_t *t = va_arg (*args, flow_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s,
	      "upf_session%d cp-seid 0x%016llx\n"
	      "%UFlowInfo - sw_if_index %d, next_index = %d\n%U%U\n%U%U\n%U%U",
	      t->session_index, t->cp_seid,
	      format_white_space, indent,
	      t->sw_if_index, t->next_index,
	      format_white_space, indent,
	      format_flow_key, &t->key,
	      format_white_space, indent,
	      format_hex_bytes, &t->key, sizeof (t->key),
	      format_white_space, indent,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

static_always_inline u32
flow_pdr_idx (flow_entry_t * flow, flow_direction_t direction,
	      struct rules *r)
{
  upf_pdr_t *pdr = pfcp_get_pdr_by_id (r, flow_pdr_id (flow, direction));
  return pdr - r->pdr;
}

always_inline u32
load_gtpu_flow_info (flowtable_main_t * fm, vlib_buffer_t * b,
		     flow_entry_t * flow, struct rules *r, uword is_reverse)
{
  flow_direction_t direction =
    flow->is_reverse == is_reverse ? FT_ORIGIN : FT_REVERSE;

  upf_buffer_opaque (b)->gtpu.is_reverse = is_reverse;
  upf_buffer_opaque (b)->gtpu.flow_id = flow - fm->flows;
  upf_buffer_opaque (b)->gtpu.pdr_idx = flow_pdr_idx (flow, direction, r);

  return flow_next (flow, direction);
}

#define FLOW_DEBUG(fm, flow)						\
  flow_debug (#flow ": %p (%u): %U\n",					\
	      (flow), (flow) - (fm)->flows,				\
	      format_flow_key, &(flow)->key);

static uword
upf_flow_process (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * frame, u8 is_ip4)
{
  upf_main_t *gtm = &upf_main;
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  flowtable_main_t *fm = &flowtable_main;
  u32 cpu_index = os_get_thread_index ();
  flowtable_main_per_cpu_t *fmt = &fm->per_cpu[cpu_index];

#define _(sym, str) u32 CPT_ ## sym = 0;
  foreach_flowtable_error
#undef _
    from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u32 current_time =
    (u32) ((u64) fm->vlib_main->cpu_time_last_node_dispatch /
	   fm->vlib_main->clib_time.clocks_per_second);
  timer_wheel_index_update (fm, fmt, current_time);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Dual loop */
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  upf_session_t *sx0, *sx1;
	  struct rules *active0, *active1;
	  u32 next0, next1;
	  BVT (clib_bihash_kv) kv0, kv1;
	  int created0, created1;
	  uword is_reverse0, is_reverse1;
	  u32 flow_idx0, flow_idx1;
	  flow_entry_t *flow0, *flow1;

	  /* prefetch next iteration */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);
	    CLIB_PREFETCH (p2->data,
			   sizeof (gtpu_header_t) + sizeof (ip6_header_t),
			   LOAD);
	    CLIB_PREFETCH (p3->data,
			   sizeof (gtpu_header_t) + sizeof (ip6_header_t),
			   LOAD);
	  }

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];
	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  created0 = created1 = 0;
	  is_reverse0 = is_reverse1 = 0;

	  if (PREDICT_FALSE
	      (pool_is_free_index
	       (gtm->sessions, upf_buffer_opaque (b0)->gtpu.session_index)
	       || pool_is_free_index (gtm->sessions,
				      upf_buffer_opaque (b1)->
				      gtpu.session_index)))
	    {
	      /*
	       * break out of the dual loop and let the
	       * single loop handle the problem
	       */

	      /* TODO: it is not clear how this can happen, but it DOES!
	       *
	       * The session removed with vlib_worker_thread_barrier_sync beeing held.
	       * According to the vpp-dev ML, that should stop workers at he top the
	       * dispatch chain and SHOULD therefor prevent packets entering the chain
	       * with now invalid things.
	       * Clearly, if we hit here, a packet with an invalid session_index HAS
	       * entered the chain or the session was removed in the middle of the chain.
	       * The later is the most likely case and that would mean that somehow
	       * we are not using the sync correctly.
	       *
	       * This needs to be investigated in depth. For the moment do the simple
	       * thing a drop the packet.
	       */
	      break;
	    }

	  sx0 =
	    pool_elt_at_index (gtm->sessions,
			       upf_buffer_opaque (b0)->gtpu.session_index);
	  sx1 =
	    pool_elt_at_index (gtm->sessions,
			       upf_buffer_opaque (b1)->gtpu.session_index);

	  active0 = pfcp_get_rules (sx0, PFCP_ACTIVE);
	  active1 = pfcp_get_rules (sx1, PFCP_ACTIVE);

	  flow_mk_key (sx0->cp_seid, b0,
		       upf_buffer_opaque (b0)->gtpu.data_offset, is_ip4,
		       &is_reverse0, &kv0);
	  flow_mk_key (sx1->cp_seid, b1,
		       upf_buffer_opaque (b1)->gtpu.data_offset, is_ip4,
		       &is_reverse1, &kv1);

	  /* lookup/create flow */
	  flow_idx0 =
	    flowtable_entry_lookup_create (fm, fmt, &kv0, current_time,
					   is_reverse0, &created0);
	  flow_idx1 =
	    flowtable_entry_lookup_create (fm, fmt, &kv1, current_time,
					   is_reverse1, &created1);

	  if (PREDICT_FALSE (~0 == flow_idx0 || ~0 == flow_idx1))
	    {
	      /*
	       * break out of the dual loop and let the
	       * single loop handle the problem
	       */
	      break;
	    }

	  flow0 = flowtable_get_flow (fm, flow_idx0);
	  flow1 = flowtable_get_flow (fm, flow_idx1);

	  flow0->session_index = upf_buffer_opaque (b0)->gtpu.session_index;
	  flow1->session_index = upf_buffer_opaque (b1)->gtpu.session_index;

	  FLOW_DEBUG (fm, flow0);
	  FLOW_DEBUG (fm, flow1);

	  /* timer management */
	  flow_update_lifetime (flow0, b0, is_ip4);
	  flow_update_lifetime (flow1, b1, is_ip4);

	  flow_update_active (flow0, current_time);
	  flow_update_active (flow1, current_time);

	  /* flow statistics */
	  flow0->stats[is_reverse0].pkts++;
	  flow0->stats[is_reverse0].bytes += b0->current_length;
	  flow1->stats[is_reverse1].pkts++;
	  flow1->stats[is_reverse1].bytes += b1->current_length;

	  /* fill buffer with flow data */
	  next0 = load_gtpu_flow_info (fm, b0, flow0, active0, is_reverse0);
	  next1 = load_gtpu_flow_info (fm, b1, flow1, active1, is_reverse1);

	  /* flowtable counters */
	  CPT_THRU += 2;
	  CPT_CREATED += created0 + created1;
	  CPT_HIT += !created0 + !created1;

	  /* frame mgmt */
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      u32 sidx = upf_buffer_opaque (b0)->gtpu.session_index;
	      upf_session_t *sess = pool_elt_at_index (gtm->sessions, sidx);
	      flow_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->session_index = sidx;
	      t->cp_seid = sess->cp_seid;
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	      clib_memcpy (t->packet_data, vlib_buffer_get_current (b0) +
			   upf_buffer_opaque (b0)->gtpu.data_offset,
			   sizeof (t->packet_data));
	    }
	  if (b1->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      u32 sidx = upf_buffer_opaque (b1)->gtpu.session_index;
	      upf_session_t *sess = pool_elt_at_index (gtm->sessions, sidx);
	      flow_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->session_index = sidx;
	      t->cp_seid = sess->cp_seid;
	      t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	      t->next_index = next1;
	      clib_memcpy (t->packet_data, vlib_buffer_get_current (b1) +
			   upf_buffer_opaque (b1)->gtpu.data_offset,
			   sizeof (t->packet_data));
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      /* Single loop */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  u32 next0;
	  vlib_buffer_t *b0;
	  upf_session_t *sx0;
	  struct rules *active0;
	  int created = 0;
	  u32 flow_idx;
	  flow_entry_t *flow = NULL;
	  uword is_reverse = 0;
	  BVT (clib_bihash_kv) kv;

	  bi0 = to_next[0] = from[0];
	  b0 = vlib_get_buffer (vm, bi0);

	  if (PREDICT_FALSE
	      (pool_is_free_index
	       (gtm->sessions, upf_buffer_opaque (b0)->gtpu.session_index)))
	    {
	      /*
	       * break out of the dual loop and let the
	       * single loop handle the problem
	       */

	      /* TODO: see comment in dual loop */

	      CPT_UNHANDLED++;
	      next0 = FT_NEXT_DROP;

	      goto stats1;
	    }

	  sx0 =
	    pool_elt_at_index (gtm->sessions,
			       upf_buffer_opaque (b0)->gtpu.session_index);

	  active0 = pfcp_get_rules (sx0, PFCP_ACTIVE);

	  /* lookup/create flow */
	  flow_mk_key (sx0->cp_seid, b0,
		       upf_buffer_opaque (b0)->gtpu.data_offset, is_ip4,
		       &is_reverse, &kv);
	  flow_idx =
	    flowtable_entry_lookup_create (fm, fmt, &kv, current_time,
					   is_reverse, &created);

	  if (PREDICT_FALSE (~0 == flow_idx))
	    {
	      CPT_UNHANDLED++;
	      next0 = FT_NEXT_DROP;

	      goto stats1;
	    }

	  flow = flowtable_get_flow (fm, flow_idx);
	  flow->session_index = upf_buffer_opaque (b0)->gtpu.session_index;
	  FLOW_DEBUG (fm, flow);

	  upf_debug ("is_rev: %u, flow: %u, c: %u", is_reverse,
		     flow->is_reverse, created);

	  /* timer management */
	  flow_update_lifetime (flow, b0, is_ip4);
	  flow_update_active (flow, current_time);

	  /* flow statistics */
	  flow->stats[is_reverse].pkts++;
	  flow->stats[is_reverse].bytes += b0->current_length;

	  /* fill opaque buffer with flow data */
	  next0 = load_gtpu_flow_info (fm, b0, flow, active0, is_reverse);
	  upf_debug ("flow next: %u, origin: %u, reverse: %u",
		     next0, flow_next (flow, FT_ORIGIN), flow_next (flow,
								    FT_REVERSE));

	  /* flowtable counters */
	  CPT_THRU++;
	  CPT_CREATED += created;
	  CPT_HIT += !created;

	stats1:
	  /* frame mgmt */
	  from++;
	  to_next++;
	  n_left_from--;
	  n_left_to_next--;

	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      u32 sidx = upf_buffer_opaque (b0)->gtpu.session_index;
	      upf_session_t *sess = pool_elt_at_index (gtm->sessions, sidx);
	      flow_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->session_index = sidx;
	      t->cp_seid = sess->cp_seid;
	      memcpy (&t->key, &kv.key, sizeof (t->key));
	      t->flow_idx = flow - fm->flows;
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	      clib_memcpy (t->packet_data, vlib_buffer_get_current (b0) +
			   upf_buffer_opaque (b0)->gtpu.data_offset,
			   sizeof (t->packet_data));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* handle expirations */
  CPT_TIMER_EXPIRE += flowtable_timer_expire (fm, fmt, current_time);

#define _(sym, str)							\
  vlib_node_increment_counter(vm, node->node_index,			\
			      FLOWTABLE_ERROR_ ## sym, CPT_ ## sym);
  foreach_flowtable_error
#undef _
    return frame->n_vectors;
}

VLIB_NODE_FN (upf_ip4_flow_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return upf_flow_process (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_flow_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return upf_flow_process (vm, node, from_frame, /* is_ip4 */ 0);
}

static char *flowtable_error_strings[] = {
#define _(sym, string) string,
  foreach_flowtable_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(upf_ip4_flow_node) = {
  .name = "upf-ip4-flow-process",
  .vector_size = sizeof(u32),
  .format_trace = format_get_flowinfo,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = FLOWTABLE_N_ERROR,
  .error_strings = flowtable_error_strings,
  .n_next_nodes = FT_NEXT_N_NEXT,
  .next_nodes = {
    [FT_NEXT_DROP] = "error-drop",
    [FT_NEXT_CLASSIFY] = "upf-ip4-classify",
    [FT_NEXT_PROCESS] = "upf-ip4-input",
    [FT_NEXT_PROXY]   = "upf-ip4-proxy-input",
  }
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(upf_ip6_flow_node) = {
  .name = "upf-ip6-flow-process",
  .vector_size = sizeof(u32),
  .format_trace = format_get_flowinfo,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = FLOWTABLE_N_ERROR,
  .error_strings = flowtable_error_strings,
  .n_next_nodes = FT_NEXT_N_NEXT,
  .next_nodes = {
    [FT_NEXT_DROP] = "error-drop",
    [FT_NEXT_CLASSIFY] = "upf-ip6-classify",
    [FT_NEXT_PROCESS] = "upf-ip6-input",
    [FT_NEXT_PROXY]   = "upf-ip6-proxy-input",
  }
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
