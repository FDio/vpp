/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <stdint.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/classify/policer_classify.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>

#include <policer/internal.h>
#include <policer/ip_punt.h>
#include <policer/policer_node.h>
#include <policer/police_inlines.h>

/* Dispatch functions meant to be instantiated elsewhere */

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u32 policer_index;
} vnet_policer_trace_t;

/* packet trace format function */
static u8 *
format_policer_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vnet_policer_trace_t *t = va_arg (*args, vnet_policer_trace_t *);

  s = format (s, "VNET_POLICER: sw_if_index %d policer_index %d next %d", t->sw_if_index,
	      t->policer_index, t->next_index);
  return s;
}

#define foreach_vnet_policer_error                                                                 \
  _ (TRANSMIT, "Packets Transmitted")                                                              \
  _ (DROP, "Packets Dropped")

typedef enum
{
#define _(sym, str) VNET_POLICER_ERROR_##sym,
  foreach_vnet_policer_error
#undef _
    VNET_POLICER_N_ERROR,
} vnet_policer_error_t;

static char *vnet_policer_error_strings[] = {
#define _(sym, string) string,
  foreach_vnet_policer_error
#undef _
};

#ifndef CLIB_MARCH_VARIANT
u8 *
format_policer_handoff_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  policer_handoff_trace_t *t = va_arg (*args, policer_handoff_trace_t *);

  s = format (s, "policer %d, handoff thread %d to %d", t->policer_index, t->current_worker_index,
	      t->next_worker_index);

  return s;
}
#endif

static inline uword
policer_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
		     vlib_dir_t dir, u8 is_l2)
{
  u32 n_left_from, *from, *to_next;
  policer_next_t next_index;
  policer_main_t *pm = &policer_main;
  u64 time_in_policer_periods;
  u32 transmitted = 0;

  time_in_policer_periods = clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  u32 sw_if_index0, sw_if_index1;
	  u32 pi0 = 0, pi1 = 0;
	  u8 act0, act1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *b2, *b3;

	    b2 = vlib_get_buffer (vm, from[2]);
	    b3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (b2, LOAD);
	    vlib_prefetch_buffer_header (b3, LOAD);
	  }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[dir];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[dir];

	  pi0 = pm->policer_index_by_sw_if_index[dir][sw_if_index0];
	  pi1 = pm->policer_index_by_sw_if_index[dir][sw_if_index1];

	  u16 l2_overhead0 = (is_l2) ? 0 : pm->l2_overhead_by_sw_if_index[dir][sw_if_index0];
	  u16 l2_overhead1 = (is_l2) ? 0 : pm->l2_overhead_by_sw_if_index[dir][sw_if_index1];

	  act0 = policer_police (vm, b0, pi0, time_in_policer_periods, POLICE_CONFORM, true,
				 l2_overhead0);

	  act1 = policer_police (vm, b1, pi1, time_in_policer_periods, POLICE_CONFORM, true,
				 l2_overhead1);

	  if (PREDICT_FALSE (act0 == QOS_ACTION_HANDOFF))
	    {
	      next0 = VNET_POLICER_NEXT_HANDOFF;
	      vnet_buffer (b0)->policer.index = pi0;
	    }
	  else if (PREDICT_FALSE (act0 == QOS_ACTION_DROP))
	    {
	      next0 = VNET_POLICER_NEXT_DROP;
	      b0->error = node->errors[VNET_POLICER_ERROR_DROP];
	    }
	  else /* transmit or mark-and-transmit action */
	    {
	      transmitted++;
	      if (is_l2)
		{
		  if (dir == VLIB_RX)
		    {
		      next0 =
			vnet_l2_feature_next (b0, pm->l2_input_feat_next, L2INPUT_FEAT_POLICER);
		    }
		  else
		    {
		      next0 =
			vnet_l2_feature_next (b0, pm->l2_output_feat_next, L2OUTPUT_FEAT_POLICER);
		    }
		}
	      else
		{
		  vnet_feature_next (&next0, b0);
		}
	    }

	  if (PREDICT_FALSE (act1 == QOS_ACTION_HANDOFF))
	    {
	      next1 = VNET_POLICER_NEXT_HANDOFF;
	      vnet_buffer (b1)->policer.index = pi1;
	    }
	  else if (PREDICT_FALSE (act1 == QOS_ACTION_DROP)) /* drop action */
	    {
	      next1 = VNET_POLICER_NEXT_DROP;
	      b1->error = node->errors[VNET_POLICER_ERROR_DROP];
	    }
	  else /* transmit or mark-and-transmit action */
	    {
	      transmitted++;
	      if (is_l2)
		{
		  if (dir == VLIB_RX)
		    {
		      next1 =
			vnet_l2_feature_next (b1, pm->l2_input_feat_next, L2INPUT_FEAT_POLICER);
		    }
		  else
		    {
		      next1 =
			vnet_l2_feature_next (b1, pm->l2_output_feat_next, L2OUTPUT_FEAT_POLICER);
		    }
		}
	      else
		{
		  vnet_feature_next (&next1, b1);
		}
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  vnet_policer_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->sw_if_index = sw_if_index0;
		  t->next_index = next0;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  vnet_policer_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->sw_if_index = sw_if_index1;
		  t->next_index = next1;
		}
	    }

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next, n_left_to_next, bi0, bi1,
					   next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 sw_if_index0;
	  u32 pi0 = 0;
	  u8 act0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[dir];
	  pi0 = pm->policer_index_by_sw_if_index[dir][sw_if_index0];

	  u16 l2_overhead0 = (is_l2) ? 0 : pm->l2_overhead_by_sw_if_index[dir][sw_if_index0];

	  act0 = policer_police (vm, b0, pi0, time_in_policer_periods, POLICE_CONFORM, true,
				 l2_overhead0);

	  if (PREDICT_FALSE (act0 == QOS_ACTION_HANDOFF))
	    {
	      next0 = VNET_POLICER_NEXT_HANDOFF;
	      vnet_buffer (b0)->policer.index = pi0;
	    }
	  else if (PREDICT_FALSE (act0 == QOS_ACTION_DROP))
	    {
	      next0 = VNET_POLICER_NEXT_DROP;
	      b0->error = node->errors[VNET_POLICER_ERROR_DROP];
	    }
	  else /* transmit or mark-and-transmit action */
	    {
	      transmitted++;
	      if (is_l2)
		{
		  if (dir == VLIB_RX)
		    {
		      next0 =
			vnet_l2_feature_next (b0, pm->l2_input_feat_next, L2INPUT_FEAT_POLICER);
		    }
		  else
		    {
		      next0 =
			vnet_l2_feature_next (b0, pm->l2_output_feat_next, L2OUTPUT_FEAT_POLICER);
		    }
		}
	      else
		{
		  vnet_feature_next (&next0, b0);
		}
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      vnet_policer_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      t->policer_index = pi0;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0,
					   next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index, VNET_POLICER_ERROR_TRANSMIT, transmitted);
  return frame->n_vectors;
}

VLIB_NODE_FN (policer_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return policer_node_inline (vm, node, frame, VLIB_RX, 0);
}

VLIB_REGISTER_NODE (policer_input_node) = {
  .name = "policer-input",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(vnet_policer_error_strings),
  .error_strings = vnet_policer_error_strings,
  .n_next_nodes = VNET_POLICER_N_NEXT,
  .next_nodes = {
		 [VNET_POLICER_NEXT_DROP] = "error-drop",
		 [VNET_POLICER_NEXT_HANDOFF] = "policer-input-handoff",
		 },
};

VLIB_NODE_FN (policer_l2_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return policer_node_inline (vm, node, frame, VLIB_RX, 1);
}

VLIB_REGISTER_NODE (policer_l2_input_node) = {
  .name = "l2-policer-input",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(vnet_policer_error_strings),
  .error_strings = vnet_policer_error_strings,
  .n_next_nodes = VNET_POLICER_N_NEXT,
  .next_nodes = {
		 [VNET_POLICER_NEXT_DROP] = "error-drop",
		 [VNET_POLICER_NEXT_HANDOFF] = "policer-input-handoff",
		 },
};

/* Register on IP unicast arcs for L3 routed sub-interfaces */
VNET_FEATURE_INIT (policer_ip4_unicast, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "policer-input",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

VNET_FEATURE_INIT (policer_ip6_unicast, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "policer-input",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};

VLIB_NODE_FN (policer_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return policer_node_inline (vm, node, frame, VLIB_TX, 0);
}

VLIB_REGISTER_NODE (policer_output_node) = {
  .name = "policer-output",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(vnet_policer_error_strings),
  .error_strings = vnet_policer_error_strings,
  .n_next_nodes = VNET_POLICER_N_NEXT,
  .next_nodes = {
		 [VNET_POLICER_NEXT_DROP] = "error-drop",
		 [VNET_POLICER_NEXT_HANDOFF] = "policer-output-handoff",
		 },
};

VLIB_NODE_FN (policer_l2_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return policer_node_inline (vm, node, frame, VLIB_TX, 1);
}

VLIB_REGISTER_NODE (policer_l2_output_node) = {
  .name = "l2-policer-output",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(vnet_policer_error_strings),
  .error_strings = vnet_policer_error_strings,
  .n_next_nodes = VNET_POLICER_N_NEXT,
  .next_nodes = {
		 [VNET_POLICER_NEXT_DROP] = "error-drop",
		 [VNET_POLICER_NEXT_HANDOFF] = "policer-output-handoff",
		 },
};

VNET_FEATURE_INIT (policer_ip4_output, static) = {
  .arc_name = "ip4-output",
  .node_name = "policer-output",
};

VNET_FEATURE_INIT (policer_ip6_output, static) = {
  .arc_name = "ip6-output",
  .node_name = "policer-output",
};

static char *policer_input_handoff_error_strings[] = { "congestion drop" };

VLIB_NODE_FN (policer_input_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return policer_handoff (vm, node, frame, policer_main.fq_index[VLIB_RX], ~0);
}

VLIB_REGISTER_NODE (policer_input_handoff_node) = {
  .name = "policer-input-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(policer_input_handoff_error_strings),
  .error_strings = policer_input_handoff_error_strings,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FN (policer_output_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return policer_handoff (vm, node, frame, policer_main.fq_index[VLIB_TX], ~0);
}

VLIB_REGISTER_NODE (policer_output_handoff_node) = {
  .name = "policer-output-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(policer_input_handoff_error_strings),
  .error_strings = policer_input_handoff_error_strings,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 table_index;
  u32 offset;
  u32 policer_index;
} policer_classify_trace_t;

static u8 *
format_policer_classify_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  policer_classify_trace_t *t = va_arg (*args, policer_classify_trace_t *);

  s = format (s,
	      "POLICER_CLASSIFY: sw_if_index %d next %d table %d offset %d"
	      " policer_index %d",
	      t->sw_if_index, t->next_index, t->table_index, t->offset, t->policer_index);
  return s;
}

#define foreach_policer_classify_error                                                             \
  _ (MISS, "Policer classify misses")                                                              \
  _ (HIT, "Policer classify hits")                                                                 \
  _ (CHAIN_HIT, "Policer classify hits after chain walk")                                          \
  _ (DROP, "Policer classify action drop")

typedef enum
{
#define _(sym, str) POLICER_CLASSIFY_ERROR_##sym,
  foreach_policer_classify_error
#undef _
    POLICER_CLASSIFY_N_ERROR,
} policer_classify_error_t;

static char *policer_classify_error_strings[] = {
#define _(sym, string) string,
  foreach_policer_classify_error
#undef _
};

static inline uword
policer_classify_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
			 policer_classify_table_id_t tid)
{
  u32 n_left_from, *from, *to_next;
  policer_classify_next_index_t next_index;
  policer_classify_main_t *pcm = &policer_classify_main;
  vnet_classify_main_t *vcm = pcm->vnet_classify_main;
  f64 now = vlib_time_now (vm);
  u32 hits = 0;
  u32 misses = 0;
  u32 chain_hits = 0;
  u32 n_next_nodes;
  u64 time_in_policer_periods;

  time_in_policer_periods = clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;

  n_next_nodes = node->n_next_nodes;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  /* First pass: compute hashes */
  while (n_left_from > 2)
    {
      vlib_buffer_t *b0, *b1;
      u32 bi0, bi1;
      u8 *h0, *h1;
      u32 sw_if_index0, sw_if_index1;
      u32 table_index0, table_index1;
      vnet_classify_table_t *t0, *t1;

      /* Prefetch next iteration */
      {
	vlib_buffer_t *p1, *p2;

	p1 = vlib_get_buffer (vm, from[1]);
	p2 = vlib_get_buffer (vm, from[2]);

	vlib_prefetch_buffer_header (p1, STORE);
	clib_prefetch_store (p1->data);
	vlib_prefetch_buffer_header (p2, STORE);
	clib_prefetch_store (p2->data);
      }

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);
      h0 = b0->data;

      bi1 = from[1];
      b1 = vlib_get_buffer (vm, bi1);
      h1 = b1->data;

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      table_index0 = pcm->classify_table_index_by_sw_if_index[tid][sw_if_index0];

      sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
      table_index1 = pcm->classify_table_index_by_sw_if_index[tid][sw_if_index1];

      t0 = pool_elt_at_index (vcm->tables, table_index0);

      t1 = pool_elt_at_index (vcm->tables, table_index1);

      vnet_buffer (b0)->l2_classify.hash = vnet_classify_hash_packet (t0, (u8 *) h0);

      vnet_classify_prefetch_bucket (t0, vnet_buffer (b0)->l2_classify.hash);

      vnet_buffer (b1)->l2_classify.hash = vnet_classify_hash_packet (t1, (u8 *) h1);

      vnet_classify_prefetch_bucket (t1, vnet_buffer (b1)->l2_classify.hash);

      vnet_buffer (b0)->l2_classify.table_index = table_index0;

      vnet_buffer (b1)->l2_classify.table_index = table_index1;

      from += 2;
      n_left_from -= 2;
    }

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0;
      u32 bi0;
      u8 *h0;
      u32 sw_if_index0;
      u32 table_index0;
      vnet_classify_table_t *t0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);
      h0 = b0->data;

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      table_index0 = pcm->classify_table_index_by_sw_if_index[tid][sw_if_index0];

      t0 = pool_elt_at_index (vcm->tables, table_index0);
      vnet_buffer (b0)->l2_classify.hash = vnet_classify_hash_packet (t0, (u8 *) h0);

      vnet_buffer (b0)->l2_classify.table_index = table_index0;
      vnet_classify_prefetch_bucket (t0, vnet_buffer (b0)->l2_classify.hash);

      from++;
      n_left_from--;
    }

  next_index = node->cached_next_index;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Not enough load/store slots to dual loop... */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = POLICER_CLASSIFY_NEXT_INDEX_DROP;
	  u32 table_index0;
	  vnet_classify_table_t *t0;
	  vnet_classify_entry_t *e0;
	  u32 hash0;
	  u8 *h0;
	  u8 act0;

	  /* Stride 3 seems to work best */
	  if (PREDICT_TRUE (n_left_from > 3))
	    {
	      vlib_buffer_t *p1 = vlib_get_buffer (vm, from[3]);
	      vnet_classify_table_t *tp1;
	      u32 table_index1;
	      u32 phash1;

	      table_index1 = vnet_buffer (p1)->l2_classify.table_index;

	      if (PREDICT_TRUE (table_index1 != ~0))
		{
		  tp1 = pool_elt_at_index (vcm->tables, table_index1);
		  phash1 = vnet_buffer (p1)->l2_classify.hash;
		  vnet_classify_prefetch_entry (tp1, phash1);
		}
	    }

	  /* Speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  h0 = b0->data;
	  table_index0 = vnet_buffer (b0)->l2_classify.table_index;
	  e0 = 0;
	  t0 = 0;

	  if (tid == POLICER_CLASSIFY_TABLE_L2)
	    {
	      /* Feature bitmap update and determine the next node */
	      next0 =
		vnet_l2_feature_next (b0, pcm->feat_next_node_index, L2INPUT_FEAT_POLICER_CLAS);
	    }
	  else
	    vnet_get_config_data (pcm->vnet_config_main[tid], &b0->current_config_index, &next0,
				  /* # bytes of config data */ 0);

	  vnet_buffer (b0)->l2_classify.opaque_index = ~0;

	  if (PREDICT_TRUE (table_index0 != ~0))
	    {
	      hash0 = vnet_buffer (b0)->l2_classify.hash;
	      t0 = pool_elt_at_index (vcm->tables, table_index0);
	      e0 = vnet_classify_find_entry (t0, (u8 *) h0, hash0, now);

	      if (e0)
		{
		  act0 = policer_police (vm, b0, e0->next_index, time_in_policer_periods,
					 e0->opaque_index, false, 0);
		  if (PREDICT_FALSE (act0 == QOS_ACTION_DROP))
		    {
		      next0 = POLICER_CLASSIFY_NEXT_INDEX_DROP;
		      b0->error = node->errors[POLICER_CLASSIFY_ERROR_DROP];
		    }
		  hits++;
		}
	      else
		{
		  while (1)
		    {
		      if (PREDICT_TRUE (t0->next_table_index != ~0))
			{
			  t0 = pool_elt_at_index (vcm->tables, t0->next_table_index);
			}
		      else
			{
			  next0 =
			    (t0->miss_next_index < n_next_nodes) ? t0->miss_next_index : next0;
			  misses++;
			  break;
			}

		      hash0 = vnet_classify_hash_packet (t0, (u8 *) h0);
		      e0 = vnet_classify_find_entry (t0, (u8 *) h0, hash0, now);
		      if (e0)
			{
			  act0 = policer_police (vm, b0, e0->next_index, time_in_policer_periods,
						 e0->opaque_index, false, 0);
			  if (PREDICT_FALSE (act0 == QOS_ACTION_DROP))
			    {
			      next0 = POLICER_CLASSIFY_NEXT_INDEX_DROP;
			      b0->error = node->errors[POLICER_CLASSIFY_ERROR_DROP];
			    }
			  hits++;
			  chain_hits++;
			  break;
			}
		    }
		}
	    }
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      policer_classify_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	      t->table_index = t0 ? t0 - vcm->tables : ~0;
	      t->offset = (e0 && t0) ? vnet_classify_get_offset (t0, e0) : ~0;
	      t->policer_index = e0 ? e0->next_index : ~0;
	    }

	  /* Verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0,
					   next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index, POLICER_CLASSIFY_ERROR_MISS, misses);
  vlib_node_increment_counter (vm, node->node_index, POLICER_CLASSIFY_ERROR_HIT, hits);
  vlib_node_increment_counter (vm, node->node_index, POLICER_CLASSIFY_ERROR_CHAIN_HIT, chain_hits);

  return frame->n_vectors;
}

VLIB_NODE_FN (ip4_policer_classify_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return policer_classify_inline (vm, node, frame, POLICER_CLASSIFY_TABLE_IP4);
}

VLIB_REGISTER_NODE (ip4_policer_classify_node) = {
  .name = "ip4-policer-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_classify_trace,
  .n_errors = ARRAY_LEN(policer_classify_error_strings),
  .error_strings = policer_classify_error_strings,
  .n_next_nodes = POLICER_CLASSIFY_NEXT_INDEX_N_NEXT,
  .next_nodes = {
    [POLICER_CLASSIFY_NEXT_INDEX_DROP] = "error-drop",
  },
};

VLIB_NODE_FN (ip6_policer_classify_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return policer_classify_inline (vm, node, frame, POLICER_CLASSIFY_TABLE_IP6);
}

VLIB_REGISTER_NODE (ip6_policer_classify_node) = {
  .name = "ip6-policer-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_classify_trace,
  .n_errors = ARRAY_LEN(policer_classify_error_strings),
  .error_strings = policer_classify_error_strings,
  .n_next_nodes = POLICER_CLASSIFY_NEXT_INDEX_N_NEXT,
  .next_nodes = {
    [POLICER_CLASSIFY_NEXT_INDEX_DROP] = "error-drop",
  },
};

VLIB_NODE_FN (l2_policer_classify_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return policer_classify_inline (vm, node, frame, POLICER_CLASSIFY_TABLE_L2);
}

VLIB_REGISTER_NODE (l2_policer_classify_node) = {
  .name = "l2-policer-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_classify_trace,
  .n_errors = ARRAY_LEN (policer_classify_error_strings),
  .error_strings = policer_classify_error_strings,
  .n_next_nodes = POLICER_CLASSIFY_NEXT_INDEX_N_NEXT,
  .next_nodes = {
    [POLICER_CLASSIFY_NEXT_INDEX_DROP] = "error-drop",
  },
};

#ifndef CLIB_MARCH_VARIANT
static clib_error_t *
policer_classify_init (vlib_main_t *vm)
{
  policer_classify_main_t *pcm = &policer_classify_main;

  pcm->vlib_main = vm;
  pcm->vnet_main = vnet_get_main ();
  pcm->vnet_classify_main = &vnet_classify_main;

  /* Initialize L2 feature next-node indexes */
  feat_bitmap_init_next_nodes (vm, l2_policer_classify_node.index, L2INPUT_N_FEAT,
			       l2input_get_feat_names (), pcm->feat_next_node_index);

  return 0;
}

VLIB_INIT_FUNCTION (policer_classify_init) = {
  .runs_after = VLIB_INITS ("in_out_acl_init"),
};
#endif /* CLIB_MARCH_VARIANT */
