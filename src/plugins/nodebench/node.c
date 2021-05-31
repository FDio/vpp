/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <nodebench/nodebench.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u8 feature_arc_index;
} nodebench_trace_t;

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u8 feature_arc_index;
  u16 orig_next;
} nodebench_sink_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *
format_nodebench_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nodebench_trace_t *t = va_arg (*args, nodebench_trace_t *);

  s =
    format (s, "NODEBENCH: sw_if_index %d, next index %d feature_arc_index %d",
	    t->sw_if_index, t->next_index, t->feature_arc_index);
  return s;
}

vlib_node_registration_t nodebench_node;

/* packet trace format function */
static u8 *
format_nodebench_sink_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nodebench_sink_trace_t *t = va_arg (*args, nodebench_sink_trace_t *);

  s =
    format (s,
	    "NODEBENCH-SINK: sw_if_index %d, next index %d feature_arc_index "
	    "%d orig_next %d",
	    t->sw_if_index, t->next_index, t->feature_arc_index, t->orig_next);
  return s;
}

vlib_node_registration_t nodebench_sink_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_nodebench_error _ (SWAPPED, "Mac swap packets processed")

typedef enum
{
#define _(sym, str) NODEBENCH_ERROR_##sym,
  foreach_nodebench_error
#undef _
    NODEBENCH_N_ERROR,
} nodebench_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *nodebench_error_strings[] = {
#define _(sym, string) string,
  foreach_nodebench_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  NODEBENCH_NEXT_DROP,
  NODEBENCH_N_NEXT,
} nodebench_next_t;

#define N_LOOP_PACKETS 4

always_inline uword
nodebench_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		  vlib_frame_t *frame, int is_trace)
{
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  nodebench_main_t *nmp = &nodebench_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;
#ifdef XXX
  while (n_left_from >= N_LOOP_PACKETS)
    {
      u8 i;
      /* Prefetch next iteration. */
      if (PREDICT_TRUE (n_left_from >= 2 * N_LOOP_PACKETS))
	{
	  for (i = 0; i < N_LOOP_PACKETS; i++)
	    vlib_prefetch_buffer_header (b[i + N_LOOP_PACKETS], STORE);
	  for (i = 0; i < N_LOOP_PACKETS; i++)
	    CLIB_PREFETCH (b[i + N_LOOP_PACKETS]->data, CLIB_CACHE_LINE_BYTES,
			   STORE);
	}

      /* $$$$ process 4x pkts right here */
      for (i = 0; i < N_LOOP_PACKETS; i++)
	next[i] = nmp->benched_node_next_index;

      if (is_trace)
	{

	  for (i = 0; i < N_LOOP_PACKETS; i++)
	    if (b[i]->flags & VLIB_BUFFER_IS_TRACED)
	      {
		nodebench_trace_t *t =
		  vlib_add_trace (vm, node, b[i], sizeof (*t));
		t->next_index = next[i];
		t->sw_if_index = vnet_buffer (b[i])->sw_if_index[VLIB_RX];
		t->feature_arc_index = vnet_buffer (b[i])->feature_arc_index;
	      }
	}

      b += N_LOOP_PACKETS;
      next += N_LOOP_PACKETS;
      n_left_from -= N_LOOP_PACKETS;
    }
#endif

  while (n_left_from > 0)
    {
      u16 j;
      u32 next0 = 0;
      u32 current_config_index;
      u32 cfg_index;
      vnet_config_t *cfg;

      vnet_feature_main_t *fm = &feature_main;
      u16 feature_arc = nmp->benched_feature_arc_index;

      vnet_feature_config_main_t *cm = fm->feature_config_mains;
      vnet_config_main_t *vcm = &(cm[feature_arc].config_main);

      u32 sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];

      /* $$$$ process 1 pkt right here */
      vnet_buffer (b[0])->feature_arc_index = nmp->benched_feature_arc_index;

      vnet_feature_arc_start (nmp->benched_feature_arc_index, sw_if_index,
			      &next0, b[0]);

      current_config_index =
	vec_elt (cm[feature_arc].config_index_by_sw_if_index, sw_if_index);
      cfg_index =
	vec_elt (vcm->config_pool_index_by_user_index, current_config_index);
      cfg = pool_elt_at_index (vcm->config_pool, cfg_index);

      for (j = 0; j < vec_len (cfg->features) &&
		  cfg->features[j].node_index != nmp->benched_node_index;
	   j++)
	{
	  clib_warning ("j: %d, node_index: %d", j,
			cfg->features[j].node_index);
	  vnet_feature_next (&next0, b[0]);
	}
      if (j < vec_len (cfg->features))
	{
	  next[0] = nmp->benched_node_next_index;
	}
      else
	{
	  next[0] = 0;
	}
      // next[0] = next0;

      if (is_trace)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      nodebench_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->next_index = next[0];
	      t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	      t->feature_arc_index = vnet_buffer (b[0])->feature_arc_index;
	    }
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

always_inline uword
nodebench_sink_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame, int is_trace)
{
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  // nodebench_main_t *nmp = &nodebench_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;
#ifdef XXX
  while (n_left_from >= N_LOOP_PACKETS)
    {
      u8 i;
      /* Prefetch next iteration. */
      if (PREDICT_TRUE (n_left_from >= 2 * N_LOOP_PACKETS))
	{
	  for (i = 0; i < N_LOOP_PACKETS; i++)
	    vlib_prefetch_buffer_header (b[i + N_LOOP_PACKETS], STORE);
	  for (i = 0; i < N_LOOP_PACKETS; i++)
	    CLIB_PREFETCH (b[i + N_LOOP_PACKETS]->data, CLIB_CACHE_LINE_BYTES,
			   STORE);
	}

      /* $$$$ process 4x pkts right here */
      for (i = 0; i < N_LOOP_PACKETS; i++)
	next[i] = nmp->benched_node_next_index;

      if (is_trace)
	{

	  for (i = 0; i < N_LOOP_PACKETS; i++)
	    if (b[i]->flags & VLIB_BUFFER_IS_TRACED)
	      {
		nodebench_trace_t *t =
		  vlib_add_trace (vm, node, b[i], sizeof (*t));
		t->next_index = next[i];
		t->sw_if_index = vnet_buffer (b[i])->sw_if_index[VLIB_RX];
		t->feature_arc_index = vnet_buffer (b[i])->feature_arc_index;
	      }
	}

      b += N_LOOP_PACKETS;
      next += N_LOOP_PACKETS;
      n_left_from -= N_LOOP_PACKETS;
    }
#endif

  while (n_left_from > 0)
    {
      next[0] = 0;

      if (is_trace)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      nodebench_sink_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->orig_next = *(u32 *) (b[0]->opaque2);
	      t->next_index = next[0];
	      t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	      t->feature_arc_index = vnet_buffer (b[0])->feature_arc_index;
	    }
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (nodebench_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return nodebench_inline (vm, node, frame, 1 /* is_trace */);
  else
    return nodebench_inline (vm, node, frame, 0 /* is_trace */);
}

VLIB_NODE_FN (nodebench_sink_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return nodebench_sink_inline (vm, node, frame, 1 /* is_trace */);
  else
    return nodebench_sink_inline (vm, node, frame, 0 /* is_trace */);
}

#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (nodebench_node) = 
{
  .name = "nodebench",
  .vector_size = sizeof (u32),
  .format_trace = format_nodebench_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(nodebench_error_strings),
  .error_strings = nodebench_error_strings,

  .n_next_nodes = NODEBENCH_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [NODEBENCH_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (nodebench_sink_node) = 
{
  .name = "nodebench-sink",
  .vector_size = sizeof (u32),
  .format_trace = format_nodebench_sink_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(nodebench_error_strings),
  .error_strings = nodebench_error_strings,

  .n_next_nodes = NODEBENCH_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [NODEBENCH_NEXT_DROP] = "error-drop",
  },
};

#endif /* CLIB_MARCH_VARIANT */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
