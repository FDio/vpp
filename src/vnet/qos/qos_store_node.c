/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/qos/qos_store.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6_to_ip4.h>
#include <vnet/feature/feature.h>
#include <vnet/qos/qos_types.h>

extern u8 *qos_store_configs[QOS_N_SOURCES];

/**
 * per-packet trace data
 */
typedef struct qos_store_trace_t_
{
  /* per-pkt trace data */
  qos_bits_t bits;
} qos_store_trace_t;

/* packet trace format function */
static u8 *
format_qos_store_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  qos_store_trace_t *t = va_arg (*args, qos_store_trace_t *);

  s = format (s, "qos:%d", t->bits);

  return s;
}

static inline uword
qos_store_inline (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame, qos_source_t qos_src)
{
  u32 n_left_from, *from, *to_next, next_index;

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 next0, bi0;
	  qos_bits_t qos0;

	  next0 = 0;
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  qos0 =
	    *(qos_bits_t *) vnet_feature_next_with_data (&next0, b0,
							 sizeof (qos_bits_t));

	  vnet_buffer2 (b0)->qos.bits = qos0;
	  vnet_buffer2 (b0)->qos.source = qos_src;
	  b0->flags |= VNET_BUFFER_F_QOS_DATA_VALID;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      qos_store_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->bits = qos0;
	    }


	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}


VLIB_NODE_FN (ip4_qos_store_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return (qos_store_inline (vm, node, frame, QOS_SOURCE_IP));
}

VLIB_NODE_FN (ip6_qos_store_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return (qos_store_inline (vm, node, frame, QOS_SOURCE_IP));
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_qos_store_node) = {
  .name = "ip4-qos-store",
  .vector_size = sizeof (u32),
  .format_trace = format_qos_store_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "ip4-drop",
  },
};

VNET_FEATURE_INIT (ip4_qos_store_node, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "ip4-qos-store",
};
VNET_FEATURE_INIT (ip4m_qos_store_node, static) = {
    .arc_name = "ip4-multicast",
    .node_name = "ip4-qos-store",
};

VLIB_REGISTER_NODE (ip6_qos_store_node) = {
  .name = "ip6-qos-store",
  .vector_size = sizeof (u32),
  .format_trace = format_qos_store_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "ip6-drop",
  },
};

VNET_FEATURE_INIT (ip6_qos_store_node, static) = {
    .arc_name = "ip6-unicast",
    .node_name = "ip6-qos-store",
};
VNET_FEATURE_INIT (ip6m_qos_store_node, static) = {
    .arc_name = "ip6-multicast",
    .node_name = "ip6-qos-store",
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
