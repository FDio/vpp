/*
 * Copyright (c) 2023 Cisco and/or its affiliates.
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
#include <vnet/feature/feature.h>
#include <vppinfra/error.h>

static u8 *
format_tracing_feature_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  s = format (s, "TRACING");
  return s;
}

static_always_inline u32
filtering_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		  vlib_frame_t *frame, int is_pcap)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 *from = vlib_frame_vector_args (frame);
  const u32 n_tot = frame->n_vectors;
  u32 n_left = n_tot;
  __clib_unused u32 n_traced = 0;

  vlib_get_buffers (vm, from, b, n_tot);

  while (n_left > 0)
    {
      /* enqueue b0 to the current next frame */
      vnet_feature_next_u16 (next, b[0]);

      /* buffer already traced */
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	goto skip;

      if (is_pcap)
	{
	  /* TODO */
	}
      else
	{
	  n_traced +=
	    vlib_trace_buffer (vm, node, next[0], b[0], 1 /* follow_chain */);
	}

    skip:
      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_tot);
  return n_tot;
}

VLIB_NODE_FN (trace_filtering_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return filtering_inline (vm, node, frame, 0 /* is_pcap */);
}

VLIB_NODE_FN (pcap_filtering_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return filtering_inline (vm, node, frame, 1 /* is_pcap */);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (trace_filtering_node) = {
  .name = "trace-filtering",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_tracing_feature_trace,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (pcap_filtering_node) = {
  .name = "pcap-filtering",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_tracing_feature_trace,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_FEATURE_INIT (trace_filtering4, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "trace-filtering",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
  .runs_after = VNET_FEATURES ("ip4-full-reassembly-feature"),
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_FEATURE_INIT (trace_filtering6, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "trace-filtering",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
  .runs_after = VNET_FEATURES ("ip6-full-reassembly-feature"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
