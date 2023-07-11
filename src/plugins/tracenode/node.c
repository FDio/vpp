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
#include <vnet/feature/feature.h>
#include <vnet/classify/pcap_classify.h>

typedef struct
{
  u32 sw_if_index;
} tracenode_trace_t;

static u8 *
format_tracenode_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vnet_main_t *vnm = vnet_get_main ();
  tracenode_trace_t *t = va_arg (*args, tracenode_trace_t *);

  s = format (s, "Packet traced from interface %U added",
	      format_vnet_sw_if_index_name, vnm, t->sw_if_index);
  return s;
}

static_always_inline u32
tracenode_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		  vlib_frame_t *frame, int is_pcap)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_pcap_t *pp = &vnm->pcap;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 *from = vlib_frame_vector_args (frame), *from0 = from;
  const u32 n_tot = frame->n_vectors;
  u32 n_left = n_tot;
  u8 is_traced;
  __clib_unused u32 n_traced = 0;

  vlib_get_buffers (vm, from, b, n_tot);

  while (n_left > 0)
    {
      /* TODO: dual/quad loop */

      /* enqueue b0 to the current next frame */
      vnet_feature_next_u16 (next, b[0]);
      is_traced = 0;

      /* buffer already traced */
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	goto skip;

      if (is_pcap && (is_traced = vnet_is_packet_pcaped (pp, b[0], ~0)))
	{
	  pcap_add_buffer (&pp->pcap_main, vm, from0[0],
			   pp->max_bytes_per_pkt);
	}
      else if (!is_pcap && (is_traced = vlib_trace_buffer (
			      vm, node, next[0], b[0], 1 /* follow_chain */)))
	{
	  tracenode_trace_t *tr = vlib_add_trace (vm, node, b[0], sizeof *tr);
	  tr->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	}
      n_traced += is_traced;

    skip:
      b++;
      from0++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_tot);
  return n_tot;
}

VLIB_NODE_FN (trace_filtering_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return tracenode_inline (vm, node, frame, 0 /* is_pcap */);
}

VLIB_NODE_FN (pcap_filtering_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return tracenode_inline (vm, node, frame, 1 /* is_pcap */);
}

VLIB_REGISTER_NODE (trace_filtering_node) = {
  .name = "trace-filtering",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_tracenode_trace,
};

VLIB_REGISTER_NODE (pcap_filtering_node) = {
  .name = "pcap-filtering",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_tracenode_trace,
};

VNET_FEATURE_INIT (trace_filtering4, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "trace-filtering",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
  .runs_after = VNET_FEATURES ("ip4-full-reassembly-feature"),
};

VNET_FEATURE_INIT (trace_filtering6, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "trace-filtering",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
  .runs_after = VNET_FEATURES ("ip6-full-reassembly-feature"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
