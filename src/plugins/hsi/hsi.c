/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <hsi/hsi.h>

char *hsi_error_strings[] = {
#define hsi_error(n, s) s,
#include <hsi/hsi_error.def>
#undef hsi_error
};

typedef enum hsi_input_next_
{
  HSI_INPUT_NEXT_IP_LOOKUP,
  HSI_INPUT_NEXT_TCP_INPUT,
  HSI_INPUT_NEXT_UDP_INPUT,
  HSI_INPUT_N_NEXT
} hsi_input_next_t;

#define foreach_hsi4_input_next                 	\
  _ (IP_LOOKUP, "ip4-lookup")                     	\
  _ (UDP_INPUT, "udp4-input")           		\
  _ (TCP_INPUT, "tcp4-input-nolookup")    		\

#define foreach_hsi6_input_next                 	\
  _ (IP_LOOKUP, "ip6-lookup")                     	\
  _ (UDP_INPUT, "udp6-input")           		\
  _ (TCP_INPUT, "tcp6-input-nolookup")    		\

static u8 *
format_hsi_trace (u8 *s, va_list *args)
{
  return 0;
}

always_inline void
hsi_lookup_next4 (vlib_buffer_t *b, u32 *next)
{
  transport_connection_t *tc;
  udp_header_t *hdr;
  ip4_header_t *ip4;
  session_t *s;
  u8 result;

  ip4 = (ip4_header_t*) vlib_buffer_get_current (b);
  hdr = ip4_next_header (ip4);

  switch (ip4->protocol)
    {
    case IP_PROTOCOL_TCP:
      tc = session_lookup_connection_wt4 (vnet_buffer (b)->ip.fib_index,
	                                  &ip4->dst_address, &ip4->src_address,
	                                  hdr->dst_port, hdr->src_port,
	                                  TRANSPORT_PROTO_TCP,
	                                  vlib_get_thread_index (), &result);
      if (tc && !result)
	{
	  vnet_buffer (b)->tcp.connection_index = tc->c_index;
	  *next = HSI_INPUT_NEXT_TCP_INPUT;
	}
      break;
    case IP_PROTOCOL_UDP:
      s = session_lookup_safe4 (vnet_buffer (b)->ip.fib_index,
	                        &ip4->dst_address, &ip4->src_address,
	                        hdr->dst_port, hdr->src_port,
	                        TRANSPORT_PROTO_UDP);
      if (s)
	{
	  *next = HSI_INPUT_NEXT_UDP_INPUT;
	  session_pool_remove_peeker (s->thread_index);
	}
      break;
    default:
      vnet_feature_next (next, b);
      break;
    }
}

always_inline void
hsi_lookup_next6 (vlib_buffer_t *b, u32 *next)
{
  transport_connection_t *tc;
  udp_header_t *hdr;
  ip6_header_t *ip6;
  session_t *s;
  u8 result;

  ip6 = (ip6_header_t*) vlib_buffer_get_current (b);
  hdr = ip6_next_header (ip6);

  switch (ip6->protocol)
    {
    case IP_PROTOCOL_TCP:
      tc = session_lookup_connection_wt6 (vnet_buffer (b)->ip.fib_index,
	                                  &ip6->dst_address, &ip6->src_address,
	                                  hdr->dst_port, hdr->src_port,
	                                  TRANSPORT_PROTO_TCP,
	                                  vlib_get_thread_index (), &result);
      if (tc && !result)
	{
	  vnet_buffer (b)->tcp.connection_index = tc->c_index;
	  *next = HSI_INPUT_NEXT_TCP_INPUT;
	}
      break;
    case IP_PROTOCOL_UDP:
      s = session_lookup_safe6 (vnet_buffer (b)->ip.fib_index,
	                        &ip6->dst_address, &ip6->src_address,
	                        hdr->dst_port, hdr->src_port,
	                        TRANSPORT_PROTO_UDP);
      if (s)
	{
	  *next = HSI_INPUT_NEXT_UDP_INPUT;
	  session_pool_remove_peeker (s->thread_index);
	}
      break;
    default:
      vnet_feature_next (next, b);
      break;
    }
}

always_inline void
hsi_lookup_next (vlib_buffer_t *b, u32 *next, u8 is_ip4)
{
  if (is_ip4)
    hsi_lookup_next4 (b, next);
  else
    hsi_lookup_next6 (b, next);
}

always_inline uword
hsi46_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, int is_ip4)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left_from, *from;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from)
    {
      u32 next0;

      hsi_lookup_next (b[0], &next0, is_ip4);

      next[0] = next0;

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (hsi4_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return hsi46_input_inline (vm, node, frame, 1 /* is_ip4 */);
}

VLIB_REGISTER_NODE (hsi4_input_node) = {
  .name = "hsi-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_hsi_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = HSI_N_ERROR,
  .error_strings = hsi_error_strings,
  .n_next_nodes = HSI_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [HSI_INPUT_NEXT_##s] = n,
      foreach_hsi4_input_next
#undef _
  },
};

VNET_FEATURE_INIT (hsi_ip4_feature, static) = {
  .arc_name = "ip4-output",
  .node_name = "hsi-ip4",
  .runs_before = VNET_FEATURES ("interface-output"),
};

VLIB_NODE_FN (hsi6_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return hsi46_input_inline (vm, node, frame, 0 /* is_ip4 */);
}

VLIB_REGISTER_NODE (hsi6_input_node) = {
  .name = "hsi-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_hsi_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = HSI_N_ERROR,
  .error_strings = hsi_error_strings,
  .n_next_nodes = HSI_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [HSI_INPUT_NEXT_##s] = n,
      foreach_hsi6_input_next
#undef _
  },
};

VNET_FEATURE_INIT (hsi_ip6_feature, static) = {
  .arc_name = "ip6-output",
  .node_name = "hsi-ip6",
  .runs_before = VNET_FEATURES ("interface-output"),
};

static clib_error_t *
hsi_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (hsi_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Host Stack Intercept (HSI)",
  .default_disabled = 0,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
