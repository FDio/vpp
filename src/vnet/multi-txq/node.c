/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/multi-txq/multi_txq.h>
#include <vnet/interface/tx_queue_funcs.h>

#include <vppinfra/crc32.h>
#include <vppinfra/error.h>

#define foreach_multi_txq_func_log                                            \
  _ (QUEUE_0, "multi txq queue 0")                                            \
  _ (QUEUE_1, "multi txq queue 1")                                            \
  _ (QUEUE_2, "multi txq queue 2")                                            \
  _ (QUEUE_3, "multi txq queue 3")                                            \
  _ (QUEUE_4, "multi txq queue 4")                                            \
  _ (QUEUE_5, "multi txq queue 5")                                            \
  _ (QUEUE_6, "multi txq queue 6")                                            \
  _ (QUEUE_7, "multi txq queue 7")

typedef enum
{
#define _(f, s) MULTI_TXQ_LOG_##f,
  foreach_multi_txq_func_log
#undef _
    MULTI_TXQ_LOG_QUEUE_N,
} multi_txq_func_log_t;

static char *multi_txq_func_log_strings[] = {
#define _(n, s) s,
  foreach_multi_txq_func_log
#undef _
};

static multi_txq_func_log_t
multi_txq_get_log_index (u32 txq_index)
{
  switch (txq_index)
    {
    case 0:
      return MULTI_TXQ_LOG_QUEUE_0;
    case 1:
      return MULTI_TXQ_LOG_QUEUE_1;
    case 2:
      return MULTI_TXQ_LOG_QUEUE_2;
    case 3:
      return MULTI_TXQ_LOG_QUEUE_3;
    case 4:
      return MULTI_TXQ_LOG_QUEUE_4;
    case 5:
      return MULTI_TXQ_LOG_QUEUE_5;
    case 6:
      return MULTI_TXQ_LOG_QUEUE_6;
    case 7:
      return MULTI_TXQ_LOG_QUEUE_7;
    default:
      return MULTI_TXQ_LOG_QUEUE_N;
    }

  return MULTI_TXQ_LOG_QUEUE_N;
}

typedef struct
{
  u32 sw_if_index;
  u32 buffer_index;
  u32 thread_index;
  u32 num_txqs_per_thread;
  u32 txq_index;
} vnet_multi_txq_trace_t;

static u8 *
format_multi_txq_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_multi_txq_trace_t *t = va_arg (*args, vnet_multi_txq_trace_t *);

  s =
    format (s,
	    "%U buffer-index 0x%x thread-index 0x%x "
	    "number-of-txqs/thread %u txq-index %u",
	    format_vnet_sw_if_index_name, vnm, t->sw_if_index, t->buffer_index,
	    t->thread_index, t->num_txqs_per_thread, t->txq_index);

  return s;
}

static_always_inline void
multi_txq_get_txq_index_inline (vlib_main_t *vm, vlib_buffer_t *b0,
				u32 node_index, u32 num_txqs, u32 *txq_index)
{
  multi_txq_key_t key = { 0 };
  u16 ethertype = 0, l2hdr_sz = 0, l4_hdr_offset = 0;
  u8 l4_proto = 0;

  key.sw_if_index[VLIB_RX] = vnet_buffer (b0)->sw_if_index[VLIB_RX];
  key.sw_if_index[VLIB_TX] = vnet_buffer (b0)->sw_if_index[VLIB_TX];

  ethernet_header_t *eh = (ethernet_header_t *) vlib_buffer_get_current (b0);
  ethertype = clib_net_to_host_u16 (eh->type);
  l2hdr_sz = sizeof (ethernet_header_t);

  if (ethernet_frame_is_tagged (ethertype))
    {
      ethernet_vlan_header_t *vlan = (ethernet_vlan_header_t *) (eh + 1);

      ethertype = clib_net_to_host_u16 (vlan->type);
      l2hdr_sz += sizeof (*vlan);
      if (ethertype == ETHERNET_TYPE_VLAN)
	{
	  vlan++;
	  ethertype = clib_net_to_host_u16 (vlan->type);
	  l2hdr_sz += sizeof (*vlan);
	}
    }

  if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP4))
    {
      ip4_header_t *ip4 =
	(ip4_header_t *) (vlib_buffer_get_current (b0) + l2hdr_sz);
      l4_hdr_offset = l2hdr_sz + ip4_header_bytes (ip4);
      l4_proto = ip4->protocol;
      ip46_address_set_ip4 (&key.src_address, &ip4->src_address);
      ip46_address_set_ip4 (&key.dst_address, &ip4->dst_address);
    }
  else if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP6))
    {
      ip6_header_t *ip6 =
	(ip6_header_t *) (vlib_buffer_get_current (b0) + l2hdr_sz);
      l4_hdr_offset = l2hdr_sz + sizeof (ip6_header_t);
      /* FIXME IPv6 EH traversal */
      l4_proto = ip6->protocol;
      ip46_address_set_ip6 (&key.src_address, &ip6->src_address);
      ip46_address_set_ip6 (&key.dst_address, &ip6->dst_address);
    }
  if (l4_proto == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp =
	(tcp_header_t *) (vlib_buffer_get_current (b0) + l4_hdr_offset);
      key.src_port = tcp->src_port;
      key.dst_port = tcp->dst_port;
    }
  else if (l4_proto == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp =
	(udp_header_t *) (vlib_buffer_get_current (b0) + l4_hdr_offset);
      key.src_port = udp->src_port;
      key.dst_port = udp->dst_port;
    }

  *txq_index = clib_crc32c (key.as_u8, sizeof (key)) % num_txqs;
  vlib_error_count (vm, node_index, multi_txq_get_log_index (*txq_index), 1);
}

static_always_inline uword
multi_txq_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame)
{
  u32 n_left_from, *from, **to_next = 0;
  vnet_main_t *vnm = vnet_get_main ();
  u32 last_sw_if_index = ~0;
  vlib_frame_t **to_frames = 0;
  vnet_hw_interface_t *hw = 0;
  u32 thread_index = vm->thread_index;
  u32 log_node_index = node->node_index;
  u32 next_index = vlib_get_node_by_name (vm, (u8 *) "interface-tx")->index;
  u32 i = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 sw_if_index0;

      u32 next0 = 0;
      u32 txq_index = 0;
      u32 num_txqs = 0;

      bi0 = from[0];
      from++;
      n_left_from--;

      b0 = vlib_get_buffer (vm, bi0);
      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];

      if (PREDICT_FALSE ((last_sw_if_index != sw_if_index0) || to_frames == 0))
	{
	  if (to_frames)
	    {
	      hw = vnet_get_sup_hw_interface (vnm, last_sw_if_index);
	      vec_foreach_index (i, to_frames)
		{
		  if (to_frames[i]->n_vectors > 0)
		    vlib_put_frame_to_node (vm, next_index, to_frames[i]);
		  else
		    vlib_frame_free (vm,
				     vlib_node_get_runtime (vm, next_index),
				     to_frames[i]);
		}
	      vec_free (to_frames);
	      vec_free (to_next);
	    }

	  num_txqs =
	    *(u32 *) vnet_feature_next_with_data (&next0, b0, sizeof (u32));
	  vec_validate (to_frames, num_txqs);
	  vec_validate (to_next, num_txqs);

	  last_sw_if_index = sw_if_index0;
	  hw = vnet_get_sup_hw_interface (vnm, sw_if_index0);
	  vec_foreach_index (i, to_frames)
	    {
	      to_frames[i] = vlib_get_frame_to_node (vm, next_index);
	      to_next[i] = vlib_frame_vector_args (to_frames[i]);
	    }
	}

      if (num_txqs)
	{
	  multi_txq_get_txq_index_inline (vm, b0, log_node_index, num_txqs,
					  &txq_index);
	  if (to_frames[txq_index]->scalar_size)
	    {
	      *(u32 *) vlib_frame_scalar_args (to_frames[txq_index]) =
		txq_index;
	      to_frames[txq_index]->flags = VNET_HW_TXQ_INDEX_SET;
	    }
	}

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  vnet_multi_txq_trace_t *t;
	  t = vlib_add_trace (vm, node, b0, sizeof (t[0]));
	  t->buffer_index = bi0;
	  t->sw_if_index = sw_if_index0;
	  t->thread_index = thread_index;
	  t->num_txqs_per_thread = num_txqs;
	  t->txq_index = txq_index;
	}

      to_next[txq_index][0] = bi0;
      to_next[txq_index]++;
      to_frames[txq_index]->n_vectors++;
    }

  vec_foreach_index (i, to_frames)
    {
      if (to_frames[i]->n_vectors > 0)
	vlib_put_frame_to_node (vm, next_index, to_frames[i]);
      else
	vlib_frame_free (vm, vlib_node_get_runtime (vm, next_index),
			 to_frames[i]);
    }
  vec_free (to_frames);
  vec_free (to_next);

  return frame->n_vectors;
}

VLIB_NODE_FN (multi_txq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return multi_txq_node_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (multi_txq_node) = {
  .vector_size = sizeof (u32),
  .format_trace = format_multi_txq_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = MULTI_TXQ_LOG_QUEUE_N,
  .error_strings = multi_txq_func_log_strings,
  .n_next_nodes = 0,
  .name = "multi-txq",
};

VNET_FEATURE_INIT (multi_txq_node, static) = {
  .arc_name = "interface-output",
  .node_name = "multi-txq",
  .runs_after = VNET_FEATURES ("stats-collect-tx", "ipsec-if-output",
			       "span-output"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
