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

#include <vppinfra/crc32.h>
#include <vppinfra/error.h>

typedef struct
{
  u32 buffer_index;
  u32 sw_if_index;
  u32 txq_index;
  u8 is_ip4;
  u8 is_ip6;
} vnet_multi_txq_trace_t;

static u8 *
format_multi_txq_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_multi_txq_trace_t *t = va_arg (*args, vnet_multi_txq_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%U %U buffer-index 0x%x txq-index %u :",
	      format_white_space, indent,
	      format_vnet_sw_if_index_name, vnm, t->sw_if_index,
	      t->buffer_index, t->txq_index);
  if (t->is_ip4)
    s = format (s, " ip4");
  else if (t->is_ip6)
    s = format (s, " ip6");

  return s;
}

static_always_inline void
multi_txq_get_txq_index_inline (vlib_buffer_t * b0, u32 num_txqs,
				u32 * txq_index, u8 * is_ip4, u8 * is_ip6)
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
      *is_ip4 = 1;
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
      *is_ip6 = 1;
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
}

static_always_inline uword
multi_txq_node_inline (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_frame_t *f =
	vlib_get_next_frame_internal (vm, node, next_index, 0);
      u32 n = f->n_vectors;
      to_next = vlib_frame_vector_args (f) + n * sizeof (to_next[0]);
      u32 n_left_to_next = VLIB_FRAME_SIZE - n;
      //f->flags = MULTI_TXQ_INDEX_SET;
      //u32 *txq_index = vlib_frame_scalar_args (f);
      u32 txq_index;
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = 0;
	  u32 *num_txqs;
	  u8 is_ip4 = 0, is_ip6 = 0;

	  /* speculatively enqueue b0 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next += 1;
	  n_left_to_next -= 1;
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  num_txqs = vnet_feature_next_with_data (&next0, b0, sizeof (u32));
	  if (num_txqs)
	    multi_txq_get_txq_index_inline (b0, *num_txqs, &txq_index,
					    &is_ip4, &is_ip6);

	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      vnet_multi_txq_trace_t *t;
	      t = vlib_add_trace (vm, node, b0, sizeof (t[0]));
	      t->buffer_index = bi0;
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      t->txq_index = txq_index;

	      t->is_ip4 = is_ip4;
	      t->is_ip6 = is_ip6;
	    }

	  // vnet_feature_next (&next0, b0);
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (multi_txq_node) (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  return multi_txq_node_inline (vm, node, frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (multi_txq_node) = {
  .vector_size = sizeof (u32),
  .format_trace = format_multi_txq_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = 0,
  .name = "multi-txq",
};

VNET_FEATURE_INIT (multi_txq_node, static) = {
  .arc_name = "interface-output",
  .node_name = "multi-txq",
  .runs_before = VNET_FEATURES ("interface-tx"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
