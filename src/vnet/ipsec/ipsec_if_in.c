/*
 * ipsec_if_in.c : IPSec interface input node
 *
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

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ipsec_io.h>

/* Statistics (not really errors) */
#define foreach_ipsec_if_input_error				  \
_(RX, "good packets received")					  \
_(DISABLED, "ipsec packets received on disabled interface")       \
_(NO_TUNNEL, "no matching tunnel")

static char *ipsec_if_input_error_strings[] = {
#define _(sym,string) string,
  foreach_ipsec_if_input_error
#undef _
};

typedef enum
{
#define _(sym,str) IPSEC_IF_INPUT_ERROR_##sym,
  foreach_ipsec_if_input_error
#undef _
    IPSEC_IF_INPUT_N_ERROR,
} ipsec_if_input_error_t;


typedef struct
{
  u32 spi;
  u32 seq;
} ipsec_if_input_trace_t;

static u8 *
format_ipsec_if_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsec_if_input_trace_t *t = va_arg (*args, ipsec_if_input_trace_t *);

  s = format (s, "IPSec: spi %u seq %u", t->spi, t->seq);
  return s;
}


always_inline uword
ipsec_if_input_inline (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  ipsec_main_t *im = &ipsec_main;
  vnet_main_t *vnm = im->vnet_main;
  vnet_interface_main_t *vim = &vnm->interface_main;

  int is_trace = node->flags & VLIB_NODE_FLAG_TRACE;
  u32 thread_index = vm->thread_index;

  u32 n_left_from, *from;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  clib_memset_u16 (nexts, im->esp4_decrypt_next_index, n_left_from);

  u64 n_bytes = 0, n_packets = 0;
  u32 n_disabled = 0, n_no_tunnel = 0;

  u32 last_sw_if_index = ~0;
  u32 last_tunnel_id = ~0;
  u64 last_key = ~0;

  vlib_combined_counter_main_t *rx_counter;
  vlib_combined_counter_main_t *drop_counter;

  rx_counter = vim->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX;
  drop_counter = vim->combined_sw_if_counters + VNET_INTERFACE_COUNTER_DROP;

  while (n_left_from >= 2)
    {
      u32 sw_if_index0, sw_if_index1;
      ip4_header_t *ip0, *ip1;
      esp_header_t *esp0, *esp1;
      u32 len0, len1;
      u16 buf_adv0, buf_adv1;
      u32 tid0, tid1;
      ipsec_tunnel_if_t *t0, *t1;
      u64 key0, key1;

      if (n_left_from >= 4)
	{
	  CLIB_PREFETCH (b[2], CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (b[2]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (b[3], CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (b[3]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	}

      ip0 = (ip4_header_t *) (b[0]->data + vnet_buffer (b[0])->l3_hdr_offset);
      ip1 = (ip4_header_t *) (b[1]->data + vnet_buffer (b[1])->l3_hdr_offset);

      /* NAT UDP port 4500 case, don't advance any more */
      if (ip0->protocol == IP_PROTOCOL_UDP)
	{
	  esp0 =
	    (esp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0) +
			      sizeof (udp_header_t));
	  buf_adv0 = 0;
	}
      else
	{
	  esp0 = (esp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
	  buf_adv0 = ip4_header_bytes (ip0);
	}
      if (ip1->protocol == IP_PROTOCOL_UDP)
	{
	  esp1 =
	    (esp_header_t *) ((u8 *) ip1 + ip4_header_bytes (ip1) +
			      sizeof (udp_header_t));
	  buf_adv1 = 0;
	}
      else
	{
	  esp1 = (esp_header_t *) ((u8 *) ip1 + ip4_header_bytes (ip1));
	  buf_adv1 = ip4_header_bytes (ip1);
	}

      vlib_buffer_advance (b[0], buf_adv0);
      vlib_buffer_advance (b[1], buf_adv1);

      len0 = vlib_buffer_length_in_chain (vm, b[0]);
      len1 = vlib_buffer_length_in_chain (vm, b[1]);

      key0 = (u64) ip0->src_address.as_u32 << 32 | (u64) esp0->spi;
      key1 = (u64) ip1->src_address.as_u32 << 32 | (u64) esp1->spi;

      if (key0 == last_key)
	{
	  tid0 = last_tunnel_id;
	}
      else
	{
	  uword *p = hash_get (im->ipsec_if_pool_index_by_key, key0);
	  if (p)
	    {
	      tid0 = p[0];
	      last_tunnel_id = tid0;
	      last_key = key0;
	    }
	  else
	    {
	      n_no_tunnel++;
	      next[0] = IPSEC_INPUT_NEXT_DROP;
	      goto pkt1;
	    }
	}

      t0 = pool_elt_at_index (im->tunnel_interfaces, tid0);
      vnet_buffer (b[0])->ipsec.sad_index = t0->input_sa_index;

      if (PREDICT_TRUE (t0->hw_if_index != ~0))
	{
	  vnet_buffer (b[0])->ipsec.flags = 0;
	  sw_if_index0 = t0->sw_if_index;
	  vnet_buffer (b[0])->sw_if_index[VLIB_RX] = sw_if_index0;

	  if (PREDICT_FALSE (!(t0->flags & VNET_HW_INTERFACE_FLAG_LINK_UP)))
	    {
	      vlib_increment_combined_counter
		(drop_counter, thread_index, sw_if_index0, 1, len0);
	      n_disabled++;
	      next[0] = IPSEC_INPUT_NEXT_DROP;
	      goto pkt1;
	    }

	  if (PREDICT_TRUE (sw_if_index0 == last_sw_if_index))
	    {
	      n_packets++;
	      n_bytes += len0;
	    }
	  else
	    {
	      if (n_packets)
		{
		  vlib_increment_combined_counter
		    (rx_counter, thread_index, last_sw_if_index,
		     n_packets, n_bytes);
		}

	      last_sw_if_index = sw_if_index0;
	      n_packets = 1;
	      n_bytes = len0;
	    }
	}
      else
	{
	  vnet_buffer (b[0])->ipsec.flags = IPSEC_FLAG_IPSEC_GRE_TUNNEL;
	}

    pkt1:
      if (key1 == last_key)
	{
	  tid1 = last_tunnel_id;
	}
      else
	{
	  uword *p = hash_get (im->ipsec_if_pool_index_by_key, key1);
	  if (p)
	    {
	      tid1 = p[0];
	      last_tunnel_id = tid1;
	      last_key = key1;
	    }
	  else
	    {
	      n_no_tunnel++;
	      next[1] = IPSEC_INPUT_NEXT_DROP;
	      goto trace1;
	    }
	}

      t1 = pool_elt_at_index (im->tunnel_interfaces, tid1);
      vnet_buffer (b[1])->ipsec.sad_index = t1->input_sa_index;

      if (PREDICT_TRUE (t1->hw_if_index != ~0))
	{
	  vnet_buffer (b[1])->ipsec.flags = 0;
	  sw_if_index1 = t1->sw_if_index;
	  vnet_buffer (b[1])->sw_if_index[VLIB_RX] = sw_if_index1;

	  if (PREDICT_FALSE (!(t1->flags & VNET_HW_INTERFACE_FLAG_LINK_UP)))
	    {
	      vlib_increment_combined_counter
		(drop_counter, thread_index, sw_if_index1, 1, len1);
	      n_disabled++;
	      next[1] = IPSEC_INPUT_NEXT_DROP;
	      goto trace1;
	    }

	  if (PREDICT_TRUE (sw_if_index1 == last_sw_if_index))
	    {
	      n_packets++;
	      n_bytes += len1;
	    }
	  else
	    {
	      if (n_packets)
		{
		  vlib_increment_combined_counter
		    (rx_counter, thread_index, last_sw_if_index,
		     n_packets, n_bytes);
		}

	      last_sw_if_index = sw_if_index1;
	      n_packets = 1;
	      n_bytes = len1;
	    }
	}
      else
	{
	  vnet_buffer (b[1])->ipsec.flags = IPSEC_FLAG_IPSEC_GRE_TUNNEL;
	}

    trace1:
      if (is_trace)
	{
	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_if_input_trace_t *tr =
		vlib_add_trace (vm, node, b[0], sizeof (*tr));
	      tr->spi = clib_host_to_net_u32 (esp0->spi);
	      tr->seq = clib_host_to_net_u32 (esp0->seq);
	    }
	  if (PREDICT_FALSE (b[1]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_if_input_trace_t *tr =
		vlib_add_trace (vm, node, b[1], sizeof (*tr));
	      tr->spi = clib_host_to_net_u32 (esp1->spi);
	      tr->seq = clib_host_to_net_u32 (esp1->seq);
	    }
	}

      /* next */
      b += 2;
      next += 2;
      n_left_from -= 2;
    }
  while (n_left_from > 0)
    {
      u32 sw_if_index0;
      ip4_header_t *ip0;
      esp_header_t *esp0;
      u32 len0;
      u16 buf_adv0;
      u32 tid0;
      ipsec_tunnel_if_t *t0;
      u64 key0;

      ip0 = (ip4_header_t *) (b[0]->data + vnet_buffer (b[0])->l3_hdr_offset);

      /* NAT UDP port 4500 case, don't advance any more */
      if (ip0->protocol == IP_PROTOCOL_UDP)
	{
	  esp0 =
	    (esp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0) +
			      sizeof (udp_header_t));
	  buf_adv0 = 0;
	}
      else
	{
	  esp0 = (esp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
	  buf_adv0 = ip4_header_bytes (ip0);
	}

      /* stats for the tunnel include all the data after the IP header
         just like a norml IP-IP tunnel */
      vlib_buffer_advance (b[0], buf_adv0);
      len0 = vlib_buffer_length_in_chain (vm, b[0]);

      key0 = (u64) ip0->src_address.as_u32 << 32 | (u64) esp0->spi;
      if (key0 == last_key)
	{
	  tid0 = last_tunnel_id;
	}
      else
	{
	  uword *p = hash_get (im->ipsec_if_pool_index_by_key, key0);
	  if (p)
	    {
	      tid0 = p[0];
	      last_tunnel_id = tid0;
	      last_key = key0;
	    }
	  else
	    {
	      n_no_tunnel++;
	      next[0] = IPSEC_INPUT_NEXT_DROP;
	      goto trace00;
	    }
	}

      t0 = pool_elt_at_index (im->tunnel_interfaces, tid0);
      vnet_buffer (b[0])->ipsec.sad_index = t0->input_sa_index;

      if (PREDICT_TRUE (t0->hw_if_index != ~0))
	{
	  vnet_buffer (b[0])->ipsec.flags = 0;
	  sw_if_index0 = t0->sw_if_index;
	  vnet_buffer (b[0])->sw_if_index[VLIB_RX] = sw_if_index0;

	  if (PREDICT_FALSE (!(t0->flags & VNET_HW_INTERFACE_FLAG_LINK_UP)))
	    {
	      vlib_increment_combined_counter
		(drop_counter, thread_index, sw_if_index0, 1, len0);
	      n_disabled++;
	      next[0] = IPSEC_INPUT_NEXT_DROP;
	      goto trace00;
	    }

	  if (PREDICT_TRUE (sw_if_index0 == last_sw_if_index))
	    {
	      n_packets++;
	      n_bytes += len0;
	    }
	  else
	    {
	      if (n_packets)
		{
		  vlib_increment_combined_counter
		    (rx_counter, thread_index, last_sw_if_index,
		     n_packets, n_bytes);
		}

	      last_sw_if_index = sw_if_index0;
	      n_packets = 1;
	      n_bytes = len0;
	    }
	}
      else
	{
	  vnet_buffer (b[0])->ipsec.flags = IPSEC_FLAG_IPSEC_GRE_TUNNEL;
	}

    trace00:
      if (is_trace)
	{
	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_if_input_trace_t *tr =
		vlib_add_trace (vm, node, b[0], sizeof (*tr));
	      tr->spi = clib_host_to_net_u32 (esp0->spi);
	      tr->seq = clib_host_to_net_u32 (esp0->seq);
	    }
	}

      /* next */
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  if (n_packets)
    {
      vlib_increment_combined_counter (rx_counter,
				       thread_index,
				       last_sw_if_index, n_packets, n_bytes);
    }

  vlib_node_increment_counter (vm, ipsec_if_input_node.index,
			       IPSEC_IF_INPUT_ERROR_RX,
			       from_frame->n_vectors - n_disabled);
  vlib_node_increment_counter (vm, ipsec_if_input_node.index,
			       IPSEC_IF_INPUT_ERROR_DISABLED, n_disabled);
  vlib_node_increment_counter (vm, ipsec_if_input_node.index,
			       IPSEC_IF_INPUT_ERROR_NO_TUNNEL, n_no_tunnel);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, from_frame->n_vectors);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (ipsec_if_input_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * from_frame)
{
  return ipsec_if_input_inline (vm, node, from_frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec_if_input_node) = {
  .name = "ipsec-if-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_if_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_if_input_error_strings),
  .error_strings = ipsec_if_input_error_strings,
  .sibling_of = "ipsec4-input-feature",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
