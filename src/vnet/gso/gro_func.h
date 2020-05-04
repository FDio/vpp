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

#ifndef included_gro_func_h
#define included_gro_func_h

#include <vnet/gso/gro.h>

static_always_inline u32
vnet_gro_flow_table_flush (vlib_main_t * vm, gro_flow_table_t * flow_table,
			   u32 * to)
{
  if (flow_table->flow_table_size > 0)
    {
      gro_flow_t *gro_flow;
      u32 i = 0, j = 0;
      while (i < GRO_FLOW_TABLE_MAX_SIZE)
	{
	  gro_flow = &flow_table->gro_flow[i];
	  if (gro_flow->n_buffers && gro_flow_is_timeout (vm, gro_flow))
	    {
	      // flush the packet
	      vlib_buffer_t *b0 =
		vlib_get_buffer (vm, gro_flow->buffer_index);
	      gro_fixup_header (vm, b0, gro_flow->last_ack_number,
				flow_table->is_l2);
	      to[j] = gro_flow->buffer_index;
	      gro_flow_table_reset_flow (flow_table, gro_flow);
	      flow_table->n_vectors++;
	      j++;
	    }
	  i++;
	}

      return j;
    }
  return 0;
}

static_always_inline void
vnet_gro_flow_table_schedule_node_on_dispatcher (vlib_main_t * vm,
						 gro_flow_table_t *
						 flow_table)
{
  if (flow_table->flush_count == GRO_FLOW_TABLE_FLUSH)
    {
      flow_table->flush_count = 0;
      u32 to[GRO_FLOW_TABLE_MAX_SIZE] = { 0 };
      u32 n_to = vnet_gro_flow_table_flush (vm, flow_table, to);

      if (n_to > 0)
	{
	  u32 node_index = flow_table->node_index;
	  vlib_frame_t *f = vlib_get_frame_to_node (vm, node_index);
	  u32 *f_to = vlib_frame_vector_args (f);
	  u32 i = 0;

	  while (i < n_to)
	    {
	      f_to[f->n_vectors] = to[i];
	      i++;
	      f->n_vectors++;
	    }
	  vlib_put_frame_to_node (vm, node_index, f);
	}
    }
  else
    flow_table->flush_count++;
}

static_always_inline u32
vnet_gro_flow_table_inline (vlib_main_t * vm, gro_flow_table_t * flow_table,
			    u32 bi0)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  generic_header_offset_t gho0 = { 0 };
  gro_flow_t *gro_flow = 0;
  gro_flow_key_t flow_key0 = { };
  tcp_header_t *tcp0 = 0;
  u32 pkt_len0 = 0;
  int is_l2 = flow_table->is_l2;

  if (PREDICT_FALSE (b0->flags & VNET_BUFFER_F_GSO))
    return bi0;

  pkt_len0 = gro_get_packet_data (vm, b0, &gho0, &flow_key0, is_l2);
  if (pkt_len0 == 0)
    return bi0;

  gro_flow = gro_flow_table_find_or_add_flow (flow_table, &flow_key0);
  if (!gro_flow)
    return bi0;

  if (PREDICT_FALSE (gro_flow->n_buffers == 0))
    {
      flow_table->total_vectors++;
      gro_flow_store_packet (gro_flow, bi0);
      tcp0 =
	(tcp_header_t *) (vlib_buffer_get_current (b0) + gho0.l4_hdr_offset);
      gro_flow->last_ack_number = tcp0->ack_number;
      gro_flow_set_timeout (vm, gro_flow, GRO_FLOW_TIMEOUT);
      return 0;
    }
  else
    {
      tcp0 =
	(tcp_header_t *) (vlib_buffer_get_current (b0) + gho0.l4_hdr_offset);
      generic_header_offset_t gho_s = { 0 };
      tcp_header_t *tcp_s;
      u16 l234_sz0, l234_sz_s;
      u32 pkt_len_s, payload_len0, payload_len_s;
      u32 bi_s = gro_flow->buffer_index;

      vlib_buffer_t *b_s = vlib_get_buffer (vm, bi_s);
      u32 is_ip_s = gro_is_ip4_or_ip6_packet (b_s, is_l2);
      if (is_ip_s & VNET_BUFFER_F_IS_IP4)
	vnet_generic_header_offset_parser (b_s, &gho_s, is_l2,
					   1 /* is_ip4 */ , 0 /* is_ip6 */ );
      else if (is_ip_s & VNET_BUFFER_F_IS_IP6)
	vnet_generic_header_offset_parser (b_s, &gho_s, is_l2,
					   0 /* is_ip4 */ , 1 /* is_ip6 */ );

      tcp_s =
	(tcp_header_t *) (vlib_buffer_get_current (b_s) +
			  gho_s.l4_hdr_offset);
      pkt_len_s = vlib_buffer_length_in_chain (vm, b_s);
      l234_sz0 = gho0.hdr_sz;
      l234_sz_s = gho_s.hdr_sz;
      payload_len0 = pkt_len0 - l234_sz0;
      payload_len_s = pkt_len_s - l234_sz_s;
      gro_packet_action_t action =
	gro_tcp_sequence_check (tcp_s, tcp0, payload_len_s);

      if (PREDICT_TRUE (action == GRO_PACKET_ACTION_ENQUEUE))
	{
	  if (PREDICT_TRUE ((pkt_len_s + payload_len0) < TCP_MAX_GSO_SZ))
	    {
	      flow_table->total_vectors++;
	      gro_merge_buffers (vm, b_s, b0, bi0, payload_len0, l234_sz0);
	      gro_flow_store_packet (gro_flow, bi0);
	      gro_flow->last_ack_number = tcp0->ack_number;
	      return 0;
	    }
	  else
	    {
	      // flush the stored packet and store the new packet
	      flow_table->n_vectors++;
	      flow_table->total_vectors++;
	      gro_fixup_header (vm, b_s, gro_flow->last_ack_number, is_l2);
	      gro_flow->n_buffers = 0;
	      gro_flow_store_packet (gro_flow, bi0);
	      gro_flow->last_ack_number = tcp0->ack_number;
	      gro_flow_set_timeout (vm, gro_flow, GRO_FLOW_TIMEOUT);
	      return bi_s;
	    }
	}
      else if (action == GRO_PACKET_ACTION_SEND)
	{
	  return bi0;
	}
      else if (action == GRO_PACKET_ACTION_FLUSH)
	{
	  // flush the stored packet and store the new packet
	  flow_table->n_vectors++;
	  flow_table->total_vectors++;
	  gro_fixup_header (vm, b_s, gro_flow->last_ack_number, is_l2);
	  gro_flow->n_buffers = 0;
	  gro_flow_store_packet (gro_flow, bi0);
	  gro_flow->last_ack_number = tcp0->ack_number;
	  gro_flow_set_timeout (vm, gro_flow, GRO_FLOW_TIMEOUT);
	  return bi_s;
	}
    }

  return bi0;
}

/**
 * coalesce buffers with flow tables
 */
static_always_inline u32
vnet_gro_inline (vlib_main_t * vm, gro_flow_table_t * flow_table, u32 * from,
		 u16 n_left_from, u32 * to)
{
  u32 bi0, i = 0;
  while (n_left_from)
    {
      bi0 = vnet_gro_flow_table_inline (vm, flow_table, from[0]);
      if (bi0 != 0)
	{
	  to[i] = bi0;
	  i++;
	}
      from++;
      n_left_from--;
    }
  return i;
}

/**
 * coalesce buffers in opportunistic way without flow tables
 */
static_always_inline u32
vnet_gro_simple_inline (vlib_main_t * vm, u32 * from, u16 n_left_from,
			int is_l2)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vlib_get_buffers (vm, from, b, n_left_from);
  u32 bi = 1, ack_number = 0;
  if (PREDICT_TRUE (((b[0]->flags & VNET_BUFFER_F_GSO) == 0)))
    {
      while (n_left_from > 1)
	{
	  if (PREDICT_TRUE (((b[bi]->flags & VNET_BUFFER_F_GSO) == 0)))
	    {
	      u32 ret;
	      if ((ret =
		   gro_coalesce_buffers (vm, b[0], b[bi], from[bi],
					 is_l2)) != 0)
		{
		  n_left_from -= 1;
		  bi += 1;
		  ack_number = ret;
		  continue;
		}
	      else
		break;
	    }
	  else
	    break;
	}

      if (bi >= 2)
	{
	  gro_fixup_header (vm, b[0], ack_number, is_l2);
	}
    }
  return bi;
}
#endif /* included_gro_func_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
