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
      u32 i = 0;
      vec_foreach (gro_flow, flow_table->gro_flow)
      {
	if (gro_flow_is_timeout (gro_flow)
	    || gro_flow->n_buffers == GRO_FLOW_N_BUFFERS)
	  {
	    // flush the packet
	    vlib_buffer_t *b0 = vlib_get_buffer (vm, gro_flow->buffers[0]);
	    gro_fixup_header (vm, b0, gro_flow->last_ack_number);
	    to[i] = gro_flow->buffers[0];
	    gro_flow_table_reset_flow (flow_table, gro_flow);
	    i++;
	  }
      }
      return i;
    }
  return 0;
}

static_always_inline u32
vnet_gro_flow_table_inline (vlib_main_t * vm, gro_flow_table_t * flow_table,
			    u32 bi0)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  generic_header_offset_t gho0 = { 0 };
  gro_flow_t *gro_flow;
  gro_flow_key_t flow_key0;
  tcp_header_t *tcp0 = 0;
  u32 pkt_len0;

  if (PREDICT_FALSE ((b0->flags & VNET_BUFFER_F_GSO) != 0))
    return bi0;

  if ((pkt_len0 = gro_get_packet_data (vm, b0, &gho0, &flow_key0, tcp0)) == 0)
    return bi0;

  gro_flow = gro_flow_table_find_or_add_flow (flow_table, &flow_key0);
  if (!gro_flow)
    return bi0;

  if (gro_flow->n_buffers == 0)
    {
      gro_flow_store_packet (gro_flow, bi0);
      gro_flow->last_ack_number = tcp0->ack_number;
      gro_flow_set_timeout (gro_flow, 3e-5);
      return ~0;
    }
  else if (gro_flow->n_buffers < GRO_FLOW_N_BUFFERS)
    {
      generic_header_offset_t gho_s = { 0 };
      tcp_header_t *tcp_s;
      u16 l234_sz0, l234_sz_s;
      u32 pkt_len_s, payload_len0, payload_len_s;
      u32 bi_s = gro_flow->buffers[0];

      vlib_buffer_t *b_s = vlib_get_buffer (vm, bi_s);
      vnet_generic_header_offset_parser (b_s, &gho_s);
      tcp_s =
	(tcp_header_t *) (vlib_buffer_get_current (b_s) +
			  gho_s.l4_hdr_offset);
      pkt_len_s = vlib_buffer_length_in_chain (vm, b_s);
      l234_sz0 = gho0.l4_hdr_offset + gho0.l4_hdr_sz - gho0.l2_hdr_offset;
      l234_sz_s = gho_s.l4_hdr_offset + gho_s.l4_hdr_sz - gho_s.l2_hdr_offset;
      payload_len0 = pkt_len0 - l234_sz0;
      payload_len_s = pkt_len_s - l234_sz_s;

      if (gro_tcp_sequence_check (tcp_s, tcp0, payload_len_s))
	{

	  if ((pkt_len_s + payload_len0) < TCP_MAX_GSO_SZ)
	    {

	      gro_merge_buffers (vm, b_s, b0, payload_len0, l234_sz0);
	      gro_flow_store_packet (gro_flow, bi0);
	      gro_flow->last_ack_number = tcp0->ack_number;
	      return ~0;
	    }
	  else
	    {
	      // flush the stored packet and store the new packet
	      gro_fixup_header (vm, b_s, gro_flow->last_ack_number);
	      //*b_flush = b_s;
	      gro_flow->n_buffers = 0;
	      gro_flow_store_packet (gro_flow, bi0);
	      gro_flow->last_ack_number = tcp0->ack_number;
	      gro_flow_set_timeout (gro_flow, 3e-5);
	      return bi_s;
	    }
	}
      else
	return bi0;
    }
  else				// gro_flow->n_buffers == GRO_FLOW_N_BUFFERS
    {
      u32 bi_s = gro_flow->buffers[0];
      vlib_buffer_t *b_s = vlib_get_buffer (vm, bi_s);
      gro_fixup_header (vm, b_s, gro_flow->last_ack_number);
      gro_flow->n_buffers = 0;
      gro_flow_store_packet (gro_flow, bi0);
      gro_flow->last_ack_number = tcp0->ack_number;
      gro_flow_set_timeout (gro_flow, 3e-5);
      return bi_s;
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
      if (bi0 != ~0)
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
vnet_gro_simple_inline (vlib_main_t * vm, u32 * from, u16 n_left_from)
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
	      if ((ret = gro_coalesce_buffers (vm, b[0], b[bi])) != 0)
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
	  gro_fixup_header (vm, b[0], ack_number);
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
