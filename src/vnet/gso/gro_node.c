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
#include <vppinfra/error.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <vnet/gso/gro.h>
#include <vnet/gso/gso.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/tcp/tcp.h>
#include <vnet/udp/udp_packet.h>

typedef struct
{
  u32 flags;
  u16 gro_size;
  u8 gro_l4_hdr_sz;
} gro_trace_t;

static u8 *
format_gro_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gro_trace_t *t = va_arg (*args, gro_trace_t *);

  if (t->flags & VNET_BUFFER_F_GSO)
    {
      s = format (s, "gro_sz %d gro_l4_hdr_sz %d",
		  t->gro_size, t->gro_l4_hdr_sz);
    }
  else
    {
      s = format (s, "non-gro buffer");
    }

  return s;
}

static_always_inline int
gro_is_good_packet (vlib_buffer_t * b, tcp_header_t * tcp, u16 l234_sz)
{
  if (((b->current_length - l234_sz) <= 0) || (tcp->flags != TCP_FLAG_ACK))
    return 1;

  return 0;
}

static_always_inline gro_ip4_flow_key_t
gro_get_flow_from_packet (ethernet_header_t * eh, ip4_header_t * ip4,
			  tcp_header_t * tcp)
{
  gro_ip4_flow_key_t flow_key;

  mac_address_from_bytes (&flow_key.saddr, eh->src_address);
  mac_address_from_bytes (&flow_key.daddr, eh->dst_address);
  flow_key.address_pair = ip4->address_pair;
  flow_key.src_port = tcp->src_port;
  flow_key.dst_port = tcp->dst_port;
  flow_key.ack_number = tcp->ack_number;

  return flow_key;
}

static_always_inline int
gro_ip4_flow_is_equal (gro_ip4_flow_key_t first, gro_ip4_flow_key_t second)
{
  if (first.flow_data[0] == second.flow_data[0] &&
      first.flow_data[1] == second.flow_data[1] &&
      first.flow_data[2] == second.flow_data[2] &&
      first.flow_data[3] == second.flow_data[3] &&
      first.flow_data_32 == second.flow_data_32)
    return 0;

  return 1;
}

static_always_inline int
gro_ip4_sequence_check (tcp_header_t * tcp0, tcp_header_t * tcp1, u16 len0)
{
  u32 next_tcp_seq0 = 0;
  u32 next_tcp_seq1 = 0;

  next_tcp_seq0 = clib_net_to_host_u32 (tcp0->seq_number);
  next_tcp_seq1 = clib_net_to_host_u32 (tcp1->seq_number);

  if (next_tcp_seq0 + len0 == next_tcp_seq1)
    return 1;
//  else if (next_tcp_seq1 + len1 == next_tcp_seq0)
//    return 2;
  else
    return 0;
}

static_always_inline int
gro_ip4_merge (vlib_main_t * vm, vlib_buffer_t * b0, vlib_buffer_t * b1,
	       u16 len1)
{
  vlib_buffer_t *pb;

  if ((vlib_buffer_length_in_chain (vm, b0) + len1) >= TCP_MAX_GSO_SZ)
    return 1;

  pb = b0;

  while (pb->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      u32 cbi = pb->next_buffer;
      pb = vlib_get_buffer (vm, cbi);
    }

  vlib_buffer_advance (b1, b1->current_length - len1);

  pb->flags |= VLIB_BUFFER_NEXT_PRESENT;
  pb->next_buffer = vlib_get_buffer_index (vm, b1);
  b0->total_length_not_including_first_buffer += len1;

  return 0;
}

static_always_inline int
gro_ip4_coalesce (vlib_main_t * vm, vlib_buffer_t * b0, vlib_buffer_t * b1)
{
  gso_header_offset_t gho0, gho1;
  gro_ip4_flow_key_t flow_key0, flow_key1;
  ethernet_header_t *eth0, *eth1;
  ip4_header_t *ip4_0, *ip4_1;
  tcp_header_t *tcp0, *tcp1;
  u16 l234_sz0, l234_sz1, len0, len1;
  int is_b0_before_b1 = 0;

  gho0 = vnet_gso_header_offset_parser (b0, 0);
  gho1 = vnet_gso_header_offset_parser (b1, 0);

  eth0 = (ethernet_header_t *) vlib_buffer_get_current (b0);
  eth1 = (ethernet_header_t *) vlib_buffer_get_current (b1);

  ip4_0 =
    (ip4_header_t *) (vlib_buffer_get_current (b0) + gho0.l3_hdr_offset);
  ip4_1 =
    (ip4_header_t *) (vlib_buffer_get_current (b1) + gho1.l3_hdr_offset);

  tcp0 = (tcp_header_t *) (vlib_buffer_get_current (b0) + gho0.l4_hdr_offset);
  tcp1 = (tcp_header_t *) (vlib_buffer_get_current (b1) + gho1.l4_hdr_offset);

  l234_sz0 = gho0.l4_hdr_offset + gho0.l4_hdr_sz - gho0.l2_hdr_offset;
  l234_sz1 = gho1.l4_hdr_offset + gho1.l4_hdr_sz - gho1.l2_hdr_offset;

  if (gro_is_good_packet (b0, tcp0, l234_sz0)
      || gro_is_good_packet (b1, tcp1, l234_sz1))
    return 0;

  flow_key0 = gro_get_flow_from_packet (eth0, ip4_0, tcp0);
  flow_key1 = gro_get_flow_from_packet (eth1, ip4_1, tcp1);

  if (gro_ip4_flow_is_equal (flow_key0, flow_key1))
    return 0;

  len0 = vlib_buffer_length_in_chain (vm, b0) - l234_sz0;
  len1 = vlib_buffer_length_in_chain (vm, b1) - l234_sz1;

  is_b0_before_b1 = gro_ip4_sequence_check (tcp0, tcp1, len0);

  if (!is_b0_before_b1)
    return 0;

  if (is_b0_before_b1 == 1)
    {
      if (gro_ip4_merge (vm, b0, b1, len1))
	return 0;
      tcp0->seq_number = tcp1->seq_number;
      return 1;
    }
/*
 * else
 *   {
 *     if (gro_ip4_merge (vm, b1, b0, len0))
 *       return 0;
 *     tcp1->seq_number = tcp0->seq_number;
 *     return 2;
 *   }
 */

  return 0;
}

static_always_inline void
gro_fixup_header (vlib_main_t * vm, vlib_buffer_t * b0,
		  gso_header_offset_t * gho)
{
  ip4_header_t *ip4 =
    (ip4_header_t *) (vlib_buffer_get_current (b0) + gho->l3_hdr_offset);
  ip4->length =
    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
			  (gho->l3_hdr_offset - gho->l2_hdr_offset));
}

static_always_inline void
drop_one_buffer_and_count (vlib_main_t * vm, vnet_main_t * vnm,
			   vlib_node_runtime_t * node, u32 * pbi0,
			   u32 sw_if_index, u32 drop_error_code)
{
  u32 thread_index = vm->thread_index;

  vlib_simple_counter_main_t *cm;
  cm =
    vec_elt_at_index (vnm->interface_main.sw_if_counters,
		      VNET_INTERFACE_COUNTER_TX_ERROR);
  vlib_increment_simple_counter (cm, thread_index, sw_if_index, 1);

  vlib_error_drop_buffers (vm, node, pbi0,
			   /* buffer stride */ 1,
			   /* n_buffers */ 1,
			   VNET_INTERFACE_OUTPUT_NEXT_DROP,
			   node->node_index, drop_error_code);
}

static_always_inline uword
vnet_gro_inline (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * frame,
		 vnet_main_t * vnm, vnet_hw_interface_t * hi, int gso)
{
  u32 *to_next;
  u32 next_index = node->cached_next_index;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from = frame->n_vectors;
  u32 *from_end = from + n_left_from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;

  vlib_get_buffers (vm, from, b, n_left_from);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      if (!gso)
	while (from + 8 <= from_end && n_left_to_next >= 4)
	  {
	    u32 bi0, bi1, bi2, bi3;
	    u32 next0, next1, next2, next3;
	    //gro_trace_t *t0, *t1, *t2, *t3;

	    /* Prefetch next iteration. */
	    vlib_prefetch_buffer_header (b[4], LOAD);
	    vlib_prefetch_buffer_header (b[5], LOAD);
	    vlib_prefetch_buffer_header (b[6], LOAD);
	    vlib_prefetch_buffer_header (b[7], LOAD);

	    bi0 = from[0];
	    bi1 = from[1];
	    bi2 = from[2];
	    bi3 = from[3];
	    to_next[0] = bi0;
	    to_next[1] = bi1;
	    to_next[2] = bi2;
	    to_next[3] = bi3;

	    /*  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	       {
	       t0 = vlib_add_trace (vm, node, b[0], sizeof (t0[0]));
	       t0->flags = b[0]->flags & VNET_BUFFER_F_GSO;
	       t0->gro_size = vnet_buffer2 (b[0])->gro_size;
	       t0->gro_l4_hdr_sz = vnet_buffer2 (b[0])->gro_l4_hdr_sz;
	       }
	       if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
	       {
	       t1 = vlib_add_trace (vm, node, b[1], sizeof (t1[0]));
	       t1->flags = b[1]->flags & VNET_BUFFER_F_GSO;
	       t1->gro_size = vnet_buffer2 (b[1])->gro_size;
	       t1->gro_l4_hdr_sz = vnet_buffer2 (b[1])->gro_l4_hdr_sz;
	       }
	       if (b[2]->flags & VLIB_BUFFER_IS_TRACED)
	       {
	       t2 = vlib_add_trace (vm, node, b[2], sizeof (t2[0]));
	       t2->flags = b[2]->flags & VNET_BUFFER_F_GSO;
	       t2->gro_size = vnet_buffer2 (b[2])->gro_size;
	       t2->gro_l4_hdr_sz = vnet_buffer2 (b[2])->gro_l4_hdr_sz;
	       }
	       if (b[3]->flags & VLIB_BUFFER_IS_TRACED)
	       {
	       t3 = vlib_add_trace (vm, node, b[3], sizeof (t3[0]));
	       t3->flags = b[3]->flags & VNET_BUFFER_F_GSO;
	       t3->gro_size = vnet_buffer2 (b[3])->gro_size;
	       t3->gro_l4_hdr_sz = vnet_buffer2 (b[3])->gro_l4_hdr_sz;
	       }
	     */

	    from += 4;
	    to_next += 4;
	    n_left_to_next -= 4;
	    n_left_from -= 4;

	    next0 = next1 = 0;
	    next2 = next3 = 0;
	    //vnet_feature_next (&next0, b[0]);
	    //vnet_feature_next (&next1, b[1]);
	    //vnet_feature_next (&next2, b[2]);
	    //vnet_feature_next (&next3, b[3]);
	    vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					     n_left_to_next, bi0, bi1, bi2,
					     bi3, next0, next1, next2, next3);
	    b += 4;
	  }

      while (from + 1 <= from_end && n_left_to_next > 0)
	{
	  u32 bi0;
	  u32 next0 = 0;
	  gro_trace_t *t0;

	  /* speculatively enqueue b0 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next += 1;
	  n_left_to_next -= 1;
	  from += 1;
	  n_left_from -= 1;

	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      t0 = vlib_add_trace (vm, node, b[0], sizeof (t0[0]));
	      t0->flags = b[0]->flags & VNET_BUFFER_F_GSO;
	      //t0->gro_size = vnet_buffer2 (b[0])->gro_size;
	      //t0->gro_l4_hdr_sz = vnet_buffer2 (b[0])->gro_l4_hdr_sz;
	    }

	  if (gso)
	    {
	      if (PREDICT_TRUE
		  (((b[0]->flags & VNET_BUFFER_F_GSO) == 0)
		   && (b[0]->flags & VNET_BUFFER_F_IS_IP4)))
		{
		  u32 bi = 1;
		  while (from + 1 <= from_end)
		    {
		      if (PREDICT_TRUE
			  (((b[bi]->flags & VNET_BUFFER_F_GSO) == 0)
			   && (b[bi]->flags & VNET_BUFFER_F_IS_IP4)))
			{
			  //u32 bi1 = from[0];
			  from += 1;
			  n_left_from -= 1;

			  int res = gro_ip4_coalesce (vm, b[0], b[bi]);


			  if (res == 0)
			    {
			      /*
			       * Undo the enqueue of the b[bi] - it is not going anywhere,
			       * and will be handled in outer loop.
			       */
			      from -= 1;
			      n_left_from += 1;
			      break;
			    }
			  else if (res == 1)
			    {
			      // update the respective parameters
			      bi += 1;
			      continue;
			    }
			  //else if (res == 2)
			  // {
			  // handle reordering of b0 and b1
			  // }

			}	// if
		      else
			break;
		    }		// while

		  if (bi >= 2)
		    {
		      gso_header_offset_t gho;
		      gho = vnet_gso_header_offset_parser (b[0], 0);
		      gro_fixup_header (vm, b[0], &gho);
		    }
		  vnet_feature_next (&next0, b[0]);
		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   bi0, next0);
		  b += bi;
		  continue;
		}		// if
	    }			// if

	  //vnet_feature_next (&next0, b[0]);
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	  b += 1;
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (gro_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi;
  vnet_interface_output_runtime_t *rt = (void *) node->runtime_data;
  hi = vnet_get_sup_hw_interface (vnm, rt->sw_if_index);

  if (hi->flags & VNET_HW_INTERFACE_FLAG_SUPPORTS_GSO)
    return vnet_gro_inline (vm, node, frame, vnm, hi, 1);
  else
    return vnet_gro_inline (vm, node, frame, vnm, hi, 0);
}

/* *INDENT-OFF* */

VLIB_REGISTER_NODE (gro_node) = {
  .vector_size = sizeof (u32),
  .format_trace = format_gro_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = 0,
  .name = "gro",
};

VNET_FEATURE_INIT (gro, static) = {
  .arc_name = "interface-output",
  .node_name = "gro",
  .runs_before = VNET_FEATURES ("interface-tx"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
