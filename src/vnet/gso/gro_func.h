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

#include <vnet/ethernet/ethernet.h>
#include <vnet/gso/gro.h>
#include <vnet/gso/hdr_offset_parser.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/vnet.h>

static_always_inline u8
gro_is_bad_packet (vlib_buffer_t * b, u8 flags, i16 l234_sz)
{
  if (((b->current_length - l234_sz) <= 0) || ((flags &= ~TCP_FLAG_ACK) != 0))
    return 1;
  return 0;
}

static_always_inline void
gro_get_ip4_flow_from_packet (u32 * sw_if_index,
			      ip4_header_t * ip4, tcp_header_t * tcp,
			      gro_flow_key_t * flow_key, int is_l2)
{
  flow_key->sw_if_index[VLIB_RX] = sw_if_index[VLIB_RX];
  flow_key->sw_if_index[VLIB_TX] = sw_if_index[VLIB_TX];
  ip46_address_set_ip4 (&flow_key->src_address, &ip4->src_address);
  ip46_address_set_ip4 (&flow_key->dst_address, &ip4->dst_address);
  flow_key->src_port = tcp->src_port;
  flow_key->dst_port = tcp->dst_port;
}

static_always_inline void
gro_get_ip6_flow_from_packet (u32 * sw_if_index,
			      ip6_header_t * ip6, tcp_header_t * tcp,
			      gro_flow_key_t * flow_key, int is_l2)
{
  flow_key->sw_if_index[VLIB_RX] = sw_if_index[VLIB_RX];
  flow_key->sw_if_index[VLIB_TX] = sw_if_index[VLIB_TX];
  ip46_address_set_ip6 (&flow_key->src_address, &ip6->src_address);
  ip46_address_set_ip6 (&flow_key->dst_address, &ip6->dst_address);
  flow_key->src_port = tcp->src_port;
  flow_key->dst_port = tcp->dst_port;
}

static_always_inline u32
gro_is_ip4_or_ip6_packet (vlib_buffer_t * b0, int is_l2)
{
  if (b0->flags & VNET_BUFFER_F_IS_IP4)
    return VNET_BUFFER_F_IS_IP4;
  if (b0->flags & VNET_BUFFER_F_IS_IP6)
    return VNET_BUFFER_F_IS_IP6;
  if (is_l2)
    {
      ethernet_header_t *eh =
	(ethernet_header_t *) vlib_buffer_get_current (b0);
      u16 ethertype = clib_net_to_host_u16 (eh->type);

      if (ethernet_frame_is_tagged (ethertype))
	{
	  ethernet_vlan_header_t *vlan = (ethernet_vlan_header_t *) (eh + 1);

	  ethertype = clib_net_to_host_u16 (vlan->type);
	  if (ethertype == ETHERNET_TYPE_VLAN)
	    {
	      vlan++;
	      ethertype = clib_net_to_host_u16 (vlan->type);
	    }
	}
      if (ethertype == ETHERNET_TYPE_IP4)
	return VNET_BUFFER_F_IS_IP4;
      if (ethertype == ETHERNET_TYPE_IP6)
	return VNET_BUFFER_F_IS_IP6;
    }
  else
    {
      if ((((u8 *) vlib_buffer_get_current (b0))[0] & 0xf0) == 0x40)
	return VNET_BUFFER_F_IS_IP4;
      if ((((u8 *) vlib_buffer_get_current (b0))[0] & 0xf0) == 0x60)
	return VNET_BUFFER_F_IS_IP6;
    }

  return 0;
}

typedef enum
{
  GRO_PACKET_ACTION_NONE = 0,
  GRO_PACKET_ACTION_ENQUEUE = 1,
  GRO_PACKET_ACTION_FLUSH = 2,
} gro_packet_action_t;

static_always_inline gro_packet_action_t
gro_tcp_sequence_check (tcp_header_t * tcp0, tcp_header_t * tcp1,
			u32 payload_len0)
{
  u32 next_tcp_seq0 = clib_net_to_host_u32 (tcp0->seq_number);
  u32 next_tcp_seq1 = clib_net_to_host_u32 (tcp1->seq_number);

  /* next packet, enqueue */
  if (PREDICT_TRUE (next_tcp_seq0 + payload_len0 == next_tcp_seq1))
    return GRO_PACKET_ACTION_ENQUEUE;
  /* flush all packets */
  else
    return GRO_PACKET_ACTION_FLUSH;
}

static_always_inline void
gro_merge_buffers (vlib_main_t * vm, vlib_buffer_t * b0,
		   vlib_buffer_t * b1, u32 bi1, u32 payload_len1,
		   u16 l234_sz1)
{
  vlib_buffer_t *pb = b0;

  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0))
    b0->total_length_not_including_first_buffer = 0;

  while (pb->flags & VLIB_BUFFER_NEXT_PRESENT)
    pb = vlib_get_buffer (vm, pb->next_buffer);

  vlib_buffer_advance (b1, l234_sz1);
  pb->flags |= VLIB_BUFFER_NEXT_PRESENT;
  pb->next_buffer = bi1;
  b0->total_length_not_including_first_buffer += payload_len1;
  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
}

static_always_inline u32
gro_validate_checksum (vlib_main_t * vm, vlib_buffer_t * b0,
		       generic_header_offset_t * gho0, int is_ip4)
{
  u32 flags = 0;

  if (b0->flags & VNET_BUFFER_F_OFFLOAD)
    return VNET_BUFFER_F_L4_CHECKSUM_CORRECT;
  vlib_buffer_advance (b0, gho0->l3_hdr_offset);
  if (is_ip4)
    flags = ip4_tcp_udp_validate_checksum (vm, b0);
  else
    flags = ip6_tcp_udp_icmp_validate_checksum (vm, b0);
  vlib_buffer_advance (b0, -gho0->l3_hdr_offset);
  return flags;
}

static_always_inline u32
gro_get_packet_data (vlib_main_t * vm, vlib_buffer_t * b0,
		     generic_header_offset_t * gho0,
		     gro_flow_key_t * flow_key0, int is_l2)
{
  ip4_header_t *ip4_0 = 0;
  ip6_header_t *ip6_0 = 0;
  tcp_header_t *tcp0 = 0;
  u32 flags = 0;
  u32 pkt_len0 = 0;
  u16 l234_sz0 = 0;
  u32 sw_if_index0[VLIB_N_RX_TX] = { ~0 };

  u32 is_ip0 = gro_is_ip4_or_ip6_packet (b0, is_l2);

  if (is_ip0 & VNET_BUFFER_F_IS_IP4)
    vnet_generic_header_offset_parser (b0, gho0, is_l2, 1 /* is_ip4 */ ,
				       0 /* is_ip6 */ );
  else if (is_ip0 & VNET_BUFFER_F_IS_IP6)
    vnet_generic_header_offset_parser (b0, gho0, is_l2, 0 /* is_ip4 */ ,
				       1 /* is_ip6 */ );
  else
    return 0;

  if (PREDICT_FALSE ((gho0->gho_flags & GHO_F_TCP) == 0))
    return 0;

  ip4_0 =
    (ip4_header_t *) (vlib_buffer_get_current (b0) + gho0->l3_hdr_offset);
  ip6_0 =
    (ip6_header_t *) (vlib_buffer_get_current (b0) + gho0->l3_hdr_offset);
  tcp0 =
    (tcp_header_t *) (vlib_buffer_get_current (b0) + gho0->l4_hdr_offset);

  l234_sz0 = gho0->hdr_sz;
  if (PREDICT_FALSE (gro_is_bad_packet (b0, tcp0->flags, l234_sz0)))
    return 0;

  sw_if_index0[VLIB_RX] = vnet_buffer (b0)->sw_if_index[VLIB_RX];
  sw_if_index0[VLIB_TX] = vnet_buffer (b0)->sw_if_index[VLIB_TX];

  if (gho0->gho_flags & GHO_F_IP4)
    {
      flags = gro_validate_checksum (vm, b0, gho0, 1);
      gro_get_ip4_flow_from_packet (sw_if_index0, ip4_0, tcp0, flow_key0,
				    is_l2);
    }
  else if (gho0->gho_flags & GHO_F_IP6)
    {
      flags = gro_validate_checksum (vm, b0, gho0, 0);
      gro_get_ip6_flow_from_packet (sw_if_index0, ip6_0, tcp0, flow_key0,
				    is_l2);
    }
  else
    return 0;

  if ((flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) == 0)
    return 0;

  pkt_len0 = vlib_buffer_length_in_chain (vm, b0);
  if (PREDICT_FALSE (pkt_len0 >= TCP_MAX_GSO_SZ))
    return 0;

  return pkt_len0;
}

static_always_inline u32
gro_coalesce_buffers (vlib_main_t * vm, vlib_buffer_t * b0,
		      vlib_buffer_t * b1, u32 bi1, int is_l2)
{
  generic_header_offset_t gho0 = { 0 };
  generic_header_offset_t gho1 = { 0 };
  gro_flow_key_t flow_key0, flow_key1;
  ip4_header_t *ip4_0, *ip4_1;
  ip6_header_t *ip6_0, *ip6_1;
  tcp_header_t *tcp0, *tcp1;
  u16 l234_sz0, l234_sz1;
  u32 pkt_len0, pkt_len1, payload_len0, payload_len1;
  u32 sw_if_index0[VLIB_N_RX_TX] = { ~0 };
  u32 sw_if_index1[VLIB_N_RX_TX] = { ~0 };

  u32 is_ip0 = gro_is_ip4_or_ip6_packet (b0, is_l2);
  u32 is_ip1 = gro_is_ip4_or_ip6_packet (b1, is_l2);

  if (is_ip0 & VNET_BUFFER_F_IS_IP4)
    vnet_generic_header_offset_parser (b0, &gho0, is_l2, 1 /* is_ip4 */ ,
				       0 /* is_ip6 */ );
  else if (is_ip0 & VNET_BUFFER_F_IS_IP6)
    vnet_generic_header_offset_parser (b0, &gho0, is_l2, 0 /* is_ip4 */ ,
				       1 /* is_ip6 */ );
  else
    return 0;

  if (is_ip1 & VNET_BUFFER_F_IS_IP4)
    vnet_generic_header_offset_parser (b1, &gho1, is_l2, 1 /* is_ip4 */ ,
				       0 /* is_ip6 */ );
  else if (is_ip1 & VNET_BUFFER_F_IS_IP6)
    vnet_generic_header_offset_parser (b1, &gho1, is_l2, 0 /* is_ip4 */ ,
				       1 /* is_ip6 */ );
  else
    return 0;

  pkt_len0 = vlib_buffer_length_in_chain (vm, b0);
  pkt_len1 = vlib_buffer_length_in_chain (vm, b1);

  if (((gho0.gho_flags & GHO_F_TCP) == 0)
      || ((gho1.gho_flags & GHO_F_TCP) == 0))
    return 0;

  ip4_0 =
    (ip4_header_t *) (vlib_buffer_get_current (b0) + gho0.l3_hdr_offset);
  ip4_1 =
    (ip4_header_t *) (vlib_buffer_get_current (b1) + gho1.l3_hdr_offset);
  ip6_0 =
    (ip6_header_t *) (vlib_buffer_get_current (b0) + gho0.l3_hdr_offset);
  ip6_1 =
    (ip6_header_t *) (vlib_buffer_get_current (b1) + gho1.l3_hdr_offset);

  tcp0 = (tcp_header_t *) (vlib_buffer_get_current (b0) + gho0.l4_hdr_offset);
  tcp1 = (tcp_header_t *) (vlib_buffer_get_current (b1) + gho1.l4_hdr_offset);

  l234_sz0 = gho0.hdr_sz;
  l234_sz1 = gho1.hdr_sz;

  if (gro_is_bad_packet (b0, tcp0->flags, l234_sz0)
      || gro_is_bad_packet (b1, tcp1->flags, l234_sz1))
    return 0;

  sw_if_index0[VLIB_RX] = vnet_buffer (b0)->sw_if_index[VLIB_RX];
  sw_if_index0[VLIB_TX] = vnet_buffer (b0)->sw_if_index[VLIB_TX];

  sw_if_index1[VLIB_RX] = vnet_buffer (b1)->sw_if_index[VLIB_RX];
  sw_if_index1[VLIB_TX] = vnet_buffer (b1)->sw_if_index[VLIB_TX];

  if ((gho0.gho_flags & GHO_F_IP4) && (gho1.gho_flags & GHO_F_IP4))
    {
      gro_get_ip4_flow_from_packet (sw_if_index0, ip4_0, tcp0, &flow_key0,
				    is_l2);
      gro_get_ip4_flow_from_packet (sw_if_index1, ip4_1, tcp1, &flow_key1,
				    is_l2);
    }
  else if ((gho0.gho_flags & GHO_F_IP6) && (gho1.gho_flags & GHO_F_IP6))
    {
      gro_get_ip6_flow_from_packet (sw_if_index0, ip6_0, tcp0, &flow_key0,
				    is_l2);
      gro_get_ip6_flow_from_packet (sw_if_index1, ip6_1, tcp1, &flow_key1,
				    is_l2);
    }
  else
    return 0;

  if (gro_flow_is_equal (&flow_key0, &flow_key1) == 0)
    return 0;

  payload_len0 = pkt_len0 - l234_sz0;
  payload_len1 = pkt_len1 - l234_sz1;

  if (pkt_len0 >= TCP_MAX_GSO_SZ || pkt_len1 >= TCP_MAX_GSO_SZ
      || (pkt_len0 + payload_len1) >= TCP_MAX_GSO_SZ)
    return 0;

  if (gro_tcp_sequence_check (tcp0, tcp1, payload_len0) ==
      GRO_PACKET_ACTION_ENQUEUE)
    {
      gro_merge_buffers (vm, b0, b1, bi1, payload_len1, l234_sz1);
      return tcp1->ack_number;
    }

  return 0;
}

static_always_inline void
gro_fixup_header (vlib_main_t * vm, vlib_buffer_t * b0, u32 ack_number,
		  int is_l2)
{
  generic_header_offset_t gho0 = { 0 };

  u32 is_ip0 = gro_is_ip4_or_ip6_packet (b0, is_l2);

  if (is_ip0 & VNET_BUFFER_F_IS_IP4)
    vnet_generic_header_offset_parser (b0, &gho0, is_l2, 1 /* is_ip4 */ ,
				       0 /* is_ip6 */ );
  else if (is_ip0 & VNET_BUFFER_F_IS_IP6)
    vnet_generic_header_offset_parser (b0, &gho0, is_l2, 0 /* is_ip4 */ ,
				       1 /* is_ip6 */ );

  vnet_buffer2 (b0)->gso_size = b0->current_length - gho0.hdr_sz;

  if (gho0.gho_flags & GHO_F_IP4)
    {
      ip4_header_t *ip4 =
	(ip4_header_t *) (vlib_buffer_get_current (b0) + gho0.l3_hdr_offset);
      ip4->length =
	clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
			      gho0.l3_hdr_offset);
      b0->flags |= (VNET_BUFFER_F_GSO | VNET_BUFFER_F_IS_IP4);
      vnet_buffer_offload_flags_set (b0,
				     (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM |
				      VNET_BUFFER_OFFLOAD_F_IP_CKSUM));
    }
  else if (gho0.gho_flags & GHO_F_IP6)
    {
      ip6_header_t *ip6 =
	(ip6_header_t *) (vlib_buffer_get_current (b0) + gho0.l3_hdr_offset);
      ip6->payload_length =
	clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
			      gho0.l4_hdr_offset);
      b0->flags |= (VNET_BUFFER_F_GSO | VNET_BUFFER_F_IS_IP6);
      vnet_buffer_offload_flags_set (b0, VNET_BUFFER_OFFLOAD_F_TCP_CKSUM);
    }

  tcp_header_t *tcp0 =
    (tcp_header_t *) (vlib_buffer_get_current (b0) + gho0.l4_hdr_offset);
  tcp0->ack_number = ack_number;
  b0->flags &= ~VLIB_BUFFER_IS_TRACED;
}

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
  if (gro_flow_table_is_timeout (vm, flow_table))
    {
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
      gro_flow_table_set_timeout (vm, flow_table, GRO_FLOW_TABLE_FLUSH);
    }
}

static_always_inline u32
vnet_gro_flow_table_inline (vlib_main_t * vm, gro_flow_table_t * flow_table,
			    u32 bi0, u32 * to)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  generic_header_offset_t gho0 = { 0 };
  gro_flow_t *gro_flow = 0;
  gro_flow_key_t flow_key0 = { };
  tcp_header_t *tcp0 = 0;
  u32 pkt_len0 = 0;
  int is_l2 = flow_table->is_l2;

  if (!gro_flow_table_is_enable (flow_table))
    {
      to[0] = bi0;
      return 1;
    }

  if (PREDICT_FALSE (b0->flags & VNET_BUFFER_F_GSO))
    {
      to[0] = bi0;
      return 1;
    }

  pkt_len0 = gro_get_packet_data (vm, b0, &gho0, &flow_key0, is_l2);
  if (pkt_len0 == 0)
    {
      to[0] = bi0;
      return 1;
    }

  gro_flow = gro_flow_table_find_or_add_flow (flow_table, &flow_key0);
  if (!gro_flow)
    {
      to[0] = bi0;
      return 1;
    }

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
	      // flush the stored GSO size packet and buffer the current packet
	      flow_table->n_vectors++;
	      flow_table->total_vectors++;
	      gro_fixup_header (vm, b_s, gro_flow->last_ack_number, is_l2);
	      gro_flow->n_buffers = 0;
	      gro_flow_store_packet (gro_flow, bi0);
	      gro_flow->last_ack_number = tcp0->ack_number;
	      gro_flow_set_timeout (vm, gro_flow, GRO_FLOW_TIMEOUT);
	      to[0] = bi_s;
	      return 1;
	    }
	}
      else
	{
	  // flush the all (current and stored) packets
	  flow_table->n_vectors++;
	  flow_table->total_vectors++;
	  gro_fixup_header (vm, b_s, gro_flow->last_ack_number, is_l2);
	  gro_flow->n_buffers = 0;
	  gro_flow_table_reset_flow (flow_table, gro_flow);
	  to[0] = bi_s;
	  to[1] = bi0;
	  return 2;
	}
    }
}

/**
 * coalesce buffers with flow tables
 */
static_always_inline u32
vnet_gro_inline (vlib_main_t * vm, gro_flow_table_t * flow_table, u32 * from,
		 u16 n_left_from, u32 * to)
{
  u16 count = 0, i = 0;

  for (i = 0; i < n_left_from; i++)
    count += vnet_gro_flow_table_inline (vm, flow_table, from[i], &to[count]);

  return count;
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
