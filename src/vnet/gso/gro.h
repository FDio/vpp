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

#ifndef included_gro_h
#define included_gro_h

#include <vlib/vlib.h>
#include <vppinfra/error.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/gso/hdr_offset_parser.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp.h>
#include <vnet/vnet.h>

#define GRO_FLOW_TABLE_MAX_SIZE 16
#define GRO_FLOW_TABLE_FLUSH 100
#define GRO_FLOW_N_BUFFERS 64
#define GRO_FLOW_TIMEOUT 1e-5	/* 10 micro-seconds */

typedef union
{
  struct
  {
    u32 sw_if_index[VLIB_N_RX_TX];
    ip46_address_t src_address;
    ip46_address_t dst_address;
    u16 src_port;
    u16 dst_port;
  };

  u64 flow_data[5];
  u32 flow_data_u32;
} gro_flow_key_t;

typedef struct
{
  gro_flow_key_t flow_key;
  f64 next_timeout_ts;
  u32 last_ack_number;
  u32 buffer_index;
  u16 n_buffers;
} gro_flow_t;

typedef struct
{
  u64 total_vectors;
  u32 n_vectors;
  u32 node_index;
  u8 is_l2;
  u8 flush_count;
  u8 flow_table_size;
  gro_flow_t gro_flow[GRO_FLOW_TABLE_MAX_SIZE];
} gro_flow_table_t;

static_always_inline void
gro_flow_set_flow_key (gro_flow_t * to, gro_flow_key_t * from)
{
  to->flow_key.flow_data[0] = from->flow_data[0];
  to->flow_key.flow_data[1] = from->flow_data[1];
  to->flow_key.flow_data[2] = from->flow_data[2];
  to->flow_key.flow_data[3] = from->flow_data[3];
  to->flow_key.flow_data[4] = from->flow_data[4];
  to->flow_key.flow_data_u32 = from->flow_data_u32;
}

static_always_inline u8
gro_flow_is_equal (gro_flow_key_t * first, gro_flow_key_t * second)
{
  if (first->flow_data[0] == second->flow_data[0] &&
      first->flow_data[1] == second->flow_data[1] &&
      first->flow_data[2] == second->flow_data[2] &&
      first->flow_data[3] == second->flow_data[3] &&
      first->flow_data[4] == second->flow_data[4] &&
      first->flow_data_u32 == second->flow_data_u32)
    return 1;

  return 0;
}

/**
 * timeout_expire is in between 3 to 10 microseconds
 * 3e-6 1e-5
 */
static_always_inline void
gro_flow_set_timeout (vlib_main_t * vm, gro_flow_t * gro_flow,
		      f64 timeout_expire)
{
  gro_flow->next_timeout_ts = vlib_time_now (vm) + timeout_expire;
}

static_always_inline u8
gro_flow_is_timeout (vlib_main_t * vm, gro_flow_t * gro_flow)
{
  if (gro_flow->next_timeout_ts < vlib_time_now (vm))
    return 1;
  return 0;
}

static_always_inline void
gro_flow_store_packet (gro_flow_t * gro_flow, u32 bi0)
{
  if (gro_flow->n_buffers == 0)
    {
      gro_flow->buffer_index = bi0;
    }
  gro_flow->n_buffers++;
}

static_always_inline u32
gro_flow_table_init (gro_flow_table_t ** flow_table, u8 is_l2, u32 node_index)
{
  if (*flow_table)
    return 0;

  gro_flow_table_t *flow_table_temp = 0;
  flow_table_temp =
    (gro_flow_table_t *) clib_mem_alloc (sizeof (gro_flow_table_t));
  if (!flow_table_temp)
    return 0;
  clib_memset (flow_table_temp, 0, sizeof (gro_flow_table_t));
  flow_table_temp->node_index = node_index;
  flow_table_temp->is_l2 = is_l2;
  *flow_table = flow_table_temp;
  return 1;
}

static_always_inline void
gro_flow_table_free (gro_flow_table_t * flow_table)
{
  if (flow_table)
    clib_mem_free (flow_table);
}

static_always_inline void
gro_flow_table_set_node_index (gro_flow_table_t * flow_table, u32 node_index)
{
  if (flow_table)
    flow_table->node_index = node_index;
}

static_always_inline gro_flow_t *
gro_flow_table_new_flow (gro_flow_table_t * flow_table)
{
  if (PREDICT_TRUE (flow_table->flow_table_size < GRO_FLOW_TABLE_MAX_SIZE))
    {
      gro_flow_t *gro_flow;
      u32 i = 0;
      while (i < GRO_FLOW_TABLE_MAX_SIZE)
	{
	  gro_flow = &flow_table->gro_flow[i];
	  if (gro_flow->n_buffers == 0)
	    {
	      flow_table->flow_table_size++;
	      return gro_flow;
	    }
	  i++;
	}
    }

  return (0);
}

static_always_inline gro_flow_t *
gro_flow_table_get_flow (gro_flow_table_t * flow_table,
			 gro_flow_key_t * flow_key)
{
  gro_flow_t *gro_flow = 0;
  u32 i = 0;
  while (i < GRO_FLOW_TABLE_MAX_SIZE)
    {
      gro_flow = &flow_table->gro_flow[i];
      if (gro_flow_is_equal (flow_key, &gro_flow->flow_key))
	return gro_flow;
      i++;
    }
  return (0);
}

static_always_inline gro_flow_t *
gro_flow_table_find_or_add_flow (gro_flow_table_t * flow_table,
				 gro_flow_key_t * flow_key)
{
  gro_flow_t *gro_flow = 0;

  gro_flow = gro_flow_table_get_flow (flow_table, flow_key);
  if (gro_flow)
    return gro_flow;

  gro_flow = gro_flow_table_new_flow (flow_table);

  if (gro_flow)
    {
      gro_flow_set_flow_key (gro_flow, flow_key);
      return gro_flow;
    }

  return (0);
}

static_always_inline void
gro_flow_table_reset_flow (gro_flow_table_t * flow_table,
			   gro_flow_t * gro_flow)
{
  if (PREDICT_TRUE (flow_table->flow_table_size > 0))
    {
      clib_memset (gro_flow, 0, sizeof (gro_flow_t));
      flow_table->flow_table_size--;
    }
}

static_always_inline u8 *
gro_flow_table_format (u8 * s, va_list * args)
{
  gro_flow_table_t *flow_table = va_arg (*args, gro_flow_table_t *);

  s =
    format (s,
	    "flow-table: size %u gro-total-vectors %lu gro-n-vectors %u",
	    flow_table->flow_table_size, flow_table->total_vectors,
	    flow_table->n_vectors);
  if (flow_table->n_vectors)
    {
      double average_rate =
	(double) flow_table->total_vectors / (double) flow_table->n_vectors;
      s = format (s, " gro-average-rate %.2f", average_rate);
    }
  else
    s = format (s, " gro-average-rate 0.00");

  return s;
}

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
  GRO_PACKET_ACTION_SEND = 2,
  GRO_PACKET_ACTION_FLUSH = 3,
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
  /* retransmission, send immediately */
  else
    if (PREDICT_FALSE
	((i32) (next_tcp_seq0 + payload_len0) > (i32) next_tcp_seq1))
    return GRO_PACKET_ACTION_SEND;
  /* flush older and enqueue new one */
  else
    if (PREDICT_FALSE
	((i32) (next_tcp_seq0 + payload_len0) < (i32) next_tcp_seq1))
    return GRO_PACKET_ACTION_FLUSH;
  return GRO_PACKET_ACTION_NONE;
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
gro_get_packet_data (vlib_main_t * vm, vlib_buffer_t * b0,
		     generic_header_offset_t * gho0,
		     gro_flow_key_t * flow_key0, int is_l2)
{
  ip4_header_t *ip4_0 = 0;
  ip6_header_t *ip6_0 = 0;
  tcp_header_t *tcp0 = 0;
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
      gro_get_ip4_flow_from_packet (sw_if_index0, ip4_0, tcp0, flow_key0,
				    is_l2);
    }
  else if (gho0->gho_flags & GHO_F_IP6)
    {
      gro_get_ip6_flow_from_packet (sw_if_index0, ip6_0, tcp0, flow_key0,
				    is_l2);
    }
  else
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
      b0->flags |=
	(VNET_BUFFER_F_GSO | VNET_BUFFER_F_IS_IP4 |
	 VNET_BUFFER_F_OFFLOAD_TCP_CKSUM | VNET_BUFFER_F_OFFLOAD_IP_CKSUM);
    }
  else if (gho0.gho_flags & GHO_F_IP6)
    {
      ip6_header_t *ip6 =
	(ip6_header_t *) (vlib_buffer_get_current (b0) + gho0.l3_hdr_offset);
      ip6->payload_length =
	clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
			      gho0.l4_hdr_offset);
      b0->flags |=
	(VNET_BUFFER_F_GSO | VNET_BUFFER_F_IS_IP6 |
	 VNET_BUFFER_F_OFFLOAD_TCP_CKSUM);
    }

  tcp_header_t *tcp0 =
    (tcp_header_t *) (vlib_buffer_get_current (b0) + gho0.l4_hdr_offset);
  tcp0->ack_number = ack_number;
}

#endif /* included_gro_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
