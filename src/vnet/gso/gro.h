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
#include <vnet/gso/gho.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp.h>
#include <vnet/vnet.h>

#define GRO_FLOW_TABLE_MAX_SIZE 16
#define GRO_FLOW_N_BUFFERS 64

typedef union
{
  struct
  {
    mac_address_t saddr;
    mac_address_t daddr;
    ip46_address_t src_address;
    ip46_address_t dst_address;
    u16 src_port;
    u16 dst_port;
  };
  u64 flow_data[6];
} gro_flow_key_t;

typedef struct
{
  gro_flow_key_t flow_key;
  f64 next_timeout_ts;
  u32 *buffers;			/* cache aligned */
  u16 n_buffers;
  u32 last_ack_number;
} gro_flow_t;

typedef struct
{
  gro_flow_t *gro_flow;
  u8 flow_table_size;
} gro_flow_table_t;

static_always_inline void
gro_flow_set_flow_key (gro_flow_t * to, gro_flow_key_t * from)
{
  to->flow_key.flow_data[0] = from->flow_data[0];
  to->flow_key.flow_data[1] = from->flow_data[1];
  to->flow_key.flow_data[2] = from->flow_data[2];
  to->flow_key.flow_data[3] = from->flow_data[3];
  to->flow_key.flow_data[4] = from->flow_data[4];
  to->flow_key.flow_data[5] = from->flow_data[5];
}

static_always_inline u8
gro_flow_is_equal (gro_flow_key_t * first, gro_flow_key_t * second)
{
  if (first->flow_data[0] == second->flow_data[0] &&
      first->flow_data[1] == second->flow_data[1] &&
      first->flow_data[2] == second->flow_data[2] &&
      first->flow_data[3] == second->flow_data[3] &&
      first->flow_data[4] == second->flow_data[4] &&
      first->flow_data[5] == second->flow_data[5])
    return 1;

  return 0;
}

static_always_inline void
gro_flow_buffers_init (gro_flow_t * gro_flow, u16 n_buffers)
{
  vec_validate_aligned (gro_flow->buffers, n_buffers, CLIB_CACHE_LINE_BYTES);
}

/**
 * timeout_expire is in between 3 to 10 microseconds
 * 3e-5 1e-6
 */
static_always_inline void
gro_flow_set_timeout (gro_flow_t * gro_flow, f64 timeout_expire)
{
  vlib_main_t *vm = vlib_get_main ();
  gro_flow->next_timeout_ts = vlib_time_now (vm) + timeout_expire;
}

static_always_inline u8
gro_flow_is_timeout (gro_flow_t * gro_flow)
{
  vlib_main_t *vm = vlib_get_main ();
  if (gro_flow->next_timeout_ts > vlib_time_now (vm))
    return 1;
  return 0;
}

static_always_inline u8
gro_flow_store_packet (gro_flow_t * gro_flow, u32 buffer)
{
  if (gro_flow->n_buffers < GRO_FLOW_N_BUFFERS)
    {
      /*
       * There is no gurantee that buffer is not chained buffer.
       * May need to handle it.
       */
      gro_flow->buffers[gro_flow->n_buffers] = buffer;
      gro_flow->n_buffers++;
      return 1;
    }

  return 0;
}

static_always_inline gro_flow_table_t *
gro_flow_table_init ()
{
  gro_flow_table_t *flow_table = 0;
  vec_validate (flow_table, 0);
  vec_validate (flow_table->gro_flow, GRO_FLOW_TABLE_MAX_SIZE);
  flow_table->flow_table_size = 0;
  return flow_table;
}

static_always_inline gro_flow_t *
gro_flow_table_new_flow (gro_flow_table_t * flow_table)
{
  if (flow_table->flow_table_size < GRO_FLOW_TABLE_MAX_SIZE)
    {
      gro_flow_t *gro_flow;
      vec_foreach (gro_flow, flow_table->gro_flow)
      {
	if (gro_flow->n_buffers == 0)
	  {
	    flow_table->flow_table_size++;
	    break;
	  }
      }
      return gro_flow;
    }

  return (0);
}

static_always_inline gro_flow_t *
gro_flow_table_get_flow (gro_flow_table_t * flow_table,
			 gro_flow_key_t * flow_key)
{
  gro_flow_t *gro_flow = 0;
  vec_foreach (gro_flow, flow_table->gro_flow)
  {
    if (gro_flow_is_equal (flow_key, &gro_flow->flow_key))
      return gro_flow;
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
      gro_flow_buffers_init (gro_flow, GRO_FLOW_N_BUFFERS);
      return gro_flow;
    }

  return (0);
}

static_always_inline void
gro_flow_table_reset_flow (gro_flow_table_t * flow_table,
			   gro_flow_t * gro_flow)
{
  if (flow_table->flow_table_size > 0)
    {
      vec_free (gro_flow->buffers);
      clib_memset (gro_flow, 0, sizeof (gro_flow));
      flow_table->flow_table_size--;
    }
}

static_always_inline u8
gro_is_bad_packet (vlib_buffer_t * b, u8 flags, i16 l234_sz)
{
  if (((b->current_length - l234_sz) <= 0) || ((flags &= ~TCP_FLAG_ACK) != 0))
    return 1;
  return 0;
}

static_always_inline gro_flow_key_t
gro_get_ip4_flow_from_packet (ethernet_header_t * eh,
			      ip4_header_t * ip4, tcp_header_t * tcp)
{
  gro_flow_key_t flow_key;
  mac_address_from_bytes (&flow_key.saddr, eh->src_address);
  mac_address_from_bytes (&flow_key.daddr, eh->dst_address);
  ip46_address_set_ip4 (&flow_key.src_address, &ip4->src_address);
  ip46_address_set_ip4 (&flow_key.dst_address, &ip4->dst_address);
  flow_key.src_port = tcp->src_port;
  flow_key.dst_port = tcp->dst_port;
  return flow_key;
}

static_always_inline gro_flow_key_t
gro_get_ip6_flow_from_packet (ethernet_header_t * eh,
			      ip6_header_t * ip6, tcp_header_t * tcp)
{
  gro_flow_key_t flow_key;
  mac_address_from_bytes (&flow_key.saddr, eh->src_address);
  mac_address_from_bytes (&flow_key.daddr, eh->dst_address);
  ip46_address_set_ip6 (&flow_key.src_address, &ip6->src_address);
  ip46_address_set_ip6 (&flow_key.dst_address, &ip6->dst_address);
  flow_key.src_port = tcp->src_port;
  flow_key.dst_port = tcp->dst_port;
  return flow_key;
}

static_always_inline u8
gro_tcp_sequence_check (tcp_header_t * tcp0, tcp_header_t * tcp1,
			u32 payload_len0)
{
  u32 next_tcp_seq0 = 0;
  u32 next_tcp_seq1 = ~0;
  next_tcp_seq0 = clib_net_to_host_u32 (tcp0->seq_number);
  next_tcp_seq1 = clib_net_to_host_u32 (tcp1->seq_number);
  if (next_tcp_seq0 + payload_len0 == next_tcp_seq1)
    return 1;
  return 0;
}

static_always_inline void
gro_merge_buffers (vlib_main_t * vm, vlib_buffer_t * b0,
		   vlib_buffer_t * b1, u32 payload_len1, u16 l234_sz)
{
  vlib_buffer_t *pb;
  pb = b0;
  while (pb->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      u32 cbi = pb->next_buffer;
      pb = vlib_get_buffer (vm, cbi);
    }

  vlib_buffer_advance (b1, l234_sz);
  pb->flags |= VLIB_BUFFER_NEXT_PRESENT;
  pb->next_buffer = vlib_get_buffer_index (vm, b1);
  b0->total_length_not_including_first_buffer += payload_len1;
  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
}

static_always_inline u32
gro_get_packet_data (vlib_main_t * vm, vlib_buffer_t * b0,
		     generic_header_offset_t * gho0,
		     gro_flow_key_t * flow_key0, tcp_header_t * tcp0)
{
  ethernet_header_t *eth0;
  ip4_header_t *ip4_0;
  ip6_header_t *ip6_0;
  u32 pkt_len0 = 0;
  u16 l234_sz0;

  vnet_generic_header_offset_parser (b0, gho0);

  if ((gho0->gho_flags & GHO_F_TCP) == 0)
    return 0;

  eth0 = (ethernet_header_t *) vlib_buffer_get_current (b0);
  ip4_0 =
    (ip4_header_t *) (vlib_buffer_get_current (b0) + gho0->l3_hdr_offset);
  ip6_0 =
    (ip6_header_t *) (vlib_buffer_get_current (b0) + gho0->l3_hdr_offset);
  tcp0 =
    (tcp_header_t *) (vlib_buffer_get_current (b0) + gho0->l4_hdr_offset);

  l234_sz0 = gho0->l4_hdr_offset + gho0->l4_hdr_sz - gho0->l2_hdr_offset;
  if (gro_is_bad_packet (b0, tcp0->flags, l234_sz0))
    return 0;

  if (gho0->gho_flags & GHO_F_IP4)
    {
      *flow_key0 = gro_get_ip4_flow_from_packet (eth0, ip4_0, tcp0);
    }
  else if (gho0->gho_flags & GHO_F_IP6)
    {
      *flow_key0 = gro_get_ip6_flow_from_packet (eth0, ip6_0, tcp0);
    }
  else
    return 0;

  pkt_len0 = vlib_buffer_length_in_chain (vm, b0);
  if (pkt_len0 >= TCP_MAX_GSO_SZ)
    return 0;

  return pkt_len0;
}

static_always_inline u32
gro_coalesce_buffers (vlib_main_t * vm, vlib_buffer_t * b0,
		      vlib_buffer_t * b1)
{
  generic_header_offset_t gho0 = { 0 };
  generic_header_offset_t gho1 = { 0 };
  gro_flow_key_t flow_key0, flow_key1;
  ethernet_header_t *eth0, *eth1;
  ip4_header_t *ip4_0, *ip4_1;
  ip6_header_t *ip6_0, *ip6_1;
  tcp_header_t *tcp0, *tcp1;
  u16 l234_sz0, l234_sz1;
  u32 pkt_len0, pkt_len1, payload_len0, payload_len1;

  pkt_len0 = vlib_buffer_length_in_chain (vm, b0);
  pkt_len1 = vlib_buffer_length_in_chain (vm, b1);
  vnet_generic_header_offset_parser (b0, &gho0);
  vnet_generic_header_offset_parser (b1, &gho1);

  if (((gho0.gho_flags & GHO_F_TCP) == 0)
      || ((gho1.gho_flags & GHO_F_TCP) == 0))
    return 0;

  eth0 = (ethernet_header_t *) vlib_buffer_get_current (b0);
  eth1 = (ethernet_header_t *) vlib_buffer_get_current (b1);

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

  l234_sz0 = gho0.l4_hdr_offset + gho0.l4_hdr_sz - gho0.l2_hdr_offset;
  l234_sz1 = gho1.l4_hdr_offset + gho1.l4_hdr_sz - gho1.l2_hdr_offset;

  if (gro_is_bad_packet (b0, tcp0->flags, l234_sz0)
      || gro_is_bad_packet (b1, tcp1->flags, l234_sz1))
    return 0;

  if ((gho0.gho_flags & GHO_F_IP4) && (gho1.gho_flags & GHO_F_IP4))
    {
      flow_key0 = gro_get_ip4_flow_from_packet (eth0, ip4_0, tcp0);
      flow_key1 = gro_get_ip4_flow_from_packet (eth1, ip4_1, tcp1);
    }
  else if ((gho0.gho_flags & GHO_F_IP6) && (gho1.gho_flags & GHO_F_IP6))
    {
      flow_key0 = gro_get_ip6_flow_from_packet (eth0, ip6_0, tcp0);
      flow_key1 = gro_get_ip6_flow_from_packet (eth1, ip6_1, tcp1);
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

  if (gro_tcp_sequence_check (tcp0, tcp1, payload_len0))
    {
      gro_merge_buffers (vm, b0, b1, payload_len1, l234_sz1);
      return tcp1->ack_number;
    }

  return 0;
}

static_always_inline void
gro_fixup_header (vlib_main_t * vm, vlib_buffer_t * b0, u32 ack_number)
{
  generic_header_offset_t gho0 = { 0 };

  vnet_generic_header_offset_parser (b0, &gho0);
  vnet_buffer2 (b0)->gso_size =
    b0->current_length - (gho0.l4_hdr_offset + gho0.l4_hdr_sz -
			  gho0.l2_hdr_offset);

  if (gho0.gho_flags & GHO_F_IP4)
    {
      ip4_header_t *ip4 =
	(ip4_header_t *) (vlib_buffer_get_current (b0) + gho0.l3_hdr_offset);
      ip4->length =
	clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
			      (gho0.l3_hdr_offset - gho0.l2_hdr_offset));
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
			      (gho0.l4_hdr_offset - gho0.l2_hdr_offset));
      b0->flags |=
	(VNET_BUFFER_F_GSO | VNET_BUFFER_F_IS_IP6 |
	 VNET_BUFFER_F_OFFLOAD_TCP_CKSUM | VNET_BUFFER_F_OFFLOAD_IP_CKSUM);
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
