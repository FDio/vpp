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
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp.h>
#include <vnet/vnet.h>

typedef union
{
  struct
  {
    mac_address_t saddr;
    mac_address_t daddr;
    ip4_address_pair_t address_pair;
    u16 src_port;
    u16 dst_port;
  };
  struct
  {
    u64 flow_data[4];
  };
} gro_ip4_flow_key_t;

static_always_inline u8
gro_is_bad_packet (vlib_buffer_t * b, u8 flags, i16 l234_sz)
{
  if (((b->current_length - l234_sz) <= 0) || ((flags &= ~TCP_FLAG_ACK) != 0))
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

  return flow_key;
}

static_always_inline u8
gro_ip4_flow_is_equal (gro_ip4_flow_key_t first, gro_ip4_flow_key_t second)
{
  if (first.flow_data[0] == second.flow_data[0] &&
      first.flow_data[1] == second.flow_data[1] &&
      first.flow_data[2] == second.flow_data[2] &&
      first.flow_data[3] == second.flow_data[3])
    return 0;

  return 1;
}

static_always_inline u8
gro_ip4_sequence_check (tcp_header_t * tcp0, tcp_header_t * tcp1,
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

static_always_inline u8
gro_ip4_merge (vlib_main_t * vm, vlib_buffer_t * b0, vlib_buffer_t * b1,
	       u32 payload_len1, u16 l234_sz)
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

  return 1;
}

static_always_inline u32
gro_ip4_coalesce (vlib_main_t * vm, vlib_buffer_t * b0, vlib_buffer_t * b1)
{
  gso_header_offset_t gho0, gho1;
  gro_ip4_flow_key_t flow_key0, flow_key1;
  ethernet_header_t *eth0, *eth1;
  ip4_header_t *ip4_0, *ip4_1;
  tcp_header_t *tcp0, *tcp1;
  u16 l234_sz0, l234_sz1;
  u32 pkt_len0, pkt_len1, payload_len0, payload_len1;

  pkt_len0 = vlib_buffer_length_in_chain (vm, b0);
  pkt_len1 = vlib_buffer_length_in_chain (vm, b1);

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

  if (gro_is_bad_packet (b0, tcp0->flags, l234_sz0)
      || gro_is_bad_packet (b1, tcp1->flags, l234_sz1))
    return 0;

  flow_key0 = gro_get_flow_from_packet (eth0, ip4_0, tcp0);
  flow_key1 = gro_get_flow_from_packet (eth1, ip4_1, tcp1);

  if (gro_ip4_flow_is_equal (flow_key0, flow_key1))
    return 0;

  payload_len0 = pkt_len0 - l234_sz0;
  payload_len1 = pkt_len1 - l234_sz1;

  if (pkt_len0 >= TCP_MAX_GSO_SZ || pkt_len1 >= TCP_MAX_GSO_SZ
      || (pkt_len0 + payload_len1) >= TCP_MAX_GSO_SZ)
    return 0;

  if (gro_ip4_sequence_check (tcp0, tcp1, payload_len0))
    {
      if (gro_ip4_merge (vm, b0, b1, payload_len1, l234_sz1))
	return tcp1->ack_number;
    }

  return 0;
}

static_always_inline void
gro_fixup_header (vlib_main_t * vm, vlib_buffer_t * b0, u32 ack_number)
{
  gso_header_offset_t gho = vnet_gso_header_offset_parser (b0, 0);

  b0->flags |=
    (VNET_BUFFER_F_GSO | VNET_BUFFER_F_IS_IP4 |
     VNET_BUFFER_F_OFFLOAD_TCP_CKSUM | VNET_BUFFER_F_OFFLOAD_IP_CKSUM);

  vnet_buffer2 (b0)->gso_size =
    b0->current_length - (gho.l4_hdr_offset + gho.l4_hdr_sz -
			  gho.l2_hdr_offset);
  ip4_header_t *ip4 =
    (ip4_header_t *) (vlib_buffer_get_current (b0) + gho.l3_hdr_offset);
  ip4->length =
    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
			  (gho.l3_hdr_offset - gho.l2_hdr_offset));
  tcp_header_t *tcp0 =
    (tcp_header_t *) (vlib_buffer_get_current (b0) + gho.l4_hdr_offset);
  tcp0->ack_number = ack_number;
}

static_always_inline u32
vnet_gro_inline (vlib_main_t * vm, u32 * from, u16 n_left_from)
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
	      if ((ret = gro_ip4_coalesce (vm, b[0], b[bi])) != 0)
		{
		  // update the respective parameters
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
#endif /* included_gro_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
