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
#include <vnet/feature/feature.h>
#include <vnet/l2/l2_in_out_feat_arc.h>
#include <vnet/gso/gro.h>
#include <vnet/gso/gso.h>
#include <vnet/tcp/tcp.h>

gro_main_t gro_main;

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
gro_ip4_sequence_check (tcp_header_t * tcp0, tcp_header_t * tcp1, u16 len0,
			u16 len1)
{
  u32 next_tcp_seq0 = 0;
  u32 next_tcp_seq1 = 0;

  next_tcp_seq0 = clib_net_to_host_u32 (tcp0->seq_number);
  next_tcp_seq1 = clib_net_to_host_u32 (tcp1->seq_number);

  if (next_tcp_seq0 + len0 == next_tcp_seq1)
    return 1;
  else if (next_tcp_seq1 + len1 == next_tcp_seq0)
    return 2;
  else
    return 0;
}

static_always_inline int
gro_ip4_merge (vlib_main_t * vm, vlib_buffer_t * b0, vlib_buffer_t * b1,
	       u16 len)
{
  vlib_buffer_t *pb;

  if ((vlib_buffer_length_in_chain (vm, b0) + len) >= TCP_MAX_GSO_SZ)
    return 1;

  pb = b0;

  while (pb->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      u32 cbi = pb->next_buffer;
      pb = vlib_get_buffer (vm, cbi);
    }

  vlib_buffer_advance (b1, b1->current_length - len);

  pb->flags |= VLIB_BUFFER_NEXT_PRESENT;
  pb->next_buffer = vlib_get_buffer_index (vm, b1);
  b0->total_length_not_including_first_buffer += len;

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

  is_b0_before_b1 = gro_ip4_sequence_check (tcp0, tcp1, len0, len1);

  if (!is_b0_before_b1)
    return 0;

  if (is_b0_before_b1 == 1)
    {
      if (gro_ip4_merge (vm, b0, b1, len1))
	return 0;
      tcp0->seq_number = tcp1->seq_number;
      return 1;
    }
  else
    {
      if (gro_ip4_merge (vm, b1, b0, len0))
	return 0;
      tcp1->seq_number = tcp0->seq_number;
      return 2;
    }

  return 0;
}

int
vnet_sw_interface_gro_enable_disable (u32 sw_if_index, u8 enable)
{
  ethernet_interface_t *eif;
  vnet_sw_interface_t *si;
  ethernet_main_t *em;
  vnet_main_t *vnm;

  vnm = vnet_get_main ();
  em = &ethernet_main;
  si = vnet_get_sw_interface (vnm, sw_if_index);

  /*
   * only ethernet HW interfaces are supported at this time
   */
  if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    {
      return (VNET_API_ERROR_INVALID_VALUE);
    }

  eif = ethernet_get_interface (em, si->hw_if_index);

  if (!eif)
    {
      return (VNET_API_ERROR_FEATURE_DISABLED);
    }

  vnet_feature_enable_disable ("ip4-output", "gro-ip4", sw_if_index, enable,
			       0, 0);
  vnet_feature_enable_disable ("ip6-output", "gro-ip6", sw_if_index, enable,
			       0, 0);

  vnet_l2_feature_enable_disable ("l2-output-nonip", "gro-l2-nonip",
				  sw_if_index, enable, 0, 0);
  vnet_l2_feature_enable_disable ("l2-output-ip4", "gro-l2-ip4",
				  sw_if_index, enable, 0, 0);
  vnet_l2_feature_enable_disable ("l2-output-ip6", "gro-l2-ip6",
				  sw_if_index, enable, 0, 0);

  return (0);
}

static clib_error_t *
gro_init (vlib_main_t * vm)
{
  gro_main_t *gm = &gro_main;

  clib_memset (gm, 0, sizeof (gm[0]));
  gm->vlib_main = vm;
  gm->vnet_main = vnet_get_main ();

  return 0;
}

VLIB_INIT_FUNCTION (gro_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
