/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef included_gso_h
#define included_gso_h

#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/vnet.h>

typedef struct
{
  i16 l2_hdr_offset;
  i16 l3_hdr_offset;
  i16 l4_hdr_offset;
  u16 l4_hdr_sz;
  i16 outer_l2_hdr_offset;
  i16 outer_l3_hdr_offset;
  i16 outer_l4_hdr_offset;
} gso_header_offset_t;

typedef struct
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  u16 msg_id_base;
} gso_main_t;

extern gso_main_t gso_main;

int vnet_sw_interface_gso_enable_disable (u32 sw_if_index, u8 enable);

static_always_inline gso_header_offset_t
vnet_gso_header_offset_parser (vlib_buffer_t * b0, int is_ip6)
{
  gso_header_offset_t gho = { 0 };
  u8 l4_proto = 0;
  u8 l4_hdr_sz = 0;

  ethernet_header_t *eh = (ethernet_header_t *) vlib_buffer_get_current (b0);
  u16 ethertype = clib_net_to_host_u16 (eh->type);
  u16 l2hdr_sz = sizeof (ethernet_header_t);

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

  gho.l2_hdr_offset = b0->current_data;
  gho.l3_hdr_offset = l2hdr_sz;

  if (PREDICT_TRUE (is_ip6 == 0))
    {
      ip4_header_t *ip4 =
	(ip4_header_t *) (vlib_buffer_get_current (b0) + l2hdr_sz);
      gho.l4_hdr_offset = l2hdr_sz + ip4_header_bytes (ip4);
      l4_proto = ip4->protocol;
    }
  else if (PREDICT_TRUE (is_ip6))
    {
      ip6_header_t *ip6 =
	(ip6_header_t *) (vlib_buffer_get_current (b0) + l2hdr_sz);
      /* FIXME IPv6 EH traversal */
      gho.l4_hdr_offset = l2hdr_sz + sizeof (ip6_header_t);
      l4_proto = ip6->protocol;
    }
  if (l4_proto == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) (vlib_buffer_get_current (b0) +
					    gho.l4_hdr_offset);
      l4_hdr_sz = tcp_header_bytes (tcp);
      tcp->checksum = 0;
    }
  else if (l4_proto == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *) (vlib_buffer_get_current (b0) +
					    gho.l4_hdr_offset);
      l4_hdr_sz = sizeof (*udp);
      udp->checksum = 0;
    }

  if (b0->flags & (VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_IS_IP6))
    {
      gho.l4_hdr_sz = l4_hdr_sz;
    }

  return gho;
}

#endif /* included_gso_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
