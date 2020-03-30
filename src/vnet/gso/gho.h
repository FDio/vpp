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

#ifndef included_gho_h
#define included_gho_h

#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/vnet.h>
#include <vnet/vxlan/vxlan_packet.h>

#define foreach_gho_flag        \
  _( 0, INNER_IP4)              \
  _( 1, INNER_IP6)              \
  _( 2, INNER_TCP)              \
  _( 3, INNER_UDP)              \
  _( 4, OUTER_IP4)              \
  _( 5, OUTER_IP6)              \
  _( 6, OUTER_TCP)              \
  _( 7, OUTER_UDP)              \
  _( 8, VXLAN_TUNNEL)           \
  _( 9, GRE_TUNNEL)             \
  _( 10, IPIP_TUNNEL)           \
  _( 11, GENEVE_TUNNEL)

typedef enum gho_flag_t_
{
#define _(bit, name) GHO_F_##name  = (1 << bit),
  foreach_gho_flag
#undef _
} gho_flag_t;

typedef struct
{
  i16 outer_l2_hdr_offset;
  i16 outer_l3_hdr_offset;
  i16 outer_l4_hdr_offset;
  u16 outer_l4_hdr_sz;
  u16 outer_hdr_sz;
  i16 inner_l2_hdr_offset;
  i16 inner_l3_hdr_offset;
  i16 inner_l4_hdr_offset;
  u16 inner_l4_hdr_sz;
  u16 inner_hdr_sz;
  gho_flag_t gho_flags;
} generic_header_offset_t;

static_always_inline void
vnet_geneve_inner_header_parser_inline (vlib_buffer_t * b0,
                              generic_header_offset_t * gho)
{
  /* not supported yet */ 
}

static_always_inline void
vnet_gre_inner_header_parser_inline (vlib_buffer_t * b0,
                             generic_header_offset_t * gho)
{
  /* not supported yet */ 
}

static_always_inline void
vnet_ipip_inner_header_parser_inline (vlib_buffer_t * b0,
                              generic_header_offset_t * gho)
{
  /* not supported yet */ 
}

static_always_inline void
vnet_vxlan_inner_header_parser_inline (vlib_buffer_t * b0,
                              generic_header_offset_t * gho)
{
  u8 l4_proto = 0;
  u8 l4_hdr_sz = 0;

  gho->inner_l2_hdr_offset = gho->outer_hdr_sz;

  ethernet_header_t *eh = (ethernet_header_t *) (vlib_buffer_get_current (b0) + gho->inner_l2_hdr_offset) ;
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

  gho->inner_l3_hdr_offset = l2hdr_sz + gho->inner_l2_hdr_offset;

  if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP4))
    {
      ip4_header_t *ip4 =
        (ip4_header_t *) (vlib_buffer_get_current (b0) + gho->inner_l3_hdr_offset);
      gho->inner_l4_hdr_offset = gho->inner_l3_hdr_offset + ip4_header_bytes (ip4);
      l4_proto = ip4->protocol;
      gho->gso_flags | = GSO_F_INNER_IP4;
    }
  else if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP6))
    {
      ip6_header_t *ip6 =
        (ip6_header_t *) (vlib_buffer_get_current (b0) + gho->inner_l3_hdr_offset);
      /* FIXME IPv6 EH traversal */
      gho->inner_l4_hdr_offset = gho->inner_l3_hdr_offset + sizeof (ip6_header_t);
      l4_proto = ip6->protocol;
      gho->gso_flags | = GSO_F_INNER_IP6;
    }
  if (l4_proto == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) (vlib_buffer_get_current (b0) +
                                            gho->inner_l4_hdr_offset);
      l4_hdr_sz = tcp_header_bytes (tcp);

      gho->gso_flags |= GSO_F_INNER_TCP;

    }
  else if (l4_proto == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *) (vlib_buffer_get_current (b0) +
                                            gho->inner_l4_hdr_offset);
      l4_hdr_sz = sizeof (*udp);

      gho->gso_flags |= GSO_F_INNER_UDP;
    }

    gho->inner_l4_hdr_sz = l4_hdr_sz;
    gho->inner_hdr_sz += gho->inner_l4_hdr_offset + l4_hdr_sz - gho->inner_l2_hdr_offset;
}

static_always_inline void
vnet_generic_inner_header_parser_inline (vlib_buffer_t * b0,
                              generic_header_offset_t * gho)
{

  if (gho->gso_flags & GSO_F_VXLAN_TUNNEL)
    vnet_vxlan_inner_header_parser_inline (b0, gho);
  else if (gho->gso_flags & GSO_F_IPIP_TUNNEL)
    vnet_ipip_inner_header_parser_inline (b0, gho);
else if (gho->gso_flags & GSO_F_GRE_TUNNEL)
    vnet_gre_inner_header_parser_inline (b0, gho);
else if (gho->gso_flags & GSO_F_GENEVE_TUNNEL)
    vnet_geneve_inner_header_parser_inline (b0, gho);
}

static_always_inline void
vnet_generic_outer_header_parser_inline (vlib_buffer_t * b0,
                              generic_header_offset_t * gho)
{
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

  gho->outer_l2_hdr_offset = b0->current_data;
  gho->outer_l3_hdr_offset = l2hdr_sz;

  if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP4))
    {
      ip4_header_t *ip4 =
	(ip4_header_t *) (vlib_buffer_get_current (b0) + l2hdr_sz);
      gho->outer_l4_hdr_offset = l2hdr_sz + ip4_header_bytes (ip4);
      l4_proto = ip4->protocol;
      gho->gso_flags | = GSO_F_OUTER_IP4;
    }
  else if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP6))
    {
      ip6_header_t *ip6 =
	(ip6_header_t *) (vlib_buffer_get_current (b0) + l2hdr_sz);
      /* FIXME IPv6 EH traversal */
      gho->outer_l4_hdr_offset = l2hdr_sz + sizeof (ip6_header_t);
      l4_proto = ip6->protocol;
      gho->gso_flags | = GSO_F_OUTER_IP6;
    }
  if (l4_proto == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) (vlib_buffer_get_current (b0) +
					    gho->outer_l4_hdr_offset);
      l4_hdr_sz = tcp_header_bytes (tcp);

      gho->gso_flags |= GSO_F_OUTER_TCP;
    }
  else if (l4_proto == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *) (vlib_buffer_get_current (b0) +
					    gho->outer_l4_hdr_offset);
      l4_hdr_sz = sizeof (*udp);

      gho->gso_flags |= GSO_F_OUTER_UDP;

      if (UDP_DST_PORT_vxlan == clib_net_to_host_u16 (udp->dst_port))
	{
          gho->gso_flags |= GSO_F_VXLAN_TUNNEL;
          gho->outer_hdr_sz = sizeof (vxlan_header_t);
	}
      else if (UDP_DST_PORT_geneve == clib_net_to_host_u16 (udp->dst_port))
        {
          gho->gso_flags |= GSO_F_GENEVE_TUNNEL;
        }
    }
   else if ((l4_proto == IP_PROTOCOL_IP_IN_IP) || (l4_proto == IP_PROTOCOL_IPV6))
    {
      l4_hdr_sz = 0;
      gho->gso_flags |= GSO_F_IPIP_TUNNEL;  
    }
   else if (l4_proto == IP_PROTOCOL_GRE)
    {
      l4_hdr_sz = 0;  
      gho->gso_flags |= GSO_F_GRE_TUNNEL;
    }

    gho->outer_l4_hdr_sz = l4_hdr_sz;
    gho->outer_hdr_sz += gho->outer_l4_hdr_offset + l4_hdr_sz;
}

static_always_inline generic_header_offset_t
vnet_generic_header_offset_parser (vlib_buffer_t * b0)
{
  generic_header_offset_t gho = { 0 };

  vnet_generic_outer_header_parser_inline (b0, &gho);
   
  if (gho.gso_flags & (GSO_F_VXLAN_TUNNEL | GSO_F_GENEVE_TUNNEL | GSO_F_IPIP_TUNNEL | GSO_F_GRE_TUNNEL))
    {
      vnet_generic_inner_header_parser_inline (b0, &gho);
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
