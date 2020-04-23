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

#ifndef included_hdr_offset_parser_h
#define included_hdr_offset_parser_h

#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/vnet.h>
#include <vnet/vxlan/vxlan_packet.h>

#define foreach_gho_flag        \
  _( 0, IP4)                    \
  _( 1, IP6)                    \
  _( 2, TCP)                    \
  _( 3, UDP)                    \
  _( 4, OUTER_IP4)              \
  _( 5, OUTER_IP6)              \
  _( 6, OUTER_TCP)              \
  _( 7, OUTER_UDP)              \
  _( 8, VXLAN_TUNNEL)           \
  _( 9, GRE_TUNNEL)             \
  _( 10, IPIP_TUNNEL)           \
  _( 11, IPIP6_TUNNEL)          \
  _( 12, GENEVE_TUNNEL)

typedef enum gho_flag_t_
{
#define _(bit, name) GHO_F_##name  = (1 << bit),
  foreach_gho_flag
#undef _
} gho_flag_t;

#define GHO_F_TUNNEL (GHO_F_VXLAN_TUNNEL  |  \
                      GHO_F_GENEVE_TUNNEL |  \
                      GHO_F_IPIP_TUNNEL   |  \
                      GHO_F_IPIP6_TUNNEL  |  \
                      GHO_F_GRE_TUNNEL)

#define GHO_F_OUTER_HDR (GHO_F_OUTER_IP4 | \
                         GHO_F_OUTER_IP6 | \
                         GHO_F_OUTER_TCP | \
                         GHO_F_OUTER_UDP)

#define GHO_F_INNER_HDR (GHO_F_IP4 | \
                         GHO_F_IP6 | \
                         GHO_F_UDP | \
                         GHO_F_TCP)

typedef struct
{
  i16 outer_l2_hdr_offset;
  i16 outer_l3_hdr_offset;
  i16 outer_l4_hdr_offset;
  u16 outer_l4_hdr_sz;
  u16 outer_hdr_sz;
  i16 l2_hdr_offset;
  i16 l3_hdr_offset;
  i16 l4_hdr_offset;
  u16 l4_hdr_sz;
  u16 hdr_sz;
  gho_flag_t gho_flags;
} generic_header_offset_t;

static_always_inline u8 *
format_generic_header_offset (u8 * s, va_list * args)
{
  generic_header_offset_t *gho = va_arg (*args, generic_header_offset_t *);

  s = format (s, "\n\t");
  if (gho->gho_flags & GHO_F_TUNNEL)
    {
      if (gho->gho_flags & GHO_F_VXLAN_TUNNEL)
	s = format (s, "vxlan-tunnel ");
      else if (gho->gho_flags & GHO_F_IPIP_TUNNEL)
	s = format (s, "ipip-tunnel ");
      else if (gho->gho_flags & GHO_F_GRE_TUNNEL)
	s = format (s, "gre-tunnel ");
      else if (gho->gho_flags & GHO_F_GENEVE_TUNNEL)
	s = format (s, "geneve-tunnel ");

      if (gho->gho_flags & GHO_F_OUTER_IP4)
	s = format (s, "outer-ipv4 ");
      else if (gho->gho_flags & GHO_F_OUTER_IP6)
	s = format (s, "outer-ipv6 ");

      if (gho->gho_flags & GHO_F_OUTER_UDP)
	s = format (s, "outer-udp ");
      else if (gho->gho_flags & GHO_F_OUTER_TCP)
	s = format (s, "outer-tcp ");

      s = format (s, "outer-hdr-sz %u outer-l2-hdr-offset %d "
		  "outer-l3-hdr-offset %d outer-l4-hdr-offset %d "
		  "outer-l4-hdr-sz %u\n\t",
		  gho->outer_hdr_sz, gho->outer_l2_hdr_offset,
		  gho->outer_l3_hdr_offset, gho->outer_l4_hdr_offset,
		  gho->outer_l4_hdr_sz);
    }

  if (gho->gho_flags & GHO_F_IP4)
    s = format (s, "ipv4 ");
  else if (gho->gho_flags & GHO_F_IP6)
    s = format (s, "ipv6 ");

  if (gho->gho_flags & GHO_F_TCP)
    s = format (s, "tcp ");
  else if (gho->gho_flags & GHO_F_UDP)
    s = format (s, "udp ");

  s = format (s, "hdr-sz %u l2-hdr-offset %d "
	      "l3-hdr-offset %d l4-hdr-offset %d "
	      "l4-hdr-sz %u",
	      gho->hdr_sz, gho->l2_hdr_offset, gho->l3_hdr_offset,
	      gho->l4_hdr_offset, gho->l4_hdr_sz);

  return s;
}

static_always_inline void
vnet_get_inner_header (vlib_buffer_t * b0, generic_header_offset_t * gho)
{
  if ((gho->gho_flags & GHO_F_TUNNEL)
      && (gho->gho_flags & GHO_F_OUTER_HDR)
      && (b0->current_data == gho->outer_l2_hdr_offset))
    vlib_buffer_advance (b0, gho->outer_hdr_sz);
}

static_always_inline void
vnet_get_outer_header (vlib_buffer_t * b0, generic_header_offset_t * gho)
{
  if ((gho->gho_flags & GHO_F_TUNNEL)
      && (gho->gho_flags & GHO_F_OUTER_HDR)
      && (b0->current_data == gho->l2_hdr_offset))
    vlib_buffer_advance (b0, -gho->outer_hdr_sz);
}

static_always_inline void
vnet_geneve_inner_header_parser_inline (vlib_buffer_t * b0,
					generic_header_offset_t * gho)
{
  /* not supported yet */
  if ((gho->gho_flags & GHO_F_GENEVE_TUNNEL) == 0)
    return;

  ASSERT (0);
}

static_always_inline void
vnet_gre_inner_header_parser_inline (vlib_buffer_t * b0,
				     generic_header_offset_t * gho)
{
  /* not supported yet */
  if ((gho->gho_flags & GHO_F_GRE_TUNNEL) == 0)
    return;

  ASSERT (0);
}

static_always_inline void
vnet_ipip_inner_header_parser_inline (vlib_buffer_t * b0,
				      generic_header_offset_t * gho)
{
  if ((gho->gho_flags & (GHO_F_IPIP_TUNNEL | GHO_F_IPIP6_TUNNEL)) == 0)
    return;

  u8 l4_proto = 0;
  u8 l4_hdr_sz = 0;

  gho->outer_l2_hdr_offset = gho->l2_hdr_offset;
  gho->outer_l3_hdr_offset = gho->l3_hdr_offset;
  gho->outer_l4_hdr_offset = gho->l4_hdr_offset;
  gho->outer_l4_hdr_sz = gho->l4_hdr_sz;
  gho->outer_hdr_sz = gho->hdr_sz;

  gho->l2_hdr_offset = 0;
  gho->l3_hdr_offset = 0;
  gho->l4_hdr_offset = 0;
  gho->l4_hdr_sz = 0;
  gho->hdr_sz = 0;

  if (gho->gho_flags & GHO_F_IP4)
    {
      gho->gho_flags |= GHO_F_OUTER_IP4;
    }
  else if (gho->gho_flags & GHO_F_IP6)
    {
      gho->gho_flags |= GHO_F_OUTER_IP6;
    }

  gho->gho_flags &= ~GHO_F_INNER_HDR;

  vnet_get_inner_header (b0, gho);

  gho->l2_hdr_offset = b0->current_data;
  gho->l3_hdr_offset = 0;

  if (PREDICT_TRUE (gho->gho_flags & GHO_F_IPIP_TUNNEL))
    {
      ip4_header_t *ip4 = (ip4_header_t *) vlib_buffer_get_current (b0);
      gho->l4_hdr_offset = ip4_header_bytes (ip4);
      l4_proto = ip4->protocol;
      gho->gho_flags |= GHO_F_IP4;
    }
  else if (PREDICT_TRUE (gho->gho_flags & GHO_F_IPIP6_TUNNEL))
    {
      ip6_header_t *ip6 = (ip6_header_t *) vlib_buffer_get_current (b0);
      /* FIXME IPv6 EH traversal */
      gho->l4_hdr_offset = sizeof (ip6_header_t);
      l4_proto = ip6->protocol;
      gho->gho_flags |= GHO_F_IP6;
    }
  if (l4_proto == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) (vlib_buffer_get_current (b0) +
					    gho->l4_hdr_offset);
      l4_hdr_sz = tcp_header_bytes (tcp);

      gho->gho_flags |= GHO_F_TCP;

    }
  else if (l4_proto == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *) (vlib_buffer_get_current (b0) +
					    gho->l4_hdr_offset);
      l4_hdr_sz = sizeof (*udp);

      gho->gho_flags |= GHO_F_UDP;
    }

  gho->l4_hdr_sz = l4_hdr_sz;
  gho->hdr_sz += gho->l4_hdr_offset + l4_hdr_sz;

  vnet_get_outer_header (b0, gho);
}

static_always_inline void
vnet_vxlan_inner_header_parser_inline (vlib_buffer_t * b0,
				       generic_header_offset_t * gho)
{
  u8 l4_proto = 0;
  u8 l4_hdr_sz = 0;

  if ((gho->gho_flags & GHO_F_VXLAN_TUNNEL) == 0)
    return;

  gho->outer_l2_hdr_offset = gho->l2_hdr_offset;
  gho->outer_l3_hdr_offset = gho->l3_hdr_offset;
  gho->outer_l4_hdr_offset = gho->l4_hdr_offset;
  gho->outer_l4_hdr_sz = gho->l4_hdr_sz;
  gho->outer_hdr_sz = gho->hdr_sz;

  gho->l2_hdr_offset = 0;
  gho->l3_hdr_offset = 0;
  gho->l4_hdr_offset = 0;
  gho->l4_hdr_sz = 0;
  gho->hdr_sz = 0;

  if (gho->gho_flags & GHO_F_IP4)
    {
      gho->gho_flags |= GHO_F_OUTER_IP4;
    }
  else if (gho->gho_flags & GHO_F_IP6)
    {
      gho->gho_flags |= GHO_F_OUTER_IP6;
    }

  if (gho->gho_flags & GHO_F_UDP)
    {
      gho->gho_flags |= GHO_F_OUTER_UDP;
    }

  gho->gho_flags &= ~GHO_F_INNER_HDR;

  vnet_get_inner_header (b0, gho);

  gho->l2_hdr_offset = b0->current_data;

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

  gho->l3_hdr_offset = l2hdr_sz;

  if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP4))
    {
      ip4_header_t *ip4 =
	(ip4_header_t *) (vlib_buffer_get_current (b0) + gho->l3_hdr_offset);
      gho->l4_hdr_offset = gho->l3_hdr_offset + ip4_header_bytes (ip4);
      l4_proto = ip4->protocol;
      gho->gho_flags |= GHO_F_IP4;
    }
  else if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP6))
    {
      ip6_header_t *ip6 =
	(ip6_header_t *) (vlib_buffer_get_current (b0) + gho->l3_hdr_offset);
      /* FIXME IPv6 EH traversal */
      gho->l4_hdr_offset = gho->l3_hdr_offset + sizeof (ip6_header_t);
      l4_proto = ip6->protocol;
      gho->gho_flags |= GHO_F_IP6;
    }
  if (l4_proto == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) (vlib_buffer_get_current (b0) +
					    gho->l4_hdr_offset);
      l4_hdr_sz = tcp_header_bytes (tcp);

      gho->gho_flags |= GHO_F_TCP;

    }
  else if (l4_proto == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *) (vlib_buffer_get_current (b0) +
					    gho->l4_hdr_offset);
      l4_hdr_sz = sizeof (*udp);

      gho->gho_flags |= GHO_F_UDP;
    }

  gho->l4_hdr_sz = l4_hdr_sz;
  gho->hdr_sz += gho->l4_hdr_offset + l4_hdr_sz;

  vnet_get_outer_header (b0, gho);
}

static_always_inline void
vnet_generic_inner_header_parser_inline (vlib_buffer_t * b0,
					 generic_header_offset_t * gho)
{

  if (gho->gho_flags & GHO_F_VXLAN_TUNNEL)
    vnet_vxlan_inner_header_parser_inline (b0, gho);
  else if (gho->gho_flags & (GHO_F_IPIP_TUNNEL | GHO_F_IPIP6_TUNNEL))
    vnet_ipip_inner_header_parser_inline (b0, gho);
  else if (gho->gho_flags & GHO_F_GRE_TUNNEL)
    vnet_gre_inner_header_parser_inline (b0, gho);
  else if (gho->gho_flags & GHO_F_GENEVE_TUNNEL)
    vnet_geneve_inner_header_parser_inline (b0, gho);
}

static_always_inline void
vnet_generic_outer_header_parser_inline (vlib_buffer_t * b0,
					 generic_header_offset_t * gho,
					 int is_l2, int is_ip4, int is_ip6)
{
  u8 l4_proto = 0;
  u8 l4_hdr_sz = 0;
  u16 ethertype = 0;
  u16 l2hdr_sz = 0;

  ASSERT (is_ip4 ^ is_ip6);

  if (is_l2)
    {
      ethernet_header_t *eh =
	(ethernet_header_t *) vlib_buffer_get_current (b0);
      ethertype = clib_net_to_host_u16 (eh->type);
      l2hdr_sz = sizeof (ethernet_header_t);

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
    }
  else
    l2hdr_sz = vnet_buffer (b0)->ip.save_rewrite_length;

  gho->l2_hdr_offset = b0->current_data;
  gho->l3_hdr_offset = l2hdr_sz;

  if (PREDICT_TRUE (is_ip4))
    {
      ip4_header_t *ip4 =
	(ip4_header_t *) (vlib_buffer_get_current (b0) + l2hdr_sz);
      gho->l4_hdr_offset = l2hdr_sz + ip4_header_bytes (ip4);
      l4_proto = ip4->protocol;
      gho->gho_flags |= GHO_F_IP4;
    }
  else if (PREDICT_TRUE (is_ip6))
    {
      ip6_header_t *ip6 =
	(ip6_header_t *) (vlib_buffer_get_current (b0) + l2hdr_sz);
      /* FIXME IPv6 EH traversal */
      gho->l4_hdr_offset = l2hdr_sz + sizeof (ip6_header_t);
      l4_proto = ip6->protocol;
      gho->gho_flags |= GHO_F_IP6;
    }
  if (l4_proto == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) (vlib_buffer_get_current (b0) +
					    gho->l4_hdr_offset);
      l4_hdr_sz = tcp_header_bytes (tcp);

      gho->gho_flags |= GHO_F_TCP;
    }
  else if (l4_proto == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *) (vlib_buffer_get_current (b0) +
					    gho->l4_hdr_offset);
      l4_hdr_sz = sizeof (*udp);

      gho->gho_flags |= GHO_F_UDP;

      if (UDP_DST_PORT_vxlan == clib_net_to_host_u16 (udp->dst_port))
	{
	  gho->gho_flags |= GHO_F_VXLAN_TUNNEL;
	  gho->hdr_sz += sizeof (vxlan_header_t);
	}
      else if (UDP_DST_PORT_geneve == clib_net_to_host_u16 (udp->dst_port))
	{
	  gho->gho_flags |= GHO_F_GENEVE_TUNNEL;
	}
    }
  else if (l4_proto == IP_PROTOCOL_IP_IN_IP)
    {
      l4_hdr_sz = 0;
      gho->gho_flags |= GHO_F_IPIP_TUNNEL;
    }
  else if (l4_proto == IP_PROTOCOL_IPV6)
    {
      l4_hdr_sz = 0;
      gho->gho_flags |= GHO_F_IPIP6_TUNNEL;
    }
  else if (l4_proto == IP_PROTOCOL_GRE)
    {
      l4_hdr_sz = 0;
      gho->gho_flags |= GHO_F_GRE_TUNNEL;
    }

  gho->l4_hdr_sz = l4_hdr_sz;
  gho->hdr_sz += gho->l4_hdr_offset + l4_hdr_sz;
}

static_always_inline void
vnet_generic_header_offset_parser (vlib_buffer_t * b0,
				   generic_header_offset_t * gho, int is_l2,
				   int is_ip4, int is_ip6)
{
  vnet_generic_outer_header_parser_inline (b0, gho, is_l2, is_ip4, is_ip6);

  if (gho->gho_flags & GHO_F_TUNNEL)
    {
      vnet_generic_inner_header_parser_inline (b0, gho);
    }
}

#endif /* included_hdr_offset_parser_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
