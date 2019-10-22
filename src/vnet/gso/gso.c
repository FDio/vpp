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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/feature/feature.h>
#include <vnet/l2/l2_in_out_feat_arc.h>
#include <vnet/gso/gso.h>

gso_main_t gso_main;

inline gso_header_offset_t
vnet_gso_header_offset_parser (vlib_buffer_t * b0)
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

  if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP4))
    {
      ip4_header_t *ip4 =
	(ip4_header_t *) (vlib_buffer_get_current (b0) + l2hdr_sz);
      gho.l4_hdr_offset = l2hdr_sz + ip4_header_bytes (ip4);
      l4_proto = ip4->protocol;
    }
  else if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP6))
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

int
vnet_sw_interface_gso_enable_disable (u32 sw_if_index, u8 enable)
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

  vnet_feature_enable_disable ("ip4-output", "gso-ip4", sw_if_index, enable,
			       0, 0);
  vnet_feature_enable_disable ("ip6-output", "gso-ip6", sw_if_index, enable,
			       0, 0);

  vnet_l2_feature_enable_disable ("l2-output-nonip", "gso-l2-nonip",
				  sw_if_index, enable, 0, 0);
  vnet_l2_feature_enable_disable ("l2-output-ip4", "gso-l2-ip4",
				  sw_if_index, enable, 0, 0);
  vnet_l2_feature_enable_disable ("l2-output-ip6", "gso-l2-ip6",
				  sw_if_index, enable, 0, 0);

  return (0);
}

static clib_error_t *
gso_init (vlib_main_t * vm)
{
  gso_main_t *gm = &gso_main;

  clib_memset (gm, 0, sizeof (gm[0]));
  gm->vlib_main = vm;
  gm->vnet_main = vnet_get_main ();

  return 0;
}

VLIB_INIT_FUNCTION (gso_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
