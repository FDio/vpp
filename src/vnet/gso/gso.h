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

#include <vnet/vnet.h>
#include <vnet/gso/hdr_offset_parser.h>

typedef struct
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  u16 msg_id_base;
} gso_main_t;

extern gso_main_t gso_main;

int vnet_sw_interface_gso_enable_disable (u32 sw_if_index, u8 enable);

static_always_inline void
vnet_gso_calc_checksums_inline (vlib_main_t * vm, vlib_buffer_t * b,
				int is_l2, int is_ip4, int is_ip6)
{
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  tcp_header_t *th;
  udp_header_t *uh;

  generic_header_offset_t gho = { 0 };
  vnet_generic_header_offset_parser (b, &gho, is_l2, is_ip4, is_ip6);

  ASSERT (!(is_ip4 && is_ip6));

  ip4 = (ip4_header_t *) (vlib_buffer_get_current (b) + gho.l3_hdr_offset);
  ip6 = (ip6_header_t *) (vlib_buffer_get_current (b) + gho.l3_hdr_offset);
  th = (tcp_header_t *) (vlib_buffer_get_current (b) + gho.l4_hdr_offset);
  uh = (udp_header_t *) (vlib_buffer_get_current (b) + gho.l4_hdr_offset);

  if (gho.gho_flags & GHO_F_IP4)
    {
      if (b->flags & VNET_BUFFER_F_OFFLOAD_IP_CKSUM)
	ip4->checksum = ip4_header_checksum (ip4);
      if (b->flags & VNET_BUFFER_F_OFFLOAD_TCP_CKSUM)
	{
	  th->checksum = 0;
	  th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
	}
      if (b->flags & VNET_BUFFER_F_OFFLOAD_UDP_CKSUM)
	{
	  uh->checksum = 0;
	  uh->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
	}
    }
  else if (gho.gho_flags & GHO_F_IP6)
    {
      int bogus;
      if (b->flags & VNET_BUFFER_F_OFFLOAD_TCP_CKSUM)
	{
	  th->checksum = 0;
	  th->checksum =
	    ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
	}
      if (b->flags & VNET_BUFFER_F_OFFLOAD_UDP_CKSUM)
	{
	  uh->checksum = 0;
	  uh->checksum =
	    ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
	}
    }

  b->flags &= ~VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;
  b->flags &= ~VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;
  b->flags &= ~VNET_BUFFER_F_OFFLOAD_IP_CKSUM;
}
#endif /* included_gso_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
