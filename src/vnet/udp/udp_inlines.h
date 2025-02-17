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

#ifndef SRC_VNET_UDP_UDP_INLINES_H_
#define SRC_VNET_UDP_UDP_INLINES_H_

#include <vnet/vnet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/interface_output.h>
#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>
#include <vnet/udp/udp_encap.h>

always_inline void *
vlib_buffer_push_udp (vlib_buffer_t *b, u16 sp, u16 dp)
{
  udp_header_t *uh;
  u16 udp_len = sizeof (udp_header_t) + b->current_length;
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID))
    udp_len += b->total_length_not_including_first_buffer;

  uh = (udp_header_t *) vlib_buffer_push_uninit (b, sizeof (udp_header_t));
  uh->src_port = sp;
  uh->dst_port = dp;
  uh->checksum = 0;
  uh->length = clib_host_to_net_u16 (udp_len);
  vnet_buffer (b)->l4_hdr_offset = (u8 *) uh - b->data;
  b->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
  return uh;
}

/*
 * Encode udp source port entropy value per
 * https://datatracker.ietf.org/doc/html/rfc7510#section-3
 */
always_inline u16
ip_udp_sport_entropy (vlib_buffer_t *b0)
{
  u16 port = clib_host_to_net_u16 (0x03 << 14);
  port |= vnet_buffer (b0)->ip.flow_hash & 0xffff;
  return port;
}

always_inline u32
ip_udp_compute_flow_hash (vlib_buffer_t *b0, u8 is_ip4)
{
  ip4_header_t *ip4;
  ip6_header_t *ip6;

  if (is_ip4)
    {
      ip4 = (ip4_header_t *) (b0->data + vnet_buffer (b0)->l3_hdr_offset);
      return ip4_compute_flow_hash (ip4, IP_FLOW_HASH_DEFAULT);
    }
  else
    {
      ip6 = (ip6_header_t *) (b0->data + vnet_buffer (b0)->l3_hdr_offset);
      return ip6_compute_flow_hash (ip6, IP_FLOW_HASH_DEFAULT);
    }
}

always_inline void
ip_udp_fixup_one (vlib_main_t *vm, vlib_buffer_t *b0, u8 is_ip4,
		  u8 sport_entropy)
{
  u16 new_l0;
  udp_header_t *udp0;

  if (is_ip4)
    {
      ip4_header_t *ip0;
      ip_csum_t sum0;
      u16 old_l0 = 0;

      ip0 = (ip4_header_t *) vlib_buffer_get_current (b0);

      /* fix the <bleep>ing outer-IP checksum */
      sum0 = ip0->checksum;
      /* old_l0 always 0, see the rewrite setup */
      new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));

      sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
			     length /* changed member */ );
      ip0->checksum = ip_csum_fold (sum0);
      ip0->length = new_l0;

      /* Fix UDP length */
      udp0 = (udp_header_t *) (ip0 + 1);
      new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0)
				     - sizeof (*ip0));
      udp0->length = new_l0;

      if (sport_entropy)
	udp0->src_port = ip_udp_sport_entropy (b0);
    }
  else
    {
      ip6_header_t *ip0;
      int bogus0;

      ip0 = (ip6_header_t *) vlib_buffer_get_current (b0);

      new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0)
				     - sizeof (*ip0));
      ip0->payload_length = new_l0;

      /* Fix UDP length */
      udp0 = (udp_header_t *) (ip0 + 1);
      udp0->length = new_l0;

      if (sport_entropy)
	udp0->src_port = ip_udp_sport_entropy (b0);

      udp0->checksum =
	ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip0, &bogus0);
      ASSERT (bogus0 == 0);

      if (udp0->checksum == 0)
	udp0->checksum = 0xffff;
    }
}

always_inline void
ip_udp_encap_one (vlib_main_t *vm, vlib_buffer_t *b0, u8 *ec0, word ec_len,
		  ip_address_family_t encap_family,
		  ip_address_family_t payload_family,
		  udp_encap_fixup_flags_t flags)
{
  u8 sport_entropy = (flags & UDP_ENCAP_FIXUP_UDP_SRC_PORT_ENTROPY) != 0;

  if (payload_family < N_AF)
    {
      vnet_calc_checksums_inline (vm, b0, payload_family == AF_IP4,
				  payload_family == AF_IP6);

      /* Сalculate flow hash to be used for entropy */
      if (sport_entropy && 0 == vnet_buffer (b0)->ip.flow_hash)
	vnet_buffer (b0)->ip.flow_hash =
	  ip_udp_compute_flow_hash (b0, payload_family == AF_IP4);
    }

  vlib_buffer_advance (b0, -ec_len);

  if (encap_family == AF_IP4)
    {
      ip4_header_t *ip0;

      ip0 = (ip4_header_t *) vlib_buffer_get_current (b0);

      /* Apply the encap string. */
      clib_memcpy_fast (ip0, ec0, ec_len);
      ip_udp_fixup_one (vm, b0, 1, sport_entropy);
    }
  else
    {
      ip6_header_t *ip0;

      ip0 = (ip6_header_t *) vlib_buffer_get_current (b0);

      /* Apply the encap string. */
      clib_memcpy_fast (ip0, ec0, ec_len);
      ip_udp_fixup_one (vm, b0, 0, sport_entropy);
    }
}

always_inline void
ip_udp_encap_two (vlib_main_t *vm, vlib_buffer_t *b0, vlib_buffer_t *b1,
		  u8 *ec0, u8 *ec1, word ec_len,
		  ip_address_family_t encap_family,
		  ip_address_family_t payload_family,
		  udp_encap_fixup_flags_t flags0,
		  udp_encap_fixup_flags_t flags1)
{
  u16 new_l0, new_l1;
  udp_header_t *udp0, *udp1;
  int payload_ip4 = (payload_family == AF_IP4);
  int sport_entropy0 = (flags0 & UDP_ENCAP_FIXUP_UDP_SRC_PORT_ENTROPY) != 0;
  int sport_entropy1 = (flags1 & UDP_ENCAP_FIXUP_UDP_SRC_PORT_ENTROPY) != 0;

  if (payload_family < N_AF)
    {
      vnet_calc_checksums_inline (vm, b0, payload_ip4, !payload_ip4);
      vnet_calc_checksums_inline (vm, b1, payload_ip4, !payload_ip4);

      /* Сalculate flow hash to be used for entropy */
      if (sport_entropy0 && 0 == vnet_buffer (b0)->ip.flow_hash)
	vnet_buffer (b0)->ip.flow_hash =
	  ip_udp_compute_flow_hash (b0, payload_ip4);
      if (sport_entropy1 && 0 == vnet_buffer (b1)->ip.flow_hash)
	vnet_buffer (b1)->ip.flow_hash =
	  ip_udp_compute_flow_hash (b1, payload_ip4);
    }

  vlib_buffer_advance (b0, -ec_len);
  vlib_buffer_advance (b1, -ec_len);

  if (encap_family == AF_IP4)
    {
      ip4_header_t *ip0, *ip1;
      ip_csum_t sum0, sum1;
      u16 old_l0 = 0, old_l1 = 0;

      ip0 = (ip4_header_t *) vlib_buffer_get_current (b0);
      ip1 = (ip4_header_t *) vlib_buffer_get_current (b1);

      /* Apply the encap string */
      clib_memcpy_fast (ip0, ec0, ec_len);
      clib_memcpy_fast (ip1, ec1, ec_len);

      /* fix the <bleep>ing outer-IP checksum */
      sum0 = ip0->checksum;
      sum1 = ip1->checksum;

      /* old_l0 always 0, see the rewrite setup */
      new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
      new_l1 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b1));

      sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
			     length /* changed member */ );
      sum1 = ip_csum_update (sum1, old_l1, new_l1, ip4_header_t,
			     length /* changed member */ );

      ip0->checksum = ip_csum_fold (sum0);
      ip1->checksum = ip_csum_fold (sum1);

      ip0->length = new_l0;
      ip1->length = new_l1;

      /* Fix UDP length */
      udp0 = (udp_header_t *) (ip0 + 1);
      udp1 = (udp_header_t *) (ip1 + 1);

      new_l0 =
	clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
			      sizeof (*ip0));
      new_l1 =
	clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b1) -
			      sizeof (*ip1));
      udp0->length = new_l0;
      udp1->length = new_l1;

      if (sport_entropy0)
	udp0->src_port = ip_udp_sport_entropy (b0);
      if (sport_entropy1)
	udp1->src_port = ip_udp_sport_entropy (b1);
    }
  else
    {
      ip6_header_t *ip0, *ip1;
      int bogus0, bogus1;

      ip0 = (ip6_header_t *) vlib_buffer_get_current (b0);
      ip1 = (ip6_header_t *) vlib_buffer_get_current (b1);

      /* Apply the encap string. */
      clib_memcpy_fast (ip0, ec0, ec_len);
      clib_memcpy_fast (ip1, ec1, ec_len);

      new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0)
				     - sizeof (*ip0));
      new_l1 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b1)
				     - sizeof (*ip1));
      ip0->payload_length = new_l0;
      ip1->payload_length = new_l1;

      /* Fix UDP length */
      udp0 = (udp_header_t *) (ip0 + 1);
      udp1 = (udp_header_t *) (ip1 + 1);

      udp0->length = new_l0;
      udp1->length = new_l1;

      if (sport_entropy0)
	udp0->src_port = ip_udp_sport_entropy (b0);
      if (sport_entropy1)
	udp1->src_port = ip_udp_sport_entropy (b1);

      udp0->checksum =
	ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip0, &bogus0);
      udp1->checksum =
	ip6_tcp_udp_icmp_compute_checksum (vm, b1, ip1, &bogus1);
      ASSERT (bogus0 == 0);
      ASSERT (bogus1 == 0);

      if (udp0->checksum == 0)
	udp0->checksum = 0xffff;
      if (udp1->checksum == 0)
	udp1->checksum = 0xffff;
    }
}

#endif /* SRC_VNET_UDP_UDP_INLINES_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
