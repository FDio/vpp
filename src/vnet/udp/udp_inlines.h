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

always_inline void *
vlib_buffer_push_udp (vlib_buffer_t * b, u16 sp, u16 dp, u8 offload_csum)
{
  udp_header_t *uh;
  u16 udp_len = sizeof (udp_header_t) + b->current_length;
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID))
    udp_len += b->total_length_not_including_first_buffer;

  uh = vlib_buffer_push_uninit (b, sizeof (udp_header_t));
  uh->src_port = sp;
  uh->dst_port = dp;
  uh->checksum = 0;
  uh->length = clib_host_to_net_u16 (udp_len);
  if (offload_csum)
    {
      vnet_buffer_offload_flags_set (b, VNET_BUFFER_OFFLOAD_F_UDP_CKSUM);
    }
  vnet_buffer (b)->l4_hdr_offset = (u8 *) uh - b->data;
  b->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
  return uh;
}

always_inline void
ip_udp_fixup_one (vlib_main_t * vm, vlib_buffer_t * b0, u8 is_ip4)
{
  u16 new_l0;
  udp_header_t *udp0;

  if (is_ip4)
    {
      ip4_header_t *ip0;
      ip_csum_t sum0;
      u16 old_l0 = 0;

      ip0 = vlib_buffer_get_current (b0);

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
    }
  else
    {
      ip6_header_t *ip0;
      int bogus0;

      ip0 = vlib_buffer_get_current (b0);

      new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0)
				     - sizeof (*ip0));
      ip0->payload_length = new_l0;

      /* Fix UDP length */
      udp0 = (udp_header_t *) (ip0 + 1);
      udp0->length = new_l0;

      udp0->checksum =
	ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip0, &bogus0);
      ASSERT (bogus0 == 0);

      if (udp0->checksum == 0)
	udp0->checksum = 0xffff;
    }
}

always_inline void
ip_udp_encap_one (vlib_main_t * vm, vlib_buffer_t * b0, u8 * ec0, word ec_len,
		  u8 is_ip4)
{
  vlib_buffer_advance (b0, -ec_len);

  if (is_ip4)
    {
      ip4_header_t *ip0;

      ip0 = vlib_buffer_get_current (b0);

      /* Apply the encap string. */
      clib_memcpy_fast (ip0, ec0, ec_len);
      ip_udp_fixup_one (vm, b0, 1);
    }
  else
    {
      ip6_header_t *ip0;

      ip0 = vlib_buffer_get_current (b0);

      /* Apply the encap string. */
      clib_memcpy_fast (ip0, ec0, ec_len);
      ip_udp_fixup_one (vm, b0, 0);
    }
}

always_inline void
ip_udp_encap_two (vlib_main_t * vm, vlib_buffer_t * b0, vlib_buffer_t * b1,
		  u8 * ec0, u8 * ec1, word ec_len, u8 is_v4)
{
  u16 new_l0, new_l1;
  udp_header_t *udp0, *udp1;

  ASSERT (_vec_len (ec0) == _vec_len (ec1));

  vlib_buffer_advance (b0, -ec_len);
  vlib_buffer_advance (b1, -ec_len);

  if (is_v4)
    {
      ip4_header_t *ip0, *ip1;
      ip_csum_t sum0, sum1;
      u16 old_l0 = 0, old_l1 = 0;

      ip0 = vlib_buffer_get_current (b0);
      ip1 = vlib_buffer_get_current (b1);

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
    }
  else
    {
      ip6_header_t *ip0, *ip1;
      int bogus0, bogus1;

      ip0 = vlib_buffer_get_current (b0);
      ip1 = vlib_buffer_get_current (b1);

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
