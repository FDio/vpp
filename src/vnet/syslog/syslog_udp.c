/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
/**
 * @file syslog protocol UDP transport layer implementation (RFC5426)
 */

#include <vnet/syslog/syslog_udp.h>
#include <vnet/ip/ip4.h>
#include <vnet/udp/udp_packet.h>

void
syslog_add_udp_transport (vlib_main_t * vm, u32 bi)
{
  syslog_main_t *sm = &syslog_main;
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  ip4_header_t *ip;
  udp_header_t *udp;

  vlib_buffer_advance (b, -(sizeof (ip4_header_t) + sizeof (udp_header_t)));

  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = sm->fib_index;

  ip = vlib_buffer_get_current (b);
  clib_memset (ip, 0, sizeof (*ip));
  udp = (udp_header_t *) (ip + 1);
  clib_memset (udp, 0, sizeof (*udp));

  ip->ip_version_and_header_length = 0x45;
  ip->flags_and_fragment_offset =
    clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);
  ip->ttl = 255;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = sm->src_address.as_u32;
  ip->dst_address.as_u32 = sm->collector.as_u32;

  udp->src_port = udp->dst_port = clib_host_to_net_u16 (sm->collector_port);

  const u16 ip_length = vlib_buffer_length_in_chain (vm, b);
  ip->length = clib_host_to_net_u16 (ip_length);
  ip->checksum = ip4_header_checksum (ip);

  const u16 udp_length = ip_length - (sizeof (ip4_header_t));
  udp->length = clib_host_to_net_u16 (udp_length);
  /* RFC5426 3.6. */
  udp->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip);
  if (udp->checksum == 0)
    udp->checksum = 0xffff;

  b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
