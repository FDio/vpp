/*
 * Copyright (c) 2025 and/or its affiliates.
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

#include <wireguard/wireguard_transport.h>
#include <vnet/ip/ip.h>

u8 *
format_wg_transport_type (u8 *s, va_list *va)
{
  wg_transport_type_t transport = va_arg (*va, wg_transport_type_t);

  switch (transport)
    {
    case WG_TRANSPORT_UDP:
      s = format (s, "UDP");
      break;
    case WG_TRANSPORT_TCP:
      s = format (s, "TCP");
      break;
    default:
      s = format (s, "Unknown");
      break;
    }

  return s;
}

u8 *
format_ip4_tcp_header (u8 *s, va_list *va)
{
  ip4_tcp_header_t *h = va_arg (*va, ip4_tcp_header_t *);

  s = format (s, "IP4: %U -> %U\n",
              format_ip4_address, &h->ip4.src_address,
              format_ip4_address, &h->ip4.dst_address);
  s = format (s, "TCP: %d -> %d seq %u ack %u",
              clib_net_to_host_u16 (h->tcp.src_port),
              clib_net_to_host_u16 (h->tcp.dst_port),
              clib_net_to_host_u32 (h->tcp.seq_number),
              clib_net_to_host_u32 (h->tcp.ack_number));

  return s;
}

u8 *
format_ip6_tcp_header (u8 *s, va_list *va)
{
  ip6_tcp_header_t *h = va_arg (*va, ip6_tcp_header_t *);

  s = format (s, "IP6: %U -> %U\n",
              format_ip6_address, &h->ip6.src_address,
              format_ip6_address, &h->ip6.dst_address);
  s = format (s, "TCP: %d -> %d seq %u ack %u",
              clib_net_to_host_u16 (h->tcp.src_port),
              clib_net_to_host_u16 (h->tcp.dst_port),
              clib_net_to_host_u32 (h->tcp.seq_number),
              clib_net_to_host_u32 (h->tcp.ack_number));

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
