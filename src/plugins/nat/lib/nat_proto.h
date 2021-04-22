/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#ifndef included_nat_proto_h__
#define included_nat_proto_h__

#include <vnet/ip/ip.h>

#define foreach_nat_protocol                                                  \
  _ (OTHER, 0, other, "other")                                                \
  _ (UDP, 1, udp, "udp")                                                      \
  _ (TCP, 2, tcp, "tcp")                                                      \
  _ (ICMP, 3, icmp, "icmp")

typedef enum
{
#define _(N, i, n, s) NAT_PROTOCOL_##N = i,
  foreach_nat_protocol
#undef _
} nat_protocol_t;

always_inline nat_protocol_t
ip_proto_to_nat_proto (u8 ip_proto)
{
  static const nat_protocol_t lookup_table[256] = {
    [IP_PROTOCOL_TCP] = NAT_PROTOCOL_TCP,
    [IP_PROTOCOL_UDP] = NAT_PROTOCOL_UDP,
    [IP_PROTOCOL_ICMP] = NAT_PROTOCOL_ICMP,
    [IP_PROTOCOL_ICMP6] = NAT_PROTOCOL_ICMP,
  };

  return lookup_table[ip_proto];
}

static_always_inline u8
nat_proto_to_ip_proto (nat_protocol_t nat_proto)
{
  ASSERT (nat_proto <= NAT_PROTOCOL_ICMP);

  static const u8 lookup_table[256] = {
    [NAT_PROTOCOL_OTHER] = ~0,
    [NAT_PROTOCOL_TCP] = IP_PROTOCOL_TCP,
    [NAT_PROTOCOL_UDP] = IP_PROTOCOL_UDP,
    [NAT_PROTOCOL_ICMP] = IP_PROTOCOL_ICMP,
  };

  ASSERT (NAT_PROTOCOL_OTHER == nat_proto || NAT_PROTOCOL_TCP == nat_proto ||
	  NAT_PROTOCOL_UDP == nat_proto || NAT_PROTOCOL_ICMP == nat_proto);

  return lookup_table[nat_proto];
}

u8 *format_nat_protocol (u8 *s, va_list *args);

uword unformat_nat_protocol (unformat_input_t *input, va_list *args);

#endif /* included_nat_proto_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
