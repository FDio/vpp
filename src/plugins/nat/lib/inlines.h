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
/**
 * @brief Common NAT inline functions
 */
#ifndef included_nat_inlines_h__
#define included_nat_inlines_h__

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

  ASSERT (NAT_PROTOCOL_OTHER == nat_proto || NAT_PROTOCOL_TCP == nat_proto
	  || NAT_PROTOCOL_UDP == nat_proto || NAT_PROTOCOL_ICMP == nat_proto);

  return lookup_table[nat_proto];
}

static_always_inline int
icmp_type_is_error_message (u8 icmp_type)
{
  int bmp = 0;
  bmp |= 1 << ICMP4_destination_unreachable;
  bmp |= 1 << ICMP4_time_exceeded;
  bmp |= 1 << ICMP4_parameter_problem;
  bmp |= 1 << ICMP4_source_quench;
  bmp |= 1 << ICMP4_redirect;
  bmp |= 1 << ICMP4_alternate_host_address;

  return (1ULL << icmp_type) & bmp;
}

#endif /* included_nat_inlines_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
