/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef __VOM_L3_ACL_RULE_H__
#define __VOM_L3_ACL_RULE_H__

#include "vom/acl_types.hpp"
#include "vom/prefix.hpp"

namespace VOM {
namespace ACL {
/**
 * An ACL rule is the building block of an ACL. An ACL, which is
 * the object applied to an interface, is comprised of an ordersed
 * sequence of ACL rules.
 * This class is a wrapper around the VAPI generated struct and exports
 * an API with better types.
 */
class l3_rule
{
public:
  /**
   * Construct a new object matching the desried state
   */
  l3_rule(uint32_t priority,
          const action_t& action,
          const route::prefix_t& src,
          const route::prefix_t& dst);

  /**
   * Copy Constructor
   */
  l3_rule(const l3_rule& o) = default;

  /**
   * Destructor
   */
  ~l3_rule() = default;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * less-than operator
   */
  bool operator<(const l3_rule& rule) const;

  /**
   * comparison operator (for testing)
   */
  bool operator==(const l3_rule& rule) const;

  /**
   * Set Src Ip Address
   */
  void set_src_ip(route::prefix_t src);

  /**
   * Set Dst Ip Address
   */
  void set_dst_ip(route::prefix_t dst);

  /**
   *Set proto
   */
  void set_proto(uint8_t proto);

  /**
   * Set Src port or ICMP Type first
   */
  void set_src_from_port(uint16_t srcport_or_icmptype_first);

  /**
   * Set Src port or ICMP Type last
   */
  void set_src_to_port(uint16_t srcport_or_icmptype_last);

  /**
   * Set Dst port or ICMP code first
   */
  void set_dst_from_port(uint16_t dstport_or_icmpcode_first);

  /**
   * Set Dst port or ICMP code last
   */
  void set_dst_to_port(uint16_t dstport_or_icmpcode_last);

  /**
   * Set TCP flags mask
   */
  void set_tcp_flags_mask(uint8_t tcp_flags_mask);

  /**
   * Set TCP flags value
   */
  void set_tcp_flags_value(uint8_t tcp_flags_value);

  /**
   * Getters
   */
  const route::prefix_t& src() const;
  uint32_t priority() const;
  action_t action() const;
  const route::prefix_t& dst() const;
  uint8_t proto() const;
  uint16_t srcport_or_icmptype_first() const;
  uint16_t srcport_or_icmptype_last() const;
  uint16_t dstport_or_icmpcode_first() const;
  uint16_t dstport_or_icmpcode_last() const;
  uint8_t tcp_flags_mask() const;
  uint8_t tcp_flags_value() const;

private:
  /**
   * Priority. Used to sort the rules in a list in the order
   * in which they are applied
   */
  uint32_t m_priority;

  /**
   * Action on match
   */
  action_t m_action;

  /**
   * Source Prefix
   */
  route::prefix_t m_src;

  /**
   * Destination Prefix
   */
  route::prefix_t m_dst;

  /**
   * L4 protocol. IANA number. 1 = ICMP, 58 = ICMPv6, 6 = TCP, 17 =
   * UDP.
   * 0 => ignore L4 and ignore the ports/tcpflags when matching.
   */
  uint8_t m_proto;

  /**
   * If the L4 protocol is TCP or UDP, the below
   * hold ranges of ports, else if the L4 is ICMP/ICMPv6
   * they hold ranges of ICMP(v6) types/codes.
   *
   * Ranges are inclusive, i.e. to match "any" TCP/UDP port,
   * use first=0,last=65535. For ICMP(v6),
   * use first=0,last=255.
   */
  uint16_t m_srcport_or_icmptype_first;
  uint16_t m_srcport_or_icmptype_last;
  uint16_t m_dstport_or_icmpcode_first;
  uint16_t m_dstport_or_icmpcode_last;

  /*
   * for proto = 6, this matches if the
   * TCP flags in the packet, ANDed with tcp_flags_mask,
   * is equal to tcp_flags_value.
   */
  uint8_t m_tcp_flags_mask;
  uint8_t m_tcp_flags_value;
};
};
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
