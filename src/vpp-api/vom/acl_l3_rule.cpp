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

#include <sstream>

#include "vom/acl_l3_rule.hpp"

namespace VOM {
namespace ACL {
l3_rule::l3_rule(uint32_t priority,
                 const action_t& action,
                 const route::prefix_t& src,
                 const route::prefix_t& dst)
  : m_priority(priority)
  , m_action(action)
  , m_src(src)
  , m_dst(dst)
  , m_proto(0)
  , m_srcport_or_icmptype_first(0)
  , m_srcport_or_icmptype_last(0)
  , m_dstport_or_icmpcode_first(0)
  , m_dstport_or_icmpcode_last(0)
  , m_tcp_flags_mask(0)
  , m_tcp_flags_value(0)
{
}

bool
l3_rule::operator<(const l3_rule& other) const
{
  return (other.m_priority < m_priority);
}

bool
l3_rule::operator==(const l3_rule& rule) const
{
  return ((m_action == rule.m_action) && (m_src == rule.m_src) &&
          (m_dst == rule.m_dst) && (m_proto == rule.m_proto) &&
          (m_srcport_or_icmptype_first == rule.m_srcport_or_icmptype_first) &&
          (m_srcport_or_icmptype_last == rule.m_srcport_or_icmptype_last) &&
          (m_dstport_or_icmpcode_first == rule.m_dstport_or_icmpcode_first) &&
          (m_dstport_or_icmpcode_last == rule.m_dstport_or_icmpcode_last) &&
          (m_tcp_flags_mask == rule.m_tcp_flags_mask) &&
          (m_tcp_flags_value == rule.m_tcp_flags_value));
}

std::string
l3_rule::to_string() const
{
  std::ostringstream s;

  s << "L3-rule:["
    << "priority:" << m_priority << " action:" << m_action.to_string()
    << " src:" << m_src.to_string() << " dst:" << m_dst.to_string()
    << " proto:" << std::to_string(m_proto)
    << " srcportfrom:" << m_srcport_or_icmptype_first
    << " srcportto: " << m_srcport_or_icmptype_last
    << " dstportfrom:" << m_dstport_or_icmpcode_first
    << " dstportto:" << m_dstport_or_icmpcode_last
    << " tcpflagmask:" << m_tcp_flags_mask
    << " tcpflagvalue:" << m_tcp_flags_value << "]";

  return (s.str());
}

void
l3_rule::set_src_ip(route::prefix_t src)
{
  m_src = src;
}

void
l3_rule::set_dst_ip(route::prefix_t dst)
{
  m_dst = dst;
}

void
l3_rule::set_proto(uint8_t proto)
{
  m_proto = proto;
}
void
l3_rule::set_src_from_port(uint16_t srcport_or_icmptype_first)
{
  m_srcport_or_icmptype_first = srcport_or_icmptype_first;
}

void
l3_rule::set_src_to_port(uint16_t srcport_or_icmptype_last)
{
  m_srcport_or_icmptype_last = srcport_or_icmptype_last;
}

void
l3_rule::set_dst_from_port(uint16_t dstport_or_icmpcode_first)
{
  m_dstport_or_icmpcode_first = dstport_or_icmpcode_first;
}

void
l3_rule::set_dst_to_port(uint16_t dstport_or_icmpcode_last)
{
  m_dstport_or_icmpcode_last = dstport_or_icmpcode_last;
}

void
l3_rule::set_tcp_flags_mask(uint8_t tcp_flags_mask)
{
  m_tcp_flags_mask = tcp_flags_mask;
}

void
l3_rule::set_tcp_flags_value(uint8_t tcp_flags_value)
{
  m_tcp_flags_value = tcp_flags_value;
}

const route::prefix_t&
l3_rule::src() const
{
  return m_src;
}

uint32_t
l3_rule::priority() const
{
  return m_priority;
}

action_t
l3_rule::action() const
{
  return m_action;
}

const route::prefix_t&
l3_rule::dst() const
{
  return m_dst;
}

uint8_t
l3_rule::proto() const
{
  return m_proto;
}

uint16_t
l3_rule::srcport_or_icmptype_first() const
{
  return m_srcport_or_icmptype_first;
}

uint16_t
l3_rule::srcport_or_icmptype_last() const
{
  return m_srcport_or_icmptype_last;
}

uint16_t
l3_rule::dstport_or_icmpcode_first() const
{
  return m_dstport_or_icmpcode_first;
}

uint16_t
l3_rule::dstport_or_icmpcode_last() const
{
  return m_dstport_or_icmpcode_last;
}

uint8_t
l3_rule::tcp_flags_mask() const
{
  return m_tcp_flags_mask;
}

uint8_t
l3_rule::tcp_flags_value() const
{
  return m_tcp_flags_value;
}

}; // namespace ACL
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
