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

using namespace VOM::ACL;

l3_rule::l3_rule(uint32_t priority,
                 const action_t &action,
                 const route::prefix_t &src,
                 const route::prefix_t &dst)
  : m_priority(priority), m_action(action), m_src(src), m_dst(dst), proto(0), srcport_or_icmptype_first(0), srcport_or_icmptype_last(0), dstport_or_icmpcode_first(0), dstport_or_icmpcode_last(0), tcp_flags_mask(0), tcp_flags_value(0)
{
}

bool l3_rule::operator<(const l3_rule &other) const
{
    return (other.m_priority < m_priority);
}

void l3_rule::to_vpp(vapi_type_acl_rule &rule) const
{
    rule.is_permit = m_action.value();
    m_src.to_vpp(&rule.is_ipv6, rule.src_ip_addr, &rule.src_ip_prefix_len);
    m_dst.to_vpp(&rule.is_ipv6, rule.dst_ip_addr, &rule.dst_ip_prefix_len);

    rule.proto = proto;
    rule.srcport_or_icmptype_first = srcport_or_icmptype_first;
    rule.srcport_or_icmptype_last = srcport_or_icmptype_last;
    rule.dstport_or_icmpcode_first = dstport_or_icmpcode_first;
    rule.dstport_or_icmpcode_last = dstport_or_icmpcode_last;

    rule.tcp_flags_mask = tcp_flags_mask;
    rule.tcp_flags_value = tcp_flags_value;
}

bool l3_rule::operator==(const l3_rule &rule) const
{
    return ((m_action == rule.m_action) &&
            (m_src == rule.m_src) &&
            (m_dst == rule.m_dst));
}

std::string l3_rule::to_string() const
{
    std::ostringstream s;

    s << "L3-rule:["
      << "priority:" << m_priority
      << " action:" << m_action.to_string()
      << " src:" << m_src.to_string()
      << " dst:" << m_dst.to_string()
      << "]";

    return (s.str());
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
