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

#include "vom/acl_l2_rule.hpp"

namespace VOM {
namespace ACL {

l2_rule::l2_rule(uint32_t priority,
                 const action_t& action,
                 const route::prefix_t& ip,
                 const mac_address_t& mac,
                 const mac_address_t& mac_mask)
  : m_priority(priority)
  , m_action(action)
  , m_src_ip(ip)
  , m_mac(mac)
  , m_mac_mask(mac_mask)
{
}

bool
l2_rule::operator<(const l2_rule& other) const
{
  return (other.m_priority < m_priority);
}

bool
l2_rule::operator==(const l2_rule& rule) const
{
  return ((m_action == rule.m_action) && (m_src_ip == rule.m_src_ip) &&
          (m_mac == rule.m_mac) && (m_mac_mask == rule.m_mac_mask));
}

std::string
l2_rule::to_string() const
{
  std::ostringstream s;

  s << "L2-rule:["
    << "priority:" << m_priority << " action:" << m_action.to_string()
    << " ip:" << m_src_ip.to_string() << " mac:" << m_mac
    << " mac-mask:" << m_mac_mask << "]";

  return (s.str());
}

uint32_t
l2_rule::priority() const
{
  return m_priority;
}

action_t
l2_rule::action() const
{
  return m_action;
}

const route::prefix_t&
l2_rule::src_ip() const
{
  return m_src_ip;
}

const mac_address_t&
l2_rule::mac() const
{
  return m_mac;
}

const mac_address_t&
l2_rule::mac_mask() const
{
  return m_mac_mask;
}
}
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
