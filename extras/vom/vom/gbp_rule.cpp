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

#include <sstream>

#include "vom/gbp_rule.hpp"

namespace VOM {
gbp_rule::next_hop_t::next_hop_t(const boost::asio::ip::address& ip,
                                 const mac_address_t& mac,
                                 uint32_t bd_id,
                                 uint32_t rd_id)
  : m_ip(ip)
  , m_mac(mac)
  , m_bd_id(bd_id)
  , m_rd_id(rd_id)
{}

std::string
gbp_rule::next_hop_t::to_string() const
{
  std::ostringstream s;

  s << "["
    << "ip:" << m_ip << " mac:" << m_mac.to_string() << " bd:" << m_bd_id
    << " rd:" << m_rd_id << "],";

  return (s.str());
}

const boost::asio::ip::address&
gbp_rule::next_hop_t::getIp() const
{
  return m_ip;
}

const mac_address_t&
gbp_rule::next_hop_t::getMac() const
{
  return m_mac;
}

const uint32_t&
gbp_rule::next_hop_t::getBdId() const
{
  return m_bd_id;
}

const uint32_t&
gbp_rule::next_hop_t::getRdId() const
{
  return m_rd_id;
}

const gbp_rule::hash_mode_t gbp_rule::hash_mode_t::SRC_IP(1, "src-ip");
const gbp_rule::hash_mode_t gbp_rule::hash_mode_t::DST_IP(0, "dst-ip");

gbp_rule::hash_mode_t::hash_mode_t(int v, const std::string s)
  : enum_base(v, s)
{}

gbp_rule::next_hop_set_t::next_hop_set_t(const hash_mode_t& hm, next_hops_t nhs)
  : m_hm(hm)
  , m_nhs(nhs)
{}

std::string
gbp_rule::next_hop_set_t::to_string() const
{
  std::ostringstream s;

  s << "next-hop-set["
    << "hash-mode:" << m_hm.to_string()
    << " next-hops:[" auto it = m_nhs.cbegin();
  while (it != m_nhs.cend()) {
    s << " " << it->to_string();
    ++it;
  }
  s << " ] next-hop-size:" << m_nhs.size() << "]";

  return (s.str());
}

const gbp_rule::hash_mode_t&
gbp_rule::next_hop_set_t::getHM() const
{
  return m_hm;
}

const next_hops_t&
gbp_rule::next_hop_set_t::getNextHops() const
{
  return m_nhs;
}

const gbp_rule::action_t gbp_rule::action_t::REDIRECT(2, "redirect");
const gbp_rule::action_t gbp_rule::action_t::PERMIT(1, "permit");
const gbp_rule::action_t gbp_rule::action_t::DENY(0, "deny");

gbp_rule::action_t::action_t(int v, const std::string s)
  : enum_base(v, s)
{}

const gbp_rule::action_t&
gbp_rule::action_t::from_int(uint8_t i)
{
  if (i == 2)
    return gbp_rule::action_t::REDIRECT;
  else if (i)
    return gbp_rule::action_t::PERMIT;

  return gbp_rule::action_t::DENY;
}

const gbp_rule::action_t&
gbp_rule::action_t::from_bool(bool b, uint8_t c)
{
  if (b) {
    if (c)
      return gbp_rule::action_t::REDIRECT;
    return gbp_rule::action_t::PERMIT;
  }
  return gbp_rule::action_t::DENY;
}

gbp_rule::gbp_rule(uint32_t priority,
                   const hash_mode_t& hm,
                   const next_hops_t& nhs,
                   const action_t& a)
  : m_priority(priority)
  , m_hm(hm)
  , m_nhs(nhs)
  , m_action(a)
{}

bool
gbp_rule::operator<(const gbp_rule& other) const
{
  return (other.m_priority < m_priority);
}

bool
gbp_rule::operator==(const gbp_rule& rule) const
{
  return ((m_action == rule.m_action) && (m_hm == rule.m_hm) &&
          (m_nhs == rule.m_nhs) && (m_priority == rule.m_priority));
}

std::string
gbp_rule::to_string() const
{
  std::ostringstream s;

  s << "gbp-rule:["
    << "priority:" << m_priority << " action:" << m_action.to_string()
    << " hash-mode:" << m_hm.to_string() << " next-hop-set:[";
  auto it = m_nhs.cbegin();
  while (it != m_nhs.cend()) {
    s << " " << it->to_string();
    ++it;
  }
  s << " ] nhs-size:" << m_nhs.size()
    << "];

    return (s.str());
}

uint32_t
gbp_rule::priority() const
{
  return m_priority;
}

const gbp_rule::action_t&
gbp_rule::action() const
{
  return m_action;
}

const hash_mode_t&
gbp_rule::getHM() const
{
  return m_hm;
}

next_hops_t&
gbp_rule::nhs() const
{
  return m_nhs;
}
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
