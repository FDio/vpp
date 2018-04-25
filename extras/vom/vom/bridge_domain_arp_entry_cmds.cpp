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

#include "vom/bridge_domain_arp_entry_cmds.hpp"

namespace VOM {
namespace bridge_domain_arp_entry_cmds {

create_cmd::create_cmd(HW::item<bool>& item,
                       uint32_t bd,
                       const mac_address_t& mac,
                       const boost::asio::ip::address& ip_addr)
  : rpc_cmd(item)
  , m_bd(bd)
  , m_mac(mac)
  , m_ip_addr(ip_addr)
{
}

bool
create_cmd::operator==(const create_cmd& other) const
{
  return ((m_mac == other.m_mac) && (m_ip_addr == other.m_ip_addr) &&
          (m_bd == other.m_bd));
}

rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.bd_id = m_bd;
  payload.is_add = 1;
  m_mac.to_bytes(payload.mac_address, 6);
  to_bytes(m_ip_addr, &payload.is_ipv6, payload.ip_address);

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return rc_t::OK;
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "bridge-domain-arp-entry-create: " << m_hw_item.to_string()
    << " bd:" << m_bd << " mac:" << m_mac.to_string()
    << " ip:" << m_ip_addr.to_string();

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<bool>& item,
                       uint32_t bd,
                       const mac_address_t& mac,
                       const boost::asio::ip::address& ip_addr)
  : rpc_cmd(item)
  , m_bd(bd)
  , m_mac(mac)
  , m_ip_addr(ip_addr)
{
}

bool
delete_cmd::operator==(const delete_cmd& other) const
{
  return ((m_mac == other.m_mac) && (m_ip_addr == other.m_ip_addr) &&
          (m_bd == other.m_bd));
}

rc_t
delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.bd_id = m_bd;
  payload.is_add = 0;
  m_mac.to_bytes(payload.mac_address, 6);
  to_bytes(m_ip_addr, &payload.is_ipv6, payload.ip_address);

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return rc_t::OK;
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "bridge-domain-arp-entry-delete: " << m_hw_item.to_string()
    << " bd:" << m_bd << " mac:" << m_mac.to_string()
    << " ip:" << m_ip_addr.to_string();

  return (s.str());
}

}; // namespace bridge_domain_arp_entry
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
