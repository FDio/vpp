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

#include "vom/bridge_domain_arp_entry.hpp"
#include "vom/bridge_domain_arp_entry_cmds.hpp"

namespace VOM {

singular_db<bridge_domain_arp_entry::key_t, bridge_domain_arp_entry>
  bridge_domain_arp_entry::m_db;

bridge_domain_arp_entry::event_handler bridge_domain_arp_entry::m_evh;

bridge_domain_arp_entry::bridge_domain_arp_entry(
  const bridge_domain& bd,
  const boost::asio::ip::address& ip_addr,
  const mac_address_t& mac)
  : m_hw(false)
  , m_bd(bd.singular())
  , m_ip_addr(ip_addr)
  , m_mac(mac)
{
}

bridge_domain_arp_entry::bridge_domain_arp_entry(
  const boost::asio::ip::address& ip_addr,
  const mac_address_t& mac)
  : m_hw(false)
  , m_bd(nullptr)
  , m_ip_addr(ip_addr)
  , m_mac(mac)
{
  /*
 * the route goes in the default table
 */
  bridge_domain bd(bridge_domain::DEFAULT_TABLE);

  m_bd = bd.singular();
}

bridge_domain_arp_entry::bridge_domain_arp_entry(
  const bridge_domain_arp_entry& bde)
  : m_hw(bde.m_hw)
  , m_bd(bde.m_bd)
  , m_ip_addr(bde.m_ip_addr)
  , m_mac(bde.m_mac)
{
}

bridge_domain_arp_entry::~bridge_domain_arp_entry()
{
  sweep();

  // not in the DB anymore.
  m_db.release(key(), this);
}

const bridge_domain_arp_entry::key_t
bridge_domain_arp_entry::key() const
{
  return (std::make_pair(m_bd->key(), m_ip_addr));
}

bool
bridge_domain_arp_entry::operator==(const bridge_domain_arp_entry& bdae) const
{
  return ((key() == bdae.key()) && (m_mac == bdae.m_mac));
}

void
bridge_domain_arp_entry::sweep()
{
  if (m_hw) {
    HW::enqueue(new bridge_domain_arp_entry_cmds::delete_cmd(m_hw, m_bd->id(),
                                                             m_mac, m_ip_addr));
  }
  HW::write();
}

void
bridge_domain_arp_entry::replay()
{
  if (m_hw) {
    HW::enqueue(new bridge_domain_arp_entry_cmds::create_cmd(m_hw, m_bd->id(),
                                                             m_mac, m_ip_addr));
  }
}

std::string
bridge_domain_arp_entry::to_string() const
{
  std::ostringstream s;
  s << "bridge-domain-arp-entry:[" << m_bd->to_string() << ", "
    << m_mac.to_string() << ", " << m_ip_addr.to_string() << "]";

  return (s.str());
}

void
bridge_domain_arp_entry::update(const bridge_domain_arp_entry& r)
{
  /*
 * create the table if it is not yet created
 */
  if (rc_t::OK != m_hw.rc()) {
    HW::enqueue(new bridge_domain_arp_entry_cmds::create_cmd(m_hw, m_bd->id(),
                                                             m_mac, m_ip_addr));
  }
}

std::shared_ptr<bridge_domain_arp_entry>
bridge_domain_arp_entry::find_or_add(const bridge_domain_arp_entry& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<bridge_domain_arp_entry>
bridge_domain_arp_entry::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<bridge_domain_arp_entry>
bridge_domain_arp_entry::singular() const
{
  return find_or_add(*this);
}

void
bridge_domain_arp_entry::dump(std::ostream& os)
{
  m_db.dump(os);
}

bridge_domain_arp_entry::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "bd-arp" },
                            "bridge domain ARP termination entries", this);
}

void
bridge_domain_arp_entry::event_handler::handle_replay()
{
  m_db.replay();
}

void
bridge_domain_arp_entry::event_handler::handle_populate(
  const client_db::key_t& key)
{
}

dependency_t
bridge_domain_arp_entry::event_handler::order() const
{
  return (dependency_t::ENTRY);
}

void
bridge_domain_arp_entry::event_handler::show(std::ostream& os)
{
  m_db.dump(os);
}
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
