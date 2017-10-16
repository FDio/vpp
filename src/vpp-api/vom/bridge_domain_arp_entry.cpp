/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "vom/bridge_domain_arp_entry.hpp"

using namespace VOM;

VOM::singular_db<bridge_domain_arp_entry::key_t, bridge_domain_arp_entry> bridge_domain_arp_entry::m_db;

bridge_domain_arp_entry::event_handler bridge_domain_arp_entry::m_evh;

bridge_domain_arp_entry::bridge_domain_arp_entry(const bridge_domain &bd,
                                                 const mac_address_t &mac,
                                                 const boost::asio::ip::address &ip_addr)
  : m_hw(false), m_bd(bd.singular()), m_mac(mac), m_ip_addr(ip_addr)
{
}

bridge_domain_arp_entry::bridge_domain_arp_entry(const mac_address_t &mac,
                                                 const boost::asio::ip::address &ip_addr)
  : m_hw(false), m_bd(nullptr), m_mac(mac), m_ip_addr(ip_addr)
{
    /*
     * the route goes in the default table
     */
    bridge_domain bd(bridge_domain::DEFAULT_TABLE);

    m_bd = bd.singular();
}

bridge_domain_arp_entry::bridge_domain_arp_entry(const bridge_domain_arp_entry &bde)
  : m_hw(bde.m_hw), m_bd(bde.m_bd), m_mac(bde.m_mac), m_ip_addr(bde.m_ip_addr)
{
}

bridge_domain_arp_entry::~bridge_domain_arp_entry()
{
    sweep();

    // not in the DB anymore.
    m_db.release(std::make_tuple(m_bd->id(), m_mac, m_ip_addr), this);
}

void bridge_domain_arp_entry::sweep()
{
    if (m_hw)
    {
        HW::enqueue(new delete_cmd(m_hw, m_bd->id(), m_mac, m_ip_addr));
    }
    HW::write();
}

void bridge_domain_arp_entry::replay()
{
    if (m_hw)
    {
        HW::enqueue(new create_cmd(m_hw, m_bd->id(), m_mac, m_ip_addr));
    }
}

std::string bridge_domain_arp_entry::to_string() const
{
    std::ostringstream s;
    s << "bridge-domain-arp-entry:["
      << m_bd->to_string()
      << ", "
      << m_mac.to_string()
      << ", "
      << m_ip_addr.to_string()
      << "]";

    return (s.str());
}

void bridge_domain_arp_entry::update(const bridge_domain_arp_entry &r)
{
    /*
     * create the table if it is not yet created
     */
    if (rc_t::OK != m_hw.rc())
    {
        HW::enqueue(new create_cmd(m_hw, m_bd->id(), m_mac, m_ip_addr));
    }
}

std::shared_ptr<bridge_domain_arp_entry> bridge_domain_arp_entry::find_or_add(const bridge_domain_arp_entry &temp)
{
    return (m_db.find_or_add(std::make_tuple(temp.m_bd->id(),
                                             temp.m_mac,
                                             temp.m_ip_addr),
                             temp));
}

std::shared_ptr<bridge_domain_arp_entry> bridge_domain_arp_entry::singular() const
{
    return find_or_add(*this);
}

void bridge_domain_arp_entry::dump(std::ostream &os)
{
    m_db.dump(os);
}

std::ostream &VOM::operator<<(std::ostream &os,
                              const bridge_domain_arp_entry::key_t &key)
{
    os << "[" << std::get<0>(key)
       << ", " << std::get<1>(key)
       << ", " << std::get<2>(key)
       << "]";

    return (os);
}

bridge_domain_arp_entry::event_handler::event_handler()
{
    OM::register_listener(this);
    inspect::register_handler({"bd-arp"}, "bridge domain ARP termination entries", this);
}

void bridge_domain_arp_entry::event_handler::handle_replay()
{
    m_db.replay();
}

void bridge_domain_arp_entry::event_handler::handle_populate(const client_db::key_t &key)
{
}

dependency_t bridge_domain_arp_entry::event_handler::order() const
{
    return (dependency_t::ENTRY);
}

void bridge_domain_arp_entry::event_handler::show(std::ostream &os)
{
    m_db.dump(os);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
