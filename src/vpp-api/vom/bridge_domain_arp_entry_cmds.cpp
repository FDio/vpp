/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <iostream>

#include "vom/bridge_domain_arp_entry.hpp"

using namespace VOM;

bridge_domain_arp_entry::create_cmd::create_cmd(HW::item<bool> &item,
                                                uint32_t bd,
                                                const mac_address_t &mac,
                                                const boost::asio::ip::address &ip_addr)
  : rpc_cmd(item), m_bd(bd), m_mac(mac), m_ip_addr(ip_addr)
{
}

bool bridge_domain_arp_entry::create_cmd::operator==(const create_cmd &other) const
{
    return ((m_mac == other.m_mac) &&
            (m_ip_addr == other.m_ip_addr) &&
            (m_bd == other.m_bd));
}

rc_t bridge_domain_arp_entry::create_cmd::issue(connection &con)
{
    msg_t req(con.ctx(), std::ref(*this));

    auto &payload = req.get_request().get_payload();
    payload.bd_id = m_bd;
    payload.is_add = 1;
    m_mac.to_bytes(payload.mac_address, 6);
    to_bytes(m_ip_addr,
             &payload.is_ipv6,
             payload.ip_address);

    VAPI_CALL(req.execute());

    m_hw_item.set(wait());

    return rc_t::OK;
}

std::string bridge_domain_arp_entry::create_cmd::to_string() const
{
    std::ostringstream s;
    s << "bridge-domain-arp-entry-create: " << m_hw_item.to_string()
      << " bd:" << m_bd
      << " mac:" << m_mac.to_string()
      << " ip:" << m_ip_addr.to_string();

    return (s.str());
}

bridge_domain_arp_entry::delete_cmd::delete_cmd(HW::item<bool> &item,
                                                uint32_t bd,
                                                const mac_address_t &mac,
                                                const boost::asio::ip::address &ip_addr)
  : rpc_cmd(item), m_bd(bd), m_mac(mac), m_ip_addr(ip_addr)
{
}

bool bridge_domain_arp_entry::delete_cmd::operator==(const delete_cmd &other) const
{
    return ((m_mac == other.m_mac) &&
            (m_ip_addr == other.m_ip_addr) &&
            (m_bd == other.m_bd));
}

rc_t bridge_domain_arp_entry::delete_cmd::issue(connection &con)
{
    msg_t req(con.ctx(), std::ref(*this));

    auto &payload = req.get_request().get_payload();
    payload.bd_id = m_bd;
    payload.is_add = 0;
    m_mac.to_bytes(payload.mac_address, 6);
    to_bytes(m_ip_addr,
             &payload.is_ipv6,
             payload.ip_address);

    VAPI_CALL(req.execute());

    wait();
    m_hw_item.set(rc_t::NOOP);

    return rc_t::OK;
}

std::string bridge_domain_arp_entry::delete_cmd::to_string() const
{
    std::ostringstream s;
    s << "bridge-domain-arp-entry-delete: " << m_hw_item.to_string()
      << " bd:" << m_bd
      << " mac:" << m_mac.to_string()
      << " ip:" << m_ip_addr.to_string();

    return (s.str());
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
