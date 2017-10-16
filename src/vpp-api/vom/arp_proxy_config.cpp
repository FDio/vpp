/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <cassert>
#include <iostream>

#include "vom/arp_proxy_config.hpp"
#include "vom/cmd.hpp"

using namespace VOM;

/**
 * A DB of all LLDP configs
 */
singular_db<arp_proxy_config::key_t, arp_proxy_config> arp_proxy_config::m_db;

arp_proxy_config::event_handler arp_proxy_config::m_evh;

arp_proxy_config::arp_proxy_config(const boost::asio::ip::address_v4 &low,
                                   const boost::asio::ip::address_v4 &high)
  : m_low(low), m_high(high), m_config(true)
{
}

arp_proxy_config::arp_proxy_config(const arp_proxy_config &o)
  : m_low(o.m_low), m_high(o.m_high), m_config(o.m_config)
{
}

arp_proxy_config::~arp_proxy_config()
{
    sweep();

    // not in the DB anymore.
    m_db.release(std::make_pair(m_low, m_high), this);
}

void arp_proxy_config::sweep()
{
    if (m_config)
    {
        HW::enqueue(new unconfig_cmd(m_config, m_low, m_high));
    }
    HW::write();
}

void arp_proxy_config::dump(std::ostream &os)
{
    m_db.dump(os);
}

void arp_proxy_config::replay()
{
    if (m_config)
    {
        HW::enqueue(new config_cmd(m_config, m_low, m_high));
    }
}

std::string arp_proxy_config::to_string() const
{
    std::ostringstream s;
    s << "ARP-proxy:"
      << " low:" << m_low.to_string()
      << " high:" << m_high.to_string();

    return (s.str());
}

void arp_proxy_config::update(const arp_proxy_config &desired)
{
    if (!m_config)
    {
        HW::enqueue(new config_cmd(m_config, m_low, m_high));
    }
}

std::shared_ptr<arp_proxy_config> arp_proxy_config::find_or_add(const arp_proxy_config &temp)
{
    return (m_db.find_or_add(std::make_pair(temp.m_low, temp.m_high), temp));
}

std::shared_ptr<arp_proxy_config> arp_proxy_config::singular() const
{
    return find_or_add(*this);
}

arp_proxy_config::event_handler::event_handler()
{
    OM::register_listener(this);
    inspect::register_handler({"arp-proxy"}, "ARP Proxy configurations", this);
}

void arp_proxy_config::event_handler::handle_replay()
{
    m_db.replay();
}

void arp_proxy_config::event_handler::handle_populate(const client_db::key_t &key)
{
    // VPP provides no dump for ARP proxy.
}

dependency_t arp_proxy_config::event_handler::order() const
{
    return (dependency_t::GLOBAL);
}

void arp_proxy_config::event_handler::show(std::ostream &os)
{
    m_db.dump(os);
}

std::ostream &VOM::operator<<(std::ostream &os, const arp_proxy_config::key_t &key)
{
    os << "["
       << key.first
       << ", "
       << key.second
       << "]";

    return (os);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
