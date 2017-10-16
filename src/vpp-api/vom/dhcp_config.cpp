/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <cassert>
#include <iostream>

#include "vom/cmd.hpp"
#include "vom/dhcp_config.hpp"

using namespace VOM;

/**
 * A DB of all DHCP configs
 */
singular_db<interface::key_type, dhcp_config> dhcp_config::m_db;

dhcp_config::event_handler dhcp_config::m_evh;

dhcp_config::dhcp_config(const interface &itf,
                         const std::string &hostname)
  : m_itf(itf.singular()), m_hostname(hostname), m_client_id(l2_address_t::ZERO), m_binding(0)
{
}

dhcp_config::dhcp_config(const interface &itf,
                         const std::string &hostname,
                         const l2_address_t &client_id)
  : m_itf(itf.singular()), m_hostname(hostname), m_client_id(client_id), m_binding(0)
{
}

dhcp_config::dhcp_config(const dhcp_config &o)
  : m_itf(o.m_itf), m_hostname(o.m_hostname), m_client_id(o.m_client_id), m_binding(0)
{
}

dhcp_config::~dhcp_config()
{
    sweep();

    // not in the DB anymore.
    m_db.release(m_itf->key(), this);
}

void dhcp_config::sweep()
{
    if (m_binding)
    {
        HW::enqueue(new unbind_cmd(m_binding, m_itf->handle(), m_hostname));
    }
    HW::write();
}

void dhcp_config::dump(std::ostream &os)
{
    m_db.dump(os);
}

void dhcp_config::replay()
{
    if (m_binding)
    {
        HW::enqueue(new bind_cmd(m_binding, m_itf->handle(), m_hostname, m_client_id));
    }
}

std::string dhcp_config::to_string() const
{
    std::ostringstream s;
    s << "Dhcp-config: " << m_itf->to_string()
      << " hostname:" << m_hostname
      << " client_id:[" << m_client_id
      << "] "
      << m_binding.to_string();

    return (s.str());
}

void dhcp_config::update(const dhcp_config &desired)
{
    /*
     * the desired state is always that the interface should be created
     */
    if (!m_binding)
    {
        HW::enqueue(new bind_cmd(m_binding, m_itf->handle(), m_hostname, m_client_id));
    }
}

std::shared_ptr<dhcp_config> dhcp_config::find_or_add(const dhcp_config &temp)
{
    return (m_db.find_or_add(temp.m_itf->key(), temp));
}

std::shared_ptr<dhcp_config> dhcp_config::singular() const
{
    return find_or_add(*this);
}

dhcp_config::event_listener::event_listener()
  : m_status(rc_t::NOOP)
{
}

HW::item<bool> &dhcp_config::event_listener::status()
{
    return (m_status);
}

dhcp_config::event_handler::event_handler()
{
    OM::register_listener(this);
    inspect::register_handler({"dhcp"}, "DHCP configurations", this);
}

void dhcp_config::event_handler::handle_replay()
{
    m_db.replay();
}

void dhcp_config::event_handler::handle_populate(const client_db::key_t &key)
{
    // FIXME
}

dependency_t dhcp_config::event_handler::order() const
{
    return (dependency_t::BINDING);
}

void dhcp_config::event_handler::show(std::ostream &os)
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
