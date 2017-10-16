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
#include "vom/lldp_global.hpp"

using namespace VOM;

/**
 * A DB of all LLDP configs
 */
singular_db<std::string, lldp_global> lldp_global::m_db;

lldp_global::event_handler lldp_global::m_evh;

lldp_global::lldp_global(const std::string &system_name,
                         uint32_t tx_hold,
                         uint32_t tx_interval)
  : m_system_name(system_name), m_tx_hold(tx_hold), m_tx_interval(tx_interval)
{
}

lldp_global::lldp_global(const lldp_global &o)
  : m_system_name(o.m_system_name), m_tx_hold(o.m_tx_hold), m_tx_interval(o.m_tx_interval)
{
}

lldp_global::~lldp_global()
{
    sweep();

    // not in the DB anymore.
    m_db.release(m_system_name, this);
}

void lldp_global::sweep()
{
    // no means to remove this in VPP
}

void lldp_global::dump(std::ostream &os)
{
    m_db.dump(os);
}

void lldp_global::replay()
{
    if (m_binding)
    {
        HW::enqueue(new config_cmd(m_binding, m_system_name, m_tx_hold, m_tx_interval));
    }
}

std::string lldp_global::to_string() const
{
    std::ostringstream s;
    s << "LLDP-global:"
      << " system_name:" << m_system_name
      << " tx-hold:" << m_tx_hold
      << " tx-interval:" << m_tx_interval;

    return (s.str());
}

void lldp_global::update(const lldp_global &desired)
{
    if (!m_binding)
    {
        HW::enqueue(new config_cmd(m_binding, m_system_name, m_tx_hold, m_tx_interval));
    }
}

std::shared_ptr<lldp_global> lldp_global::find_or_add(const lldp_global &temp)
{
    return (m_db.find_or_add(temp.m_system_name, temp));
}

std::shared_ptr<lldp_global> lldp_global::singular() const
{
    return find_or_add(*this);
}

lldp_global::event_handler::event_handler()
{
    OM::register_listener(this);
    inspect::register_handler({"lldp-global"}, "LLDP global configurations", this);
}

void lldp_global::event_handler::handle_replay()
{
    m_db.replay();
}

void lldp_global::event_handler::handle_populate(const client_db::key_t &key)
{
    // FIXME
}

dependency_t lldp_global::event_handler::order() const
{
    return (dependency_t::GLOBAL);
}

void lldp_global::event_handler::show(std::ostream &os)
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
