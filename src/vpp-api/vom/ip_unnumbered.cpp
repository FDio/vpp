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
#include "vom/ip_unnumbered.hpp"

using namespace VOM;

/**
 * A DB of all LLDP configs
 */
singular_db<ip_unnumbered::key_t, ip_unnumbered> ip_unnumbered::m_db;

ip_unnumbered::event_handler ip_unnumbered::m_evh;

ip_unnumbered::ip_unnumbered(const interface &itf,
                             const interface &l3_itf)
  : m_itf(itf.singular()), m_l3_itf(l3_itf.singular())
{
}

ip_unnumbered::ip_unnumbered(const ip_unnumbered &o)
  : m_itf(o.m_itf), m_l3_itf(o.m_l3_itf), m_config(o.m_config)
{
}

ip_unnumbered::~ip_unnumbered()
{
    sweep();

    // not in the DB anymore.
    m_db.release(m_itf->key(), this);
}

void ip_unnumbered::sweep()
{
    if (m_config)
    {
        HW::enqueue(new unconfig_cmd(m_config, m_itf->handle(), m_l3_itf->handle()));
    }
    HW::write();
}

void ip_unnumbered::dump(std::ostream &os)
{
    m_db.dump(os);
}

void ip_unnumbered::replay()
{
    if (m_config)
    {
        HW::enqueue(new config_cmd(m_config, m_itf->handle(), m_l3_itf->handle()));
    }
}

std::string ip_unnumbered::to_string() const
{
    std::ostringstream s;
    s << "IP Unnumbered-config:"
      << " itf:" << m_itf->to_string()
      << " l3-itf:" << m_l3_itf->to_string();

    return (s.str());
}

void ip_unnumbered::update(const ip_unnumbered &desired)
{
    if (!m_config)
    {
        HW::enqueue(new config_cmd(m_config, m_itf->handle(), m_l3_itf->handle()));
    }
}

std::shared_ptr<ip_unnumbered> ip_unnumbered::find_or_add(const ip_unnumbered &temp)
{
    return (m_db.find_or_add(temp.m_itf->key(), temp));
}

std::shared_ptr<ip_unnumbered> ip_unnumbered::singular() const
{
    return find_or_add(*this);
}

ip_unnumbered::event_handler::event_handler()
{
    OM::register_listener(this);
    inspect::register_handler({"ip-un"}, "IP unnumbered configurations", this);
}

void ip_unnumbered::event_handler::handle_replay()
{
    m_db.replay();
}

void ip_unnumbered::event_handler::handle_populate(const client_db::key_t &key)
{
    // VPP provides no dump for IP unnumbered
}

dependency_t ip_unnumbered::event_handler::order() const
{
    return (dependency_t::BINDING);
}

void ip_unnumbered::event_handler::show(std::ostream &os)
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
