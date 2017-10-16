/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <cassert>
#include <iostream>

#include "vom/arp_proxy_binding.hpp"
#include "vom/cmd.hpp"

using namespace VOM;

/**
 * A DB of all LLDP configs
 */
singular_db<interface::key_type, arp_proxy_binding> arp_proxy_binding::m_db;

arp_proxy_binding::event_handler arp_proxy_binding::m_evh;

arp_proxy_binding::arp_proxy_binding(const interface &itf,
                                     const arp_proxy_config &proxy_cfg)
  : m_itf(itf.singular()), m_arp_proxy_cfg(proxy_cfg.singular()), m_binding(true)
{
}

arp_proxy_binding::arp_proxy_binding(const arp_proxy_binding &o)
  : m_itf(o.m_itf), m_arp_proxy_cfg(o.m_arp_proxy_cfg), m_binding(o.m_binding)
{
}

arp_proxy_binding::~arp_proxy_binding()
{
    sweep();

    // not in the DB anymore.
    m_db.release(m_itf->key(), this);
}

void arp_proxy_binding::sweep()
{
    if (m_binding)
    {
        HW::enqueue(new unbind_cmd(m_binding, m_itf->handle()));
    }
    HW::write();
}

void arp_proxy_binding::dump(std::ostream &os)
{
    m_db.dump(os);
}

void arp_proxy_binding::replay()
{
    if (m_binding)
    {
        HW::enqueue(new bind_cmd(m_binding, m_itf->handle()));
    }
}

std::string arp_proxy_binding::to_string() const
{
    std::ostringstream s;
    s << "ArpProxy-binding: " << m_itf->to_string();

    return (s.str());
}

void arp_proxy_binding::update(const arp_proxy_binding &desired)
{
    /*
     * the desired state is always that the interface should be created
     */
    if (!m_binding)
    {
        HW::enqueue(new bind_cmd(m_binding, m_itf->handle()));
    }
}

std::shared_ptr<arp_proxy_binding> arp_proxy_binding::find_or_add(const arp_proxy_binding &temp)
{
    return (m_db.find_or_add(temp.m_itf->key(), temp));
}

std::shared_ptr<arp_proxy_binding> arp_proxy_binding::singular() const
{
    return find_or_add(*this);
}

arp_proxy_binding::event_handler::event_handler()
{
    OM::register_listener(this);
    inspect::register_handler({"arp-proxy"}, "ARP proxy bindings", this);
}

void arp_proxy_binding::event_handler::handle_replay()
{
    m_db.replay();
}

void arp_proxy_binding::event_handler::handle_populate(const client_db::key_t &key)
{
    // FIXME
}

dependency_t arp_proxy_binding::event_handler::order() const
{
    return (dependency_t::BINDING);
}

void arp_proxy_binding::event_handler::show(std::ostream &os)
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
