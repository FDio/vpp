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
#include "vom/l3_binding.hpp"

using namespace VOM;

singular_db<l3_binding::key_type_t, l3_binding> l3_binding::m_db;

l3_binding::event_handler l3_binding::m_evh;

/**
 * Construct a new object matching the desried state
 */
l3_binding::l3_binding(const interface &itf,
                       const route::prefix_t &pfx)
  : m_itf(itf.singular()), m_pfx(pfx), m_binding(true)
{
}

l3_binding::l3_binding(const l3_binding &o)
  : m_itf(o.m_itf), m_pfx(o.m_pfx), m_binding(true)
{
}

l3_binding::~l3_binding()
{
    sweep();

    // not in the DB anymore.
    m_db.release(make_pair(m_itf->key(), m_pfx), this);
}

void l3_binding::sweep()
{
    if (m_binding)
    {
        HW::enqueue(new unbind_cmd(m_binding, m_itf->handle(), m_pfx));
    }
    HW::write();
}

void l3_binding::replay()
{
    if (m_binding)
    {
        HW::enqueue(new bind_cmd(m_binding, m_itf->handle(), m_pfx));
    }
}

const route::prefix_t &l3_binding::prefix() const
{
    return (m_pfx);
}


std::string l3_binding::to_string() const
{
    std::ostringstream s;
    s << "L3-config:[" << m_itf->to_string()
      << " prefix:" << m_pfx.to_string()
      << " "
      << m_binding.to_string()
      << "]";

    return (s.str());
}

void l3_binding::update(const l3_binding &desired)
{
    /*
     * the desired state is always that the interface should be created
     */
    if (!m_binding)
    {
        HW::enqueue(new bind_cmd(m_binding, m_itf->handle(), m_pfx));
    }
}

std::shared_ptr<l3_binding> l3_binding::find_or_add(const l3_binding &temp)
{
    return (m_db.find_or_add(make_pair(temp.m_itf->key(), temp.m_pfx), temp));
}

std::shared_ptr<l3_binding> l3_binding::singular() const
{
    return find_or_add(*this);
}

void l3_binding::dump(std::ostream &os)
{
    m_db.dump(os);
}

std::ostream &VOM::operator<<(std::ostream &os, const l3_binding::key_type_t &key)
{
    os << "["
       << key.first
       << ", "
       << key.second
       << "]";

    return (os);
}

std::deque<std::shared_ptr<l3_binding>> l3_binding::find(const interface &i)
{
    /*
     * Loop throught the entire map looking for matching interface.
     * not the most efficient algorithm, but it will do for now. The
     * number of L3 configs is low and this is only called during bootup
     */
    std::deque<std::shared_ptr<l3_binding>> l3s;

    auto it = m_db.cbegin();

    while (it != m_db.cend())
    {
        /*
         * The key in the DB is a pair of the interface's name and prefix.
         * If the keys match, save the L3-config
         */
        auto key = it->first;

        if (i.key() == key.first)
        {
            l3s.push_back(it->second.lock());
        }

        ++it;
    }

    return (l3s);
}

l3_binding::event_handler::event_handler()
{
    OM::register_listener(this);
    inspect::register_handler({"l3"}, "L3 bindings", this);
}

void l3_binding::event_handler::handle_replay()
{
    m_db.replay();
}

void l3_binding::event_handler::handle_populate(const client_db::key_t &key)
{
    /**
     * This is done while populating the interfaces
     */
}

dependency_t l3_binding::event_handler::order() const
{
    return (dependency_t::BINDING);
}

void l3_binding::event_handler::show(std::ostream &os)
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
