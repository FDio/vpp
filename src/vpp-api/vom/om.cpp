/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <algorithm>

#include "vom/om.hpp"

using namespace VOM;

client_db *OM::m_db;

std::unique_ptr<OM::listener_list> OM::m_listeners;

/**
 * Initalse the connection to VPP
 */
void OM::init()
{
    m_db = new client_db();
}

void OM::mark(const client_db::key_t &key)
{
    /*
     * Find if the object already stored on behalf of this key.
     * and mark them stale
     */
    VOM::object_ref_list &objs = m_db->find(key);

    auto mark_obj = [](const object_ref &oref) {
        oref.mark();
    };

    std::for_each(objs.begin(), objs.end(), mark_obj);
}

void OM::sweep(const client_db::key_t &key)
{
    /*
     * Find if the object already stored on behalf of this key.
     * and mark them stale
     */
    object_ref_list &objs = m_db->find(key);

    for (auto it = objs.begin(); it != objs.end();)
    {
        if (it->stale())
        {
            it = objs.erase(it);
        }
        else
        {
            ++it;
        }
    }

    HW::write();
}

void OM::remove(const client_db::key_t &key)
{
    /*
     * Simply reset the list for this key. This will desctruct the
     * object list and shared_ptrs therein. When the last shared_ptr
     * goes the objects desctructor is called and the object is
     * removed from OM
     */
    m_db->flush(key);

    HW::write();
}

void OM::replay()
{
    /*
     * the listeners are sorted in dependency order
     */
    for (listener *l : *m_listeners)
    {
        l->handle_replay();
    }

    HW::write();
}

void OM::dump(const client_db::key_t &key, std::ostream &os)
{
    m_db->dump(key, os);
}

void OM::dump(std::ostream &os)
{
    m_db->dump(os);
}

void OM::populate(const client_db::key_t &key)
{
    /*
     * the listeners are sorted in dependency order
     */
    for (listener *l : *m_listeners)
    {
        l->handle_populate(key);
    }

    /*
     * once we have it all, mark it stale.
     */
    mark(key);
}

bool OM::register_listener(OM::listener *listener)
{
    if (!m_listeners)
    {
        m_listeners.reset(new listener_list);
    }

    m_listeners->insert(listener);

    return (true);
}


OM::mark_n_sweep::mark_n_sweep(const client_db::key_t &key)
  : m_key(key)
{
    OM::mark(m_key);
}

OM::mark_n_sweep::~mark_n_sweep()
{
    OM::sweep(m_key);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
