/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "vom/client_db.hpp"

using namespace VOM;

object_ref_list &client_db::find(const client_db::key_t &k)
{
    return (m_objs[k]);
}

void client_db::flush(const client_db::key_t &k)
{
    m_objs.erase(m_objs.find(k));
}

void client_db::dump(const key_t &key, std::ostream &os)
{
    object_ref_list &orlist = find(key);

    for (auto entry : orlist)
    {
        os << "  " << entry.obj()->to_string() << std::endl;
    }
}

void client_db::dump(std::ostream &os)
{
    for (auto entry : m_objs)
    {
        os << "  key:[" << entry.first << "]" << std::endl;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
