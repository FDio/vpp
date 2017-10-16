/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "vom/object_base.hpp"

using namespace VOM;

object_ref::object_ref(std::shared_ptr<object_base> obj)
  : m_obj(obj), m_state(OBJECT_STATE_NONE)
{
}

bool object_ref::operator<(const object_ref &other) const
{
    return (m_obj.get() < other.m_obj.get());
}

std::shared_ptr<object_base> object_ref::obj() const
{
    return (m_obj);
}

void object_ref::mark() const
{
    m_state = OBJECT_STATE_STALE;
}

void object_ref::clear() const
{
    m_state = OBJECT_STATE_NONE;
}

bool object_ref::stale() const
{
    return (m_state == OBJECT_STATE_STALE);
}

std::ostream &VOM::operator<<(std::ostream &os, const object_base &o)
{
    os << o.to_string();

    return (os);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
