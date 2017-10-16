/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "vom/sub_interface.hpp"

using namespace VOM;

/**
 * Construct a new object matching the desried state
 */
sub_interface::sub_interface(const interface &parent,
                             admin_state_t state,
                             vlan_id_t vlan)
  : interface(mk_name(parent, vlan), parent.type(), state), m_parent(parent.singular()), m_vlan(vlan)
{
}

sub_interface::sub_interface(const handle_t &handle,
                             const interface &parent,
                             admin_state_t state,
                             vlan_id_t vlan)
  : interface(handle, l2_address_t::ZERO, mk_name(parent, vlan), parent.type(), state), m_parent(parent.singular()), m_vlan(vlan)
{
}

sub_interface::~sub_interface()
{
    sweep();
    release();
}

sub_interface::sub_interface(const sub_interface &o)
  : interface(o), m_parent(o.m_parent), m_vlan(o.m_vlan)
{
}

std::string sub_interface::mk_name(const interface &parent,
                                   vlan_id_t vlan)
{
    return (parent.name() + "." + std::to_string(vlan));
}

std::queue<cmd *> &sub_interface::mk_create_cmd(std::queue<cmd *> &q)
{
    q.push(new create_cmd(m_hdl, name(), m_parent->handle(), m_vlan));

    return (q);
}

std::queue<cmd *> &sub_interface::mk_delete_cmd(std::queue<cmd *> &q)
{
    q.push(new delete_cmd(m_hdl));

    return (q);
}

std::shared_ptr<sub_interface> sub_interface::singular() const
{
    return std::dynamic_pointer_cast<sub_interface>(singular_i());
}

std::shared_ptr<interface> sub_interface::singular_i() const
{
    return m_db.find_or_add(name(), *this);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
