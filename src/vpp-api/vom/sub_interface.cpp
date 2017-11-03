/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "vom/sub_interface.hpp"
#include "vom/sub_interface_cmds.hpp"

namespace VOM {
/**
 * Construct a new object matching the desried state
 */
sub_interface::sub_interface(const interface& parent,
                             admin_state_t state,
                             vlan_id_t vlan)
  : interface(mk_name(parent, vlan), parent.type(), state)
  , m_parent(parent.singular())
  , m_vlan(vlan)
{
}

sub_interface::sub_interface(const handle_t& handle,
                             const interface& parent,
                             admin_state_t state,
                             vlan_id_t vlan)
  : interface(handle,
              l2_address_t::ZERO,
              mk_name(parent, vlan),
              parent.type(),
              state)
  , m_parent(parent.singular())
  , m_vlan(vlan)
{
}

sub_interface::~sub_interface()
{
  sweep();
  release();
}

sub_interface::sub_interface(const sub_interface& o)
  : interface(o)
  , m_parent(o.m_parent)
  , m_vlan(o.m_vlan)
{
}

std::string
sub_interface::mk_name(const interface& parent, vlan_id_t vlan)
{
  return (parent.name() + "." + std::to_string(vlan));
}

std::queue<cmd*>&
sub_interface::mk_create_cmd(std::queue<cmd*>& q)
{
  q.push(new sub_interface_cmds::create_cmd(m_hdl, name(), m_parent->handle(),
                                            m_vlan));

  return (q);
}

std::queue<cmd*>&
sub_interface::mk_delete_cmd(std::queue<cmd*>& q)
{
  q.push(new sub_interface_cmds::delete_cmd(m_hdl));

  return (q);
}

std::shared_ptr<sub_interface>
sub_interface::singular() const
{
  return std::dynamic_pointer_cast<sub_interface>(singular_i());
}

std::shared_ptr<interface>
sub_interface::singular_i() const
{
  return m_db.find_or_add(name(), *this);
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
