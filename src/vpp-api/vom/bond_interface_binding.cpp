/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include "vom/bond_interface_binding.hpp"
#include "vom/bond_interface_binding_cmds.hpp"

namespace VOM {

/**
 * A DB of all bond interface binding
 */
singular_db<interface::key_t, bond_interface_binding>
  bond_interface_binding::m_db;

bond_interface_binding::event_handler bond_interface_binding::m_evh;

bond_interface_binding::bond_interface_binding(const bond_interface& itf,
                                               const mem_itf_t& mem)
  : m_itf(itf.singular())
  , m_mem(mem)
  , m_binding(false)
{
}

bond_interface_binding::bond_interface_binding(const bond_interface_binding& o)
  : m_itf(o.m_itf)
  , m_mem(o.m_mem)
  , m_binding(o.m_binding)
{
}

bond_interface_binding::~bond_interface_binding()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_itf->key(), this);
}

void
bond_interface_binding::sweep()
{
  if (m_binding) {
    HW::enqueue(
      new bond_interface_binding_cmds::unbind_cmd(m_binding, m_itf->handle()));
  }
  HW::write();
}

void
bond_interface_binding::dump(std::ostream& os)
{
  m_db.dump(os);
}

void
bond_interface_binding::replay()
{
  if (m_binding) {
    HW::enqueue(
      new bond_interface_binding_cmds::bind_cmd(m_binding, m_itf->handle()));
  }
}

std::string
bond_interface_binding::to_string() const
{
  std::ostringstream s;
  s << "ArpProxy-binding: " << m_itf->to_string();

  return (s.str());
}

void
bond_interface_binding::update(const bond_interface_binding& desired)
{
  /*
 * the desired state is always that the interface should be created
 */
  if (!m_binding) {
    HW::enqueue(
      new bond_interface_binding_cmds::bind_cmd(m_binding, m_itf->handle()));
  }
}

std::shared_ptr<bond_interface_binding>
bond_interface_binding::find_or_add(const bond_interface_binding& temp)
{
  return (m_db.find_or_add(temp.m_itf->key(), temp));
}

std::shared_ptr<bond_interface_binding>
bond_interface_binding::singular() const
{
  return find_or_add(*this);
}

bond_interface_binding::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "arp-proxy" }, "ARP proxy bindings", this);
}

void
bond_interface_binding::event_handler::handle_replay()
{
  m_db.replay();
}

void
bond_interface_binding::event_handler::handle_populate(
  const client_db::key_t& key)
{
  // FIXME
}

dependency_t
bond_interface_binding::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
bond_interface_binding::event_handler::show(std::ostream& os)
{
  m_db.dump(os);
}
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
