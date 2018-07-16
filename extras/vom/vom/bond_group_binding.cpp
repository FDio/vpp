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

#include "vom/bond_group_binding.hpp"
#include "vom/bond_group_binding_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {

/**
 * A DB of all bond interface binding
 */
singular_db<bond_group_binding::key_t, bond_group_binding>
  bond_group_binding::m_db;

bond_group_binding::event_handler bond_group_binding::m_evh;

bond_group_binding::bond_group_binding(const bond_interface& itf,
                                       const enslaved_itf_t& itfs)
  : m_itf(itf.singular())
  , m_mem_itfs(itfs)
  , m_binding(false)
{
}

bond_group_binding::bond_group_binding(const bond_group_binding& o)
  : m_itf(o.m_itf)
  , m_mem_itfs(o.m_mem_itfs)
  , m_binding(o.m_binding)
{
}

bond_group_binding::~bond_group_binding()
{
  sweep();

  // not in the DB anymore.
  m_db.release(key(), this);
}

const bond_group_binding::key_t
bond_group_binding::key() const
{
  return (m_itf->key() + "-binding");
}

void
bond_group_binding::sweep()
{

  auto it = m_mem_itfs.cbegin();
  while (it != m_mem_itfs.cend()) {
    if (m_binding) {
      HW::enqueue(
        new bond_group_binding_cmds::unbind_cmd(m_binding, it->hdl()));
    }
    HW::write();
    ++it;
  }
}

void
bond_group_binding::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

void
bond_group_binding::replay()
{
  auto it = m_mem_itfs.cbegin();
  while (it != m_mem_itfs.cend()) {
    if (m_binding) {
      HW::enqueue(
        new bond_group_binding_cmds::bind_cmd(m_binding, m_itf->handle(), *it));
    }
    HW::write();
    ++it;
  }
}

std::string
bond_group_binding::to_string() const
{
  auto it = m_mem_itfs.cbegin();
  std::ostringstream s;
  s << "bond-interface-binding: " << m_itf->to_string() << " slave-itfs: [";
  while (it != m_mem_itfs.cend()) {
    s << " " << it->to_string();
    ++it;
  }
  s << "]";
  return (s.str());
}

void
bond_group_binding::update(const bond_group_binding& desired)
{
  /*
   * the desired state is always that the interface should be created
   */
  auto it = m_mem_itfs.cbegin();
  while (it != m_mem_itfs.cend()) {
    if (!m_binding) {
      HW::enqueue(
        new bond_group_binding_cmds::bind_cmd(m_binding, m_itf->handle(), *it));
    }
    ++it;
  }
}

std::shared_ptr<bond_group_binding>
bond_group_binding::find_or_add(const bond_group_binding& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<bond_group_binding>
bond_group_binding::singular() const
{
  return find_or_add(*this);
}

bond_group_binding::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "bond-intf-binding" }, "Bond interface binding",
                            this);
}

void
bond_group_binding::event_handler::handle_replay()
{
  m_db.replay();
}

void
bond_group_binding::event_handler::handle_populate(const client_db::key_t& key)
{
  /*
   * handle it in interface class
   */
}

dependency_t
bond_group_binding::event_handler::order() const
{
  /*
   * We want enslaved interfaces bind to bond after interface
   * but before anything else.
   */
  return (dependency_t::VIRTUAL_INTERFACE);
}

void
bond_group_binding::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
