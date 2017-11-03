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

#include "vom/lldp_binding.hpp"
#include "vom/lldp_binding_cmds.hpp"

namespace VOM {
/**
 * A DB of all LLDP configs
 */
singular_db<interface::key_type, lldp_binding> lldp_binding::m_db;

lldp_binding::event_handler lldp_binding::m_evh;

lldp_binding::lldp_binding(const interface& itf, const std::string& port_desc)
  : m_itf(itf.singular())
  , m_port_desc(port_desc)
  , m_binding(0)
{
}

lldp_binding::lldp_binding(const lldp_binding& o)
  : m_itf(o.m_itf)
  , m_port_desc(o.m_port_desc)
  , m_binding(0)
{
}

lldp_binding::~lldp_binding()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_itf->key(), this);
}

void
lldp_binding::sweep()
{
  if (m_binding) {
    HW::enqueue(new lldp_binding_cmds::unbind_cmd(m_binding, m_itf->handle()));
  }
  HW::write();
}

void
lldp_binding::dump(std::ostream& os)
{
  m_db.dump(os);
}

void
lldp_binding::replay()
{
  if (m_binding) {
    HW::enqueue(
      new lldp_binding_cmds::bind_cmd(m_binding, m_itf->handle(), m_port_desc));
  }
}

std::string
lldp_binding::to_string() const
{
  std::ostringstream s;
  s << "Lldp-binding: " << m_itf->to_string() << " port_desc:" << m_port_desc
    << " " << m_binding.to_string();

  return (s.str());
}

void
lldp_binding::update(const lldp_binding& desired)
{
  /*
 * the desired state is always that the interface should be created
 */
  if (!m_binding) {
    HW::enqueue(
      new lldp_binding_cmds::bind_cmd(m_binding, m_itf->handle(), m_port_desc));
  }
}

std::shared_ptr<lldp_binding>
lldp_binding::find_or_add(const lldp_binding& temp)
{
  return (m_db.find_or_add(temp.m_itf->key(), temp));
}

std::shared_ptr<lldp_binding>
lldp_binding::singular() const
{
  return find_or_add(*this);
}

lldp_binding::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "lldp" }, "LLDP bindings", this);
}

void
lldp_binding::event_handler::handle_replay()
{
  m_db.replay();
}

void
lldp_binding::event_handler::handle_populate(const client_db::key_t& key)
{
  // FIXME
}

dependency_t
lldp_binding::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
lldp_binding::event_handler::show(std::ostream& os)
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
