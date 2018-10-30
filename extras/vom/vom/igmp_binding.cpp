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

#include "vom/igmp_binding.hpp"
#include "vom/igmp_binding_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {

/**
 * A DB of all igmp bindings configs
 */
singular_db<interface::key_t, igmp_binding> igmp_binding::m_db;

igmp_binding::event_handler igmp_binding::m_evh;

igmp_binding::igmp_binding(const interface& itf)
  : m_itf(itf.singular())
  , m_binding(true)
{}

igmp_binding::igmp_binding(const igmp_binding& o)
  : m_itf(o.m_itf)
  , m_binding(o.m_binding)
{}

igmp_binding::~igmp_binding()
{
  sweep();
  m_db.release(m_itf->key(), this);
}

bool
igmp_binding::operator==(const igmp_binding& l) const
{
  return (*m_itf == *l.m_itf);
}

void
igmp_binding::sweep()
{
  if (m_binding) {
    HW::enqueue(new igmp_binding_cmds::unbind_cmd(m_binding, m_itf->handle()));
  }
  HW::write();
}

void
igmp_binding::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

void
igmp_binding::replay()
{
  if (m_binding) {
    HW::enqueue(new igmp_binding_cmds::bind_cmd(m_binding, m_itf->handle()));
  }
}

std::string
igmp_binding::to_string() const
{
  std::ostringstream s;
  s << "igmp-binding: [" << m_itf->to_string() << " mode:host]";

  return (s.str());
}

void
igmp_binding::update(const igmp_binding& desired)
{
  /*
   * the desired state is always that the interface should be created
   */
  if (!m_binding) {
    HW::enqueue(new igmp_binding_cmds::bind_cmd(m_binding, m_itf->handle()));
  }
}

std::shared_ptr<igmp_binding>
igmp_binding::find_or_add(const igmp_binding& temp)
{
  return (m_db.find_or_add(temp.m_itf->key(), temp));
}

std::shared_ptr<igmp_binding>
igmp_binding::singular() const
{
  return find_or_add(*this);
}

std::shared_ptr<interface>
igmp_binding::itf() const
{
  return m_itf;
}

igmp_binding::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "igmp-binding" }, "IGMP bindings", this);
}

void
igmp_binding::event_handler::handle_replay()
{
  m_db.replay();
}

void
igmp_binding::event_handler::handle_populate(const client_db::key_t& key)
{
  /* done with igmp_dump in igmp_listen */
}

dependency_t
igmp_binding::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
igmp_binding::event_handler::show(std::ostream& os)
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
