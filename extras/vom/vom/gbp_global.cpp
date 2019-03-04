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

#include "vom/gbp_global.hpp"
#include "vom/gbp_global_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {
/**
 * A DB of all GBP configs
 */
singular_db<std::string, gbp_global> gbp_global::m_db;

gbp_global::event_handler gbp_global::m_evh;

gbp_global::gbp_global(const std::string& system_name,
                       uint32_t remote_ep_retention)
  : m_system_name(system_name)
  , m_remote_ep_retention(remote_ep_retention)
{
}

gbp_global::gbp_global(const gbp_global& o)
  : m_system_name(o.m_system_name)
  , m_remote_ep_retention(o.m_remote_ep_retention)
{
}

gbp_global::~gbp_global()
{
  sweep();
  m_db.release(m_system_name, this);
}

const gbp_global::key_t&
gbp_global::key() const
{
  return (m_system_name);
}

bool
gbp_global::operator==(const gbp_global& l) const
{
  return ((key() == l.key()) &&
          (m_remote_ep_retention == l.m_remote_ep_retention));
}

void
gbp_global::sweep()
{
  // no means to remove this in VPP
}

void
gbp_global::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

void
gbp_global::replay()
{
  if (m_binding) {
    HW::enqueue(
      new gbp_global_cmds::config_cmd(m_binding, m_remote_ep_retention));
  }
}

std::string
gbp_global::to_string() const
{
  std::ostringstream s;
  s << "GBP-global:"
    << " remote-EP-retention:" << m_remote_ep_retention;

  return (s.str());
}

void
gbp_global::update(const gbp_global& desired)
{
  if (!m_binding) {
    HW::enqueue(
      new gbp_global_cmds::config_cmd(m_binding, m_remote_ep_retention));
  }
}

std::shared_ptr<gbp_global>
gbp_global::find_or_add(const gbp_global& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<gbp_global>
gbp_global::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<gbp_global>
gbp_global::singular() const
{
  return find_or_add(*this);
}

gbp_global::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "gbp-global" }, "GBP global configurations",
                            this);
}

void
gbp_global::event_handler::handle_replay()
{
  m_db.replay();
}

void
gbp_global::event_handler::handle_populate(const client_db::key_t& key)
{
}

dependency_t
gbp_global::event_handler::order() const
{
  return (dependency_t::GLOBAL);
}

void
gbp_global::event_handler::show(std::ostream& os)
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
