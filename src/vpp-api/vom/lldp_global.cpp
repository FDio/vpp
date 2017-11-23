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

#include "vom/lldp_global.hpp"
#include "vom/lldp_global_cmds.hpp"

namespace VOM {
/**
 * A DB of all LLDP configs
 */
singular_db<std::string, lldp_global> lldp_global::m_db;

lldp_global::event_handler lldp_global::m_evh;

lldp_global::lldp_global(const std::string& system_name,
                         uint32_t tx_hold,
                         uint32_t tx_interval)
  : m_system_name(system_name)
  , m_tx_hold(tx_hold)
  , m_tx_interval(tx_interval)
{
}

lldp_global::lldp_global(const lldp_global& o)
  : m_system_name(o.m_system_name)
  , m_tx_hold(o.m_tx_hold)
  , m_tx_interval(o.m_tx_interval)
{
}

lldp_global::~lldp_global()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_system_name, this);
}

const lldp_global::key_t&
lldp_global::key() const
{
  return (m_system_name);
}

bool
lldp_global::operator==(const lldp_global& l) const
{
  return ((key() == l.key()) && (m_tx_hold == l.m_tx_hold) &&
          (m_tx_interval == l.m_tx_interval));
}

void
lldp_global::sweep()
{
  // no means to remove this in VPP
}

void
lldp_global::dump(std::ostream& os)
{
  m_db.dump(os);
}

void
lldp_global::replay()
{
  if (m_binding) {
    HW::enqueue(new lldp_global_cmds::config_cmd(m_binding, m_system_name,
                                                 m_tx_hold, m_tx_interval));
  }
}

std::string
lldp_global::to_string() const
{
  std::ostringstream s;
  s << "LLDP-global:"
    << " system_name:" << m_system_name << " tx-hold:" << m_tx_hold
    << " tx-interval:" << m_tx_interval;

  return (s.str());
}

void
lldp_global::update(const lldp_global& desired)
{
  if (!m_binding) {
    HW::enqueue(new lldp_global_cmds::config_cmd(m_binding, m_system_name,
                                                 m_tx_hold, m_tx_interval));
  }
}

std::shared_ptr<lldp_global>
lldp_global::find_or_add(const lldp_global& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<lldp_global>
lldp_global::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<lldp_global>
lldp_global::singular() const
{
  return find_or_add(*this);
}

lldp_global::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "lldp-global" }, "LLDP global configurations",
                            this);
}

void
lldp_global::event_handler::handle_replay()
{
  m_db.replay();
}

void
lldp_global::event_handler::handle_populate(const client_db::key_t& key)
{
  // FIXME
}

dependency_t
lldp_global::event_handler::order() const
{
  return (dependency_t::GLOBAL);
}

void
lldp_global::event_handler::show(std::ostream& os)
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
