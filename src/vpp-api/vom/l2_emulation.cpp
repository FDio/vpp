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

#include "vom/l2_emulation.hpp"
#include "vom/l2_emulation_cmds.hpp"

namespace VOM {
/**
 * A DB of all the L2 Configs
 */
singular_db<l2_emulation::key_t, l2_emulation> l2_emulation::m_db;

l2_emulation::event_handler l2_emulation::m_evh;

/**
 * Construct a new object matching the desried state
 */
l2_emulation::l2_emulation(const interface& itf)
  : m_itf(itf.singular())
  , m_emulation(0)
{
}

l2_emulation::l2_emulation(const l2_emulation& o)
  : m_itf(o.m_itf)
  , m_emulation(0)
{
}

const l2_emulation::key_t&
l2_emulation::key() const
{
  return (m_itf->key());
}

bool
l2_emulation::operator==(const l2_emulation& l) const
{
  return ((*m_itf == *l.m_itf));
}

std::shared_ptr<l2_emulation>
l2_emulation::find(const key_t& key)
{
  return (m_db.find(key));
}

void
l2_emulation::sweep()
{
  if (m_emulation && handle_t::INVALID != m_itf->handle()) {
    HW::enqueue(
      new l2_emulation_cmds::enable_cmd(m_emulation, m_itf->handle()));
  }

  // no need to undo the VTR operation.
  HW::write();
}

void
l2_emulation::replay()
{
  if (m_emulation && handle_t::INVALID != m_itf->handle()) {
    HW::enqueue(
      new l2_emulation_cmds::enable_cmd(m_emulation, m_itf->handle()));
  }
}

l2_emulation::~l2_emulation()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_itf->key(), this);
}

std::string
l2_emulation::to_string() const
{
  std::ostringstream s;
  s << "L2-emulation:[" << m_itf->to_string() << "]";

  return (s.str());
}

void
l2_emulation::update(const l2_emulation& desired)
{
  /*
   * the desired state is always that the interface should be created
   */
  if (rc_t::OK != m_emulation.rc()) {
    HW::enqueue(
      new l2_emulation_cmds::enable_cmd(m_emulation, m_itf->handle()));
  }
}

std::shared_ptr<l2_emulation>
l2_emulation::find_or_add(const l2_emulation& temp)
{
  return (m_db.find_or_add(temp.m_itf->key(), temp));
}

std::shared_ptr<l2_emulation>
l2_emulation::singular() const
{
  return find_or_add(*this);
}

void
l2_emulation::dump(std::ostream& os)
{
  m_db.dump(os);
}

l2_emulation::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "l2e" }, "L2 Emulation", this);
}

void
l2_emulation::event_handler::handle_replay()
{
  m_db.replay();
}

void
l2_emulation::event_handler::handle_populate(const client_db::key_t& key)
{
  /**
   * This is done while populating the bridge-domain
   */
}

dependency_t
l2_emulation::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
l2_emulation::event_handler::show(std::ostream& os)
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
