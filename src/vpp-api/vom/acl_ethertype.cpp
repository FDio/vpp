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

#include "vom/acl_ethertype.hpp"
#include "vom/acl_ethertype_cmds.hpp"

namespace VOM {
namespace ACL {

ethertype_t::ethertype_t(uint16_t e, const direction_t& dir)
  : m_e(e)
  , m_dir(dir)
{
}

std::string
ethertype_t::to_string() const
{
  std::ostringstream s;

  s << "["
    << " ethertype:0x" << std::hex << m_e << " dir:" << m_dir.to_string()
    << "],";

  return (s.str());
}

bool
ethertype_t::operator<(const ethertype_t& other) const
{
  return (m_dir > other.m_dir);
}

uint16_t
ethertype_t::getEthertype() const
{
  return m_e;
}

/**
 * A DB of all acl ethertype bindings configs
 */
singular_db<interface::key_t, acl_ethertype> acl_ethertype::m_db;

acl_ethertype::event_handler acl_ethertype::m_evh;

acl_ethertype::acl_ethertype(const interface& itf,
                             acl_ethertype::list_ethertype_t le,
                             uint8_t n_input)
  : m_itf(itf.singular())
  , m_le(le)
  , m_n_input(n_input)
  , m_binding(true)
{
}

acl_ethertype::acl_ethertype(const acl_ethertype& o)
  : m_itf(o.m_itf)
  , m_le(o.m_le)
  , m_n_input(o.m_n_input)
  , m_binding(o.m_binding)
{
}

acl_ethertype::~acl_ethertype()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_itf->key(), this);
}

void
acl_ethertype::sweep()
{
}

void
acl_ethertype::dump(std::ostream& os)
{
  m_db.dump(os);
}

void
acl_ethertype::replay()
{
  if (m_binding) {
    HW::enqueue(new acl_ethertype_cmds::bind_cmd(m_binding, m_itf->handle(),
                                                 m_le, m_n_input));
  }
}

std::string
acl_ethertype::to_string() const
{
  std::ostringstream s;
  s << "Acl-Ethertype:" << m_itf->to_string() << " ethertype-list:";
  auto it = m_le.cbegin();
  while (it != m_le.cend()) {
    s << it->to_string();
    ++it;
  }
  s << " count:" << m_le.size() << " n_input:" << std::to_string(m_n_input);

  return (s.str());
}

void
acl_ethertype::update(const acl_ethertype& desired)
{
  /*
   * the desired state is always that the interface should be created
   */
  if (!m_binding) {
    HW::enqueue(new acl_ethertype_cmds::bind_cmd(m_binding, m_itf->handle(),
                                                 m_le, m_n_input));
  }
}

std::shared_ptr<acl_ethertype>
acl_ethertype::find_or_add(const acl_ethertype& temp)
{
  return (m_db.find_or_add(temp.m_itf->key(), temp));
}

std::shared_ptr<acl_ethertype>
acl_ethertype::singular() const
{
  return find_or_add(*this);
}

acl_ethertype::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "acl-ethertype" }, "ACL Ethertype bindings",
                            this);
}

void
acl_ethertype::event_handler::handle_replay()
{
  m_db.replay();
}

void
acl_ethertype::event_handler::handle_populate(const client_db::key_t& key)
{
  // FIXME
}

dependency_t
acl_ethertype::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
acl_ethertype::event_handler::show(std::ostream& os)
{
  m_db.dump(os);
}
};
};
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
