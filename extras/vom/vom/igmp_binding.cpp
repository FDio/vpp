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

#include "vom/igmp_binding.hpp"
#include "vom/igmp_binding_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {
singular_db<igmp_binding::key_t, igmp_binding> igmp_binding::m_db;

igmp_binding::event_handler igmp_binding::m_evh;

/**
 * Construct a new object matching the desried state
 */
igmp_binding::igmp_binding(const interface& itf,
                           const boost::asio::ip::address& gaddr,
                           igmp_binding::src_addrs_t& saddrs)
  : m_itf(itf.singular())
  , m_gaddr(gaddr)
  , m_saddrs(saddrs)
  , m_binding(true, rc_t::NOOP)
{}

igmp_binding::igmp_binding(const igmp_binding& o)
  : m_itf(o.m_itf)
  , m_gaddr(o.m_gaddr)
  , m_saddrs(o.m_saddrs)
  , m_binding(o.m_binding)
{}

igmp_binding::~igmp_binding()
{
  sweep();

  // not in the DB anymore.
  m_db.release(key(), this);
}

bool
igmp_binding::operator==(const igmp_binding& l) const
{
  return ((m_gaddr == l.m_gaddr) && (*m_itf == *l.m_itf));
}

const igmp_binding::key_t
igmp_binding::key() const
{
  return (make_pair(m_itf->key(), m_gaddr));
}

void
igmp_binding::sweep()
{
  if (m_binding) {
    HW::enqueue(new igmp_binding_cmds::unbind_cmd(
      m_binding, m_itf->handle(), m_gaddr, m_saddrs));
  }
  HW::write();
}

void
igmp_binding::replay()
{
  if (m_binding) {
    HW::enqueue(new igmp_binding_cmds::bind_cmd(
      m_binding, m_itf->handle(), m_gaddr, m_saddrs));
  }
}

/*const route::prefix_t&
igmp_binding::prefix() const
{
  return (m_pfx);
}

const interface&
igmp_binding::itf() const
{
  return (*m_itf);
}
*/
igmp_binding::const_iterator_t
igmp_binding::cbegin()
{
  return m_db.begin();
}

igmp_binding::const_iterator_t
igmp_binding::cend()
{
  return m_db.end();
}

std::string
igmp_binding::to_string() const
{
  auto addr = m_saddrs.cbegin();

  std::ostringstream s;
  s << "L3-binding:[" << m_itf->to_string() << " group:" << m_gaddr
    << " src addrs: [";
  while (addr != m_saddrs.cend()) {
    s << " " << *addr;
    ++addr;
  }
  s << "] " << m_binding.to_string() << "]";

  return (s.str());
}

void
igmp_binding::update(const igmp_binding& desired)
{
  /*
   * no updates for the binding. chaning the interface or the prefix is a change
   * to the
   * key, hence a new object
   */
  if (!m_binding) {
    HW::enqueue(new igmp_binding_cmds::bind_cmd(
      m_binding, m_itf->handle(), m_gaddr, m_saddrs));
  }
}

std::shared_ptr<igmp_binding>
igmp_binding::find_or_add(const igmp_binding& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<igmp_binding>
igmp_binding::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<igmp_binding>
igmp_binding::singular() const
{
  return find_or_add(*this);
}

void
igmp_binding::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

std::ostream&
operator<<(std::ostream& os, const igmp_binding::key_t& key)
{
  os << "[" << key.first << ", " << key.second << "]";

  return (os);
}

igmp_binding::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "igmp" }, "igmp host", this);
}

void
igmp_binding::event_handler::handle_replay()
{
  m_db.replay();
}

void
igmp_binding::event_handler::handle_populate(const client_db::key_t& key)
{
  /**
   * This is done while populating the interfaces
   */
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
