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

#include "vom/igmp_listen.hpp"
#include "vom/igmp_listen_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {
singular_db<igmp_listen::key_t, igmp_listen> igmp_listen::m_db;

igmp_listen::event_handler igmp_listen::m_evh;

/**
 * Construct a new object matching the desried state
 */
igmp_listen::igmp_listen(const igmp_binding& igmp_bind,
                         const boost::asio::ip::address& gaddr,
                         const igmp_listen::src_addrs_t& saddrs)
  : m_igmp_bind(igmp_bind.singular())
  , m_gaddr(gaddr)
  , m_saddrs(saddrs)
  , m_listen(true, rc_t::NOOP)
{
}

igmp_listen::igmp_listen(const igmp_listen& o)
  : m_igmp_bind(o.m_igmp_bind)
  , m_gaddr(o.m_gaddr)
  , m_saddrs(o.m_saddrs)
  , m_listen(o.m_listen)
{
}

igmp_listen::~igmp_listen()
{
  sweep();

  // not in the DB anymore.
  m_db.release(key(), this);
}

bool
igmp_listen::operator==(const igmp_listen& l) const
{
  return ((m_gaddr == l.m_gaddr) && (*m_igmp_bind == *l.m_igmp_bind) &&
          (m_saddrs == l.m_saddrs));
}

const igmp_listen::key_t
igmp_listen::key() const
{
  return (make_pair(m_igmp_bind->itf()->key(), m_gaddr));
}

void
igmp_listen::sweep()
{
  if (m_listen) {
    HW::enqueue(new igmp_listen_cmds::unlisten_cmd(
      m_listen, m_igmp_bind->itf()->handle(), m_gaddr));
  }
  HW::write();
}

void
igmp_listen::replay()
{
  if (m_listen) {
    HW::enqueue(new igmp_listen_cmds::listen_cmd(
      m_listen, m_igmp_bind->itf()->handle(), m_gaddr, m_saddrs));
  }
}

std::string
igmp_listen::to_string() const
{
  auto addr = m_saddrs.cbegin();

  std::ostringstream s;
  s << "igmp-listen:[" << m_igmp_bind->to_string() << " group:" << m_gaddr
    << " src-addrs: [";
  while (addr != m_saddrs.cend()) {
    s << " " << *addr;
    ++addr;
  }
  s << " ] " << m_listen.to_string() << "]";

  return (s.str());
}

void
igmp_listen::update(const igmp_listen& desired)
{
  /*
   * no updates for the listen. chaning the interface or the group addr is a
   * change to the key, hence a new object
   */
  if (!m_listen) {
    HW::enqueue(new igmp_listen_cmds::listen_cmd(
      m_listen, m_igmp_bind->itf()->handle(), m_gaddr, m_saddrs));
  }
}

std::shared_ptr<igmp_listen>
igmp_listen::find_or_add(const igmp_listen& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<igmp_listen>
igmp_listen::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<igmp_listen>
igmp_listen::singular() const
{
  return find_or_add(*this);
}

void
igmp_listen::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

igmp_listen::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "igmp-listen" }, "igmp listener", this);
}

void
igmp_listen::event_handler::handle_replay()
{
  m_db.replay();
}

void
igmp_listen::event_handler::handle_populate(const client_db::key_t& key)
{
  /**
   * This is done while populating the interfaces
   */
}

dependency_t
igmp_listen::event_handler::order() const
{
  return (dependency_t::ENTRY);
}

void
igmp_listen::event_handler::show(std::ostream& os)
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
