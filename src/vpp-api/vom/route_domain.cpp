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

#include "vom/route_domain.hpp"
#include "vom/cmd.hpp"
#include "vom/route_domain_cmds.hpp"

namespace VOM {

route_domain::event_handler route_domain::m_evh;

/**
 * A DB of al the interfaces, key on the name
 */
singular_db<route::table_id_t, route_domain> route_domain::m_db;

/**
 * Construct a new object matching the desried state
 */
route_domain::route_domain(route::table_id_t id)
  : m_hw_v4(true)
  , m_hw_v6(true)
  , m_table_id(id)
{
}

route_domain::route_domain(const route_domain& o)
  : m_hw_v4(o.m_hw_v4)
  , m_hw_v6(o.m_hw_v6)
  , m_table_id(o.m_table_id)
{
}

bool
route_domain::operator==(const route_domain& r) const
{
  return (m_table_id == r.m_table_id);
}

route::table_id_t
route_domain::table_id() const
{
  return (m_table_id);
}

route_domain::key_t
route_domain::key() const
{
  return (table_id());
}

void
route_domain::sweep()
{
  if (m_hw_v4) {
    HW::enqueue(
      new route_domain_cmds::delete_cmd(m_hw_v4, l3_proto_t::IPV4, m_table_id));
  }
  if (m_hw_v6) {
    HW::enqueue(
      new route_domain_cmds::delete_cmd(m_hw_v6, l3_proto_t::IPV6, m_table_id));
  }
  HW::write();
}

void
route_domain::replay()
{
  if (m_hw_v4) {
    HW::enqueue(
      new route_domain_cmds::create_cmd(m_hw_v4, l3_proto_t::IPV4, m_table_id));
  }
  if (m_hw_v6) {
    HW::enqueue(
      new route_domain_cmds::create_cmd(m_hw_v6, l3_proto_t::IPV6, m_table_id));
  }
}

route_domain::~route_domain()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_table_id, this);
}

std::string
route_domain::to_string() const
{
  std::ostringstream s;
  s << "route-domain:["
    << "table-id:" << m_table_id << " v4:" << m_hw_v4 << " v6:" << m_hw_v6
    << "]";

  return (s.str());
}

std::shared_ptr<route_domain>
route_domain::find(const route_domain& temp)
{
  std::shared_ptr<route_domain> rd;

  auto it = m_db.cbegin();

  while (it != m_db.cend()) {
    /*
 * The key in the DB is a pair of the interface's name and prefix.
 * If the keys match, save the L3-config
 */
    auto key = it->first;

    if (temp.table_id() == key) {
      rd = it->second.lock();
      break;
    }

    ++it;
  }

  return (rd);
}

void
route_domain::update(const route_domain& desired)
{
  /*
 * create the table if it is not yet created
 */
  if (rc_t::OK != m_hw_v4.rc()) {
    HW::enqueue(
      new route_domain_cmds::create_cmd(m_hw_v4, l3_proto_t::IPV4, m_table_id));
  }
  if (rc_t::OK != m_hw_v6.rc()) {
    HW::enqueue(
      new route_domain_cmds::create_cmd(m_hw_v6, l3_proto_t::IPV6, m_table_id));
  }
}

std::shared_ptr<route_domain>
route_domain::get_default()
{
  route_domain rd(route::DEFAULT_TABLE);

  return (find_or_add(rd));
}

std::shared_ptr<route_domain>
route_domain::find_or_add(const route_domain& temp)
{
  return (m_db.find_or_add(temp.m_table_id, temp));
}

std::shared_ptr<route_domain>
route_domain::singular() const
{
  return find_or_add(*this);
}

void
route_domain::dump(std::ostream& os)
{
  m_db.dump(os);
}

void
route_domain::event_handler::handle_populate(const client_db::key_t& key)
{
}

route_domain::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "rd", "route-domain" }, "Route Domains", this);
}

void
route_domain::event_handler::handle_replay()
{
  m_db.replay();
}

dependency_t
route_domain::event_handler::order() const
{
  return (dependency_t::TABLE);
}

void
route_domain::event_handler::show(std::ostream& os)
{
  m_db.dump(os);
}

}; // namespace VOPM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
