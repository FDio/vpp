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

#include "vom/nat_static.hpp"
#include "vom/nat_static_cmds.hpp"

namespace VOM {
singular_db<nat_static::key_t, nat_static> nat_static::m_db;
nat_static::event_handler nat_static::m_evh;

nat_static::nat_static(const boost::asio::ip::address& inside,
                       const boost::asio::ip::address_v4& outside)
  : m_hw(false)
  , m_rd(route_domain::get_default())
  , m_inside(inside)
  , m_outside(outside)
{
}

nat_static::nat_static(const route_domain& rd,
                       const boost::asio::ip::address& inside,
                       const boost::asio::ip::address_v4& outside)
  : m_hw(false)
  , m_rd(rd.singular())
  , m_inside(inside)
  , m_outside(outside)
{
}

nat_static::nat_static(const nat_static& ns)
  : m_hw(ns.m_hw)
  , m_rd(ns.m_rd)
  , m_inside(ns.m_inside)
  , m_outside(ns.m_outside)
{
}

nat_static::~nat_static()
{
  sweep();

  // not in the DB anymore.
  m_db.release(key(), this);
}

const nat_static::key_t
nat_static::key() const
{
  return (std::make_pair(m_rd->key(), m_outside));
}

bool
nat_static::operator==(const nat_static& n) const
{
  return ((key() == n.key()) && (m_inside == n.m_inside));
}

void
nat_static::sweep()
{
  if (m_hw) {
    if (m_inside.is_v4()) {
      HW::enqueue(new nat_static_cmds::delete_44_cmd(
        m_hw, m_rd->table_id(), m_inside.to_v4(), m_outside));
    }
  }
  HW::write();
}

void
nat_static::replay()
{
  if (m_hw) {
    if (m_inside.is_v4()) {
      HW::enqueue(new nat_static_cmds::create_44_cmd(
        m_hw, m_rd->table_id(), m_inside.to_v4(), m_outside));
    }
  }
}

void
nat_static::update(const nat_static& r)
{
  /*
 * create the table if it is not yet created
 */
  if (rc_t::OK != m_hw.rc()) {
    if (m_inside.is_v4()) {
      HW::enqueue(new nat_static_cmds::create_44_cmd(
        m_hw, m_rd->table_id(), m_inside.to_v4(), m_outside));
    }
  }
}

std::string
nat_static::to_string() const
{
  std::ostringstream s;
  s << "nat-static:["
    << "table:" << m_rd->to_string() << " inside:" << m_inside.to_string()
    << " outside:" << m_outside.to_string() << "]";

  return (s.str());
}

std::shared_ptr<nat_static>
nat_static::find_or_add(const nat_static& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<nat_static>
nat_static::find(const key_t& key)
{
  return (m_db.find(key));
}

std::shared_ptr<nat_static>
nat_static::singular() const
{
  return find_or_add(*this);
}

void
nat_static::dump(std::ostream& os)
{
  m_db.dump(os);
}

nat_static::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "nat-static" }, "NAT Statics", this);
}

void
nat_static::event_handler::handle_replay()
{
  m_db.replay();
}

void
nat_static::event_handler::handle_populate(const client_db::key_t& key)
{
  /*
   * dump VPP current states
   */
  std::shared_ptr<nat_static_cmds::dump_44_cmd> cmd =
    std::make_shared<nat_static_cmds::dump_44_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {

    auto& payload = record.get_payload();

    boost::asio::ip::address inside = from_bytes(0, payload.local_ip_address);
    boost::asio::ip::address outside =
      from_bytes(0, payload.external_ip_address);
    nat_static n(route_domain(payload.vrf_id), inside, outside.to_v4());

    /*
     * Write each of the discovered mappings into the OM,
     * but disable the HW Command q whilst we do, so that no
     * commands are sent to VPP
     */
    OM::commit(key, n);
  }
}

dependency_t
nat_static::event_handler::order() const
{
  return (dependency_t::ENTRY);
}

void
nat_static::event_handler::show(std::ostream& os)
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
