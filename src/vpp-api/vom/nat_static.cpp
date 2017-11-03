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
  m_db.release(std::make_pair(m_rd->key(), m_outside), this);
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
    << "table:" << m_rd->to_string() << " inside: " << m_inside.to_string()
    << " outside " << m_outside.to_string() << "]";

  return (s.str());
}

std::shared_ptr<nat_static>
nat_static::find_or_add(const nat_static& temp)
{
  return (
    m_db.find_or_add(std::make_pair(temp.m_rd->key(), temp.m_outside), temp));
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

std::ostream&
operator<<(std::ostream& os, const nat_static::key_t& key)
{
  os << "[" << key.first << ", " << key.second << "]";

  return (os);
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

/* void nat_static::populate_i(const client_db::key_t &key, */
/*                            std::shared_ptr<interface> itf, */
/*                            const l3_proto_t &proto) */
/* { */
/*     /\* */
/*      * dump VPP current states */
/*      *\/ */
/*     std::shared_ptr<nat_static::dump_cmd> cmd = */
/*         std::make_shared<nat_static::dump_cmd>(nat_static::dump_cmd(itf->handle(),
 * proto)); */

/*     HW::enqueue(cmd); */
/*     HW::write(); */

/*     for (auto & record : *cmd) */
/*     { */
/*         /\* */
/*          * construct a nat_static from each recieved record. */
/*          *\/ */
/*         auto &payload = record.get_payload(); */

/*      mac_address_t mac(payload.mac_address); */
/*         boost::asio::ip::address ip_addr = from_bytes(payload.is_ipv6, */
/*                                                       payload.ip_address);
 */
/*         nat_static n(*itf, mac, ip_addr); */

/*         VOM_LOG(log_level_t::DEBUG) << "nat_static-dump: " */
/*                                                << itf->to_string() */
/*                                                << mac.to_string() */
/*                                                << ip_addr.to_string(); */

/*         /\* */
/*          * Write each of the discovered interfaces into the OM, */
/*          * but disable the HW Command q whilst we do, so that no */
/*          * commands are sent to VPP */
/*          *\/ */
/*         OM::commit(key, n); */
/*     } */
/* } */

void
nat_static::event_handler::handle_populate(const client_db::key_t& key)
{
  /* auto it = interface::cbegin(); */

  /* while (it != interface::cend()) */
  /* { */
  /*     nat_static::populate_i(key, it->second.lock(), l3_proto_t::IPV4);
 */
  /*     nat_static::populate_i(key, it->second.lock(), l3_proto_t::IPV6);
 */

  /*     ++it; */
  /* } */
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
