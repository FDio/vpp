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

#include "vom/route.hpp"
#include "vom/route_cmds.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
namespace route {
singular_db<ip_route::key_t, ip_route> ip_route::m_db;

const path::special_t path::special_t::STANDARD(0, "standard");
const path::special_t path::special_t::LOCAL(0, "local");
const path::special_t path::special_t::DROP(0, "standard");
const path::special_t path::special_t::UNREACH(0, "unreachable");
const path::special_t path::special_t::PROHIBIT(0, "prohibit");

path::special_t::special_t(int v, const std::string& s)
  : enum_base<path::special_t>(v, s)
{
}

path::path(special_t special)
  : m_type(special)
  , m_nh_proto(nh_proto_t::IPV4)
  , m_nh()
  , m_rd(nullptr)
  , m_interface(nullptr)
  , m_weight(1)
  , m_preference(0)
{
}

path::path(const boost::asio::ip::address& nh,
           const interface& interface,
           uint8_t weight,
           uint8_t preference)
  : m_type(special_t::STANDARD)
  , m_nh_proto(nh_proto_t::from_address(nh))
  , m_nh(nh)
  , m_rd(nullptr)
  , m_interface(interface.singular())
  , m_weight(weight)
  , m_preference(preference)
{
}

path::path(const route_domain& rd,
           const boost::asio::ip::address& nh,
           uint8_t weight,
           uint8_t preference)
  : m_type(special_t::STANDARD)
  , m_nh_proto(nh_proto_t::from_address(nh))
  , m_nh(nh)
  , m_rd(rd.singular())
  , m_interface(nullptr)
  , m_weight(weight)
  , m_preference(preference)
{
}

path::path(const interface& interface,
           const nh_proto_t& proto,
           uint8_t weight,
           uint8_t preference)
  : m_type(special_t::STANDARD)
  , m_nh_proto(proto)
  , m_nh()
  , m_rd(nullptr)
  , m_interface(interface.singular())
  , m_weight(weight)
  , m_preference(preference)
{
}

path::path(const path& p)
  : m_type(p.m_type)
  , m_nh_proto(p.m_nh_proto)
  , m_nh(p.m_nh)
  , m_rd(p.m_rd)
  , m_interface(p.m_interface)
  , m_weight(p.m_weight)
  , m_preference(p.m_preference)
{
}

bool
path::operator<(const path& p) const
{
  if (m_type < p.m_type)
    return true;
  if (m_rd->table_id() < p.m_rd->table_id())
    return true;
  if (m_nh < p.m_nh)
    return true;
  if (m_interface->handle() < p.m_interface->handle())
    return true;

  return (false);
}

std::string
path::to_string() const
{
  std::ostringstream s;

  s << "path:["
    << "type:" << m_type.to_string() << " proto:" << m_nh_proto.to_string()
    << " neighbour:" << m_nh.to_string();
  if (m_rd) {
    s << " " << m_rd->to_string();
  }
  if (m_interface) {
    s << " " << m_interface->to_string();
  }
  s << " weight:" << static_cast<int>(m_weight)
    << " preference:" << static_cast<int>(m_preference) << "]";

  return (s.str());
}

path::special_t
path::type() const
{
  return m_type;
}

nh_proto_t
path::nh_proto() const
{
  return m_nh_proto;
}

const boost::asio::ip::address&
path::nh() const
{
  return m_nh;
}

std::shared_ptr<route_domain>
path::rd() const
{
  return m_rd;
}

std::shared_ptr<interface>
path::itf() const
{
  return m_interface;
}

uint8_t
path::weight() const
{
  return m_weight;
}

uint8_t
path::preference() const
{
  return m_preference;
}

ip_route::ip_route(const prefix_t& prefix)
  : m_hw(false)
  , m_rd(route_domain::get_default())
  , m_prefix(prefix)
  , m_paths()
{
}

ip_route::ip_route(const ip_route& r)
  : m_hw(r.m_hw)
  , m_rd(r.m_rd)
  , m_prefix(r.m_prefix)
  , m_paths(r.m_paths)
{
}

ip_route::ip_route(const route_domain& rd, const prefix_t& prefix)
  : m_hw(false)
  , m_rd(rd.singular())
  , m_prefix(prefix)
  , m_paths()
{
}

ip_route::~ip_route()
{
  sweep();

  // not in the DB anymore.
  m_db.release(std::make_pair(m_rd->table_id(), m_prefix), this);
}

void
ip_route::add(const path& path)
{
  m_paths.insert(path);
}

void
ip_route::remove(const path& path)
{
  m_paths.erase(path);
}

void
ip_route::sweep()
{
  if (m_hw) {
    HW::enqueue(
      new ip_route_cmds::delete_cmd(m_hw, m_rd->table_id(), m_prefix));
  }
  HW::write();
}

void
ip_route::replay()
{
  if (m_hw) {
    HW::enqueue(
      new ip_route_cmds::update_cmd(m_hw, m_rd->table_id(), m_prefix, m_paths));
  }
}
std::string
ip_route::to_string() const
{
  std::ostringstream s;
  s << "route:[" << m_rd->to_string() << ", " << m_prefix.to_string() << " ["
    << m_paths << "]"
    << "]";

  return (s.str());
}

void
ip_route::update(const ip_route& r)
{
  /*
* create the table if it is not yet created
*/
  if (rc_t::OK != m_hw.rc()) {
    HW::enqueue(
      new ip_route_cmds::update_cmd(m_hw, m_rd->table_id(), m_prefix, m_paths));
  }
}

std::shared_ptr<ip_route>
ip_route::find_or_add(const ip_route& temp)
{
  return (m_db.find_or_add(std::make_pair(temp.m_rd->table_id(), temp.m_prefix),
                           temp));
}

std::shared_ptr<ip_route>
ip_route::singular() const
{
  return find_or_add(*this);
}

void
ip_route::dump(std::ostream& os)
{
  m_db.dump(os);
}

ip_route::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "ip-route" }, "ip route configurations", this);
}

void
ip_route::event_handler::handle_replay()
{
  m_db.replay();
}

void
ip_route::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<ip_route_cmds::dump_v4_cmd> cmd_v4(
    new ip_route_cmds::dump_v4_cmd());
  std::shared_ptr<ip_route_cmds::dump_v6_cmd> cmd_v6(
    new ip_route_cmds::dump_v6_cmd());

  HW::enqueue(cmd_v4);
  HW::enqueue(cmd_v6);
  HW::write();

  for (auto& record : *cmd_v4) {
    auto& payload = record.get_payload();

    prefix_t pfx(0, payload.address, payload.address_length);

    /**
* populating the route domain here
*/
    route_domain rd_temp(payload.table_id);
    std::shared_ptr<route_domain> rd = route_domain::find(rd_temp);
    if (!rd) {
      OM::commit(key, rd_temp);
    }
    ip_route ip_r(rd_temp, pfx);

    for (unsigned int i = 0; i < payload.count; i++) {
      vapi_type_fib_path p = payload.path[i];
      if (p.is_local) {
        path path_v4(path::special_t::LOCAL);
        ip_r.add(path_v4);
      } else if (p.is_drop) {
        path path_v4(path::special_t::DROP);
        ip_r.add(path_v4);
      } else if (p.is_unreach) {
        path path_v4(path::special_t::UNREACH);
        ip_r.add(path_v4);
      } else if (p.is_prohibit) {
        path path_v4(path::special_t::PROHIBIT);
        ip_r.add(path_v4);
      } else {
        std::shared_ptr<interface> itf = interface::find(p.sw_if_index);
        boost::asio::ip::address address = from_bytes(0, p.next_hop);
        path path_v4(address, *itf, p.weight, p.preference);
        ip_r.add(path_v4);
      }
    }
    VOM_LOG(log_level_t::DEBUG) << "ip-route-dump: " << ip_r.to_string();

    /*
* Write each of the discovered interfaces into the OM,
* but disable the HW Command q whilst we do, so that no
* commands are sent to VPP
*/
    OM::commit(key, ip_r);
  }

  for (auto& record : *cmd_v6) {
    auto& payload = record.get_payload();

    prefix_t pfx(1, payload.address, payload.address_length);
    route_domain rd_temp(payload.table_id);
    std::shared_ptr<route_domain> rd = route_domain::find(rd_temp);
    if (!rd) {
      OM::commit(key, rd_temp);
    }
    ip_route ip_r(rd_temp, pfx);

    for (unsigned int i = 0; i < payload.count; i++) {
      vapi_type_fib_path p = payload.path[i];
      if (p.is_local) {
        path path_v6(path::special_t::LOCAL);
        ip_r.add(path_v6);
      } else if (p.is_drop) {
        path path_v6(path::special_t::DROP);
        ip_r.add(path_v6);
      } else if (p.is_unreach) {
        path path_v6(path::special_t::UNREACH);
        ip_r.add(path_v6);
      } else if (p.is_prohibit) {
        path path_v6(path::special_t::PROHIBIT);
        ip_r.add(path_v6);
      } else {
        std::shared_ptr<interface> itf = interface::find(p.sw_if_index);
        boost::asio::ip::address address = from_bytes(1, p.next_hop);
        path path_v6(address, *itf, p.weight, p.preference);
        ip_r.add(path_v6);
      }
    }
    VOM_LOG(log_level_t::DEBUG) << "ip-route-dump: " << ip_r.to_string();

    /*
* Write each of the discovered interfaces into the OM,
* but disable the HW Command q whilst we do, so that no
* commands are sent to VPP
*/
    OM::commit(key, ip_r);
  }
}

dependency_t
ip_route::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
ip_route::event_handler::show(std::ostream& os)
{
  m_db.dump(os);
}

std::ostream&
operator<<(std::ostream& os, const ip_route::key_t& key)
{
  os << "[" << key.first << ", " << key.second.to_string() << "]";

  return (os);
}

std::ostream&
operator<<(std::ostream& os, const path_list_t& key)
{
  os << "[";
  for (auto k : key) {
    os << k.to_string() << " ";
  }
  os << "]";

  return (os);
}
}
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
