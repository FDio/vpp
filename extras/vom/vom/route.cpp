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
#include "vom/api_types.hpp"
#include "vom/mroute_cmds.hpp"
#include "vom/route_api_types.hpp"
#include "vom/route_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {
namespace route {
ip_route::event_handler ip_route::m_evh;
ip_mroute::event_handler ip_mroute::m_evh;
singular_db<ip_route::key_t, ip_route> ip_route::m_db;
singular_db<ip_mroute::key_t, ip_mroute> ip_mroute::m_db;

const path::special_t path::special_t::STANDARD(0, "standard");
const path::special_t path::special_t::LOCAL(1, "local");
const path::special_t path::special_t::DROP(2, "standard");
const path::special_t path::special_t::UNREACH(3, "unreachable");
const path::special_t path::special_t::PROHIBIT(4, "prohibit");

path::special_t::special_t(int v, const std::string& s)
  : enum_base<path::special_t>(v, s)
{
}

const path::flags_t path::flags_t::NONE(0, "none");
const path::flags_t path::flags_t::DVR((1 << 0), "dvr");

path::flags_t::flags_t(int v, const std::string& s)
  : enum_base<path::flags_t>(v, s)
{
}

const itf_flags_t itf_flags_t::NONE(0, "none");
const itf_flags_t itf_flags_t::ACCEPT((1 << 2), "accept");
const itf_flags_t itf_flags_t::FORWARD((1 << 3), "forward");

itf_flags_t::itf_flags_t(int v, const std::string& s)
  : enum_base<itf_flags_t>(v, s)
{
}
const itf_flags_t&
itf_flags_t::from_vpp(uint32_t val)
{
  if (itf_flags_t::ACCEPT == (int)val)
    return itf_flags_t::ACCEPT;
  else
    return itf_flags_t::FORWARD;
}

path::path(special_t special)
  : m_type(special)
  , m_nh_proto(nh_proto_t::IPV4)
  , m_flags(flags_t::NONE)
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
  , m_flags(flags_t::NONE)
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
  , m_flags(flags_t::NONE)
  , m_nh(nh)
  , m_rd(rd.singular())
  , m_interface(nullptr)
  , m_weight(weight)
  , m_preference(preference)
{
}

path::path(const interface& interface,
           const nh_proto_t& proto,
           const flags_t& flags,
           uint8_t weight,
           uint8_t preference)
  : m_type(special_t::STANDARD)
  , m_nh_proto(proto)
  , m_flags(flags)
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
  , m_flags(p.m_flags)
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
  if (m_nh_proto < p.m_nh_proto)
    return true;
  if (m_flags < p.m_flags)
    return true;
  if (m_type < p.m_type)
    return true;
  if (m_rd && !p.m_rd)
    return false;
  if (!m_rd && p.m_rd)
    return true;
  if (m_rd && p.m_rd) {
    if (m_rd->table_id() < p.m_rd->table_id())
      return true;
    else if (m_rd->table_id() > p.m_rd->table_id())
      return false;
  }
  if (m_nh < p.m_nh)
    return true;
  if (m_interface && !p.m_interface)
    return false;
  if (!m_interface && p.m_interface)
    return true;
  if (m_interface && p.m_interface) {
    if (m_interface->handle() < p.m_interface->handle())
      return true;
    if (p.m_interface->handle() < m_interface->handle())
      return false;
  }

  return (false);
}

path::~path()
{
}

bool
path::operator==(const path& p) const
{
  bool result = true;
  if (m_rd && !p.m_rd)
    return false;
  if (!m_rd && p.m_rd)
    return false;
  if (m_rd && p.m_rd)
    result &= (*m_rd == *p.m_rd);
  if (m_interface && !p.m_interface)
    return false;
  if (!m_interface && p.m_interface)
    return false;
  if (m_interface && p.m_interface)
    result &= (*m_interface == *p.m_interface);
  return (result && (m_type == p.m_type) && (m_nh == p.m_nh) &&
          (m_nh_proto == p.m_nh_proto) && (m_flags == p.m_flags));
}

std::string
path::to_string() const
{
  std::ostringstream s;

  s << "path:["
    << "type:" << m_type.to_string() << " proto:" << m_nh_proto.to_string()
    << " flags:" << m_flags.to_string() << " neighbour:" << m_nh.to_string();
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

path::flags_t
path::flags() const
{
  return m_flags;
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

ip_route::ip_route(const prefix_t& prefix, const path& p)
  : m_hw(false)
  , m_rd(route_domain::get_default())
  , m_prefix(prefix)
  , m_paths({ p })
{
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

ip_route::ip_route(const route_domain& rd,
                   const prefix_t& prefix,
                   const path& p)
  : m_hw(false)
  , m_rd(rd.singular())
  , m_prefix(prefix)
  , m_paths({ p })
{
}

ip_route::~ip_route()
{
  sweep();

  // not in the DB anymore.
  m_db.release(key(), this);
  m_paths.clear();
}

const ip_route::key_t
ip_route::key() const
{
  return (std::make_pair(m_rd->table_id(), m_prefix));
}

bool
ip_route::operator==(const ip_route& i) const
{
  return ((key() == i.key()) && (m_paths == i.m_paths));
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
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<ip_route>
ip_route::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<ip_route>
ip_route::singular() const
{
  return find_or_add(*this);
}

void
ip_route::dump(std::ostream& os)
{
  db_dump(m_db, os);
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
  std::shared_ptr<ip_route_cmds::dump_v4_cmd> cmd_v4 =
    std::make_shared<ip_route_cmds::dump_v4_cmd>();
  std::shared_ptr<ip_route_cmds::dump_v6_cmd> cmd_v6 =
    std::make_shared<ip_route_cmds::dump_v6_cmd>();

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
    std::shared_ptr<route_domain> rd = route_domain::find(payload.table_id);
    if (!rd) {
      OM::commit(key, rd_temp);
    }
    ip_route ip_r(rd_temp, pfx);

    for (unsigned int i = 0; i < payload.count; i++) {
      ip_r.add(from_vpp(payload.path[i], nh_proto_t::IPV4));
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
    std::shared_ptr<route_domain> rd = route_domain::find(payload.table_id);
    if (!rd) {
      OM::commit(key, rd_temp);
    }
    ip_route ip_r(rd_temp, pfx);

    for (unsigned int i = 0; i < payload.count; i++) {
      ip_r.add(from_vpp(payload.path[i], nh_proto_t::IPV6));
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
  return (dependency_t::TABLE);
}

void
ip_route::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}

ip_mroute::ip_mroute(const mprefix_t& mprefix)
  : m_hw(false)
  , m_rd(route_domain::get_default())
  , m_mprefix(mprefix)
  , m_paths()
{
}

ip_mroute::ip_mroute(const ip_mroute& r)
  : m_hw(r.m_hw)
  , m_rd(r.m_rd)
  , m_mprefix(r.m_mprefix)
  , m_paths(r.m_paths)
{
}

ip_mroute::ip_mroute(const route_domain& rd, const mprefix_t& mprefix)
  : m_hw(false)
  , m_rd(rd.singular())
  , m_mprefix(mprefix)
  , m_paths()
{
}

void
ip_mroute::add(const path& path, const itf_flags_t& flag)
{
  m_paths.insert(std::make_pair(path, flag));
}

ip_mroute::~ip_mroute()
{
  sweep();
  m_db.release(key(), this);
}

const ip_mroute::key_t
ip_mroute::key() const
{
  return (std::make_pair(m_rd->table_id(), m_mprefix));
}

bool
ip_mroute::operator==(const ip_mroute& i) const
{
  return ((key() == i.key()) && (m_paths == i.m_paths));
}

void
ip_mroute::sweep()
{
  if (m_hw) {
    for (auto& p : m_paths)
      HW::enqueue(new ip_mroute_cmds::delete_cmd(m_hw, m_rd->table_id(),
                                                 m_mprefix, p.first, p.second));
  }
  HW::write();
}

void
ip_mroute::replay()
{
  if (m_hw) {
    for (auto& p : m_paths)
      HW::enqueue(new ip_mroute_cmds::update_cmd(m_hw, m_rd->table_id(),
                                                 m_mprefix, p.first, p.second));
  }
}
std::string
ip_mroute::to_string() const
{
  std::ostringstream s;
  s << "route:[" << m_rd->to_string() << ", " << m_mprefix.to_string() << " ["
    << m_paths << "]"
    << "]";

  return (s.str());
}

void
ip_mroute::update(const ip_mroute& r)
{
  if (rc_t::OK != m_hw.rc()) {
    for (auto& p : m_paths)
      HW::enqueue(new ip_mroute_cmds::update_cmd(m_hw, m_rd->table_id(),
                                                 m_mprefix, p.first, p.second));
  }
}

std::shared_ptr<ip_mroute>
ip_mroute::find_or_add(const ip_mroute& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<ip_mroute>
ip_mroute::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<ip_mroute>
ip_mroute::singular() const
{
  return find_or_add(*this);
}

void
ip_mroute::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

ip_mroute::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "ip-route" }, "ip route configurations", this);
}

void
ip_mroute::event_handler::handle_replay()
{
  m_db.replay();
}

void
ip_mroute::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<ip_mroute_cmds::dump_v4_cmd> cmd_v4 =
    std::make_shared<ip_mroute_cmds::dump_v4_cmd>();
  std::shared_ptr<ip_mroute_cmds::dump_v6_cmd> cmd_v6 =
    std::make_shared<ip_mroute_cmds::dump_v6_cmd>();

  HW::enqueue(cmd_v4);
  HW::enqueue(cmd_v6);
  HW::write();

  VOM_LOG(log_level_t::INFO) << "ip-mroute-dump: ";

  for (auto& record : *cmd_v4) {
    auto& payload = record.get_payload();

    ip_address_t gaddr = from_bytes(0, payload.grp_address);
    ip_address_t saddr = from_bytes(0, payload.src_address);
    mprefix_t pfx(saddr, gaddr, payload.address_length);

    /**
     * populating the route domain here
     */
    route_domain rd_temp(payload.table_id);
    std::shared_ptr<route_domain> rd = route_domain::find(payload.table_id);
    if (!rd) {
      OM::commit(key, rd_temp);
    }
    ip_mroute ip_r(rd_temp, pfx);

    for (unsigned int i = 0; i < payload.count; i++) {
      vapi_type_mfib_path& p = payload.path[i];
      ip_r.add(from_vpp(p.path, nh_proto_t::IPV4),
               itf_flags_t::from_vpp(p.itf_flags));
    }
    VOM_LOG(log_level_t::INFO) << "ip-mroute-dump: " << ip_r.to_string();

    /*
     * Write each of the discovered interfaces into the OM,
     * but disable the HW Command q whilst we do, so that no
     * commands are sent to VPP
     */
    OM::commit(key, ip_r);
  }

  for (auto& record : *cmd_v6) {
    auto& payload = record.get_payload();

    ip_address_t gaddr = from_bytes(1, payload.grp_address);
    ip_address_t saddr = from_bytes(1, payload.src_address);
    mprefix_t pfx(saddr, gaddr, payload.address_length);

    route_domain rd_temp(payload.table_id);
    std::shared_ptr<route_domain> rd = route_domain::find(payload.table_id);
    if (!rd) {
      OM::commit(key, rd_temp);
    }
    ip_mroute ip_r(rd_temp, pfx);

    for (unsigned int i = 0; i < payload.count; i++) {
      vapi_type_mfib_path& p = payload.path[i];
      ip_r.add(from_vpp(p.path, nh_proto_t::IPV6),
               itf_flags_t::from_vpp(p.itf_flags));
    }
    VOM_LOG(log_level_t::INFO) << "ip-mroute-dump: " << ip_r.to_string();

    /*
     * Write each of the discovered interfaces into the OM,
     * but disable the HW Command q whilst we do, so that no
     * commands are sent to VPP
     */
    OM::commit(key, ip_r);
  }
}

dependency_t
ip_mroute::event_handler::order() const
{
  return (dependency_t::TABLE);
}

void
ip_mroute::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}

std::ostream&
operator<<(std::ostream& os, const ip_route::key_t& key)
{
  os << "[" << key.first << ", " << key.second.to_string() << "]";

  return (os);
}

std::ostream&
operator<<(std::ostream& os, const ip_mroute::key_t& key)
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

std::ostream&
operator<<(std::ostream& os, const mpath_list_t& key)
{
  os << "[";
  for (auto k : key) {
    os << "[" << k.first.to_string() << ", " << k.second.to_string() << "]";
  }
  os << "]";

  return (os);
}

}; // namespace route
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
