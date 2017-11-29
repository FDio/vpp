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

#include "vom/vxlan_tunnel.hpp"
#include "vom/logger.hpp"
#include "vom/vxlan_tunnel_cmds.hpp"

namespace VOM {
const std::string VXLAN_TUNNEL_NAME = "vxlan-tunnel-itf";

vxlan_tunnel::event_handler vxlan_tunnel::m_evh;

/**
 * A DB of all vxlan_tunnels
 * this does not register as a listener for replay events, since the tunnels
 * are also in the base-class interface DB and so will be poked from there.
 */
singular_db<vxlan_tunnel::endpoint_t, vxlan_tunnel> vxlan_tunnel::m_db;

vxlan_tunnel::endpoint_t::endpoint_t(const boost::asio::ip::address& src,
                                     const boost::asio::ip::address& dst,
                                     uint32_t vni)
  : src(src)
  , dst(dst)
  , vni(vni)
{
}

vxlan_tunnel::endpoint_t::endpoint_t()
  : src()
  , dst()
  , vni(0)
{
}

bool
vxlan_tunnel::endpoint_t::operator==(const endpoint_t& other) const
{
  return ((src == other.src) && (dst == other.dst) && (vni == other.vni));
}

bool
vxlan_tunnel::endpoint_t::operator<(const vxlan_tunnel::endpoint_t& o) const
{
  if (src < o.src)
    return true;
  if (dst < o.dst)
    return true;
  if (vni < o.vni)
    return true;

  return false;
}

std::string
vxlan_tunnel::endpoint_t::to_string() const
{
  std::ostringstream s;

  s << "ep:["
    << "src:" << src.to_string() << " dst:" << dst.to_string() << " vni:" << vni
    << "]";

  return (s.str());
}

std::ostream&
operator<<(std::ostream& os, const vxlan_tunnel::endpoint_t& ep)
{
  os << ep.to_string();

  return (os);
}

std::string
vxlan_tunnel::mk_name(const boost::asio::ip::address& src,
                      const boost::asio::ip::address& dst,
                      uint32_t vni)
{
  std::ostringstream s;

  s << VXLAN_TUNNEL_NAME << "-" << src << "-" << dst << ":" << vni;

  return (s.str());
}

vxlan_tunnel::vxlan_tunnel(const boost::asio::ip::address& src,
                           const boost::asio::ip::address& dst,
                           uint32_t vni)
  : interface(mk_name(src, dst, vni),
              interface::type_t::VXLAN,
              interface::admin_state_t::UP)
  , m_tep(src, dst, vni)
{
}

vxlan_tunnel::vxlan_tunnel(const vxlan_tunnel& o)
  : interface(o)
  , m_tep(o.m_tep)
{
}

const handle_t&
vxlan_tunnel::handle() const
{
  return (m_hdl.data());
}

void
vxlan_tunnel::sweep()
{
  if (m_hdl) {
    HW::enqueue(new vxlan_tunnel_cmds::delete_cmd(m_hdl, m_tep));
  }
  HW::write();
}

void
vxlan_tunnel::replay()
{
  if (m_hdl) {
    HW::enqueue(new vxlan_tunnel_cmds::create_cmd(m_hdl, name(), m_tep));
  }
}

vxlan_tunnel::~vxlan_tunnel()
{
  sweep();

  /*
 * release from both DBs
 */
  release();
  m_db.release(m_tep, this);
}

std::string
vxlan_tunnel::to_string() const
{
  std::ostringstream s;
  s << "vxlan-tunnel: " << m_hdl.to_string() << " " << m_tep.to_string();

  return (s.str());
}

void
vxlan_tunnel::update(const vxlan_tunnel& desired)
{
  /*
   * the desired state is always that the interface should be created
   */
  if (!m_hdl) {
    HW::enqueue(new vxlan_tunnel_cmds::create_cmd(m_hdl, name(), m_tep));
  }
}

std::shared_ptr<vxlan_tunnel>
vxlan_tunnel::find_or_add(const vxlan_tunnel& temp)
{
  /*
   * a VXLAN tunnel needs to be in both the interface-find-by-name
   * and the vxlan_tunnel-find-by-endpoint singular databases
   */
  std::shared_ptr<vxlan_tunnel> sp;

  sp = m_db.find_or_add(temp.m_tep, temp);

  interface::m_db.add(temp.name(), sp);

  return (sp);
}

std::shared_ptr<vxlan_tunnel>
vxlan_tunnel::singular() const
{
  return (find_or_add(*this));
}

std::shared_ptr<interface>
vxlan_tunnel::singular_i() const
{
  return find_or_add(*this);
}

void
vxlan_tunnel::dump(std::ostream& os)
{
  m_db.dump(os);
}

void
vxlan_tunnel::event_handler::handle_populate(const client_db::key_t& key)
{
  /*
   * dump VPP current states
   */
  std::shared_ptr<vxlan_tunnel_cmds::dump_cmd> cmd =
    std::make_shared<vxlan_tunnel_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();
    handle_t hdl(payload.sw_if_index);
    boost::asio::ip::address src =
      from_bytes(payload.is_ipv6, payload.src_address);
    boost::asio::ip::address dst =
      from_bytes(payload.is_ipv6, payload.dst_address);

    std::shared_ptr<vxlan_tunnel> vt =
      vxlan_tunnel(src, dst, payload.vni).singular();
    vt->set(hdl);

    VOM_LOG(log_level_t::DEBUG) << "dump: " << vt->to_string();

    OM::commit(key, *vt);
  }
}

vxlan_tunnel::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "vxlan" }, "VXLAN Tunnels", this);
}

void
vxlan_tunnel::event_handler::handle_replay()
{
  // replay is handled from the interface DB
}

dependency_t
vxlan_tunnel::event_handler::order() const
{
  return (dependency_t::TUNNEL);
}

void
vxlan_tunnel::event_handler::show(std::ostream& os)
{
  // dumped by the interface handler
}

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
