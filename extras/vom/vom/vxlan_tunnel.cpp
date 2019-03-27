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
#include "vom/api_types.hpp"
#include "vom/interface_cmds.hpp"
#include "vom/logger.hpp"
#include "vom/singular_db_funcs.hpp"
#include "vom/vxlan_gbp_tunnel_cmds.hpp"
#include "vom/vxlan_tunnel_cmds.hpp"

namespace VOM {
const std::string VXLAN_TUNNEL_NAME = "vxlan-tunnel-itf";

vxlan_tunnel::event_handler vxlan_tunnel::m_evh;

const vxlan_tunnel::mode_t vxlan_tunnel::mode_t::STANDARD(0, "standard");
const vxlan_tunnel::mode_t vxlan_tunnel::mode_t::GBP_L2(1, "GBP-L2");
const vxlan_tunnel::mode_t vxlan_tunnel::mode_t::GBP_L3(2, "GBP-L3");
const vxlan_tunnel::mode_t vxlan_tunnel::mode_t::GPE(3, "GPE");

vxlan_tunnel::mode_t::mode_t(int v, const std::string s)
  : enum_base<vxlan_tunnel::mode_t>(v, s)
{
}

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

std::string
vxlan_tunnel::endpoint_t::to_string() const
{
  std::ostringstream s;

  s << "ep:["
    << "src:" << src.to_string() << " dst:" << dst.to_string() << " vni:" << vni
    << "]";

  return (s.str());
}

std::string
vxlan_tunnel::mk_name(const boost::asio::ip::address& src,
                      const boost::asio::ip::address& dst,
                      const mode_t& mode,
                      uint32_t vni)
{
  std::ostringstream s;

  s << VXLAN_TUNNEL_NAME << "-" << mode.to_string() << "-" << src << "-" << dst
    << ":" << vni;

  return (s.str());
}

vxlan_tunnel::vxlan_tunnel(const boost::asio::ip::address& src,
                           const boost::asio::ip::address& dst,
                           uint32_t vni,
                           const mode_t& mode)
  : interface(mk_name(src, dst, mode, vni),
              interface::type_t::VXLAN,
              interface::admin_state_t::UP)
  , m_tep(src, dst, vni)
  , m_mode(mode)
  , m_mcast_itf()
  , m_rd()
  , m_table_id(route::DEFAULT_TABLE)
{
}

vxlan_tunnel::vxlan_tunnel(const boost::asio::ip::address& src,
                           const boost::asio::ip::address& dst,
                           uint32_t vni,
                           const interface& mcast_itf,
                           const mode_t& mode)
  : interface(mk_name(src, dst, mode, vni),
              interface::type_t::VXLAN,
              interface::admin_state_t::UP)
  , m_tep(src, dst, vni)
  , m_mode(mode)
  , m_mcast_itf(mcast_itf.singular())
  , m_rd()
  , m_table_id(route::DEFAULT_TABLE)
{
}

vxlan_tunnel::vxlan_tunnel(const boost::asio::ip::address& src,
                           const boost::asio::ip::address& dst,
                           uint32_t vni,
                           const route_domain& rd,
                           const mode_t& mode)
  : interface(mk_name(src, dst, mode, vni),
              interface::type_t::VXLAN,
              interface::admin_state_t::UP)
  , m_tep(src, dst, vni)
  , m_mode(mode)
  , m_mcast_itf()
  , m_rd(rd.singular())
  , m_table_id(m_rd->table_id())
{
}

vxlan_tunnel::vxlan_tunnel(const vxlan_tunnel& o)
  : interface(o)
  , m_tep(o.m_tep)
  , m_mode(o.m_mode)
  , m_mcast_itf(o.m_mcast_itf)
  , m_rd(o.m_rd)
  , m_table_id(o.m_table_id)
{
}

bool
vxlan_tunnel::operator==(const vxlan_tunnel& other) const
{
  return ((m_tep == other.m_tep) && (m_mode == other.m_mode) &&
          (m_mcast_itf == other.m_mcast_itf));
}

const handle_t&
vxlan_tunnel::handle() const
{
  return (m_hdl.data());
}

std::shared_ptr<vxlan_tunnel>
vxlan_tunnel::find(const interface::key_t& k)
{
  return std::dynamic_pointer_cast<vxlan_tunnel>(m_db.find(k));
}

void
vxlan_tunnel::sweep()
{
  if (m_hdl) {
    if (mode_t::STANDARD == m_mode)
      HW::enqueue(new vxlan_tunnel_cmds::delete_cmd(m_hdl, m_tep));
    else if (mode_t::GBP_L2 == m_mode || mode_t::GBP_L3 == m_mode)
      HW::enqueue(new vxlan_gbp_tunnel_cmds::delete_cmd(m_hdl, m_tep));
  }
  HW::write();
}

void
vxlan_tunnel::replay()
{
  if (m_hdl) {
    if (mode_t::STANDARD == m_mode)
      HW::enqueue(new vxlan_tunnel_cmds::create_cmd(
        m_hdl, name(), m_tep,
        (m_mcast_itf ? m_mcast_itf->handle() : handle_t::INVALID)));
    else if (mode_t::GBP_L2 == m_mode)
      HW::enqueue(new vxlan_gbp_tunnel_cmds::create_cmd(
        m_hdl, name(), m_tep, true,
        (m_mcast_itf ? m_mcast_itf->handle() : handle_t::INVALID)));
    else if (mode_t::GBP_L3 == m_mode)
      HW::enqueue(new vxlan_gbp_tunnel_cmds::create_cmd(
        m_hdl, name(), m_tep, false,
        (m_mcast_itf ? m_mcast_itf->handle() : handle_t::INVALID)));
  }
  if (m_rd && (m_rd->table_id() != route::DEFAULT_TABLE)) {
    HW::enqueue(
      new interface_cmds::set_table_cmd(m_table_id, l3_proto_t::IPV4, m_hdl));
    HW::enqueue(
      new interface_cmds::set_table_cmd(m_table_id, l3_proto_t::IPV6, m_hdl));
  }
}

vxlan_tunnel::~vxlan_tunnel()
{
  sweep();
  release();
}

std::string
vxlan_tunnel::to_string() const
{
  std::ostringstream s;
  s << "vxlan-tunnel: " << m_hdl.to_string() << " " << m_mode.to_string() << " "
    << m_tep.to_string();
  if (m_mcast_itf)
    s << " " << m_mcast_itf->to_string();

  return (s.str());
}

void
vxlan_tunnel::update(const vxlan_tunnel& desired)
{
  /*
   * the desired state is always that the interface should be created
   */
  if (rc_t::OK != m_hdl.rc()) {
    if (mode_t::STANDARD == m_mode)
      HW::enqueue(new vxlan_tunnel_cmds::create_cmd(
        m_hdl, name(), m_tep,
        (m_mcast_itf ? m_mcast_itf->handle() : handle_t::INVALID)));
    else if (mode_t::GBP_L2 == m_mode)
      HW::enqueue(new vxlan_gbp_tunnel_cmds::create_cmd(
        m_hdl, name(), m_tep, true,
        (m_mcast_itf ? m_mcast_itf->handle() : handle_t::INVALID)));
    else if (mode_t::GBP_L3 == m_mode)
      HW::enqueue(new vxlan_gbp_tunnel_cmds::create_cmd(
        m_hdl, name(), m_tep, false,
        (m_mcast_itf ? m_mcast_itf->handle() : handle_t::INVALID)));
  }
  if (!m_table_id && m_rd) {
    HW::enqueue(
      new interface_cmds::set_table_cmd(m_table_id, l3_proto_t::IPV4, m_hdl));
    HW::enqueue(
      new interface_cmds::set_table_cmd(m_table_id, l3_proto_t::IPV6, m_hdl));
  }
}

std::shared_ptr<vxlan_tunnel>
vxlan_tunnel::singular() const
{
  return std::dynamic_pointer_cast<vxlan_tunnel>(singular_i());
}

std::shared_ptr<interface>
vxlan_tunnel::singular_i() const
{
  return m_db.find_or_add(key(), *this);
}

void
vxlan_tunnel::event_handler::handle_populate(const client_db::key_t& key)
{
  /*
   * dump VPP current states
   */
  {
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
  {
    std::shared_ptr<vxlan_gbp_tunnel_cmds::dump_cmd> cmd =
      std::make_shared<vxlan_gbp_tunnel_cmds::dump_cmd>();

    HW::enqueue(cmd);
    HW::write();

    for (auto& record : *cmd) {
      auto& payload = record.get_payload();
      handle_t hdl(payload.tunnel.sw_if_index);
      boost::asio::ip::address src = from_api(payload.tunnel.src);
      boost::asio::ip::address dst = from_api(payload.tunnel.dst);

      std::shared_ptr<vxlan_tunnel> vt =
        vxlan_tunnel(src, dst, payload.tunnel.vni,
                     (payload.tunnel.mode == VXLAN_GBP_API_TUNNEL_MODE_L2
                        ? mode_t::GBP_L2
                        : mode_t::GBP_L3))
          .singular();
      vt->set(hdl);

      VOM_LOG(log_level_t::DEBUG) << "dump: " << vt->to_string();

      OM::commit(key, *vt);
    }
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
  return (dependency_t::VIRTUAL_INTERFACE);
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
