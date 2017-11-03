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

#include "vom/vxlan_tunnel_cmds.hpp"

DEFINE_VAPI_MSG_IDS_VXLAN_API_JSON;

namespace VOM {
namespace vxlan_tunnel_cmds {

create_cmd::create_cmd(HW::item<handle_t>& item,
                       const std::string& name,
                       const vxlan_tunnel::endpoint_t& ep)
  : interface::create_cmd<vapi::Vxlan_add_del_tunnel>(item, name)
  , m_ep(ep)
{
}

bool
create_cmd::operator==(const create_cmd& other) const
{
  return (m_ep == other.m_ep);
}

rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;
  payload.is_ipv6 = 0;
  to_bytes(m_ep.src, &payload.is_ipv6, payload.src_address);
  to_bytes(m_ep.dst, &payload.is_ipv6, payload.dst_address);
  payload.mcast_sw_if_index = ~0;
  payload.encap_vrf_id = 0;
  payload.decap_next_index = ~0;
  payload.vni = m_ep.vni;

  VAPI_CALL(req.execute());

  m_hw_item = wait();

  if (m_hw_item) {
    insert_interface();
  }

  return rc_t::OK;
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "vxlan-tunnel-create: " << m_hw_item.to_string() << m_ep.to_string();

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<handle_t>& item,
                       const vxlan_tunnel::endpoint_t& ep)
  : interface::delete_cmd<vapi::Vxlan_add_del_tunnel>(item)
  , m_ep(ep)
{
}

bool
delete_cmd::operator==(const delete_cmd& other) const
{
  return (m_ep == other.m_ep);
}

rc_t
delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto payload = req.get_request().get_payload();
  payload.is_add = 0;
  payload.is_ipv6 = 0;
  to_bytes(m_ep.src, &payload.is_ipv6, payload.src_address);
  to_bytes(m_ep.dst, &payload.is_ipv6, payload.dst_address);
  payload.mcast_sw_if_index = ~0;
  payload.encap_vrf_id = 0;
  payload.decap_next_index = ~0;
  payload.vni = m_ep.vni;

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  remove_interface();
  return (rc_t::OK);
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "vxlan-tunnel-delete: " << m_hw_item.to_string() << m_ep.to_string();

  return (s.str());
}

dump_cmd::dump_cmd()
{
}

bool
dump_cmd::operator==(const dump_cmd& other) const
{
  return (true);
}

rc_t
dump_cmd::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  auto& payload = m_dump->get_request().get_payload();
  payload.sw_if_index = ~0;

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_cmd::to_string() const
{
  return ("Vpp-vxlan_tunnels-Dump");
}
} // namespace vxlan_tunnel_cmds
} // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
