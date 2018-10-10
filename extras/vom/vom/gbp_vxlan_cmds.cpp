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

#include "vom/gbp_vxlan_cmds.hpp"

#include <vapi/tap.api.vapi.hpp>

namespace VOM {
namespace gbp_vxlan_cmds {
create_cmd::create_cmd(HW::item<handle_t>& item,
                       const std::string& name,
                       uint32_t vni,
                       bool is_l2,
                       uint32_t bd_rd)
  : interface::create_cmd<vapi::Gbp_vxlan_tunnel_add>(item, name)
  , m_vni(vni)
  , m_is_l2(is_l2)
  , m_bd_rd(bd_rd)
{
}

rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();

  payload.tunnel.vni = m_vni;
  payload.tunnel.bd_rd_id = m_bd_rd;
  if (m_is_l2)
    payload.tunnel.mode = GBP_VXLAN_TUNNEL_MODE_L2;
  else
    payload.tunnel.mode = GBP_VXLAN_TUNNEL_MODE_L3;

  VAPI_CALL(req.execute());

  wait();
  if (m_hw_item.rc() == rc_t::OK) {
    insert_interface();
  }

  return (m_hw_item.rc());
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-vxlan-create: " << m_hw_item.to_string() << " vni:" << m_vni
    << " bd/rd:" << m_bd_rd;

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<handle_t>& item, uint32_t vni)
  : interface::delete_cmd<vapi::Gbp_vxlan_tunnel_del>(item)
  , m_vni(vni)
{
}

rc_t
delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.vni = m_vni;

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  remove_interface();
  return rc_t::OK;
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-vxlan-delete: " << m_hw_item.to_string() << " vni:" << m_vni;

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

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_cmd::to_string() const
{
  return ("gbp-vxlan-dump");
}

} // namespace gbp_vxlan_cmds
} // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
