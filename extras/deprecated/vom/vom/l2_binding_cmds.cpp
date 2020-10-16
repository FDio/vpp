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

#include "vom/l2_binding_cmds.hpp"

namespace VOM {
namespace l2_binding_cmds {
bind_cmd::bind_cmd(HW::item<bool>& item,
                   const handle_t& itf,
                   uint32_t bd,
                   const l2_binding::l2_port_type_t& port_type)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_bd(bd)
  , m_port_type(port_type)
{
}

bool
bind_cmd::operator==(const bind_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_bd == other.m_bd) &&
          (m_port_type == other.m_port_type));
}

rc_t
bind_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.rx_sw_if_index = m_itf.value();
  payload.bd_id = m_bd;
  payload.shg = 0;
  if (m_port_type == l2_binding::l2_port_type_t::L2_PORT_TYPE_BVI)
    payload.port_type = L2_API_PORT_TYPE_BVI;
  else if (m_port_type == l2_binding::l2_port_type_t::L2_PORT_TYPE_UU_FWD)
    payload.port_type = L2_API_PORT_TYPE_UU_FWD;
  else
    payload.port_type = L2_API_PORT_TYPE_NORMAL;

  payload.enable = 1;

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
bind_cmd::to_string() const
{
  std::ostringstream s;
  s << "L2-bind: " << m_hw_item.to_string() << " itf:" << m_itf.to_string()
    << " bd:" << m_bd << " port-type:" << m_port_type.to_string();

  return (s.str());
}

unbind_cmd::unbind_cmd(HW::item<bool>& item,
                       const handle_t& itf,
                       uint32_t bd,
                       const l2_binding::l2_port_type_t& port_type)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_bd(bd)
  , m_port_type(port_type)
{
}

bool
unbind_cmd::operator==(const unbind_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_bd == other.m_bd) &&
          (m_port_type == other.m_port_type));
}

rc_t
unbind_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.rx_sw_if_index = m_itf.value();
  payload.bd_id = m_bd;
  payload.shg = 0;
  if (m_port_type == l2_binding::l2_port_type_t::L2_PORT_TYPE_BVI)
    payload.port_type = L2_API_PORT_TYPE_BVI;
  else if (m_port_type == l2_binding::l2_port_type_t::L2_PORT_TYPE_UU_FWD)
    payload.port_type = L2_API_PORT_TYPE_UU_FWD;
  else
    payload.port_type = L2_API_PORT_TYPE_NORMAL;

  payload.enable = 0;

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return (rc_t::OK);
}

std::string
unbind_cmd::to_string() const
{
  std::ostringstream s;
  s << "L2-unbind: " << m_hw_item.to_string() << " itf:" << m_itf.to_string()
    << " bd:" << m_bd << " port-type:" << m_port_type;

  return (s.str());
}
}; // namespace l2_binding_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
