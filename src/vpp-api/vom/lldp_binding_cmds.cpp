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

#include "vom/lldp_binding_cmds.hpp"

DEFINE_VAPI_MSG_IDS_LLDP_API_JSON;

namespace VOM {
namespace lldp_binding_cmds {

bind_cmd::bind_cmd(HW::item<bool>& item,
                   const handle_t& itf,
                   const std::string& port_desc)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_port_desc(port_desc)
{
}

bool
bind_cmd::operator==(const bind_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_port_desc == other.m_port_desc));
}

rc_t
bind_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_itf.value();
  payload.enable = 1;

  memcpy(payload.port_desc, m_port_desc.c_str(),
         std::min(sizeof(payload.port_desc), m_port_desc.length()));

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return rc_t::OK;
}

std::string
bind_cmd::to_string() const
{
  std::ostringstream s;
  s << "Lldp-bind: " << m_hw_item.to_string() << " itf:" << m_itf.to_string()
    << " port_desc:" << m_port_desc;

  return (s.str());
}

unbind_cmd::unbind_cmd(HW::item<bool>& item, const handle_t& itf)
  : rpc_cmd(item)
  , m_itf(itf)
{
}

bool
unbind_cmd::operator==(const unbind_cmd& other) const
{
  return (m_itf == other.m_itf);
}

rc_t
unbind_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_itf.value();
  payload.enable = 0;

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return rc_t::OK;
}

std::string
unbind_cmd::to_string() const
{
  std::ostringstream s;
  s << "Lldp-unbind: " << m_hw_item.to_string() << " itf:" << m_itf.to_string();

  return (s.str());
}

}; // namespace lldp_binding_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
