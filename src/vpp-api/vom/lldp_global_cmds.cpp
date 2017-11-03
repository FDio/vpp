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

#include "vom/lldp_global_cmds.hpp"

namespace VOM {
namespace lldp_global_cmds {
config_cmd::config_cmd(HW::item<bool>& item,
                       const std::string& system_name,
                       uint32_t tx_hold,
                       uint32_t tx_interval)
  : rpc_cmd(item)
  , m_system_name(system_name)
  , m_tx_hold(tx_hold)
  , m_tx_interval(tx_interval)
{
}

bool
config_cmd::operator==(const config_cmd& other) const
{
  return (m_system_name == other.m_system_name);
}

rc_t
config_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.tx_hold = m_tx_hold;
  payload.tx_interval = m_tx_interval;

  memcpy(payload.system_name, m_system_name.c_str(),
         std::min(sizeof(payload.system_name), m_system_name.length()));

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return rc_t::OK;
}

std::string
config_cmd::to_string() const
{
  std::ostringstream s;
  s << "Lldp-global-config: " << m_hw_item.to_string()
    << " system_name:" << m_system_name << " tx-hold:" << m_tx_hold
    << " tx-interval:" << m_tx_interval;

  return (s.str());
}

}; // namespace lldp_global_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
