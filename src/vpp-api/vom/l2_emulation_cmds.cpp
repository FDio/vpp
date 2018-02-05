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

#include "vom/l2_emulation_cmds.hpp"

DEFINE_VAPI_MSG_IDS_L2E_API_JSON;

namespace VOM {
namespace l2_emulation_cmds {
enable_cmd::enable_cmd(HW::item<bool>& item, const handle_t& itf)
  : rpc_cmd(item)
  , m_itf(itf)
{
}

bool
enable_cmd::operator==(const enable_cmd& other) const
{
  return (m_itf == other.m_itf);
}

rc_t
enable_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_itf.value();
  payload.enable = 1;

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return (rc_t::OK);
}

std::string
enable_cmd::to_string() const
{
  std::ostringstream s;
  s << "L2-emulation-enable: " << m_hw_item.to_string()
    << " itf:" << m_itf.to_string();

  return (s.str());
}

disable_cmd::disable_cmd(HW::item<bool>& item, const handle_t& itf)
  : rpc_cmd(item)
  , m_itf(itf)
{
}

bool
disable_cmd::operator==(const disable_cmd& other) const
{
  return (m_itf == other.m_itf);
}

rc_t
disable_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_itf.value();
  payload.enable = 0;

  VAPI_CALL(req.execute());

  wait();

  return (rc_t::OK);
}

std::string
disable_cmd::to_string() const
{
  std::ostringstream s;
  s << "L2-emulation-disable: " << m_hw_item.to_string()
    << " itf:" << m_itf.to_string();

  return (s.str());
}

}; // namespace l2_emulation_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
