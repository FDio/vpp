/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include "vom/acl_ethertype_cmds.hpp"

namespace VOM {
namespace ACL {
namespace acl_ethertype_cmds {

bind_cmd::bind_cmd(HW::item<bool>& item,
                   const handle_t& itf,
                   const acl_ethertype::ethertype_rules_t& le,
                   uint8_t n_input)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_le(le)
  , m_n_input(n_input)
{
}

bool
bind_cmd::operator==(const bind_cmd& other) const
{
  return (m_itf == other.m_itf && m_le == other.m_le);
}

rc_t
bind_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), m_le.size(), std::ref(*this));
  uint32_t i = 0;

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_itf.value();
  payload.count = m_le.size();
  payload.n_input = m_n_input;

  auto it = m_le.cbegin();
  while (it != m_le.cend()) {
    payload.whitelist[i] = it->getEthertype();
    ++it;
    ++i;
  }

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return rc_t::OK;
}

std::string
bind_cmd::to_string() const
{
  std::ostringstream s;
  s << "ACL-Ethertype: " << m_hw_item.to_string()
    << " itf:" << m_itf.to_string() << " ethertype-rules:";
  auto it = m_le.cbegin();
  while (it != m_le.cend()) {
    s << it->to_string();
    ++it;
  }

  s << " rules-size:" << m_le.size()
    << " n_input:" << std::to_string(m_n_input);

  return (s.str());
}

}; // namespace acl_ethertype_cmds
}; // namespace ACL
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
