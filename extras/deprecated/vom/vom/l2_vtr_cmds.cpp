/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include "vom/l2_vtr_cmds.hpp"

namespace VOM {
namespace l2_vtr_cmds {

set_cmd::set_cmd(HW::item<l2_vtr::option_t>& item,
                 const handle_t& itf,
                 uint16_t tag)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_tag(tag)
{
}

bool
set_cmd::operator==(const set_cmd& other) const
{
  return (
    (m_hw_item.data() == other.m_hw_item.data() && m_itf == other.m_itf) &&
    (m_tag == other.m_tag));
}

rc_t
set_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_itf.value();
  payload.vtr_op = m_hw_item.data().value();
  payload.push_dot1q = 1;
  payload.tag1 = m_tag;

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
set_cmd::to_string() const
{
  std::ostringstream s;
  s << "L2-vtr-set: " << m_hw_item.to_string() << " itf:" << m_itf.to_string()
    << " tag:" << m_tag;

  return (s.str());
}

}; // namespace vtr_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
