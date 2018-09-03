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

#include "vom/l2_xconnect_cmds.hpp"

namespace VOM {
namespace l2_xconnect_cmds {
bind_cmd::bind_cmd(HW::item<bool>& item,
                   const handle_t& east_itf,
                   const handle_t& west_itf)
  : rpc_cmd(item)
  , m_east_itf(east_itf)
  , m_west_itf(west_itf)
{
}

bool
bind_cmd::operator==(const bind_cmd& other) const
{
  return ((m_east_itf == other.m_east_itf) && (m_west_itf == other.m_west_itf));
}

rc_t
bind_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.rx_sw_if_index = m_east_itf.value();
  payload.tx_sw_if_index = m_west_itf.value();
  payload.enable = 1;

  VAPI_CALL(req.execute());

  wait();

  return (rc_t::OK);
}

std::string
bind_cmd::to_string() const
{
  std::ostringstream s;
  s << "L2-bind: " << m_hw_item.to_string()
    << " east-itf:" << m_east_itf.to_string()
    << " west-itf:" << m_west_itf.to_string();

  return (s.str());
}

unbind_cmd::unbind_cmd(HW::item<bool>& item,
                       const handle_t& east_itf,
                       const handle_t& west_itf)
  : rpc_cmd(item)
  , m_east_itf(east_itf)
  , m_west_itf(west_itf)
{
}

bool
unbind_cmd::operator==(const unbind_cmd& other) const
{
  return ((m_east_itf == other.m_east_itf) && (m_west_itf == other.m_west_itf));
}

rc_t
unbind_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.rx_sw_if_index = m_east_itf.value();
  payload.tx_sw_if_index = m_west_itf.value();
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
  s << "L2-unbind: " << m_hw_item.to_string()
    << " east-itf:" << m_east_itf.to_string()
    << " west-itf:" << m_west_itf.to_string();

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
  return ("l2-xconnect-dump");
}

}; // namespace l2_xconnect_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
