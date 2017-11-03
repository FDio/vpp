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

#include "vom/interface_span_cmds.hpp"

DEFINE_VAPI_MSG_IDS_SPAN_API_JSON;

namespace VOM {
namespace interface_span_cmds {

config_cmd::config_cmd(HW::item<bool>& item,
                       const handle_t& itf_from,
                       const handle_t& itf_to,
                       const interface_span::state_t& state)
  : rpc_cmd(item)
  , m_itf_from(itf_from)
  , m_itf_to(itf_to)
  , m_state(state)
{
}

bool
config_cmd::operator==(const config_cmd& o) const
{
  return ((m_itf_from == o.m_itf_from) && (m_itf_to == o.m_itf_to) &&
          (m_state == o.m_state));
}

rc_t
config_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_l2 = 0;
  payload.sw_if_index_from = m_itf_from.value();
  payload.sw_if_index_to = m_itf_to.value();
  payload.state = m_state.value();

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return rc_t::OK;
}

std::string
config_cmd::to_string() const
{
  std::ostringstream s;
  s << "itf-span-config: " << m_hw_item.to_string()
    << " itf-from:" << m_itf_from.to_string()
    << " itf-to:" << m_itf_to.to_string() << " state:" << m_state.to_string();

  return (s.str());
}

unconfig_cmd::unconfig_cmd(HW::item<bool>& item,
                           const handle_t& itf_from,
                           const handle_t& itf_to)
  : rpc_cmd(item)
  , m_itf_from(itf_from)
  , m_itf_to(itf_to)
{
}

bool
unconfig_cmd::operator==(const unconfig_cmd& o) const
{
  return ((m_itf_from == o.m_itf_from) && (m_itf_to == o.m_itf_to));
}

rc_t
unconfig_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_l2 = 0;
  payload.sw_if_index_from = m_itf_from.value();
  payload.sw_if_index_to = m_itf_to.value();
  payload.state = 0;

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return rc_t::OK;
}

std::string
unconfig_cmd::to_string() const
{
  std::ostringstream s;
  s << "itf-span-unconfig: " << m_hw_item.to_string()
    << " itf-from:" << m_itf_from.to_string()
    << " itf-to:" << m_itf_to.to_string();

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
  payload.is_l2 = 0;

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_cmd::to_string() const
{
  return ("interface-span-dump");
}

}; // namespace interface_span_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
