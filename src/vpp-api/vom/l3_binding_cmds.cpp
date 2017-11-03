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

#include "vom/l3_binding_cmds.hpp"

DEFINE_VAPI_MSG_IDS_IP_API_JSON;

namespace VOM {
namespace l3_binding_cmds {
bind_cmd::bind_cmd(HW::item<bool>& item,
                   const handle_t& itf,
                   const route::prefix_t& pfx)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_pfx(pfx)
{
}

bool
bind_cmd::operator==(const bind_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_pfx == other.m_pfx));
}

rc_t
bind_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_itf.value();
  payload.is_add = 1;
  payload.del_all = 0;

  m_pfx.to_vpp(&payload.is_ipv6, payload.address, &payload.address_length);

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return rc_t::OK;
}

std::string
bind_cmd::to_string() const
{
  std::ostringstream s;
  s << "L3-bind: " << m_hw_item.to_string() << " itf:" << m_itf.to_string()
    << " pfx:" << m_pfx.to_string();

  return (s.str());
}

unbind_cmd::unbind_cmd(HW::item<bool>& item,
                       const handle_t& itf,
                       const route::prefix_t& pfx)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_pfx(pfx)
{
}

bool
unbind_cmd::operator==(const unbind_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_pfx == other.m_pfx));
}

rc_t
unbind_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_itf.value();
  payload.is_add = 0;
  payload.del_all = 0;

  m_pfx.to_vpp(&payload.is_ipv6, payload.address, &payload.address_length);

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return rc_t::OK;
}

std::string
unbind_cmd::to_string() const
{
  std::ostringstream s;
  s << "L3-unbind: " << m_hw_item.to_string() << " itf:" << m_itf.to_string()
    << " pfx:" << m_pfx.to_string();

  return (s.str());
}

dump_v4_cmd::dump_v4_cmd(const handle_t& hdl)
  : m_itf(hdl)
{
}

dump_v4_cmd::dump_v4_cmd(const dump_v4_cmd& d)
  : m_itf(d.m_itf)
{
}

bool
dump_v4_cmd::operator==(const dump_v4_cmd& other) const
{
  return (true);
}

rc_t
dump_v4_cmd::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  auto& payload = m_dump->get_request().get_payload();
  payload.sw_if_index = m_itf.value();
  payload.is_ipv6 = 0;

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_v4_cmd::to_string() const
{
  return ("L3-binding-dump");
}

}; // namespace l3_binding_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
