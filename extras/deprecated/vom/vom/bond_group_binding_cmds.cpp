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

#include "vom/bond_group_binding_cmds.hpp"

namespace VOM {
namespace bond_group_binding_cmds {

bind_cmd::bind_cmd(HW::item<bool>& item,
                   const handle_t& bond_itf,
                   const bond_member& itf)
  : rpc_cmd(item)
  , m_bond_itf(bond_itf)
  , m_itf(itf)
{
}

bool
bind_cmd::operator==(const bind_cmd& other) const
{
  return ((m_bond_itf == other.m_bond_itf) && (m_itf == other.m_itf));
}

rc_t
bind_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();

  m_itf.to_vpp(payload);
  payload.bond_sw_if_index = m_bond_itf.value();

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
bind_cmd::to_string() const
{
  std::ostringstream s;
  s << "bond-itf-bind: " << m_hw_item.to_string()
    << " bond-itf:" << m_bond_itf.to_string()
    << " slave-itf:" << m_itf.hdl().to_string();

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

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return rc_t::OK;
}

std::string
unbind_cmd::to_string() const
{
  std::ostringstream s;
  s << "bond-itf-unbind: " << m_hw_item.to_string()
    << " slave-itf:" << m_itf.to_string();

  return (s.str());
}

dump_cmd::dump_cmd(const handle_t& hdl)
  : m_itf(hdl)
{
}

dump_cmd::dump_cmd(const dump_cmd& d)
  : m_itf(d.m_itf)
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
  payload.sw_if_index = m_itf.value();

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_cmd::to_string() const
{
  return ("bond-slave-itfs-dump");
}

}; // namespace bond_group_binding_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
