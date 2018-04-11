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

#include "vom/bond_interface_cmds.hpp"

DEFINE_VAPI_MSG_IDS_BOND_API_JSON;

namespace VOM {
namespace bond_interface_cmds {
create_cmd::create_cmd(HW::item<handle_t>& item,
                       const std::string& name,
                       const bond_interface::mode_t& mode,
                       const bond_interface::lb_t& lb,
                       const l2_address_t& l2_address)
  : interface::create_cmd<vapi::Bond_create>(item, name)
  , m_mode(mode)
  , m_lb(lb)
  , m_l2_address(l2_address)
{
}

rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();

  if (m_l2_address != l2_address_t::ZERO) {
    m_l2_address.to_bytes(payload.mac_address, 6);
    payload.use_custom_mac = 1;
  }

  payload.mode = m_mode.value();
  if ((m_mode == bond_interface::mode_t::XOR ||
       m_mode == bond_interface::mode_t::LACP) &&
      m_lb != bond_interface::lb_t::UNSPECIFIED)
    payload.lb = m_lb.value();

  VAPI_CALL(req.execute());

  wait();

  if (m_hw_item.rc() == rc_t::OK) {
    insert_interface();
  }

  return rc_t::OK;
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "bond-intf-create: " << m_hw_item.to_string();

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<handle_t>& item)
  : interface::delete_cmd<vapi::Bond_delete>(item)
{
}

rc_t
delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_hw_item.data().value();

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);
  remove_interface();

  return rc_t::OK;
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "bond-itf-delete: " << m_hw_item.to_string();

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
  return ("bond-itf-dump");
}
} // namespace bond_interface_cmds
} // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
