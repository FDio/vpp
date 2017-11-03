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

#include "vom/sub_interface_cmds.hpp"
#include "vom/cmd.hpp"

#include <vapi/vpe.api.vapi.hpp>

namespace VOM {
namespace sub_interface_cmds {

create_cmd::create_cmd(HW::item<handle_t>& item,
                       const std::string& name,
                       const handle_t& parent,
                       uint16_t vlan)
  : interface::create_cmd<vapi::Create_vlan_subif>(item, name)
  , m_parent(parent)
  , m_vlan(vlan)
{
}

bool
create_cmd::operator==(const create_cmd& other) const
{
  return ((m_name == other.m_name) && (m_parent == other.m_parent) &&
          (m_vlan == other.m_vlan));
}

rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_parent.value();
  payload.vlan_id = m_vlan;

  VAPI_CALL(req.execute());

  m_hw_item = wait();

  if (m_hw_item.rc() == rc_t::OK) {
    insert_interface();
  }

  return rc_t::OK;
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "sub-itf-create: " << m_hw_item.to_string() << " parent:" << m_parent
    << " vlan:" << m_vlan;
  return (s.str());
}

delete_cmd::delete_cmd(HW::item<handle_t>& item)
  : interface::delete_cmd<vapi::Delete_subif>(item)
{
}

bool
delete_cmd::operator==(const delete_cmd& other) const
{
  return (m_hw_item == other.m_hw_item);
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
  return (rc_t::OK);
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;

  s << "sub-itf-delete: " << m_hw_item.to_string();

  return (s.str());
}
} // namespace sub_interface_cmds
} // namespace VOM
  /*
   * fd.io coding-style-patch-verification: ON
   *
   * Local Variables:
   * eval: (c-set-style "mozilla")
   * End:
   */
