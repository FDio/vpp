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

#include "vom/vhost_interface_cmds.hpp"

#include <vapi/vhost_user.api.vapi.hpp>

namespace VOM {
namespace vhost_interface_cmds {
create_cmd::create_cmd(HW::item<handle_t>& item,
                       const std::string& name,
                       const std::string& tag)
  : interface::create_cmd<vapi::Create_vhost_user_if>(item, name)
  , m_tag(tag)
{
}

rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  memset(payload.sock_filename, 0, sizeof(payload.sock_filename));
  memcpy(payload.sock_filename, m_name.c_str(),
         std::min(m_name.length(), sizeof(payload.sock_filename)));
  memset(payload.tag, 0, sizeof(payload.tag));
  memcpy(payload.tag, m_name.c_str(),
         std::min(m_name.length(), sizeof(payload.tag)));

  payload.is_server = 1;
  payload.use_custom_mac = 0;
  payload.renumber = 0;

  VAPI_CALL(req.execute());

  m_hw_item = wait();

  return rc_t::OK;
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "vhost-intf-create: " << m_hw_item.to_string()
    << " name:" << m_name
    << " tag:" << m_tag;

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<handle_t>& item)
  : interface::delete_cmd<vapi::Delete_vhost_user_if>(item)
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

  return rc_t::OK;
}
std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "vhost-itf-delete: " << m_hw_item.to_string()
    << " name:" << m_name;

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
  return ("vhost-itf-dump");
}
} // namespace vhost_interface_cmds
} // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
