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

#include "vom/bridge_domain_cmds.hpp"

DEFINE_VAPI_MSG_IDS_L2_API_JSON;

namespace VOM {
namespace bridge_domain_cmds {
create_cmd::create_cmd(HW::item<uint32_t>& item)
  : rpc_cmd(item)
{
}

bool
create_cmd::operator==(const create_cmd& other) const
{
  return (m_hw_item.data() == other.m_hw_item.data());
}

rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.bd_id = m_hw_item.data();
  payload.flood = 1;
  payload.uu_flood = 1;
  payload.forward = 1;
  payload.learn = 1;
  payload.arp_term = 1;
  payload.mac_age = 0;
  payload.is_add = 1;

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return (rc_t::OK);
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "bridge-domain-create: " << m_hw_item.to_string();

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<uint32_t>& item)
  : rpc_cmd(item)
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
  payload.bd_id = m_hw_item.data();
  payload.is_add = 0;

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return (rc_t::OK);
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "bridge-domain-delete: " << m_hw_item.to_string();

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
  payload.bd_id = ~0;

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_cmd::to_string() const
{
  return ("bridge-domain-dump");
}
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
