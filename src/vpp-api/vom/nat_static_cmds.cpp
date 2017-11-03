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

#include "vom/nat_static_cmds.hpp"

DEFINE_VAPI_MSG_IDS_NAT_API_JSON;

namespace VOM {
namespace nat_static_cmds {

create_44_cmd::create_44_cmd(HW::item<bool>& item,
                             route::table_id_t id,
                             const boost::asio::ip::address_v4& inside,
                             const boost::asio::ip::address_v4& outside)
  : rpc_cmd(item)
  , m_id(id)
  , m_inside(inside)
  , m_outside(outside)
{
}

bool
create_44_cmd::operator==(const create_44_cmd& other) const
{
  return ((m_id == other.m_id) && (m_inside == other.m_inside) &&
          (m_outside == other.m_outside));
}

rc_t
create_44_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;
  payload.addr_only = 1;
  payload.local_port = 0;
  payload.external_port = 0;
  payload.vrf_id = m_id;
  payload.external_sw_if_index = ~0;
  to_bytes(m_inside, payload.local_ip_address);
  to_bytes(m_outside, payload.external_ip_address);

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return rc_t::OK;
}

std::string
create_44_cmd::to_string() const
{
  std::ostringstream s;
  s << "nat-44-static-create: " << m_hw_item.to_string() << " table:" << m_id
    << " inside:" << m_inside.to_string()
    << " outside:" << m_outside.to_string();

  return (s.str());
}

delete_44_cmd::delete_44_cmd(HW::item<bool>& item,
                             route::table_id_t id,
                             const boost::asio::ip::address_v4& inside,
                             const boost::asio::ip::address_v4& outside)
  : rpc_cmd(item)
  , m_id(id)
  , m_inside(inside)
  , m_outside(outside)
{
}

bool
delete_44_cmd::operator==(const delete_44_cmd& other) const
{
  return ((m_id == other.m_id) && (m_inside == other.m_inside) &&
          (m_outside == other.m_outside));
}

rc_t
delete_44_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 0;
  payload.addr_only = 1;
  payload.local_port = 0;
  payload.external_port = 0;
  payload.vrf_id = m_id;
  payload.external_sw_if_index = ~0;
  to_bytes(m_inside, payload.local_ip_address);
  to_bytes(m_outside, payload.external_ip_address);

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return rc_t::OK;
}

std::string
delete_44_cmd::to_string() const
{
  std::ostringstream s;
  s << "nat-44-static-delete: " << m_hw_item.to_string() << " table:" << m_id
    << " inside:" << m_inside.to_string()
    << " outside:" << m_outside.to_string();

  return (s.str());
}

dump_44_cmd::dump_44_cmd()
{
}

dump_44_cmd::dump_44_cmd(const dump_44_cmd& d)
{
}

bool
dump_44_cmd::operator==(const dump_44_cmd& other) const
{
  return (true);
}

rc_t
dump_44_cmd::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_44_cmd::to_string() const
{
  return ("nat-static-dump");
}
} // namespace nat_static_cmds
} // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
