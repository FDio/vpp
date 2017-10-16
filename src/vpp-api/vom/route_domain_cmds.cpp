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

#include "vom/route_domain.hpp"

namespace VOM {

route_domain::create_cmd::create_cmd(HW::item<bool>& item,
                                     l3_proto_t proto,
                                     route::table_id_t id)
  : rpc_cmd(item)
  , m_id(id)
  , m_proto(proto)
{
}

bool
route_domain::create_cmd::operator==(const create_cmd& other) const
{
  return (m_id == other.m_id);
}

rc_t
route_domain::create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.table_id = m_id;
  payload.is_add = 1;
  payload.is_ipv6 = m_proto.is_ipv6();

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return (rc_t::OK);
}

std::string
route_domain::create_cmd::to_string() const
{
  std::ostringstream s;
  s << "ip-table-create: " << m_hw_item.to_string() << " id:" << m_id
    << " af:" << m_proto.to_string();

  return (s.str());
}

route_domain::delete_cmd::delete_cmd(HW::item<bool>& item,
                                     l3_proto_t proto,
                                     route::table_id_t id)
  : rpc_cmd(item)
  , m_id(id)
  , m_proto(proto)
{
}

bool
route_domain::delete_cmd::operator==(const delete_cmd& other) const
{
  return (m_id == other.m_id);
}

rc_t
route_domain::delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.table_id = m_id;
  payload.is_add = 0;
  payload.is_ipv6 = m_proto.is_ipv6();

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return (rc_t::OK);
}

std::string
route_domain::delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "ip-table-delete: " << m_hw_item.to_string() << " id:" << m_id
    << " af:" << m_proto.to_string();

  return (s.str());
}
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
