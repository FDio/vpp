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

#include <sstream>

#include "vom/api_types.hpp"
#include "vom/mroute_cmds.hpp"
#include "vom/route_api_types.hpp"

namespace VOM {
namespace route {
namespace ip_mroute_cmds {

update_cmd::update_cmd(HW::item<bool>& item,
                       table_id_t id,
                       const mprefix_t& mprefix,
                       const path& path,
                       const itf_flags_t& flags)
  : rpc_cmd(item)
  , m_id(id)
  , m_mprefix(mprefix)
  , m_path(path)
  , m_flags(flags)
{
}

bool
update_cmd::operator==(const update_cmd& other) const
{
  return ((m_mprefix == other.m_mprefix) && (m_id == other.m_id));
}

rc_t
update_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), 1, std::ref(*this));

  auto& payload = req.get_request().get_payload();

  payload.is_add = 1;

  payload.route.table_id = m_id;
  payload.route.prefix = to_api(m_mprefix);

  to_api(m_path, payload.route.paths[0].path);
  payload.route.paths[0].itf_flags = to_api(m_flags);

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
update_cmd::to_string() const
{
  std::ostringstream s;
  s << "ip-mroute-create: " << m_hw_item.to_string() << " table-id:" << m_id
    << " mprefix:" << m_mprefix.to_string() << " path:" << m_path.to_string()
    << " flags:" << m_flags;

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<bool>& item,
                       table_id_t id,
                       const mprefix_t& mprefix,
                       const path& path,
                       const itf_flags_t& flags)
  : rpc_cmd(item)
  , m_id(id)
  , m_mprefix(mprefix)
  , m_path(path)
  , m_flags(flags)
{
}

bool
delete_cmd::operator==(const delete_cmd& other) const
{
  return ((m_mprefix == other.m_mprefix) && (m_id == other.m_id));
}

rc_t
delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), 1, std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;

  payload.route.table_id = m_id;
  payload.route.prefix = to_api(m_mprefix);

  to_api(m_path, payload.route.paths[0].path);
  payload.route.paths[0].itf_flags = to_api(m_flags);

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return rc_t::OK;
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "ip-mroute-delete: " << m_hw_item.to_string() << " id:" << m_id
    << " mprefix:" << m_mprefix.to_string();

  return (s.str());
}

dump_cmd::dump_cmd(route::table_id_t id, const l3_proto_t& proto)
  : m_id(id)
  , m_proto(proto)
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

  payload.table.table_id = m_id;
  payload.table.is_ip6 = m_proto.is_ipv6();

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_cmd::to_string() const
{
  std::ostringstream s;
  s << "ip-mroute-dump: id:" << m_id << " proto:" << m_proto.to_string();

  return (s.str());
}

} // namespace ip_mroute_cmds
} // namespace mroute
} // namespace vom
  /*
   * fd.io coding-style-patch-verification: ON
   *
   * Local Variables:
   * eval: (c-set-style "mozilla")
   * End:
   */
