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
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();

  payload.table_id = m_id;
  payload.is_add = 1;

  m_mprefix.to_vpp(&payload.is_ipv6, payload.grp_address, payload.src_address,
                   &payload.grp_address_length);

  to_vpp(m_path, payload);
  payload.itf_flags = m_flags.value();

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
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.table_id = m_id;
  payload.is_add = 0;

  m_mprefix.to_vpp(&payload.is_ipv6, payload.grp_address, payload.src_address,
                   &payload.grp_address_length);

  to_vpp(m_path, payload);
  payload.itf_flags = m_flags.value();

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

dump_v4_cmd::dump_v4_cmd()
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

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_v4_cmd::to_string() const
{
  return ("ip-mroute-v4-dump");
}

dump_v6_cmd::dump_v6_cmd()
{
}

bool
dump_v6_cmd::operator==(const dump_v6_cmd& other) const
{
  return (true);
}

rc_t
dump_v6_cmd::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_v6_cmd::to_string() const
{
  return ("ip-mroute-v6-dump");
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
