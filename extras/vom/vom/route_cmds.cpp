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

#include "vom/route_cmds.hpp"

namespace VOM {
namespace route {
namespace ip_route_cmds {

static void
to_vpp(const route::path& p, vapi_type_fib_path& payload)
{
  payload.is_drop = 0;
  payload.is_unreach = 0;
  payload.is_prohibit = 0;
  payload.is_local = 0;
  payload.is_classify = 0;
  payload.is_resolve_host = 0;
  payload.is_resolve_attached = 0;

  if (route::path::flags_t::DVR & p.flags()) {
    payload.is_dvr = 1;
  }

  if (route::path::special_t::STANDARD == p.type()) {
    uint8_t path_v6;
    to_bytes(p.nh(), &path_v6, payload.next_hop);

    if (p.rd()) {
      payload.table_id = p.rd()->table_id();
    }
    if (p.itf()) {
      payload.sw_if_index = p.itf()->handle().value();
    }
  } else if (route::path::special_t::DROP == p.type()) {
    payload.is_drop = 1;
  } else if (route::path::special_t::UNREACH == p.type()) {
    payload.is_unreach = 1;
  } else if (route::path::special_t::PROHIBIT == p.type()) {
    payload.is_prohibit = 1;
  } else if (route::path::special_t::LOCAL == p.type()) {
    payload.is_local = 1;
  }
  payload.weight = p.weight();
  payload.preference = p.preference();
  payload.via_label = 0;
  payload.classify_table_index = 0;
}

update_cmd::update_cmd(HW::item<bool>& item,
                       table_id_t id,
                       const prefix_t& prefix,
                       const path_list_t& paths)
  : rpc_cmd(item)
  , m_id(id)
  , m_prefix(prefix)
  , m_paths(paths)
{
  // no multipath yet.
  assert(paths.size() == 1);
}

bool
update_cmd::operator==(const update_cmd& other) const
{
  return ((m_prefix == other.m_prefix) && (m_id == other.m_id));
}

rc_t
update_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();

  payload.route.table_id = m_id;
  payload.is_add = 1;
  payload.is_multipath = 0;

  m_prefix.to_vpp(&payload.route.prefix.is_ip6, payload.route.prefix.address,
                  &payload.route.prefix.address_length);

  uint32_t ii = 0;
  for (auto& p : m_paths)
    to_vpp(p, payload.route.paths[ii++]);

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return rc_t::OK;
}

std::string
update_cmd::to_string() const
{
  std::ostringstream s;
  s << "ip-route-create: " << m_hw_item.to_string() << " table-id:" << m_id
    << " prefix:" << m_prefix.to_string() << " paths:" << m_paths;

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<bool>& item,
                       table_id_t id,
                       const prefix_t& prefix)
  : rpc_cmd(item)
  , m_id(id)
  , m_prefix(prefix)
{
}

bool
delete_cmd::operator==(const delete_cmd& other) const
{
  return ((m_prefix == other.m_prefix) && (m_id == other.m_id));
}

rc_t
delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.route.table_id = m_id;
  payload.is_add = 0;

  m_prefix.to_vpp(&payload.route.prefix.is_ip6, payload.route.prefix.address,
                  &payload.route.prefix.address_length);

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return rc_t::OK;
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "ip-route-delete: " << m_hw_item.to_string() << " id:" << m_id
    << " prefix:" << m_prefix.to_string();

  return (s.str());
}

dump_cmd::dump_cmd(route::table_id_t id)
  : m_id(id)
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
  return ("ip-route-v4-dump");
}

} // namespace ip_route_cmds
} // namespace route
} // namespace vom

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
