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

#include "vom/gbp_route_domain_cmds.hpp"

namespace VOM {
namespace gbp_route_domain_cmds {

create_cmd::create_cmd(HW::item<uint32_t>& item,
                       const handle_t ip4_uu_fwd,
                       const handle_t ip6_uu_fwd)
  : rpc_cmd(item)
  , m_ip4_uu_fwd(ip4_uu_fwd)
  , m_ip6_uu_fwd(ip6_uu_fwd)
{
}

bool
create_cmd::operator==(const create_cmd& other) const
{
  return ((m_hw_item.data() == other.m_hw_item.data()) &&
          (m_ip4_uu_fwd == other.m_ip4_uu_fwd) &&
          (m_ip6_uu_fwd == other.m_ip6_uu_fwd));
}

rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();

  payload.rd.rd_id = m_hw_item.data();
  payload.rd.ip4_uu_sw_if_index = m_ip4_uu_fwd.value();
  payload.rd.ip6_uu_sw_if_index = m_ip6_uu_fwd.value();

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-route-domain: " << m_hw_item.to_string()
    << " ip4-uu-fwd:" << m_ip4_uu_fwd.to_string()
    << " ip6-uu-fwd:" << m_ip6_uu_fwd.to_string();

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<uint32_t>& item)
  : rpc_cmd(item)
{
}

bool
delete_cmd::operator==(const delete_cmd& other) const
{
  return (m_hw_item.data() == other.m_hw_item.data());
}

rc_t
delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();

  payload.rd_id = m_hw_item.data();

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return rc_t::OK;
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-route-domain: " << m_hw_item.to_string();

  return (s.str());
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
  return ("gbp-route-domain-dump");
}

}; // namespace gbp_route_domain_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
