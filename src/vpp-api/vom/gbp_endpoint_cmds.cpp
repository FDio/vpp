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

#include "vom/gbp_endpoint_cmds.hpp"

DEFINE_VAPI_MSG_IDS_GBP_API_JSON;

namespace VOM {
namespace gbp_endpoint_cmds {

create_cmd::create_cmd(HW::item<bool>& item,
                       const handle_t& itf,
                       const boost::asio::ip::address& ip_addr,
                       epg_id_t epg_id)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_ip_addr(ip_addr)
  , m_epg_id(epg_id)
{
}

bool
create_cmd::operator==(const create_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_ip_addr == other.m_ip_addr) &&
          (m_epg_id == other.m_epg_id));
}

rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;
  payload.endpoint.sw_if_index = m_itf.value();
  payload.endpoint.epg_id = m_epg_id;
  to_bytes(m_ip_addr, &payload.endpoint.is_ip6, payload.endpoint.address);

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return rc_t::OK;
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-endpoint-create: " << m_hw_item.to_string() << " itf:" << m_itf
    << " ip:" << m_ip_addr.to_string() << " epg-id:" << m_epg_id;

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<bool>& item,
                       const handle_t& itf,
                       const boost::asio::ip::address& ip_addr)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_ip_addr(ip_addr)
{
}

bool
delete_cmd::operator==(const delete_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_ip_addr == other.m_ip_addr));
}

rc_t
delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 0;
  payload.endpoint.sw_if_index = m_itf.value();
  payload.endpoint.epg_id = ~0;
  to_bytes(m_ip_addr, &payload.endpoint.is_ip6, payload.endpoint.address);

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return rc_t::OK;
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-endpoint-create: " << m_hw_item.to_string() << " itf:" << m_itf
    << " ip:" << m_ip_addr.to_string();

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
  return ("gbp-endpoint-dump");
}

}; // namespace gbp_endpoint_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
