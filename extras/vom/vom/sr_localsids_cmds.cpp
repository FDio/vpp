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

#include "vom/sr_localsids_cmds.hpp"
#include "vom/prefix.hpp"

DEFINE_VAPI_MSG_IDS_SR_API_JSON;

namespace VOM {
namespace sr_localsids_cmds {

create_cmd::create_cmd(HW::item<bool> &item,
                       const localsid::sr_behavior_t& behavior,
                       const boost::asio::ip::address_v6& sid, handle_t intf,
                       route::table_id_t vrf)
  : rpc_cmd(item), m_behavior(behavior), m_localsid(sid), m_intf(intf),
    m_table_id(vrf), m_nh()
{
}

create_cmd::create_cmd(HW::item<bool> &item,
                       const localsid::sr_behavior_t& behavior,
                       const boost::asio::ip::address_v6& sid,
                       const boost::asio::ip::address &nh,
                       handle_t intf, route::table_id_t vrf)
  : rpc_cmd(item), m_behavior(behavior), m_localsid(sid), m_intf(intf),
    m_table_id(vrf), m_nh(nh)
{
}

rc_t
create_cmd::issue(connection &con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_del = 0;
  to_bytes(m_localsid, payload.localsid.addr);
  payload.end_psp = 0;
  payload.behavior = m_behavior.value();
  payload.sw_if_index = m_intf.value();
  payload.vlan_index = ~0;
  payload.fib_table = m_table_id;
  if (m_nh.is_v6()) {
    to_bytes(m_nh.to_v6(), payload.nh_addr6);
    memset(payload.nh_addr4, 0, 4);
  } else if (m_nh.is_v4()) {
    to_bytes(m_nh.to_v4(), payload.nh_addr4);
    memset(payload.nh_addr6, 0, 16);
  } else {
    memset(payload.nh_addr4, 0, 4);
    memset(payload.nh_addr6, 0, 16);
  }

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "sr-localsid-create:" << m_hw_item.to_string()
    << "behavior: " << m_behavior.to_string()
    << "sid:" << m_localsid;

  return (s.str());
}

bool
create_cmd::operator==(const create_cmd &other) const
{
  return ((m_behavior == other.m_behavior) && (m_localsid == other.m_localsid));
}


delete_cmd::delete_cmd(HW::item<bool> &item,
                       const boost::asio::ip::address_v6& sid)
  : rpc_cmd(item), m_localsid(sid)
{
}

rc_t
delete_cmd::issue(connection &con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_del = 1;
  to_bytes(m_localsid, payload.localsid.addr);
  payload.end_psp = 0;
  payload.behavior = 0;
  payload.sw_if_index = ~0;
  payload.vlan_index = 0;
  payload.fib_table = 0;
  payload.nh_addr6[16] = 0;
  payload.nh_addr4[4] = 0;

  VAPI_CALL(req.execute());

  return (wait());
}

std::string delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "sr-localsid-delete:" << m_hw_item.to_string()
    << "sid:" << m_localsid;

  return (s.str());
}

bool
delete_cmd::operator==(const delete_cmd &other) const
{
  return (m_localsid == other.m_localsid);
}

rc_t
dump_cmd::issue(connection &con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_cmd::to_string() const
{
  return ("sr-localsid-dump");
}

bool
dump_cmd::operator==(const dump_cmd &other) const
{
  return (true);
}

}; // namespace sr_cmds
}; // namespace VOM
