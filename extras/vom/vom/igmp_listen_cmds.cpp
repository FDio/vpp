/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include "vom/igmp_listen_cmds.hpp"

DEFINE_VAPI_MSG_IDS_IGMP_API_JSON;

namespace VOM {
namespace igmp_listen_cmds {
listen_cmd::listen_cmd(HW::item<bool>& item,
                       const handle_t& itf,
                       const boost::asio::ip::address& gaddr,
                       const igmp_listen::src_addrs_t& saddrs)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_gaddr(gaddr)
  , m_saddrs(saddrs)
{
}

bool
listen_cmd::operator==(const listen_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_gaddr == other.m_gaddr));
}

rc_t
listen_cmd::issue(connection& con)
{
  u8 size = m_saddrs.size();
  msg_t req(con.ctx(), sizeof(vapi_type_ip4_address) * size, std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.group.sw_if_index = m_itf.value();
  payload.group.filter = EXCLUDE;
  to_bytes(m_gaddr.to_v4(), (u8*)&payload.group.gaddr);
  auto addr = m_saddrs.cbegin();
  u8 i = 0;
  while (addr != m_saddrs.cend()) {
    to_bytes(addr->to_v4(), (u8*)&payload.group.saddrs[i]);
    addr++;
    i++;
  }

  payload.group.n_srcs = i;
  VAPI_CALL(req.execute());

  return (wait());
}

std::string
listen_cmd::to_string() const
{
  auto addr = m_saddrs.cbegin();
  std::ostringstream s;
  s << "igmp-listen: " << m_hw_item.to_string() << " itf:" << m_itf.to_string()
    << " group:" << m_gaddr << " src-addrs:[";
  while (addr != m_saddrs.cend()) {
    s << " " << *addr;
    addr++;
  }
  s << " ]";
  return (s.str());
}

unlisten_cmd::unlisten_cmd(HW::item<bool>& item,
                           const handle_t& itf,
                           const boost::asio::ip::address& gaddr)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_gaddr(gaddr)
{
}

bool
unlisten_cmd::operator==(const unlisten_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_gaddr == other.m_gaddr));
}

rc_t
unlisten_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), 0, std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.group.sw_if_index = m_itf.value();
  payload.group.n_srcs = 0;
  payload.group.filter = INCLUDE;
  to_bytes(m_gaddr.to_v4(), (u8*)&payload.group.gaddr);

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return rc_t::OK;
}

std::string
unlisten_cmd::to_string() const
{
  std::ostringstream s;
  s << "igmp-unlisten: " << m_hw_item.to_string()
    << " itf:" << m_itf.to_string() << " group:" << m_gaddr;

  return (s.str());
}

dump_cmd::dump_cmd(const handle_t& hdl)
  : m_itf(hdl)
{
}

dump_cmd::dump_cmd(const dump_cmd& d)
  : m_itf(d.m_itf)
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
  payload.sw_if_index = m_itf.value();

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_cmd::to_string() const
{
  return ("igmp-listen-dump");
}

}; // namespace igmp_listen_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
