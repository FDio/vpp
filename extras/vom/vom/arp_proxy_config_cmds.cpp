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

#include "vom/arp_proxy_config_cmds.hpp"

namespace VOM {
namespace arp_proxy_config_cmds {

config_cmd::config_cmd(HW::item<bool>& item,
                       const boost::asio::ip::address_v4& low,
                       const boost::asio::ip::address_v4& high)
  : rpc_cmd(item)
  , m_low(low)
  , m_high(high)
{
}

bool
config_cmd::operator==(const config_cmd& o) const
{
  return ((m_low == o.m_low) && (m_high == o.m_high));
}

rc_t
config_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;

  std::copy_n(std::begin(m_low.to_bytes()), m_low.to_bytes().size(),
              payload.low_address);
  std::copy_n(std::begin(m_high.to_bytes()), m_high.to_bytes().size(),
              payload.hi_address);

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return (rc_t::OK);
}

std::string
config_cmd::to_string() const
{
  std::ostringstream s;
  s << "ARP-proxy-config: " << m_hw_item.to_string()
    << " low:" << m_low.to_string() << " high:" << m_high.to_string();

  return (s.str());
}

unconfig_cmd::unconfig_cmd(HW::item<bool>& item,
                           const boost::asio::ip::address_v4& low,
                           const boost::asio::ip::address_v4& high)
  : rpc_cmd(item)
  , m_low(low)
  , m_high(high)
{
}

bool
unconfig_cmd::operator==(const unconfig_cmd& o) const
{
  return ((m_low == o.m_low) && (m_high == o.m_high));
}

rc_t
unconfig_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 0;

  std::copy_n(std::begin(m_low.to_bytes()), m_low.to_bytes().size(),
              payload.low_address);
  std::copy_n(std::begin(m_high.to_bytes()), m_high.to_bytes().size(),
              payload.hi_address);

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return (rc_t::OK);
}

std::string
unconfig_cmd::to_string() const
{
  std::ostringstream s;
  s << "ARP-proxy-unconfig: " << m_hw_item.to_string()
    << " low:" << m_low.to_string() << " high:" << m_high.to_string();

  return (s.str());
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
