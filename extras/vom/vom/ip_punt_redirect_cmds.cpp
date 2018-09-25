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

#include "vom/ip_punt_redirect_cmds.hpp"

namespace VOM {
namespace ip_punt_redirect_cmds {

config_cmd::config_cmd(HW::item<bool>& item,
                       const handle_t& rx_itf,
                       const handle_t& tx_itf,
                       const boost::asio::ip::address& addr)
  : rpc_cmd(item)
  , m_rx_itf(rx_itf)
  , m_tx_itf(tx_itf)
  , m_addr(addr)
{
}

bool
config_cmd::operator==(const config_cmd& o) const
{
  return ((m_rx_itf == o.m_rx_itf) && (m_tx_itf == o.m_tx_itf) &&
          (m_addr == o.m_addr));
}

rc_t
config_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();

  payload.is_add = 1;
  payload.rx_sw_if_index = m_rx_itf.value();
  payload.tx_sw_if_index = m_tx_itf.value();

  to_bytes(m_addr, &payload.is_ip6, payload.nh);

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
config_cmd::to_string() const
{
  std::ostringstream s;
  s << "IP-punt-redirect-config: " << m_hw_item.to_string()
    << " rx-itf:" << m_rx_itf.to_string() << " tx-itf:" << m_tx_itf.to_string()
    << " next-hop:" << m_addr;

  return (s.str());
}

unconfig_cmd::unconfig_cmd(HW::item<bool>& item,
                           const handle_t& rx_itf,
                           const handle_t& tx_itf,
                           const boost::asio::ip::address& addr)
  : rpc_cmd(item)
  , m_rx_itf(rx_itf)
  , m_tx_itf(tx_itf)
  , m_addr(addr)
{
}

bool
unconfig_cmd::operator==(const unconfig_cmd& o) const
{
  return ((m_rx_itf == o.m_rx_itf) && (m_tx_itf == o.m_tx_itf) &&
          (m_addr == o.m_addr));
}

rc_t
unconfig_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();

  payload.is_add = 0;
  payload.rx_sw_if_index = m_rx_itf.value();
  payload.tx_sw_if_index = m_tx_itf.value();

  to_bytes(m_addr, &payload.is_ip6, payload.nh);

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return rc_t::OK;
}

std::string
unconfig_cmd::to_string() const
{
  std::ostringstream s;
  s << "IP-punt-redirect-unconfig: " << m_hw_item.to_string()
    << " rx-itf:" << m_rx_itf.to_string() << " tx-itf:" << m_tx_itf.to_string()
    << " next-hop:" << m_addr.to_string();

  return (s.str());
}

}; // namespace ip_punt_redirect_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
