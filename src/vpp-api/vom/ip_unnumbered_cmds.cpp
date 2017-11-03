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

#include "vom/ip_unnumbered_cmds.hpp"

#include <vapi/vpe.api.vapi.hpp>

namespace VOM {
namespace ip_unnumbered_cmds {

config_cmd::config_cmd(HW::item<bool>& item,
                       const handle_t& itf,
                       const handle_t& l3_itf)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_l3_itf(l3_itf)
{
}

bool
config_cmd::operator==(const config_cmd& o) const
{
  return ((m_itf == o.m_itf) && (m_l3_itf == o.m_l3_itf));
}

rc_t
config_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;
  payload.sw_if_index = m_l3_itf.value();
  payload.unnumbered_sw_if_index = m_itf.value();

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return rc_t::OK;
}

std::string
config_cmd::to_string() const
{
  std::ostringstream s;
  s << "IP-unnumberd-config: " << m_hw_item.to_string()
    << " itf:" << m_itf.to_string() << " l3-itf:" << m_l3_itf.to_string();

  return (s.str());
}

unconfig_cmd::unconfig_cmd(HW::item<bool>& item,
                           const handle_t& itf,
                           const handle_t& l3_itf)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_l3_itf(l3_itf)
{
}

bool
unconfig_cmd::operator==(const unconfig_cmd& o) const
{
  return ((m_itf == o.m_itf) && (m_l3_itf == o.m_l3_itf));
}

rc_t
unconfig_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 0;
  payload.sw_if_index = m_l3_itf.value();
  payload.unnumbered_sw_if_index = m_itf.value();

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return rc_t::OK;
}

std::string
unconfig_cmd::to_string() const
{
  std::ostringstream s;
  s << "IP-unnumberd-unconfig: " << m_hw_item.to_string()
    << " itf:" << m_itf.to_string() << " l3-itf:" << m_l3_itf.to_string();

  return (s.str());
}

}; // namespace ip_unnumbered_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
