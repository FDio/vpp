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

#include "vom/nat_binding.hpp"

namespace VOM {
nat_binding::bind_44_input_cmd::bind_44_input_cmd(HW::item<bool>& item,
                                                  const handle_t& itf,
                                                  const zone_t& zone)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_zone(zone)
{
}

bool
nat_binding::bind_44_input_cmd::operator==(const bind_44_input_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_zone == other.m_zone));
}

rc_t
nat_binding::bind_44_input_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;
  payload.is_inside = (zone_t::INSIDE == m_zone ? 1 : 0);
  payload.sw_if_index = m_itf.value();

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return rc_t::OK;
}

std::string
nat_binding::bind_44_input_cmd::to_string() const
{
  std::ostringstream s;
  s << "nat-44-input-binding-create: " << m_hw_item.to_string()
    << " itf:" << m_itf << " " << m_zone.to_string();

  return (s.str());
}

nat_binding::unbind_44_input_cmd::unbind_44_input_cmd(HW::item<bool>& item,
                                                      const handle_t& itf,
                                                      const zone_t& zone)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_zone(zone)
{
}

bool
nat_binding::unbind_44_input_cmd::operator==(
  const unbind_44_input_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_zone == other.m_zone));
}

rc_t
nat_binding::unbind_44_input_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 0;
  payload.is_inside = (zone_t::INSIDE == m_zone ? 1 : 0);
  payload.sw_if_index = m_itf.value();

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return rc_t::OK;
}

std::string
nat_binding::unbind_44_input_cmd::to_string() const
{
  std::ostringstream s;
  s << "nat-44-input-binding-create: " << m_hw_item.to_string()
    << " itf:" << m_itf << " " << m_zone.to_string();

  return (s.str());
}

nat_binding::dump_44_cmd::dump_44_cmd()
{
}

nat_binding::dump_44_cmd::dump_44_cmd(const dump_44_cmd& d)
{
}

bool
nat_binding::dump_44_cmd::operator==(const dump_44_cmd& other) const
{
  return (true);
}

rc_t
nat_binding::dump_44_cmd::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
nat_binding::dump_44_cmd::to_string() const
{
  return ("nat-binding-dump");
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
