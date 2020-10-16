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

#include "vom/nat_binding_cmds.hpp"

namespace VOM {
namespace nat_binding_cmds {
bind_44_input_cmd::bind_44_input_cmd(HW::item<bool>& item,
                                     const handle_t& itf,
                                     const nat_binding::zone_t& zone)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_zone(zone)
{
}

bool
bind_44_input_cmd::operator==(const bind_44_input_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_zone == other.m_zone));
}

rc_t
bind_44_input_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;
  payload.flags = (vapi_enum_nat_config_flags)(
    nat_binding::zone_t::INSIDE == m_zone ? NAT_IS_INSIDE : 0);
  payload.sw_if_index = m_itf.value();

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
bind_44_input_cmd::to_string() const
{
  std::ostringstream s;
  s << "nat-44-input-binding-create: " << m_hw_item.to_string()
    << " itf:" << m_itf << " " << m_zone.to_string();

  return (s.str());
}

unbind_44_input_cmd::unbind_44_input_cmd(HW::item<bool>& item,
                                         const handle_t& itf,
                                         const nat_binding::zone_t& zone)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_zone(zone)
{
}

bool
unbind_44_input_cmd::operator==(const unbind_44_input_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_zone == other.m_zone));
}

rc_t
unbind_44_input_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 0;
  payload.flags = (vapi_enum_nat_config_flags)(
    nat_binding::zone_t::INSIDE == m_zone ? NAT_IS_INSIDE : 0);
  payload.sw_if_index = m_itf.value();

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
unbind_44_input_cmd::to_string() const
{
  std::ostringstream s;
  s << "nat-44-input-binding-create: " << m_hw_item.to_string()
    << " itf:" << m_itf << " " << m_zone.to_string();

  return (s.str());
}

bind_44_output_cmd::bind_44_output_cmd(HW::item<bool>& item,
                                       const handle_t& itf,
                                       const nat_binding::zone_t& zone)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_zone(zone)
{
}

bool
bind_44_output_cmd::operator==(const bind_44_output_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_zone == other.m_zone));
}

rc_t
bind_44_output_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;
  payload.flags = (vapi_enum_nat_config_flags)(
    nat_binding::zone_t::INSIDE == m_zone ? NAT_IS_INSIDE : 0);
  payload.sw_if_index = m_itf.value();

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
bind_44_output_cmd::to_string() const
{
  std::ostringstream s;
  s << "nat-44-output-binding-create: " << m_hw_item.to_string()
    << " itf:" << m_itf << " " << m_zone.to_string();

  return (s.str());
}

unbind_44_output_cmd::unbind_44_output_cmd(HW::item<bool>& item,
                                           const handle_t& itf,
                                           const nat_binding::zone_t& zone)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_zone(zone)
{
}

bool
unbind_44_output_cmd::operator==(const unbind_44_output_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_zone == other.m_zone));
}

rc_t
unbind_44_output_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 0;
  payload.flags = (vapi_enum_nat_config_flags)(
    nat_binding::zone_t::INSIDE == m_zone ? NAT_IS_INSIDE : 0);
  payload.sw_if_index = m_itf.value();

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
unbind_44_output_cmd::to_string() const
{
  std::ostringstream s;
  s << "nat-44-output-binding-create: " << m_hw_item.to_string()
    << " itf:" << m_itf << " " << m_zone.to_string();

  return (s.str());
}

dump_input_44_cmd::dump_input_44_cmd()
{
}

dump_input_44_cmd::dump_input_44_cmd(const dump_input_44_cmd& d)
{
}

bool
dump_input_44_cmd::operator==(const dump_input_44_cmd& other) const
{
  return (true);
}

rc_t
dump_input_44_cmd::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_input_44_cmd::to_string() const
{
  return ("nat-44-input-binding-dump");
}

dump_output_44_cmd::dump_output_44_cmd()
{
}

dump_output_44_cmd::dump_output_44_cmd(const dump_output_44_cmd& d)
{
}

bool
dump_output_44_cmd::operator==(const dump_output_44_cmd& other) const
{
  return (true);
}

rc_t
dump_output_44_cmd::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_output_44_cmd::to_string() const
{
  return ("nat-44-output-binding-dump");
}

bind_66_input_cmd::bind_66_input_cmd(HW::item<bool>& item,
                                     const handle_t& itf,
                                     const nat_binding::zone_t& zone)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_zone(zone)
{
}

bool
bind_66_input_cmd::operator==(const bind_66_input_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_zone == other.m_zone));
}

rc_t
bind_66_input_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;
  payload.flags = (vapi_enum_nat_config_flags)(
    nat_binding::zone_t::INSIDE == m_zone ? NAT_IS_INSIDE : 0);
  payload.sw_if_index = m_itf.value();

  VAPI_CALL(req.execute());

  wait();

  return rc_t::OK;
}

std::string
bind_66_input_cmd::to_string() const
{
  std::ostringstream s;
  s << "nat-66-input-binding-create: " << m_hw_item.to_string()
    << " itf:" << m_itf << " " << m_zone.to_string();

  return (s.str());
}

unbind_66_input_cmd::unbind_66_input_cmd(HW::item<bool>& item,
                                         const handle_t& itf,
                                         const nat_binding::zone_t& zone)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_zone(zone)
{
}

bool
unbind_66_input_cmd::operator==(const unbind_66_input_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_zone == other.m_zone));
}

rc_t
unbind_66_input_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 0;
  payload.flags = (vapi_enum_nat_config_flags)(
    nat_binding::zone_t::INSIDE == m_zone ? NAT_IS_INSIDE : 0);
  payload.sw_if_index = m_itf.value();

  VAPI_CALL(req.execute());

  wait();

  return rc_t::OK;
}

std::string
unbind_66_input_cmd::to_string() const
{
  std::ostringstream s;
  s << "nat-66-input-binding-create: " << m_hw_item.to_string()
    << " itf:" << m_itf << " " << m_zone.to_string();

  return (s.str());
}

dump_input_66_cmd::dump_input_66_cmd()
{
}

dump_input_66_cmd::dump_input_66_cmd(const dump_input_66_cmd& d)
{
}

bool
dump_input_66_cmd::operator==(const dump_input_66_cmd& other) const
{
  return (true);
}

rc_t
dump_input_66_cmd::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_input_66_cmd::to_string() const
{
  return ("nat-66-input-binding-dump");
}

}; // namespace nat_binding_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
