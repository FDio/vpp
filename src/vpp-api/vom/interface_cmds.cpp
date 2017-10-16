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

#include "vom/interface.hpp"
#include "vom/cmd.hpp"

DEFINE_VAPI_MSG_IDS_VPE_API_JSON;
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON;
DEFINE_VAPI_MSG_IDS_AF_PACKET_API_JSON;
DEFINE_VAPI_MSG_IDS_TAP_API_JSON;
DEFINE_VAPI_MSG_IDS_STATS_API_JSON;

namespace VOM {
interface::loopback_create_cmd::loopback_create_cmd(HW::item<handle_t>& item,
                                                    const std::string& name)
  : create_cmd(item, name)
{
}

rc_t
interface::loopback_create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  VAPI_CALL(req.execute());

  m_hw_item = wait();

  if (m_hw_item.rc() == rc_t::OK) {
    interface::add(m_name, m_hw_item);
  }

  return rc_t::OK;
}
std::string
interface::loopback_create_cmd::to_string() const
{
  std::ostringstream s;
  s << "loopback-itf-create: " << m_hw_item.to_string() << " name:" << m_name;

  return (s.str());
}

interface::af_packet_create_cmd::af_packet_create_cmd(HW::item<handle_t>& item,
                                                      const std::string& name)
  : create_cmd(item, name)
{
}

rc_t
interface::af_packet_create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();

  payload.use_random_hw_addr = 1;
  memset(payload.host_if_name, 0, sizeof(payload.host_if_name));
  memcpy(payload.host_if_name, m_name.c_str(),
         std::min(m_name.length(), sizeof(payload.host_if_name)));

  VAPI_CALL(req.execute());

  m_hw_item = wait();

  if (m_hw_item.rc() == rc_t::OK) {
    interface::add(m_name, m_hw_item);
  }

  return rc_t::OK;
}
std::string
interface::af_packet_create_cmd::to_string() const
{
  std::ostringstream s;
  s << "af-packet-itf-create: " << m_hw_item.to_string() << " name:" << m_name;

  return (s.str());
}

interface::tap_create_cmd::tap_create_cmd(HW::item<handle_t>& item,
                                          const std::string& name)
  : create_cmd(item, name)
{
}

rc_t
interface::tap_create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();

  memset(payload.tap_name, 0, sizeof(payload.tap_name));
  memcpy(payload.tap_name, m_name.c_str(),
         std::min(m_name.length(), sizeof(payload.tap_name)));
  payload.use_random_mac = 1;

  VAPI_CALL(req.execute());

  m_hw_item = wait();

  if (m_hw_item.rc() == rc_t::OK) {
    interface::add(m_name, m_hw_item);
  }

  return rc_t::OK;
}

std::string
interface::tap_create_cmd::to_string() const
{
  std::ostringstream s;
  s << "tap-intf-create: " << m_hw_item.to_string() << " name:" << m_name;

  return (s.str());
}

interface::loopback_delete_cmd::loopback_delete_cmd(HW::item<handle_t>& item)
  : delete_cmd(item)
{
}

rc_t
interface::loopback_delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_hw_item.data().value();

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  interface::remove(m_hw_item);
  return rc_t::OK;
}

std::string
interface::loopback_delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "loopback-itf-delete: " << m_hw_item.to_string();

  return (s.str());
}

interface::af_packet_delete_cmd::af_packet_delete_cmd(HW::item<handle_t>& item,
                                                      const std::string& name)
  : delete_cmd(item, name)
{
}

rc_t
interface::af_packet_delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  memset(payload.host_if_name, 0, sizeof(payload.host_if_name));
  memcpy(payload.host_if_name, m_name.c_str(),
         std::min(m_name.length(), sizeof(payload.host_if_name)));

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  interface::remove(m_hw_item);
  return rc_t::OK;
}
std::string
interface::af_packet_delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "af_packet-itf-delete: " << m_hw_item.to_string();

  return (s.str());
}

interface::tap_delete_cmd::tap_delete_cmd(HW::item<handle_t>& item)
  : delete_cmd(item)
{
}

rc_t
interface::tap_delete_cmd::issue(connection& con)
{
  // finally... call VPP

  interface::remove(m_hw_item);
  return rc_t::OK;
}
std::string
interface::tap_delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "tap-itf-delete: " << m_hw_item.to_string();

  return (s.str());
}

interface::state_change_cmd::state_change_cmd(
  HW::item<interface::admin_state_t>& state,
  const HW::item<handle_t>& hdl)
  : rpc_cmd(state)
  , m_hdl(hdl)
{
}

bool
interface::state_change_cmd::operator==(const state_change_cmd& other) const
{
  return ((m_hdl == other.m_hdl) && (m_hw_item == other.m_hw_item));
}

rc_t
interface::state_change_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_hdl.data().value();
  payload.admin_up_down = m_hw_item.data().value();

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return rc_t::OK;
}

std::string
interface::state_change_cmd::to_string() const
{
  std::ostringstream s;
  s << "itf-state-change: " << m_hw_item.to_string()
    << " hdl:" << m_hdl.to_string();
  return (s.str());
}

interface::set_table_cmd::set_table_cmd(HW::item<route::table_id_t>& table,
                                        const l3_proto_t& proto,
                                        const HW::item<handle_t>& hdl)
  : rpc_cmd(table)
  , m_hdl(hdl)
  , m_proto(proto)
{
}

bool
interface::set_table_cmd::operator==(const set_table_cmd& other) const
{
  return ((m_hdl == other.m_hdl) && (m_proto == other.m_proto) &&
          (m_hw_item == other.m_hw_item));
}

rc_t
interface::set_table_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_hdl.data().value();
  payload.is_ipv6 = m_proto.is_ipv6();
  payload.vrf_id = m_hw_item.data();

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return (rc_t::OK);
}

std::string
interface::set_table_cmd::to_string() const
{
  std::ostringstream s;
  s << "itf-set-table: " << m_hw_item.to_string()
    << " proto:" << m_proto.to_string() << " hdl:" << m_hdl.to_string();
  return (s.str());
}

interface::set_mac_cmd::set_mac_cmd(HW::item<l2_address_t>& mac,
                                    const HW::item<handle_t>& hdl)
  : rpc_cmd(mac)
  , m_hdl(hdl)
{
}

bool
interface::set_mac_cmd::operator==(const set_mac_cmd& other) const
{
  return ((m_hdl == other.m_hdl) && (m_hw_item == other.m_hw_item));
}

rc_t
interface::set_mac_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_hdl.data().value();
  m_hw_item.data().to_mac().to_bytes(payload.mac_address,
                                     sizeof(payload.mac_address));

  VAPI_CALL(req.execute());

  m_hw_item.set(wait());

  return (rc_t::OK);
}

std::string
interface::set_mac_cmd::to_string() const
{
  std::ostringstream s;
  s << "itf-set-mac: " << m_hw_item.to_string() << " hdl:" << m_hdl.to_string();
  return (s.str());
}

interface::events_cmd::events_cmd(event_listener& el)
  : event_cmd(el.status())
  , m_listener(el)
{
}

bool
interface::events_cmd::operator==(const events_cmd& other) const
{
  return (true);
}

rc_t
interface::events_cmd::issue(connection& con)
{
  /*
 * First set the call back to handle the interface events
 */
  m_reg.reset(new reg_t(con.ctx(), std::ref(*(static_cast<event_cmd*>(this)))));

  /*
 * then send the request to enable them
 */
  msg_t req(con.ctx(), std::ref(*(static_cast<rpc_cmd*>(this))));

  auto& payload = req.get_request().get_payload();
  payload.enable_disable = 1;
  payload.pid = getpid();

  VAPI_CALL(req.execute());

  wait();

  return (rc_t::INPROGRESS);
}

void
interface::events_cmd::retire(connection& con)
{
  /*
 * disable interface events.
 */
  msg_t req(con.ctx(), std::ref(*(static_cast<rpc_cmd*>(this))));

  auto& payload = req.get_request().get_payload();
  payload.enable_disable = 0;
  payload.pid = getpid();

  VAPI_CALL(req.execute());

  wait();
}

void
interface::events_cmd::notify()
{
  m_listener.handle_interface_event(this);
}

std::string
interface::events_cmd::to_string() const
{
  return ("itf-events");
}

/**
 * Interface statistics
 */
interface::stats_cmd::stats_cmd(stat_listener& el,
                                const std::vector<handle_t>& interfaces)
  : event_cmd(el.status())
  , m_listener(el)
  , m_swifindex(interfaces)
{
}

bool
interface::stats_cmd::operator==(const stats_cmd& other) const
{
  return (true);
}

rc_t
interface::stats_cmd::issue(connection& con)
{
  /*
 * First set the clal back to handle the interface stats
 */
  m_reg.reset(new reg_t(con.ctx(), std::ref(*(static_cast<event_cmd*>(this)))));
  // m_reg->execute();

  /*
 * then send the request to enable them
 */
  msg_t req(con.ctx(), m_swifindex.size(),
            std::ref(*(static_cast<rpc_cmd*>(this))));

  auto& payload = req.get_request().get_payload();
  payload.enable_disable = 1;
  payload.pid = getpid();
  payload.num = m_swifindex.size();

  auto it = m_swifindex.cbegin();
  uint32_t ii = 0;
  while (it != m_swifindex.cend()) {
    payload.sw_ifs[ii] = it->value();
    ++it;
    ++ii;
  }

  VAPI_CALL(req.execute());

  wait();

  return (rc_t::INPROGRESS);
}

void
interface::stats_cmd::retire(connection& con)
{
}

void
interface::stats_cmd::notify()
{
  m_listener.handle_interface_stat(this);
}

std::string
interface::stats_cmd::to_string() const
{
  return ("itf-stats");
}

interface::dump_cmd::dump_cmd()
{
}

bool
interface::dump_cmd::operator==(const dump_cmd& other) const
{
  return (true);
}

rc_t
interface::dump_cmd::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  auto& payload = m_dump->get_request().get_payload();
  payload.name_filter_valid = 0;

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
interface::dump_cmd::to_string() const
{
  return ("itf-dump");
}

interface::set_tag::set_tag(HW::item<handle_t>& item, const std::string& name)
  : rpc_cmd(item)
  , m_name(name)
{
}

rc_t
interface::set_tag::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;
  payload.sw_if_index = m_hw_item.data().value();
  memcpy(payload.tag, m_name.c_str(), m_name.length());

  VAPI_CALL(req.execute());

  wait();

  return rc_t::OK;
}
std::string
interface::set_tag::to_string() const
{
  std::ostringstream s;
  s << "itf-set-tag: " << m_hw_item.to_string() << " name:" << m_name;

  return (s.str());
}

bool
interface::set_tag::operator==(const set_tag& o) const
{
  return ((m_name == o.m_name) && (m_hw_item.data() == o.m_hw_item.data()));
}
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
