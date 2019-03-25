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

#include "vom/interface_cmds.hpp"
#include "vom/cmd.hpp"

DEFINE_VAPI_MSG_IDS_VPE_API_JSON;
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON;
DEFINE_VAPI_MSG_IDS_AF_PACKET_API_JSON;
DEFINE_VAPI_MSG_IDS_VHOST_USER_API_JSON;

namespace VOM {
namespace interface_cmds {

bvi_create_cmd::bvi_create_cmd(HW::item<handle_t>& item,
                               const std::string& name)
  : create_cmd(item, name)
{
}

rc_t
bvi_create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();

  payload.user_instance = ~0;

  VAPI_CALL(req.execute());

  wait();

  if (m_hw_item.rc() == rc_t::OK) {
    insert_interface();
  }

  return rc_t::OK;
}
std::string
bvi_create_cmd::to_string() const
{
  std::ostringstream s;
  s << "bvi-itf-create: " << m_hw_item.to_string() << " name:" << m_name;

  return (s.str());
}

loopback_create_cmd::loopback_create_cmd(HW::item<handle_t>& item,
                                         const std::string& name)
  : create_cmd(item, name)
{
}

rc_t
loopback_create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  VAPI_CALL(req.execute());

  wait();

  if (m_hw_item.rc() == rc_t::OK) {
    insert_interface();
  }

  return rc_t::OK;
}
std::string
loopback_create_cmd::to_string() const
{
  std::ostringstream s;
  s << "loopback-itf-create: " << m_hw_item.to_string() << " name:" << m_name;

  return (s.str());
}

af_packet_create_cmd::af_packet_create_cmd(HW::item<handle_t>& item,
                                           const std::string& name)
  : create_cmd(item, name)
{
}

rc_t
af_packet_create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();

  payload.use_random_hw_addr = 1;
  memset(payload.host_if_name, 0, sizeof(payload.host_if_name));
  memcpy(payload.host_if_name, m_name.c_str(),
         std::min(m_name.length(), sizeof(payload.host_if_name)));

  VAPI_CALL(req.execute());

  wait();

  if (m_hw_item.rc() == rc_t::OK) {
    insert_interface();
  }

  return rc_t::OK;
}
std::string
af_packet_create_cmd::to_string() const
{
  std::ostringstream s;
  s << "af-packet-itf-create: " << m_hw_item.to_string() << " name:" << m_name;

  return (s.str());
}

vhost_create_cmd::vhost_create_cmd(HW::item<handle_t>& item,
                                   const std::string& name,
                                   const std::string& tag)
  : create_cmd(item, name)
  , m_tag(tag)
{
}

rc_t
vhost_create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  memset(payload.sock_filename, 0, sizeof(payload.sock_filename));
  memcpy(payload.sock_filename, m_name.c_str(),
         std::min(m_name.length(), sizeof(payload.sock_filename)));
  memset(payload.tag, 0, sizeof(payload.tag));

  if (!m_tag.empty())
    memcpy(payload.tag, m_tag.c_str(),
           std::min(m_tag.length(), sizeof(payload.tag)));

  payload.is_server = 0;
  payload.use_custom_mac = 0;
  payload.renumber = 0;

  VAPI_CALL(req.execute());

  wait();

  if (m_hw_item.rc() == rc_t::OK) {
    insert_interface();
  }

  return rc_t::OK;
}

std::string
vhost_create_cmd::to_string() const
{
  std::ostringstream s;
  s << "vhost-intf-create: " << m_hw_item.to_string() << " name:" << m_name
    << " tag:" << m_tag;

  return (s.str());
}

bvi_delete_cmd::bvi_delete_cmd(HW::item<handle_t>& item)
  : delete_cmd(item)
{
}

rc_t
bvi_delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_hw_item.data().value();

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  remove_interface();
  return rc_t::OK;
}

std::string
bvi_delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "bvi-itf-delete: " << m_hw_item.to_string();

  return (s.str());
}

loopback_delete_cmd::loopback_delete_cmd(HW::item<handle_t>& item)
  : delete_cmd(item)
{
}

rc_t
loopback_delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_hw_item.data().value();

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  remove_interface();
  return rc_t::OK;
}

std::string
loopback_delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "loopback-itf-delete: " << m_hw_item.to_string();

  return (s.str());
}

af_packet_delete_cmd::af_packet_delete_cmd(HW::item<handle_t>& item,
                                           const std::string& name)
  : delete_cmd(item, name)
{
}

rc_t
af_packet_delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  memset(payload.host_if_name, 0, sizeof(payload.host_if_name));
  memcpy(payload.host_if_name, m_name.c_str(),
         std::min(m_name.length(), sizeof(payload.host_if_name)));

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  remove_interface();
  return rc_t::OK;
}
std::string
af_packet_delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "af_packet-itf-delete: " << m_hw_item.to_string();

  return (s.str());
}

vhost_delete_cmd::vhost_delete_cmd(HW::item<handle_t>& item,
                                   const std::string& name)
  : delete_cmd(item, name)
{
}

rc_t
vhost_delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_hw_item.data().value();

  VAPI_CALL(req.execute());

  wait();
  remove_interface();

  return rc_t::OK;
}
std::string
vhost_delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "vhost-itf-delete: " << m_hw_item.to_string() << " name:" << m_name;

  return (s.str());
}

state_change_cmd::state_change_cmd(HW::item<interface::admin_state_t>& state,
                                   const HW::item<handle_t>& hdl)
  : rpc_cmd(state)
  , m_hdl(hdl)
{
}

bool
state_change_cmd::operator==(const state_change_cmd& other) const
{
  return ((m_hdl == other.m_hdl) && (m_hw_item == other.m_hw_item));
}

rc_t
state_change_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_hdl.data().value();
  payload.admin_up_down = m_hw_item.data().value();

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
state_change_cmd::to_string() const
{
  std::ostringstream s;
  s << "itf-state-change: " << m_hw_item.to_string()
    << " hdl:" << m_hdl.to_string();
  return (s.str());
}

set_table_cmd::set_table_cmd(HW::item<route::table_id_t>& table,
                             const l3_proto_t& proto,
                             const HW::item<handle_t>& hdl)
  : rpc_cmd(table)
  , m_hdl(hdl)
  , m_proto(proto)
{
}

bool
set_table_cmd::operator==(const set_table_cmd& other) const
{
  return ((m_hdl == other.m_hdl) && (m_proto == other.m_proto) &&
          (m_hw_item == other.m_hw_item));
}

rc_t
set_table_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_hdl.data().value();
  payload.is_ipv6 = m_proto.is_ipv6();
  payload.vrf_id = m_hw_item.data();

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
set_table_cmd::to_string() const
{
  std::ostringstream s;
  s << "itf-set-table: " << m_hw_item.to_string()
    << " proto:" << m_proto.to_string() << " hdl:" << m_hdl.to_string();
  return (s.str());
}

set_mac_cmd::set_mac_cmd(HW::item<l2_address_t>& mac,
                         const HW::item<handle_t>& hdl)
  : rpc_cmd(mac)
  , m_hdl(hdl)
{
}

bool
set_mac_cmd::operator==(const set_mac_cmd& other) const
{
  return ((m_hdl == other.m_hdl) && (m_hw_item == other.m_hw_item));
}

rc_t
set_mac_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_hdl.data().value();
  m_hw_item.data().to_mac().to_bytes(payload.mac_address,
                                     sizeof(payload.mac_address));

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
set_mac_cmd::to_string() const
{
  std::ostringstream s;
  s << "itf-set-mac: " << m_hw_item.to_string() << " hdl:" << m_hdl.to_string();
  return (s.str());
}

collect_detail_stats_change_cmd::collect_detail_stats_change_cmd(
  HW::item<interface::stats_type_t>& item,
  const handle_t& hdl,
  bool enable)
  : rpc_cmd(item)
  , m_hdl(hdl)
  , m_enable(enable)
{
}

bool
collect_detail_stats_change_cmd::operator==(
  const collect_detail_stats_change_cmd& other) const
{
  return ((m_hdl == other.m_hdl) && (m_hw_item == other.m_hw_item) &&
          (m_enable == other.m_enable));
}

rc_t
collect_detail_stats_change_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.sw_if_index = m_hdl.value();
  payload.enable_disable = m_enable;

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
collect_detail_stats_change_cmd::to_string() const
{
  std::ostringstream s;
  s << "itf-stats: " << m_hw_item.to_string() << " hdl:" << m_hdl.to_string();
  return (s.str());
}

events_cmd::events_cmd(interface::event_listener& el)
  : event_cmd(el.status())
  , m_listener(el)
{
}

bool
events_cmd::operator==(const events_cmd& other) const
{
  return (true);
}

rc_t
events_cmd::issue(connection& con)
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

  return (rc_t::OK);
}

void
events_cmd::retire(connection& con)
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
events_cmd::notify()
{
  std::lock_guard<interface_cmds::events_cmd> lg(*this);
  std::vector<interface::event> events;

  for (auto& msg : *this) {
    auto& payload = msg.get_payload();

    handle_t handle(payload.sw_if_index);
    std::shared_ptr<interface> sp = interface::find(handle);

    if (sp) {
      interface::oper_state_t oper_state =
        interface::oper_state_t::from_int(payload.link_up_down);

      VOM_LOG(log_level_t::DEBUG) << "Interface Event: " << sp->to_string()
                                  << " state: " << oper_state.to_string();

      sp->set(oper_state);
      events.push_back({ *sp, oper_state });
    }
  }

  flush();

  m_listener.handle_interface_event(events);
}

std::string
events_cmd::to_string() const
{
  return ("itf-events");
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

  auto& payload = m_dump->get_request().get_payload();
  payload.name_filter_valid = 0;

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_cmd::to_string() const
{
  return ("itf-dump");
}

vhost_dump_cmd::vhost_dump_cmd()
{
}

bool
vhost_dump_cmd::operator==(const vhost_dump_cmd& other) const
{
  return (true);
}

rc_t
vhost_dump_cmd::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
vhost_dump_cmd::to_string() const
{
  return ("vhost-itf-dump");
}

bool
af_packet_dump_cmd::operator==(const af_packet_dump_cmd& other) const
{
  return (true);
}

rc_t
af_packet_dump_cmd::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
af_packet_dump_cmd::to_string() const
{
  return ("af-packet-itf-dump");
}

set_tag::set_tag(HW::item<handle_t>& item, const std::string& name)
  : rpc_cmd(item)
  , m_name(name)
{
}

rc_t
set_tag::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;
  payload.sw_if_index = m_hw_item.data().value();
  memset(payload.tag, 0, sizeof(payload.tag));
  memcpy(payload.tag, m_name.c_str(), m_name.length());

  VAPI_CALL(req.execute());

  return (wait());
}
std::string
set_tag::to_string() const
{
  std::ostringstream s;
  s << "itf-set-tag: " << m_hw_item.to_string() << " name:" << m_name;

  return (s.str());
}

bool
set_tag::operator==(const set_tag& o) const
{
  return ((m_name == o.m_name) && (m_hw_item.data() == o.m_hw_item.data()));
}
}; // namespace interface_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
