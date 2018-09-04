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

#include "vom/dhcp_client_cmds.hpp"

DEFINE_VAPI_MSG_IDS_DHCP_API_JSON;

namespace VOM {
namespace dhcp_client_cmds {

bind_cmd::bind_cmd(HW::item<bool>& item,
                   const handle_t& itf,
                   const std::string& hostname,
                   const l2_address_t& client_id,
                   bool set_broadcast_flag)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_hostname(hostname)
  , m_client_id(client_id)
  , m_set_broadcast_flag(set_broadcast_flag)
{
}

bool
bind_cmd::operator==(const bind_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_hostname == other.m_hostname));
}

rc_t
bind_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;
  payload.client.sw_if_index = m_itf.value();
  payload.client.pid = getpid();
  payload.client.want_dhcp_event = 1;
  payload.client.set_broadcast_flag = m_set_broadcast_flag;

  memset(payload.client.hostname, 0, sizeof(payload.client.hostname));
  memcpy(payload.client.hostname, m_hostname.c_str(),
         std::min(sizeof(payload.client.hostname), m_hostname.length()));

  memset(payload.client.id, 0, sizeof(payload.client.id));
  payload.client.id[0] = 1;
  std::copy_n(begin(m_client_id.bytes),
              std::min(sizeof(payload.client.id), m_client_id.bytes.size()),
              payload.client.id + 1);

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
bind_cmd::to_string() const
{
  std::ostringstream s;
  s << "Dhcp-client-bind: " << m_hw_item.to_string()
    << " itf:" << m_itf.to_string() << " hostname:" << m_hostname;

  return (s.str());
}

unbind_cmd::unbind_cmd(HW::item<bool>& item,
                       const handle_t& itf,
                       const std::string& hostname)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_hostname(hostname)
{
}

bool
unbind_cmd::operator==(const unbind_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_hostname == other.m_hostname));
}

rc_t
unbind_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 0;
  payload.client.sw_if_index = m_itf.value();
  payload.client.pid = getpid();
  payload.client.want_dhcp_event = 0;

  memcpy(payload.client.hostname, m_hostname.c_str(),
         std::min(sizeof(payload.client.hostname), m_hostname.length()));

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return rc_t::OK;
}

std::string
unbind_cmd::to_string() const
{
  std::ostringstream s;
  s << "Dhcp-client-unbind: " << m_hw_item.to_string()
    << " itf:" << m_itf.to_string() << " hostname:" << m_hostname;

  return (s.str());
}

events_cmd::events_cmd(dhcp_client::event_listener& el)
  : event_cmd(el.status())
  , m_listener(el)
{
}

events_cmd::~events_cmd()
{
  VOM_LOG(log_level_t::INFO) << "DHCP events destroyed";
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
   * Set the call back to handle DHCP complete envets.
   */
  m_reg.reset(new reg_t(con.ctx(), std::ref(*this)));

  /*
   * return in-progress so the command stays in the pending list.
   */
  return (rc_t::OK);
}

void
events_cmd::retire(connection& con)
{
}

void
events_cmd::notify()
{
  for (auto& msg : *this) {
    auto& payload = msg.get_payload();

    const dhcp_client::state_t& s =
      dhcp_client::state_t::from_vpp(payload.lease.state);
    route::prefix_t pfx(payload.lease.is_ipv6, payload.lease.host_address,
                        payload.lease.mask_width);
    std::shared_ptr<interface> itf = interface::find(payload.lease.sw_if_index);

    if (itf) {
      std::shared_ptr<dhcp_client::lease_t> ev =
        std::make_shared<dhcp_client::lease_t>(
          s, itf, from_bytes(0, payload.lease.router_address), pfx,
          reinterpret_cast<const char*>(payload.lease.hostname),
          mac_address_t(payload.lease.host_mac));
      m_listener.handle_dhcp_event(ev);

      VOM_LOG(log_level_t::INFO) << "DHCP: " << ev->to_string();
    } else {
      VOM_LOG(log_level_t::ERROR) << "DHCP: no interface: "
                                  << payload.lease.sw_if_index;
    }
  }

  flush();
}

std::string
events_cmd::to_string() const
{
  return ("dhcp-events");
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
  return ("dhcp-client-dump");
}

}; // namespace dhcp_client_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
