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

#include "vom/dhcp_client.hpp"
#include "vom/dhcp_client_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {
const dhcp_client::state_t dhcp_client::state_t::DISCOVER(0, "discover");
const dhcp_client::state_t dhcp_client::state_t::REQUEST(1, "request");
const dhcp_client::state_t dhcp_client::state_t::BOUND(2, "bound");

dhcp_client::state_t::state_t(int v, const std::string& s)
  : enum_base<dhcp_client::state_t>(v, s)
{
}

const dhcp_client::state_t&
dhcp_client::state_t::from_vpp(int n)
{
  if (REQUEST == n)
    return (REQUEST);
  if (BOUND == n)
    return (BOUND);

  return (DISCOVER);
}

singular_db<interface::key_t, dhcp_client> dhcp_client::m_db;
std::weak_ptr<dhcp_client_cmds::events_cmd> dhcp_client::m_s_event_cmd;
dhcp_client::dhcp_client_listener dhcp_client::m_listener;

dhcp_client::event_handler dhcp_client::m_evh;

dhcp_client::dhcp_client(const interface& itf,
                         const std::string& hostname,
                         bool set_broadcast_flag,
                         event_listener* ev)
  : m_itf(itf.singular())
  , m_hostname(hostname)
  , m_client_id(l2_address_t::ZERO)
  , m_set_broadcast_flag(set_broadcast_flag)
  , m_binding(0)
  , m_evl(ev)
  , m_event_cmd(get_event_cmd())
{
}

dhcp_client::dhcp_client(const interface& itf,
                         const std::string& hostname,
                         const l2_address_t& client_id,
                         bool set_broadcast_flag,
                         event_listener* ev)
  : m_itf(itf.singular())
  , m_hostname(hostname)
  , m_client_id(client_id)
  , m_set_broadcast_flag(set_broadcast_flag)
  , m_binding(0)
  , m_evl(ev)
  , m_event_cmd(get_event_cmd())
{
}

dhcp_client::dhcp_client(const dhcp_client& o)
  : m_itf(o.m_itf)
  , m_hostname(o.m_hostname)
  , m_client_id(o.m_client_id)
  , m_set_broadcast_flag(o.m_set_broadcast_flag)
  , m_binding(0)
  , m_evl(o.m_evl)
  , m_event_cmd(o.m_event_cmd)
{
}

dhcp_client::~dhcp_client()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_itf->key(), this);
}

bool
dhcp_client::operator==(const dhcp_client& l) const
{
  return ((key() == l.key()) && (m_hostname == l.m_hostname) &&
          (m_client_id == l.m_client_id));
}

const dhcp_client::key_t&
dhcp_client::key() const
{
  return (m_itf->key());
}

void
dhcp_client::sweep()
{
  if (m_binding) {
    HW::enqueue(
      new dhcp_client_cmds::unbind_cmd(m_binding, m_itf->handle(), m_hostname));
  }
  HW::write();
}

void
dhcp_client::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

void
dhcp_client::replay()
{
  if (m_binding) {
    HW::enqueue(new dhcp_client_cmds::bind_cmd(m_binding, m_itf->handle(),
                                               m_hostname, m_client_id));
  }
}

std::string
dhcp_client::to_string() const
{
  std::ostringstream s;
  s << "DHCP-client: " << m_itf->to_string() << " hostname:" << m_hostname
    << " client_id:[" << m_client_id << "] " << m_binding.to_string();
  if (m_lease)
    s << " " << m_lease->to_string();
  else
    s << " no-lease";

  return (s.str());
}

void
dhcp_client::update(const dhcp_client& desired)
{
  /*
   * the desired state is always that the interface should be created
   */
  if (!m_binding) {
    HW::enqueue(new dhcp_client_cmds::bind_cmd(m_binding, m_itf->handle(),
                                               m_hostname, m_client_id));
  }

  if (desired.m_lease)
    m_lease = desired.m_lease;
  if (m_evl != desired.m_evl) {
    m_evl = desired.m_evl;
  }
}

const std::shared_ptr<dhcp_client::lease_t>
dhcp_client::lease() const
{
  return (m_lease);
}

void
dhcp_client::lease(std::shared_ptr<dhcp_client::lease_t> lease)
{
  m_lease = lease;
}

std::shared_ptr<dhcp_client>
dhcp_client::find_or_add(const dhcp_client& temp)
{
  return (m_db.find_or_add(temp.m_itf->key(), temp));
}

std::shared_ptr<dhcp_client>
dhcp_client::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<dhcp_client>
dhcp_client::singular() const
{
  return find_or_add(*this);
}

dhcp_client::lease_t::lease_t()
  : state(state_t::DISCOVER)
  , mac(mac_address_t::ZERO)
{
}

dhcp_client::lease_t::lease_t(const state_t& state,
                              std::shared_ptr<interface> itf,
                              const boost::asio::ip::address& router_address,
                              const route::prefix_t& host_prefix,
                              const std::string& hostname,
                              const mac_address_t& mac)
  : state(state)
  , itf(itf)
  , router_address(router_address)
  , host_prefix(host_prefix)
  , hostname(hostname)
  , mac(mac)
{
}

std::string
dhcp_client::lease_t::to_string() const
{
  std::stringstream ss;

  ss << "lease:[" << itf->to_string() << " state: " << state.to_string()
     << " host: " << host_prefix.to_string() << " router: " << router_address
     << " mac: " << mac.to_string() << "]";

  return (ss.str());
}

dhcp_client::event_listener::event_listener()
  : m_status(rc_t::NOOP)
{
}

HW::item<bool>&
dhcp_client::event_listener::status()
{
  return (m_status);
}

dhcp_client::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "dhcp" }, "DHCP clients", this);
}

void
dhcp_client::event_handler::handle_replay()
{
  m_db.replay();
}

void
dhcp_client::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<dhcp_client_cmds::dump_cmd> cmd =
    std::make_shared<dhcp_client_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<interface> itf =
      interface::find(payload.client.sw_if_index);

    if (!itf) {
      VOM_LOG(log_level_t::ERROR) << "dhcp-client dump:"
                                  << " itf:" << payload.client.sw_if_index;
      continue;
    }

    const dhcp_client::state_t& s =
      dhcp_client::state_t::from_vpp(payload.lease.state);
    route::prefix_t pfx(payload.lease.is_ipv6, payload.lease.host_address,
                        payload.lease.mask_width);
    std::string hostname =
      reinterpret_cast<const char*>(payload.lease.hostname);
    l2_address_t l2(payload.client.id + 1);
    dhcp_client dc(*itf, hostname, l2, payload.client.set_broadcast_flag);
    dc.lease(std::make_shared<dhcp_client::lease_t>(
      s, itf, from_bytes(0, payload.lease.router_address), pfx, hostname,
      mac_address_t(payload.lease.host_mac)));
    OM::commit(key, dc);
  }
}

dependency_t
dhcp_client::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
dhcp_client::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}

std::shared_ptr<dhcp_client_cmds::events_cmd>
dhcp_client::get_event_cmd()
{
  if (m_s_event_cmd.expired()) {
    std::shared_ptr<dhcp_client_cmds::events_cmd> c =
      std::make_shared<dhcp_client_cmds::events_cmd>(m_listener);

    m_s_event_cmd = c;

    HW::enqueue(c);
    HW::write();

    return c;
  }

  return (m_s_event_cmd.lock());
}

void
dhcp_client::handle_dhcp_event(std::shared_ptr<lease_t> lease)
{
  m_lease = lease;
  if (m_evl)
    m_evl->handle_dhcp_event(m_lease);
}

void
dhcp_client::dhcp_client_listener::handle_dhcp_event(std::shared_ptr<lease_t> e)
{
  /*
   * Find the client the event references
   */
  std::shared_ptr<dhcp_client> client = find(e->itf->key());

  if (client) {
    client->handle_dhcp_event(e);
  }
}

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
