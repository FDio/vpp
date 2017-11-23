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

#include "vom/dhcp_config.hpp"
#include "vom/dhcp_config_cmds.hpp"

namespace VOM {
/**
 * A DB of all DHCP configs
 */
singular_db<interface::key_t, dhcp_config> dhcp_config::m_db;

dhcp_config::event_handler dhcp_config::m_evh;

dhcp_config::dhcp_config(const interface& itf, const std::string& hostname)
  : m_itf(itf.singular())
  , m_hostname(hostname)
  , m_client_id(l2_address_t::ZERO)
  , m_binding(0)
{
}

dhcp_config::dhcp_config(const interface& itf,
                         const std::string& hostname,
                         const l2_address_t& client_id)
  : m_itf(itf.singular())
  , m_hostname(hostname)
  , m_client_id(client_id)
  , m_binding(0)
{
}

dhcp_config::dhcp_config(const dhcp_config& o)
  : m_itf(o.m_itf)
  , m_hostname(o.m_hostname)
  , m_client_id(o.m_client_id)
  , m_binding(0)
{
}

dhcp_config::~dhcp_config()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_itf->key(), this);
}

bool
dhcp_config::operator==(const dhcp_config& l) const
{
  return ((key() == l.key()) && (m_hostname == l.m_hostname) &&
          (m_client_id == l.m_client_id));
}

const dhcp_config::key_t&
dhcp_config::key() const
{
  return (m_itf->key());
}

void
dhcp_config::sweep()
{
  if (m_binding) {
    HW::enqueue(
      new dhcp_config_cmds::unbind_cmd(m_binding, m_itf->handle(), m_hostname));
  }
  HW::write();
}

void
dhcp_config::dump(std::ostream& os)
{
  m_db.dump(os);
}

void
dhcp_config::replay()
{
  if (m_binding) {
    HW::enqueue(new dhcp_config_cmds::bind_cmd(m_binding, m_itf->handle(),
                                               m_hostname, m_client_id));
  }
}

std::string
dhcp_config::to_string() const
{
  std::ostringstream s;
  s << "Dhcp-config: " << m_itf->to_string() << " hostname:" << m_hostname
    << " client_id:[" << m_client_id << "] " << m_binding.to_string();

  return (s.str());
}

void
dhcp_config::update(const dhcp_config& desired)
{
  /*
 * the desired state is always that the interface should be created
 */
  if (!m_binding) {
    HW::enqueue(new dhcp_config_cmds::bind_cmd(m_binding, m_itf->handle(),
                                               m_hostname, m_client_id));
  }
}

std::shared_ptr<dhcp_config>
dhcp_config::find_or_add(const dhcp_config& temp)
{
  return (m_db.find_or_add(temp.m_itf->key(), temp));
}

std::shared_ptr<dhcp_config>
dhcp_config::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<dhcp_config>
dhcp_config::singular() const
{
  return find_or_add(*this);
}

dhcp_config::event_listener::event_listener()
  : m_status(rc_t::NOOP)
{
}

HW::item<bool>&
dhcp_config::event_listener::status()
{
  return (m_status);
}

dhcp_config::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "dhcp" }, "DHCP configurations", this);
}

void
dhcp_config::event_handler::handle_replay()
{
  m_db.replay();
}

void
dhcp_config::event_handler::handle_populate(const client_db::key_t& key)
{
  // FIXME
}

dependency_t
dhcp_config::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
dhcp_config::event_handler::show(std::ostream& os)
{
  m_db.dump(os);
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
