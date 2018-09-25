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

#include "vom/ip_punt_redirect.hpp"
#include "vom/ip_punt_redirect_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {
/**
 * A DB of all IP Punt configs
 */
singular_db<ip_punt_redirect::key_t, ip_punt_redirect> ip_punt_redirect::m_db;

ip_punt_redirect::event_handler ip_punt_redirect::m_evh;

ip_punt_redirect::ip_punt_redirect(const interface& rx_itf,
                                   const interface& tx_itf,
                                   const boost::asio::ip::address& addr)
  : m_rx_itf(rx_itf.singular())
  , m_tx_itf(tx_itf.singular())
  , m_addr(addr)
{
}

ip_punt_redirect::ip_punt_redirect(const ip_punt_redirect& o)
  : m_rx_itf(o.m_rx_itf)
  , m_tx_itf(o.m_tx_itf)
  , m_addr(o.m_addr)
  , m_config(o.m_config)
{
}

ip_punt_redirect::~ip_punt_redirect()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_rx_itf->key(), this);
}

void
ip_punt_redirect::sweep()
{
  if (m_config) {
    HW::enqueue(new ip_punt_redirect_cmds::unconfig_cmd(
      m_config, m_rx_itf->handle(), m_tx_itf->handle(), m_addr));
  }
  HW::write();
}

void
ip_punt_redirect::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

void
ip_punt_redirect::replay()
{
  if (m_config) {
    HW::enqueue(new ip_punt_redirect_cmds::config_cmd(
      m_config, m_rx_itf->handle(), m_tx_itf->handle(), m_addr));
  }
}

std::string
ip_punt_redirect::to_string() const
{
  std::ostringstream s;
  s << "IP-punt-redirect-config:"
    << " rx-itf:" << m_rx_itf->to_string()
    << " tx-itf:" << m_tx_itf->to_string() << " next-hop:" << m_addr;

  return (s.str());
}

void
ip_punt_redirect::update(const ip_punt_redirect& desired)
{
  if (!m_config) {
    HW::enqueue(new ip_punt_redirect_cmds::config_cmd(
      m_config, m_rx_itf->handle(), m_tx_itf->handle(), m_addr));
  }
}

std::shared_ptr<ip_punt_redirect>
ip_punt_redirect::find_or_add(const ip_punt_redirect& temp)
{
  return (m_db.find_or_add(temp.m_rx_itf->key(), temp));
}

std::shared_ptr<ip_punt_redirect>
ip_punt_redirect::singular() const
{
  return find_or_add(*this);
}

ip_punt_redirect::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "ip-punt-redirect" },
                            "IP punt redirect configurations", this);
}

void
ip_punt_redirect::event_handler::handle_replay()
{
  m_db.replay();
}

void
ip_punt_redirect::event_handler::handle_populate(const client_db::key_t& key)
{
}

dependency_t
ip_punt_redirect::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
ip_punt_redirect::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
