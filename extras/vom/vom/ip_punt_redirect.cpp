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
#include "vom/api_types.hpp"
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

ip_punt_redirect::ip_punt_redirect(const interface& tx_itf,
                                   const boost::asio::ip::address& addr)
  : m_rx_itf(nullptr)
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
  m_db.release(key(), this);
}

const ip_punt_redirect::key_t
ip_punt_redirect::key() const
{
  if (m_rx_itf)
    return m_rx_itf->key();
  else
    return ("ALL");
}

void
ip_punt_redirect::sweep()
{
  if (m_config) {
    HW::enqueue(new ip_punt_redirect_cmds::unconfig_cmd(
      m_config, (m_rx_itf ? m_rx_itf->handle() : handle_t::INVALID),
      m_tx_itf->handle(), m_addr));
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
      m_config, (m_rx_itf ? m_rx_itf->handle() : handle_t::INVALID),
      m_tx_itf->handle(), m_addr));
  }
}

std::string
ip_punt_redirect::to_string() const
{
  std::ostringstream s;
  s << "IP-punt-redirect:"
    << " rx-itf:" << key() << " tx-itf:" << m_tx_itf->to_string()
    << " next-hop:" << m_addr;

  return (s.str());
}

void
ip_punt_redirect::update(const ip_punt_redirect& desired)
{
  if (!m_config) {
    HW::enqueue(new ip_punt_redirect_cmds::config_cmd(
      m_config, (m_rx_itf ? m_rx_itf->handle() : handle_t::INVALID),
      m_tx_itf->handle(), m_addr));
  }
}

std::shared_ptr<ip_punt_redirect>
ip_punt_redirect::find_or_add(const ip_punt_redirect& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
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
  std::shared_ptr<ip_punt_redirect_cmds::dump_cmd> cmd =
    std::make_shared<ip_punt_redirect_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<interface> tx_itf =
      interface::find(payload.punt.tx_sw_if_index);
    std::shared_ptr<interface> rx_itf =
      interface::find(payload.punt.rx_sw_if_index);
    boost::asio::ip::address nh = from_api(payload.punt.nh);

    VOM_LOG(log_level_t::DEBUG) << "data: [" << payload.punt.tx_sw_if_index
                                << ", " << payload.punt.rx_sw_if_index << ", "
                                << nh << "]";

    if (rx_itf && tx_itf) {
      ip_punt_redirect ipr(*rx_itf, *tx_itf, nh);
      OM::commit(key, ipr);
      VOM_LOG(log_level_t::DEBUG) << "read: " << ipr.to_string();
    } else if (tx_itf) {
      ip_punt_redirect ipr(*tx_itf, nh);
      OM::commit(key, ipr);
      VOM_LOG(log_level_t::DEBUG) << "read: " << ipr.to_string();
    }
  }
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
