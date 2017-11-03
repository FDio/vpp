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

#include "vom/neighbour.hpp"
#include "vom/neighbour_cmds.hpp"

namespace VOM {
singular_db<neighbour::key_t, neighbour> neighbour::m_db;
neighbour::event_handler neighbour::m_evh;

neighbour::neighbour(const interface& itf,
                     const mac_address_t& mac,
                     const boost::asio::ip::address& ip_addr)
  : m_hw(false)
  , m_itf(itf.singular())
  , m_mac(mac)
  , m_ip_addr(ip_addr)
{
}

neighbour::neighbour(const neighbour& bde)
  : m_hw(bde.m_hw)
  , m_itf(bde.m_itf)
  , m_mac(bde.m_mac)
  , m_ip_addr(bde.m_ip_addr)
{
}

neighbour::~neighbour()
{
  sweep();

  // not in the DB anymore.
  m_db.release(std::make_tuple(m_itf->key(), m_mac, m_ip_addr), this);
}

void
neighbour::sweep()
{
  if (m_hw) {
    HW::enqueue(
      new neighbour_cmds::delete_cmd(m_hw, m_itf->handle(), m_mac, m_ip_addr));
  }
  HW::write();
}

void
neighbour::replay()
{
  if (m_hw) {
    HW::enqueue(
      new neighbour_cmds::create_cmd(m_hw, m_itf->handle(), m_mac, m_ip_addr));
  }
}

std::string
neighbour::to_string() const
{
  std::ostringstream s;
  s << "arp-entry:[" << m_itf->to_string() << ", " << m_mac.to_string() << ", "
    << m_ip_addr.to_string() << "]";

  return (s.str());
}

void
neighbour::update(const neighbour& r)
{
  /*
 * create the table if it is not yet created
 */
  if (rc_t::OK != m_hw.rc()) {
    HW::enqueue(
      new neighbour_cmds::create_cmd(m_hw, m_itf->handle(), m_mac, m_ip_addr));
  }
}

std::shared_ptr<neighbour>
neighbour::find_or_add(const neighbour& temp)
{
  return (m_db.find_or_add(
    std::make_tuple(temp.m_itf->key(), temp.m_mac, temp.m_ip_addr), temp));
}

std::shared_ptr<neighbour>
neighbour::singular() const
{
  return find_or_add(*this);
}

void
neighbour::dump(std::ostream& os)
{
  m_db.dump(os);
}

std::ostream&
operator<<(std::ostream& os, const neighbour::key_t& key)
{
  os << "[" << std::get<0>(key) << ", " << std::get<1>(key) << ", "
     << std::get<2>(key) << "]";

  return (os);
}

neighbour::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "neighbour" }, "Neighbours", this);
}

void
neighbour::event_handler::handle_replay()
{
  m_db.replay();
}

void
neighbour::populate_i(const client_db::key_t& key,
                      std::shared_ptr<interface> itf,
                      const l3_proto_t& proto)
{
  /*
 * dump VPP current states
 */
  std::shared_ptr<neighbour_cmds::dump_cmd> cmd =
    std::make_shared<neighbour_cmds::dump_cmd>(
      neighbour_cmds::dump_cmd(itf->handle(), proto));

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    /*
 * construct a neighbour from each recieved record.
 */
    auto& payload = record.get_payload();

    mac_address_t mac(payload.mac_address);
    boost::asio::ip::address ip_addr =
      from_bytes(payload.is_ipv6, payload.ip_address);
    neighbour n(*itf, mac, ip_addr);

    VOM_LOG(log_level_t::DEBUG) << "neighbour-dump: " << itf->to_string()
                                << mac.to_string() << ip_addr.to_string();

    /*
 * Write each of the discovered interfaces into the OM,
 * but disable the HW Command q whilst we do, so that no
 * commands are sent to VPP
 */
    OM::commit(key, n);
  }
}

void
neighbour::event_handler::handle_populate(const client_db::key_t& key)
{
  auto it = interface::cbegin();

  while (it != interface::cend()) {
    neighbour::populate_i(key, it->second.lock(), l3_proto_t::IPV4);
    neighbour::populate_i(key, it->second.lock(), l3_proto_t::IPV6);

    ++it;
  }
}

dependency_t
neighbour::event_handler::order() const
{
  return (dependency_t::ENTRY);
}

void
neighbour::event_handler::show(std::ostream& os)
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
