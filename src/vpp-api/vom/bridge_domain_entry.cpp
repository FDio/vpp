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

#include "vom/bridge_domain_entry.hpp"
#include "vom/bridge_domain_entry_cmds.hpp"

namespace VOM {
singular_db<bridge_domain_entry::key_t, bridge_domain_entry>
  bridge_domain_entry::m_db;

bridge_domain_entry::event_handler bridge_domain_entry::m_evh;

bridge_domain_entry::bridge_domain_entry(const bridge_domain& bd,
                                         const mac_address_t& mac,
                                         const interface& tx_itf)
  : m_hw(false)
  , m_mac(mac)
  , m_bd(bd.singular())
  , m_tx_itf(tx_itf.singular())
{
}

bridge_domain_entry::bridge_domain_entry(const mac_address_t& mac,
                                         const interface& tx_itf)
  : m_hw(false)
  , m_mac(mac)
  , m_bd(nullptr)
  , m_tx_itf(tx_itf.singular())
{
  /*
   * the entry goes in the default bridge-domain
   */
  bridge_domain bd(bridge_domain::DEFAULT_TABLE);

  m_bd = bd.singular();
}

bridge_domain_entry::bridge_domain_entry(const bridge_domain_entry& bde)
  : m_hw(bde.m_hw)
  , m_mac(bde.m_mac)
  , m_bd(bde.m_bd)
  , m_tx_itf(bde.m_tx_itf)
{
}

const bridge_domain_entry::key_t
bridge_domain_entry::key() const
{
  return (std::make_pair(m_bd->key(), m_mac));
}

bool
bridge_domain_entry::operator==(const bridge_domain_entry& bde) const
{
  return ((key() == bde.key()) && (m_tx_itf == bde.m_tx_itf));
}

bridge_domain_entry::~bridge_domain_entry()
{
  sweep();

  // not in the DB anymore.
  m_db.release(key(), this);
}

void
bridge_domain_entry::sweep()
{
  if (m_hw) {
    HW::enqueue(new bridge_domain_entry_cmds::delete_cmd(
      m_hw, m_mac, m_bd->id(), interface::type_t::BVI == m_tx_itf->type()));
  }
  HW::write();
}

void
bridge_domain_entry::replay()
{
  if (m_hw) {
    HW::enqueue(new bridge_domain_entry_cmds::create_cmd(
      m_hw, m_mac, m_bd->id(), m_tx_itf->handle(),
      interface::type_t::BVI == m_tx_itf->type()));
  }
}
std::string
bridge_domain_entry::to_string() const
{
  std::ostringstream s;
  s << "bridge-domain-entry:[" << m_bd->to_string() << ", " << m_mac.to_string()
    << ", tx:" << m_tx_itf->name() << "]";

  return (s.str());
}

void
bridge_domain_entry::update(const bridge_domain_entry& r)
{
  /*
   * create the table if it is not yet created
   */
  if (rc_t::OK != m_hw.rc()) {
    HW::enqueue(new bridge_domain_entry_cmds::create_cmd(
      m_hw, m_mac, m_bd->id(), m_tx_itf->handle(),
      interface::type_t::BVI == m_tx_itf->type()));
  }
}

std::shared_ptr<bridge_domain_entry>
bridge_domain_entry::find_or_add(const bridge_domain_entry& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<bridge_domain_entry>
bridge_domain_entry::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<bridge_domain_entry>
bridge_domain_entry::singular() const
{
  return find_or_add(*this);
}

void
bridge_domain_entry::dump(std::ostream& os)
{
  m_db.dump(os);
}

bridge_domain_entry::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "bd-entry" },
                            "bridge domain entry configurations", this);
}

void
bridge_domain_entry::event_handler::handle_replay()
{
  m_db.replay();
}

void
bridge_domain_entry::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<bridge_domain_entry_cmds::dump_cmd> cmd =
    std::make_shared<bridge_domain_entry_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<interface> itf = interface::find(payload.sw_if_index);
    std::shared_ptr<bridge_domain> bd = bridge_domain::find(payload.bd_id);

    if (!bd || !itf) {
      VOM_LOG(log_level_t::ERROR) << "bridge-domain-entry dump:"
                                  << " itf:" << payload.sw_if_index
                                  << " bd:" << payload.bd_id;
      continue;
    }

    mac_address_t mac(payload.mac);
    bridge_domain_entry bd_e(*bd, mac, *itf);

    VOM_LOG(log_level_t::DEBUG) << "bridge-domain-entry dump:"
                                << " " << bd->to_string() << " "
                                << itf->to_string() << " mac:["
                                << mac.to_string() << "]";

    /*
     * Write each of the discovered interfaces into the OM,
     * but disable the HW Command q whilst we do, so that no
     * commands are sent to VPP
     */
    OM::commit(key, bd_e);
  }
}

dependency_t
bridge_domain_entry::event_handler::order() const
{
  return (dependency_t::ENTRY);
}

void
bridge_domain_entry::event_handler::show(std::ostream& os)
{
  m_db.dump(os);
}

std::ostream&
operator<<(std::ostream& os, const bridge_domain_entry::key_t& key)
{
  os << "[" << key.first << ", " << key.second.to_string() << "]";

  return (os);
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
