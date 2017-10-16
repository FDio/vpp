/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "vom/bridge_domain_entry.hpp"

using namespace VOM;

singular_db<bridge_domain_entry::key_t, bridge_domain_entry> bridge_domain_entry::m_db;

bridge_domain_entry::event_handler bridge_domain_entry::m_evh;

bridge_domain_entry::bridge_domain_entry(const bridge_domain &bd,
                                         const mac_address_t &mac,
                                         const interface &tx_itf)
  : m_hw(false), m_mac(mac), m_bd(bd.singular()), m_tx_itf(tx_itf.singular())
{
}

bridge_domain_entry::bridge_domain_entry(const mac_address_t &mac,
                                         const interface &tx_itf)
  : m_hw(false), m_mac(mac), m_bd(nullptr), m_tx_itf(tx_itf.singular())
{
    /*
     * the route goes in the default table
     */
    bridge_domain bd(bridge_domain::DEFAULT_TABLE);

    m_bd = bd.singular();
}

bridge_domain_entry::bridge_domain_entry(const bridge_domain_entry &bde)
  : m_hw(bde.m_hw), m_mac(bde.m_mac), m_bd(bde.m_bd), m_tx_itf(bde.m_tx_itf)
{
}

bridge_domain_entry::~bridge_domain_entry()
{
    sweep();

    // not in the DB anymore.
    m_db.release(std::make_pair(m_bd->id(), m_mac), this);
}

void bridge_domain_entry::sweep()
{
    if (m_hw)
    {
        HW::enqueue(new delete_cmd(m_hw, m_mac, m_bd->id()));
    }
    HW::write();
}

void bridge_domain_entry::replay()
{
    if (m_hw)
    {
        HW::enqueue(new create_cmd(m_hw, m_mac, m_bd->id(), m_tx_itf->handle()));
    }
}
std::string bridge_domain_entry::to_string() const
{
    std::ostringstream s;
    s << "bridge-domain-entry:["
      << m_bd->to_string()
      << ", "
      << m_mac.to_string()
      << ", tx:"
      << m_tx_itf->name()
      << "]";

    return (s.str());
}

void bridge_domain_entry::update(const bridge_domain_entry &r)
{
    /*
     * create the table if it is not yet created
     */
    if (rc_t::OK != m_hw.rc())
    {
        HW::enqueue(new create_cmd(m_hw, m_mac, m_bd->id(), m_tx_itf->handle()));
    }
}

std::shared_ptr<bridge_domain_entry> bridge_domain_entry::find_or_add(const bridge_domain_entry &temp)
{
    return (m_db.find_or_add(std::make_pair(temp.m_bd->id(),
                                            temp.m_mac),
                             temp));
}

std::shared_ptr<bridge_domain_entry> bridge_domain_entry::singular() const
{
    return find_or_add(*this);
}

void bridge_domain_entry::dump(std::ostream &os)
{
    m_db.dump(os);
}

bridge_domain_entry::event_handler::event_handler()
{
    OM::register_listener(this);
    inspect::register_handler({"bd-entry"}, "bridge domain entry configurations", this);
}

void bridge_domain_entry::event_handler::handle_replay()
{
    m_db.replay();
}

void bridge_domain_entry::event_handler::handle_populate(const client_db::key_t &key)
{

    std::shared_ptr<bridge_domain_entry::dump_cmd> cmd(new bridge_domain_entry::dump_cmd());

    HW::enqueue(cmd);
    HW::write();

    for (auto &record : *cmd)
    {
        auto &payload = record.get_payload();

        std::shared_ptr<interface> itf = interface::find(payload.sw_if_index);
        std::shared_ptr<bridge_domain> bd = bridge_domain::find(payload.bd_id);
        mac_address_t mac(payload.mac);
        bridge_domain_entry bd_e(*bd,
                                 mac,
                                 *itf);

        BOOST_LOG_SEV(logger(), levels::debug) << "bd-entry-dump: "
                                               << bd->to_string()
                                               << mac.to_string()
                                               << itf->to_string();

        /*
         * Write each of the discovered interfaces into the OM,
         * but disable the HW Command q whilst we do, so that no
         * commands are sent to VPP
         */
        OM::commit(key, bd_e);
    }
}

dependency_t bridge_domain_entry::event_handler::order() const
{
    return (dependency_t::ENTRY);
}

void bridge_domain_entry::event_handler::show(std::ostream &os)
{
    m_db.dump(os);
}

std::ostream &VOM::operator<<(std::ostream &os,
                              const bridge_domain_entry::key_t &key)
{
    os << "["
       << key.first
       << ", "
       << key.second.to_string()
       << "]";

    return (os);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
