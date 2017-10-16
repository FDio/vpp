/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <cassert>
#include <iostream>
#include <typeinfo>

#include "vom/bridge_domain.hpp"
#include "vom/cmd.hpp"

DEFINE_VAPI_MSG_IDS_L2_API_JSON;

using namespace VOM;

bridge_domain::create_cmd::create_cmd(HW::item<uint32_t> &item)
  : rpc_cmd(item)
{
}

bool bridge_domain::create_cmd::operator==(const create_cmd &other) const
{
    return (m_hw_item.data() == other.m_hw_item.data());
}

rc_t bridge_domain::create_cmd::issue(connection &con)
{
    msg_t req(con.ctx(), std::ref(*this));

    auto &payload = req.get_request().get_payload();
    payload.bd_id = m_hw_item.data();
    payload.flood = 1;
    payload.uu_flood = 1;
    payload.forward = 1;
    payload.learn = 1;
    payload.arp_term = 1;
    payload.mac_age = 0;
    payload.is_add = 1;

    VAPI_CALL(req.execute());

    m_hw_item.set(wait());

    return (rc_t::OK);
}

std::string bridge_domain::create_cmd::to_string() const
{
    std::ostringstream s;
    s << "bridge-domain-create: " << m_hw_item.to_string();

    return (s.str());
}

bridge_domain::delete_cmd::delete_cmd(HW::item<uint32_t> &item)
  : rpc_cmd(item)
{
}

bool bridge_domain::delete_cmd::operator==(const delete_cmd &other) const
{
    return (m_hw_item == other.m_hw_item);
}

rc_t bridge_domain::delete_cmd::issue(connection &con)
{
    msg_t req(con.ctx(), std::ref(*this));

    auto &payload = req.get_request().get_payload();
    payload.bd_id = m_hw_item.data();
    payload.is_add = 0;

    VAPI_CALL(req.execute());

    wait();
    m_hw_item.set(rc_t::NOOP);

    return (rc_t::OK);
}

std::string bridge_domain::delete_cmd::to_string() const
{
    std::ostringstream s;
    s << "bridge-domain-delete: " << m_hw_item.to_string();

    return (s.str());
}

bridge_domain::dump_cmd::dump_cmd()
{
}

bool bridge_domain::dump_cmd::operator==(const dump_cmd &other) const
{
    return (true);
}

rc_t bridge_domain::dump_cmd::issue(connection &con)
{
    m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

    auto &payload = m_dump->get_request().get_payload();
    payload.bd_id = ~0;

    VAPI_CALL(m_dump->execute());

    wait();

    return rc_t::OK;
}

std::string bridge_domain::dump_cmd::to_string() const
{
    return ("bridge-domain-dump");
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
