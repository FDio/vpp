/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <algorithm>
#include <iostream>

#include "vom/lldp_global.hpp"

using namespace VOM;

lldp_global::config_cmd::config_cmd(HW::item<bool> &item,
                                    const std::string &system_name,
                                    uint32_t tx_hold,
                                    uint32_t tx_interval)
  : rpc_cmd(item), m_system_name(system_name), m_tx_hold(tx_hold), m_tx_interval(tx_interval)
{
}

bool lldp_global::config_cmd::operator==(const config_cmd &other) const
{
    return (m_system_name == other.m_system_name);
}

rc_t lldp_global::config_cmd::issue(connection &con)
{
    msg_t req(con.ctx(), std::ref(*this));

    auto &payload = req.get_request().get_payload();
    payload.tx_hold = m_tx_hold;
    payload.tx_interval = m_tx_interval;

    memcpy(payload.system_name,
           m_system_name.c_str(),
           std::min(sizeof(payload.system_name),
                    m_system_name.length()));

    VAPI_CALL(req.execute());

    m_hw_item.set(wait());

    return rc_t::OK;
}

std::string lldp_global::config_cmd::to_string() const
{
    std::ostringstream s;
    s << "Lldp-global-config: " << m_hw_item.to_string()
      << " system_name:" << m_system_name
      << " tx-hold:" << m_tx_hold
      << " tx-interval:" << m_tx_interval;

    return (s.str());
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
