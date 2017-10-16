/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <algorithm>
#include <iostream>

#include "vom/lldp_binding.hpp"

DEFINE_VAPI_MSG_IDS_LLDP_API_JSON;

using namespace VOM;

lldp_binding::bind_cmd::bind_cmd(HW::item<bool> &item,
                                 const handle_t &itf,
                                 const std::string &port_desc)
  : rpc_cmd(item), m_itf(itf), m_port_desc(port_desc)
{
}

bool lldp_binding::bind_cmd::operator==(const bind_cmd &other) const
{
    return ((m_itf == other.m_itf) &&
            (m_port_desc == other.m_port_desc));
}

rc_t lldp_binding::bind_cmd::issue(connection &con)
{
    msg_t req(con.ctx(), std::ref(*this));

    auto &payload = req.get_request().get_payload();
    payload.sw_if_index = m_itf.value();
    payload.enable = 1;

    memcpy(payload.port_desc,
           m_port_desc.c_str(),
           std::min(sizeof(payload.port_desc),
                    m_port_desc.length()));

    VAPI_CALL(req.execute());

    m_hw_item.set(wait());

    return rc_t::OK;
}

std::string lldp_binding::bind_cmd::to_string() const
{
    std::ostringstream s;
    s << "Lldp-bind: " << m_hw_item.to_string()
      << " itf:" << m_itf.to_string()
      << " port_desc:" << m_port_desc;

    return (s.str());
}

lldp_binding::unbind_cmd::unbind_cmd(HW::item<bool> &item,
                                     const handle_t &itf)
  : rpc_cmd(item), m_itf(itf)
{
}

bool lldp_binding::unbind_cmd::operator==(const unbind_cmd &other) const
{
    return (m_itf == other.m_itf);
}

rc_t lldp_binding::unbind_cmd::issue(connection &con)
{
    msg_t req(con.ctx(), std::ref(*this));

    auto &payload = req.get_request().get_payload();
    payload.sw_if_index = m_itf.value();
    payload.enable = 0;

    VAPI_CALL(req.execute());

    wait();
    m_hw_item.set(rc_t::NOOP);

    return rc_t::OK;
}

std::string lldp_binding::unbind_cmd::to_string() const
{
    std::ostringstream s;
    s << "Lldp-unbind: " << m_hw_item.to_string()
      << " itf:" << m_itf.to_string();

    return (s.str());
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
