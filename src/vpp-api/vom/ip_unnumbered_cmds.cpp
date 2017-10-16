/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <algorithm>
#include <iostream>

#include "vom/ip_unnumbered.hpp"

#include <vapi/vpe.api.vapi.hpp>

using namespace VOM;

ip_unnumbered::config_cmd::config_cmd(HW::item<bool> &item,
                                      const handle_t &itf,
                                      const handle_t &l3_itf)
  : rpc_cmd(item), m_itf(itf), m_l3_itf(l3_itf)
{
}

bool ip_unnumbered::config_cmd::operator==(const config_cmd &o) const
{
    return ((m_itf == o.m_itf) &&
            (m_l3_itf == o.m_l3_itf));
}

rc_t ip_unnumbered::config_cmd::issue(connection &con)
{
    msg_t req(con.ctx(), std::ref(*this));

    auto &payload = req.get_request().get_payload();
    payload.is_add = 1;
    payload.sw_if_index = m_l3_itf.value();
    payload.unnumbered_sw_if_index = m_itf.value();

    VAPI_CALL(req.execute());

    m_hw_item.set(wait());

    return rc_t::OK;
}

std::string ip_unnumbered::config_cmd::to_string() const
{
    std::ostringstream s;
    s << "IP-unnumberd-config: " << m_hw_item.to_string()
      << " itf:" << m_itf.to_string()
      << " l3-itf:" << m_l3_itf.to_string();

    return (s.str());
}

ip_unnumbered::unconfig_cmd::unconfig_cmd(HW::item<bool> &item,
                                          const handle_t &itf,
                                          const handle_t &l3_itf)
  : rpc_cmd(item), m_itf(itf), m_l3_itf(l3_itf)
{
}

bool ip_unnumbered::unconfig_cmd::operator==(const unconfig_cmd &o) const
{
    return ((m_itf == o.m_itf) &&
            (m_l3_itf == o.m_l3_itf));
}

rc_t ip_unnumbered::unconfig_cmd::issue(connection &con)
{
    msg_t req(con.ctx(), std::ref(*this));

    auto &payload = req.get_request().get_payload();
    payload.is_add = 0;
    payload.sw_if_index = m_l3_itf.value();
    payload.unnumbered_sw_if_index = m_itf.value();

    VAPI_CALL(req.execute());

    wait();
    m_hw_item.set(rc_t::NOOP);

    return rc_t::OK;
}

std::string ip_unnumbered::unconfig_cmd::to_string() const
{
    std::ostringstream s;
    s << "IP-unnumberd-unconfig: " << m_hw_item.to_string()
      << " itf:" << m_itf.to_string()
      << " l3-itf:" << m_l3_itf.to_string();

    return (s.str());
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
