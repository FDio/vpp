/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <iostream>

#include "vom/l3_binding.hpp"

DEFINE_VAPI_MSG_IDS_IP_API_JSON;

using namespace VOM;

l3_binding::bind_cmd::bind_cmd(HW::item<bool> &item,
                               const handle_t &itf,
                               const route::prefix_t &pfx)
  : rpc_cmd(item), m_itf(itf), m_pfx(pfx)
{
}

bool l3_binding::bind_cmd::operator==(const bind_cmd &other) const
{
    return ((m_itf == other.m_itf) &&
            (m_pfx == other.m_pfx));
}

rc_t l3_binding::bind_cmd::issue(connection &con)
{
    msg_t req(con.ctx(), std::ref(*this));

    auto &payload = req.get_request().get_payload();
    payload.sw_if_index = m_itf.value();
    payload.is_add = 1;
    payload.del_all = 0;

    m_pfx.to_vpp(&payload.is_ipv6,
                 payload.address,
                 &payload.address_length);

    VAPI_CALL(req.execute());

    m_hw_item.set(wait());

    return rc_t::OK;
}

std::string l3_binding::bind_cmd::to_string() const
{
    std::ostringstream s;
    s << "L3-bind: " << m_hw_item.to_string()
      << " itf:" << m_itf.to_string()
      << " pfx:" << m_pfx.to_string();

    return (s.str());
}

l3_binding::unbind_cmd::unbind_cmd(HW::item<bool> &item,
                                   const handle_t &itf,
                                   const route::prefix_t &pfx)
  : rpc_cmd(item), m_itf(itf), m_pfx(pfx)
{
}

bool l3_binding::unbind_cmd::operator==(const unbind_cmd &other) const
{
    return ((m_itf == other.m_itf) &&
            (m_pfx == other.m_pfx));
}

rc_t l3_binding::unbind_cmd::issue(connection &con)
{
    msg_t req(con.ctx(), std::ref(*this));

    auto &payload = req.get_request().get_payload();
    payload.sw_if_index = m_itf.value();
    payload.is_add = 0;
    payload.del_all = 0;

    m_pfx.to_vpp(&payload.is_ipv6,
                 payload.address,
                 &payload.address_length);

    VAPI_CALL(req.execute());

    wait();
    m_hw_item.set(rc_t::NOOP);

    return rc_t::OK;
}

std::string l3_binding::unbind_cmd::to_string() const
{
    std::ostringstream s;
    s << "L3-unbind: " << m_hw_item.to_string()
      << " itf:" << m_itf.to_string()
      << " pfx:" << m_pfx.to_string();

    return (s.str());
}

l3_binding::dump_v4_cmd::dump_v4_cmd(const handle_t &hdl)
  : m_itf(hdl)
{
}

l3_binding::dump_v4_cmd::dump_v4_cmd(const dump_v4_cmd &d)
  : m_itf(d.m_itf)
{
}

bool l3_binding::dump_v4_cmd::operator==(const dump_v4_cmd &other) const
{
    return (true);
}

rc_t l3_binding::dump_v4_cmd::issue(connection &con)
{
    m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

    auto &payload = m_dump->get_request().get_payload();
    payload.sw_if_index = m_itf.value();
    payload.is_ipv6 = 0;

    VAPI_CALL(m_dump->execute());

    wait();

    return rc_t::OK;
}

std::string l3_binding::dump_v4_cmd::to_string() const
{
    return ("L3-binding-dump");
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
