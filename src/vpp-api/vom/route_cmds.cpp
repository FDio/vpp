/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <algorithm>
#include <iostream>

#include "vom/route.hpp"

using namespace VOM;
using namespace VOM::route;

ip_route::update_cmd::update_cmd(HW::item<bool> &item,
                                 table_id_t id,
                                 const prefix_t &prefix,
                                 const path_list_t &paths)
  : rpc_cmd(item), m_id(id), m_prefix(prefix), m_paths(paths)
{
    // no multipath yet.
    assert(paths.size() == 1);
}

bool ip_route::update_cmd::operator==(const update_cmd &other) const
{
    return ((m_prefix == other.m_prefix) &&
            (m_id == other.m_id));
}

rc_t ip_route::update_cmd::issue(connection &con)
{
    msg_t req(con.ctx(), 0, std::ref(*this));

    auto &payload = req.get_request().get_payload();

    payload.table_id = m_id;
    payload.is_add = 1;
    payload.is_multipath = 0;

    m_prefix.to_vpp(&payload.is_ipv6,
                    payload.dst_address,
                    &payload.dst_address_length);

    for (auto &p : m_paths)
        p.to_vpp(payload);

    VAPI_CALL(req.execute());

    m_hw_item.set(wait());

    return rc_t::OK;
}

std::string ip_route::update_cmd::to_string() const
{
    std::ostringstream s;
    s << "ip-route-create: " << m_hw_item.to_string()
      << " table-id:" << m_id
      << " prefix:" << m_prefix.to_string()
      << " paths:" << m_paths;

    return (s.str());
}

ip_route::delete_cmd::delete_cmd(HW::item<bool> &item,
                                 table_id_t id,
                                 const prefix_t &prefix)
  : rpc_cmd(item), m_id(id), m_prefix(prefix)
{
}

bool ip_route::delete_cmd::operator==(const delete_cmd &other) const
{
    return ((m_prefix == other.m_prefix) &&
            (m_id == other.m_id));
}

rc_t ip_route::delete_cmd::issue(connection &con)
{
    msg_t req(con.ctx(), 0, std::ref(*this));

    auto &payload = req.get_request().get_payload();
    payload.table_id = m_id;
    payload.is_add = 0;

    m_prefix.to_vpp(&payload.is_ipv6,
                    payload.dst_address,
                    &payload.dst_address_length);

    VAPI_CALL(req.execute());

    wait();
    m_hw_item.set(rc_t::NOOP);

    return rc_t::OK;
}

std::string ip_route::delete_cmd::to_string() const
{
    std::ostringstream s;
    s << "ip-route-delete: " << m_hw_item.to_string()
      << " id:" << m_id
      << " prefix:" << m_prefix.to_string();

    return (s.str());
}

ip_route::dump_v4_cmd::dump_v4_cmd()
{
}

bool ip_route::dump_v4_cmd::operator==(const dump_v4_cmd &other) const
{
    return (true);
}

rc_t ip_route::dump_v4_cmd::issue(connection &con)
{
    m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

    VAPI_CALL(m_dump->execute());

    wait();

    return rc_t::OK;
}

std::string ip_route::dump_v4_cmd::to_string() const
{
    return ("ip-route-v4-dump");
}

ip_route::dump_v6_cmd::dump_v6_cmd()
{
}

bool ip_route::dump_v6_cmd::operator==(const dump_v6_cmd &other) const
{
    return (true);
}

rc_t ip_route::dump_v6_cmd::issue(connection &con)
{
    m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

    VAPI_CALL(m_dump->execute());

    wait();

    return rc_t::OK;
}

std::string ip_route::dump_v6_cmd::to_string() const
{
    return ("ip-route-v6-dump");
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
