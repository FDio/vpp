/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <iostream>

#include "vom/neighbour.hpp"

using namespace VOM;

neighbour::create_cmd::create_cmd(HW::item<bool> &item,
                                  handle_t itf,
                                  const mac_address_t &mac,
                                  const boost::asio::ip::address &ip_addr)
  : rpc_cmd(item), m_itf(itf), m_mac(mac), m_ip_addr(ip_addr)
{
}

bool neighbour::create_cmd::operator==(const create_cmd &other) const
{
    return ((m_mac == other.m_mac) &&
            (m_ip_addr == other.m_ip_addr) &&
            (m_itf == other.m_itf));
}

rc_t neighbour::create_cmd::issue(connection &con)
{
    msg_t req(con.ctx(), std::ref(*this));

    auto &payload = req.get_request().get_payload();
    payload.sw_if_index = m_itf.value();
    payload.is_add = 1;
    payload.is_static = 1;
    m_mac.to_bytes(payload.mac_address, 6);
    to_bytes(m_ip_addr,
             &payload.is_ipv6,
             payload.dst_address);

    VAPI_CALL(req.execute());

    m_hw_item.set(wait());

    return rc_t::OK;
}

std::string neighbour::create_cmd::to_string() const
{
    std::ostringstream s;
    s << "nieghbour-create: " << m_hw_item.to_string()
      << " itf:" << m_itf.to_string()
      << " mac:" << m_mac.to_string()
      << " ip:" << m_ip_addr.to_string();

    return (s.str());
}

neighbour::delete_cmd::delete_cmd(HW::item<bool> &item,
                                  handle_t itf,
                                  const mac_address_t &mac,
                                  const boost::asio::ip::address &ip_addr)
  : rpc_cmd(item), m_itf(itf), m_mac(mac), m_ip_addr(ip_addr)
{
}

bool neighbour::delete_cmd::operator==(const delete_cmd &other) const
{
    return ((m_mac == other.m_mac) &&
            (m_ip_addr == other.m_ip_addr) &&
            (m_itf == other.m_itf));
}

rc_t neighbour::delete_cmd::issue(connection &con)
{
    msg_t req(con.ctx(), std::ref(*this));

    auto &payload = req.get_request().get_payload();
    payload.sw_if_index = m_itf.value();
    payload.is_add = 0;
    payload.is_static = 1;
    m_mac.to_bytes(payload.mac_address, 6);
    to_bytes(m_ip_addr,
             &payload.is_ipv6,
             payload.dst_address);

    VAPI_CALL(req.execute());

    wait();
    m_hw_item.set(rc_t::NOOP);

    return rc_t::OK;
}

std::string neighbour::delete_cmd::to_string() const
{
    std::ostringstream s;
    s << "neighbour-delete: " << m_hw_item.to_string()
      << " itf:" << m_itf.to_string()
      << " mac:" << m_mac.to_string()
      << " ip:" << m_ip_addr.to_string();

    return (s.str());
}

neighbour::dump_cmd::dump_cmd(const handle_t &hdl,
                              const l3_proto_t &proto)
  : m_itf(hdl), m_proto(proto)
{
}

neighbour::dump_cmd::dump_cmd(const dump_cmd &d)
  : m_itf(d.m_itf), m_proto(d.m_proto)
{
}

bool neighbour::dump_cmd::operator==(const dump_cmd &other) const
{
    return (true);
}

rc_t neighbour::dump_cmd::issue(connection &con)
{
    m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

    auto &payload = m_dump->get_request().get_payload();
    payload.sw_if_index = m_itf.value();
    payload.is_ipv6 = m_proto.is_ipv6();

    VAPI_CALL(m_dump->execute());

    wait();

    return rc_t::OK;
}

std::string neighbour::dump_cmd::to_string() const
{
    return ("neighbour-dump");
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
