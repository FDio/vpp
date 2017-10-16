/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <iostream>

#include "vom/interface_ip6_nd.hpp"

#include <vapi/vpe.api.vapi.hpp>

namespace VOM
{
    template <>
    rc_t ip6nd_ra_config::config_cmd::issue(connection &con)
    {
        msg_t req(con.ctx(), std::ref(*this));

        auto &payload = req.get_request().get_payload();
        payload.sw_if_index = m_itf.value();
        m_cls.to_vpp(payload);
        payload.is_no = 0;

        VAPI_CALL(req.execute());

        m_hw_item.set(wait());

        return rc_t::OK;
    }

    template <>
    rc_t ip6nd_ra_config::unconfig_cmd::issue(connection &con)
    {
        msg_t req(con.ctx(), std::ref(*this));

        auto &payload = req.get_request().get_payload();
        payload.sw_if_index = m_itf.value();
        m_cls.to_vpp(payload);
        payload.is_no = 1;

        VAPI_CALL(req.execute());

        wait();
        m_hw_item.set(rc_t::NOOP);

        return rc_t::OK;
    }

    template <>
    rc_t ip6nd_ra_prefix::config_cmd::issue(connection &con)
    {
        msg_t req(con.ctx(), std::ref(*this));

        auto &payload = req.get_request().get_payload();
        payload.sw_if_index = m_itf.value();
        m_cls.to_vpp(payload);
        payload.is_no = 0;

        VAPI_CALL(req.execute());

        m_hw_item.set(wait());

        return rc_t::OK;
    }

    template <>
    rc_t ip6nd_ra_prefix::unconfig_cmd::issue(connection &con)
    {
        msg_t req(con.ctx(), std::ref(*this));

        auto &payload = req.get_request().get_payload();
        payload.sw_if_index = m_itf.value();
        m_cls.to_vpp(payload);
        payload.is_no = 1;

        VAPI_CALL(req.execute());

        wait();
        m_hw_item.set(rc_t::NOOP);

        return rc_t::OK;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
