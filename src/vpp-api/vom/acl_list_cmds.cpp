/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "vom/acl_list.hpp"

namespace VOM
{
    namespace ACL
    {
        template <>
        rc_t l3_list::update_cmd::issue(connection &con)
        {
            msg_t req(con.ctx(), m_rules.size(), std::ref(*this));
            uint32_t ii = 0;

            auto &payload = req.get_request().get_payload();
            payload.acl_index = m_hw_item.data().value();
            payload.count = m_rules.size();
            memset(payload.tag, 0, sizeof(payload.tag));
            memcpy(payload.tag, m_key.c_str(),
                   std::min(m_key.length(),
                            sizeof(payload.tag)));

            auto it = m_rules.cbegin();

            while (it != m_rules.cend())
            {
                it->to_vpp(payload.r[ii]);
                ++it;
                ++ii;
            }

            VAPI_CALL(req.execute());

            m_hw_item = wait();
            complete();

            return rc_t::OK;
        }

        template <>
        rc_t l3_list::delete_cmd::issue(connection &con)
        {
            msg_t req(con.ctx(), std::ref(*this));

            auto &payload = req.get_request().get_payload();
            payload.acl_index = m_hw_item.data().value();

            VAPI_CALL(req.execute());

            wait();
            m_hw_item.set(rc_t::NOOP);

            return rc_t::OK;
        }

        template <>
        rc_t l3_list::dump_cmd::issue(connection &con)
        {
            m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

            auto &payload = m_dump->get_request().get_payload();
            payload.acl_index = ~0;

            VAPI_CALL(m_dump->execute());

            wait();

            return rc_t::OK;
        }

        template <>
        rc_t l2_list::update_cmd::issue(connection &con)
        {
            msg_t req(con.ctx(), m_rules.size(), std::ref(*this));
            uint32_t ii = 0;

            auto &payload = req.get_request().get_payload();
            // payload.acl_index = m_hw_item.data().value();
            payload.count = m_rules.size();
            memset(payload.tag, 0, sizeof(payload.tag));
            memcpy(payload.tag, m_key.c_str(),
                   std::min(m_key.length(),
                            sizeof(payload.tag)));

            auto it = m_rules.cbegin();

            while (it != m_rules.cend())
            {
                it->to_vpp(payload.r[ii]);
                ++it;
                ++ii;
            }

            VAPI_CALL(req.execute());

            m_hw_item = wait();

            return rc_t::OK;
        }

        template <>
        rc_t l2_list::delete_cmd::issue(connection &con)
        {
            msg_t req(con.ctx(), std::ref(*this));

            auto &payload = req.get_request().get_payload();
            payload.acl_index = m_hw_item.data().value();

            VAPI_CALL(req.execute());

            wait();
            m_hw_item.set(rc_t::NOOP);

            return rc_t::OK;
        }

        template <>
        rc_t l2_list::dump_cmd::issue(connection &con)
        {
            m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

            auto &payload = m_dump->get_request().get_payload();
            payload.acl_index = ~0;

            VAPI_CALL(m_dump->execute());

            wait();

            return rc_t::OK;
        }
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
