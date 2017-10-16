/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "vom/acl_binding.hpp"

namespace VOM
{
    namespace ACL
    {
        template <>
        void l2_binding::event_handler::handle_populate(const client_db::key_t &key)
        {
            /*
             * dump VPP Bridge domains
             */
            std::shared_ptr<l2_binding::dump_cmd> cmd(new l2_binding::dump_cmd());

            HW::enqueue(cmd);
            HW::write();

            for (auto &record : *cmd)
            {
                auto &payload = record.get_payload();

                std::shared_ptr<interface> itf = interface::find(payload.sw_if_index);

                for (int ii = 0; ii < payload.count; ii++)
                {
                    std::shared_ptr<l2_list> acl = l2_list::find(payload.acls[ii]);

                    l2_binding binding(direction_t::INPUT, *itf, *acl);

                    OM::commit(key, binding);
                }
            }
        }

        template <>
        void l3_binding::event_handler::handle_populate(const client_db::key_t &key)
        {
            std::shared_ptr<l3_binding::dump_cmd> cmd(new l3_binding::dump_cmd());

            HW::enqueue(cmd);
            HW::write();

            for (auto &record : *cmd)
            {
                auto &payload = record.get_payload();

                std::shared_ptr<interface> itf = interface::find(payload.sw_if_index);
                uint8_t n_input = payload.n_input;

                for (int ii = 0; ii < payload.count; ii++)
                {
                    std::shared_ptr<l3_list> acl = l3_list::find(payload.acls[ii]);

                    if (n_input)
                    {
                        l3_binding binding(direction_t::INPUT, *itf, *acl);
                        n_input--;
                        OM::commit(key, binding);
                    }
                    else
                    {
                        l3_binding binding(direction_t::OUTPUT, *itf, *acl);
                        OM::commit(key, binding);
                    }
                }
            }
        }
    };

    std::ostream &operator<<(std::ostream &os,
                             const std::pair<direction_t, interface::key_type> &key)
    {
        os << "["
           << key.first.to_string()
           << " "
           << key.second
           << "]";

        return (os);
    }
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
