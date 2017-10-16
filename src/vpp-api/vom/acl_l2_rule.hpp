/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VOM_L2_ACL_RULE_H__
#define __VOM_L2_ACL_RULE_H__

#include <stdint.h>

#include "vom/acl_types.hpp"
#include "vom/prefix.hpp"

#include <vapi/acl.api.vapi.hpp>

namespace VOM
{
    namespace ACL
    {
        /**
         * An ACL rule is the building block of an ACL. An ACL, which is
         * the object applied to an interface, is comprised of an ordersed
         * sequence of ACL rules.
         * This class is a wrapper around the VAPI generated struct and exports
         * an API with better types.
         */
        class l2_rule
        {
          public:
            /**
             * Construct a new object matching the desried state
             */
            l2_rule(uint32_t priority,
                    const action_t &action,
                    const route::prefix_t &ip,
                    const mac_address_t &mac,
                    const mac_address_t &mac_mask);

            /**
             * Copy Constructor
             */
            l2_rule(const l2_rule &o) = default;

            /**
             * Destructor
             */
            ~l2_rule() = default;

            /**
             * convert to string format for debug purposes
             */
            std::string to_string() const;

            /**
             * less-than operator
             */
            bool operator<(const l2_rule &rule) const;

            /**
             * comparison operator (for testing)
             */
            bool operator==(const l2_rule &rule) const;

            /**
             * Convert to VPP API fromat
             */
            void to_vpp(vapi_type_macip_acl_rule &rule) const;

          private:
            /**
             * Priority. Used to sort the rules in a list in the order
             * in which they are applied
             */
            uint32_t m_priority;

            /**
             * Action on match
             */
            action_t m_action;

            /**
             * Source Prefix
             */
            route::prefix_t m_src_ip;

            /**
             * Source Mac
             */
            mac_address_t m_mac;

            /**
             * Source MAC mask
             */
            mac_address_t m_mac_mask;
        };
    };
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
