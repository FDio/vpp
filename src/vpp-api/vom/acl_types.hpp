/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Main implementation for OVS agent
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VOM_ACL_TYPES_H__
#define __VOM_ACL_TYPES_H__

#include "vom/types.hpp"

namespace VOM
{
    namespace ACL
    {
        /**
         * ACL Actions
         */
        struct action_t : public enum_base<action_t>
        {
            /**
             * Constructor
             */
            action_t(int v, const std::string s);

            /**
             * Destructor
             */
            ~action_t() = default;

            /**
             * Permit Action
             */
            const static action_t PERMIT;

            /**
             * Deny Action
             */
            const static action_t DENY;

            /**
             * Get the enum type from a VPP integer value
             */
            static const action_t &from_int(uint8_t i);
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
