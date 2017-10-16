/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VOM_RA_PREFIX_H__
#define __VOM_RA_PREFIX_H__

#include <stdint.h>
#include <string>

#include "vom/prefix.hpp"

#include <vapi/ip.api.vapi.hpp>

namespace VOM
{
    /**
     * A representation of RA prefix configuration on given interface
     */
    class ra_prefix
    {
      public:
        /**
         * Construct a new object matching the desried state
         */
        ra_prefix(const route::prefix_t &pfx, uint8_t use_default, uint8_t no_advertise, uint32_t val_lifetime, uint32_t pref_lifetime);

        /**
         * Copy Constructor
         */
        ra_prefix(const ra_prefix &o) = default;

        /**
         * Destructor
         */
        ~ra_prefix() = default;

        /**
         * convert to string format for debug purposes
         */
        std::string to_string() const;

        /**
         * Return the prefix associated with this ra prefix
         */
        const route::prefix_t &prefix() const;

        /**
         * Comparison operator - only used for UT
         */
        bool operator==(const ra_prefix &ra_prefix) const;

        /**
         * Convert the ra prefix configuration to Vpp Api
         */
        void to_vpp(vapi_payload_sw_interface_ip6nd_ra_prefix &ra_prefix) const;

      private:
        /**
         * The prefix to be advertised.
         */
        route::prefix_t m_pfx;

        /**
         * Revert to default settings.
         */
        uint8_t m_use_default;

        /**
         * Do not send full router address in prefix advertisement.
         * Default is to advertise.
         */
        uint8_t m_no_advertise;

        /**
         * Prefix is off-link. Default is on-link.
         */
        uint8_t m_off_link;

        /**
         * Do not use prefix for autoconfiguration.
         * Default is autoconfig.
         */
        uint8_t m_no_autoconfig;

        /**
         * Do not use prefix for onlink determination.
         * Default is on-link (this flag is off).
         */
        uint8_t m_no_onlink;

        /**
         * <valid-lifetime>' is the length of time in seconds during what
         * the prefix is valid for the purpose of on-link determination.
         *
         * Range is 7203 to 2592000 seconds and default is 2592000 seconds.
         * A value of all one bits (0xffffffff) represents infinity (no timeout).
         */
        uint32_t m_val_lifetime;

        /**
         * '<pref-lifetime>' is the prefered-lifetime and is the length of
         * time in seconds during what addresses generated from the prefix
         * remain preferred.
         *
         * Range is 0 to 604800 seconds and default is 604800 seconds.
         * A value of all one bits (0xffffffff) represents infinity (no timeout).
         */
        uint32_t m_pref_lifetime;
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
