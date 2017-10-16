/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <iostream>
#include <sstream>

#include "vom/ra_prefix.hpp"

using namespace VOM;

/**
 * Construct a new object matching the desried state
 */
ra_prefix::ra_prefix(const route::prefix_t &pfx, uint8_t use_default, uint8_t no_advertise, uint32_t val_lifetime, uint32_t pref_lifetime)
  : m_pfx(pfx), m_use_default(use_default), m_no_advertise(no_advertise), m_off_link(0), m_no_autoconfig(0), m_no_onlink(0), m_val_lifetime(val_lifetime), m_pref_lifetime(pref_lifetime)
{
}

void ra_prefix::to_vpp(vapi_payload_sw_interface_ip6nd_ra_prefix &ra_prefix) const
{

    uint8_t is_ipv6 = 0;

    m_pfx.to_vpp(&is_ipv6,
                 ra_prefix.address,
                 &ra_prefix.address_length);

    ra_prefix.use_default = m_use_default;
    ra_prefix.no_advertise = m_no_advertise;
    ra_prefix.off_link = m_off_link;
    ra_prefix.no_autoconfig = m_no_autoconfig;
    ra_prefix.no_onlink = m_no_onlink;
    ra_prefix.val_lifetime = m_val_lifetime;
    ra_prefix.pref_lifetime = m_pref_lifetime;
}

bool ra_prefix::operator==(const ra_prefix &other) const
{
    return ((m_pfx == other.m_pfx) &&
            (m_use_default == other.m_use_default) &&
            (m_no_advertise == other.m_no_advertise) &&
            (m_val_lifetime == other.m_val_lifetime) &&
            (m_pref_lifetime == other.m_pref_lifetime));
}


std::string ra_prefix::to_string() const
{
    std::ostringstream s;

    s << "ra-pfx-config:["
      << " pfx:" << m_pfx.to_string()
      << " use-default:" << m_use_default
      << " no-advertise:" << m_no_advertise
      << " val-lifetime:" << m_val_lifetime
      << " pref-lifetime:" << m_pref_lifetime
      << "]";

    return (s.str());
}

const route::prefix_t &ra_prefix::prefix() const
{
    return (m_pfx);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
