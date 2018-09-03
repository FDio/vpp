/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sstream>

#include "vom/ra_config.hpp"

namespace VOM {

/**
 * Construct a new object matching the desried state
 */
ra_config::ra_config(uint8_t suppress,
                     uint8_t send_unicast,
                     uint8_t default_router,
                     uint32_t max_interval)
  : m_suppress(suppress)
  , m_managed(0)
  , m_other(0)
  , m_ll_option(0)
  , m_send_unicast(send_unicast)
  , m_cease(0)
  , m_default_router(default_router)
  , m_max_interval(max_interval)
  , m_min_interval((max_interval * 3) / 4)
  , m_lifetime(600)
  , m_initial_count(3)
  , m_initial_interval(16)
{
}

void
ra_config::to_vpp(vapi_payload_sw_interface_ip6nd_ra_config& ra_config) const
{
  ra_config.suppress = m_suppress;
  ra_config.managed = m_managed;
  ra_config.other = m_other;
  ra_config.ll_option = m_ll_option;
  ra_config.send_unicast = m_send_unicast;
  ra_config.cease = m_cease;
  ra_config.max_interval = m_max_interval;
  ra_config.min_interval = m_min_interval;
  ra_config.lifetime = m_lifetime;
  ra_config.initial_count = m_initial_count;
  ra_config.initial_interval = m_initial_interval;
}

bool
ra_config::operator==(const ra_config& other) const
{
  return ((m_suppress == other.m_suppress) &&
          (m_send_unicast == other.m_send_unicast) &&
          (m_default_router == other.m_default_router) &&
          (m_max_interval == other.m_max_interval));
}

std::string
ra_config::to_string() const
{
  std::ostringstream s;

  s << "ra-config:["
    << " suppress:" << m_suppress << " send-unicast:" << m_send_unicast
    << " default-router:" << m_default_router
    << " max_interval:" << m_max_interval << "]";

  return (s.str());
}
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
