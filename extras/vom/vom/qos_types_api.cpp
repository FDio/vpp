/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include "vom/qos_types.hpp"

#include <vapi/qos.api.vapi.hpp>

DEFINE_VAPI_MSG_IDS_QOS_API_JSON;

namespace VOM {
namespace QoS {

const source_t&
from_api(vapi_enum_qos_source e)
{
  switch (e) {
    case QOS_API_SOURCE_EXT:
      return source_t::EXT;
    case QOS_API_SOURCE_VLAN:
      return source_t::VLAN;
    case QOS_API_SOURCE_IP:
      return source_t::IP;
    case QOS_API_SOURCE_MPLS:
      return source_t::MPLS;
  }
  return source_t::EXT;
}

vapi_enum_qos_source
to_api(const source_t& s)
{
  return static_cast<vapi_enum_qos_source>((int)s);
}

}; // namespace QoS
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
