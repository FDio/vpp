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

namespace VOM {
namespace QoS {

const source_t source_t::EXT(0, "ext");
const source_t source_t::VLAN(1, "vlan");
const source_t source_t::MPLS(2, "mpls");
const source_t source_t::IP(3, "IP");

source_t::source_t(int v, const std::string& s)
  : enum_base<source_t>(v, s)
{
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
