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

#include "vom/interface.hpp"

namespace VOM {
/*
 * constants and enums
 */
const interface::type_t interface::type_t::UNKNOWN(0, "unknown");
const interface::type_t interface::type_t::BVI(1, "BVI");
const interface::type_t interface::type_t::ETHERNET(2, "Ethernet");
const interface::type_t interface::type_t::VXLAN(3, "VXLAN");
const interface::type_t interface::type_t::AFPACKET(4, "AFPACKET");
const interface::type_t interface::type_t::LOOPBACK(5, "LOOPBACK");
const interface::type_t interface::type_t::LOCAL(6, "LOCAL");
const interface::type_t interface::type_t::TAP(7, "TAP");

const interface::oper_state_t interface::oper_state_t::DOWN(0, "down");
const interface::oper_state_t interface::oper_state_t::UP(1, "up");

const interface::admin_state_t interface::admin_state_t::DOWN(0, "down");
const interface::admin_state_t interface::admin_state_t::UP(1, "up");

interface::type_t
interface::type_t::from_string(const std::string& str)
{
  if (str.find("Ethernet") != std::string::npos) {
    return interface::type_t::ETHERNET;
  } else if (str.find("vxlan") != std::string::npos) {
    return interface::type_t::VXLAN;
  } else if (str.find("loop") != std::string::npos) {
    return interface::type_t::LOOPBACK;
  } else if (str.find("host-") != std::string::npos) {
    return interface::type_t::AFPACKET;
  } else if (str.find("local") != std::string::npos) {
    return interface::type_t::LOCAL;
  } else if (str.find("tap") != std::string::npos) {
    return interface::type_t::TAP;
  } else if (str.find("bvi") != std::string::npos) {
    return interface::type_t::BVI;
  }

  return interface::type_t::UNKNOWN;
}

interface::type_t::type_t(int v, const std::string& s)
  : enum_base<interface::type_t>(v, s)
{
}

interface::oper_state_t::oper_state_t(int v, const std::string& s)
  : enum_base<interface::oper_state_t>(v, s)
{
}

interface::admin_state_t::admin_state_t(int v, const std::string& s)
  : enum_base<interface::admin_state_t>(v, s)
{
}

interface::admin_state_t
interface::admin_state_t::from_int(uint8_t v)
{
  if (0 == v) {
    return (interface::admin_state_t::DOWN);
  }
  return (interface::admin_state_t::UP);
}

interface::oper_state_t
interface::oper_state_t::from_int(uint8_t v)
{
  if (0 == v) {
    return (interface::oper_state_t::DOWN);
  }
  return (interface::oper_state_t::UP);
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
