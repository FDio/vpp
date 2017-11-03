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

#include <boost/algorithm/string.hpp>

#include "vom/interface_factory.hpp"
#include "vom/sub_interface.hpp"
#include "vom/tap_interface.hpp"

namespace VOM {
std::unique_ptr<interface>
interface_factory::new_interface(const vapi_payload_sw_interface_details& vd)
{
  std::unique_ptr<interface> up_itf;

  /**
 * Determine the interface type from the name and VLAN attributes
 */
  std::string name = reinterpret_cast<const char*>(vd.interface_name);
  interface::type_t type = interface::type_t::from_string(name);
  interface::admin_state_t state =
    interface::admin_state_t::from_int(vd.link_up_down);
  handle_t hdl(vd.sw_if_index);
  l2_address_t l2_address(vd.l2_address, vd.l2_address_length);

  if (interface::type_t::AFPACKET == type) {
    /*
 * need to strip VPP's "host-" prefix from the interface name
 */
    name = name.substr(5);
  }
  /**
 * if the tag is set, then we wrote that to specify a name to make
 * the interface type more specific
 */
  if (vd.tag[0] != 0) {
    name = std::string(reinterpret_cast<const char*>(vd.tag));
    type = interface::type_t::from_string(name);
  }

  /*
 * pull out the other special cases
 */
  if (interface::type_t::TAP == type) {
    /*
 * TAP interface
 */
    up_itf.reset(new tap_interface(hdl, name, state, route::prefix_t()));
  } else if ((name.find(".") != std::string::npos) && (0 != vd.sub_id)) {
    /*
 * Sub-interface
 *   split the name into the parent and VLAN
 */
    std::vector<std::string> parts;
    boost::split(parts, name, boost::is_any_of("."));

    interface parent(parts[0], type, state);
    up_itf.reset(new sub_interface(hdl, parent, state, vd.sub_id));
  } else if (interface::type_t::VXLAN == type) {
    /*
 * there's not enough inforation in a SW interface record to
 * construct
 * a VXLAN tunnel. so skip it.
 */
  } else {
    up_itf.reset(new interface(hdl, l2_address, name, type, state));
  }

  return (up_itf);
}
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
