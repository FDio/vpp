/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <algorithm>
#include <boost/algorithm/string.hpp>

#include "vom/interface.hpp"
#include "vom/sub_interface.hpp"
#include "vom/tap_interface.hpp"

using namespace VOM;

std::unique_ptr<interface>
interface::new_interface(const vapi_payload_sw_interface_details &vd)
{
    std::unique_ptr<interface> up_itf;

    /**
     * Determine the interface type from the name and VLAN attributes
     */
    std::string name = reinterpret_cast<const char *>(vd.interface_name);
    type_t type = interface::type_t::from_string(name);
    admin_state_t state = interface::admin_state_t::from_int(vd.link_up_down);
    handle_t hdl(vd.sw_if_index);
    l2_address_t l2_address(vd.l2_address, vd.l2_address_length);

    if (type_t::AFPACKET == type)
    {
        /*
         * need to strip VPP's "host-" prefix from the interface name
         */
        name = name.substr(5);
    }
    /**
     * if the tag is set, then we wrote that to specify a name to make
     * the interface type more specific
     */
    if (vd.tag[0] != 0)
    {
        name = std::string(reinterpret_cast<const char *>(vd.tag));
        type = interface::type_t::from_string(name);
    }

    /*
     * pull out the other special cases
     */
    if (type_t::TAP == type)
    {
        /*
         * TAP interface
         */
        up_itf.reset(new tap_interface(hdl, name, state, route::prefix_t()));
    }
    else if ((name.find(".") != std::string::npos) &&
             (0 != vd.sub_id))
    {
        /*
         * Sub-interface
         *   split the name into the parent and VLAN
         */
        std::vector<std::string> parts;
        boost::split(parts, name, boost::is_any_of("."));

        interface parent(parts[0], type, state);
        up_itf.reset(new sub_interface(hdl, parent, state, vd.sub_id));
    }
    else if (type_t::VXLAN == type)
    {
        /*
         * there's not enough inforation in a SW interface record to construct
         * a VXLAN tunnel. so skip it.
         */
    }
    else
    {
        up_itf.reset(new interface(hdl, l2_address, name, type, state));
    }

    return (up_itf);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
