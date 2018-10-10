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

#include "vom/bond_interface.hpp"
#include "vom/bond_member.hpp"
#include "vom/interface_factory.hpp"
#include "vom/sub_interface.hpp"
#include "vom/tap_interface.hpp"

namespace VOM {
std::shared_ptr<interface>
interface_factory::new_interface(const vapi_payload_sw_interface_details& vd)
{
  std::shared_ptr<interface> sp;

  /**
   * Determine the interface type from the name and VLAN attributes
   */
  std::string name = reinterpret_cast<const char*>(vd.interface_name);
  interface::type_t type = interface::type_t::from_string(name);
  interface::admin_state_t state =
    interface::admin_state_t::from_int(vd.admin_up_down);
  handle_t hdl(vd.sw_if_index);
  l2_address_t l2_address(vd.l2_address, vd.l2_address_length);
  std::string tag = "";

  if (interface::type_t::UNKNOWN == type) {
    return sp;
  }

  sp = interface::find(hdl);
  if (sp) {
    sp->set(state);
    sp->set(l2_address);
    if (!tag.empty())
      sp->set(tag);
    return sp;
  }

  /*
   * If here, Fall back to old routine
   */
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
    tag = std::string(reinterpret_cast<const char*>(vd.tag));
  }

  if (!tag.empty() && interface::type_t::LOOPBACK == type) {
    name = tag;
    type = interface::type_t::from_string(name);
  }

  /*
   * pull out the other special cases
   */
  if (interface::type_t::TAP == type || interface::type_t::TAPV2 == type) {
    /*
     * TAP interfaces
     */
    sp = interface::find(hdl);
    if (sp && !tag.empty())
      sp->set(tag);
  } else if (interface::type_t::PIPE == type) {
    /*
     * there's not enough information in a SW interface record to
     * construct a pipe. so skip it. They have
     * their own dump routines
     */
  } else if ((name.find(".") != std::string::npos) && (0 != vd.sub_id)) {
    /*
     * Sub-interface
     *   split the name into the parent and VLAN
     */
    std::vector<std::string> parts;
    std::shared_ptr<interface> parent;
    boost::split(parts, name, boost::is_any_of("."));

    if ((parent = interface::find(parts[0])))
      sp = sub_interface(*parent, state, vd.sub_id).singular();
    else {
      interface parent_itf(parts[0], type, state, tag);
      sp = sub_interface(parent_itf, state, vd.sub_id).singular();
    }
  } else if (interface::type_t::VXLAN == type) {
    /*
     * there's not enough information in a SW interface record to
     * construct a VXLAN tunnel. so skip it. They have
     * their own dump routines
     */
  } else if (interface::type_t::VHOST == type) {
    /*
     * vhost interface already exist in db, look for it using
     * sw_if_index
     */
  } else if (interface::type_t::BOND == type) {
    sp = bond_interface(name, state, l2_address,
                        bond_interface::mode_t::UNSPECIFIED)
           .singular();
  } else {
    sp = interface(name, type, state, tag).singular();
    sp->set(l2_address);
  }

  /*
   * set the handle on the intterface - N.B. this is the sigluar instance
   * not a stack local.
   */
  if (sp)
    sp->set(hdl);

  return (sp);
}

std::shared_ptr<interface>
interface_factory::new_vhost_user_interface(
  const vapi_payload_sw_interface_vhost_user_details& vd)
{
  std::shared_ptr<interface> sp;
  std::string name = reinterpret_cast<const char*>(vd.sock_filename);
  interface::type_t type = interface::type_t::from_string(name);
  handle_t hdl(vd.sw_if_index);

  sp = interface(name, type, interface::admin_state_t::DOWN).singular();
  sp->set(hdl);
  return (sp);
}

std::shared_ptr<interface>
interface_factory::new_af_packet_interface(
  const vapi_payload_af_packet_details& vd)
{
  std::shared_ptr<interface> sp;
  std::string name = reinterpret_cast<const char*>(vd.host_if_name);
  handle_t hdl(vd.sw_if_index);

  sp =
    interface(name, interface::type_t::AFPACKET, interface::admin_state_t::DOWN)
      .singular();
  sp->set(hdl);
  return (sp);
}

std::shared_ptr<tap_interface>
interface_factory::new_tap_interface(
  const vapi_payload_sw_interface_tap_details& vd)
{
  std::shared_ptr<tap_interface> sp;
  std::string name = reinterpret_cast<const char*>(vd.dev_name);
  handle_t hdl(vd.sw_if_index);

  sp = tap_interface(name, interface::type_t::TAP, interface::admin_state_t::UP,
                     route::prefix_t::ZERO)
         .singular();
  sp->set(hdl);
  return (sp);
}

std::shared_ptr<tap_interface>
interface_factory::new_tap_v2_interface(
  const vapi_payload_sw_interface_tap_v2_details& vd)
{
  std::shared_ptr<tap_interface> sp;
  handle_t hdl(vd.sw_if_index);
  std::string name = reinterpret_cast<const char*>(vd.host_if_name);
  route::prefix_t pfx(route::prefix_t::ZERO);
  boost::asio::ip::address addr;

  if (vd.host_ip4_prefix_len)
    pfx =
      route::prefix_t(0, (uint8_t*)vd.host_ip4_addr, vd.host_ip4_prefix_len);
  else if (vd.host_ip6_prefix_len)
    pfx =
      route::prefix_t(1, (uint8_t*)vd.host_ip6_addr, vd.host_ip6_prefix_len);

  l2_address_t l2_address(vd.host_mac_addr, 6);
  sp = tap_interface(name, interface::type_t::TAPV2,
                     interface::admin_state_t::UP, pfx, l2_address)
         .singular();

  sp->set(hdl);

  return (sp);
}

std::shared_ptr<bond_interface>
interface_factory::new_bond_interface(
  const vapi_payload_sw_interface_bond_details& vd)
{
  std::shared_ptr<bond_interface> sp;
  std::string name = reinterpret_cast<const char*>(vd.interface_name);
  handle_t hdl(vd.sw_if_index);
  bond_interface::mode_t mode =
    bond_interface::mode_t::from_numeric_val(vd.mode);
  bond_interface::lb_t lb = bond_interface::lb_t::from_numeric_val(vd.lb);
  sp = bond_interface::find(hdl);
  if (sp) {
    sp->set(mode);
    sp->set(lb);
  }
  return (sp);
}

bond_member
interface_factory::new_bond_member_interface(
  const vapi_payload_sw_interface_slave_details& vd)
{
  std::shared_ptr<bond_member> sp;
  std::string name = reinterpret_cast<const char*>(vd.interface_name);
  handle_t hdl(vd.sw_if_index);
  bond_member::mode_t mode =
    bond_member::mode_t::from_numeric_val(vd.is_passive);
  bond_member::rate_t rate =
    bond_member::rate_t::from_numeric_val(vd.is_long_timeout);
  std::shared_ptr<interface> itf = interface::find(hdl);
  bond_member bm(*itf, mode, rate);
  return (bm);
}

std::shared_ptr<pipe>
interface_factory::new_pipe_interface(const vapi_payload_pipe_details& payload)
{
  std::shared_ptr<pipe> sp;

  handle_t hdl(payload.sw_if_index);
  pipe::handle_pair_t hdl_pair(payload.pipe_sw_if_index[0],
                               payload.pipe_sw_if_index[1]);

  sp = pipe(payload.instance, interface::admin_state_t::UP).singular();

  sp->set(hdl);
  sp->set_ends(hdl_pair);

  return (sp);
}

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
