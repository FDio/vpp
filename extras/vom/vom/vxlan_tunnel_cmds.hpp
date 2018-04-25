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

#ifndef __VOM_VXLAN_TUNNEL_CMDS_H__
#define __VOM_VXLAN_TUNNEL_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/rpc_cmd.hpp"
#include "vom/vxlan_tunnel.hpp"

#include <vapi/vapi.hpp>
#include <vapi/vxlan.api.vapi.hpp>

namespace VOM {
namespace vxlan_tunnel_cmds {

/**
 * A Command class that creates an VXLAN tunnel
 */
class create_cmd : public interface::create_cmd<vapi::Vxlan_add_del_tunnel>
{
public:
  /**
   * Create command constructor taking HW item to update and the
   * endpoint values
   */
  create_cmd(HW::item<handle_t>& item,
             const std::string& name,
             const vxlan_tunnel::endpoint_t& ep);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const create_cmd& i) const;

private:
  /**
   * Enpoint values of the tunnel to be created
   */
  const vxlan_tunnel::endpoint_t m_ep;
};

/**
 * A functor class that creates an VXLAN tunnel
 */
class delete_cmd : public interface::delete_cmd<vapi::Vxlan_add_del_tunnel>
{
public:
  /**
   * delete command constructor taking HW item to update and the
   * endpoint values
   */
  delete_cmd(HW::item<handle_t>& item, const vxlan_tunnel::endpoint_t& ep);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const delete_cmd& i) const;

private:
  /**
   * Enpoint values of the tunnel to be deleted
   */
  const vxlan_tunnel::endpoint_t m_ep;
};

/**
 * A cmd class that Dumps all the Vpp interfaces
 */
class dump_cmd : public VOM::dump_cmd<vapi::Vxlan_tunnel_dump>
{
public:
  /**
   * Default Constructor
   */
  dump_cmd();

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const dump_cmd& i) const;
};

}; // namespace vxlan_tunnel_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
