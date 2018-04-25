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

#ifndef __VOM_IP_UNNUMBERED_CMDS_H__
#define __VOM_IP_UNNUMBERED_CMDS_H__

#include "vom/ip_unnumbered.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/interface.api.vapi.hpp>

namespace VOM {
namespace ip_unnumbered_cmds {

/**
*A command class that configures the IP unnumbered
*/
class config_cmd
  : public rpc_cmd<HW::item<bool>, rc_t, vapi::Sw_interface_set_unnumbered>
{
public:
  /**
   * Constructor
   */
  config_cmd(HW::item<bool>& item, const handle_t& itf, const handle_t& l3_itf);

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
  bool operator==(const config_cmd& i) const;

private:
  /**
   * Reference to the interface for which the address is required
   */
  const handle_t& m_itf;
  /**
   * Reference to the interface which has an address
   */
  const handle_t& m_l3_itf;
};

/**
 * A cmd class that Unconfigs L3 Config from an interface
 */
class unconfig_cmd
  : public rpc_cmd<HW::item<bool>, rc_t, vapi::Sw_interface_set_unnumbered>
{
public:
  /**
   * Constructor
   */
  unconfig_cmd(HW::item<bool>& item,
               const handle_t& itf,
               const handle_t& l3_itf);

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
  bool operator==(const unconfig_cmd& i) const;

private:
  /**
   * Reference to the interface for which the address is required
   */
  const handle_t& m_itf;
  /**
   * Reference to the interface which has an address
   */
  const handle_t& m_l3_itf;
};

}; // namespace ip_unnumbered_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
