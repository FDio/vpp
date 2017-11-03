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

#ifndef __VOM_LLDP_GLOBAL_CMDS_H__
#define __VOM_LLDP_GLOBAL_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/lldp_global.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/lldp.api.vapi.hpp>

namespace VOM {
namespace lldp_global_cmds {

/**
* A command class that binds the LLDP global to the interface
*/
class config_cmd : public rpc_cmd<HW::item<bool>, rc_t, vapi::Lldp_config>
{
public:
  /**
   * Constructor
   */
  config_cmd(HW::item<bool>& item,
             const std::string& system_name,
             uint32_t tx_hold,
             uint32_t tx_interval);

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
   * The system name
   */
  const std::string m_system_name;

  /**
   * TX timer configs
   */
  uint32_t m_tx_hold;
  uint32_t m_tx_interval;
};

}; // namespace lldp_global_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
