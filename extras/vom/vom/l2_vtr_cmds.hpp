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

#ifndef __VOM_L2_VTR_CMDS_H__
#define __VOM_L2_VTR_CMDS_H__

#include "vom/l2_vtr.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/l2.api.vapi.hpp>

namespace VOM {
namespace l2_vtr_cmds {
/**
 * A cmd class sets the VTR operation
 */
class set_cmd : public rpc_cmd<HW::item<l2_vtr::option_t>,
                               vapi::L2_interface_vlan_tag_rewrite>
{
public:
  /**
   * Constructor
   */
  set_cmd(HW::item<l2_vtr::option_t>& item, const handle_t& itf, uint16_t tag);

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
  bool operator==(const set_cmd& i) const;

private:
  /**
   * The interface to bind
   */
  const handle_t m_itf;

  /**
   * The tag for the operation
   */
  uint16_t m_tag;
};

}; // namespace vtr_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
