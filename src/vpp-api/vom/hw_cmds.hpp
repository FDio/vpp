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

#ifndef __VOM_HW_CMDS_H__
#define __VOM_HW_CMDS_H__

#include <vapi/vapi.hpp>
#include <vapi/vpe.api.vapi.hpp>

#include "vom/hw.hpp"
#include "vom/rpc_cmd.hpp"

namespace VOM {
namespace hw_cmds {
/**
*A command poll the HW for liveness
*/
class poll : public rpc_cmd<HW::item<bool>, rc_t, vapi::Control_ping>
{
public:
  /**
   * Constructor taking the HW::item to update
   */
  poll(HW::item<bool>& item);

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
  bool operator==(const poll& i) const;
};
};
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
