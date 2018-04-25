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

#ifndef __VOM_L2_EMULATION_CMDS_H__
#define __VOM_L2_EMULATION_CMDS_H__

#include "vom/l2_emulation.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/l2e.api.vapi.hpp>

namespace VOM {
namespace l2_emulation_cmds {

/**
 * A functor class that enable L2 emulation to an interface
 */
class enable_cmd : public rpc_cmd<HW::item<bool>, rc_t, vapi::L2_emulation>
{
public:
  /**
   * Constructor
   */
  enable_cmd(HW::item<bool>& item, const handle_t& itf);

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
  bool operator==(const enable_cmd& i) const;

private:
  /**
   * The interface to bind
   */
  const handle_t m_itf;
};

/**
 * A cmd class that Unbinds L2 configuration from an interface
 */
class disable_cmd : public rpc_cmd<HW::item<bool>, rc_t, vapi::L2_emulation>
{
public:
  /**
   * Constructor
   */
  disable_cmd(HW::item<bool>& item, const handle_t& itf);

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
  bool operator==(const disable_cmd& i) const;

private:
  /**
   * The interface to bind
   */
  const handle_t m_itf;
};

}; // namespace l2_emulation_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
