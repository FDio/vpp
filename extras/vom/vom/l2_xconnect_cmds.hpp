/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __VOM_L2_XCONNECT_CMDS_H__
#define __VOM_L2_XCONNECT_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/l2_xconnect.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/l2.api.vapi.hpp>
#include <vapi/vpe.api.vapi.hpp>

namespace VOM {
namespace l2_xconnect_cmds {

/**
 * A functor class that binds L2 configuration to an interface
 */
class bind_cmd
  : public rpc_cmd<HW::item<bool>, vapi::Sw_interface_set_l2_xconnect>
{
public:
  /**
   * Constructor
   */
  bind_cmd(HW::item<bool>& item,
           const handle_t& east_itf,
           const handle_t& west_itf);

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
  bool operator==(const bind_cmd& i) const;

private:
  /**
   * The east interface for cross_connect
   */
  const handle_t m_east_itf;

  /**
   * The west interface for x-connect
   */
  const handle_t m_west_itf;
};

/**
 * A cmd class that Unbinds L2 configuration from an interface
 */
class unbind_cmd
  : public rpc_cmd<HW::item<bool>, vapi::Sw_interface_set_l2_xconnect>
{
public:
  /**
   * Constructor
   */
  unbind_cmd(HW::item<bool>& item,
             const handle_t& east_itf,
             const handle_t& west_itf);

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
  bool operator==(const unbind_cmd& i) const;

private:
  /**
   * The east interface for x-connect
   */
  const handle_t m_east_itf;

  /**
   * The west interface for x-connect
   */
  const handle_t m_west_itf;
};

/**
 * A cmd class that Dumps all the bridge domains
 */
class dump_cmd : public VOM::dump_cmd<vapi::L2_xconnect_dump>
{
public:
  /**
   * Constructor
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

}; // namespace l2_xconnect_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
