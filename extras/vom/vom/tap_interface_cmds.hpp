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

#ifndef __VOM_TAP_INTERFACE_CMDS_H__
#define __VOM_TAP_INTERFACE_CMDS_H__

#include "vom/interface.hpp"
#include "vom/tap_interface.hpp"
#include "vom/dump_cmd.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/interface.api.vapi.hpp>
#include <vapi/tap.api.vapi.hpp>

namespace VOM {
namespace tap_interface_cmds {

/**
 * A functor class that creates an interface
 */
class create_cmd : public interface::create_cmd<vapi::Tap_connect>
{
public:
  create_cmd(HW::item<handle_t>& item,
             const std::string& name,
             route::prefix_t& prefix,
             const l2_address_t& l2_address);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

private:
  route::prefix_t& m_prefix;
  const l2_address_t& m_l2_address;
};

/**
 * A functor class that deletes a Tap interface
 */
class delete_cmd : public interface::delete_cmd<vapi::Tap_delete>
{
public:
  delete_cmd(HW::item<handle_t>& item);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;
};

/**
 * A cmd class that Dumps all the Vpp Interfaces
 */
class dump_cmd : public VOM::dump_cmd<vapi::Sw_interface_tap_dump>
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

}; // namespace tap_interface_cmds 
}; // namespace VOM

#endif
