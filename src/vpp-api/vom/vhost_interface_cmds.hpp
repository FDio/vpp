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

#ifndef __VOM_VHOST_INTERFACE_CMDS_H__
#define __VOM_VHOST_INTERFACE_CMDS_H__

#include "vom/interface.hpp"
#include "vom/vhost_interface.hpp"
#include "vom/dump_cmd.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/interface.api.vapi.hpp>
#include <vapi/vhost_user.api.vapi.hpp>

namespace VOM {
namespace vhost_interface_cmds {

/**
 * A functor class that creates an interface
 */
class create_cmd : public interface::create_cmd<vapi::Create_vhost_user_if>
{
public:
  create_cmd(HW::item<handle_t>& item,
             const std::string& name,
             const std::string& tag);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

private:
  const std::string m_tag;
};

/**
 * A functor class that deletes a Vhost interface
 */
class delete_cmd : public interface::delete_cmd<vapi::Delete_vhost_user_if>
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
class dump_cmd : public VOM::dump_cmd<vapi::Sw_interface_vhost_user_dump>
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

}; // namespace vhost_interface_cmds 
}; // namespace VOM

#endif
