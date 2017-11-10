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

#ifndef __VOM_SUB_INTERFACE_CMDS_H__
#define __VOM_SUB_INTERFACE_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/rpc_cmd.hpp"
#include "vom/sub_interface.hpp"

#include <vapi/interface.api.vapi.hpp>

namespace VOM {
namespace sub_interface_cmds {

/**
 * A functor class that creates an interface
 */
class create_cmd : public interface::create_cmd<vapi::Create_vlan_subif>
{
public:
  /**
   * Cstrunctor taking the reference to the parent
   * and the sub-interface's VLAN
   */
  create_cmd(HW::item<handle_t>& item,
             const std::string& name,
             const handle_t& parent,
             uint16_t vlan);

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
   * Refernece to the parents handle
   */
  const handle_t& m_parent;

  /**
   * The VLAN of the sub-interface
   */
  uint16_t m_vlan;
};

/**
 * A cmd class that Delete an interface
 */
class delete_cmd : public interface::delete_cmd<vapi::Delete_subif>
{
public:
  /**
   * Constructor
   */
  delete_cmd(HW::item<handle_t>& item);

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
};

}; // namespace sub_interface_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
