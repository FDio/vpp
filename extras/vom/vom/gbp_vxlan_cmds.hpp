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

#ifndef __VOM_GBP_VXLAN_CMDS_H__
#define __VOM_GBP_VXLAN_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/gbp_vxlan.hpp"
#include "vom/interface.hpp"

#include <vapi/gbp.api.vapi.hpp>

namespace VOM {
namespace gbp_vxlan_cmds {
/**
 * A command class that creates an Bridge-Domain
 */
class create_cmd : public interface::create_cmd<vapi::Gbp_vxlan_tunnel_add>
{
public:
  /**
   * Constructor
   */
  create_cmd(HW::item<handle_t>& item,
             const std::string& name,
             uint32_t vni,
             bool is_l2,
             uint32_t bd_rd);

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
  uint32_t m_vni;
  bool m_is_l2;
  uint32_t m_bd_rd;
};

/**
 * A cmd class that Delete an Bridge-Domain
 */
class delete_cmd : public interface::delete_cmd<vapi::Gbp_vxlan_tunnel_del>
{
public:
  /**
   * Constructor
   */
  delete_cmd(HW::item<handle_t>& item, uint32_t vni);

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
  uint32_t m_vni;
};

/**
 * A cmd class that Dumps all the bridge domains
 */
class dump_cmd : public VOM::dump_cmd<vapi::Gbp_vxlan_tunnel_dump>
{
public:
  /**
   * Constructor
   */
  dump_cmd();
  dump_cmd(const dump_cmd& d);

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

private:
  /**
   * HW reutrn code
   */
  HW::item<bool> item;
};

}; // gbp_vxlan_cmds
}; // VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
