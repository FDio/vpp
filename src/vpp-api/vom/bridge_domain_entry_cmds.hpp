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

#ifndef __VOM_BRIDGE_DOMAIN_ENTRY_CMDS_H__
#define __VOM_BRIDGE_DOMAIN_ENTRY_CMDS_H__

#include "vom/bridge_domain_entry.hpp"
#include "vom/dump_cmd.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/l2.api.vapi.hpp>

namespace VOM {
namespace bridge_domain_entry_cmds {

/**
* A command class that creates or updates the bridge_domain
*/
class create_cmd : public rpc_cmd<HW::item<bool>, rc_t, vapi::L2fib_add_del>
{
public:
  /**
   * Constructor
   */
  create_cmd(HW::item<bool>& item,
             const mac_address_t& mac,
             uint32_t id,
             handle_t tx_intf,
             bool is_bvi);

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
  mac_address_t m_mac;
  uint32_t m_bd;
  handle_t m_tx_itf;
  bool m_is_bvi;
};

/**
 * A cmd class that deletes a bridge_domain
 */
class delete_cmd : public rpc_cmd<HW::item<bool>, rc_t, vapi::L2fib_add_del>
{
public:
  /**
   * Constructor
   */
  delete_cmd(HW::item<bool>& item,
             const mac_address_t& mac,
             uint32_t id,
             bool is_bvi);

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
  mac_address_t m_mac;
  uint32_t m_bd;
  bool m_is_bvi;
};

/**
 * A cmd class that Dumps all the interface spans
 */
class dump_cmd : public VOM::dump_cmd<vapi::L2_fib_table_dump>
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
