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

#ifndef __VOM_BRIDGE_DOMAIN_ARP_ENTRY_CMDS_H__
#define __VOM_BRIDGE_DOMAIN_ARP_ENTRY_CMDS_H__

#include "vom/bridge_domain_arp_entry.hpp"

#include <vapi/l2.api.vapi.hpp>
#include <vapi/vpe.api.vapi.hpp>

namespace VOM {
namespace bridge_domain_arp_entry_cmds {

/**
* A command class that creates or updates the bridge domain ARP Entry
*/
class create_cmd : public rpc_cmd<HW::item<bool>, rc_t, vapi::Bd_ip_mac_add_del>
{
public:
  /**
   * Constructor
   */
  create_cmd(HW::item<bool>& item,
             uint32_t id,
             const mac_address_t& mac,
             const boost::asio::ip::address& ip_addr);

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
  uint32_t m_bd;
  mac_address_t m_mac;
  boost::asio::ip::address m_ip_addr;
};

/**
 * A cmd class that deletes a bridge domain ARP entry
 */
class delete_cmd : public rpc_cmd<HW::item<bool>, rc_t, vapi::Bd_ip_mac_add_del>
{
public:
  /**
   * Constructor
   */
  delete_cmd(HW::item<bool>& item,
             uint32_t id,
             const mac_address_t& mac,
             const boost::asio::ip::address& ip_addr);

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
  uint32_t m_bd;
  mac_address_t m_mac;
  boost::asio::ip::address m_ip_addr;
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
