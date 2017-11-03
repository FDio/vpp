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

#ifndef __VOM_ARP_PROXY_CONFIG_CMDS_H__
#define __VOM_ARP_PROXY_CONFIG_CMDS_H__

#include "vom/arp_proxy_config.hpp"
#include "vom/dump_cmd.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/vpe.api.vapi.hpp>

namespace VOM {
namespace arp_proxy_config_cmds {
/**
 * A command class that adds the ARP Proxy config
 */
class config_cmd : public rpc_cmd<HW::item<bool>, rc_t, vapi::Proxy_arp_add_del>
{
public:
  /**
   * Constructor
   */
  config_cmd(HW::item<bool>& item,
             const boost::asio::ip::address_v4& lo,
             const boost::asio::ip::address_v4& high);

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
  bool operator==(const config_cmd& i) const;

private:
  /**
   * Address range
   */
  const boost::asio::ip::address_v4 m_low;
  const boost::asio::ip::address_v4 m_high;
};

/**
 * A cmd class that Unconfigs ArpProxy Config from an interface
 */
class unconfig_cmd
  : public rpc_cmd<HW::item<bool>, rc_t, vapi::Proxy_arp_add_del>
{
public:
  /**
   * Constructor
   */
  unconfig_cmd(HW::item<bool>& item,
               const boost::asio::ip::address_v4& lo,
               const boost::asio::ip::address_v4& hig);

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
  bool operator==(const unconfig_cmd& i) const;

private:
  /**
   * Address range
   */
  const boost::asio::ip::address_v4 m_low;
  const boost::asio::ip::address_v4 m_high;
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
