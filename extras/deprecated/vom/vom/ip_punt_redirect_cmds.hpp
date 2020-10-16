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

#ifndef __VOM_IP_PUNT_REDIRECT_CMDS_H__
#define __VOM_IP_PUNT_REDIRECT_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/ip_punt_redirect.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/ip.api.vapi.hpp>

namespace VOM {
namespace ip_punt_redirect_cmds {

/**
*A command class that configures the IP punt_redirect
*/
class config_cmd : public rpc_cmd<HW::item<bool>, vapi::Ip_punt_redirect>
{
public:
  /**
   * Constructor
   */
  config_cmd(HW::item<bool>& item,
             const handle_t rx_itf,
             const handle_t tx_itf,
             const boost::asio::ip::address& addr);

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
   * Reference to the interface from which traffic is coming
   */
  const handle_t m_rx_itf;
  /**
   * Reference to the interface where traffic will be redirected
   */
  const handle_t m_tx_itf;

  /**
   * Reference to nexh hop ip address
   */
  const boost::asio::ip::address& m_addr;
};

/**
 * A cmd class that Unconfigs Ip punt redirect
 */
class unconfig_cmd : public rpc_cmd<HW::item<bool>, vapi::Ip_punt_redirect>
{
public:
  /**
   * Constructor
   */
  unconfig_cmd(HW::item<bool>& item,
               const handle_t rx_itf,
               const handle_t tx_itf,
               const boost::asio::ip::address& addr);

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
   * Reference to the interface from which traffic is coming
   */
  const handle_t m_rx_itf;
  /**
   * Reference to the interface where traffic will be redirected
   */
  const handle_t m_tx_itf;

  /**
   * Reference to nexh hop ip address
   */
  const boost::asio::ip::address& m_addr;
};

/**
 * A cmd class that Dumps all the IP punt redirect
 */
class dump_cmd : public VOM::dump_cmd<vapi::Ip_punt_redirect_dump>
{
public:
  /**
   * Constructor
   */
  dump_cmd() = default;

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

}; // namespace ip_punt_redirect_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
