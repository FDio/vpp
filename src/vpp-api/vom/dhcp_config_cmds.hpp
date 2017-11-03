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

#ifndef __VOM_DHCP_CONFIG_CMDS_H__
#define __VOM_DHCP_CONFIG_CMDS_H__

#include "vom/dhcp_config.hpp"
#include "vom/event_cmd.hpp"

#include <vapi/dhcp.api.vapi.hpp>
#include <vapi/vpe.api.vapi.hpp>

namespace VOM {
namespace dhcp_config_cmds {

/**
  * A command class that binds the DHCP config to the interface
  */
class bind_cmd : public rpc_cmd<HW::item<bool>, rc_t, vapi::Dhcp_client_config>
{
public:
  /**
   * Constructor
   */
  bind_cmd(HW::item<bool>& item,
           const handle_t& itf,
           const std::string& hostname,
           const l2_address_t& client_id);

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
   * Reference to the HW::item of the interface to bind
   */
  const handle_t& m_itf;

  /**
   * The DHCP client's hostname
   */
  const std::string m_hostname;

  /**
   * The DHCP client's ID
   */
  const l2_address_t m_client_id;
};

/**
 * A cmd class that Unbinds Dhcp Config from an interface
 */
class unbind_cmd
  : public rpc_cmd<HW::item<bool>, rc_t, vapi::Dhcp_client_config>
{
public:
  /**
   * Constructor
   */
  unbind_cmd(HW::item<bool>& item,
             const handle_t& itf,
             const std::string& hostname);

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
   * Reference to the HW::item of the interface to unbind
   */
  const handle_t& m_itf;

  /**
   * The DHCP client's hostname
   */
  const std::string m_hostname;
};

/**
 * A functor class represents our desire to recieve interface events
 */
class events_cmd : public event_cmd<vapi::Control_ping, vapi::Dhcp_compl_event>
{
public:
  /**
   * Constructor
   */
  events_cmd(dhcp_config::event_listener& el);

  /**
   * Issue the command to VPP/HW - subscribe to DHCP events
   */
  rc_t issue(connection& con);

  /**
   * Retire the command - unsubscribe
   */
  void retire(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const events_cmd& i) const;

  /**
   * called in the VAPI RX thread when data is available.
   */
  void notify();

private:
  void succeeded() {}
  /**
   * The listner of this command
   */
  dhcp_config::event_listener& m_listener;
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
