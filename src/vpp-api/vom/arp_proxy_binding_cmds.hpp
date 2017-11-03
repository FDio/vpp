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

#ifndef __VOM_ARP_PROXY_BINDING_CMDS_H__
#define __VOM_ARP_PROXY_BINDING_CMDS_H__

#include "vom/arp_proxy_binding.hpp"

#include <vapi/vpe.api.vapi.hpp>

namespace VOM {
namespace arp_proxy_binding_cmds {
/**
 * A command class that binds the LLDP config to the interface
 */
class bind_cmd
  : public rpc_cmd<HW::item<bool>, rc_t, vapi::Proxy_arp_intfc_enable_disable>
{
public:
  /**
   * Constructor
   */
  bind_cmd(HW::item<bool>& item, const handle_t& itf);

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
};

/**
 * A cmd class that Unbinds ArpProxy Config from an interface
 */
class unbind_cmd
  : public rpc_cmd<HW::item<bool>, rc_t, vapi::Proxy_arp_intfc_enable_disable>
{
public:
  /**
   * Constructor
   */
  unbind_cmd(HW::item<bool>& item, const handle_t& itf);

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
