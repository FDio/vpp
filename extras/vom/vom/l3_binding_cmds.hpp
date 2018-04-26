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

#ifndef __VOM_L3_BINDING_CMDS_H__
#define __VOM_L3_BINDING_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/l3_binding.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/interface.api.vapi.hpp>
#include <vapi/ip.api.vapi.hpp>

namespace VOM {
namespace l3_binding_cmds {

/**
 * A functor class that binds the L3 config to the interface
 */
class bind_cmd
  : public rpc_cmd<HW::item<bool>, rc_t, vapi::Sw_interface_add_del_address>
{
public:
  /**
   * Constructor
   */
  bind_cmd(HW::item<bool>& item,
           const handle_t& itf,
           const route::prefix_t& pfx);

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
   * Reference to the interface to bind to
   */
  const handle_t& m_itf;

  /**
   * The prefix to bind
   */
  const route::prefix_t& m_pfx;
};

/**
 * A cmd class that Unbinds L3 Config from an interface
 */
class unbind_cmd
  : public rpc_cmd<HW::item<bool>, rc_t, vapi::Sw_interface_add_del_address>
{
public:
  /**
   * Constructor
   */
  unbind_cmd(HW::item<bool>& item,
             const handle_t& itf,
             const route::prefix_t& pfx);

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
   * Reference to the interface to unbind fomr
   */
  const handle_t& m_itf;

  /**
   * The prefix to unbind
   */
  const route::prefix_t& m_pfx;
};

/**
 * A cmd class that Dumps all the IPv4 L3 configs
 */
class dump_v4_cmd : public dump_cmd<vapi::Ip_address_dump>
{
public:
  /**
   * Constructor
   */
  dump_v4_cmd(const handle_t& itf);
  dump_v4_cmd(const dump_v4_cmd& d);

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
  bool operator==(const dump_v4_cmd& i) const;

private:
  /**
   * HW reutrn code
   */
  HW::item<bool> item;

  /**
   * The interface to get the addresses for
   */
  const handle_t& m_itf;
};

}; // namespace l3_binding_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
