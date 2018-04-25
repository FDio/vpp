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

#ifndef __VOM_INTERFACE_SPAN_CMDS_H__
#define __VOM_INTERFACE_SPAN_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/interface_span.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/span.api.vapi.hpp>

namespace VOM {
namespace interface_span_cmds {

/**
 * A command class that configures the interface span
 */
class config_cmd
  : public rpc_cmd<HW::item<bool>, rc_t, vapi::Sw_interface_span_enable_disable>
{
public:
  /**
   * Constructor
   */
  config_cmd(HW::item<bool>& item,
             const handle_t& itf_from,
             const handle_t& itf_to,
             const interface_span::state_t& state);

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
   * Reference to the interface to be mirrored
   */
  const handle_t& m_itf_from;
  /**
   * Reference to the interface where the traffic is mirrored
   */
  const handle_t& m_itf_to;
  /**
   * the state (rx, tx or both) of the interface to be mirrored
   */
  const interface_span::state_t& m_state;
};

/**
 * A cmd class that Unconfigs interface span
 */
class unconfig_cmd
  : public rpc_cmd<HW::item<bool>, rc_t, vapi::Sw_interface_span_enable_disable>
{
public:
  /**
   * Constructor
   */
  unconfig_cmd(HW::item<bool>& item,
               const handle_t& itf_from,
               const handle_t& itf_to);

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
   * Reference to the interface to be mirrored
   */
  const handle_t& m_itf_from;
  /**
   * Reference to the interface where the traffic is mirrored
   */
  const handle_t& m_itf_to;
};

/**
 * A cmd class that Dumps all the interface spans
 */
class dump_cmd : public VOM::dump_cmd<vapi::Sw_interface_span_dump>
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
