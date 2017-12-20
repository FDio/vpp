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

#ifndef __VOM_NAT_BINDING_CMDS_H__
#define __VOM_NAT_BINDING_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/nat_binding.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/nat.api.vapi.hpp>

namespace VOM {
namespace nat_binding_cmds {
/**
 * A functor class that binds a NAT configuration to an input interface
 */
class bind_44_input_cmd
  : public rpc_cmd<HW::item<bool>, rc_t, vapi::Nat44_interface_add_del_feature>
{
public:
  /**
   * Constructor
   */
  bind_44_input_cmd(HW::item<bool>& item,
                    const handle_t& itf,
                    const nat_binding::zone_t& zone);

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
  bool operator==(const bind_44_input_cmd& i) const;

private:
  /**
   * The interface to bind
   */
  const handle_t m_itf;

  /**
   * The zone the interface is in
   */
  const nat_binding::zone_t m_zone;
};

/**
 * A cmd class that unbinds a NAT configuration from an input interface
 */
class unbind_44_input_cmd
  : public rpc_cmd<HW::item<bool>, rc_t, vapi::Nat44_interface_add_del_feature>
{
public:
  /**
   * Constructor
   */
  unbind_44_input_cmd(HW::item<bool>& item,
                      const handle_t& itf,
                      const nat_binding::zone_t& zone);

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
  bool operator==(const unbind_44_input_cmd& i) const;

private:
  /**
   * The interface to bind
   */
  const handle_t m_itf;

  /**
   * The zone the interface is in
   */
  const nat_binding::zone_t m_zone;
};

/**
 * A functor class that binds a NAT configuration to an output interface
 */
class bind_44_output_cmd
  : public rpc_cmd<HW::item<bool>,
                   rc_t,
                   vapi::Nat44_interface_add_del_output_feature>
{
public:
  /**
   * Constructor
   */
  bind_44_output_cmd(HW::item<bool>& item,
                     const handle_t& itf,
                     const nat_binding::zone_t& zone);

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
  bool operator==(const bind_44_output_cmd& i) const;

private:
  /**
   * The interface to bind
   */
  const handle_t m_itf;

  /**
   * The zone the interface is in
   */
  const nat_binding::zone_t m_zone;
};

/**
 * A cmd class that unbinds a NAT configuration from an output interface
 */
class unbind_44_output_cmd
  : public rpc_cmd<HW::item<bool>,
                   rc_t,
                   vapi::Nat44_interface_add_del_output_feature>
{
public:
  /**
   * Constructor
   */
  unbind_44_output_cmd(HW::item<bool>& item,
                       const handle_t& itf,
                       const nat_binding::zone_t& zone);

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
  bool operator==(const unbind_44_output_cmd& i) const;

private:
  /**
   * The interface to bind
   */
  const handle_t m_itf;

  /**
   * The zone the interface is in
   */
  const nat_binding::zone_t m_zone;
};

/**
 * A cmd class that Dumps all the nat_statics
 */
class dump_input_44_cmd : public dump_cmd<vapi::Nat44_interface_dump>
{
public:
  /**
   * Constructor
   */
  dump_input_44_cmd();
  dump_input_44_cmd(const dump_input_44_cmd& d);

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
  bool operator==(const dump_input_44_cmd& i) const;

private:
  /**
   * HW reutrn code
   */
  HW::item<bool> item;
};

/**
 * A cmd class that Dumps all the nat_statics
 */
class dump_output_44_cmd
  : public dump_cmd<vapi::Nat44_interface_output_feature_dump>
{
public:
  /**
   * Constructor
   */
  dump_output_44_cmd();
  dump_output_44_cmd(const dump_output_44_cmd& d);

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
  bool operator==(const dump_output_44_cmd& i) const;

private:
  /**
   * HW reutrn code
   */
  HW::item<bool> item;
};

}; // namespace nat_binding_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
