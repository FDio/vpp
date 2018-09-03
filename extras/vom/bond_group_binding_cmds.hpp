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

#ifndef __VOM_BOND_GROUP_BINDING_CMDS_H__
#define __VOM_BOND_GROUP_BINDING_CMDS_H__

#include "vom/bond_group_binding.hpp"
#include "vom/dump_cmd.hpp"

#include <vapi/bond.api.vapi.hpp>

namespace VOM {
namespace bond_group_binding_cmds {
/**
 * A command class that binds the slave interface to the bond interface
 */
class bind_cmd : public rpc_cmd<HW::item<bool>, vapi::Bond_enslave>
{
public:
  /**
   * Constructor
   */
  bind_cmd(HW::item<bool>& item,
           const handle_t& bond_itf,
           const bond_member& itf);

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
   * sw_if_index of bond interface
   */
  const handle_t m_bond_itf;

  /**
   * member interface of bond group
   */
  const bond_member m_itf;
};

/**
 * A cmd class that detach slave from a bond interface
 */
class unbind_cmd : public rpc_cmd<HW::item<bool>, vapi::Bond_detach_slave>
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
   * slave interface of bond group
   */
  const handle_t m_itf;
};

/**
 * A cmd class that Dumps slave itfs
 */
class dump_cmd : public VOM::dump_cmd<vapi::Sw_interface_slave_dump>
{
public:
  /**
   * Default Constructor
   */
  dump_cmd(const handle_t& itf);
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
   * The interface to get the addresses for
   */
  const handle_t m_itf;
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
