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

#ifndef __VOM_ACL_ETHERTYPE_CMDS_H__
#define __VOM_ACL_ETHERTYPE_CMDS_H__

#include "vom/acl_ethertype.hpp"
#include "vom/dump_cmd.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/acl.api.vapi.hpp>

namespace VOM {
namespace ACL {
namespace acl_ethertype_cmds {
/**
 * A command class that binds the ethertype list to the interface
 */
class bind_cmd
  : public rpc_cmd<HW::item<bool>, vapi::Acl_interface_set_etype_whitelist>
{
public:
  /**
   * Constructor
   */
  bind_cmd(HW::item<bool>& item,
           const handle_t& itf,
           const acl_ethertype::ethertype_rules_t& le);

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
   * Ethertype list applied to interface
   */
  const acl_ethertype::ethertype_rules_t& m_le;
};

/**
 * A command class that unbinds the ethertype list to the interface
 */
class unbind_cmd
  : public rpc_cmd<HW::item<bool>, vapi::Acl_interface_set_etype_whitelist>
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
   * Reference to the HW::item of the interface to bind
   */
  const handle_t m_itf;
};

/**
 * A cmd class that Dumps all the acl ethertypes on given interface
 */
class dump_cmd : public VOM::dump_cmd<vapi::Acl_interface_etype_whitelist_dump>
{
public:
  /**
   * Constructor
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
};
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
