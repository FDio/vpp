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

#ifndef __VOM_ACL_BINDING_CMDS_H__
#define __VOM_ACL_BINDING_CMDS_H__

#include "vom/acl_binding.hpp"
#include "vom/dump_cmd.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/acl.api.vapi.hpp>

namespace VOM {
namespace ACL {
namespace binding_cmds {
/**
 * A command class that binds the ACL to the interface
 */
template <typename BIND>
class bind_cmd : public rpc_cmd<HW::item<bool>, rc_t, BIND>
{
public:
  /**
   * Constructor
   */
  bind_cmd(HW::item<bool>& item,
           const direction_t& direction,
           const handle_t& itf,
           const handle_t& acl)
    : rpc_cmd<HW::item<bool>, rc_t, BIND>(item)
    , m_direction(direction)
    , m_itf(itf)
    , m_acl(acl)
  {
  }

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const
  {
    std::ostringstream s;
    s << "acl-bind:[" << m_direction.to_string() << " itf:" << m_itf.to_string()
      << " acl:" << m_acl.to_string() << "]";

    return (s.str());
  }

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const bind_cmd& other) const
  {
    return ((m_itf == other.m_itf) && (m_acl == m_acl));
  }

private:
  /**
   * The direction of the binding
   */
  const direction_t m_direction;

  /**
   * The interface to bind to
   */
  const handle_t m_itf;

  /**
   * The ACL to bind
   */
  const handle_t m_acl;
};

/**
 * A command class that binds the ACL to the interface
 */
template <typename BIND>
class unbind_cmd : public rpc_cmd<HW::item<bool>, rc_t, BIND>
{
public:
  /**
   * Constructor
   */
  unbind_cmd(HW::item<bool>& item,
             const direction_t& direction,
             const handle_t& itf,
             const handle_t& acl)
    : rpc_cmd<HW::item<bool>, rc_t, BIND>(item)
    , m_direction(direction)
    , m_itf(itf)
    , m_acl(acl)
  {
  }

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const
  {
    std::ostringstream s;
    s << "acl-unbind:[" << m_direction.to_string()
      << " itf:" << m_itf.to_string() << " acl:" << m_acl.to_string() << "]";

    return (s.str());
  }

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const unbind_cmd& other) const
  {
    return ((m_itf == other.m_itf) && (m_acl == m_acl));
  }

private:
  /**
   * The direction of the binding
   */
  const direction_t m_direction;

  /**
   * The interface to bind to
   */
  const handle_t m_itf;

  /**
   * The ACL to bind
   */
  const handle_t m_acl;
};

/**
 * A cmd class that Dumps all the ACLs
 */
template <typename DUMP>
class dump_cmd : public VOM::dump_cmd<DUMP>
{
public:
  /**
   * Constructor
   */
  dump_cmd() = default;
  dump_cmd(const dump_cmd& d) = default;

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const { return ("acl-bind-dump"); }

private:
  /**
   * HW reutrn code
   */
  HW::item<bool> item;
};

/**
 * Typedef the L3 ACL binding commands
 */
typedef bind_cmd<vapi::Acl_interface_add_del> l3_bind_cmd;
typedef unbind_cmd<vapi::Acl_interface_add_del> l3_unbind_cmd;
typedef dump_cmd<vapi::Acl_interface_list_dump> l3_dump_cmd;

/**
 * Typedef the L2 binding type
 */
typedef bind_cmd<vapi::Macip_acl_interface_add_del> l2_bind_cmd;
typedef unbind_cmd<vapi::Macip_acl_interface_add_del> l2_unbind_cmd;
typedef dump_cmd<vapi::Macip_acl_interface_list_dump> l2_dump_cmd;

}; // namespace binding_cmds
}; // namespace ACL
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
