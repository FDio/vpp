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

#ifndef __VOM_ACL_LIST_CMDS_H__
#define __VOM_ACL_LIST_CMDS_H__

#include "vom/acl_list.hpp"
#include "vom/dump_cmd.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/acl.api.vapi.hpp>

namespace VOM {
namespace ACL {
namespace list_cmds {
/**
 * A command class that Create the list
 */
template <typename RULE, typename UPDATE>
class update_cmd
  : public rpc_cmd<HW::item<handle_t>, HW::item<handle_t>, UPDATE>
{
public:
  typedef typename list<RULE>::rules_t cmd_rules_t;
  typedef typename list<RULE>::key_t cmd_key_t;

  /**
   * Constructor
   */
  update_cmd(HW::item<handle_t>& item,
             const cmd_key_t& key,
             const cmd_rules_t& rules)
    : rpc_cmd<HW::item<handle_t>, HW::item<handle_t>, UPDATE>(item)
    , m_key(key)
    , m_rules(rules)
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
    s << "ACL-list-update: " << this->item().to_string();

    return (s.str());
  }

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const update_cmd& other) const
  {
    return ((m_key == other.m_key) && (m_rules == other.m_rules));
  }

  void complete()
  {
    std::shared_ptr<list<RULE>> sp = list<RULE>::find(m_key);
    if (sp && this->item()) {
      list<RULE>::add(this->item().data(), sp);
    }
  }

  void succeeded()
  {
    rpc_cmd<HW::item<handle_t>, HW::item<handle_t>, UPDATE>::succeeded();
    complete();
  }

  /**
   * A callback function for handling ACL creates
   */
  virtual vapi_error_e operator()(UPDATE& reply)
  {
    int acl_index = reply.get_response().get_payload().acl_index;
    int retval = reply.get_response().get_payload().retval;

    VOM_LOG(log_level_t::DEBUG) << this->to_string() << " " << retval;

    HW::item<handle_t> res(acl_index, rc_t::from_vpp_retval(retval));

    this->fulfill(res);

    return (VAPI_OK);
  }

private:
  /**
   * The key.
   */
  const cmd_key_t& m_key;

  /**
   * The rules
   */
  const cmd_rules_t& m_rules;
};

/**
 * A cmd class that Deletes an ACL
 */
template <typename DELETE>
class delete_cmd : public rpc_cmd<HW::item<handle_t>, rc_t, DELETE>
{
public:
  /**
   * Constructor
   */
  delete_cmd(HW::item<handle_t>& item)
    : rpc_cmd<HW::item<handle_t>, rc_t, DELETE>(item)
  {
  }

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con) { return (rc_t::INVALID); }

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const
  {
    std::ostringstream s;
    s << "ACL-list-delete: " << this->item().to_string();

    return (s.str());
  }

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const delete_cmd& other) const
  {
    return (this->item().data() == other.item().data());
  }
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
  rc_t issue(connection& con) { return rc_t::INVALID; }

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const { return ("acl-list-dump"); }

private:
  /**
   * HW reutrn code
   */
  HW::item<bool> item;
};

/**
 * Typedef the L3 ACL commands
 */
typedef update_cmd<l3_rule, vapi::Acl_add_replace> l3_update_cmd;
typedef delete_cmd<vapi::Acl_del> l3_delete_cmd;
typedef dump_cmd<vapi::Acl_dump> l3_dump_cmd;

/**
 * Typedef the L2 ACL commands
 */
typedef update_cmd<l2_rule, vapi::Macip_acl_add> l2_update_cmd;
typedef delete_cmd<vapi::Macip_acl_del> l2_delete_cmd;
typedef dump_cmd<vapi::Macip_acl_dump> l2_dump_cmd;

}; // namespace list_cmds
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
