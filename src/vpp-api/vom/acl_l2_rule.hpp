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

#ifndef __VOM_L2_ACL_RULE_H__
#define __VOM_L2_ACL_RULE_H__

#include "vom/acl_types.hpp"
#include "vom/prefix.hpp"

namespace VOM {
namespace ACL {
/**
 * An ACL rule is the building block of an ACL. An ACL, which is
 * the object applied to an interface, is comprised of an ordersed
 * sequence of ACL rules.
 * This class is a wrapper around the VAPI generated struct and exports
 * an API with better types.
 */
class l2_rule
{
public:
  /**
   * Construct a new object matching the desried state
   */
  l2_rule(uint32_t priority,
          const action_t& action,
          const route::prefix_t& ip,
          const mac_address_t& mac,
          const mac_address_t& mac_mask);

  /**
   * Copy Constructor
   */
  l2_rule(const l2_rule& o) = default;

  /**
   * Destructor
   */
  ~l2_rule() = default;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * less-than operator
   */
  bool operator<(const l2_rule& rule) const;

  /**
   * comparison operator (for testing)
   */
  bool operator==(const l2_rule& rule) const;

  /**
   * Getters
   */
  uint32_t priority() const;
  action_t action() const;
  const route::prefix_t& src_ip() const;
  const mac_address_t& mac() const;
  const mac_address_t& mac_mask() const;

private:
  /**
   * Priority. Used to sort the rules in a list in the order
   * in which they are applied
   */
  uint32_t m_priority;

  /**
   * Action on match
   */
  action_t m_action;

  /**
   * Source Prefix
   */
  route::prefix_t m_src_ip;

  /**
   * Source Mac
   */
  mac_address_t m_mac;

  /**
   * Source MAC mask
   */
  mac_address_t m_mac_mask;
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
