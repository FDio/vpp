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

#ifndef __VOM_ACL_TYPES_H__
#define __VOM_ACL_TYPES_H__

#include "vom/types.hpp"

namespace VOM {
namespace ACL {
/**
 * ACL Actions
 */
struct action_t : public enum_base<action_t>
{
  /**
   * Constructor
   */
  action_t(int v, const std::string s);

  /**
   * Destructor
   */
  ~action_t() = default;

  /**
   * Permit and Reflexive
   */
  const static action_t PERMITANDREFLEX;

  /**
   * Permit Action
   */
  const static action_t PERMIT;

  /**
   * Deny Action
   */
  const static action_t DENY;

  /**
   * Get the enum type from a VPP integer value
   */
  static const action_t& from_int(uint8_t i);

  /**
   *Get the enum type from a bool value and optional uint8_t value
   *which implements the connection tracking ....
   */
  static const action_t& from_bool(bool b, uint8_t c);
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
