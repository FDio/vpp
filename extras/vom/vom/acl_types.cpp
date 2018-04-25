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

#include "vom/acl_types.hpp"

namespace VOM {
namespace ACL {
const action_t action_t::PERMITANDREFLEX(2, "permitandreflex");
const action_t action_t::PERMIT(1, "permit");
const action_t action_t::DENY(0, "deny");

action_t::action_t(int v, const std::string s)
  : enum_base(v, s)
{
}

const action_t&
action_t::from_int(uint8_t i)
{
  if (i == 2)
    return action_t::PERMITANDREFLEX;
  else if (i)
    return action_t::PERMIT;

  return action_t::DENY;
}

const action_t&
action_t::from_bool(bool b, uint8_t c)
{
  if (b) {
    if (c)
      return action_t::PERMITANDREFLEX;
    return action_t::PERMIT;
  }
  return action_t::DENY;
}
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
