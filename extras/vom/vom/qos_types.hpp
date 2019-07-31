/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef __VOM_QOS_TYPES_H__
#define __VOM_QOS_TYPES_H__

#include "vom/enum_base.hpp"

namespace VOM {
/**
 * Types belonging to QoS
 */
namespace QoS {

typedef uint8_t bits_t;

/**
 * The Source of the QoS classification (i.e. which header the bits are
 * associated with).
 */
class source_t : public enum_base<source_t>
{
public:
  const static source_t EXT;
  const static source_t VLAN;
  const static source_t MPLS;
  const static source_t IP;

private:
  /**
   * Private constructor taking the value and the string name
   */
  source_t(int v, const std::string& s);
};

}; // namesapce QoS

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
