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
#ifndef __VOM_L2_VTR_H__
#define __VOM_L2_VTR_H__

#include "vom/hw.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"

namespace VOM {
namespace l2_vtr {
struct option_t : public enum_base<option_t>
{
  option_t(const option_t& l) = default;
  ~option_t() = default;

  const static option_t DISABLED;
  const static option_t PUSH_1;
  const static option_t PUSH_2;
  const static option_t POP_1;
  const static option_t POP_2;
  const static option_t TRANSLATE_1_1;
  const static option_t TRANSLATE_1_2;
  const static option_t TRANSLATE_2_1;
  const static option_t TRANSLATE_2_2;

private:
  option_t(int v, const std::string s);
};
}; // namespace l2_vtr
}; // namesapce VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
#endif
