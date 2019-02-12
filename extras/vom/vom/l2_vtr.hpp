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
struct l2_vtr_op_t : public enum_base<l2_vtr_op_t>
{
  l2_vtr_op_t(const l2_vtr_op_t& l) = default;
  ~l2_vtr_op_t() = default;

  const static l2_vtr_op_t L2_VTR_DISABLED;
  const static l2_vtr_op_t L2_VTR_PUSH_1;
  const static l2_vtr_op_t L2_VTR_PUSH_2;
  const static l2_vtr_op_t L2_VTR_POP_1;
  const static l2_vtr_op_t L2_VTR_POP_2;
  const static l2_vtr_op_t L2_VTR_TRANSLATE_1_1;
  const static l2_vtr_op_t L2_VTR_TRANSLATE_1_2;
  const static l2_vtr_op_t L2_VTR_TRANSLATE_2_1;
  const static l2_vtr_op_t L2_VTR_TRANSLATE_2_2;

private:
  l2_vtr_op_t(int v, const std::string s);
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
