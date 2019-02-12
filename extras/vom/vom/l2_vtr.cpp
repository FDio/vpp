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

#include "vom/l2_vtr.hpp"

namespace VOM {

/*
 * Make sure these are in sync with the smae enum in VPP
 */
const l2_vtr_op_t l2_vtr_op_t::L2_VTR_DISABLED(0, "disabled");
const l2_vtr_op_t l2_vtr_op_t::L2_VTR_PUSH_1(1, "push-1");
const l2_vtr_op_t l2_vtr_op_t::L2_VTR_PUSH_2(2, "push-2");
const l2_vtr_op_t l2_vtr_op_t::L2_VTR_POP_1(3, "pop-1");
const l2_vtr_op_t l2_vtr_op_t::L2_VTR_POP_2(4, "pop-2");
const l2_vtr_op_t l2_vtr_op_t::L2_VTR_TRANSLATE_1_1(5, "translate-1-1");
const l2_vtr_op_t l2_vtr_op_t::L2_VTR_TRANSLATE_1_2(6, "translate-1-2");
const l2_vtr_op_t l2_vtr_op_t::L2_VTR_TRANSLATE_2_1(7, "translate-2-1");
const l2_vtr_op_t l2_vtr_op_t::L2_VTR_TRANSLATE_2_2(5, "translate-2-2");

l2_vtr_op_t::l2_vtr_op_t(int v, const std::string s)
  : enum_base<l2_vtr_op_t>(v, s)
{
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
