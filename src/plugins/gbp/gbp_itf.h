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

#ifndef __GBP_INTERFACE_H__
#define __GBP_INTERFACE_H__

#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>

extern index_t gbp_itf_add_and_lock (u32 sw_if_index, u32 bd_index);
extern void gbp_itf_unlock (index_t index);

extern void gbp_itf_set_l2_input_feature (index_t gii,
					  index_t useri,
					  l2input_feat_masks_t feats);
extern void gbp_itf_set_l2_output_feature (index_t gii,
					   index_t useri,
					   l2output_feat_masks_t feats);

extern u8 *format_gbp_itf (u8 * s, va_list * args);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
