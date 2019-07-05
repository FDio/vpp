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


#define foreach_gdb_l3_feature                  \
  _(LEARN_IP4, "gbp-learn-ip4", "ip4-unicast") \
  _(LEARN_IP6, "gbp-learn-ip6", "ip6-unicast")

typedef enum gbp_itf_l3_feat_pos_t_
{
#define _(s,v,a) GBP_ITF_L3_FEAT_POS_##s,
  foreach_gdb_l3_feature
#undef _
} gbp_itf_l3_feat_pos_t;

typedef enum gbp_itf_l3_feat_t_
{
  GBP_ITF_L3_FEAT_NONE,
#define _(s,v,a) GBP_ITF_L3_FEAT_##s = (1 << GBP_ITF_L3_FEAT_POS_##s),
  foreach_gdb_l3_feature
#undef _
} gbp_itf_l3_feat_t;

#define GBP_ITF_L3_FEAT_LEARN (GBP_ITF_L3_FEAT_LEARN_IP4|GBP_ITF_L3_FEAT_LEARN_IP6)

typedef struct gbp_itf_hdl_t_
{
  union
  {
    struct
    {
      u32 gh_who;
      u32 gh_which;
    };
  };
} gbp_itf_hdl_t;

#define GBP_ITF_HDL_INIT {.gh_which = ~0}
const static gbp_itf_hdl_t GBP_ITF_HDL_INVALID = GBP_ITF_HDL_INIT;

extern void gbp_itf_hdl_reset (gbp_itf_hdl_t * gh);
extern bool gbp_itf_hdl_is_valid (gbp_itf_hdl_t gh);

typedef void (*gbp_itf_free_fn_t) (u32 sw_if_index);

extern gbp_itf_hdl_t gbp_itf_l2_add_and_lock (u32 sw_if_index, u32 bd_index);
extern gbp_itf_hdl_t gbp_itf_l3_add_and_lock (u32 sw_if_index, index_t gri);
extern gbp_itf_hdl_t gbp_itf_l2_add_and_lock_w_free (u32 sw_if_index,
						     u32 bd_index,
						     gbp_itf_free_fn_t ff);
extern gbp_itf_hdl_t gbp_itf_l3_add_and_lock_w_free (u32 sw_if_index,
						     index_t gri,
						     gbp_itf_free_fn_t ff);

extern void gbp_itf_unlock (gbp_itf_hdl_t * hdl);
extern void gbp_itf_lock (gbp_itf_hdl_t hdl);
extern gbp_itf_hdl_t gbp_itf_clone_and_lock (gbp_itf_hdl_t hdl);
extern u32 gbp_itf_get_sw_if_index (gbp_itf_hdl_t hdl);

extern void gbp_itf_l2_set_input_feature (gbp_itf_hdl_t hdl,
					  l2input_feat_masks_t feats);
extern void gbp_itf_l2_set_output_feature (gbp_itf_hdl_t hdl,
					   l2output_feat_masks_t feats);

extern void gbp_itf_l3_set_input_feature (gbp_itf_hdl_t hdl,
					  gbp_itf_l3_feat_t feats);

extern u8 *format_gbp_itf_hdl (u8 * s, va_list * args);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
