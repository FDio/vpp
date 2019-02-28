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
#include <plugins/gbp/gbp.h>
#include <vnet/l2/l2_input.h>
#include <plugins/gbp/gbp_learn.h>

/**
 * Grouping of global data for the GBP source EPG classification feature
 */
typedef struct gbp_fwd_main_t_
{
  /**
   * Next nodes for L2 output features
   */
  u32 l2_input_feat_next[32];
} gbp_fwd_main_t;

static gbp_fwd_main_t gbp_fwd_main;

gbp_policy_main_t gbp_policy_main;

void
gbp_learn_enable (u32 sw_if_index, gbb_learn_mode_t mode)
{
  if (GBP_LEARN_MODE_L2 == mode)
    {
      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_LEARN, 1);
    }
  else
    {
      vnet_feature_enable_disable ("ip4-unicast",
				   "gbp-learn-ip4", sw_if_index, 1, 0, 0);
      vnet_feature_enable_disable ("ip6-unicast",
				   "gbp-learn-ip6", sw_if_index, 1, 0, 0);
    }
}

void
gbp_learn_disable (u32 sw_if_index, gbb_learn_mode_t mode)
{
  if (GBP_LEARN_MODE_L2 == mode)
    {
      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_LEARN, 0);
    }
  else
    {
      vnet_feature_enable_disable ("ip4-unicast",
				   "gbp-learn-ip4", sw_if_index, 0, 0, 0);
      vnet_feature_enable_disable ("ip6-unicast",
				   "gbp-learn-ip6", sw_if_index, 0, 0, 0);
    }
}

static clib_error_t *
gbp_fwd_init (vlib_main_t * vm)
{
  gbp_fwd_main_t *gpm = &gbp_fwd_main;
  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) "gbp-fwd");

  /* Initialize the feature next-node indices */
  feat_bitmap_init_next_nodes (vm,
			       node->index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       gpm->l2_input_feat_next);

  return 0;
}

VLIB_INIT_FUNCTION (gbp_fwd_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
