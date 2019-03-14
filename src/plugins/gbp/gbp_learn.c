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

#include <plugins/gbp/gbp.h>
#include <plugins/gbp/gbp_learn.h>
#include <plugins/gbp/gbp_bridge_domain.h>

#include <vnet/l2/l2_input.h>

gbp_learn_main_t gbp_learn_main;

void
gbp_learn_enable_disable (u32 sw_if_index, gbp_learn_mode_t mode,
			  int enable_disable)
{
  switch (mode)
    {
    case GBP_LEARN_MODE_NONE:
      break;
    case GBP_LEARN_MODE_L2_ONLY:
      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_LEARN_L2_ONLY,
				  enable_disable);
      break;
    case GBP_LEARN_MODE_L3_ONLY:
      vnet_feature_enable_disable ("ip4-unicast",
				   "gbp-learn-ip4", sw_if_index,
				   enable_disable, 0, 0);
      vnet_feature_enable_disable ("ip6-unicast", "gbp-learn-ip6",
				   sw_if_index, enable_disable, 0, 0);
      break;
    case GBP_LEARN_MODE_L2_AND_L3:
      l2input_intf_bitmap_enable (sw_if_index,
				  L2INPUT_FEAT_GBP_LEARN_L2_AND_L3,
				  enable_disable);
      break;
    }
}

static void
gbp_l2_feat_init (vlib_main_t * vm, u32 * l2_input_feat_next,
		  const char *node_name)
{
  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) node_name);
  feat_bitmap_init_next_nodes (vm,
			       node->index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (), l2_input_feat_next);
}

static clib_error_t *
gbp_learn_init (vlib_main_t * vm)
{
  gbp_learn_main_t *glm = &gbp_learn_main;
  vlib_thread_main_t *tm = &vlib_thread_main;

  /* Initialize the feature next-node indices */
  gbp_l2_feat_init (vm, glm->gl_l2_and_l3_input_feat_next,
		    "gbp-learn-l2-and-l3");
  gbp_l2_feat_init (vm, glm->gl_l2_only_input_feat_next, "gbp-learn-l2-only");

  throttle_init (&glm->gl_l2_throttle,
		 tm->n_vlib_mains, GBP_ENDPOINT_HASH_LEARN_RATE);

  throttle_init (&glm->gl_l3_throttle,
		 tm->n_vlib_mains, GBP_ENDPOINT_HASH_LEARN_RATE);

  glm->gl_logger = vlib_log_register_class ("gbp", "learn");

  return 0;
}

VLIB_INIT_FUNCTION (gbp_learn_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
