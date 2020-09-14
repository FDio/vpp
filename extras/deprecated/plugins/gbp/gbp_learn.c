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
gbp_learn_enable (u32 sw_if_index)
{
  vnet_feature_enable_disable ("ip4-unicast",
			       "gbp-learn-ip4", sw_if_index, 1, 0, 0);
  vnet_feature_enable_disable ("ip6-unicast",
			       "gbp-learn-ip6", sw_if_index, 1, 0, 0);
}

void
gbp_learn_disable (u32 sw_if_index)
{
  vnet_feature_enable_disable ("ip4-unicast",
			       "gbp-learn-ip4", sw_if_index, 0, 0, 0);
  vnet_feature_enable_disable ("ip6-unicast",
			       "gbp-learn-ip6", sw_if_index, 0, 0, 0);
}

static clib_error_t *
gbp_learn_init (vlib_main_t * vm)
{
  gbp_learn_main_t *glm = &gbp_learn_main;
  vlib_thread_main_t *tm = &vlib_thread_main;

  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) "gbp-learn-l2");

  /* Initialize the feature next-node indices */
  feat_bitmap_init_next_nodes (vm,
			       node->index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       glm->gl_l2_input_feat_next);

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
