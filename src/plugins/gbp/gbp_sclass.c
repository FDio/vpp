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

#include <plugins/gbp/gbp_sclass.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>

gbp_sclass_main_t gbp_sclass_main;

void
gbp_sclass_enable_l2 (u32 sw_if_index)
{
  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_SCLASS_2_ID, 1);
  l2output_intf_bitmap_enable (sw_if_index, L2OUTPUT_FEAT_GBP_ID_2_SCLASS, 1);
}

void
gbp_sclass_disable_l2 (u32 sw_if_index)
{
  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_SCLASS_2_ID, 0);
  l2output_intf_bitmap_enable (sw_if_index, L2OUTPUT_FEAT_GBP_ID_2_SCLASS, 0);
}

void
gbp_sclass_enable_ip (u32 sw_if_index)
{
  vnet_feature_enable_disable ("ip4-unicast",
			       "ip4-gbp-sclass-2-id", sw_if_index, 1, 0, 0);
  vnet_feature_enable_disable ("ip6-unicast",
			       "ip6-gbp-sclass-2-id", sw_if_index, 1, 0, 0);
  vnet_feature_enable_disable ("ip4-output",
			       "ip4-gbp-id-2-sclass", sw_if_index, 1, 0, 0);
  vnet_feature_enable_disable ("ip6-output",
			       "ip6-gbp-id-2-sclass", sw_if_index, 1, 0, 0);
}

void
gbp_sclass_disable_ip (u32 sw_if_index)
{
  vnet_feature_enable_disable ("ip4-unicast",
			       "ip4-gbp-sclass-2-id", sw_if_index, 0, 0, 0);
  vnet_feature_enable_disable ("ip6-unicast",
			       "ip6-gbp-sclass-2-id", sw_if_index, 0, 0, 0);
  vnet_feature_enable_disable ("ip4-output",
			       "ip4-gbp-id-2-sclass", sw_if_index, 0, 0, 0);
  vnet_feature_enable_disable ("ip6-output",
			       "ip6-gbp-id-2-sclass", sw_if_index, 0, 0, 0);
}

static clib_error_t *
gbp_sclass_init (vlib_main_t * vm)
{
  gbp_sclass_main_t *glm = &gbp_sclass_main;
  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) "l2-gbp-sclass-2-id");

  /* Initialize the feature next-node indices */
  feat_bitmap_init_next_nodes (vm,
			       node->index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       glm->gel_l2_input_feat_next);

  node = vlib_get_node_by_name (vm, (u8 *) "l2-gbp-id-2-sclass");
  feat_bitmap_init_next_nodes (vm,
			       node->index,
			       L2OUTPUT_N_FEAT,
			       l2output_get_feat_names (),
			       glm->gel_l2_output_feat_next);

  return (NULL);
}

VLIB_INIT_FUNCTION (gbp_sclass_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
