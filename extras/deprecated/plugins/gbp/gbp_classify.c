/*
 * gbp.h : Group Based Policy
 *
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
#include <plugins/gbp/gbp_classify.h>
#include <vnet/l2/l2_input.h>

gbp_src_classify_main_t gbp_src_classify_main;

static clib_error_t *
gbp_src_classify_init (vlib_main_t * vm)
{
  gbp_src_classify_main_t *em = &gbp_src_classify_main;

  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) "gbp-src-classify");

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       node->index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       em->l2_input_feat_next[GBP_SRC_CLASSIFY_NULL]);

  node = vlib_get_node_by_name (vm, (u8 *) "gbp-null-classify");
  feat_bitmap_init_next_nodes (vm,
			       node->index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       em->l2_input_feat_next[GBP_SRC_CLASSIFY_PORT]);

  node = vlib_get_node_by_name (vm, (u8 *) "l2-gbp-lpm-classify");
  feat_bitmap_init_next_nodes (vm,
			       node->index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       em->l2_input_feat_next[GBP_SRC_CLASSIFY_LPM]);

  node = vlib_get_node_by_name (vm, (u8 *) "l2-gbp-lpm-anon-classify");
  feat_bitmap_init_next_nodes (vm,
			       node->index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       em->l2_input_feat_next
			       [GBP_SRC_CLASSIFY_LPM_ANON]);

  return 0;
}

VLIB_INIT_FUNCTION (gbp_src_classify_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
