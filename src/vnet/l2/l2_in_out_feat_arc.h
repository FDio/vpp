/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef __included_vnet_in_out_feat_arc_h__
#define __included_vnet_in_out_feat_arc_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/classify/vnet_classify.h>

typedef enum
{
  FEAT_ARC_NEXT_INDEX_DROP,
  FEAT_ARC_NEXT_INDEX_N_NEXT,
} in_out_feat_arc_next_index_t;

typedef enum
{
  IN_OUT_FEAT_ARC_TABLE_IP4,
  IN_OUT_FEAT_ARC_TABLE_IP6,
  IN_OUT_FEAT_ARC_TABLE_L2,
  IN_OUT_FEAT_ARC_N_TABLES,
} in_out_feat_arc_table_id_t;

typedef enum
{
  IN_OUT_FEAT_ARC_INPUT_TABLE_GROUP,
  IN_OUT_FEAT_ARC_OUTPUT_TABLE_GROUP,
  IN_OUT_FEAT_ARC_N_TABLE_GROUPS
} in_out_feat_arc_table_group_id_t;

typedef struct
{
  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  vnet_classify_main_t *vnet_classify_main;
    vnet_config_main_t
    *
    vnet_config_main[IN_OUT_FEAT_ARC_N_TABLE_GROUPS]
    [IN_OUT_FEAT_ARC_N_TABLES];
} in_out_feat_arc_main_t;

int vnet_l2_feature_enable_disable (const char *arc_name,
				    const char *node_name, u32 sw_if_index,
				    int enable_disable, void *feature_config,
				    u32 n_feature_config_bytes);

extern vlib_node_registration_t l2_in_feat_arc_end_node;
extern vlib_node_registration_t l2_out_feat_arc_end_node;
extern vlib_node_registration_t l2_out_feat_arc_node;
extern vlib_node_registration_t l2_in_feat_arc_node;

#endif /* __included_vnet_in_out_feat_arc_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
