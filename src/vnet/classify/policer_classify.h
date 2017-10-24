/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef __included_vnet_policer_classify_h__
#define __included_vnet_policer_classify_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/classify/vnet_classify.h>

typedef enum {
  POLICER_CLASSIFY_TABLE_IP4,
  POLICER_CLASSIFY_TABLE_IP6,
  POLICER_CLASSIFY_TABLE_L2,
  POLICER_CLASSIFY_N_TABLES,
} policer_classify_table_id_t;

typedef enum {
  POLICER_CLASSIFY_NEXT_INDEX_DROP,
  POLICER_CLASSIFY_NEXT_INDEX_N_NEXT,
} policer_classify_next_index_t;

typedef struct {
  /* Classifier table vectors */
  u32 * classify_table_index_by_sw_if_index [POLICER_CLASSIFY_N_TABLES];

  /* L2 next nodes for each feature */
  u32 feat_next_node_index[32];

  /* Convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  vnet_classify_main_t * vnet_classify_main;
  vnet_config_main_t * vnet_config_main [POLICER_CLASSIFY_N_TABLES];
} policer_classify_main_t;

extern policer_classify_main_t policer_classify_main;

int vnet_set_policer_classify_intfc (vlib_main_t * vm, u32 sw_if_index,
                                     u32 ip4_table_index, u32 ip6_table_index,
                                     u32 l2_table_index, u32 is_add);

#endif /* __included_vnet_policer_classify_h__ */
