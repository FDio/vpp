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

#ifndef __included_vnet_input_acl_h__
#define __included_vnet_input_acl_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/classify/vnet_classify.h>

typedef enum
{
  INPUT_ACL_TABLE_IP4,
  INPUT_ACL_TABLE_IP6,
  INPUT_ACL_TABLE_L2,
  INPUT_ACL_N_TABLES,
} input_acl_table_id_t;

typedef enum
{
  ACL_NEXT_INDEX_DENY,
  ACL_NEXT_INDEX_N_NEXT,
} acl_next_index_t;

typedef struct
{

  /* classifier table vectors */
  u32 *classify_table_index_by_sw_if_index[INPUT_ACL_N_TABLES];

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  vnet_classify_main_t *vnet_classify_main;
  vnet_config_main_t *vnet_config_main[INPUT_ACL_N_TABLES];
} input_acl_main_t;

extern input_acl_main_t input_acl_main;

int vnet_set_input_acl_intfc (vlib_main_t * vm, u32 sw_if_index,
			      u32 ip4_table_index,
			      u32 ip6_table_index,
			      u32 l2_table_index, u32 is_add);

#endif /* __included_vnet_input_acl_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
