/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef __FILTER_HOOK_H__
#define __FILTER_HOOK_H__

#include <filter/filter_list.h>

/**
 * A hook represents an attachment of the filter system into the switch path.
 * There are several places this can haapen defined by the hook type.
 * At each hook several tables can provide several chains to be traversed.
 */
typedef struct filter_hook_t_
{
  /**
   * graph linkage
   */
  filter_node_t ft_node;

  /**
   * name of the hook
   */
  filter_hook_type_t fh_hook;

  dpo_proto_t fh_proto;

  struct filter_list_t_ *fh_tables1;
} filter_hook_t;


extern void filter_hook_table_add (dpo_proto_t dproto,
				   filter_hook_type_t fht, index_t fti);
extern void filter_hook_update (dpo_proto_t dproto, filter_hook_type_t fht);
extern void filter_hook_table_remove (dpo_proto_t dproto,
				      filter_hook_type_t fht, index_t fti);

/**
 * For the data-plane the nodes that start the traversal at the given hook
 */
extern dpo_id_t filter_hook_roots[DPO_PROTO_NUM][FILTER_N_BASE_HOOKS];

always_inline const dpo_id_t *
filter_hook_root_get (dpo_proto_t dproto, filter_hook_type_t fht)
{
  return (&filter_hook_roots[dproto][fht]);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
