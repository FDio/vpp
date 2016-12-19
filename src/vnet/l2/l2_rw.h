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

/*
 * l2_rw is based on vnet classifier and provides a way
 * to modify packets matching a given table.
 *
 * Tables must be created using vnet's classify features.
 * Entries contained within these tables must have their
 * opaque index set to the rewrite entry created with l2_rw_mod_entry.
 */

#ifndef L2_RW_H_
#define L2_RW_H_

#include <vnet/l2/l2_input.h>

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct _l2_rw_entry {
  u16 skip_n_vectors;
  u16 rewrite_n_vectors;
  u64 hit_count;
  u32x4 *mask;
  u32x4 *value;
}) l2_rw_entry_t;
/* *INDENT-ON* */

/* l2_rw configuration for one interface */
/* *INDENT-OFF* */
typedef CLIB_PACKED(struct _l2_rw_config {
  u32 table_index; /* Which classify table to use */
  u32 miss_index;  /* Rewrite entry to use if table does not match */
}) l2_rw_config_t;
/* *INDENT-ON* */

typedef struct
{
  /* Next feature node indexes */
  u32 feat_next_node_index[32];

  /* A pool of entries */
  l2_rw_entry_t *entries;

  /* Config vector indexed by sw_if_index */
  l2_rw_config_t *configs;
  uword *configs_bitmap;
} l2_rw_main_t;

extern l2_rw_main_t l2_rw_main;

/*
 * Specifies which classify table and miss_index should be used
 * with the given interface.
 * Use special values ~0 in order to un-set table_index
 * or miss_index.
 * l2_rw feature is automatically enabled for the interface
 * when table_index or miss_index is not ~0.
 * returns 0 on success and something else on error.
 */
int l2_rw_interface_set_table (u32 sw_if_index,
			       u32 table_index, u32 miss_index);

/*
 * Creates, modifies or delete a rewrite entry.
 * If *index != ~0, modifies an existing entry (or simply
 * deletes it if is_del is set).
 * If *index == ~0, creates a new entry and the created
 * entry index is stored in *index (Does nothing if is_del
 * is set).
 * returns 0 on success and something else on error.
 */
int l2_rw_mod_entry (u32 * index,
		     u8 * mask, u8 * value, u32 len, u32 skip, u8 is_del);

#endif /* L2_FW_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
