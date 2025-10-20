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
 * config.h: feature configuration
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_vnet_config_h
#define included_vnet_config_h

#include <vlib/vlib.h>
#include <vppinfra/heap.h>

typedef struct
{
  /* Features are prioritized by index.  Smaller indices get
     performed first. */
  u32 feature_index;

  /* VLIB node which performs feature. */
  u32 node_index;

  /* Next index relative to previous node or main node. */
  u32 next_index;

  /* Opaque per feature configuration data. */
  u32 *feature_config;
} vnet_config_feature_t;

always_inline void
vnet_config_feature_free (vnet_config_feature_t * f)
{
  vec_free (f->feature_config);
}

typedef struct
{
  /* Sorted vector of features for this configuration. */
  vnet_config_feature_t *features;

  /* Config string as vector for hashing. */
  u32 *config_string_vector;

  /* Config string including all next indices and feature data as a vector. */
  u32 config_string_heap_index, config_string_heap_handle;

  /* Index in main pool. */
  u32 index;

  /* Number of interfaces/traffic classes that reference this config. */
  u32 reference_count;
} vnet_config_t;

typedef struct
{
  /* Pool of configs.  Index 0 is always null config and is never deleted. */
  vnet_config_t *config_pool;

  /* Hash table mapping vector config string to config pool index. */
  uword *config_string_hash;

  /* Global heap of configuration data. */
  u32 *config_string_heap;

  /* Node index which starts/ends feature processing. */
  u32 *start_node_indices, *end_node_indices_by_user_index,
    default_end_node_index;

  /* Interior feature processing nodes (not including start and end nodes). */
  u32 *node_index_by_feature_index;

  /* vnet_config pool index by user index */
  u32 *config_pool_index_by_user_index;

  /* Temporary vector for holding config strings.  Used to avoid continually
     allocating vectors. */
  u32 *config_string_temp;
} vnet_config_main_t;

always_inline void
vnet_config_free (vnet_config_main_t * cm, vnet_config_t * c)
{
  vnet_config_feature_t *f;
  vec_foreach (f, c->features) vnet_config_feature_free (f);
  vec_free (c->features);
  heap_dealloc (cm->config_string_heap, c->config_string_heap_handle);
  vec_free (c->config_string_vector);
}

always_inline void *
vnet_get_config_data (vnet_config_main_t * cm,
		      u32 * config_index, u32 * next_index, u32 n_data_bytes)
{
  u32 i, n, *d;

  i = *config_index;

  d = heap_elt_at_index (cm->config_string_heap, i);

  n = round_pow2 (n_data_bytes, sizeof (d[0])) / sizeof (d[0]);

  /* Last 32 bits are next index. */
  *next_index = d[n];

  /* Advance config index to next config. */
  *config_index = (i + n + 1);

  /* Return config data to user for this feature. */
  return (void *) d;
}

always_inline void *
vnet_get_config_data_next16 (vnet_config_main_t *cm, u32 *config_index,
			     u16 *next_index, u32 n_data_bytes)
{
  u32 ni;
  void *rv = vnet_get_config_data (cm, config_index, &ni, n_data_bytes);
  *next_index = (u16) ni;
  return rv;
}

void vnet_config_init (vlib_main_t * vm,
		       vnet_config_main_t * cm,
		       char *start_node_names[],
		       int n_start_node_names,
		       char *feature_node_names[], int n_feature_node_names);

void vnet_config_del (vnet_config_main_t * cm, u32 config_id);

/* Calls to add/delete features from configurations. */
u32 vnet_config_add_feature (vlib_main_t * vm,
			     vnet_config_main_t * cm,
			     u32 config_id,
			     u32 feature_index,
			     void *feature_config,
			     u32 n_feature_config_bytes);

u32 vnet_config_del_feature (vlib_main_t * vm,
			     vnet_config_main_t * cm,
			     u32 config_id,
			     u32 feature_index,
			     void *feature_config,
			     u32 n_feature_config_bytes);

u32 vnet_config_modify_end_node (vlib_main_t * vm,
				 vnet_config_main_t * cm,
				 u32 config_string_heap_index,
				 u32 end_node_index);

u32 vnet_config_reset_end_node (vlib_main_t *vm, vnet_config_main_t *cm,
				u32 config_string_heap_index);

u32 vnet_config_get_end_node (vlib_main_t *vm, vnet_config_main_t *cm,
			      u32 config_string_heap_index);

u8 *vnet_config_format_features (vlib_main_t * vm,
				 vnet_config_main_t * cm,
				 u32 config_index, u8 * s);

#endif /* included_vnet_config_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
