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
 * config.c: feature configuration
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

#include <vnet/vnet.h>

static vnet_config_feature_t *
duplicate_feature_vector (vnet_config_feature_t * feature_vector)
{
  vnet_config_feature_t *result, *f;

  result = vec_dup (feature_vector);
  vec_foreach (f, result) f->feature_config = vec_dup (f->feature_config);

  return result;
}

static void
free_feature_vector (vnet_config_feature_t * feature_vector)
{
  vnet_config_feature_t *f;

  vec_foreach (f, feature_vector) vnet_config_feature_free (f);
  vec_free (feature_vector);
}

static u32
add_next (vlib_main_t * vm,
	  vnet_config_main_t * cm, u32 last_node_index, u32 this_node_index)
{
  u32 i, ni = ~0;

  if (last_node_index != ~0)
    return vlib_node_add_next (vm, last_node_index, this_node_index);

  for (i = 0; i < vec_len (cm->start_node_indices); i++)
    {
      u32 tmp;
      tmp =
	vlib_node_add_next (vm, cm->start_node_indices[i], this_node_index);
      if (ni == ~0)
	ni = tmp;
      /* Start nodes to first must agree on next indices. */
      ASSERT (ni == tmp);
    }

  return ni;
}

static vnet_config_t *
find_config_with_features (vlib_main_t * vm,
			   vnet_config_main_t * cm,
			   vnet_config_feature_t * feature_vector)
{
  u32 last_node_index = ~0;
  vnet_config_feature_t *f;
  u32 *config_string;
  uword *p;
  vnet_config_t *c;

  config_string = cm->config_string_temp;
  cm->config_string_temp = 0;
  if (config_string)
    _vec_len (config_string) = 0;

  vec_foreach (f, feature_vector)
  {
    /* Connect node graph. */
    f->next_index = add_next (vm, cm, last_node_index, f->node_index);
    last_node_index = f->node_index;

    /* Store next index in config string. */
    vec_add1 (config_string, f->next_index);

    /* Store feature config. */
    vec_add (config_string, f->feature_config, vec_len (f->feature_config));
  }

  /* Terminate config string with next for end node. */
  if (last_node_index == ~0 || last_node_index != cm->end_node_index)
    {
      u32 next_index = add_next (vm, cm, last_node_index, cm->end_node_index);
      vec_add1 (config_string, next_index);
    }

  /* See if config string is unique. */
  p = hash_get_mem (cm->config_string_hash, config_string);
  if (p)
    {
      /* Not unique.  Share existing config. */
      cm->config_string_temp = config_string;	/* we'll use it again later. */
      free_feature_vector (feature_vector);
      c = pool_elt_at_index (cm->config_pool, p[0]);
    }
  else
    {
      u32 *d;

      pool_get (cm->config_pool, c);
      c->index = c - cm->config_pool;
      c->features = feature_vector;
      c->config_string_vector = config_string;

      /* Allocate copy of config string in heap.
         VLIB buffers will maintain pointers to heap as they read out
         configuration data. */
      c->config_string_heap_index
	= heap_alloc (cm->config_string_heap, vec_len (config_string) + 1,
		      c->config_string_heap_handle);

      /* First element in heap points back to pool index. */
      d =
	vec_elt_at_index (cm->config_string_heap,
			  c->config_string_heap_index);
      d[0] = c->index;
      clib_memcpy (d + 1, config_string, vec_bytes (config_string));
      hash_set_mem (cm->config_string_hash, config_string, c->index);

      c->reference_count = 0;	/* will be incremented by caller. */
    }

  return c;
}

void
vnet_config_init (vlib_main_t * vm,
		  vnet_config_main_t * cm,
		  char *start_node_names[],
		  int n_start_node_names,
		  char *feature_node_names[], int n_feature_node_names)
{
  vlib_node_t *n;
  u32 i;

  memset (cm, 0, sizeof (cm[0]));

  cm->config_string_hash =
    hash_create_vec (0,
		     STRUCT_SIZE_OF (vnet_config_t, config_string_vector[0]),
		     sizeof (uword));

  ASSERT (n_feature_node_names >= 1);

  vec_resize (cm->start_node_indices, n_start_node_names);
  for (i = 0; i < n_start_node_names; i++)
    {
      n = vlib_get_node_by_name (vm, (u8 *) start_node_names[i]);
      /* Given node name must exist. */
      ASSERT (n != 0);
      cm->start_node_indices[i] = n->index;
    }

  vec_resize (cm->node_index_by_feature_index, n_feature_node_names);
  for (i = 0; i < n_feature_node_names; i++)
    {
      if (!feature_node_names[i])
	cm->node_index_by_feature_index[i] = ~0;
      else
	{
	  n = vlib_get_node_by_name (vm, (u8 *) feature_node_names[i]);
	  /* Given node may exist in plug-in library which is not present */
	  if (n)
	    {
	      if (i + 1 == n_feature_node_names)
		cm->end_node_index = n->index;
	      cm->node_index_by_feature_index[i] = n->index;
	    }
	  else
	    cm->node_index_by_feature_index[i] = ~0;
	}
    }
}

static void
remove_reference (vnet_config_main_t * cm, vnet_config_t * c)
{
  ASSERT (c->reference_count > 0);
  c->reference_count -= 1;
  if (c->reference_count == 0)
    {
      hash_unset (cm->config_string_hash, c->config_string_vector);
      vnet_config_free (cm, c);
      pool_put (cm->config_pool, c);
    }
}

static int
feature_cmp (void *a1, void *a2)
{
  vnet_config_feature_t *f1 = a1;
  vnet_config_feature_t *f2 = a2;

  return (int) f1->feature_index - f2->feature_index;
}

always_inline u32 *
vnet_get_config_heap (vnet_config_main_t * cm, u32 ci)
{
  return heap_elt_at_index (cm->config_string_heap, ci);
}

u32
vnet_config_add_feature (vlib_main_t * vm,
			 vnet_config_main_t * cm,
			 u32 config_string_heap_index,
			 u32 feature_index,
			 void *feature_config, u32 n_feature_config_bytes)
{
  vnet_config_t *old, *new;
  vnet_config_feature_t *new_features, *f;
  u32 n_feature_config_u32s;
  u32 node_index = vec_elt (cm->node_index_by_feature_index, feature_index);

  if (node_index == ~0)		// feature node does not exist
    return ~0;

  if (config_string_heap_index == ~0)
    {
      old = 0;
      new_features = 0;
    }
  else
    {
      u32 *p = vnet_get_config_heap (cm, config_string_heap_index);
      old = pool_elt_at_index (cm->config_pool, p[-1]);
      new_features = old->features;
      if (new_features)
	new_features = duplicate_feature_vector (new_features);
    }

  vec_add2 (new_features, f, 1);
  f->feature_index = feature_index;
  f->node_index = node_index;

  n_feature_config_u32s =
    round_pow2 (n_feature_config_bytes,
		sizeof (f->feature_config[0])) /
    sizeof (f->feature_config[0]);
  vec_add (f->feature_config, feature_config, n_feature_config_u32s);

  /* Sort (prioritize) features. */
  if (vec_len (new_features) > 1)
    vec_sort_with_function (new_features, feature_cmp);

  if (old)
    remove_reference (cm, old);

  new = find_config_with_features (vm, cm, new_features);
  new->reference_count += 1;

  /*
   * User gets pointer to config string first element
   * (which defines the pool index
   * this config string comes from).
   */
  vec_validate (cm->config_pool_index_by_user_index,
		new->config_string_heap_index + 1);
  cm->config_pool_index_by_user_index[new->config_string_heap_index + 1]
    = new - cm->config_pool;
  return new->config_string_heap_index + 1;
}

u32
vnet_config_del_feature (vlib_main_t * vm,
			 vnet_config_main_t * cm,
			 u32 config_string_heap_index,
			 u32 feature_index,
			 void *feature_config, u32 n_feature_config_bytes)
{
  vnet_config_t *old, *new;
  vnet_config_feature_t *new_features, *f;
  u32 n_feature_config_u32s;

  {
    u32 *p = vnet_get_config_heap (cm, config_string_heap_index);

    old = pool_elt_at_index (cm->config_pool, p[-1]);
  }

  n_feature_config_u32s =
    round_pow2 (n_feature_config_bytes,
		sizeof (f->feature_config[0])) /
    sizeof (f->feature_config[0]);

  /* Find feature with same index and opaque data. */
  vec_foreach (f, old->features)
  {
    if (f->feature_index == feature_index
	&& vec_len (f->feature_config) == n_feature_config_u32s
	&& (n_feature_config_u32s == 0
	    || !memcmp (f->feature_config, feature_config,
			n_feature_config_bytes)))
      break;
  }

  /* Feature not found. */
  if (f >= vec_end (old->features))
    return ~0;

  new_features = duplicate_feature_vector (old->features);
  f = new_features + (f - old->features);
  vnet_config_feature_free (f);
  vec_delete (new_features, 1, f - new_features);

  /* must remove old from config_pool now as it may be expanded and change
     memory location if the following function find_config_with_features()
     adds a new config because none of existing config's has matching features
     and so can be reused */
  remove_reference (cm, old);
  new = find_config_with_features (vm, cm, new_features);
  new->reference_count += 1;

  vec_validate (cm->config_pool_index_by_user_index,
		new->config_string_heap_index + 1);
  cm->config_pool_index_by_user_index[new->config_string_heap_index + 1]
    = new - cm->config_pool;
  return new->config_string_heap_index + 1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
