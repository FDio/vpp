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

#include <stdbool.h>
#include <vnet/vnet.h>

#undef CONFIG_DEBUG_FEAT_CFG_STR

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
			   vnet_config_feature_t * feature_vector,
			   u32 end_node_index)
{
  u32 last_node_index = ~0;
  vnet_config_feature_t *f;
  u32 *config_string;
  uword *p;
  vnet_config_t *c;

  config_string = cm->config_string_temp;
  cm->config_string_temp = 0;
  if (config_string)
    vec_set_len (config_string, 0);

#if FEATURE_CFG_EMBED_LENGTH
  /*
   * Feature data length is always 0 for first feature.
   * Add this field even if feature_vector is empty.
   */
  vec_add1 (config_string, 0);
#endif

  vec_foreach (f, feature_vector)
  {
    /* Connect node graph. */
    f->next_index = add_next (vm, cm, last_node_index, f->node_index);
    last_node_index = f->node_index;

    /* Store next index in config string. */
    vec_add1 (config_string, f->next_index);

#if FEATURE_CFG_EMBED_LENGTH
    /* Store length (number of u32s) of feature_config */
    vec_add1(config_string, (u32)vec_len (f->feature_config));
#endif

    /* Store feature config. */
    vec_add (config_string, f->feature_config, vec_len (f->feature_config));
  }

  /* Terminate config string with next for end node. */
  if (last_node_index == ~0 || last_node_index != end_node_index)
    {
      u32 next_index = add_next (vm, cm, last_node_index, end_node_index);
      vec_add1 (config_string, next_index);
    }

  /* Add the end node index to the config string so that it is part of
   * the key used to detect string sharing. If this is not included then
   * a modification of the end node would affect all the user of a shared
   * string. */
  vec_add1 (config_string, end_node_index);

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

      vec_validate_init_empty (cm->end_node_indices_by_user_index,
			       c->config_string_heap_index + 1,
			       cm->default_end_node_index);
      cm->end_node_indices_by_user_index[c->config_string_heap_index + 1]
	= end_node_index;
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

  clib_memset (cm, 0, sizeof (cm[0]));

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
		cm->default_end_node_index = n->index;
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

void
vnet_config_del (vnet_config_main_t * cm, u32 config_id)
{
  u32 *p = vnet_get_config_heap (cm, config_id);
  vnet_config_t *old = pool_elt_at_index (cm->config_pool, p[-1]);
  remove_reference (cm, old);
}

u32
vnet_config_reset_end_node (vlib_main_t *vm, vnet_config_main_t *cm, u32 ci)
{
  cm->end_node_indices_by_user_index[ci] = cm->default_end_node_index;

  return (
    vnet_config_modify_end_node (vm, cm, ci, cm->default_end_node_index));
}

u32
vnet_config_modify_end_node (vlib_main_t * vm,
			     vnet_config_main_t * cm,
			     u32 config_string_heap_index, u32 end_node_index)
{
  vnet_config_feature_t *new_features;
  vnet_config_t *old, *new;

  if (end_node_index == ~0)	// feature node does not exist
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

  if (vec_len (new_features))
    {
      /* is the last feature the cuurent end node */
      u32 last = vec_len (new_features) - 1;
      if (new_features[last].node_index == cm->default_end_node_index)
	{
	  vec_free (new_features->feature_config);
	  vec_set_len (new_features, last);
	}
    }

  if (old)
    remove_reference (cm, old);

  new = find_config_with_features (vm, cm, new_features, end_node_index);
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
vnet_config_get_end_node (vlib_main_t *vm, vnet_config_main_t *cm,
			  u32 config_string_heap_index)
{
  if (config_string_heap_index >= vec_len (cm->end_node_indices_by_user_index))
    return cm->default_end_node_index;
  if (~0 == cm->end_node_indices_by_user_index[config_string_heap_index])
    return cm->default_end_node_index;

  return (cm->end_node_indices_by_user_index[config_string_heap_index]);
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
  u32 n_feature_config_u32s, end_node_index;
  u32 node_index = vec_elt (cm->node_index_by_feature_index, feature_index);

  if (node_index == ~0)		// feature node does not exist
    return ~0;

  if (config_string_heap_index == ~0)
    {
      old = 0;
      new_features = 0;
      end_node_index = cm->default_end_node_index;
    }
  else
    {
      u32 *p = vnet_get_config_heap (cm, config_string_heap_index);
      old = pool_elt_at_index (cm->config_pool, p[-1]);
      new_features = old->features;
      end_node_index =
	cm->end_node_indices_by_user_index[config_string_heap_index];
      if (new_features)
	new_features = duplicate_feature_vector (new_features);
    }

  vec_add2 (new_features, f, 1);
  f->feature_index = feature_index;
  f->node_index = node_index;

  if (n_feature_config_bytes)
    {
      n_feature_config_u32s =
	round_pow2 (n_feature_config_bytes,
		    sizeof (f->feature_config[0])) /
	sizeof (f->feature_config[0]);
      vec_validate (f->feature_config, n_feature_config_u32s - 1);
      clib_memcpy_fast (f->feature_config, feature_config,
			n_feature_config_bytes);
    }

  /* Sort (prioritize) features. */
  if (vec_len (new_features) > 1)
    vec_sort_with_function (new_features, feature_cmp);

  if (old)
    remove_reference (cm, old);

  new = find_config_with_features (vm, cm, new_features, end_node_index);
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

#ifdef CONFIG_DEBUG_FEAT_CFG_STR
  clib_warning("\n  Config string: %U",
    format_vnet_feature_config_string_detailed, cm, new);
#endif

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
  new = find_config_with_features (vm, cm, new_features,
				   cm->end_node_indices_by_user_index
				   [config_string_heap_index]);
  new->reference_count += 1;

  vec_validate (cm->config_pool_index_by_user_index,
		new->config_string_heap_index + 1);
  cm->config_pool_index_by_user_index[new->config_string_heap_index + 1]
    = new - cm->config_pool;

#ifdef CONFIG_DEBUG_FEAT_CFG_STR
  clib_warning("\n  Config string: %U",
    format_vnet_feature_config_string_detailed, cm, new);
#endif

  return new->config_string_heap_index + 1;
}

/*
 * Feature config strings
 *
 * A Feature Config String (hereafter called "FCS") is a simple
 * program that encodes the steering of a packet through a feature
 * arc along with optional data for each node in the arc.
 *
 * FCSs are built by find_config_with_features() and are
 * processed by vnet_get_config_data(). Each packet maintains
 * an index into the config string, which is advanced as
 * the packet moves along the arc.
 *
 * An FCS is a vector of u32 elements. It is structured like this:
 *
 *    c->index
 *    length_cfg_u32s_0  <-- always 0
 *    [optional config bytes, feat_0 (ALWAYS EMPTY)]
 *    next_index_0
 *    length_cfg_u32s_1
 *    [optional config bytes, feat_1]
 *    next_index_1
 *        .
 *        .
 *        .
 *    length_cfg_u32s_end
 *    [optional config bytes, feat_end]
 *    next_index_end_node <-- not always present
 *    end_node index      <-- hashing distinguisher
 *
 * The first vector element contains an index into the config_pool
 * for the allocated string. It is not used during arc processing.
 *
 * Next, each feature on the arc is represented by a set of
 * vector elements, consisting of a one-element length, a variable-
 * length set of feature data, and a next_index. The next_index
 * is a small index into the feature node's "next" array.
 *
 * Finally, the string is terminated with the absolute node index
 * of the arc's terminating node, for hashing purposes.
 *
 * There are a few quirks:
 *
 * The jumping-off points on the node graph into the feature arc
 * are maintained in the vector cm->start_node_indices. Thus an
 * arc can be entered from multiple nodes. There is a constraint
 * that the node index of initial node in the arc must be stored
 * at the same next_index for each of the start nodes, which is
 * enforced by an ASSERT in add_next().
 *
 * The next_index in the first "frame" of the FCS (next_index_0
 * above) is in the context of each of the start nodes. The next_index
 * values in the remaining "frames" of the FCS are in the contexts
 * of their respective nodes.
 *
 * A feature configuration also maintains an end_node_index which
 * indicates where packets should go when they are done transiting
 * the arc.
 *
 * The last "frame" in the FCS is often incomplete. Due to the way
 * find_config_with_features() builds the FCS, the node of the
 * last configured feature in the arc is referenced by the next_index
 * of the penultimate frame in the FCS. If that last configured feature
 * node is actually the node referenced by end_node_index, i.e., the
 * exit point from the arc back into the general node graph, then
 * steering is finished after the penultimate frame is processed,
 * so no final next_index is added.
 *
 * However, if the last configured feature does NOT match end_node_index,
 * a next_index is added to the final frame of the FCS that points to
 * the end_node_index node.
 */

static u8 *
_format_vnet_feature_config_string_simple(
  u8 *s, 
  vnet_config_main_t *cm,
  vnet_config_t *c)
{
  u32 *d;
  u32 *dc = NULL;
  uword len;
  int i;
  u8 *rs;
  u32 poolidx;

  d = vec_elt_at_index (cm->config_string_heap,
			c->config_string_heap_index);
  len = heap_len(cm->config_string_heap,
		 c->config_string_heap_handle);

  /*
   * The length value printed here includes the pool index
   */
  rs = format(s, "[len=%u", len);
  if (len < 1) {
    rs = format(rs, "]");
    goto done;
  }

  /* First element is pool index */
  poolidx = d[0];

  /*
   * Set up a vector (having the correct length) with the rest of
   * the elements (i.e., those referenced by "user index")
   */
  for (i = 1; i < len; ++i) {
    vec_add1(dc, d[i]);
  }
  rs = format(s, ",poolidx=%u] %U", poolidx, format_vec32, dc, "0x%x");
  vec_free(dc);

done:
  return rs;
}

/*
 * vnet_config_main_t *cm;
 * vnet_config_t *c;
 *
 * format(s, "%U", format_vnet_feature_config_string_simple, cm, c);
 */
u8 *
format_vnet_feature_config_string_simple (u8 *s, va_list * args)
{
  vnet_config_main_t *cm = va_arg (*args, vnet_config_main_t *);
  vnet_config_t *c = va_arg (*args, vnet_config_t *);

  return _format_vnet_feature_config_string_simple(s, cm, c);

}

#if FEATURE_CFG_EMBED_LENGTH

/*
 * Side effect: updates basis_node_indices
 */
static u8*
_format_frame_detail(
  u8		*s,
  u32		indent,
  int		frame_number,
  u32		**pBasisNodeIndices,	/* vector, IN/OUT */
  u32		*feature_data,		/* vector */
  u32		next_index,
  bool		next_index_valid)
{
  vlib_main_t *vm = vlib_get_main();
  u32 *bi;
  u32 *new_basis_node_indices = NULL;

  s = format(s, "%U---- start of frame number %d:\n",
    format_white_space, indent, frame_number);

  s = format(s, "%Ufeature data (u32, count=%u): %U\n",
    format_white_space, indent, vec_len(feature_data),
    format_vec32, feature_data, "0x%x");


  if (next_index_valid) {
    s = format(s, "%Unext_index: %u\n", format_white_space, indent,
      next_index);

    /* look up in prev node's next array */
    vec_foreach(bi, *pBasisNodeIndices) {
      vlib_node_t *bn = vlib_get_node(vm, bi[0]);
      vlib_node_t *nn = NULL;

      if (next_index < vec_len(bn->next_nodes)) {
	u32 found;

	nn = vlib_get_next_node(vm, bi[0], next_index);
	found = vec_search(new_basis_node_indices, nn->index);
	if (found == ~0)
	  vec_add1(new_basis_node_indices, nn->index);
      }

      s = format(s, "%U%v->next[%u] = ", format_white_space, indent,
	bn->name, next_index);
      if (nn)
	s = format(s, "%u (%v)\n", nn->index, nn->name);
      else
	s = format(s, "??\n");
    }
  } else {
    s = format(s, "%Unext_index: NOT PRESENT\n", format_white_space, indent);
  }
  vec_free(*pBasisNodeIndices);
  *pBasisNodeIndices = new_basis_node_indices;

  s = format(s, "%U---- end of frame number %d\n",
    format_white_space, indent, frame_number);

  return s;
}


/*
 * Parse frame. Returns nonzero if insufficient elements.
 *
 * d[0]	feature data length
 * ...	feature data
 * d[N]	next_index from previous node
 *
 * Advances pD to start of next frame
 */
static int
_parse_frame(
  uword			*pRemaining,		/* nr. of elements */
  u32			**pD,			/* start of frame */
  u32			**pFeatureData,		/* vector, caller must free */
  u32			*pNextIndex)
{
  u32 *feature_data = NULL;
  u32 fdlen;
  u32 i;

  if (*pRemaining < 1)
    return -1;

  fdlen = (*pD)[0];

  if (*pRemaining < (1 + fdlen + 1))
    return -1;

  for (i = 0; i < fdlen; ++i)
    vec_add1(feature_data, (*pD)[1 + i]);

  *pFeatureData = feature_data;
  *pNextIndex = (*pD)[1 + fdlen];
  *pD += 1 + fdlen + 1;

  *pRemaining -= 1 + fdlen + 1;

  return 0;
}


static u8 *
_format_vnet_feature_config_string_detailed (u8 *s, va_list * args)
{
  vnet_config_main_t *cm = va_arg (*args, vnet_config_main_t *);
  vnet_config_t *c = va_arg (*args, vnet_config_t *);
  u32 *d;
  uword remaining;
  u32 indent = 0;
  u32 *basis_node_indices = NULL;
  u32 end_node_index = ~0;
  int frame_number = 0;

  s = _format_vnet_feature_config_string_simple(s, cm, c);
  s = format(s, "\n");

  d = vec_elt_at_index (cm->config_string_heap,
			c->config_string_heap_index);
  remaining = heap_len(cm->config_string_heap,
		 c->config_string_heap_handle);

  indent += 2;

  if (remaining < 1)
    return format(s, "%U<0-length config string>\n", format_white_space, indent);

  s = format(s, "%Upool index: %u", format_white_space, indent, d[0]);
  if (d[0] != c->index) {
    s = format(s, " *** disagrees with c->index %u", c->index);
  }
  s = format(s, "\n");

  ++d, --remaining;

  if (remaining < 1)
    return format(s, "%U<no frames present>\n", format_white_space, indent);

  /*
   * initialize for first frame handling.
   */
  basis_node_indices = vec_dup(cm->start_node_indices);

  while (remaining) {
    u32 *feature_data = NULL; /* vec */
    u32 next_index;
    int rc;
    bool next_index_valid;

    /*
     * Check if this is the last frame
     */
    next_index_valid = true;
    rc = _parse_frame(&remaining, &d, &feature_data, &next_index);
    if (rc) {
      s = format(s, "Error: _parse_frame failed\n");
      vec_free(basis_node_indices);
      return s;
    }
    if (remaining == 0) {
      /*
       * This was last frame and the returned next_index is
       * actually the end_node_index.
       */
      next_index_valid = false;
      end_node_index = next_index;
    }

    s = _format_frame_detail(s, indent, frame_number, &basis_node_indices,
      feature_data, next_index, next_index_valid);

    ++frame_number;
    vec_free(feature_data);

    if (remaining == 1) {
      /*
       * tail after last frame contains just end_node_index
       */
      end_node_index = d[0];
      break;
    }
  }
  vec_free(basis_node_indices);
  s = format(s, "%UEnd node index: ", format_white_space, indent);
  if (end_node_index == ~0)
    s = format(s, "??\n");
  else
    s = format(s, "0x%x=%u\n", end_node_index, end_node_index);

  return s;
}

#endif

/*
 * vnet_config_main_t *cm;
 * vnet_config_t *c;
 *
 * format(s, "%U", format_vnet_feature_config_string_detailed, cm, c);
 */
u8 *
format_vnet_feature_config_string_detailed (u8 *s, va_list * args)
{
#if FEATURE_CFG_EMBED_LENGTH
  return _format_vnet_feature_config_string_detailed(s, args);
#else
  return format_vnet_feature_config_string_simple(s, args);
#endif
}

/*
 * vnet_config_main_t *cm;
 * vnet_config_t *c;
 *
 * format(s, "%U", format_vnet_feature_config_string, cm, c);
 */
u8 *
format_vnet_feature_config_string (u8 *s, va_list * args)
{
  return format_vnet_feature_config_string_simple(s, args);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
