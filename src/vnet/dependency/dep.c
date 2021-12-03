/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Copyright (c) 2021 Graphiant and/or its affiliates.
 *
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

#include <vnet/dependency/dep.h>
#include <vnet/dependency/dep_list.h>

/**
 * The per-type vector of virtual function tables
 */
static dep_vft_t *d_vfts;

/**
 * The last registered new type
 */
static dep_type_t last_type;

/**
 * the per-type vector of depednecy type names
 */
static const char **d_type_names;

const char *
dep_type_get_name (dep_type_t type)
{
  if ((type < vec_len (d_type_names)) && (NULL != d_type_names[type]))
    {
      return (d_type_names[type]);
    }
  else
    {
      return ("unknown");
    }
}

/**
 * dep_register_type
 *
 * Register the function table for a given type
 */
dep_type_t
dep_register_type (const char *name, const dep_vft_t *vft)
{
  /*
   * Assert that we are getting each of the required functions
   */
  ASSERT (NULL != vft->dv_get);
  ASSERT (NULL != vft->dv_last_lock);

  dep_type_t type = ++last_type;

  vec_validate (d_vfts, type);
  vec_validate (d_type_names, type);

  /*
   * assert that one only registration is made per-node type
   */
  ASSERT (NULL == d_vfts[type].dv_get);

  d_vfts[type] = *vft;
  d_type_names[type] = name;

  return (type);
}

static u8 *
dep_format (dep_ptr_t *dp, u8 *s)
{
  return (format (s, "{%s:%d}", d_type_names[dp->dp_type], dp->dp_index));
}

u32
dep_child_add (dep_type_t parent_type, dep_index_t parent_index,
	       dep_type_t type, dep_index_t index)
{
  dep_t *parent;

  parent = d_vfts[parent_type].dv_get (parent_index);

  /*
   * return the index of the sibling in the child list
   */
  dep_lock (parent);

  if (DEP_INDEX_INVALID == parent->d_children)
    {
      parent->d_children = dep_list_create ();
    }

  return (dep_list_push_front (parent->d_children, 0, type, index));
}

void
dep_child_remove (dep_type_t parent_type, dep_index_t parent_index,
		  dep_index_t sibling_index)
{
  dep_t *parent;

  parent = d_vfts[parent_type].dv_get (parent_index);

  dep_list_remove (parent->d_children, sibling_index);

  if (0 == dep_list_get_size (parent->d_children))
    {
      dep_list_destroy (&parent->d_children);
    }

  dep_unlock (parent);
}

u32
dep_get_n_children (dep_type_t parent_type, dep_index_t parent_index)
{
  dep_t *parent;

  parent = d_vfts[parent_type].dv_get (parent_index);

  return (dep_list_get_size (parent->d_children));
}

dep_back_walk_rc_t
dep_back_walk_one (dep_ptr_t *ptr, dep_back_walk_ctx_t *ctx)
{
  dep_t *node;

  node = d_vfts[ptr->dp_type].dv_get (ptr->dp_index);

  return (d_vfts[ptr->dp_type].dv_back_walk (node, ctx));
}

static walk_rc_t
dep_ptr_format_one_child (dep_ptr_t *ptr, void *arg)
{
  u8 **s = (u8 **) arg;

  *s = dep_format (ptr, *s);

  return (WALK_CONTINUE);
}

u8 *
dep_children_format (dep_list_t list, u8 *s)
{
  dep_list_walk (list, dep_ptr_format_one_child, (void *) &s);

  return (s);
}

void
dep_init (dep_t *node, dep_type_t type)
{
  /**
   * The node's type. used to retrieve the VFT.
   */
  node->d_type = type;
  node->d_locks = 0;
  node->d_children = DEP_INDEX_INVALID;
}

void
dep_deinit (dep_t *node)
{
  dep_list_destroy (&node->d_children);
}

void
dep_lock (dep_t *node)
{
  node->d_locks++;
}

void
dep_unlock (dep_t *node)
{
  node->d_locks--;

  if (0 == node->d_locks)
    {
      d_vfts[node->d_type].dv_last_lock (node);
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
