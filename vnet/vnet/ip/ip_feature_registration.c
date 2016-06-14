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

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

static int comma_split (u8 *s, u8 **a, u8 **b)
{
  *a = s;

  while (*s && *s != ',')
    s++;

  if (*s == ',')
    *s = 0;
  else
    return 1;

  *b = (u8 *) (s+1);
  return 0;
}

clib_error_t *
ip_feature_init_cast (vlib_main_t * vm,
                      ip_config_main_t * cm,
                      vnet_config_main_t * vcm,
                      char **feature_start_nodes,
                      int num_feature_start_nodes,
                      vnet_cast_t cast,
                      int is_ip4)
{
  uword * index_by_name;
  uword * reg_by_index;
  u8 ** node_names = 0;
  u8 * node_name;
  char ** these_constraints;
  char * this_constraint_c;
  u8 ** constraints = 0;
  u8 * constraint_tuple;
  u8 * this_constraint;
  u8 ** orig, ** closure;
  uword * p;
  int i, j, k;
  u8 * a_name, * b_name;
  int a_index, b_index;
  int n_features;
  u32 * result = 0;
  vnet_ip_feature_registration_t * this_reg, * first_reg;
  char ** feature_nodes = 0;
  hash_pair_t * hp;
  u8 ** keys_to_delete = 0;
  ip4_main_t * im4 = &ip4_main;
  ip6_main_t * im6 = &ip6_main;

  index_by_name = hash_create_string (0, sizeof (uword));
  reg_by_index = hash_create (0, sizeof (uword));

  if (cast == VNET_UNICAST)
    {
      if (is_ip4)
        first_reg = im4->next_uc_feature;
      else
        first_reg = im6->next_uc_feature;
    }
  else
    {
      if (is_ip4)
        first_reg = im4->next_mc_feature;
      else
        first_reg = im6->next_mc_feature;
    }
  
  this_reg = first_reg;

  /* pass 1, collect feature node names, construct a before b pairs */
  while (this_reg)
    {
      node_name = format (0, "%s%c", this_reg->node_name, 0);
      hash_set (reg_by_index, vec_len(node_names), (uword) this_reg);

      hash_set_mem (index_by_name, node_name, vec_len(node_names));

      vec_add1 (node_names, node_name);

      these_constraints = this_reg->runs_before;

      while (these_constraints [0])
        {
          this_constraint_c = these_constraints[0];

          constraint_tuple = format (0, "%s,%s%c", node_name,
                                     this_constraint_c, 0);
          vec_add1 (constraints, constraint_tuple);
          these_constraints++;
        }
      this_reg = this_reg->next;
    }

  n_features = vec_len (node_names);
  orig = clib_ptclosure_alloc (n_features);

  for (i = 0; i < vec_len (constraints); i++)
    {
      this_constraint = constraints[i];

      if (comma_split (this_constraint, &a_name, &b_name))
        return clib_error_return (0, "comma_split failed!");
      
      p = hash_get_mem (index_by_name, a_name);
      if (p == 0)
        return clib_error_return (0, "feature node '%s' not found", a_name);
      a_index = p[0];

      p = hash_get_mem (index_by_name, b_name);
      if (p == 0)
        return clib_error_return (0, "feature node '%s' not found", b_name);
      b_index = p[0];

      /* add a before b to the original set of constraints */
      orig[a_index][b_index] = 1;
      vec_free (this_constraint);
    }
  
  /* Compute the positive transitive closure of the original constraints */
  closure = clib_ptclosure (orig);

  /* Compute a partial order across feature nodes, if one exists. */
 again:
  for (i = 0; i < n_features; i++)
    {
      for (j = 0; j < n_features; j++)
        {
          if (closure[i][j])
            goto item_constrained;
        }
      /* Item i can be output */
      vec_add1 (result, i);
      {
        for (k = 0; k < n_features; k++)
          closure [k][i] = 0;
        /* 
         * Add a "Magic" a before a constraint. 
         * This means we'll never output it again
         */
        closure [i][i] = 1;
        goto again;
      }
    item_constrained:
      ;
    }

  /* see if we got a partial order... */
  if (vec_len (result) != n_features)
    return clib_error_return (0, "ip4_feature_init_cast (cast=%d), no PO!");

  /* 
   * We win.
   * Bind the index variables, and output the feature node name vector
   * using the partial order we just computed. Result is in stack
   * order, because the entry with the fewest constraints (e.g. none)
   * is output first, etc.
   */

  for (i = n_features-1; i >= 0; i--)
    {
      p = hash_get (reg_by_index, result[i]);
      ASSERT (p != 0);
      this_reg = (vnet_ip_feature_registration_t *)p[0];
      *this_reg->feature_index = n_features - (i+1);
      vec_add1 (feature_nodes, this_reg->node_name);
    }
  
  /* Set up the config infrastructure */
  vnet_config_init (vm, vcm,
                    feature_start_nodes, 
                    num_feature_start_nodes,
                    feature_nodes, 
                    vec_len(feature_nodes));

  /* Finally, clean up all the shit we allocated */
  hash_foreach_pair (hp, index_by_name,
  ({
    vec_add1 (keys_to_delete, (u8 *)hp->key);
  }));
  hash_free (index_by_name);
  for (i = 0; i < vec_len(keys_to_delete); i++)
    vec_free (keys_to_delete[i]);
  vec_free (keys_to_delete);
  hash_free (reg_by_index);
  vec_free (result);
  clib_ptclosure_free (orig);
  clib_ptclosure_free (closure);
  return 0;
}

