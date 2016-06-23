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
      return clib_error_return 
        (0, "ip%s_feature_init_cast (cast=%d), no partial order!",
         is_ip4 ? "4" : "6", cast);

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

  /* Save a copy for show command */
  if (is_ip4)
    im4->feature_nodes[cast] = feature_nodes;
  else
    im6->feature_nodes[cast] = feature_nodes;

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

#define foreach_af_cast                         \
_(4, VNET_UNICAST, "ip4 unicast")               \
_(4, VNET_MULTICAST, "ip4 multicast")           \
_(6, VNET_UNICAST, "ip6 unicast")               \
_(6, VNET_MULTICAST, "ip6 multicast")

static clib_error_t *
show_ip_features_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  ip4_main_t * im4 = &ip4_main;
  ip6_main_t * im6 = &ip6_main;
  int i;
  char ** features;

  vlib_cli_output (vm, "Available IP feature nodes");

#define _(a,c,s)                                        \
  do {                                                  \
    features = im##a->feature_nodes[c];                 \
    vlib_cli_output (vm, "%s:", s);                     \
    for (i = 0; i < vec_len(features); i++)             \
      vlib_cli_output (vm, "  %s\n", features[i]);      \
  } while(0);
  foreach_af_cast;
#undef _

  return 0;
}

VLIB_CLI_COMMAND (show_ip_features_command, static) = {
  .path = "show ip features",
  .short_help = "show ip features",
  .function = show_ip_features_command_fn,
};

static clib_error_t *
show_ip_interface_features_command_fn (vlib_main_t * vm,
                                       unformat_input_t * input,
                                       vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  ip4_main_t * im4 = &ip4_main;
  ip_lookup_main_t * lm4 = &im4->lookup_main;
  ip6_main_t * im6 = &ip6_main;
  ip_lookup_main_t * lm6 = &im6->lookup_main;
  
  ip_lookup_main_t * lm;
  ip_config_main_t * cm;
  vnet_config_main_t * vcm;
  vnet_config_t * cfg;
  u32 cfg_index;
  vnet_config_feature_t * feat;
  vlib_node_t * n;
  u32 sw_if_index;
  u32 node_index;
  u32 current_config_index;
  int i, af;
  u32 cast;

  if (! unformat (input, "%U", unformat_vnet_sw_interface, 
                  vnm, &sw_if_index))
    return clib_error_return (0, "Interface not specified...");

  vlib_cli_output (vm, "IP feature paths configured on %U...",
                   format_vnet_sw_if_index_name, vnm, sw_if_index);

  
  for (af = 0; af < 2; af++)
    {
      if (af == 0)
        lm = lm4;
      else
        lm = lm6;

      for (cast = VNET_UNICAST; cast < VNET_N_CAST; cast++)
        {
          cm = lm->rx_config_mains + cast;
          vcm = &cm->config_main;
      
          vlib_cli_output (vm, "\nipv%s %scast:", 
                           (af == 0) ? "4" : "6",
                           cast == VNET_UNICAST ?
                           "uni": "multi");

          current_config_index = vec_elt (cm->config_index_by_sw_if_index, 
                                          sw_if_index);

          ASSERT(current_config_index 
                 < vec_len (vcm->config_pool_index_by_user_index));
          
          cfg_index = 
            vcm->config_pool_index_by_user_index[current_config_index];
          cfg = pool_elt_at_index (vcm->config_pool, cfg_index);

          for (i = 0; i < vec_len(cfg->features); i++)
            {
              feat = cfg->features + i;
              node_index = feat->node_index;
              n = vlib_get_node (vm, node_index);
              vlib_cli_output (vm, "  %v", n->name);
            }
        }
    }

  return 0;
}

VLIB_CLI_COMMAND (show_ip_interface_features_command, static) = {
  .path = "show ip interface features",
  .short_help = "show ip interface features <intfc>",
  .function = show_ip_interface_features_command_fn,
};


