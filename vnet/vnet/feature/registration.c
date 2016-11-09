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

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/mpls/mpls.h>

/**
 * @file
 * @brief Feature Subgraph Ordering.

    Dynamically compute feature subgraph ordering by performing a
    topological sort across a set of "feature A before feature B" and
    "feature C after feature B" constraints.

    Use the topological sort result to set up vnet_config_main_t's for
    use at runtime.

    Feature subgraph arcs are simple enough. They start at specific
    fixed nodes, and end at specific fixed nodes.  In between, a
    per-interface current feature configuration dictates which
    additional nodes each packet visits. Each so-called feature node
    can [of course] drop any specific packet.

    See ip4_forward.c, ip6_forward.c in this directory to see the
    current rx-unicast, rx-multicast, and tx feature subgraph arc
    definitions.

    Let's say that we wish to add a new feature to the ip4 unicast
    feature subgraph arc, which needs to run before @c ip4-lookup.  In
    either base code or a plugin,
    <CODE><PRE>
    \#include <vnet/feature/feature.h>
    </PRE></CODE>

    and add the new feature as shown:

    <CODE><PRE>
    VNET_FEATURE_INIT (ip4_lookup, static) =
    {
      .arch_name = "ip4-unicast",
      .node_name = "my-ip4-unicast-feature",
      .runs_before = VLIB_FEATURES ("ip4-lookup")
    };
    </PRE></CODE>

    Here's the standard coding pattern to enable / disable
    @c my-ip4-unicast-feature on an interface:

    <CODE><PRE>

    sw_if_index = <interface-handle>
    vnet_feature_enable_disable ("ip4-unicast", "my-ip4-unicast-feature",
                                 sw_if_index, 1 );
    </PRE></CODE>

    Here's how to obtain the correct next node index in packet
    processing code, aka in the implementation of @c my-ip4-unicast-feature:

    <CODE><PRE>
    vnet_feature_next (sw_if_index0, &next0, b0);

    </PRE></CODE>

    Nodes are free to drop or otherwise redirect packets. Packets
    which "pass" should be enqueued via the next0 arc computed by
    vnet_feature_next.
*/


static int
comma_split (u8 * s, u8 ** a, u8 ** b)
{
  *a = s;

  while (*s && *s != ',')
    s++;

  if (*s == ',')
    *s = 0;
  else
    return 1;

  *b = (u8 *) (s + 1);
  return 0;
}

/**
 * @brief Initialize a feature graph arc
 * @param vm vlib main structure pointer
 * @param vcm vnet config main structure pointer
 * @param feature_start_nodes names of start-nodes which use this
 *	  feature graph arc
 * @param num_feature_start_nodes number of start-nodes
 * @param first_reg first element in
 *        [an __attribute__((constructor)) function built, or
 *        otherwise created] singly-linked list of feature registrations
 * @param [out] in_feature_nodes returned vector of
 *        topologically-sorted feature node names, for use in
 *        show commands
 * @returns 0 on success, otherwise an error message. Errors
 *        are fatal since they invariably involve mistyped node-names, or
 *        genuinely missing node-names
 */
clib_error_t *
vnet_feature_arc_init (vlib_main_t * vm,
		       vnet_config_main_t * vcm,
		       char **feature_start_nodes,
		       int num_feature_start_nodes,
		       vnet_feature_registration_t * first_reg,
		       char ***in_feature_nodes)
{
  uword *index_by_name;
  uword *reg_by_index;
  u8 **node_names = 0;
  u8 *node_name;
  char **these_constraints;
  char *this_constraint_c;
  u8 **constraints = 0;
  u8 *constraint_tuple;
  u8 *this_constraint;
  u8 **orig, **closure;
  uword *p;
  int i, j, k;
  u8 *a_name, *b_name;
  int a_index, b_index;
  int n_features;
  u32 *result = 0;
  vnet_feature_registration_t *this_reg = 0;
  char **feature_nodes = 0;
  hash_pair_t *hp;
  u8 **keys_to_delete = 0;

  index_by_name = hash_create_string (0, sizeof (uword));
  reg_by_index = hash_create (0, sizeof (uword));

  this_reg = first_reg;

  /* pass 1, collect feature node names, construct a before b pairs */
  while (this_reg)
    {
      node_name = format (0, "%s%c", this_reg->node_name, 0);
      hash_set (reg_by_index, vec_len (node_names), (uword) this_reg);

      hash_set_mem (index_by_name, node_name, vec_len (node_names));

      vec_add1 (node_names, node_name);

      these_constraints = this_reg->runs_before;
      while (these_constraints && these_constraints[0])
	{
	  this_constraint_c = these_constraints[0];

	  constraint_tuple = format (0, "%s,%s%c", node_name,
				     this_constraint_c, 0);
	  vec_add1 (constraints, constraint_tuple);
	  these_constraints++;
	}

      these_constraints = this_reg->runs_after;
      while (these_constraints && these_constraints[0])
	{
	  this_constraint_c = these_constraints[0];

	  constraint_tuple = format (0, "%s,%s%c",
				     this_constraint_c, node_name, 0);
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
      /*
       * Note: the next two errors mean that something is
       * b0rked. As in: if you code "A depends on B," and you forget
       * to define a FEATURE_INIT macro for B, you lose.
       * Nonexistent graph nodes are tolerated.
       */
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
	  closure[k][i] = 0;
	/*
	 * Add a "Magic" a before a constraint.
	 * This means we'll never output it again
	 */
	closure[i][i] = 1;
	goto again;
      }
    item_constrained:
      ;
    }

  /* see if we got a partial order... */
  if (vec_len (result) != n_features)
    return clib_error_return (0, "%d feature_init_cast no partial order!");

  /*
   * We win.
   * Bind the index variables, and output the feature node name vector
   * using the partial order we just computed. Result is in stack
   * order, because the entry with the fewest constraints (e.g. none)
   * is output first, etc.
   */

  for (i = n_features - 1; i >= 0; i--)
    {
      p = hash_get (reg_by_index, result[i]);
      ASSERT (p != 0);
      this_reg = (vnet_feature_registration_t *) p[0];
      if (this_reg->feature_index_ptr)
	*this_reg->feature_index_ptr = n_features - (i + 1);
      this_reg->feature_index = n_features - (i + 1);
      vec_add1 (feature_nodes, this_reg->node_name);
    }

  /* Set up the config infrastructure */
  vnet_config_init (vm, vcm,
		    feature_start_nodes,
		    num_feature_start_nodes,
		    feature_nodes, vec_len (feature_nodes));

  /* Save a copy for show command */
  *in_feature_nodes = feature_nodes;

  /* Finally, clean up all the shit we allocated */
  /* *INDENT-OFF* */
  hash_foreach_pair (hp, index_by_name,
  ({
    vec_add1 (keys_to_delete, (u8 *)hp->key);
  }));
  /* *INDENT-ON* */
  hash_free (index_by_name);
  for (i = 0; i < vec_len (keys_to_delete); i++)
    vec_free (keys_to_delete[i]);
  vec_free (keys_to_delete);
  hash_free (reg_by_index);
  vec_free (result);
  clib_ptclosure_free (orig);
  clib_ptclosure_free (closure);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
