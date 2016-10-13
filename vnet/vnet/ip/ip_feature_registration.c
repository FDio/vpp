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
#include <vnet/mpls/mpls.h>

/**
 * @file
 * @brief IP Feature Subgraph Ordering.

    Dynamically compute IP feature subgraph ordering by performing a
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
    \#include <vnet/ip/ip_feature_registration.h>
    </PRE></CODE>

    and add the new feature as shown:

    <CODE><PRE>
    VNET_IP4_UNICAST_FEATURE_INIT (ip4_lookup, static) =
    {
      .node_name = "my-ip4-unicast-feature",
      .runs_before = ORDER_CONSTRAINTS {"ip4-lookup", 0}
      .feature_index = &my_feature_index,
    };
    </PRE></CODE>

    Here's the standard coding pattern to enable / disable
    @c my-ip4-unicast-feature on an interface:

    <CODE><PRE>
    ip4_main_t *im = \&ip4_main;
    ip_lookup_main_t *lm = &im->lookup_main;
    ip_config_main_t *rx_cm =
        &lm->feature_config_mains[VNET_IP_RX_UNICAST_FEAT];

    sw_if_index = <interface-handle>
    ci = rx_cm->config_index_by_sw_if_index[sw_if_index];
    ci = (is_add
          ? vnet_config_add_feature
          : vnet_config_del_feature)
      (vm, &rx_cm->config_main,
       ci,
       my_feature_index,
       0 / * &config struct if feature uses private config data * /,
       0 / * sizeof config struct if feature uses private config data * /);
    rx_cm->config_index_by_sw_if_index[sw_if_index] = ci;
    </PRE></CODE>

    For tx features, add this line after setting
    <CODE><PRE>
    tx_cm->config_index_by_sw_if_index = ci.
    </PRE></CODE>

    This maintains a
    per-interface "at least one TX feature enabled" bitmap:

    <CODE><PRE>
    vnet_config_update_tx_feature_count (lm, tx_cm, sw_if_index, is_add);
    </PRE></CODE>

    Here's how to obtain the correct next node index in packet
    processing code, aka in the implementation of @c my-ip4-unicast-feature:

    <CODE><PRE>
    ip_lookup_main_t * lm = sm->ip4_lookup_main;
    ip_config_main_t * cm = &lm->feature_config_mains[VNET_IP_RX_UNICAST_FEAT];

    Call @c vnet_get_config_data to set next0, and to advance
    @c b0->current_config_index:

    config_data0 = vnet_get_config_data (&cm->config_main,
                                         &b0->current_config_index,
                                         &next0,
                                         0 / * sizeof config data * /);
    </PRE></CODE>

    Nodes are free to drop or otherwise redirect packets. Packets
    which "pass" should be enqueued via the next0 arc computed by
    vnet_get_config_data.
*/

static const char *vnet_cast_names[] = VNET_CAST_NAMES;

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
		       vnet_ip_feature_registration_t * first_reg,
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
  vnet_ip_feature_registration_t *this_reg = 0;
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
       * Note: the next two errors mean that the xxx_FEATURE_INIT macros are
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
      this_reg = (vnet_ip_feature_registration_t *) p[0];
      *this_reg->feature_index = n_features - (i + 1);
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

#define foreach_af_cast                                 \
_(4, VNET_IP_RX_UNICAST_FEAT, "ip4 unicast")            \
_(4, VNET_IP_RX_MULTICAST_FEAT, "ip4 multicast")        \
_(4, VNET_IP_TX_FEAT, "ip4 output")                     \
_(6, VNET_IP_RX_UNICAST_FEAT, "ip6 unicast")            \
_(6, VNET_IP_RX_MULTICAST_FEAT, "ip6 multicast")        \
_(6, VNET_IP_TX_FEAT, "ip6 output")

/** Display the set of available ip features.
    Useful for verifying that expected features are present
*/

static clib_error_t *
show_ip_features_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  int i;
  char **features;

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

/*?
 * This command is used to display the set of available IP features.
 * This can be useful for verifying that expected features are present.
 *
 * @cliexpar
 * Example of how to display the set of available IP features:
 * @cliexstart{show ip features}
 * Available IP feature nodes
 * ip4 unicast:
 *   ip4-inacl
 *   ip4-source-check-via-rx
 *   ip4-source-check-via-any
 *   ip4-source-and-port-range-check-rx
 *   ip4-policer-classify
 *   ipsec-input-ip4
 *   vpath-input-ip4
 *   snat-in2out
 *   snat-out2in
 *   ip4-lookup
 * ip4 multicast:
 *   vpath-input-ip4
 *   ip4-lookup-multicast
 * ip4 output:
 *   ip4-source-and-port-range-check-tx
 *   interface-output
 * ip6 unicast:
 *   ip6-inacl
 *   ip6-policer-classify
 *   ipsec-input-ip6
 *   l2tp-decap
 *   vpath-input-ip6
 *   sir-to-ila
 *   ip6-lookup
 * ip6 multicast:
 *   vpath-input-ip6
 *   ip6-lookup
 * ip6 output:
 *   interface-output
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip_features_command, static) = {
  .path = "show ip features",
  .short_help = "show ip features",
  .function = show_ip_features_command_fn,
};
/* *INDENT-ON* */

/** Display the set of IP features configured on a specific interface
 */

void
ip_interface_features_show (vlib_main_t * vm,
			    const char *pname,
			    ip_config_main_t * cm, u32 sw_if_index)
{
  u32 node_index, current_config_index;
  vnet_cast_t cast;
  vnet_config_main_t *vcm;
  vnet_config_t *cfg;
  u32 cfg_index;
  vnet_config_feature_t *feat;
  vlib_node_t *n;
  int i;

  vlib_cli_output (vm, "%s feature paths configured on %U...",
		   pname, format_vnet_sw_if_index_name,
		   vnet_get_main (), sw_if_index);

  for (cast = VNET_IP_RX_UNICAST_FEAT; cast < VNET_N_IP_FEAT; cast++)
    {
      vcm = &(cm[cast].config_main);

      vlib_cli_output (vm, "\n%s %s:", pname, vnet_cast_names[cast]);

      if (NULL == cm[cast].config_index_by_sw_if_index ||
	  vec_len (cm[cast].config_index_by_sw_if_index) < sw_if_index)
	{
	  vlib_cli_output (vm, "none configured");
	  continue;
	}

      current_config_index = vec_elt (cm[cast].config_index_by_sw_if_index,
				      sw_if_index);

      ASSERT (current_config_index
	      < vec_len (vcm->config_pool_index_by_user_index));

      cfg_index = vcm->config_pool_index_by_user_index[current_config_index];
      cfg = pool_elt_at_index (vcm->config_pool, cfg_index);

      for (i = 0; i < vec_len (cfg->features); i++)
	{
	  feat = cfg->features + i;
	  node_index = feat->node_index;
	  n = vlib_get_node (vm, node_index);
	  vlib_cli_output (vm, "  %v", n->name);
	}
    }
}

static clib_error_t *
show_ip_interface_features_command_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip4_main_t *im4 = &ip4_main;
  ip_lookup_main_t *lm4 = &im4->lookup_main;
  ip6_main_t *im6 = &ip6_main;
  ip_lookup_main_t *lm6 = &im6->lookup_main;

  ip_lookup_main_t *lm;
  u32 sw_if_index, af;

  if (!unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
    return clib_error_return (0, "Interface not specified...");

  vlib_cli_output (vm, "IP feature paths configured on %U...",
		   format_vnet_sw_if_index_name, vnm, sw_if_index);

  for (af = 0; af < 2; af++)
    {
      if (af == 0)
	lm = lm4;
      else
	lm = lm6;

      ip_interface_features_show (vm, (af == 0) ? "ip4" : "ip6",
				  lm->feature_config_mains, sw_if_index);
    }

  return 0;
}

/*?
 * This command is used to display the set of IP features configured
 * on a specific interface
 *
 * @cliexpar
 * Example of how to display the set of available IP features on an interface:
 * @cliexstart{show ip interface features GigabitEthernet2/0/0}
 * IP feature paths configured on GigabitEthernet2/0/0...
 * ipv4 unicast:
 *   ip4-lookup
 * ipv4 multicast:
 *   ip4-lookup-multicast
 * ipv4 multicast:
 *   interface-output
 * ipv6 unicast:
 *   ip6-lookup
 * ipv6 multicast:
 *   ip6-lookup
 * ipv6 multicast:
 *   interface-output
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip_interface_features_command, static) = {
  .path = "show ip interface features",
  .short_help = "show ip interface features <interface>",
  .function = show_ip_interface_features_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
