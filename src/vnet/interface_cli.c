/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* interface_cli.c: interface CLI */

/**
 * @file
 * @brief Interface CLI.
 *
 * Source code for several CLI interface commands.
 *
 */
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/bitmap.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_input.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/interface/tx_queue_funcs.h>
#include <vnet/hash/hash.h>
#include <vnet/interface/cli_types.h>
#include <vnet/ethernet/cli_types.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/dev_funcs.h>
#include <vnet/ethernet/sfp.h>

/* sw interface, or "any" which is sw_if_index 0 */
static u8 *
parse_sw_interface_any (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  if (vec_len (tok) == 3 && memcmp (tok, "any", 3) == 0)
    {
      v->index = 0;
      return 0;
    }
  return cli_type_sw_interface.parse (a, tok, v);
}

static void
complete_sw_interface_any (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  if (cli_prefix_match ("any", prefix))
    cli_candidate_add (out, "any", "any interface");
  cli_type_sw_interface.complete (a, prefix, out);
}

CLIB_CLI_TYPE (cli_type_sw_interface_any, static) = {
  .name = "interface",
  .help = "interface name or index, or any",
  .parse = parse_sw_interface_any,
  .complete = complete_sw_interface_any,
};

/* hardware interface class, the value is the class index */
static const char *
next_hw_class_name (const cli_arg_t *a, u32 *iter, u32 *value, const char **help)
{
  vnet_interface_main_t *im = &vnet_get_main ()->interface_main;
  const char *name = 0;
  u32 n = 0;
  hash_pair_t *p;

  /* the classes are in a hash, the iterator is the number of names already given */
  hash_foreach_pair (p, im->hw_interface_class_by_name, ({
		       if (n++ == *iter)
			 {
			   *value = p->value[0];
			   name = (char *) p->key;
			   break;
			 }
		     }));

  if (name)
    (*iter)++;
  return name;
}

CLIB_CLI_TYPE (cli_type_hw_class, static) = {
  .name = "hw-class",
  .help = "hardware interface class",
  .next_name = next_hw_class_name,
  .parse = cli_names_parse,
  .complete = cli_names_complete,
};

#define VLAN_ID_ANY 0x10000

/* vlan id, or "any" which is VLAN_ID_ANY, the value is in v->u64 */
static u8 *
parse_vlan (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  u64 id = 0;

  if (vec_len (tok) == 3 && memcmp (tok, "any", 3) == 0)
    {
      v->u64 = VLAN_ID_ANY;
      return 0;
    }

  for (u32 i = 0; i < vec_len (tok); i++)
    {
      if (!cli_is_digit (tok[i]) || id > 4095)
	return format (0, "'%v' is not a vlan id or any", tok);
      id = id * 10 + tok[i] - '0';
    }
  if (vec_len (tok) == 0 || id > 4095)
    return format (0, "'%v' is not a vlan id or any", tok);

  v->u64 = id;
  return 0;
}

static void
complete_vlan (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  if (cli_prefix_match ("any", prefix))
    cli_candidate_add (out, "any", "any vlan id");
}

CLIB_CLI_TYPE (cli_type_vlan, static) = {
  .name = "vlan-id",
  .help = "vlan id, or any",
  .parse = parse_vlan,
  .complete = complete_vlan,
};

/* sub-interface id or a range of ids, first-last, the value is in v->range */
static u8 *
parse_sub_id (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  if (vec_search (tok, '-') != ~0)
    return cli_type_range.parse (a, tok, v);

  u8 *err = cli_type_u32.parse (a, tok, v);

  if (err)
    return err;
  v->range.start = v->range.stop = v->u64;
  return 0;
}

CLIB_CLI_TYPE (cli_type_sub_id, static) = {
  .name = "id",
  .help = "sub-interface id, or a range of ids first-last",
  .parse = parse_sub_id,
};

static int
compare_interface_names (void *a1, void *a2)
{
  u32 *hi1 = a1;
  u32 *hi2 = a2;

  return vnet_hw_interface_compare (vnet_get_main (), *hi1, *hi2);
}

static clib_error_t *
show_or_clear_hw_interfaces (vlib_main_t *vm, cli_ctx_t *ctx, int is_show)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi;
  u32 *hw_if_indices = 0;
  cli_value_t *v;
  int i, verbose = -1, show_bond = cli_flag (ctx, "bond");

  cli_foreach (v, ctx, "interface") vec_add1 (hw_if_indices, v->index);

  if (cli_flag (ctx, "detail"))
    verbose = 2;
  else if (cli_flag (ctx, "brief"))
    verbose = 0;
  else if (cli_flag (ctx, "verbose"))
    verbose = 1; /* this is also the default */

  /* default to brief for link bonding */
  if (show_bond && verbose < 0)
    verbose = 0;

  /* Gather interfaces. */
  if (vec_len (hw_if_indices) == 0)
    pool_foreach (hi, im->hw_interfaces)
      vec_add1 (hw_if_indices, hi - im->hw_interfaces);

  if (verbose < 0)
    verbose = 1; /* default to verbose (except bond) */

  if (is_show)
    {
      /* Sort by name. */
      vec_sort_with_function (hw_if_indices, compare_interface_names);

      vlib_cli_output (vm, "%U\n", format_vnet_hw_interface, vnm, 0, verbose);
      for (i = 0; i < vec_len (hw_if_indices); i++)
	{
	  hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);
	  if (show_bond == 0) /* show all interfaces */
	    vlib_cli_output (vm, "%U\n", format_vnet_hw_interface, vnm, hi, verbose);
	  else if ((hi->bond_info) && (hi->bond_info != VNET_HW_INTERFACE_BOND_INFO_SLAVE))
	    { /* show only bonded interface and all its slave interfaces */
	      int hw_idx;
	      vnet_hw_interface_t *shi;
	      vlib_cli_output (vm, "%U\n", format_vnet_hw_interface, vnm, hi, verbose);

	      clib_bitmap_foreach (hw_idx, hi->bond_info)
		{
		  shi = vnet_get_hw_interface (vnm, hw_idx);
		  vlib_cli_output (vm, "%U\n", format_vnet_hw_interface, vnm, shi, verbose);
		}
	    }
	}
    }
  else
    {
      for (i = 0; i < vec_len (hw_if_indices); i++)
	{
	  vnet_device_class_t *dc;

	  hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);
	  dc = vec_elt_at_index (im->device_classes, hi->dev_class_index);

	  if (dc->clear_counters)
	    dc->clear_counters (hi->dev_instance);
	}
    }

  vec_free (hw_if_indices);
  return 0;
}

static clib_error_t *
show_hw_interfaces (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return show_or_clear_hw_interfaces (vm, ctx, 1 /* is_show */);
}

static clib_error_t *
clear_hw_interfaces (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return show_or_clear_hw_interfaces (vm, ctx, 0 /* is_show */);
}


/*?
 * Display more detailed information about all or a list of given interfaces.
 * The verboseness of the output can be controlled by the following optional
 * parameters:
 * - brief: Only show name, index and state (default for bonded interfaces).
 * - verbose: Also display additional attributes (default for all other interfaces).
 * - detail: Also display all remaining attributes and extended statistics.
 *
 * To limit the output of the command to bonded interfaces and their slave
 * interfaces, use the '<em>bond</em>' optional parameter.
 *
 * @cliexpar
 * Example of how to display default data for all interfaces:
 * @cliexstart{show hardware-interfaces}
 *               Name                Idx   Link  Hardware
 * GigabitEthernet7/0/0               1     up   GigabitEthernet7/0/0
 *   Ethernet address ec:f4:bb:c0:bc:fc
 *   Intel e1000
 *     carrier up full duplex speed 1000 mtu 9216
 *     rx queues 1, rx desc 1024, tx queues 3, tx desc 1024
 *     cpu socket 0
 * GigabitEthernet7/0/1               2     up   GigabitEthernet7/0/1
 *   Ethernet address ec:f4:bb:c0:bc:fd
 *   Intel e1000
 *     carrier up full duplex speed 1000 mtu 9216
 *     rx queues 1, rx desc 1024, tx queues 3, tx desc 1024
 *     cpu socket 0
 * VirtualEthernet0/0/0               3     up   VirtualEthernet0/0/0
 *   Ethernet address 02:fe:a5:a9:8b:8e
 * VirtualEthernet0/0/1               4     up   VirtualEthernet0/0/1
 *   Ethernet address 02:fe:c0:4e:3b:b0
 * VirtualEthernet0/0/2               5     up   VirtualEthernet0/0/2
 *   Ethernet address 02:fe:1f:73:92:81
 * VirtualEthernet0/0/3               6     up   VirtualEthernet0/0/3
 *   Ethernet address 02:fe:f2:25:c4:68
 * local0                             0    down  local0
 *   local
 * @cliexend
 * Example of how to display '<em>verbose</em>' data for an interface by name and
 * software index (where 2 is the software index):
 * @cliexstart{show hardware-interfaces GigabitEthernet7/0/0 2 verbose}
 *               Name                Idx   Link  Hardware
 * GigabitEthernet7/0/0               1     up   GigabitEthernet7/0/0
 *   Ethernet address ec:f4:bb:c0:bc:fc
 *   Intel e1000
 *     carrier up full duplex speed 1000 mtu 9216
 *     rx queues 1, rx desc 1024, tx queues 3, tx desc 1024
 *     cpu socket 0
 * GigabitEthernet7/0/1               2    down  GigabitEthernet7/0/1
 *   Ethernet address ec:f4:bb:c0:bc:fd
 *   Intel e1000
 *     carrier up full duplex speed 1000 mtu 9216
 *     rx queues 1, rx desc 1024, tx queues 3, tx desc 1024
 *     cpu socket 0
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (show_hw_interfaces_command, static) = {
  .path = "show hardware-interfaces",
  .short_help = "Show the hardware interfaces",
  .args =
    (cli_arg_t[]) {
      CLI_FLAG ("brief", .help = "name, index and state"),
      CLI_FLAG ("verbose", .help = "additional attributes, the default"),
      CLI_FLAG ("detail", .help = "all attributes and extended statistics"),
      CLI_FLAG ("bond", .help = "only bonded interfaces and their slaves"),
      CLI_VALUE ("interface", cli_type_hw_interface, .flags = CLI_F_OPTIONAL | CLI_F_REPEAT),
      {},
    },
  .handler = show_hw_interfaces,
};

/*?
 * Clear the extended statistics for all or a list of given interfaces
 * (statistics associated with the '<em>show hardware-interfaces</em>' command).
 *
 * @cliexpar
 * Example of how to clear the extended statistics for all interfaces:
 * @cliexcmd{clear hardware-interfaces}
 * Example of how to clear the extended statistics for an interface by
 * name and software index (where 2 is the software index):
 * @cliexcmd{clear hardware-interfaces GigabitEthernet7/0/0 2}
 ?*/
VLIB_CLI_COMMAND (clear_hw_interface_counters_command, static) = {
  .path = "clear hardware-interfaces",
  .short_help = "Clear the extended statistics of the hardware interfaces",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_hw_interface, .flags = CLI_F_OPTIONAL | CLI_F_REPEAT),
      {},
    },
  .handler = clear_hw_interfaces,
};

static int
sw_interface_name_compare (void *a1, void *a2)
{
  vnet_sw_interface_t *si1 = a1;
  vnet_sw_interface_t *si2 = a2;

  return vnet_sw_interface_compare (vnet_get_main (),
				    si1->sw_if_index, si2->sw_if_index);
}

static const cli_column_t show_sw_interfaces_columns[] = {
  { "name", "Name" }, { "sw_if_index", "Idx" },	    { "state", "State" },
  { "mtu", "MTU" },   { "addresses", "Addresses" }, {},
};

static clib_error_t *
show_sw_interfaces (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_sw_interface_t *si, *sorted_sis = 0;
  cli_value_t *v;
  u32 sw_if_index = ~(u32) 0;
  u8 show_addresses = cli_flag (ctx, "address");
  u8 show_features = cli_flag (ctx, "features");
  u8 show_tag = cli_flag (ctx, "tag");
  u8 show_vtr = cli_flag (ctx, "vtr");
  int verbose = cli_flag (ctx, "verbose");

  cli_foreach (v, ctx, "interface")
  {
    sw_if_index = v->index;
    si = pool_elt_at_index (im->sw_interfaces, sw_if_index);
    vec_add1 (sorted_sis, si[0]);
  }

  if (show_features || show_tag || show_vtr)
    {
      if (sw_if_index == ~(u32) 0)
	{
	  vec_free (sorted_sis);
	  return clib_error_return (0, "Interface not specified...");
	}
    }

  if (show_features)
    {
      vnet_interface_features_show (vm, sw_if_index, verbose);
      vlib_cli_output (vm, "%U", format_l2_input_features, sw_if_index, 1);

      l2_output_config_t *l2_output = l2output_intf_config (sw_if_index);
      vlib_cli_output (vm, "\nl2-output:");
      if (l2_output->out_vtr_flag)
	vlib_cli_output (vm, "%10s (%s)", "VTR", "--internal--");
      vlib_cli_output (vm, "%U", format_l2_output_features,
		       l2_output->feature_bitmap, 1);
      vec_free (sorted_sis);
      return 0;
    }
  if (show_tag)
    {
      u8 *tag;
      tag = vnet_get_sw_interface_tag (vnm, sw_if_index);
      vlib_cli_output (vm, "%U: %s",
		       format_vnet_sw_if_index_name, vnm, sw_if_index,
		       tag ? (char *) tag : "(none)");
      vec_free (sorted_sis);
      return 0;
    }

  /*
   * Show vlan tag rewrite data for one interface.
   */
  if (show_vtr)
    {
      u32 vtr_op = L2_VTR_DISABLED;
      u32 push_dot1q = 0, tag1 = 0, tag2 = 0;

      if (l2vtr_get (vm, vnm, sw_if_index,
		     &vtr_op, &push_dot1q, &tag1, &tag2) != 0)
	{
	  vlib_cli_output (vm, "%U: Problem getting vlan tag-rewrite data",
			   format_vnet_sw_if_index_name, vnm, sw_if_index);
	  return 0;
	}
      vlib_cli_output (vm, "%U:  VTR %0U",
		       format_vnet_sw_if_index_name, vnm, sw_if_index,
		       format_vtr, vtr_op, push_dot1q, tag1, tag2);
      return 0;
    }

  if (!show_addresses && !cli_is_structured (ctx))
    vlib_cli_output (vm, "%U\n", format_vnet_sw_interface, vnm, 0);

  if (vec_len (sorted_sis) == 0)	/* Get all interfaces */
    {
      /* Gather interfaces. */
      sorted_sis =
	vec_new (vnet_sw_interface_t, pool_elts (im->sw_interfaces));
      vec_set_len (sorted_sis, 0);
      pool_foreach (si, im->sw_interfaces)
       {
        int visible = vnet_swif_is_api_visible (si);
        if (visible)
          vec_add1 (sorted_sis, si[0]);
        }
      /* Sort by name. */
      vec_sort_with_function (sorted_sis, sw_interface_name_compare);
    }

  if (cli_is_structured (ctx))
    {
      clib_json_text_t j;

      clib_json_init (&j);
      clib_json_add_array (&j, 0);
      vec_foreach (si, sorted_sis)
	{
	  ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
	  ip_lookup_main_t *lm6 = &ip6_main.lookup_main;
	  ip_interface_address_t *ia = 0;

	  clib_json_add_object (&j, 0);
	  clib_json_add_string (&j, "name", "%U", format_vnet_sw_if_index_name, vnm,
				si->sw_if_index);
	  clib_json_add_number (&j, "sw_if_index", si->sw_if_index);
	  clib_json_add_string (&j, "state", "%s",
				(si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? "up" : "down");
	  clib_json_add_number (&j, "mtu", si->mtu[VNET_MTU_L3]);
	  clib_json_add_array (&j, "addresses");

	  foreach_ip_interface_address (
	    lm4, ia, si->sw_if_index, 1 /* honor unnumbered */, ({
	      clib_json_add_string (&j, 0, "%U/%d", format_ip4_address,
				    ip_interface_address_get_address (lm4, ia), ia->address_length);
	    }));
	  foreach_ip_interface_address (
	    lm6, ia, si->sw_if_index, 1 /* honor unnumbered */, ({
	      clib_json_add_string (&j, 0, "%U/%d", format_ip6_address,
				    ip_interface_address_get_address (lm6, ia), ia->address_length);
	    }));
	  clib_json_parent (&j);
	  clib_json_parent (&j);
	}
      clib_json_parent (&j);
      vec_free (sorted_sis);
      return cli_emit_table (ctx, &j, show_sw_interfaces_columns);
    }

  if (show_addresses)
    {
      vec_foreach (si, sorted_sis)
      {
	ip4_main_t *im4 = &ip4_main;
	ip6_main_t *im6 = &ip6_main;
	ip_lookup_main_t *lm4 = &im4->lookup_main;
	ip_lookup_main_t *lm6 = &im6->lookup_main;
	ip_interface_address_t *ia = 0;
	u32 fib_index4 = 0, fib_index6 = 0;

	if (vec_len (im4->fib_index_by_sw_if_index) > si->sw_if_index)
	  fib_index4 = vec_elt (im4->fib_index_by_sw_if_index,
				si->sw_if_index);

	if (vec_len (im6->fib_index_by_sw_if_index) > si->sw_if_index)
	  fib_index6 = vec_elt (im6->fib_index_by_sw_if_index,
				si->sw_if_index);

	ip4_fib_t *fib4 = ip4_fib_get (fib_index4);
	ip6_fib_t *fib6 = ip6_fib_get (fib_index6);

	if (si->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)
	  vlib_cli_output
	    (vm, "%U (%s): \n  unnumbered, use %U",
	     format_vnet_sw_if_index_name, vnm, si->sw_if_index,
	     (si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? "up" : "dn",
	     format_vnet_sw_if_index_name, vnm, si->unnumbered_sw_if_index);
	else
	  vlib_cli_output
	    (vm, "%U (%s):",
	     format_vnet_sw_if_index_name, vnm, si->sw_if_index,
	     (si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? "up" : "dn");

	/* Display any L2 info */
	vlib_cli_output (vm, "%U", format_l2_input, si->sw_if_index);

	/* Display any IP4 addressing info */
	foreach_ip_interface_address (lm4, ia, si->sw_if_index,
				      1 /* honor unnumbered */,
	({
	  ip4_address_t *r4 = ip_interface_address_get_address (lm4, ia);
	  if (fib4->hash.table_id)
	    vlib_cli_output (
	      vm, "  L3 %U/%d ip4 table-id %u fib-idx %d", format_ip4_address,
	      r4, ia->address_length, fib4->hash.table_id,
	      ip4_fib_index_from_table_id (fib4->hash.table_id));
	  else
	    vlib_cli_output (vm, "  L3 %U/%d",
			     format_ip4_address, r4, ia->address_length);
        }));

	/* Display any IP6 addressing info */
	foreach_ip_interface_address (lm6, ia, si->sw_if_index,
				      1 /* honor unnumbered */,
        ({
	  ip6_address_t *r6 = ip_interface_address_get_address (lm6, ia);
	  if (fib6->table_id)
	    vlib_cli_output (vm, "  L3 %U/%d ip6 table-id %d fib-idx %d",
			     format_ip6_address, r6, ia->address_length,
			     fib6->table_id,
			     ip6_fib_index_from_table_id (fib6->table_id));
	  else
	    vlib_cli_output (vm, "  L3 %U/%d",
			     format_ip6_address, r6, ia->address_length);
        }));
      }
    }
  else
    {
      vec_foreach (si, sorted_sis)
      {
	vlib_cli_output (vm, "%U\n", format_vnet_sw_interface, vnm, si);
      }
    }

  vec_free (sorted_sis);
  return 0;
}

VLIB_CLI_COMMAND (show_sw_interfaces_command, static) = {
  .path = "show interface",
  .short_help = "Show interfaces, their addresses, features, tag or VTR",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_sw_interface, .flags = CLI_F_OPTIONAL | CLI_F_REPEAT),
      CLI_FLAG ("address", .alias = "addr", .help = "show IP addresses"),
      CLI_FLAG ("features", .alias = "feat", .help = "show enabled features"),
      CLI_FLAG ("vtr", .help = "show VLAN tag rewrite"),
      CLI_FLAG ("tag", .help = "show interface tag"),
      CLI_FLAG ("verbose", .help = "more details"),
      {},
    },
  .handler = show_sw_interfaces,
  .is_mp_safe = 1,
};

/* Root of all interface commands. */
VLIB_CLI_COMMAND (vnet_cli_interface_command, static) = {
  .path = "interface",
  .short_help = "Interface commands",
};

VLIB_CLI_COMMAND (vnet_cli_set_interface_command, static) = {
  .path = "set interface",
  .short_help = "Interface commands",
};

static clib_error_t *
clear_interface_counters (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vlib_simple_counter_main_t *sm;
  vlib_combined_counter_main_t *cm;
  int j, n_counters;

  n_counters = vec_len (im->combined_sw_if_counters);

  for (j = 0; j < n_counters; j++)
    {
      im = &vnm->interface_main;
      cm = im->combined_sw_if_counters + j;
      vlib_clear_combined_counters (cm);
    }

  n_counters = vec_len (im->sw_if_counters);

  for (j = 0; j < n_counters; j++)
    {
      im = &vnm->interface_main;
      sm = im->sw_if_counters + j;
      vlib_clear_simple_counters (sm);
    }

  return 0;
}

/*?
 * Clear the statistics for all interfaces (statistics associated with the
 * '<em>show interface</em>' command).
 *
 * @cliexpar
 * Example of how to clear the statistics for all interfaces:
 * @cliexcmd{clear interfaces}
 ?*/
VLIB_CLI_COMMAND (clear_interface_counters_command, static) = {
  .path = "clear interfaces",
  .short_help = "Clear the counters of all interfaces",
  .handler = clear_interface_counters,
};

/**
 * Parse subinterface names.
 *
 * The following subinterface syntax is supported. The first two are for
 * backwards compatability:
 *
 * <intf-name> <id>
 *     - a subinterface with the name <intf-name>.<id>. The subinterface
 *       is a single dot1q vlan with vlan id <id> and exact-match semantics.
 *
 * <intf-name> <min_id>-<max_id>
 *     - a set of the above subinterfaces, repeating for each id
 *       in the range <min_id> to <max_id>
 *
 * In the following, exact-match semantics (i.e. the number of vlan tags on the
 * packet must match the number of tags in the configuration) are used only if
 * the keyword exact-match is present. Non-exact match is the default.
 *
 * <intf-name> <id> dot1q <outer_id> [exact-match]
 *     - a subinterface with the name <intf-name>.<id>. The subinterface
 *       is a single dot1q vlan with vlan id <outer_id>.
 *
 * <intf-name> <id> dot1q any [exact-match]
 *     - a subinterface with the name <intf-name>.<id>. The subinterface
 *       is a single dot1q vlan with any vlan id.
 *
 * <intf-name> <id> dot1q <outer_id> inner-dot1q <inner_id> [exact-match]
 *     - a subinterface with the name <intf-name>.<id>. The subinterface
 *       is a double dot1q vlan with outer vlan id <outer_id> and inner vlan id
 *       <inner_id>.
 *
 * <intf-name> <id> dot1q <outer_id> inner-dot1q any [exact-match]
 *     - a subinterface with the name <intf-name>.<id>. The subinterface
 *       is a double dot1q vlan with outer vlan id <id> and any inner vlan id.
 *
 * <intf-name> <id> dot1q any inner-dot1q any [exact-match]
 *
 *     - a subinterface with the name <intf-name>.<id>. The subinterface
 *       is a double dot1q vlan with any outer vlan id and any inner vlan id.
 *
 * For each of the above CLI, there is a duplicate that uses the keyword
 * "dot1ad" in place of the first "dot1q". These interfaces use ethertype
 * 0x88ad in place of 0x8100 for the outer ethertype. Note that for double-
 * tagged packets the inner ethertype is always 0x8100. Also note that
 * the dot1q and dot1ad naming spaces are independent, so it is legal to
 * have both "Gig3/0/0.1 dot1q 100" and "Gig3/0/0.2 dot1ad 100". For example:
 *
 * <intf-name> <id> dot1ad <outer_id> inner-dot1q <inner_id> [exact-match]
 *     - a subinterface with the name <intf-name>.<id>. The subinterface
 *       is a double dot1ad vlan with outer vlan id <outer_id> and inner vlan
 *       id <inner_id>.
 *
 * <intf-name> <id> untagged
 *     - a subinterface with the name <intf-name>.<id>. The subinterface
 *       has no vlan tags. Only one can be specified per interface.
 *
 * <intf-name> <id> default
 *     - a subinterface with the name <intf-name>.<id>. This is associated
 *       with a packet that did not match any other configured subinterface
 *       on this interface. Only one can be specified per interface.
 */

enum
{
  SUB_KIND_DEFAULT,
  SUB_KIND_UNTAGGED,
  SUB_KIND_DOT1Q,
  SUB_KIND_DOT1AD,
};

static clib_error_t *
parse_vlan_sub_interface (cli_ctx_t *ctx, vnet_sw_interface_t *template)
{
  cli_value_t *outer = cli_get (ctx, "outer"), *inner = cli_get (ctx, "inner-dot1q");

  if (!outer)
    return clib_error_return (0, "expected the outer vlan id or any");

  if (outer->u64 == VLAN_ID_ANY)
    {
      if (inner && inner->u64 != VLAN_ID_ANY)
	return clib_error_return (0, "an inner vlan id needs an outer vlan id");
      template->sub.eth.flags.outer_vlan_id_any = 1;
      template->sub.eth.flags.one_tag = !inner;
      template->sub.eth.flags.two_tags = !!inner;
      template->sub.eth.flags.inner_vlan_id_any = !!inner;
    }
  else
    {
      template->sub.eth.outer_vlan_id = outer->u64;
      if (!inner)
	template->sub.eth.flags.one_tag = 1;
      else
	{
	  template->sub.eth.flags.two_tags = 1;
	  if (inner->u64 == VLAN_ID_ANY)
	    template->sub.eth.flags.inner_vlan_id_any = 1;
	  else
	    template->sub.eth.inner_vlan_id = inner->u64;
	}
    }

  template->sub.eth.flags.exact_match = cli_flag (ctx, "exact-match");
  return 0;
}

static clib_error_t *
create_sub_interfaces (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 hw_if_index = cli_index (ctx, "interface"), sw_if_index;
  u32 kind = cli_index (ctx, "kind");
  cli_value_t *id_value = cli_get (ctx, "id");
  u32 id_min = id_value->range.start, id_max = id_value->range.stop;
  vnet_hw_interface_t *hi;
  u32 id;
  vnet_sw_interface_t template = {};

  if (kind != ~0 && id_min != id_max)
    return clib_error_return (
      0, "a range of ids can not be used with default, untagged, dot1q or dot1ad");

  if (kind == ~0)
    {
      template.sub.eth.flags.one_tag = 1;
      template.sub.eth.flags.exact_match = 1;
      template.sub.eth.outer_vlan_id = id_min;
    }
  else if (kind == SUB_KIND_DEFAULT)
    template.sub.eth.flags.default_sub = 1;
  else if (kind == SUB_KIND_UNTAGGED)
    {
      template.sub.eth.flags.no_tags = 1;
      template.sub.eth.flags.exact_match = 1;
    }
  else
    {
      if (kind == SUB_KIND_DOT1AD)
	template.sub.eth.flags.dot1ad = 1;
      error = parse_vlan_sub_interface (ctx, &template);
      if (error)
	return error;
    }

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  if (hi->bond_info == VNET_HW_INTERFACE_BOND_INFO_SLAVE)
    return clib_error_return (0, "not allowed as %v belong to a BondEthernet interface", hi->name);

  for (id = id_min; id <= id_max; id++)
    {
      uword *p;
      vnet_interface_main_t *im = &vnm->interface_main;
      u64 sup_and_sub_key = ((u64) (hi->sw_if_index) << 32) | (u64) id;
      u64 *kp;

      p = hash_get_mem (im->sw_if_index_by_sup_and_sub, &sup_and_sub_key);
      if (p)
	{
	  if (CLIB_DEBUG > 0)
	    clib_warning ("sup sw_if_index %d, sub id %d already exists\n", hi->sw_if_index, id);
	  continue;
	}

      template.type = VNET_SW_INTERFACE_TYPE_SUB;
      template.flood_class = VNET_FLOOD_CLASS_NORMAL;
      template.sup_sw_if_index = hi->sw_if_index;
      template.sub.id = id;
      if (id_min < id_max)
	template.sub.eth.outer_vlan_id = id;

      error = vnet_create_sw_interface (vnm, &template, &sw_if_index);
      if (error)
	return error;

      kp = clib_mem_alloc (sizeof (*kp));
      *kp = sup_and_sub_key;

      hash_set (hi->sub_interface_sw_if_index_by_id, id, sw_if_index);
      hash_set_mem (im->sw_if_index_by_sup_and_sub, kp, sw_if_index);
      vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index);
    }

  return 0;
}

/*?
 * This command is used to add VLAN IDs to interfaces, also known as subinterfaces.
 * The primary input to this command is the '<em>interface</em>' and '<em>subId</em>'
 * (subinterface Id) parameters. If no additional VLAN ID is provide, the VLAN ID is
 * assumed to be the '<em>subId</em>'. The VLAN ID and '<em>subId</em>' can be different,
 * but this is not recommended.
 *
 * This command has several variations:
 * - <b>create sub-interfaces <interface> <subId></b> - Create a subinterface to
 * process packets with a given 802.1q VLAN ID (same value as the '<em>subId</em>').
 *
 * - <b>create sub-interfaces <interface> <subId> default</b> - Adding the
 * '<em>default</em>' parameter indicates that packets with VLAN IDs that do not
 * match any other subinterfaces should be sent to this subinterface.
 *
 * - <b>create sub-interfaces <interface> <subId> untagged</b> - Adding the
 * '<em>untagged</em>' parameter indicates that packets no VLAN IDs should be sent
 * to this subinterface.
 *
 * - <b>create sub-interfaces <interface> <subId>-<subId></b> - Create a range of
 * subinterfaces to handle a range of VLAN IDs.
 *
 * - <b>create sub-interfaces <interface> <subId> dot1q|dot1ad <vlanId>|any [exact-match]</b> -
 * Use this command to specify the outer VLAN ID, to either be explicit or to make the
 * VLAN ID different from the '<em>subId</em>'.
 *
 * - <b>create sub-interfaces <interface> <subId> dot1q|dot1ad <vlanId>|any inner-dot1q
 * <vlanId>|any [exact-match]</b> - Use this command to specify the outer VLAN ID and
 * the inner VLAN ID.
 *
 * When '<em>dot1q</em>' or '<em>dot1ad</em>' is explicitly entered, subinterfaces
 * can be configured as either exact-match or non-exact match. Non-exact match is the CLI
 * default. If '<em>exact-match</em>' is specified, packets must have the same number of
 * VLAN tags as the configuration. For non-exact-match, packets must at least that number
 * of tags. L3 (routed) interfaces must be configured as exact-match. L2 interfaces are
 * typically configured as non-exact-match. If '<em>dot1q</em>' or '<em>dot1ad</em>' is NOT
 * entered, then the default behavior is exact-match.
 *
 * Use the '<em>show interface</em>' command to display all subinterfaces.
 *
 * @cliexpar
 * @parblock
 * Example of how to create a VLAN subinterface 11 to process packets on 802.1q VLAN ID 11:
 * @cliexcmd{create sub-interfaces GigabitEthernet2/0/0 11}
 *
 * The previous example is shorthand and is equivalent to:
 * @cliexcmd{create sub-interfaces GigabitEthernet2/0/0 11 dot1q 11 exact-match}
 *
 *
 * Example of how to create a subinterface number that is different from the VLAN ID:
 * @cliexcmd{create sub-interfaces GigabitEthernet2/0/0 11 dot1q 100}
 *
 *
 * Examples of how to create q-in-q and q-in-any subinterfaces:
 * @cliexcmd{create sub-interfaces GigabitEthernet2/0/0 11 dot1q 100 inner-dot1q 200}
 * @cliexcmd{create sub-interfaces GigabitEthernet2/0/0 12 dot1q 100 inner-dot1q any}
 *
 * Examples of how to create dot1ad interfaces:
 * @cliexcmd{create sub-interfaces GigabitEthernet2/0/0 11 dot1ad 11}
 * @cliexcmd{create sub-interfaces GigabitEthernet2/0/0 12 dot1ad 100 inner-dot1q 200}
 *
 *
 * Examples of '<em>exact-match</em>' versus non-exact match. A packet with
 * outer VLAN 100 and inner VLAN 200 would match this interface, because the default
 * is non-exact match:
 * @cliexcmd{create sub-interfaces GigabitEthernet2/0/0 5 dot1q 100}
 *
 * However, the same packet would NOT match this interface because '<em>exact-match</em>'
 * is specified and only one VLAN is configured, but packet contains two VLANs:
 * @cliexcmd{create sub-interfaces GigabitEthernet2/0/0 5 dot1q 100 exact-match}
 *
 *
 * Example of how to created a subinterface to process untagged packets:
 * @cliexcmd{create sub-interfaces GigabitEthernet2/0/0 5 untagged}
 *
 * Example of how to created a subinterface to process any packet with a VLAN ID that
 * does not match any other subinterface:
 * @cliexcmd{create sub-interfaces GigabitEthernet2/0/0 7 default}
 *
 * When subinterfaces are created, they are in the down state. Example of how to
 * enable a newly created subinterface:
 * @cliexcmd{set interface GigabitEthernet2/0/0.7 up}
 * @endparblock
 ?*/
VLIB_CLI_COMMAND (create_sub_interfaces_command, static) = {
  .path = "create sub-interfaces",
  .short_help = "Create sub-interfaces",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_hw_interface),
      CLI_VALUE ("id", cli_type_sub_id),
      CLI_ENUM ("kind", CLI_F_OPTIONAL,
		{ "default", "packets which match no other sub-interface", SUB_KIND_DEFAULT },
		{ "untagged", "packets without vlan tags", SUB_KIND_UNTAGGED },
		{ "dot1q", "802.1q vlan tags", SUB_KIND_DOT1Q },
		{ "dot1ad", "802.1ad outer vlan tag", SUB_KIND_DOT1AD }),
      CLI_VALUE ("outer", cli_type_vlan, .flags = CLI_F_OPTIONAL, .requires = "kind",
		 .help = "outer vlan id or any"),
      CLI_KEYWORD ("inner-dot1q", cli_type_vlan, .flags = CLI_F_OPTIONAL, .requires = "outer",
		   .help = "inner vlan id or any"),
      CLI_FLAG ("exact-match", .help = "the number of tags must match"),
      {},
    },
  .handler = create_sub_interfaces,
};

static clib_error_t *
set_state (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();

  return vnet_sw_interface_set_flags (vnm, cli_index (ctx, "interface"), cli_index (ctx, "state"));
}

/*?
 * This command is used to change the admin state (up/down) of an interface.
 *
 * If an interface is down, the optional '<em>punt</em>' flag can also be set.
 * The '<em>punt</em>' flag implies the interface is disabled for forwarding
 * but punt all traffic to slow-path. Use the '<em>enable</em>' flag to clear
 * '<em>punt</em>' flag (interface is still down).
 *
 * @cliexpar
 * Example of how to configure the admin state of an interface to
 '<em>up</em>':
 * @cliexcmd{set interface state GigabitEthernet2/0/0 up}
 * Example of how to configure the admin state of an interface to
 '<em>down</em>':
 * @cliexcmd{set interface state GigabitEthernet2/0/0 down}
 ?*/
VLIB_CLI_COMMAND (set_state_command, static) = {
  .path = "set interface state",
  .short_help = "Set the admin state of an interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_sw_interface),
      CLI_ENUM ("state", 0, { "up", "admin up", VNET_SW_INTERFACE_FLAG_ADMIN_UP },
		{ "down", "admin down", 0 },
		{ "punt", "admin down, punt traffic to slow path", VNET_SW_INTERFACE_FLAG_PUNT },
		{ "enable", "admin down, clear punt", 0 }),
      {},
    },
  .handler = set_state,
};

static clib_error_t *
set_unnumbered (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u32 unnumbered_sw_if_index, inherit_from_sw_if_index = ~0;
  int enable = !cli_get (ctx, "del");

  if (enable)
    {
      unnumbered_sw_if_index = cli_index (ctx, "interface");
      inherit_from_sw_if_index = cli_index (ctx, "use");
    }
  else
    unnumbered_sw_if_index = cli_index (ctx, "del");

  int rv =
    vnet_sw_interface_update_unnumbered (unnumbered_sw_if_index, inherit_from_sw_if_index, enable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_UNEXPECTED_INTF_STATE:
      return clib_error_return (
	0, "When enabling unnumbered both interfaces must be in the same tables");

    default:
      return clib_error_return (0, "vnet_sw_interface_update_unnumbered returned %d", rv);
    }

  return (NULL);
}

VLIB_CLI_COMMAND (set_unnumbered_command, static) = {
  .path = "set interface unnumbered",
  .short_help = "Make an interface use the IP address of another interface",
  .args =
    (cli_arg_t[]) {
      CLI_ONEOF ("action", 0,
		 CLI_SEQ (CLI_VALUE ("interface", cli_type_sw_interface,
				     .help = "interface which becomes unnumbered"),
			  CLI_KEYWORD ("use", cli_type_sw_interface,
				       .help = "interface with the IP address")),
		 CLI_KEYWORD ("del", cli_type_sw_interface, .help = "interface to make numbered")),
      {},
    },
  .handler = set_unnumbered,
};

static clib_error_t *
set_hw_class (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return vnet_hw_interface_set_class (vnet_get_main (), cli_index (ctx, "interface"),
				      cli_index (ctx, "class"));
}

VLIB_CLI_COMMAND (set_hw_class_command, static) = {
  .path = "set interface hw-class",
  .short_help = "Set interface hardware class",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_hw_interface),
      CLI_VALUE ("class", cli_type_hw_class),
      {},
    },
  .handler = set_hw_class,
};

static clib_error_t *
vnet_interface_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (vnet_interface_cli_init);

static clib_error_t *
renumber_interface_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  int rv = vnet_interface_name_renumber (cli_index (ctx, "interface"),
					 cli_u64 (ctx, "new-dev-instance", 0));

  if (rv)
    return clib_error_return (0, "vnet_interface_name_renumber returned %d", rv);

  return 0;
}

VLIB_CLI_COMMAND (renumber_interface_command, static) = {
  .path = "renumber interface",
  .short_help = "Renumber the device instance of an interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_hw_interface),
      CLI_VALUE ("new-dev-instance", cli_type_u32),
      {},
    },
  .handler = renumber_interface_command_fn,
};

static clib_error_t *
promiscuous_cmd (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index = cli_index (ctx, "interface");
  u32 flags = cli_index (ctx, "state") ? ETHERNET_INTERFACE_FLAG_ACCEPT_ALL : 0;
  ethernet_main_t *em = &ethernet_main;
  ethernet_interface_t *eif;

  eif = ethernet_get_interface (em, hw_if_index);
  if (!eif)
    return clib_error_return (0, "not supported");

  ethernet_set_flags (vnm, hw_if_index, flags);
  return 0;
}

VLIB_CLI_COMMAND (set_interface_promiscuous_cmd, static) = {
  .path = "set interface promiscuous",
  .short_help = "Set the promiscuous mode of an Ethernet interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("state", cli_type_bool),
      CLI_VALUE ("interface", cli_type_hw_interface),
      {},
    },
  .handler = promiscuous_cmd,
};

static clib_error_t *
mtu_cmd (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 mtu = cli_u64 (ctx, "mtu", 0);
  u32 mtus[VNET_N_MTU] = { 0, 0, 0, 0 };
  u32 hw_if_index = cli_index (ctx, "hw-interface");
  u32 sw_if_index = cli_index (ctx, "interface");
  u32 proto = cli_index (ctx, "protocol");

  if (hw_if_index != ~0)
    {
      /*
       * Change physical MTU on interface. Only supported for Ethernet
       * interfaces
       */
      if (!ethernet_get_interface (&ethernet_main, hw_if_index))
	return clib_error_return (0, "not supported");

      return vnet_hw_interface_set_mtu (vnm, hw_if_index, mtu);
    }

  /* Set default packet MTU (including L3 header) or a per protocol one */
  mtus[proto] = mtu;
  vnet_sw_interface_set_protocol_mtu (vnm, sw_if_index, mtus);
  return 0;
}

VLIB_CLI_COMMAND (set_interface_mtu_cmd, static) = {
  .path = "set interface mtu",
  .short_help = "Set the physical or the protocol MTU of an interface",
  .args =
    (cli_arg_t[]) {
      CLI_ONEOF (
	"scope", 0,
	CLI_SEQ (CLI_VALUE ("mtu", cli_type_u32, .min = 64, .max = 65535, .help = "physical MTU"),
		 CLI_VALUE ("hw-interface", cli_type_hw_interface)),
	CLI_SEQ (CLI_ENUM ("protocol", 0, { "packet", "L3 packet MTU", VNET_MTU_L3 },
			   { "ip4", "IPv4 MTU", VNET_MTU_IP4 }, { "ip6", "IPv6 MTU", VNET_MTU_IP6 },
			   { "mpls", "MPLS MTU", VNET_MTU_MPLS }),
		 CLI_VALUE ("mtu", cli_type_u32, .help = "protocol MTU"),
		 CLI_VALUE ("interface", cli_type_sw_interface))),
      {},
    },
  .handler = mtu_cmd,
};

static clib_error_t *
show_interface_sec_mac_addr_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  ethernet_main_t *em = &ethernet_main;
  u32 sw_if_index = cli_index (ctx, "interface");
  vnet_sw_interface_t *si, *sorted_sis = 0;

  if (sw_if_index != ~0)
    {
      si = pool_elt_at_index (im->sw_interfaces, sw_if_index);
      vec_add1 (sorted_sis, si[0]);
    }

  /* if an interface name was not passed, get all interfaces */
  if (vec_len (sorted_sis) == 0)
    {
      sorted_sis = vec_new (vnet_sw_interface_t, pool_elts (im->sw_interfaces));
      vec_set_len (sorted_sis, 0);
      pool_foreach (si, im->sw_interfaces)
	{
	  int visible = vnet_swif_is_api_visible (si);
	  if (visible)
	    vec_add1 (sorted_sis, si[0]);
	}
      /* Sort by name. */
      vec_sort_with_function (sorted_sis, sw_interface_name_compare);
    }

  vec_foreach (si, sorted_sis)
    {
      vnet_sw_interface_t *sup_si;
      ethernet_interface_t *ei;

      sup_si = vnet_get_sup_sw_interface (vnm, si->sw_if_index);
      ei = ethernet_get_interface (em, sup_si->hw_if_index);

      vlib_cli_output (vm, "%U (%s):", format_vnet_sw_if_index_name, vnm, si->sw_if_index,
		       (si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? "up" : "dn");

      if (ei && ei->secondary_addrs)
	{
	  ethernet_interface_address_t *sec_addr;

	  vec_foreach (sec_addr, ei->secondary_addrs)
	    {
	      vlib_cli_output (vm, "  %U", format_mac_address_t, &sec_addr->mac);
	    }
	}
    }

  vec_free (sorted_sis);
  return 0;
}

/*?
 * This command is used to display interface secondary mac addresses.
 *
 * @cliexpar
 * Example of how to display interface secondary mac addresses:
 * @cliexstart{show interface secondary-mac-address}
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_interface_sec_mac_addr, static) = {
  .path = "show interface secondary-mac-address",
  .short_help = "Show the secondary MAC addresses of the interfaces",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_sw_interface, .flags = CLI_F_OPTIONAL),
      {},
    },
  .handler = show_interface_sec_mac_addr_fn,
};

static clib_error_t *
interface_add_del_mac_address (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, cli_index (ctx, "interface"));

  return vnet_hw_interface_add_del_mac_address (
    vnm, si->hw_if_index, cli_get (ctx, "mac-address")->prefix.addr, cli_index (ctx, "action"));
}

/*?
 * The '<em>set interface secondary-mac-address </em>' command allows adding
 * or deleting extra MAC addresses on a given interface without changing the
 * default MAC address. This could allow packets sent to these MAC addresses
 * to be received without setting the interface to promiscuous mode.
 * Not all interfaces support this operation. The ones that do are mostly
 * hardware NICs, though virtio does also.
 *
 * @cliexpar
 * @parblock
 * Example of how to add a secondary MAC Address on an interface:
 * @cliexcmd{set interface secondary-mac-address GigabitEthernet0/8/0 aa:bb:cc:dd:ee:01 add}
 * Example of how to delete a secondary MAC address from an interface:
 * @cliexcmd{set interface secondary-mac-address GigabitEthernet0/8/0 aa:bb:cc:dd:ee:01 del}
 * @endparblock
?*/
VLIB_CLI_COMMAND (interface_add_del_mac_address_cmd, static) = {
  .path = "set interface secondary-mac-address",
  .short_help = "Add or delete a secondary MAC address of an interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_sw_interface),
      CLI_VALUE ("mac-address", cli_type_mac_address),
      CLI_ENUM ("action", 0, { "add", "add the address", 1 }, { "del", "delete the address", 0 }),
      {},
    },
  .handler = interface_add_del_mac_address,
};

static clib_error_t *
set_interface_mac_address (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, cli_index (ctx, "interface"));

  return vnet_hw_interface_change_mac_address (vnm, si->hw_if_index,
					       cli_get (ctx, "mac-address")->prefix.addr);
}

/*?
 * The '<em>set interface mac address </em>' command allows to set MAC address of given interface.
 * In case of NIC interfaces the one has to support MAC address change. A side effect of MAC address
 * change are changes of MAC addresses in FIB tables (ipv4 and ipv6).
 *
 * @cliexpar
 * @parblock
 * Example of how to change MAC Address of interface:
 * @cliexcmd{set interface mac address GigabitEthernet0/8/0 aa:bb:cc:dd:ee:01}
 * @cliexcmd{set interface mac address host-vpp0 aa:bb:cc:dd:ee:02}
 * @cliexcmd{set interface mac address tap-0 aa:bb:cc:dd:ee:03}
 * @cliexcmd{set interface mac address pg0 aa:bb:cc:dd:ee:04}
 * @endparblock
?*/
VLIB_CLI_COMMAND (set_interface_mac_address_cmd, static) = {
  .path = "set interface mac address",
  .short_help = "Set the MAC address of an interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_sw_interface),
      CLI_VALUE ("mac-address", cli_type_mac_address),
      {},
    },
  .handler = set_interface_mac_address,
};

static clib_error_t *
set_tag (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u8 *tag = format (0, "%v%c", cli_get (ctx, "tag")->str, 0);

  vnet_set_sw_interface_tag (vnet_get_main (), tag, cli_index (ctx, "interface"));

  return 0;
}

VLIB_CLI_COMMAND (set_tag_command, static) = {
  .path = "set interface tag",
  .short_help = "Set the tag of an interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_sw_interface),
      CLI_VALUE ("tag", cli_type_string),
      {},
    },
  .handler = set_tag,
};

static clib_error_t *
clear_tag (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_clear_sw_interface_tag (vnet_get_main (), cli_index (ctx, "interface"));

  return 0;
}

VLIB_CLI_COMMAND (clear_tag_command, static) = {
  .path = "clear interface tag",
  .short_help = "Clear the tag of an interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_sw_interface),
      {},
    },
  .handler = clear_tag,
};

static clib_error_t *
set_ip_directed_broadcast (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_sw_interface_ip_directed_broadcast (vnet_get_main (), cli_index (ctx, "interface"),
					   cli_index (ctx, "state"));

  return 0;
}

/*?
 * This command is used to enable/disable IP directed broadcast
 * If directed broadcast is enabled a packet sent to the interface's
 * subnet broadcast address will be sent L2 broadcast on the interface,
 * otherwise it is dropped.
 ?*/
VLIB_CLI_COMMAND (set_ip_directed_broadcast_command, static) = {
  .path = "set interface ip directed-broadcast",
  .short_help = "Enable or disable the forwarding of IP directed broadcasts on an interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_sw_interface),
      CLI_VALUE ("state", cli_type_bool),
      {},
    },
  .handler = set_ip_directed_broadcast,
};

clib_error_t *
set_hw_interface_change_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
				 u8 queue_id_valid, u32 queue_id,
				 vnet_hw_if_rx_mode mode)
{
  clib_error_t *error = 0;
  vnet_hw_interface_t *hw;
  u32 *queue_indices = 0;
  vnet_dev_port_t *port;

  port = vnet_dev_get_port_from_hw_if_index (hw_if_index);

  if (port)
    {
      vlib_main_t *vm = vlib_get_main ();
      vnet_dev_rv_t rv;

      vnet_dev_port_cfg_change_req_t req = {
	.type = mode == VNET_HW_IF_RX_MODE_POLLING ?
			VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE :
			VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE,
	.queue_id = queue_id_valid ? queue_id : 0,
	.all_queues = queue_id_valid ? 0 : 1,
      };

      if ((rv = vnet_dev_port_cfg_change_req_validate (vm, port, &req)))
	return vnet_dev_port_err (
	  vm, port, rv, "rx queue interupt mode enable/disable not supported");

      if ((rv = vnet_dev_process_port_cfg_change_req (vm, port, &req)))
	return vnet_dev_port_err (
	  vm, port, rv,
	  "device failed to enable/disable queue interrupt mode");
      return 0;
    }

  hw = vnet_get_hw_interface (vnm, hw_if_index);

  if (queue_id_valid)
    {
      u32 queue_index;
      queue_index =
	vnet_hw_if_get_rx_queue_index_by_id (vnm, hw_if_index, queue_id);
      if (queue_index == ~0)
	return clib_error_return (0, "unknown queue %u on interface %s",
				  queue_id, hw->name);
      vec_add1 (queue_indices, queue_index);
    }
  else
    queue_indices = hw->rx_queue_indices;

  for (int i = 0; i < vec_len (queue_indices); i++)
    {
      int rv = vnet_hw_if_set_rx_queue_mode (vnm, queue_indices[i], mode);
      if (rv)
	{
	  error = clib_error_return (
	    0, "unable to set rx-mode on interface %v queue-id %u.\n",
	    hw->name, queue_id);
	  goto done;
	}
    }

done:
  if (queue_indices != hw->rx_queue_indices)
    vec_free (queue_indices);
  vnet_hw_if_update_runtime_data (vnm, hw_if_index);
  return error;
}

static clib_error_t *
set_interface_rx_mode (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return set_hw_interface_change_rx_mode (vnet_get_main (), cli_index (ctx, "interface"),
					  cli_get (ctx, "queue") != 0, cli_u64 (ctx, "queue", 0),
					  cli_index (ctx, "mode"));
}

/*?
 * This command is used to assign the RX packet processing mode (polling,
 * interrupt, adaptive) of the a given interface, and optionally a
 * given queue. If the '<em>queue</em>' is not provided, the '<em>mode</em>'
 * is applied to all queues of the interface. Not all interfaces support
 * all modes. To display the current rx-mode use the command
 * '<em>show interface rx-placement</em>'.
 *
 * @cliexpar
 * Example of how to assign rx-mode to all queues on an interface:
 * @cliexcmd{set interface rx-mode VirtualEthernet0/0/12 polling}
 * Example of how to assign rx-mode to one queue of an interface:
 * @cliexcmd{set interface rx-mode VirtualEthernet0/0/12 queue 0 interrupt}
 * Example of how to display the rx-mode of all interfaces:
 * @cliexstart{show interface rx-placement}
 * Thread 1 (vpp_wk_0):
 *   node dpdk-input:
 *     GigabitEthernet7/0/0 queue 0 (polling)
 *   node vhost-user-input:
 *     VirtualEthernet0/0/12 queue 0 (interrupt)
 *     VirtualEthernet0/0/12 queue 2 (polling)
 *     VirtualEthernet0/0/13 queue 0 (polling)
 *     VirtualEthernet0/0/13 queue 2 (polling)
 * Thread 2 (vpp_wk_1):
 *   node dpdk-input:
 *     GigabitEthernet7/0/1 queue 0 (polling)
 *   node vhost-user-input:
 *     VirtualEthernet0/0/12 queue 1 (polling)
 *     VirtualEthernet0/0/12 queue 3 (polling)
 *     VirtualEthernet0/0/13 queue 1 (polling)
 *     VirtualEthernet0/0/13 queue 3 (polling)
 * @cliexend
?*/
VLIB_CLI_COMMAND (cmd_set_if_rx_mode, static) = {
  .path = "set interface rx-mode",
  .short_help = "Set the rx mode of the queues of an interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_hw_interface),
      CLI_ENUM ("mode", 0, { "polling", "poll the queue", VNET_HW_IF_RX_MODE_POLLING },
		{ "interrupt", "wait for interrupts", VNET_HW_IF_RX_MODE_INTERRUPT },
		{ "adaptive", "interrupt when idle, poll when busy", VNET_HW_IF_RX_MODE_ADAPTIVE }),
      CLI_KEYWORD ("queue", cli_type_u32, .flags = CLI_F_OPTIONAL,
		   .help = "only this queue, default all queues"),
      {},
    },
  .handler = set_interface_rx_mode,
};

static clib_error_t *
set_interface_default_rx_mode (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_if_rx_mode mode = cli_index (ctx, "mode");

  im->default_rx_mode = mode;
  vlib_cli_output (vm, "Default interface rx-mode set to %U", format_vnet_hw_if_rx_mode, mode);
  return 0;
}

VLIB_CLI_COMMAND (cmd_set_if_default_rx_mode, static) = {
  .path = "set interface default rx-mode",
  .short_help = "Set the rx mode of the interfaces created afterwards",
  .args =
    (cli_arg_t[]) {
      CLI_ENUM ("mode", 0, { "polling", "poll the queue", VNET_HW_IF_RX_MODE_POLLING },
		{ "interrupt", "wait for interrupts", VNET_HW_IF_RX_MODE_INTERRUPT },
		{ "adaptive", "interrupt when idle, poll when busy", VNET_HW_IF_RX_MODE_ADAPTIVE }),
      {},
    },
  .handler = set_interface_default_rx_mode,
};

static clib_error_t *
show_interface_default_rx_mode (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vlib_cli_output (vm, "Default interface rx-mode: %U", format_vnet_hw_if_rx_mode,
		   im->default_rx_mode);
  return 0;
}

VLIB_CLI_COMMAND (cmd_show_if_default_rx_mode, static) = {
  .path = "show interface default rx-mode",
  .short_help = "Show the rx mode of the interfaces created afterwards",
  .handler = show_interface_default_rx_mode,
};

static clib_error_t *
show_interface_rx_placement_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u8 *s = 0;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_if_rx_queue_t **all_queues = 0;
  vnet_hw_if_rx_queue_t **qptr;
  vnet_hw_if_rx_queue_t *q;
  pool_foreach (q, vnm->interface_main.hw_if_rx_queues)
    vec_add1 (all_queues, q);
  vec_sort_with_function (all_queues, vnet_hw_if_rxq_cmp_cli_api);
  u32 prev_node = ~0;

  vec_foreach (qptr, all_queues)
    {
      u32 current_thread = qptr[0]->thread_index;
      u32 hw_if_index = qptr[0]->hw_if_index;
      vnet_hw_interface_t *hw_if = vnet_get_hw_interface (vnm, hw_if_index);
      u32 current_node = hw_if->input_node_index;
      if (current_node != prev_node)
	s = format (s, " node %U:\n", format_vlib_node_name, vm, current_node);
      s = format (s, "    %U queue %u (%U)\n", format_vnet_sw_if_index_name,
		  vnm, hw_if->sw_if_index, qptr[0]->queue_id,
		  format_vnet_hw_if_rx_mode, qptr[0]->mode);
      if (qptr == all_queues + vec_len (all_queues) - 1 ||
	  current_thread != qptr[1]->thread_index)
	{
	  vlib_cli_output (vm, "Thread %u (%s):\n%v", current_thread,
			   vlib_worker_threads[current_thread].name, s);
	  vec_reset_length (s);
	}
      prev_node = current_node;
    }
  vec_free (s);
  vec_free (all_queues);
  return 0;
}

/*?
 * This command is used to display the interface and queue worker
 * thread placement.
 *
 * @cliexpar
 * Example of how to display the interface placement:
 * @cliexstart{show interface rx-placement}
 * Thread 1 (vpp_wk_0):
 *   node dpdk-input:
 *     GigabitEthernet7/0/0 queue 0 (polling)
 *   node vhost-user-input:
 *     VirtualEthernet0/0/12 queue 0 (polling)
 *     VirtualEthernet0/0/12 queue 2 (polling)
 *     VirtualEthernet0/0/13 queue 0 (polling)
 *     VirtualEthernet0/0/13 queue 2 (polling)
 * Thread 2 (vpp_wk_1):
 *   node dpdk-input:
 *     GigabitEthernet7/0/1 queue 0 (polling)
 *   node vhost-user-input:
 *     VirtualEthernet0/0/12 queue 1 (polling)
 *     VirtualEthernet0/0/12 queue 3 (polling)
 *     VirtualEthernet0/0/13 queue 1 (polling)
 *     VirtualEthernet0/0/13 queue 3 (polling)
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_interface_rx_placement, static) = {
  .path = "show interface rx-placement",
  .short_help = "Show the threads which poll the rx queues",
  .handler = show_interface_rx_placement_fn,
};
clib_error_t *
set_hw_interface_rx_placement (u32 hw_if_index, u32 queue_id,
			       clib_thread_index_t thread_index, u8 is_main)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_device_main_t *vdm = &vnet_device_main;
  vnet_hw_interface_t *hw;
  u32 queue_index;

  if (is_main)
    thread_index = 0;
  else
    thread_index += vdm->first_worker_thread_index;

  if (thread_index > vdm->last_worker_thread_index)
    return clib_error_return (0,
			      "please specify valid worker thread or main");

  hw = vnet_get_hw_interface (vnm, hw_if_index);

  queue_index =
    vnet_hw_if_get_rx_queue_index_by_id (vnm, hw_if_index, queue_id);
  if (queue_index == ~0)
    return clib_error_return (0, "unknown queue %u on interface %s", queue_id,
			      hw->name);
  vnet_hw_if_set_rx_queue_thread_index (vnm, queue_index, thread_index);
  vnet_hw_if_update_runtime_data (vnm, hw_if_index);
  return 0;
}

static clib_error_t *
set_interface_rx_placement (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u8 is_main = cli_flag (ctx, "main");

  return set_hw_interface_rx_placement (cli_index (ctx, "interface"), cli_u64 (ctx, "queue", 0),
					cli_u64 (ctx, "worker", ~0), is_main);
}

/*?
 * This command is used to assign a given interface, and optionally a
 * given queue, to a different thread. If the '<em>queue</em>' is not provided,
 * it defaults to 0. The '<em>worker</em>' parameter is zero based and the index
 * in the thread name, for example, 0 in the thread name '<em>vpp_wk_0</em>'.
 *
 * @cliexpar
 * Example of how to display the interface placement:
 * @cliexstart{show interface rx-placement}
 * Thread 1 (vpp_wk_0):
 *   node dpdk-input:
 *     GigabitEthernet7/0/0 queue 0 (polling)
 *   node vhost-user-input:
 *     VirtualEthernet0/0/12 queue 0 (polling)
 *     VirtualEthernet0/0/12 queue 2 (polling)
 *     VirtualEthernet0/0/13 queue 0 (polling)
 *     VirtualEthernet0/0/13 queue 2 (polling)
 * Thread 2 (vpp_wk_1):
 *   node dpdk-input:
 *     GigabitEthernet7/0/1 queue 0 (polling)
 *   node vhost-user-input:
 *     VirtualEthernet0/0/12 queue 1 (polling)
 *     VirtualEthernet0/0/12 queue 3 (polling)
 *     VirtualEthernet0/0/13 queue 1 (polling)
 *     VirtualEthernet0/0/13 queue 3 (polling)
 * @cliexend
 * Example of how to assign a interface and queue to a worker thread:
 * @cliexcmd{set interface rx-placement VirtualEthernet0/0/12 queue 1 worker 0}
 * Example of how to display the interface placement:
 * @cliexstart{show interface rx-placement}
 * Thread 1 (vpp_wk_0):
 *   node dpdk-input:
 *     GigabitEthernet7/0/0 queue 0 (polling)
 *   node vhost-user-input:
 *     VirtualEthernet0/0/12 queue 0 (polling)
 *     VirtualEthernet0/0/12 queue 1 (polling)
 *     VirtualEthernet0/0/12 queue 2 (polling)
 *     VirtualEthernet0/0/13 queue 0 (polling)
 *     VirtualEthernet0/0/13 queue 2 (polling)
 * Thread 2 (vpp_wk_1):
 *   node dpdk-input:
 *     GigabitEthernet7/0/1 queue 0 (polling)
 *   node vhost-user-input:
 *     VirtualEthernet0/0/12 queue 3 (polling)
 *     VirtualEthernet0/0/13 queue 1 (polling)
 *     VirtualEthernet0/0/13 queue 3 (polling)
 * @cliexend
?*/
VLIB_CLI_COMMAND (cmd_set_if_rx_placement, static) = {
  .path = "set interface rx-placement",
  .short_help = "Set the thread which polls an rx queue",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_hw_interface),
      CLI_KEYWORD ("queue", cli_type_u32, .flags = CLI_F_OPTIONAL, .help = "queue id, default 0"),
      CLI_ONEOF ("thread", 0, CLI_KEYWORD ("worker", cli_type_u32, .help = "worker thread number"),
		 CLI_FLAG ("main", .help = "the main thread")),
      {},
    },
  .handler = set_interface_rx_placement,
  .is_mp_safe = 1,
};

int
set_hw_interface_tx_queue (u32 hw_if_index, u32 queue_id, uword *bitmap)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  vnet_hw_if_tx_queue_t *txq;
  u32 queue_index;
  clib_thread_index_t thread_index;

  /* highest set bit in bitmap should not exceed last worker thread index */
  thread_index = clib_bitmap_last_set (bitmap);
  if ((thread_index != CLIB_INVALID_THREAD_INDEX) &&
      (thread_index >= vtm->n_vlib_mains))
    return VNET_API_ERROR_INVALID_VALUE;

  queue_index =
    vnet_hw_if_get_tx_queue_index_by_id (vnm, hw_if_index, queue_id);
  if (queue_index == ~0)
    return VNET_API_ERROR_INVALID_QUEUE;

  txq = vnet_hw_if_get_tx_queue (vnm, queue_index);

  // free the existing bitmap
  if (clib_bitmap_count_set_bits (txq->threads))
    {
      txq->shared_queue = 0;
      clib_bitmap_free (txq->threads);
    }

  clib_bitmap_foreach (thread_index, bitmap)
    vnet_hw_if_tx_queue_assign_thread (vnm, queue_index, thread_index);

  vnet_hw_if_update_runtime_data (vnm, hw_if_index);
  return 0;
}

static clib_error_t *
set_interface_tx_queue (vlib_main_t *vm, cli_ctx_t *ctx)
{
  clib_error_t *error = 0;
  u32 hw_if_index = cli_index (ctx, "interface");
  u32 queue_id = cli_u64 (ctx, "queue", 0);
  cli_value_t *threads = cli_get (ctx, "threads");
  uword *bitmap = threads ? (uword *) threads->str : 0;
  int rv = set_hw_interface_tx_queue (hw_if_index, queue_id, bitmap);

  switch (rv)
    {
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "please specify valid thread(s) - last thread index %u",
				 clib_bitmap_last_set (bitmap));
      break;
    case VNET_API_ERROR_INVALID_QUEUE:
      error = clib_error_return (0, "unknown queue %u on interface %s", queue_id,
				 vnet_get_hw_interface (vnet_get_main (), hw_if_index)->name);
      break;
    default:
      break;
    }

  return error;
}

VLIB_CLI_COMMAND (cmd_set_if_tx_queue, static) = {
  .path = "set interface tx-queue",
  .short_help = "Set the threads which use a tx queue",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_hw_interface),
      CLI_KEYWORD ("queue", cli_type_u32, .flags = CLI_F_OPTIONAL, .help = "queue id, default 0"),
      CLI_KEYWORD ("threads", cli_type_bitmap, .flags = CLI_F_OPTIONAL,
		   .help = "threads which use the queue"),
      {},
    },
  .handler = set_interface_tx_queue,
  .is_mp_safe = 1,
};

clib_error_t *
set_interface_rss_queues (vlib_main_t * vm, u32 hw_if_index,
			  clib_bitmap_t * bitmap)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);

  return vnet_hw_interface_set_rss_queues (vnm, hi, bitmap);
}

static clib_error_t *
set_interface_rss_queues_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return set_interface_rss_queues (vm, cli_index (ctx, "interface"),
				   (clib_bitmap_t *) cli_get (ctx, "list")->str);
}

/*?
 * This command is used to set the rss queues of a given interface
 * Not all the interfaces support this operation.
 * To display the current rss queues, use the command
 * '<em>show hardware-interfaces</em>'.
 *
 * @cliexpar
 * Example of how to set the rss queues to 0,2-5,7 of an interface:
 * @cliexstart{set interface rss queues VirtualFunctionEthernet18/1/0 list 0,2-5,7}
 * @cliexend
?*/
VLIB_CLI_COMMAND (cmd_set_interface_rss_queues, static) = {
  .path = "set interface rss queues",
  .short_help = "Set the rx queues which receive the RSS traffic of an interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_hw_interface),
      CLI_KEYWORD ("list", cli_type_bitmap, .help = "queues, e.g. 0-3"),
      {},
    },
  .handler = set_interface_rss_queues_fn,
};

static u8 *
format_vnet_pcap (u8 * s, va_list * args)
{
  vnet_pcap_t *pp = va_arg (*args, vnet_pcap_t *);
  int type = va_arg (*args, int);
  int printed = 0;

  if (type == 0)
    {
      if (pp->pcap_rx_enable)
	{
	  s = format (s, "rx");
	  printed = 1;
	}
      if (pp->pcap_tx_enable)
	{
	  if (printed)
	    s = format (s, " and ");
	  s = format (s, "tx");
	  printed = 1;
	}
      if (pp->pcap_drop_enable)
	{
	  if (printed)
	    s = format (s, " and ");
	  s = format (s, "drop");
	  printed = 1;
	}

      if (printed && pp->pcap_filter_enable)
	{
	  s = format (s, "with filter");
	  printed = 1;
	}
      return s;
    }
  s = format (s, "unknown type %d!", type);
  return s;
}


int
vnet_pcap_dispatch_trace_configure (vnet_pcap_dispatch_trace_args_t * a)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  vnet_pcap_t *pp = &vnm->pcap;
  pcap_main_t *pm = &pp->pcap_main;
  vnet_classify_main_t *cm = &vnet_classify_main;

  if (a->status)
    {
      if (pp->pcap_rx_enable || pp->pcap_tx_enable || pp->pcap_drop_enable)
	{
	  vlib_cli_output
	    (vm, "pcap %U dispatch capture enabled: %d of %d pkts...",
	     format_vnet_pcap, pp, 0 /* print type */ ,
	     pm->n_packets_captured, pm->n_packets_to_capture);
	  vlib_cli_output (vm, "capture to file %s", pm->file_name);
	}
      else
	vlib_cli_output (vm, "pcap dispatch capture disabled");

      return 0;
    }

  /* Consistency checks */

  /* Enable w/ capture already enabled not allowed */
  if ((pp->pcap_rx_enable + pp->pcap_tx_enable + pp->pcap_drop_enable)
      && (a->rx_enable + a->tx_enable + a->drop_enable))
    return VNET_API_ERROR_INVALID_VALUE;

  /* Disable capture with capture already disabled, not interesting */
  if (((pp->pcap_rx_enable + pp->pcap_tx_enable + pp->pcap_drop_enable) ==
       0) &&
      ((a->rx_enable + a->tx_enable + a->drop_enable == 0)))
    return VNET_API_ERROR_VALUE_EXIST;

  /* Change number of packets to capture while capturing */
  if ((pp->pcap_rx_enable + pp->pcap_tx_enable + pp->pcap_drop_enable)
      && (a->rx_enable + a->tx_enable + a->drop_enable)
      && (pm->n_packets_to_capture != a->packets_to_capture))
    return VNET_API_ERROR_INVALID_VALUE_2;

  if (a->rx_enable + a->tx_enable + a->drop_enable)
    {
      void *save_pcap_data;

      /* Sanity check max bytes per pkt */
      if (a->max_bytes_per_pkt < 32 || a->max_bytes_per_pkt > 9000)
	return VNET_API_ERROR_INVALID_MEMORY_SIZE;

      /* Clean up from previous run, if any */
      vec_reset_length (pm->pcap_data);

      /* Throw away the data buffer? */
      if (a->free_data)
	vec_free (pm->pcap_data);

      save_pcap_data = pm->pcap_data;

      memset (pm, 0, sizeof (*pm));

      pm->pcap_data = save_pcap_data;

      vec_validate_aligned (vnet_trace_placeholder, 2048,
			    CLIB_CACHE_LINE_BYTES);
      if (pm->lock == 0)
	clib_spinlock_init (&(pm->lock));

      if (a->filename == 0)
	{
	  u8 *stem = 0;

	  if (a->rx_enable)
	    stem = format (stem, "rx");
	  if (a->tx_enable)
	    stem = format (stem, "tx");
	  if (a->drop_enable)
	    stem = format (stem, "drop");
	  a->filename = format (0, "/tmp/%v.pcap%c", stem, 0);
	  vec_free (stem);
	}

      pm->file_name = (char *) a->filename;
      pm->n_packets_captured = 0;
      pm->packet_type = PCAP_PACKET_TYPE_ethernet;
      /* Preallocate the data vector? */
      if (a->preallocate_data)
	{
	  vec_validate
	    (pm->pcap_data, a->packets_to_capture
	     * ((sizeof (pcap_packet_header_t) + a->max_bytes_per_pkt)));
	  vec_reset_length (pm->pcap_data);
	}
      pm->n_packets_to_capture = a->packets_to_capture;
      pp->pcap_sw_if_index = a->sw_if_index;
      if (a->filter && cm->classify_table_index_by_sw_if_index &&
	  cm->classify_table_index_by_sw_if_index[0] != ~0)
	pp->filter_classify_table_index =
	  cm->classify_table_index_by_sw_if_index[0];
      else
	pp->filter_classify_table_index = ~0;
      pp->pcap_filter_enable = a->filter;
      pp->pcap_error_index = a->drop_err;
      pp->pcap_rx_enable = a->rx_enable;
      pp->pcap_tx_enable = a->tx_enable;
      pp->pcap_drop_enable = a->drop_enable;
      pp->max_bytes_per_pkt = a->max_bytes_per_pkt;
    }
  else
    {
      pp->pcap_filter_enable = 0;
      pp->pcap_rx_enable = 0;
      pp->pcap_tx_enable = 0;
      pp->pcap_drop_enable = 0;
      pp->filter_classify_table_index = ~0;
      pp->pcap_error_index = ~0;
      if (pm->n_packets_captured)
	{
	  clib_error_t *error;
	  pm->n_packets_to_capture = pm->n_packets_captured;
	  vlib_cli_output (vm, "Write %d packets to %s, and stop capture...",
			   pm->n_packets_captured, pm->file_name);
	  error = pcap_write (pm);
	  if (pm->flags & PCAP_MAIN_INIT_DONE)
	    pcap_close (pm);
	  /* Report I/O errors... */
	  if (error)
	    {
	      clib_error_report (error);
	      return VNET_API_ERROR_SYSCALL_ERROR_1;
	    }
	  vec_free (pm->file_name);
	  if (a->free_data)
	    vec_free (pm->pcap_data);
	  return 0;
	}
      else
	return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  return 0;
}

static clib_error_t *
pcap_trace_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_pcap_dispatch_trace_args_t _a, *a = &_a;
  cli_value_t *v;
  int rv;
  int off = cli_flag (ctx, "off");

  /* no need for memset (a, 0, sizeof (*a)), set all fields here. */
  a->filename = (v = cli_get (ctx, "file")) ? vec_dup (v->str) : 0;
  a->rx_enable = !off && cli_flag (ctx, "rx");
  a->tx_enable = !off && cli_flag (ctx, "tx");
  a->drop_enable = !off && cli_flag (ctx, "drop");
  a->preallocate_data = cli_flag (ctx, "preallocate-data");
  a->free_data = cli_flag (ctx, "free-data");
  a->status = cli_flag (ctx, "status");
  a->packets_to_capture = cli_u64 (ctx, "max", 1000);
  a->sw_if_index = cli_index (ctx, "interface") == ~0 ? 0 : cli_index (ctx, "interface");
  a->filter = cli_flag (ctx, "filter");
  a->max_bytes_per_pkt = cli_u64 (ctx, "max-bytes-per-pkt", 512);
  a->drop_err = (v = cli_get (ctx, "error")) ? v->u64 : ~0;

  rv = vnet_pcap_dispatch_trace_configure (a);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, "dispatch trace already enabled...");

    case VNET_API_ERROR_VALUE_EXIST:
      return clib_error_return (0, "dispatch trace already disabled...");

    case VNET_API_ERROR_INVALID_VALUE_2:
      return clib_error_return (0, "can't change number of records to capture while tracing...");

    case VNET_API_ERROR_SYSCALL_ERROR_1:
      return clib_error_return (0, "I/O writing trace capture...");

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "No packets captured...");

    case VNET_API_ERROR_INVALID_MEMORY_SIZE:
      return clib_error_return (0, "Max bytes per pkt must be > 32, < 9000...");

    default:
      vlib_cli_output (vm, "WARNING: trace configure returned %d", rv);
      break;
    }
  return 0;
}

/*?
 * This command is used to start or stop a packet capture, or show
 * the status of packet capture.
 *
 * This command has the following optional parameters:
 *
 *
 * - <b>rx</b> - Capture received packets
 *
 * - <b>tx</b> - Capture transmitted packets
 *
 * - <b>drop</b> - Capture dropped packets
 *
 * - <b>off</b> - Stop capturing packets, write results to the specified file
 *
 * - <b>max <nn></b> - Depth of local buffer. Once '<em>nn</em>' number
 *   of packets have been received, buffer is flushed to file. Once another
 *   '<em>nn</em>' number of packets have been received, buffer is flushed
 *   to file, overwriting previous write. If not entered, value defaults
 *   to 100. Can only be updated if packet capture is off.
 *
 * - <b>max-bytes-per-pkt <nnnn></b> - Maximum number of bytes to capture
 *   for each packet. Must be >= 32, <= 9000.
 *
 * - <b>preallocate-data</b> - Preallocate the data buffer, to avoid
 *   vector expansion delays during pcap capture
 *
 * - <b>free-data</b> - Free the data buffer. Ordinarily it's a feature
 *   to retain the data buffer so this option is seldom used.
 *
 * - <b>intfc <interface-name>|any</b> - Used to specify a given interface,
 *   or use '<em>any</em>' to run packet capture on all interfaces.
 *   '<em>any</em>' is the default if not provided. Settings from a previous
 *   packet capture are preserved, so '<em>any</em>' can be used to reset
 *   the interface setting.
 *
 * - <b>filter</b> - Use the pcap trace rx / tx / drop filter, which
 *   must be configured. Use <b>classify filter pcap...</b> to configure the
 *   filter. The filter will only be executed if the per-interface or
 *   any-interface tests fail.
 *
 * - <b>error <node>.<error></b> - filter packets based on a specific error.
 *   For example: error {ip4-udp-lookup}.{no_listener}
 *
 * - <b>file <name></b> - Used to specify the output filename. The file will
 *   be placed in the '<em>/tmp</em>' directory, so only the filename is
 *   supported. Directory should not be entered. If file already exists, file
 *   will be overwritten. If no filename is provided, the file will be
 *   named "/tmp/rx.pcap", "/tmp/tx.pcap", "/tmp/rxandtx.pcap", etc.
 *   Can only be updated if packet capture is off.
 *
 * - <b>status</b> - Displays the current status and configured attributes
 *   associated with a packet capture. If packet capture is in progress,
 *   '<em>status</em>' also will return the number of packets currently in
 *   the local buffer. All additional attributes entered on command line
 *   with '<em>status</em>' will be ignored and not applied.
 *
 * @cliexpar
 * Example of how to display the status of a tx packet capture when off:
 * @cliexstart{pcap trace status}
 * max is 100, for any interface to file /tmp/vpe.pcap
 * pcap tx capture is off...
 * @cliexend
 * Example of how to start a tx packet capture:
 * @cliexstart{pcap trace tx max 35 intfc GigabitEthernet0/8/0 file
 * vppTest.pcap}
 * @cliexend
 * Example of how to display the status of a tx packet capture in progress:
 * @cliexstart{pcap trace status}
 * max is 35, for interface GigabitEthernet0/8/0 to file /tmp/vppTest.pcap
 * pcap tx capture is on: 20 of 35 pkts...
 * @cliexend
 * Example of how to stop a tx packet capture:
 * @cliexstart{pcap trace off}
 * captured 21 pkts...
 * saved to /tmp/vppTest.pcap...
 * @cliexend
?*/

VLIB_CLI_COMMAND (pcap_tx_trace_command, static) = {
  .path = "pcap trace",
  .short_help = "Capture the packets of the dispatch to a pcap file",
  .args =
    (cli_arg_t[]) {
      CLI_FLAG ("rx", .help = "capture the received packets"),
      CLI_FLAG ("tx", .help = "capture the transmitted packets"),
      CLI_FLAG ("drop", .help = "capture the dropped packets"),
      CLI_FLAG ("off", .help = "stop the capture"),
      CLI_KEYWORD ("max", cli_type_u32, .alias = "packets-to-capture", .flags = CLI_F_OPTIONAL,
		   .help = "number of packets to capture, default 1000"),
      CLI_KEYWORD ("max-bytes-per-pkt", cli_type_size, .flags = CLI_F_OPTIONAL,
		   .help = "bytes to capture of each packet, default 512"),
      CLI_KEYWORD ("file", cli_type_tmpfile, .flags = CLI_F_OPTIONAL,
		   .help = "name of the capture file in /tmp"),
      CLI_KEYWORD ("interface", cli_type_sw_interface_any, .alias = "intfc",
		   .flags = CLI_F_OPTIONAL, .help = "only this interface, default any"),
      CLI_KEYWORD ("error", cli_type_error, .flags = CLI_F_OPTIONAL,
		   .help = "only the packets dropped with this error"),
      CLI_FLAG ("status", .help = "show the state of the capture"),
      CLI_FLAG ("preallocate-data", .help = "allocate the memory for the capture in advance"),
      CLI_FLAG ("free-data", .help = "free the memory of the capture"),
      CLI_FLAG ("filter", .help = "capture only the packets which match the trace filter"),
      {},
    },
  .handler = pcap_trace_command_fn,
};

static clib_error_t *
set_pcap_filter_function (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_pcap_t *pp = &vnet_get_main ()->pcap;
  vlib_trace_filter_function_registration_t *reg = (void *) cli_get (ctx, "function")->u64;

  pp->current_filter_function = reg->function;
  return 0;
}

VLIB_CLI_COMMAND (set_pcap_filter_function_cli, static) = {
  .path = "set pcap filter function",
  .short_help = "Set the function which filters the packets of the pcap capture",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("function", cli_type_trace_filter_function),
      {},
    },
  .handler = set_pcap_filter_function,
};

static clib_error_t *
show_pcap_filter_function (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_pcap_t *pp = &vnet_get_main ()->pcap;
  vlib_trace_filter_main_t *tfm = &vlib_trace_filter_main;
  vlib_is_packet_traced_fn_t *current_trace_filter_fn = pp->current_filter_function;
  vlib_trace_filter_function_registration_t *reg = tfm->trace_filter_registration;

  while (reg)
    {
      vlib_cli_output (vm, "%sname:%s description: %s priority: %u",
		       reg->function == current_trace_filter_fn ? "(*) " : "", reg->name,
		       reg->description, reg->priority);
      reg = reg->next;
    }
  return 0;
}

VLIB_CLI_COMMAND (show_pcap_filter_function_cli, static) = {
  .path = "show pcap filter function",
  .short_help = "Show the functions which filter the packets of the pcap capture",
  .handler = show_pcap_filter_function,
};

static clib_error_t *
set_interface_name (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u8 *name = format (0, "%v%c", cli_get (ctx, "new-name")->str, 0);
  clib_error_t *error =
    vnet_rename_interface (vnet_get_main (), cli_index (ctx, "interface"), (char *) name);

  vec_free (name);
  return error;
}

VLIB_CLI_COMMAND (cmd_set_if_name, static) = {
  .path = "set interface name",
  .short_help = "Rename an interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_hw_interface),
      CLI_VALUE ("new-name", cli_type_string, .help = "new name of the interface"),
      {},
    },
  .handler = set_interface_name,
  .is_mp_safe = 1,
};

static clib_error_t *
set_interface_tx_hash_cmd (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, cli_index (ctx, "interface"));
  u8 *hash_name = format (0, "%v%c", cli_get (ctx, "hash-name")->str, 0);
  vnet_hash_fn_type_t ftype =
    vnet_get_hw_interface_class (vnm, hi->hw_class_index)->tx_hash_fn_type;
  vnet_hash_fn_t hf = vnet_hash_function_from_name ((const char *) hash_name, ftype);

  vec_free (hash_name);
  if (!hf)
    return clib_error_return (0, "please specify valid hash name");

  hi->hf = hf;
  return 0;
}

VLIB_CLI_COMMAND (cmd_set_if_tx_hash, static) = {
  .path = "set interface tx-hash",
  .short_help = "Set the hash function used to select the tx queue of an interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_hw_interface),
      CLI_KEYWORD ("hash-name", cli_type_string, .help = "name of the hash function"),
      {},
    },
  .handler = set_interface_tx_hash_cmd,
};

static clib_error_t *
show_tx_hash (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, cli_index (ctx, "interface"));
  vnet_hash_function_registration_t *hash;
  vnet_hash_fn_type_t ftype =
    vnet_get_hw_interface_class (vnm, hi->hw_class_index)->tx_hash_fn_type;

  if (hi->hf)
    {
      hash = vnet_hash_function_from_func (hi->hf, ftype);
      if (hash)
	vlib_cli_output (vm, "%U", format_vnet_hash, hash);
      else
	vlib_cli_output (vm, "no matching hash function found");
    }
  else
    vlib_cli_output (vm, "no hashing function set");

  return 0;
}

VLIB_CLI_COMMAND (cmd_show_tx_hash, static) = {
  .path = "show interface tx-hash",
  .short_help = "Show the hash function used to select the tx queue of an interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_hw_interface),
      {},
    },
  .handler = show_tx_hash,
};

static void
show_interface_transceiver_output (vlib_main_t *vm, vnet_hw_interface_t *hi,
				   u8 show_module, u8 show_diag,
				   u8 show_eeprom, u8 is_terse)
{
  clib_error_t *error = 0;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_eeprom_t *eeprom = 0;
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_device_class_t *dc =
    vec_elt_at_index (im->device_classes, hi->dev_class_index);

  if (!dc->eeprom_read_function)
    {
      error = clib_error_return (
	0, "interface %v does not support EEPROM reading", hi->name);
      goto done;
    }

  error = dc->eeprom_read_function (vnm, hi, &eeprom);
  if (error)
    goto done;

  if (!eeprom)
    {
      error = clib_error_return (
	0, "no EEPROM data available for interface %v", hi->name);
      goto done;
    }

  vlib_cli_output (vm, "Interface: %v", hi->name);
  vlib_cli_output (vm, "  EEPROM Type: 0x%02x (%U)", eeprom->eeprom_type,
		   format_vnet_interface_eeprom_type, eeprom->eeprom_type);

  /* Default to module if none are set */
  if (!show_module && !show_diag && !show_eeprom)
    show_module = 1;

  if (show_eeprom)
    {
      vlib_cli_output (vm, "  EEPROM Length: %u bytes", eeprom->eeprom_len);
      vlib_cli_output (vm, "  EEPROM Data:");

      /* Print hexdump */
      for (u32 offset = 0; offset < eeprom->eeprom_len; offset += 16)
	{
	  u8 *line = format (0, "    %04x: ", offset);

	  /* Print hex bytes */
	  for (u32 j = 0; j < 16 && (offset + j) < eeprom->eeprom_len; j++)
	    {
	      line = format (line, "%02x ", eeprom->eeprom_raw[offset + j]);
	    }

	  /* Pad to align ASCII section */
	  for (u32 j = (offset + 16 > eeprom->eeprom_len) ?
			 eeprom->eeprom_len - offset :
			 16;
	       j < 16; j++)
	    {
	      line = format (line, "   ");
	    }

	  line = format (line, " |");

	  /* Print ASCII representation */
	  for (u32 j = 0; j < 16 && (offset + j) < eeprom->eeprom_len; j++)
	    {
	      u8 c = eeprom->eeprom_raw[offset + j];
	      line = format (line, "%c", (c >= 32 && c <= 126) ? c : '.');
	    }

	  line = format (line, "|");
	  vlib_cli_output (vm, "%v", line);
	  vec_free (line);
	}

      vlib_cli_output (vm, "");
    }

  if (show_module)
    vlib_cli_output (vm, "  Module Base Information:\n%U%U", format_white_space, 4,
		     format_sfp_eeprom_module, eeprom, is_terse);

  if (show_diag)
    vlib_cli_output (vm, "  Module Diagnostics:\n%U%U", format_white_space, 4,
		     format_sfp_eeprom_diagnostics, eeprom, is_terse);

done:
  if (eeprom)
    clib_mem_free (eeprom);
}

static clib_error_t *
show_interface_transceiver (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  u32 hw_if_index = cli_index (ctx, "interface");
  vnet_hw_interface_t *hi;
  u8 is_terse = !cli_flag (ctx, "verbose");
  u8 show_diag = cli_flag (ctx, "diag");
  u8 show_module = cli_flag (ctx, "module");
  u8 show_eeprom = cli_flag (ctx, "eeprom");

  pool_foreach (hi, im->hw_interfaces)
    {
      if (hw_if_index == ~0 || hw_if_index == hi->hw_if_index)
	{
	  show_interface_transceiver_output (vm, hi, show_module, show_diag, show_eeprom, is_terse);
	}
    }
  return 0;
}

/*?
 * This command displays the transceiver EEPROM data for a given interface.
 * The EEPROM data is read from the physical transceiver module (SFP, QSFP,
 * etc.) and displayed as a hexadecimal dump.
 *
 * @cliexpar
 * Example of how to display transceiver EEPROM data:
 * @cliexcmd{show interface transceiver GigabitEthernet0/8/0 module diag}
 ?*/
VLIB_CLI_COMMAND (cmd_show_interface_transceiver, static) = {
  .path = "show interface transceiver",
  .short_help = "Show the transceiver module of the interfaces",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_hw_interface, .flags = CLI_F_OPTIONAL),
      CLI_FLAG ("module", .help = "module information, the default"),
      CLI_FLAG ("diag", .help = "module diagnostics"),
      CLI_FLAG ("eeprom", .help = "EEPROM content"),
      CLI_FLAG ("verbose", .help = "more details"),
      {},
    },
  .handler = show_interface_transceiver,
};

static clib_error_t *
set_interface_link_speed (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return vnet_hw_interface_change_link_speed (vnet_get_main (), cli_index (ctx, "interface"),
					      cli_u64 (ctx, "speed-kbps", 0));
}

VLIB_CLI_COMMAND (cmd_set_interface_link_speed, static) = {
  .path = "set interface link-speed",
  .short_help = "Set the link speed of an interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_hw_interface),
      CLI_VALUE ("speed-kbps", cli_type_u32, .help = "speed in Kbps"),
      {},
    },
  .handler = set_interface_link_speed,
};

static clib_error_t *
show_interface_link_speed_capa (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index = cli_index (ctx, "interface");

  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);

  if (hw->supported_link_speeds == 0)
    {
      vlib_cli_output (vm, "no speed capabilities reported for %U", format_vnet_hw_if_index_name,
		       vnm, hw_if_index);
      return 0;
    }

  vlib_cli_output (vm, "Supported speeds for %U:", format_vnet_hw_if_index_name, vnm, hw_if_index);

#define _(name, bit, mbps)                                                                         \
  if (hw->supported_link_speeds & bit)                                                             \
    vlib_cli_output (vm, "  %u Kbps", (u32) mbps * 1000);
  foreach_vnet_hw_if_speed
#undef _

    return 0;
}

VLIB_CLI_COMMAND (cmd_show_interface_link_speed_capa, static) = {
  .path = "show interface link-speed-capa",
  .short_help = "Show the link speeds supported by an interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_hw_interface),
      {},
    },
  .handler = show_interface_link_speed_capa,
};
