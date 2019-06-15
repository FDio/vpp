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
 * interface_cli.c: interface CLI
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

static int
compare_interface_names (void *a1, void *a2)
{
  u32 *hi1 = a1;
  u32 *hi2 = a2;

  return vnet_hw_interface_compare (vnet_get_main (), *hi1, *hi2);
}

static clib_error_t *
show_or_clear_hw_interfaces (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi;
  u32 hw_if_index, *hw_if_indices = 0;
  int i, verbose = -1, is_show, show_bond = 0;

  is_show = strstr (cmd->path, "show") != 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      /* See if user wants to show a specific interface. */
      if (unformat
	  (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	vec_add1 (hw_if_indices, hw_if_index);

      /* See if user wants to show an interface with a specific hw_if_index. */
      else if (unformat (input, "%u", &hw_if_index))
	vec_add1 (hw_if_indices, hw_if_index);

      else if (unformat (input, "verbose"))
	verbose = 1;		/* this is also the default */

      else if (unformat (input, "detail"))
	verbose = 2;

      else if (unformat (input, "brief"))
	verbose = 0;

      else if (unformat (input, "bond"))
	{
	  show_bond = 1;
	  if (verbose < 0)
	    verbose = 0;	/* default to brief for link bonding */
	}

      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  /* Gather interfaces. */
  if (vec_len (hw_if_indices) == 0)
    pool_foreach (hi, im->hw_interfaces,
		  vec_add1 (hw_if_indices, hi - im->hw_interfaces));

  if (verbose < 0)
    verbose = 1;		/* default to verbose (except bond) */

  if (is_show)
    {
      /* Sort by name. */
      vec_sort_with_function (hw_if_indices, compare_interface_names);

      vlib_cli_output (vm, "%U\n", format_vnet_hw_interface, vnm, 0, verbose);
      for (i = 0; i < vec_len (hw_if_indices); i++)
	{
	  hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);
	  if (show_bond == 0)	/* show all interfaces */
	    vlib_cli_output (vm, "%U\n", format_vnet_hw_interface, vnm,
			     hi, verbose);
	  else if ((hi->bond_info) &&
		   (hi->bond_info != VNET_HW_INTERFACE_BOND_INFO_SLAVE))
	    {			/* show only bonded interface and all its slave interfaces */
	      int hw_idx;
	      vnet_hw_interface_t *shi;
	      vlib_cli_output (vm, "%U\n", format_vnet_hw_interface, vnm,
			       hi, verbose);

              /* *INDENT-OFF* */
	      clib_bitmap_foreach (hw_idx, hi->bond_info,
              ({
                shi = vnet_get_hw_interface(vnm, hw_idx);
                vlib_cli_output (vm, "%U\n",
                                 format_vnet_hw_interface, vnm, shi, verbose);
              }));
              /* *INDENT-ON* */
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

done:
  vec_free (hw_if_indices);
  return error;
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
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_hw_interfaces_command, static) = {
  .path = "show hardware-interfaces",
  .short_help = "show hardware-interfaces [brief|verbose|detail] [bond] "
    "[<interface> [<interface> [..]]] [<sw_idx> [<sw_idx> [..]]]",
  .function = show_or_clear_hw_interfaces,
};
/* *INDENT-ON* */


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
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_hw_interface_counters_command, static) = {
  .path = "clear hardware-interfaces",
  .short_help = "clear hardware-interfaces "
    "[<interface> [<interface> [..]]] [<sw_idx> [<sw_idx> [..]]]",
  .function = show_or_clear_hw_interfaces,
};
/* *INDENT-ON* */

static int
sw_interface_name_compare (void *a1, void *a2)
{
  vnet_sw_interface_t *si1 = a1;
  vnet_sw_interface_t *si2 = a2;

  return vnet_sw_interface_compare (vnet_get_main (),
				    si1->sw_if_index, si2->sw_if_index);
}

static clib_error_t *
show_sw_interfaces (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t _linput, *linput = &_linput;
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_sw_interface_t *si, *sorted_sis = 0;
  u32 sw_if_index = ~(u32) 0;
  u8 show_addresses = 0;
  u8 show_features = 0;
  u8 show_tag = 0;
  int verbose = 0;

  /*
   * Get a line of input. Won't work if the user typed
   * "show interface" and nothing more.
   */
  if (unformat_user (input, unformat_line_input, linput))
    {
      while (unformat_check_input (linput) != UNFORMAT_END_OF_INPUT)
	{
	  /* See if user wants to show specific interface */
	  if (unformat
	      (linput, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	    {
	      si = pool_elt_at_index (im->sw_interfaces, sw_if_index);
	      vec_add1 (sorted_sis, si[0]);
	    }
	  else if (unformat (linput, "address") || unformat (linput, "addr"))
	    show_addresses = 1;
	  else if (unformat (linput, "features") || unformat (linput, "feat"))
	    show_features = 1;
	  else if (unformat (linput, "tag"))
	    show_tag = 1;
	  else if (unformat (linput, "verbose"))
	    verbose = 1;
	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, linput);
	      goto done;
	    }
	}
      unformat_free (linput);
    }
  if (show_features || show_tag)
    {
      if (sw_if_index == ~(u32) 0)
	return clib_error_return (0, "Interface not specified...");
    }

  if (show_features)
    {
      vnet_interface_features_show (vm, sw_if_index, verbose);

      l2_input_config_t *l2_input = l2input_intf_config (sw_if_index);
      u32 fb = l2_input->feature_bitmap;
      /* intf input features are masked by bridge domain */
      if (l2_input->bridge)
	fb &= l2input_bd_config (l2_input->bd_index)->feature_bitmap;
      vlib_cli_output (vm, "\nl2-input:\n%U", format_l2_input_features, fb,
		       1);

      l2_output_config_t *l2_output = l2output_intf_config (sw_if_index);
      vlib_cli_output (vm, "\nl2-output:");
      if (l2_output->out_vtr_flag)
	vlib_cli_output (vm, "%10s (%s)", "VTR", "--internal--");
      vlib_cli_output (vm, "%U", format_l2_output_features,
		       l2_output->feature_bitmap, 1);
      return 0;
    }
  if (show_tag)
    {
      u8 *tag;
      tag = vnet_get_sw_interface_tag (vnm, sw_if_index);
      vlib_cli_output (vm, "%U: %s",
		       format_vnet_sw_if_index_name, vnm, sw_if_index,
		       tag ? (char *) tag : "(none)");
      return 0;
    }

  if (!show_addresses)
    vlib_cli_output (vm, "%U\n", format_vnet_sw_interface, vnm, 0);

  if (vec_len (sorted_sis) == 0)	/* Get all interfaces */
    {
      /* Gather interfaces. */
      sorted_sis =
	vec_new (vnet_sw_interface_t, pool_elts (im->sw_interfaces));
      _vec_len (sorted_sis) = 0;
      /* *INDENT-OFF* */
      pool_foreach (si, im->sw_interfaces,
      ({
        int visible = vnet_swif_is_api_visible (si);
        if (visible)
          vec_add1 (sorted_sis, si[0]);}
        ));
      /* *INDENT-ON* */
      /* Sort by name. */
      vec_sort_with_function (sorted_sis, sw_interface_name_compare);
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
	l2_input_config_t *l2_input = l2input_intf_config (si->sw_if_index);
	if (l2_input->bridge)
	  {
	    bd_main_t *bdm = &bd_main;
	    u32 bd_id = l2input_main.bd_configs[l2_input->bd_index].bd_id;
	    vlib_cli_output (vm, "  L2 bridge bd-id %d idx %d shg %d %s",
			     bd_id, bd_find_index (bdm, bd_id), l2_input->shg,
			     l2_input->bvi ? "bvi" : " ");
	  }
	else if (l2_input->xconnect)
	  vlib_cli_output (vm, "  L2 xconnect %U",
			   format_vnet_sw_if_index_name, vnm,
			   l2_input->output_sw_if_index);

	/* *INDENT-OFF* */
	/* Display any IP4 addressing info */
	foreach_ip_interface_address (lm4, ia, si->sw_if_index,
				      1 /* honor unnumbered */,
	({
	  ip4_address_t *r4 = ip_interface_address_get_address (lm4, ia);
	  if (fib4->table_id)
	    vlib_cli_output (vm, "  L3 %U/%d ip4 table-id %d fib-idx %d",
			     format_ip4_address, r4, ia->address_length,
			     fib4->table_id,
			     ip4_fib_index_from_table_id (fib4->table_id));
	  else
	    vlib_cli_output (vm, "  L3 %U/%d",
			     format_ip4_address, r4, ia->address_length);
        }));
	/* *INDENT-ON* */

	/* *INDENT-OFF* */
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
	/* *INDENT-ON* */
      }
    }
  else
    {
      vec_foreach (si, sorted_sis)
      {
	vlib_cli_output (vm, "%U\n", format_vnet_sw_interface, vnm, si);
      }
    }

done:
  vec_free (sorted_sis);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_sw_interfaces_command, static) = {
  .path = "show interface",
  .short_help = "show interface [address|addr|features|feat] [<interface> [<interface> [..]]] [verbose]",
  .function = show_sw_interfaces,
};
/* *INDENT-ON* */

/* Root of all interface commands. */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vnet_cli_interface_command, static) = {
  .path = "interface",
  .short_help = "Interface commands",
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vnet_cli_set_interface_command, static) = {
  .path = "set interface",
  .short_help = "Interface commands",
};
/* *INDENT-ON* */

static clib_error_t *
clear_interface_counters (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vlib_simple_counter_main_t *sm;
  vlib_combined_counter_main_t *cm;
  static vnet_main_t **my_vnet_mains;
  int i, j, n_counters;

  vec_reset_length (my_vnet_mains);

  for (i = 0; i < vec_len (vnet_mains); i++)
    {
      if (vnet_mains[i])
	vec_add1 (my_vnet_mains, vnet_mains[i]);
    }

  if (vec_len (vnet_mains) == 0)
    vec_add1 (my_vnet_mains, vnm);

  n_counters = vec_len (im->combined_sw_if_counters);

  for (j = 0; j < n_counters; j++)
    {
      for (i = 0; i < vec_len (my_vnet_mains); i++)
	{
	  im = &my_vnet_mains[i]->interface_main;
	  cm = im->combined_sw_if_counters + j;
	  vlib_clear_combined_counters (cm);
	}
    }

  n_counters = vec_len (im->sw_if_counters);

  for (j = 0; j < n_counters; j++)
    {
      for (i = 0; i < vec_len (my_vnet_mains); i++)
	{
	  im = &my_vnet_mains[i]->interface_main;
	  sm = im->sw_if_counters + j;
	  vlib_clear_simple_counters (sm);
	}
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
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_interface_counters_command, static) = {
  .path = "clear interfaces",
  .short_help = "clear interfaces",
  .function = clear_interface_counters,
};
/* *INDENT-ON* */

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

static clib_error_t *
parse_vlan_sub_interfaces (unformat_input_t * input,
			   vnet_sw_interface_t * template)
{
  clib_error_t *error = 0;
  u32 inner_vlan, outer_vlan;

  if (unformat (input, "any inner-dot1q any"))
    {
      template->sub.eth.flags.two_tags = 1;
      template->sub.eth.flags.outer_vlan_id_any = 1;
      template->sub.eth.flags.inner_vlan_id_any = 1;
    }
  else if (unformat (input, "any"))
    {
      template->sub.eth.flags.one_tag = 1;
      template->sub.eth.flags.outer_vlan_id_any = 1;
    }
  else if (unformat (input, "%d inner-dot1q any", &outer_vlan))
    {
      template->sub.eth.flags.two_tags = 1;
      template->sub.eth.flags.inner_vlan_id_any = 1;
      template->sub.eth.outer_vlan_id = outer_vlan;
    }
  else if (unformat (input, "%d inner-dot1q %d", &outer_vlan, &inner_vlan))
    {
      template->sub.eth.flags.two_tags = 1;
      template->sub.eth.outer_vlan_id = outer_vlan;
      template->sub.eth.inner_vlan_id = inner_vlan;
    }
  else if (unformat (input, "%d", &outer_vlan))
    {
      template->sub.eth.flags.one_tag = 1;
      template->sub.eth.outer_vlan_id = outer_vlan;
    }
  else
    {
      error = clib_error_return (0, "expected dot1q config, got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "exact-match"))
	{
	  template->sub.eth.flags.exact_match = 1;
	}
    }

done:
  return error;
}

static clib_error_t *
create_sub_interfaces (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 hw_if_index, sw_if_index;
  vnet_hw_interface_t *hi;
  u32 id, id_min, id_max;
  vnet_sw_interface_t template;

  hw_if_index = ~0;
  if (!unformat_user (input, unformat_vnet_hw_interface, vnm, &hw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  clib_memset (&template, 0, sizeof (template));
  template.sub.eth.raw_flags = 0;

  if (unformat (input, "%d default", &id_min))
    {
      id_max = id_min;
      template.sub.eth.flags.default_sub = 1;
    }
  else if (unformat (input, "%d untagged", &id_min))
    {
      id_max = id_min;
      template.sub.eth.flags.no_tags = 1;
      template.sub.eth.flags.exact_match = 1;
    }
  else if (unformat (input, "%d dot1q", &id_min))
    {
      /* parse dot1q config */
      id_max = id_min;
      error = parse_vlan_sub_interfaces (input, &template);
      if (error)
	goto done;
    }
  else if (unformat (input, "%d dot1ad", &id_min))
    {
      /* parse dot1ad config */
      id_max = id_min;
      template.sub.eth.flags.dot1ad = 1;
      error = parse_vlan_sub_interfaces (input, &template);
      if (error)
	goto done;
    }
  else if (unformat (input, "%d-%d", &id_min, &id_max))
    {
      template.sub.eth.flags.one_tag = 1;
      template.sub.eth.flags.exact_match = 1;
      if (id_min > id_max)
	goto id_error;
    }
  else if (unformat (input, "%d", &id_min))
    {
      id_max = id_min;
      template.sub.eth.flags.one_tag = 1;
      template.sub.eth.outer_vlan_id = id_min;
      template.sub.eth.flags.exact_match = 1;
    }
  else
    {
    id_error:
      error = clib_error_return (0, "expected ID or ID MIN-MAX, got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  if (hi->bond_info == VNET_HW_INTERFACE_BOND_INFO_SLAVE)
    {
      error =
	clib_error_return (0,
			   "not allowed as %v belong to a BondEthernet interface",
			   hi->name);
      goto done;
    }

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
	    clib_warning ("sup sw_if_index %d, sub id %d already exists\n",
			  hi->sw_if_index, id);
	  continue;
	}

      kp = clib_mem_alloc (sizeof (*kp));
      *kp = sup_and_sub_key;

      template.type = VNET_SW_INTERFACE_TYPE_SUB;
      template.flood_class = VNET_FLOOD_CLASS_NORMAL;
      template.sup_sw_if_index = hi->sw_if_index;
      template.sub.id = id;
      if (id_min < id_max)
	template.sub.eth.outer_vlan_id = id;

      error = vnet_create_sw_interface (vnm, &template, &sw_if_index);
      if (error)
	goto done;

      hash_set (hi->sub_interface_sw_if_index_by_id, id, sw_if_index);
      hash_set_mem (im->sw_if_index_by_sup_and_sub, kp, sw_if_index);
      vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
		       vnet_get_main (), sw_if_index);
    }

done:
  return error;
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
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_sub_interfaces_command, static) = {
  .path = "create sub-interfaces",
  .short_help = "create sub-interfaces <interface> "
    "{<subId> [default|untagged]} | "
    "{<subId>-<subId>} | "
    "{<subId> dot1q|dot1ad <vlanId>|any [inner-dot1q <vlanId>|any] [exact-match]}",
  .function = create_sub_interfaces,
};
/* *INDENT-ON* */

static clib_error_t *
set_state (vlib_main_t * vm,
	   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error;
  u32 sw_if_index, flags;

  sw_if_index = ~0;
  if (!unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (!unformat (input, "%U", unformat_vnet_sw_interface_flags, &flags))
    {
      error = clib_error_return (0, "unknown flags `%U'",
				 format_unformat_error, input);
      goto done;
    }

  error = vnet_sw_interface_set_flags (vnm, sw_if_index, flags);
  if (error)
    goto done;

done:
  return error;
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
 * Example of how to configure the admin state of an interface to '<em>up</em?':
 * @cliexcmd{set interface state GigabitEthernet2/0/0 up}
 * Example of how to configure the admin state of an interface to '<em>down</em?':
 * @cliexcmd{set interface state GigabitEthernet2/0/0 down}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_state_command, static) = {
  .path = "set interface state",
  .short_help = "set interface state <interface> [up|down|punt|enable]",
  .function = set_state,
};
/* *INDENT-ON* */

static clib_error_t *
set_unnumbered (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 unnumbered_sw_if_index = ~0;
  u32 inherit_from_sw_if_index = ~0;
  int enable = 1;

  if (unformat (input, "%U use %U",
		unformat_vnet_sw_interface, vnm, &unnumbered_sw_if_index,
		unformat_vnet_sw_interface, vnm, &inherit_from_sw_if_index))
    enable = 1;
  else if (unformat (input, "del %U",
		     unformat_vnet_sw_interface, vnm,
		     &unnumbered_sw_if_index))
    enable = 0;
  else
    return clib_error_return (0, "parse error '%U'",
			      format_unformat_error, input);

  if (~0 == unnumbered_sw_if_index)
    return clib_error_return (0, "Specify the unnumbered interface");
  if (enable && ~0 == inherit_from_sw_if_index)
    return clib_error_return (0, "When enabling unnumbered specify the"
			      " IP enabled interface that it uses");

  vnet_sw_interface_update_unnumbered (unnumbered_sw_if_index,
				       inherit_from_sw_if_index, enable);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_unnumbered_command, static) = {
  .path = "set interface unnumbered",
  .short_help = "set interface unnumbered [<interface> use <interface> | del <interface>]",
  .function = set_unnumbered,
};
/* *INDENT-ON* */



static clib_error_t *
set_hw_class (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  clib_error_t *error;
  u32 hw_if_index, hw_class_index;

  hw_if_index = ~0;
  if (!unformat_user (input, unformat_vnet_hw_interface, vnm, &hw_if_index))
    {
      error = clib_error_return (0, "unknown hardware interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (!unformat_user (input, unformat_hash_string,
		      im->hw_interface_class_by_name, &hw_class_index))
    {
      error = clib_error_return (0, "unknown hardware class `%U'",
				 format_unformat_error, input);
      goto done;
    }

  error = vnet_hw_interface_set_class (vnm, hw_if_index, hw_class_index);
  if (error)
    goto done;

done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_hw_class_command, static) = {
  .path = "set interface hw-class",
  .short_help = "Set interface hardware class",
  .function = set_hw_class,
};
/* *INDENT-ON* */

static clib_error_t *
vnet_interface_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (vnet_interface_cli_init);

static clib_error_t *
renumber_interface_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  u32 hw_if_index;
  u32 new_dev_instance;
  vnet_main_t *vnm = vnet_get_main ();
  int rv;

  if (!unformat_user (input, unformat_vnet_hw_interface, vnm, &hw_if_index))
    return clib_error_return (0, "unknown hardware interface `%U'",
			      format_unformat_error, input);

  if (!unformat (input, "%d", &new_dev_instance))
    return clib_error_return (0, "new dev instance missing");

  rv = vnet_interface_name_renumber (hw_if_index, new_dev_instance);

  switch (rv)
    {
    case 0:
      break;

    default:
      return clib_error_return (0, "vnet_interface_name_renumber returned %d",
				rv);

    }

  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (renumber_interface_command, static) = {
  .path = "renumber interface",
  .short_help = "renumber interface <interface> <new-dev-instance>",
  .function = renumber_interface_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
promiscuous_cmd (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index;
  u32 flags = ETHERNET_INTERFACE_FLAG_ACCEPT_ALL;
  ethernet_main_t *em = &ethernet_main;
  ethernet_interface_t *eif;

  if (unformat (input, "on %U",
		unformat_vnet_hw_interface, vnm, &hw_if_index))
    ;
  else if (unformat (input, "off %U",
		     unformat_ethernet_interface, vnm, &hw_if_index))
    flags = 0;
  else
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);

  eif = ethernet_get_interface (em, hw_if_index);
  if (!eif)
    return clib_error_return (0, "not supported");

  ethernet_set_flags (vnm, hw_if_index, flags);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_promiscuous_cmd, static) = {
  .path = "set interface promiscuous",
  .short_help = "set interface promiscuous [on|off] <interface>",
  .function = promiscuous_cmd,
};
/* *INDENT-ON* */

static clib_error_t *
mtu_cmd (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index, sw_if_index, mtu;
  ethernet_main_t *em = &ethernet_main;
  u32 mtus[VNET_N_MTU] = { 0, 0, 0, 0 };

  if (unformat (input, "%d %U", &mtu,
		unformat_vnet_hw_interface, vnm, &hw_if_index))
    {
      /*
       * Change physical MTU on interface. Only supported for Ethernet
       * interfaces
       */
      vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
      ethernet_interface_t *eif = ethernet_get_interface (em, hw_if_index);

      if (!eif)
	return clib_error_return (0, "not supported");

      if (mtu < hi->min_supported_packet_bytes)
	return clib_error_return (0, "Invalid mtu (%d): "
				  "must be >= min pkt bytes (%d)", mtu,
				  hi->min_supported_packet_bytes);

      if (mtu > hi->max_supported_packet_bytes)
	return clib_error_return (0, "Invalid mtu (%d): must be <= (%d)", mtu,
				  hi->max_supported_packet_bytes);

      vnet_hw_interface_set_mtu (vnm, hw_if_index, mtu);
      goto done;
    }
  else if (unformat (input, "packet %d %U", &mtu,
		     unformat_vnet_sw_interface, vnm, &sw_if_index))
    /* Set default packet MTU (including L3 header */
    mtus[VNET_MTU_L3] = mtu;
  else if (unformat (input, "ip4 %d %U", &mtu,
		     unformat_vnet_sw_interface, vnm, &sw_if_index))
    mtus[VNET_MTU_IP4] = mtu;
  else if (unformat (input, "ip6 %d %U", &mtu,
		     unformat_vnet_sw_interface, vnm, &sw_if_index))
    mtus[VNET_MTU_IP6] = mtu;
  else if (unformat (input, "mpls %d %U", &mtu,
		     unformat_vnet_sw_interface, vnm, &sw_if_index))
    mtus[VNET_MTU_MPLS] = mtu;
  else
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);

  vnet_sw_interface_set_protocol_mtu (vnm, sw_if_index, mtus);

done:
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_mtu_cmd, static) = {
  .path = "set interface mtu",
  .short_help = "set interface mtu [packet|ip4|ip6|mpls] <value> <interface>",
  .function = mtu_cmd,
};
/* *INDENT-ON* */

static clib_error_t *
set_interface_mac_address (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si = NULL;
  clib_error_t *error = 0;
  u32 sw_if_index = ~0;
  u8 mac[6] = { 0 };

  if (!unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }
  if (!unformat_user (input, unformat_ethernet_address, mac))
    {
      error = clib_error_return (0, "expected mac address `%U'",
				 format_unformat_error, input);
      goto done;
    }
  si = vnet_get_sw_interface (vnm, sw_if_index);
  error = vnet_hw_interface_change_mac_address (vnm, si->hw_if_index, mac);
done:
  return error;
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
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_mac_address_cmd, static) = {
  .path = "set interface mac address",
  .short_help = "set interface mac address <interface> <mac-address>",
  .function = set_interface_mac_address,
};
/* *INDENT-ON* */

static clib_error_t *
set_tag (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u8 *tag = 0;

  if (!unformat (input, "%U %s", unformat_vnet_sw_interface,
		 vnm, &sw_if_index, &tag))
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);

  vnet_set_sw_interface_tag (vnm, tag, sw_if_index);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_tag_command, static) = {
  .path = "set interface tag",
  .short_help = "set interface tag <interface> <tag>",
  .function = set_tag,
};
/* *INDENT-ON* */

static clib_error_t *
clear_tag (vlib_main_t * vm, unformat_input_t * input,
	   vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;

  if (!unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);

  vnet_clear_sw_interface_tag (vnm, sw_if_index);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_tag_command, static) = {
  .path = "clear interface tag",
  .short_help = "clear interface tag <interface>",
  .function = clear_tag,
};
/* *INDENT-ON* */

static clib_error_t *
set_ip_directed_broadcast (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u8 enable = 0;

  if (!unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index));
  else if (unformat (input, "enable"))
    enable = 1;
  else if (unformat (input, "disable"))
    enable = 0;
  else
    return clib_error_return (0, "unknown input: `%U'",
			      format_unformat_error, input);

  if (~0 == sw_if_index)
    return clib_error_return (0, "specify an interface: `%U'",
			      format_unformat_error, input);

  vnet_sw_interface_ip_directed_broadcast (vnm, sw_if_index, enable);

  return 0;
}

/*?
 * This command is used to enable/disable IP directed broadcast
 * If directed broadcast is enabled a packet sent to the interface's
 * subnet broadcast address will be sent L2 broadcast on the interface,
 * otherwise it is dropped.
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ip_directed_broadcast_command, static) = {
  .path = "set interface ip directed-broadcast",
  .short_help = "set interface enable <interface> <enable|disable>",
  .function = set_ip_directed_broadcast,
};
/* *INDENT-ON* */

static clib_error_t *
set_hw_interface_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
			  u32 queue_id, vnet_hw_interface_rx_mode mode)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hw->dev_class_index);
  clib_error_t *error;
  vnet_hw_interface_rx_mode old_mode;
  int rv;

  if (mode == VNET_HW_INTERFACE_RX_MODE_DEFAULT)
    mode = hw->default_rx_mode;

  rv = vnet_hw_interface_get_rx_mode (vnm, hw_if_index, queue_id, &old_mode);
  switch (rv)
    {
    case 0:
      if (old_mode == mode)
	return 0;		/* same rx-mode, no change */
      break;
    case VNET_API_ERROR_INVALID_INTERFACE:
      return clib_error_return (0, "invalid interface");
    case VNET_API_ERROR_INVALID_QUEUE:
      return clib_error_return (0, "invalid queue");
    default:
      return clib_error_return (0, "unknown error");
    }

  if (dev_class->rx_mode_change_function)
    {
      error = dev_class->rx_mode_change_function (vnm, hw_if_index, queue_id,
						  mode);
      if (error)
	return (error);
    }

  rv = vnet_hw_interface_set_rx_mode (vnm, hw_if_index, queue_id, mode);
  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_UNSUPPORTED:
      return clib_error_return (0, "unsupported");
    case VNET_API_ERROR_INVALID_INTERFACE:
      return clib_error_return (0, "invalid interface");
    case VNET_API_ERROR_INVALID_QUEUE:
      return clib_error_return (0, "invalid queue");
    default:
      return clib_error_return (0, "unknown error");
    }

  return 0;
}

clib_error_t *
set_hw_interface_change_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
				 u8 queue_id_valid, u32 queue_id,
				 vnet_hw_interface_rx_mode mode)
{
  clib_error_t *error = 0;
  vnet_hw_interface_t *hw;
  int i;

  hw = vnet_get_hw_interface (vnm, hw_if_index);

  if (queue_id_valid == 0)
    {
      for (i = 0; i < vec_len (hw->dq_runtime_index_by_queue); i++)
	{
	  error = set_hw_interface_rx_mode (vnm, hw_if_index, i, mode);
	  if (error)
	    break;
	}
      hw->default_rx_mode = mode;
    }
  else
    error = set_hw_interface_rx_mode (vnm, hw_if_index, queue_id, mode);

  return (error);
}

static clib_error_t *
set_interface_rx_mode (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index = (u32) ~ 0;
  u32 queue_id = (u32) ~ 0;
  vnet_hw_interface_rx_mode mode = VNET_HW_INTERFACE_RX_MODE_UNKNOWN;
  u8 queue_id_valid = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	;
      else if (unformat (line_input, "queue %d", &queue_id))
	queue_id_valid = 1;
      else if (unformat (line_input, "polling"))
	mode = VNET_HW_INTERFACE_RX_MODE_POLLING;
      else if (unformat (line_input, "interrupt"))
	mode = VNET_HW_INTERFACE_RX_MODE_INTERRUPT;
      else if (unformat (line_input, "adaptive"))
	mode = VNET_HW_INTERFACE_RX_MODE_ADAPTIVE;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  unformat_free (line_input);
	  return error;
	}
    }

  unformat_free (line_input);

  if (hw_if_index == (u32) ~ 0)
    return clib_error_return (0, "please specify valid interface name");

  if (mode == VNET_HW_INTERFACE_RX_MODE_UNKNOWN)
    return clib_error_return (0, "please specify valid rx-mode");

  error = set_hw_interface_change_rx_mode (vnm, hw_if_index, queue_id_valid,
					   queue_id, mode);

  return (error);
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
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_if_rx_mode,static) = {
    .path = "set interface rx-mode",
    .short_help = "set interface rx-mode <interface> [queue <n>] [polling | interrupt | adaptive]",
    .function = set_interface_rx_mode,
};
/* *INDENT-ON* */

static clib_error_t *
show_interface_rx_placement_fn (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  u8 *s = 0;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_device_input_runtime_t *rt;
  vnet_device_and_queue_t *dq;
  vlib_node_t *pn = vlib_get_node_by_name (vm, (u8 *) "device-input");
  uword si;
  int index = 0;

  /* *INDENT-OFF* */
  foreach_vlib_main (({
    clib_bitmap_foreach (si, pn->sibling_bitmap,
      ({
        rt = vlib_node_get_runtime_data (this_vlib_main, si);

        if (vec_len (rt->devices_and_queues))
          s = format (s, "  node %U:\n", format_vlib_node_name, vm, si);

        vec_foreach (dq, rt->devices_and_queues)
	  {
	    vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm,
							     dq->hw_if_index);
	    s = format (s, "    %U queue %u (%U)\n",
			format_vnet_sw_if_index_name, vnm, hi->sw_if_index,
			dq->queue_id,
			format_vnet_hw_interface_rx_mode, dq->mode);
	  }
      }));
    if (vec_len (s) > 0)
      {
        vlib_cli_output(vm, "Thread %u (%s):\n%v", index,
			vlib_worker_threads[index].name, s);
        vec_reset_length (s);
      }
    index++;
  }));
  /* *INDENT-ON* */

  vec_free (s);
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
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_interface_rx_placement, static) = {
  .path = "show interface rx-placement",
  .short_help = "show interface rx-placement",
  .function = show_interface_rx_placement_fn,
};
/* *INDENT-ON* */

clib_error_t *
set_hw_interface_rx_placement (u32 hw_if_index, u32 queue_id,
			       u32 thread_index, u8 is_main)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_device_main_t *vdm = &vnet_device_main;
  clib_error_t *error = 0;
  vnet_hw_interface_rx_mode mode = VNET_HW_INTERFACE_RX_MODE_UNKNOWN;
  int rv;

  if (is_main)
    thread_index = 0;
  else
    thread_index += vdm->first_worker_thread_index;

  if (thread_index > vdm->last_worker_thread_index)
    return clib_error_return (0,
			      "please specify valid worker thread or main");

  rv = vnet_hw_interface_get_rx_mode (vnm, hw_if_index, queue_id, &mode);

  if (rv)
    return clib_error_return (0, "not found");

  rv = vnet_hw_interface_unassign_rx_thread (vnm, hw_if_index, queue_id);

  if (rv)
    return clib_error_return (0, "not found");

  vnet_hw_interface_assign_rx_thread (vnm, hw_if_index, queue_id,
				      thread_index);
  vnet_hw_interface_set_rx_mode (vnm, hw_if_index, queue_id, mode);

  return (error);
}

static clib_error_t *
set_interface_rx_placement (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index = (u32) ~ 0;
  u32 queue_id = (u32) 0;
  u32 thread_index = (u32) ~ 0;
  u8 is_main = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	;
      else if (unformat (line_input, "queue %d", &queue_id))
	;
      else if (unformat (line_input, "main", &thread_index))
	is_main = 1;
      else if (unformat (line_input, "worker %d", &thread_index))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  unformat_free (line_input);
	  return error;
	}
    }

  unformat_free (line_input);

  if (hw_if_index == (u32) ~ 0)
    return clib_error_return (0, "please specify valid interface name");

  error = set_hw_interface_rx_placement (hw_if_index, queue_id, thread_index,
					 is_main);

  return (error);
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
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_if_rx_placement,static) = {
    .path = "set interface rx-placement",
    .short_help = "set interface rx-placement <interface> [queue <n>] "
      "[worker <n> | main]",
    .function = set_interface_rx_placement,
    .is_mp_safe = 1,
};
/* *INDENT-ON* */

static inline clib_error_t *
pcap_trace_command_internal (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd, int rx_tx)
{
#define PCAP_DEF_PKT_TO_CAPTURE (1000)

  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *filename;
  u8 *chroot_filename = 0;
  u32 max = 0;
  int enabled = 0;
  int errorFlag = 0;
  clib_error_t *error = 0;
  vnet_main_t *vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on"))
	{
	  if (vm->pcap[rx_tx].pcap_enable == 0)
	    {
	      enabled = 1;
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap %s capture already on...",
			       (rx_tx == VLIB_RX) ? "rx" : "tx");
	      errorFlag = 1;
	      break;
	    }
	}
      else if (unformat (line_input, "off"))
	{
	  if (vm->pcap[rx_tx].pcap_enable)
	    {
	      vlib_cli_output
		(vm, "captured %d pkts...",
		 vm->pcap[rx_tx].pcap_main.n_packets_captured);
	      if (vm->pcap[rx_tx].pcap_main.n_packets_captured)
		{
		  vm->pcap[rx_tx].pcap_main.n_packets_to_capture =
		    vm->pcap[rx_tx].pcap_main.n_packets_captured;
		  error = pcap_write (&vm->pcap[rx_tx].pcap_main);
		  if (error)
		    clib_error_report (error);
		  else
		    vlib_cli_output (vm, "saved to %s...",
				     vm->pcap[rx_tx].pcap_main.file_name);
		}

	      vm->pcap[rx_tx].pcap_enable = 0;
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap %s capture already off...",
			       (rx_tx == VLIB_RX) ? "rx" : "tx");
	      errorFlag = 1;
	      break;
	    }
	}
      else if (unformat (line_input, "max %d", &max))
	{
	  if (vm->pcap[rx_tx].pcap_enable)
	    {
	      vlib_cli_output
		(vm,
		 "can't change max value while pcap tx capture active...");
	      errorFlag = 1;
	      break;
	    }
	  vm->pcap[rx_tx].pcap_main.n_packets_to_capture = max;
	}
      else if (unformat (line_input, "intfc %U",
			 unformat_vnet_sw_interface, vnm,
			 &vm->pcap[rx_tx].pcap_sw_if_index))
	;

      else if (unformat (line_input, "intfc any"))
	{
	  vm->pcap[rx_tx].pcap_sw_if_index = 0;
	}
      else if (unformat (line_input, "file %s", &filename))
	{
	  if (vm->pcap[rx_tx].pcap_enable)
	    {
	      vlib_cli_output
		(vm, "can't change file while pcap tx capture active...");
	      errorFlag = 1;
	      break;
	    }

	  /* Brain-police user path input */
	  if (strstr ((char *) filename, "..")
	      || index ((char *) filename, '/'))
	    {
	      vlib_cli_output (vm, "illegal characters in filename '%s'",
			       filename);
	      vlib_cli_output (vm, "Hint: .. and / are not allowed.");
	      vec_free (filename);
	      errorFlag = 1;
	      break;
	    }

	  chroot_filename = format (0, "/tmp/%s%c", filename, 0);
	  vec_free (filename);
	}
      else if (unformat (line_input, "status"))
	{
	  if (vm->pcap[rx_tx].pcap_sw_if_index == 0)
	    {
	      vlib_cli_output
		(vm, "max is %d for any interface to file %s",
		 vm->pcap[rx_tx].pcap_main.n_packets_to_capture ?
		 vm->pcap[rx_tx].pcap_main.n_packets_to_capture
		 : PCAP_DEF_PKT_TO_CAPTURE,
		 vm->pcap[rx_tx].pcap_main.file_name ?
		 (u8 *) vm->pcap[rx_tx].pcap_main.file_name :
		 (u8 *) "/tmp/vpe.pcap");
	    }
	  else
	    {
	      vlib_cli_output (vm, "max is %d for interface %U to file %s",
			       vm->pcap[rx_tx].pcap_main.n_packets_to_capture
			       ? vm->pcap[rx_tx].
			       pcap_main.n_packets_to_capture :
			       PCAP_DEF_PKT_TO_CAPTURE,
			       format_vnet_sw_if_index_name, vnm,
			       vm->pcap[rx_tx].pcap_sw_if_index,
			       vm->pcap[rx_tx].
			       pcap_main.file_name ? (u8 *) vm->pcap[rx_tx].
			       pcap_main.file_name : (u8 *) "/tmp/vpe.pcap");
	    }

	  if (vm->pcap[rx_tx].pcap_enable == 0)
	    {
	      vlib_cli_output (vm, "pcap %s capture is off...",
			       (rx_tx == VLIB_RX) ? "rx" : "tx");
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap %s capture is on: %d of %d pkts...",
			       (rx_tx == VLIB_RX) ? "rx" : "tx",
			       vm->pcap[rx_tx].pcap_main.n_packets_captured,
			       vm->pcap[rx_tx].
			       pcap_main.n_packets_to_capture);
	    }
	  break;
	}

      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  errorFlag = 1;
	  break;
	}
    }
  unformat_free (line_input);


  if (errorFlag == 0)
    {
      /* Since no error, save configured values. */
      if (chroot_filename)
	{
	  if (vm->pcap[rx_tx].pcap_main.file_name)
	    vec_free (vm->pcap[rx_tx].pcap_main.file_name);
	  vec_add1 (chroot_filename, 0);
	  vm->pcap[rx_tx].pcap_main.file_name = (char *) chroot_filename;
	}

      if (max)
	vm->pcap[rx_tx].pcap_main.n_packets_to_capture = max;

      if (enabled)
	{
	  if (vm->pcap[rx_tx].pcap_main.file_name == 0)
	    vm->pcap[rx_tx].pcap_main.file_name
	      = (char *) format (0, "/tmp/vpe.pcap%c", 0);

	  vm->pcap[rx_tx].pcap_main.n_packets_captured = 0;
	  vm->pcap[rx_tx].pcap_main.packet_type = PCAP_PACKET_TYPE_ethernet;
	  if (vm->pcap[rx_tx].pcap_main.lock == 0)
	    clib_spinlock_init (&(vm->pcap[rx_tx].pcap_main.lock));
	  vm->pcap[rx_tx].pcap_enable = 1;
	  vlib_cli_output (vm, "pcap %s capture on...",
			   rx_tx == VLIB_RX ? "rx" : "tx");
	}
    }
  else if (chroot_filename)
    vec_free (chroot_filename);

  return error;
}

static clib_error_t *
pcap_rx_trace_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return pcap_trace_command_internal (vm, input, cmd, VLIB_RX);
}

static clib_error_t *
pcap_tx_trace_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return pcap_trace_command_internal (vm, input, cmd, VLIB_TX);
}


/*?
 * This command is used to start or stop a packet capture, or show
 * the status of packet capture. Note that both "pcap rx trace" and
 * "pcap tx trace" are implemented. The command syntax is identical,
 * simply substitute rx for tx as needed.
 *
 * This command has the following optional parameters:
 *
 * - <b>on|off</b> - Used to start or stop a packet capture.
 *
 * - <b>max <nn></b> - Depth of local buffer. Once '<em>nn</em>' number
 *   of packets have been received, buffer is flushed to file. Once another
 *   '<em>nn</em>' number of packets have been received, buffer is flushed
 *   to file, overwriting previous write. If not entered, value defaults
 *   to 100. Can only be updated if packet capture is off.
 *
 * - <b>intfc <interface>|any</b> - Used to specify a given interface,
 *   or use '<em>any</em>' to run packet capture on all interfaces.
 *   '<em>any</em>' is the default if not provided. Settings from a previous
 *   packet capture are preserved, so '<em>any</em>' can be used to reset
 *   the interface setting.
 *
 * - <b>file <name></b> - Used to specify the output filename. The file will
 *   be placed in the '<em>/tmp</em>' directory, so only the filename is
 *   supported. Directory should not be entered. If file already exists, file
 *   will be overwritten. If no filename is provided, '<em>/tmp/vpe.pcap</em>'
 *   will be used. Can only be updated if packet capture is off.
 *
 * - <b>status</b> - Displays the current status and configured attributes
 *   associated with a packet capture. If packet capture is in progress,
 *   '<em>status</em>' also will return the number of packets currently in
 *   the local buffer. All additional attributes entered on command line
 *   with '<em>status</em>' will be ignored and not applied.
 *
 * @cliexpar
 * Example of how to display the status of a tx packet capture when off:
 * @cliexstart{pcap tx trace status}
 * max is 100, for any interface to file /tmp/vpe.pcap
 * pcap tx capture is off...
 * @cliexend
 * Example of how to start a tx packet capture:
 * @cliexstart{pcap tx trace on max 35 intfc GigabitEthernet0/8/0 file vppTest.pcap}
 * pcap tx capture on...
 * @cliexend
 * Example of how to display the status of a tx packet capture in progress:
 * @cliexstart{pcap tx trace status}
 * max is 35, for interface GigabitEthernet0/8/0 to file /tmp/vppTest.pcap
 * pcap tx capture is on: 20 of 35 pkts...
 * @cliexend
 * Example of how to stop a tx packet capture:
 * @cliexstart{vppctl pcap tx trace off}
 * captured 21 pkts...
 * saved to /tmp/vppTest.pcap...
 * @cliexend
?*/
/* *INDENT-OFF* */

VLIB_CLI_COMMAND (pcap_tx_trace_command, static) = {
    .path = "pcap tx trace",
    .short_help =
    "pcap tx trace [on|off] [max <nn>] [intfc <interface>|any] [file <name>] [status]",
    .function = pcap_tx_trace_command_fn,
};
VLIB_CLI_COMMAND (pcap_rx_trace_command, static) = {
    .path = "pcap rx trace",
    .short_help =
    "pcap rx trace [on|off] [max <nn>] [intfc <interface>|any] [file <name>] [status]",
    .function = pcap_rx_trace_command_fn,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
