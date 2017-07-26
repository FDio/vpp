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
 * Interface CLI.
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

/* *INDENT-OFF* */
/*?
 * Displays various information about the state of the current terminal
 * session.
 *
 * @cliexpar
 * @cliexstart{show hardware}
 * Name                Link  Hardware
 * GigabitEthernet2/0/0               up   GigabitEthernet2/0/0
 * Ethernet address 00:50:56:b7:7c:83
 * Intel 82545em_copper
 *   link up, media 1000T full-duplex, master,
 *   0 unprocessed, 384 total buffers on rx queue 0 ring
 *   237 buffers in driver rx cache
 *   rx total packets                                    1816
 *   rx total bytes                                    181084
 *   rx good packets                                     1816
 *   rx good bytes                                     181084
 *   rx 65 127 byte packets                              1586
 *   rx 256 511 byte packets                              230
 *   tx total packets                                     346
 *   tx total bytes                                     90224
 *   tx good packets                                      346
 *   tx good bytes                                      88840
 *   tx 64 byte packets                                     1
 *   tx 65 127 byte packets                               115
 *   tx 256 511 byte packets                              230
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (show_hw_interfaces_command, static) = {
  .path = "show hardware-interfaces",
  .short_help = "show hardware-interfaces [brief|verbose|detail] [bond] [<if-name1> <if-name2> ...]",
  .function = show_or_clear_hw_interfaces,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_hw_interface_counters_command, static) = {
  .path = "clear hardware-interfaces",
  .short_help = "Clear hardware interfaces statistics",
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
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_sw_interface_t *si, *sorted_sis = 0;
  u32 sw_if_index = ~(u32) 0;
  u8 show_addresses = 0;
  u8 show_features = 0;
  u8 show_tag = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      /* See if user wants to show specific interface */
      if (unformat
	  (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	{
	  si = pool_elt_at_index (im->sw_interfaces, sw_if_index);
	  vec_add1 (sorted_sis, si[0]);
	}
      else if (unformat (input, "address") || unformat (input, "addr"))
	show_addresses = 1;
      else if (unformat (input, "features") || unformat (input, "feat"))
	show_features = 1;
      else if (unformat (input, "tag"))
	show_tag = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (show_features || show_tag)
    {
      if (sw_if_index == ~(u32) 0)
	return clib_error_return (0, "Interface not specified...");
    }

  if (show_features)
    {
      vnet_interface_features_show (vm, sw_if_index);

      l2_input_config_t *l2_input = l2input_intf_config (sw_if_index);
      u32 fb = l2_input->feature_bitmap;
      /* intf input features are masked by bridge domain */
      if (l2_input->bridge)
	fb &= l2input_bd_config (l2_input->bd_index)->feature_bitmap;
      vlib_cli_output (vm, "\nl2-input:\n%U", format_l2_input_features, fb);

      l2_output_config_t *l2_output = l2output_intf_config (sw_if_index);
      vlib_cli_output (vm, "\nl2-output:");
      if (l2_output->out_vtr_flag)
	vlib_cli_output (vm, "%10s (%s)", "VTR", "--internal--");
      vlib_cli_output (vm, "%U", format_l2_output_features,
		       l2_output->feature_bitmap);
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
      pool_foreach (si, im->sw_interfaces, (
					     {
					     int visible =
					     vnet_swif_is_api_visible (si);
					     if (visible)
					     vec_add1 (sorted_sis, si[0]);}
		    ));

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
	ip4_address_t *r4;
	ip6_address_t *r6;
	u32 fib_index4 = 0, fib_index6 = 0;
	ip4_fib_t *fib4;
	ip6_fib_t *fib6;

	if (vec_len (im4->fib_index_by_sw_if_index) > si->sw_if_index)
	  fib_index4 = vec_elt (im4->fib_index_by_sw_if_index,
				si->sw_if_index);

	if (vec_len (im6->fib_index_by_sw_if_index) > si->sw_if_index)
	  fib_index6 = vec_elt (im6->fib_index_by_sw_if_index,
				si->sw_if_index);

	fib4 = ip4_fib_get (fib_index4);
	fib6 = ip6_fib_get (fib_index6);

	if (si->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)
	  vlib_cli_output
	    (vm, "%U (%s): \n  unnumbered, use %U",
	     format_vnet_sw_if_index_name,
	     vnm, si->sw_if_index,
	     (si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? "up" : "dn",
	     format_vnet_sw_if_index_name, vnm, si->unnumbered_sw_if_index);

	else
	  {
	    vlib_cli_output (vm, "%U (%s):",
			     format_vnet_sw_if_index_name,
			     vnm, si->sw_if_index,
			     (si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
			     ? "up" : "dn");
	  }

	/* Display any L2 info */
	l2_input_config_t *l2_input = l2input_intf_config (si->sw_if_index);
	if (l2_input->bridge)
	  {
	    u32 bd_id = l2input_main.bd_configs[l2_input->bd_index].bd_id;
	    vlib_cli_output (vm, "  l2 bridge bd_id %d%s%d", bd_id,
			     l2_input->bvi ? " bvi shg " : " shg ",
			     l2_input->shg);
	  }
	else if (l2_input->xconnect)
	  {
	    vlib_cli_output (vm, "  l2 xconnect %U",
			     format_vnet_sw_if_index_name,
			     vnm, l2_input->output_sw_if_index);
	  }

	/* Display any IP4 addressing info */
          /* *INDENT-OFF* */
	  foreach_ip_interface_address (lm4, ia, si->sw_if_index,
					1 /* honor unnumbered */,
	  ({
            r4 = ip_interface_address_get_address (lm4, ia);
            if (fib4->table_id)
              {
                vlib_cli_output (vm, "  %U/%d table %d",
                                 format_ip4_address, r4,
                                 ia->address_length,
                                 fib4->table_id);
              }
            else
              {
                vlib_cli_output (vm, "  %U/%d",
                                 format_ip4_address, r4,
                                 ia->address_length);
              }
          }));
          /* *INDENT-ON* */

	/* Display any IP6 addressing info */
          /* *INDENT-OFF* */
          foreach_ip_interface_address (lm6, ia, si->sw_if_index,
                                        1 /* honor unnumbered */,
          ({
            r6 = ip_interface_address_get_address (lm6, ia);
            if (fib6->table_id)
              {
                vlib_cli_output (vm, "  %U/%d table %d",
                                 format_ip6_address, r6,
                                 ia->address_length,
                                 fib6->table_id);
              }
            else
              {
                vlib_cli_output (vm, "  %U/%d",
                                 format_ip6_address, r6,
                                 ia->address_length);
              }
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
  .short_help = "show interface [address|addr|features|feat] [<if-name1> <if-name2> ...]",
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_interface_counters_command, static) = {
  .path = "clear interfaces",
  .short_help = "Clear interfaces statistics",
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

  memset (&template, 0, sizeof (template));
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

/* *INDENT-OFF* */
/*?
 * Create vlan subinterfaces
 *
 * @cliexpar
 * @cliexstart{create sub-interfaces}
 *
 * To create a vlan subinterface 11 to process packets on 802.1q VLAN id 11, use:
 *
 *  vpp# create sub GigabitEthernet2/0/0 11
 *
 * This shorthand is equivalent to:
 *  vpp# create sub GigabitEthernet2/0/0 11 dot1q 11 exact-match
 *
 * You can specify a subinterface number that is different from the vlan id:
 *  vpp# create sub GigabitEthernet2/0/0 11 dot1q 100
 *
 * You can create qinq and q-in-any interfaces:
 *  vpp# create sub GigabitEthernet2/0/0 11 dot1q 100 inner-dot1q 200
 *  vpp# create sub GigabitEthernet2/0/0 12 dot1q 100 inner-dot1q any
 *
 * You can also create dot1ad interfaces:
 *  vpp# create sub GigabitEthernet2/0/0 11 dot1ad 11
 *  vpp# create sub GigabitEthernet2/0/0 12 dot1q 100 inner-dot1q 200
 *
 * Subinterfaces can be configured as either exact-match or non-exact match.
 * Non-exact match is the CLI default. If exact-match is specified,
 * packets must have the same number of vlan tags as the configuration.
 * For non-exact-match, packets must at least that number of tags.
 * L3 (routed) interfaces must be configured as exact-match.
 * L2 interfaces are typically configured as non-exact-match.
 *
 * For example, a packet with outer vlan 100 and inner 200 would match this interface:
 *  vpp# create sub GigabitEthernet2/0/0 5 dot1q 100
 *
 * but would not match this interface:
 *  vpp# create sub GigabitEthernet2/0/0 5 dot1q 100 exact-match
 *
 * There are two special subinterfaces that can be configured. Subinterface untagged has no vlan tags:
 *  vpp# create sub GigabitEthernet2/0/0 5 untagged
 *
 * The subinterface default matches any packet that does not match any other subinterface:
 *  vpp# create sub GigabitEthernet2/0/0 7 default
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (create_sub_interfaces_command, static) = {
  .path = "create sub-interfaces",
  .short_help = "create sub-interfaces <nn>[-<nn>] [dot1q|dot1ad|default|untagged]",
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


/* *INDENT-OFF* */
/*?
 * Interface admin up/down
 *
 * @cliexpar
 * @cliexstart{set interface state}
 *  vpp# set interface state GigabitEthernet2/0/0 up
 *  vpp# set interface state GigabitEthernet2/0/0 down
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (set_state_command, static) = {
  .path = "set interface state",
  .short_help = "set interface state <if-name> [up|down|punt|enable]",
  .function = set_state,
};
/* *INDENT-ON* */

static clib_error_t *
set_unnumbered (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 unnumbered_sw_if_index;
  u32 inherit_from_sw_if_index;
  vnet_sw_interface_t *si;
  int is_set = 0;
  int is_del = 0;
  u32 was_unnum;

  if (unformat (input, "%U use %U",
		unformat_vnet_sw_interface, vnm, &unnumbered_sw_if_index,
		unformat_vnet_sw_interface, vnm, &inherit_from_sw_if_index))
    is_set = 1;
  else if (unformat (input, "del %U",
		     unformat_vnet_sw_interface, vnm,
		     &unnumbered_sw_if_index))
    is_del = 1;
  else
    return clib_error_return (0, "parse error '%U'",
			      format_unformat_error, input);

  si = vnet_get_sw_interface (vnm, unnumbered_sw_if_index);
  was_unnum = (si->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED);

  if (is_del)
    {
      si->flags &= ~(VNET_SW_INTERFACE_FLAG_UNNUMBERED);
      si->unnumbered_sw_if_index = (u32) ~ 0;

      ip4_main.lookup_main.if_address_pool_index_by_sw_if_index
	[unnumbered_sw_if_index] = ~0;
      ip6_main.lookup_main.if_address_pool_index_by_sw_if_index
	[unnumbered_sw_if_index] = ~0;
    }
  else if (is_set)
    {
      si->flags |= VNET_SW_INTERFACE_FLAG_UNNUMBERED;
      si->unnumbered_sw_if_index = inherit_from_sw_if_index;

      ip4_main.lookup_main.if_address_pool_index_by_sw_if_index
	[unnumbered_sw_if_index] =
	ip4_main.lookup_main.if_address_pool_index_by_sw_if_index
	[inherit_from_sw_if_index];
      ip6_main.lookup_main.if_address_pool_index_by_sw_if_index
	[unnumbered_sw_if_index] =
	ip6_main.lookup_main.if_address_pool_index_by_sw_if_index
	[inherit_from_sw_if_index];
    }

  if (was_unnum != (si->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED))
    {
      ip4_sw_interface_enable_disable (unnumbered_sw_if_index, !is_del);
      ip6_sw_interface_enable_disable (unnumbered_sw_if_index, !is_del);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_unnumbered_command, static) = {
  .path = "set interface unnumbered",
  .short_help = "set interface unnumbered [<intfc> use <intfc> | del <intfc>]",
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
  .short_help = "renumber interface <if-name> <new-dev-instance>",
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
  .short_help = "set interface promiscuous [on | off] <intfc>",
  .function = promiscuous_cmd,
};
/* *INDENT-ON* */

static clib_error_t *
mtu_cmd (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index, mtu;
  u32 flags = ETHERNET_INTERFACE_FLAG_MTU;
  ethernet_main_t *em = &ethernet_main;

  if (unformat (input, "%d %U", &mtu,
		unformat_vnet_hw_interface, vnm, &hw_if_index))
    {
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

      if (hi->max_packet_bytes != mtu)
	{
	  hi->max_packet_bytes = mtu;
	  ethernet_set_flags (vnm, hw_if_index, flags);
	}
    }
  else
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_mtu_cmd, static) = {
  .path = "set interface mtu",
  .short_help = "set interface mtu <value> <intfc>",
  .function = mtu_cmd,
};
/* *INDENT-ON* */

static clib_error_t *
set_interface_mac_address (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index = ~0;
  u64 mac = 0;

  if (!unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }
  if (!unformat_user (input, unformat_ethernet_address, &mac))
    {
      error = clib_error_return (0, "expected mac address `%U'",
				 format_unformat_error, input);
      goto done;
    }
  error = vnet_hw_interface_change_mac_address (vnm, sw_if_index, mac);
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
  .short_help = "set interface mac address <intfc> <mac-address>",
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
  .short_help = "set interface tag <intfc> <tag>",
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
  .short_help = "clear interface tag <intfc>",
  .function = clear_tag,
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
    default:
      return clib_error_return (0, "unknown error");
    }

  return 0;
}

static clib_error_t *
set_interface_rx_mode (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw;
  u32 hw_if_index = (u32) ~ 0;
  u32 queue_id = (u32) ~ 0;
  vnet_hw_interface_rx_mode mode = VNET_HW_INTERFACE_RX_MODE_UNKNOWN;
  int i;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	;
      else if (unformat (line_input, "queue %d", &queue_id))
	;
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

  hw = vnet_get_hw_interface (vnm, hw_if_index);

  if (queue_id == ~0)
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

/*?
 * This command is used to assign a given interface, and optionally a
 * given queue, to a different thread. If the '<em>queue</em>' is not provided,
 * it defaults to 0.
 *
 * @cliexpar
 * Example of how to display the interface placement:
 * @cliexstart{show interface rx-placement}
 * Thread 1 (vpp_wk_0):
 *   GigabitEthernet0/8/0 queue 0
 *   GigabitEthernet0/9/0 queue 0
 * Thread 2 (vpp_wk_1):
 *   GigabitEthernet0/8/0 queue 1
 *   GigabitEthernet0/9/0 queue 1
 * @cliexend
 * Example of how to assign a interface and queue to a thread:
 * @cliexcmd{set interface placement GigabitEthernet0/8/0 queue 1 thread 1}
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
        vlib_cli_output(vm, "Thread %u (%v):\n%v", index,
			vlib_worker_threads[index].name, s);
        vec_reset_length (s);
      }
    index++;
  }));
  /* *INDENT-ON* */

  vec_free (s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_interface_rx_placement, static) = {
  .path = "show interface rx-placement",
  .short_help = "show interface rx-placement",
  .function = show_interface_rx_placement_fn,
};
/* *INDENT-ON* */

static clib_error_t *
set_interface_rx_placement (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_device_main_t *vdm = &vnet_device_main;
  vnet_hw_interface_rx_mode mode;
  u32 hw_if_index = (u32) ~ 0;
  u32 queue_id = (u32) 0;
  u32 thread_index = (u32) ~ 0;
  int rv;

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
	thread_index = 0;
      else if (unformat (line_input, "worker %d", &thread_index))
	thread_index += vdm->first_worker_thread_index;
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

  return 0;
}

/*?
 * This command is used to assign a given interface, and optionally a
 * given queue, to a different thread. If the '<em>queue</em>' is not provided,
 * it defaults to 0.
 *
 * @cliexpar
 * Example of how to display the interface placement:
 * @cliexstart{show interface placement}
 * Thread 1 (vpp_wk_0):
 *   GigabitEthernet0/8/0 queue 0
 *   GigabitEthernet0/9/0 queue 0
 * Thread 2 (vpp_wk_1):
 *   GigabitEthernet0/8/0 queue 1
 *   GigabitEthernet0/9/0 queue 1
 * @cliexend
 * Example of how to assign a interface and queue to a thread:
 * @cliexcmd{set interface placement GigabitEthernet0/8/0 queue 1 thread 1}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_if_rx_placement,static) = {
    .path = "set interface rx-placement",
    .short_help = "set interface rx-placement <hw-interface> [queue <n>] "
      "[worker <n> | main]",
    .function = set_interface_rx_placement,
    .is_mp_safe = 1,
};

/* *INDENT-ON* */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
