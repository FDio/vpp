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

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

static int compare_interface_names (void *a1, void *a2)
{
  u32 * hi1 = a1;
  u32 * hi2 = a2;

  return vnet_hw_interface_compare (vnet_get_main(), *hi1, *hi2);
}

static clib_error_t *
show_or_clear_hw_interfaces (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  clib_error_t * error = 0;
  vnet_main_t * vnm = vnet_get_main();
  vnet_interface_main_t * im = &vnm->interface_main;
  vnet_hw_interface_t * hi;
  u32 hw_if_index, * hw_if_indices = 0;
  int i, verbose = 1, is_show;

  is_show = strstr (cmd->path, "show") != 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      /* See if user wants to show a specific interface. */
      if (unformat (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	{
	  vec_add1 (hw_if_indices, hw_if_index);
	  /* Implies verbose. */
	  verbose = 1;
	}
      /* See if user wants to show an interface with a specific hw_if_index. */
      else if (unformat (input, "%u", &hw_if_index))
       {
         vec_add1 (hw_if_indices, hw_if_index);
         /* Implies verbose. */
         verbose = 1;
       }

      else if (unformat (input, "verbose"))
	verbose = 1;

      else if (unformat (input, "detail"))
	verbose = 2;

      else if (unformat (input, "brief"))
	verbose = 0;

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

  if (is_show)
    {
      /* Sort by name. */
      vec_sort_with_function (hw_if_indices, compare_interface_names);

      vlib_cli_output (vm, "%U\n", format_vnet_hw_interface, vnm, 0, verbose);
      for (i = 0; i < vec_len (hw_if_indices); i++)
	{
	  hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);
	  vlib_cli_output (vm, "%U\n", format_vnet_hw_interface, vnm, hi, verbose);
	}
    }
  else
    {
      for (i = 0; i < vec_len (hw_if_indices); i++)
	{
	  vnet_device_class_t * dc;

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

VLIB_CLI_COMMAND (show_hw_interfaces_command, static) = {
  .path = "show hardware-interfaces",
  .short_help = "show hardware-interfaces [verbose|brief]  [<if-name1> <if-name2> ...]",
  .function = show_or_clear_hw_interfaces,
};

VLIB_CLI_COMMAND (clear_hw_interface_counters_command, static) = {
  .path = "clear hardware-interfaces",
  .short_help = "Clear hardware interfaces statistics",
  .function = show_or_clear_hw_interfaces,
};

static int sw_interface_name_compare (void *a1, void *a2)
{
  vnet_sw_interface_t *si1 = a1;
  vnet_sw_interface_t *si2 = a2;

  return vnet_sw_interface_compare (vnet_get_main(), 
                                    si1->sw_if_index, si2->sw_if_index);
}

static clib_error_t *
show_sw_interfaces (vlib_main_t * vm,
		    unformat_input_t * input,
		    vlib_cli_command_t * cmd)
{
  clib_error_t * error = 0;
  vnet_main_t * vnm = vnet_get_main();
  vnet_interface_main_t * im = &vnm->interface_main;
  vnet_sw_interface_t * si, * sorted_sis = 0;
  u8 show_addresses = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
       u32 sw_if_index;

      /* See if user wants to show specific interface */
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	{
	  si =  pool_elt_at_index (im->sw_interfaces, sw_if_index);
	  vec_add1 (sorted_sis, si[0]);
	}

      else if (unformat (input, "address") || unformat (input, "addr"))
	  show_addresses = 1;

      else
        {
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
        }
    }

  if (!show_addresses)
      vlib_cli_output (vm, "%U\n", format_vnet_sw_interface, vnm, 0);

  if (vec_len (sorted_sis) == 0) /* Get all interfaces */
    {
      /* Gather interfaces. */
      sorted_sis = vec_new (vnet_sw_interface_t, pool_elts (im->sw_interfaces));
      _vec_len (sorted_sis) = 0;
      pool_foreach (si, im->sw_interfaces, ({ vec_add1 (sorted_sis, si[0]); }));

      /* Sort by name. */
      vec_sort_with_function (sorted_sis, sw_interface_name_compare);
    }

  if (show_addresses)
    {
      vec_foreach (si, sorted_sis)
        {
	  l2input_main_t * l2m = &l2input_main;
          ip4_main_t * im4 = &ip4_main;
          ip6_main_t * im6 = &ip6_main;
          ip_lookup_main_t * lm4 = &im4->lookup_main;
          ip_lookup_main_t * lm6 = &im6->lookup_main;
          ip_interface_address_t * ia = 0;
          ip4_address_t * r4;
          ip6_address_t * r6;
          u32 fib_index4 = 0, fib_index6 = 0;
          ip4_fib_t * fib4;
          ip6_fib_t * fib6;
	  l2_input_config_t * config;

          if (vec_len (im4->fib_index_by_sw_if_index) > si->sw_if_index)
            fib_index4 = vec_elt (im4->fib_index_by_sw_if_index, 
                                  si->sw_if_index);

          if (vec_len (im6->fib_index_by_sw_if_index) > si->sw_if_index)
            fib_index6 = vec_elt (im6->fib_index_by_sw_if_index,
                                  si->sw_if_index);

          fib4 = vec_elt_at_index (im4->fibs, fib_index4);
          fib6 = vec_elt_at_index (im6->fibs, fib_index6);

          if (si->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)
            vlib_cli_output 
                (vm, "%U (%s): \n  unnumbered, use %U", 
                 format_vnet_sw_if_index_name,
                 vnm, si->sw_if_index,
                 (si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? "up" : "dn",
                 format_vnet_sw_if_index_name,
                 vnm, si->unnumbered_sw_if_index);
                             
          else
            {
            vlib_cli_output (vm, "%U (%s):", 
                             format_vnet_sw_if_index_name,
                             vnm, si->sw_if_index,
                             (si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) 
                             ? "up" : "dn");
            }

	  /* Display any L2 addressing info */
	  vec_validate(l2m->configs, si->sw_if_index);
	  config = vec_elt_at_index(l2m->configs, si->sw_if_index);
	  if (config->bridge) 
	    {
	      u32 bd_id = l2input_main.bd_configs[config->bd_index].bd_id;
	      vlib_cli_output (vm, "  l2 bridge bd_id %d%s%d", bd_id, 
			     config->bvi ? " bvi shg " : " shg ", config->shg);
            } 
	  else if (config->xconnect) 
	    {
	      vlib_cli_output (vm, "  l2 xconnect %U", 
			       format_vnet_sw_if_index_name,
			       vnm, config->output_sw_if_index);
	    }

	  /* Display any IP4 addressing info */
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

	  /* Display any IP6 addressing info */
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

VLIB_CLI_COMMAND (show_sw_interfaces_command, static) = {
  .path = "show interfaces",
  .short_help = "show interfaces [address|addr] [<if-name1> <if-name2> ...]",
  .function = show_sw_interfaces,
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
clear_interface_counters (vlib_main_t * vm,
			  unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  vnet_interface_main_t * im = &vnm->interface_main;
  vlib_simple_counter_main_t * sm;
  vlib_combined_counter_main_t * cm;
  static vnet_main_t ** my_vnet_mains;
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
      for (i = 0; i < vec_len(my_vnet_mains); i++)
        {
          im = &my_vnet_mains[i]->interface_main;
          cm = im->combined_sw_if_counters + j;
          vlib_clear_combined_counters (cm);
        }
    }

  n_counters = vec_len (im->sw_if_counters);

  for (j = 0; j < n_counters; j++)
    {
      for (i = 0; i < vec_len(my_vnet_mains); i++)
        {
          im = &my_vnet_mains[i]->interface_main;
          sm = im->sw_if_counters + j;
          vlib_clear_simple_counters (sm);
        }
    }

  return 0;
}

VLIB_CLI_COMMAND (clear_interface_counters_command, static) = {
  .path = "clear interfaces",
  .short_help = "Clear interfaces statistics",
  .function = clear_interface_counters,
};

// The following subinterface syntax is supported. The first two are for 
// backwards compatability:
//
// <intf-name> <id>
//     - a subinterface with the name <intf-name>.<id>. The subinterface
//       is a single dot1q vlan with vlan id <id> and exact-match semantics.
//
// <intf-name> <min_id>-<max_id> 
//     - a set of the above subinterfaces, repeating for each id
//       in the range <min_id> to <max_id>
//
// In the following, exact-match semantics (i.e. the number of vlan tags on the
// packet must match the number of tags in the configuration) are used only if 
// the keyword exact-match is present. Non-exact match is the default.
//
// <intf-name> <id> dot1q <outer_id> [exact-match]
//     - a subinterface with the name <intf-name>.<id>. The subinterface
//       is a single dot1q vlan with vlan id <outer_id>. 
//
// <intf-name> <id> dot1q any [exact-match]
//     - a subinterface with the name <intf-name>.<id>. The subinterface
//       is a single dot1q vlan with any vlan id.
//
// <intf-name> <id> dot1q <outer_id> inner-dot1q <inner_id> [exact-match]
//     - a subinterface with the name <intf-name>.<id>. The subinterface
//       is a double dot1q vlan with outer vlan id <outer_id> and inner vlan id 
//       <inner_id>. 
//
// <intf-name> <id> dot1q <outer_id> inner-dot1q any [exact-match]
//     - a subinterface with the name <intf-name>.<id>. The subinterface
//       is a double dot1q vlan with outer vlan id <id> and any inner vlan id.
//
// <intf-name> <id> dot1q any inner-dot1q any [exact-match]
//
//     - a subinterface with the name <intf-name>.<id>. The subinterface
//       is a double dot1q vlan with any outer vlan id and any inner vlan id.
//
// For each of the above CLI, there is a duplicate that uses the keyword
// "dot1ad" in place of the first "dot1q". These interfaces use ethertype
// 0x88ad in place of 0x8100 for the outer ethertype. Note that for double-
// tagged packets the inner ethertype is always 0x8100. Also note that
// the dot1q and dot1ad naming spaces are independent, so it is legal to
// have both "Gig3/0/0.1 dot1q 100" and "Gig3/0/0.2 dot1ad 100". For example:
//
// <intf-name> <id> dot1ad <outer_id> inner-dot1q <inner_id> [exact-match]
//     - a subinterface with the name <intf-name>.<id>. The subinterface
//       is a double dot1ad vlan with outer vlan id <outer_id> and inner vlan 
//       id <inner_id>. 
//
// <intf-name> <id> untagged
//     - a subinterface with the name <intf-name>.<id>. The subinterface
//       has no vlan tags. Only one can be specified per interface.
//      
// <intf-name> <id> default
//     - a subinterface with the name <intf-name>.<id>. This is associated
//       with a packet that did not match any other configured subinterface
//       on this interface. Only one can be specified per interface.


static clib_error_t *
parse_vlan_sub_interfaces (unformat_input_t    * input,
                           vnet_sw_interface_t * template)
{
  clib_error_t * error = 0;
  u32 inner_vlan, outer_vlan;

  if (unformat (input, "any inner-dot1q any")) {
    template->sub.eth.flags.two_tags = 1;
    template->sub.eth.flags.outer_vlan_id_any = 1;
    template->sub.eth.flags.inner_vlan_id_any = 1;
  } else if (unformat (input, "any")) {
    template->sub.eth.flags.one_tag = 1;
    template->sub.eth.flags.outer_vlan_id_any = 1;
  } else if (unformat (input, "%d inner-dot1q any", &outer_vlan)) {
    template->sub.eth.flags.two_tags = 1;
    template->sub.eth.flags.inner_vlan_id_any = 1;
    template->sub.eth.outer_vlan_id = outer_vlan;     
  } else if (unformat (input, "%d inner-dot1q %d", &outer_vlan, &inner_vlan)) {
    template->sub.eth.flags.two_tags = 1;
    template->sub.eth.outer_vlan_id = outer_vlan;
    template->sub.eth.inner_vlan_id = inner_vlan;     
  } else if (unformat (input, "%d", &outer_vlan)) {
    template->sub.eth.flags.one_tag = 1;
    template->sub.eth.outer_vlan_id = outer_vlan;
  } else {
    error = clib_error_return (0, "expected dot1q config, got `%U'",
                              format_unformat_error, input);
    goto done;
  }

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "exact-match")) {
      template->sub.eth.flags.exact_match = 1;
    }
  }

 done:
  return error;
}

static clib_error_t *
create_sub_interfaces (vlib_main_t * vm,
		       unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  u32 hw_if_index, sw_if_index;
  vnet_hw_interface_t * hi;
  u32 id, id_min, id_max;
  vnet_sw_interface_t template;

  hw_if_index = ~0;
  if (! unformat_user (input, unformat_vnet_hw_interface, vnm, &hw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  memset (&template, 0, sizeof (template));
  template.sub.eth.raw_flags = 0;

  if (unformat (input, "%d default", &id_min)) {
    id_max = id_min;
    template.sub.eth.flags.default_sub = 1;
  } else if (unformat (input, "%d untagged", &id_min)) {
    id_max = id_min;
    template.sub.eth.flags.no_tags = 1;
    template.sub.eth.flags.exact_match = 1;
  } else if (unformat (input, "%d dot1q", &id_min)) {
    // parse dot1q config
    id_max = id_min;
    error = parse_vlan_sub_interfaces(input, &template);
    if (error) goto done;
  } else if (unformat (input, "%d dot1ad", &id_min)) {
    // parse dot1ad config
    id_max = id_min;
    template.sub.eth.flags.dot1ad = 1;
    error = parse_vlan_sub_interfaces(input, &template);
    if (error) goto done;
  } else if (unformat (input, "%d-%d", &id_min, &id_max)) {
    template.sub.eth.flags.one_tag = 1;
    template.sub.eth.outer_vlan_id = id_min;
    template.sub.eth.flags.exact_match = 1;
    if (id_min > id_max)
      goto id_error;
  } else if (unformat (input, "%d", &id_min)) {
    id_max = id_min;
    template.sub.eth.flags.one_tag = 1;
    template.sub.eth.outer_vlan_id = id_min;
    template.sub.eth.flags.exact_match = 1;
  } else {
    id_error:
      error = clib_error_return (0, "expected ID or ID MIN-MAX, got `%U'",
				 format_unformat_error, input);
      goto done;
  }

  /*
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    error = clib_error_return (0, "unexpected text `%U'",
                               format_unformat_error, input);
    goto done;
  }
  */

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  for (id = id_min; id <= id_max; id++)
    {
      uword * p;
      vnet_interface_main_t * im = &vnm->interface_main;
      u64 sup_and_sub_key = ((u64)(hi->sw_if_index) << 32) |
          (u64) id;
      u64 * kp;

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
      template.sup_sw_if_index = hi->sw_if_index;
      template.sub.id = id;
      error = vnet_create_sw_interface (vnm, &template, &sw_if_index);
      if (error) goto done;
      hash_set (hi->sub_interface_sw_if_index_by_id, id, sw_if_index);
      hash_set_mem (im->sw_if_index_by_sup_and_sub, kp, sw_if_index);
    }

  if (error)
    goto done;

 done:
  return error;
}

VLIB_CLI_COMMAND (create_sub_interfaces_command, static) = {
  .path = "create sub-interface",
  .short_help = "create sub-interfaces <nn>[-<nn>] [dot1q|dot1ad|default|untagged]",
  .function = create_sub_interfaces,
};

static clib_error_t *
set_state (vlib_main_t * vm,
	   unformat_input_t * input,
	   vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error;
  u32 sw_if_index, flags;

  sw_if_index = ~0;
  if (! unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (! unformat (input, "%U", unformat_vnet_sw_interface_flags, &flags))
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

VLIB_CLI_COMMAND (set_state_command, static) = {
  .path = "set interface state",
  .short_help = "Set interface state",
  .function = set_state,
};

static clib_error_t *
set_unnumbered (vlib_main_t * vm,
                unformat_input_t * input,
                vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  u32 unnumbered_sw_if_index;
  u32 inherit_from_sw_if_index;
  vnet_sw_interface_t * si;
  int is_set = 0;
  int is_del = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
  {

      if (unformat (input, "%U use %U", 
                    unformat_vnet_sw_interface, vnm, &unnumbered_sw_if_index,
                    unformat_vnet_sw_interface, vnm, &inherit_from_sw_if_index))
          is_set = 1;
      else if (unformat (input, "del %U",
                         unformat_vnet_sw_interface, 
                         vnm, &unnumbered_sw_if_index))
          is_del = 1;
      else
        {
          if (is_set || is_del)
            break;
          else
            return clib_error_return 
              (0, "parse error '%U'", format_unformat_error, input);
        }
  }

  si = vnet_get_sw_interface (vnm, unnumbered_sw_if_index);
  if (is_del) {
      si->flags &= ~(VNET_SW_INTERFACE_FLAG_UNNUMBERED);
      si->unnumbered_sw_if_index = (u32)~0;
  } else {
      si->flags |= VNET_SW_INTERFACE_FLAG_UNNUMBERED;
      si->unnumbered_sw_if_index = inherit_from_sw_if_index;
  }
      
  return 0;
}

VLIB_CLI_COMMAND (set_unnumbered_command, static) = {
  .path = "set interface unnumbered",
  .short_help = "set interface unnumbered [<intfc> use <intfc>][del <intfc>]",
  .function = set_unnumbered,
};



static clib_error_t *
set_hw_class (vlib_main_t * vm,
	      unformat_input_t * input,
	      vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  vnet_interface_main_t * im = &vnm->interface_main;
  clib_error_t * error;
  u32 hw_if_index, hw_class_index;

  hw_if_index = ~0;
  if (! unformat_user (input, unformat_vnet_hw_interface, vnm, &hw_if_index))
    {
      error = clib_error_return (0, "unknown hardware interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (! unformat_user (input, unformat_hash_string,
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

VLIB_CLI_COMMAND (set_hw_class_command, static) = {
  .path = "set interface hw-class",
  .short_help = "Set interface hardware class",
  .function = set_hw_class,
};

static clib_error_t * vnet_interface_cli_init (vlib_main_t * vm)
{ return 0; }

VLIB_INIT_FUNCTION (vnet_interface_cli_init);

static clib_error_t * 
renumber_interface_command_fn (vlib_main_t * vm,
                               unformat_input_t * input,
                               vlib_cli_command_t * cmd)
{
  u32 hw_if_index;
  u32 new_dev_instance;
  vnet_main_t * vnm = vnet_get_main();
  int rv;

  if (! unformat_user (input, unformat_vnet_hw_interface, vnm, &hw_if_index))
    return clib_error_return (0, "unknown hardware interface `%U'",
                              format_unformat_error, input);

  if (! unformat (input, "%d", &new_dev_instance))
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


VLIB_CLI_COMMAND (renumber_interface_command, static) = {
  .path = "renumber interface",
  .short_help = "renumber interface <if-name> <new-dev-instance>",
  .function = renumber_interface_command_fn,
};

