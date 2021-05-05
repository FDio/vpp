/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief NAT66 CLI
 */

#include <nat/nat66/nat66.h>
#include <vnet/fib/fib_table.h>

#define NAT66_EXPECTED_ARGUMENT "expected required argument(s)"
#define NAT66_PLUGIN_DISABLED	"error plugin disabled"

#define CHECK_ENABLED()                                                       \
  do                                                                          \
    {                                                                         \
      if (PREDICT_FALSE (!nat66_main.enabled))                                \
	{                                                                     \
	  return clib_error_return (0, NAT66_PLUGIN_DISABLED);                \
	}                                                                     \
    }                                                                         \
  while (0)

static clib_error_t *
nat66_enable_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  nat66_main_t *nm = &nat66_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  u32 outside_vrf = 0;
  u8 enable_set = 0, enable = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT66_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "outside-vrf %u", &outside_vrf))
	;
      else if (!enable_set)
	{
	  enable_set = 1;
	  if (unformat (line_input, "disable"))
	    ;
	  else if (unformat (line_input, "enable"))
	    enable = 1;
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!enable_set)
    {
      error = clib_error_return (0, "expected enable | disable");
      goto done;
    }

  if (enable)
    {
      if (nm->enabled)
	{
	  error = clib_error_return (0, "already enabled");
	  goto done;
	}

      if (nat66_plugin_enable (outside_vrf) != 0)
	error = clib_error_return (0, "enable failed");
    }
  else
    {
      if (!nm->enabled)
	{
	  error = clib_error_return (0, "already disabled");
	  goto done;
	}

      if (nat66_plugin_disable () != 0)
	error = clib_error_return (0, "disable failed");
    }

done:
  unformat_free (line_input);
  return error;
}

static clib_error_t *
nat66_interface_feature_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index;
  u32 *inside_sw_if_indices = 0;
  u32 *outside_sw_if_indices = 0;
  u8 is_add = 1;
  int i, rv;

  CHECK_ENABLED ();

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT66_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "in %U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	vec_add1 (inside_sw_if_indices, sw_if_index);
      else if (unformat (line_input, "out %U", unformat_vnet_sw_interface,
			 vnm, &sw_if_index))
	vec_add1 (outside_sw_if_indices, sw_if_index);
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (vec_len (inside_sw_if_indices))
    {
      for (i = 0; i < vec_len (inside_sw_if_indices); i++)
	{
	  sw_if_index = inside_sw_if_indices[i];
	  rv = nat66_interface_add_del (sw_if_index, 1, is_add);
	  switch (rv)
	    {
	    case VNET_API_ERROR_NO_SUCH_ENTRY:
	      error =
		clib_error_return (0, "%U NAT66 feature not enabled.",
				   format_vnet_sw_interface_name, vnm,
				   vnet_get_sw_interface (vnm, sw_if_index));
	      goto done;
	    case VNET_API_ERROR_VALUE_EXIST:
	      error =
		clib_error_return (0, "%U NAT66 feature already enabled.",
				   format_vnet_sw_interface_name, vnm,
				   vnet_get_sw_interface (vnm, sw_if_index));
	      goto done;
	    case VNET_API_ERROR_INVALID_VALUE:
	    case VNET_API_ERROR_INVALID_VALUE_2:
	      error =
		clib_error_return (0,
				   "%U NAT66 feature enable/disable failed.",
				   format_vnet_sw_interface_name, vnm,
				   vnet_get_sw_interface (vnm, sw_if_index));
	      goto done;
	    default:
	      break;

	    }
	}
    }

  if (vec_len (outside_sw_if_indices))
    {
      for (i = 0; i < vec_len (outside_sw_if_indices); i++)
	{
	  sw_if_index = outside_sw_if_indices[i];
	  rv = nat66_interface_add_del (sw_if_index, 0, is_add);
	  switch (rv)
	    {
	    case VNET_API_ERROR_NO_SUCH_ENTRY:
	      error =
		clib_error_return (0, "%U NAT66 feature not enabled.",
				   format_vnet_sw_interface_name, vnm,
				   vnet_get_sw_interface (vnm, sw_if_index));
	      goto done;
	    case VNET_API_ERROR_VALUE_EXIST:
	      error =
		clib_error_return (0, "%U NAT66 feature already enabled.",
				   format_vnet_sw_interface_name, vnm,
				   vnet_get_sw_interface (vnm, sw_if_index));
	      goto done;
	    case VNET_API_ERROR_INVALID_VALUE:
	    case VNET_API_ERROR_INVALID_VALUE_2:
	      error =
		clib_error_return (0,
				   "%U NAT66 feature enable/disable failed.",
				   format_vnet_sw_interface_name, vnm,
				   vnet_get_sw_interface (vnm, sw_if_index));
	      goto done;
	    default:
	      break;

	    }
	}
    }

done:
  unformat_free (line_input);
  vec_free (inside_sw_if_indices);
  vec_free (outside_sw_if_indices);

  return error;
}

static int
nat66_cli_interface_walk (nat66_interface_t * i, void *ctx)
{
  vlib_main_t *vm = ctx;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_cli_output (vm, " %U %s", format_vnet_sw_interface_name, vnm,
		   vnet_get_sw_interface (vnm, i->sw_if_index),
		   nat66_interface_is_inside (i) ? "in" : "out");
  return 0;
}

static clib_error_t *
nat66_show_interfaces_command_fn (vlib_main_t * vm, unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  CHECK_ENABLED ();
  vlib_cli_output (vm, "NAT66 interfaces:");
  nat66_interfaces_walk (nat66_cli_interface_walk, vm);
  return 0;
}

static clib_error_t *
nat66_add_del_static_mapping_command_fn (vlib_main_t * vm,
					 unformat_input_t * input,
					 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  ip6_address_t l_addr, e_addr;
  u32 vrf_id = 0;
  u8 is_add = 1;
  int rv;

  CHECK_ENABLED ();

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT66_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U external %U",
		    unformat_ip6_address, &l_addr,
		    unformat_ip6_address, &e_addr))
	;
      else if (unformat (line_input, "vrf %u", &vrf_id))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = nat66_static_mapping_add_del (&l_addr, &e_addr, vrf_id, is_add);

  switch (rv)
    {
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "NAT66 static mapping entry not exist.");
      goto done;
    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "NAT66 static mapping entry exist.");
      goto done;
    default:
      break;
    }

done:
  unformat_free (line_input);

  return error;
}

static int
nat66_cli_static_mapping_walk (nat66_static_mapping_t * sm, void *ctx)
{
  nat66_main_t *nm = &nat66_main;
  vlib_main_t *vm = ctx;
  fib_table_t *fib;
  vlib_counter_t vc;

  fib = fib_table_get (sm->fib_index, FIB_PROTOCOL_IP6);
  if (!fib)
    return -1;

  vlib_get_combined_counter (&nm->session_counters, sm - nm->sm, &vc);

  vlib_cli_output (vm, " local %U external %U vrf %d",
		   format_ip6_address, &sm->l_addr,
		   format_ip6_address, &sm->e_addr, fib->ft_table_id);
  vlib_cli_output (vm, "  total pkts %lld, total bytes %lld", vc.packets,
		   vc.bytes);

  return 0;
}

static clib_error_t *
nat66_show_static_mappings_command_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  CHECK_ENABLED ();
  vlib_cli_output (vm, "NAT66 static mappings:");
  nat66_static_mappings_walk (nat66_cli_static_mapping_walk, vm);
  return 0;
}

/*?
 * @cliexpar
 * @cliexstart{nat66}
 * To enable NAT66 plugin
 *  vpp# nat66 enable
 * To disable NAT66 plugin
 *  vpp# nat66 disable
 * To enable NAT66 plugin with outside-vrf id 10
 *  vpp# nat66 enable outside-vrf 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat66_enable_disable_command, static) = {
  .path = "nat66",
  .short_help = "nat66 <enable [outside-vrf <vrf-id>]>|disable",
  .function = nat66_enable_disable_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set interface nat66}
 * Enable/disable NAT66 feature on the interface.
 * To enable NAT66 feature with local (IPv6) network interface
 * GigabitEthernet0/8/0 and external (IPv4) network interface
 * GigabitEthernet0/a/0 use:
 *  vpp# set interface nat66 in GigabitEthernet0/8/0 out GigabitEthernet0/a/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (set_interface_nat66_command, static) = {
  .path = "set interface nat66",
  .short_help = "set interface nat66 in|out <intfc> [del]",
  .function = nat66_interface_feature_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat66 interfaces}
 * Show interfaces with NAT66 feature.
 * To show interfaces with NAT66 feature use:
 *  vpp# show nat66 interfaces
 *  NAT66 interfaces:
 *   GigabitEthernet0/8/0 in
 *   GigabitEthernet0/a/0 out
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_nat66_interfaces_command, static) = {
  .path = "show nat66 interfaces",
  .short_help = "show nat66 interfaces",
  .function = nat66_show_interfaces_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat66 add static mapping}
 * Add/delete NAT66 static mapping entry.
 * To add NAT66 static mapping entry use:
 *  vpp# nat66 add static mapping local fd01:1::4 external 2001:db8:c000:223::
 *  vpp# nat66 add static mapping local fd01:1::2 external 2001:db8:c000:221:: vrf 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_nat66_add_del_static_mapping_command, static) = {
  .path = "nat66 add static mapping",
  .short_help = "nat66 add static mapping local <ip6-addr> external <ip6-addr>"
                " [vfr <table-id>] [del]",
  .function = nat66_add_del_static_mapping_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat66 static mappings}
 * Show NAT66 static mappings.
 * To show NAT66 static mappings use:
 *  vpp# show nat66 static mappings
 *  NAT66 static mappings:
 *   local fd01:1::4 external 2001:db8:c000:223:: vrf 0
 *   local fd01:1::2 external 2001:db8:c000:221:: vrf 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_nat66_static_mappings_command, static) = {
  .path = "show nat66 static mappings",
  .short_help = "show nat66 static mappings",
  .function = nat66_show_static_mappings_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
