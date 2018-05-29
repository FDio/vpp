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

#include <snort/snort.h>

static clib_error_t *
snort_command_fn (vlib_main_t * vm, unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  snort_enable_disable_args_t args;
  clib_error_t *error = 0;
  u32 is_enable = 1;
  u8 sif_set = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm, &args.sw_if_index))
	sif_set = 1;
      else if (unformat (line_input, "disable"))
	is_enable = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
		                     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (is_enable && !sif_set)
    {
      error = clib_error_return (0, "sw_if_index not set");
      goto done;
    }
  args.is_en = is_enable;
  if (snort_enable_disable (&args))
    error = clib_error_return (0, "failed to enable");

  done:
  unformat_free (line_input);
  return error;
}

static clib_error_t *
snort_feature_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  snort_interface_add_del_args_t _args, *args = &_args;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0, is_add = 1;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
		                     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sw_if_index == (u32) ~0)
    {
      error = clib_error_return (0, "unknown interface provided");
      goto done;
    }

  args->is_add = is_add;
  args->sw_if_index = sw_if_index;
  if (snort_interface_add_del (args))
    error = clib_error_return (0, "failed to %s snort on interface %u",
	                       is_add ? "enable" : "disable", sw_if_index);

done:
  unformat_free (line_input);
  return error;
}

static clib_error_t *
snort_feature_status_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  snort_main_t *sm = snort_get_main ();

  vlib_cli_output (vm, "status: %s", sm->is_enabled ? "enabled" : "disabled");
  if (!sm->is_enabled)
    return 0;

  vlib_cli_output (vm, "snort interface: %U", format_vnet_sw_if_index_name,
	           vnet_get_main (), sm->sw_if_index);
  return 0;
}

u8 *
format_snort_tcp_udp_flow_id (u8 *s, va_list * args)
{
  snort_flow_id_t *sf = va_arg (*args, snort_flow_id_t *);
  u32 is_udp = va_arg (*args, u32);
  char *proto;

  proto = is_udp ? "udp" : "tcp";
  if (sf->is_ip4)
    s = format (s, "%s %U:%d->%U:%d", proto, format_ip4_address, &sf->v4.src,
	        sf->v4.src_port, format_ip4_address, &sf->v4.dst,
	        sf->v4.dst_port);
  else
    s = format (s, "%s %U:%d->%U:%d", proto, format_ip6_address, &sf->v6.src,
	        sf->v6.src_port, format_ip6_address, &sf->v6.dst,
	        sf->v6.dst_port);
  return s;
}

u8 *
format_snort_flow_id (u8 *s, va_list * args)
{
  snort_flow_id_t *sf = va_arg (*args, snort_flow_id_t *);
  u8 proto;

  if (sf->is_ip4)
    {
      proto = sf->v4.proto;
      if (proto == 1)
	s = format (s, "icmp %U->%U", format_ip4_address, &sf->v4.src,
	            format_ip4_address, &sf->v4.dst);
      else if (proto == IP_PROTOCOL_TCP || proto == IP_PROTOCOL_TCP)
	s = format (s, "%U", format_snort_tcp_udp_flow_id, sf);
      else
	s = format (s, "proto: %u %U->%U", format_ip4_address, &sf->v4.src,
	            format_ip4_address, &sf->v4.dst);
    }
  else
    {
      proto = sf->v6.proto;
      if (proto == 1)
	s = format (s, "icmp %U->%U", format_ip6_address, &sf->v6.src,
	            format_ip6_address, &sf->v6.dst);
      else if (proto == IP_PROTOCOL_TCP || proto == IP_PROTOCOL_TCP)
	s = format (s, "%U", format_snort_tcp_udp_flow_id, sf);
      else
	s = format (s, "proto: %u %U->%U", format_ip6_address, &sf->v6.src,
	            format_ip6_address, &sf->v6.dst);
    }
  return s;
}

u8 *
format_snort_flow (u8 * s, va_list * args)
{
  snort_flow_t *sf = va_arg (*args, snort_flow_t *);
  char *action;
  if (!sf)
    return s;

  switch (sf->action)
    {
    case SNORT_ACTION_INSPECT:
      action = "inspect";
      break;
    case SNORT_ACTION_DROP:
      action = "drop";
      break;
    case SNORT_ACTION_FWD:
      action = "fwd";
      break;
    default:
      action = "unknown";
    }

  s = format (s, "action: %s %U", action, format_snort_flow_id, &sf->id);
  return s;
}

u8 *
format_snort_interface (u8 *s, va_list * args)
{
  snort_interface_t *sif = va_arg(*args, snort_interface_t *);
  s = format (s, "interface: %U flows: %u", format_vnet_sw_if_index_name,
	      vnet_get_main (), sif->sw_if_index, pool_elts (sif->flows));
  return s;
}

static clib_error_t *
show_snort_interface_fn (vlib_main_t * vm, unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  snort_main_t *sm = snort_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index = ~0;
  snort_interface_t *sif;
  snort_flow_t *sf;


  if (!sm->is_enabled)
    {
      vlib_cli_output (vm, "feature not enabled");
      return 0;
    }

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      /* *INDENT-OFF* */
      pool_foreach (sif, sm->interfaces, ({
	vlib_cli_output (vm, "%U", format_snort_interface, sif);
      }));
      /* *INDENT-ON* */
      return 0;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
	            &sw_if_index))
	;
      else
	{
	  error = clib_error_return(0, "unknown input '%U'",
		                    format_unformat_error, line_input);
	  goto done;
	}
    }

  sif = snort_interface_lookup (sw_if_index);
  if (!sif)
    {
      vlib_cli_output (vm, "snort not enabled on interface: %u", sw_if_index);
      error = clib_error_return(0, "snort not enabled on interface: %u",
	                        sw_if_index);
      goto done;

    }
  /* *INDENT-OFF* */
  pool_foreach(sf, sif->flows, ({
    vlib_cli_output (vm, "%U", format_snort_flow, sf);
  }));
  /* *INDENT-ON* */

  done:
  unformat_free (line_input);
  return error;

}

VLIB_CLI_COMMAND (snort_interface_command, static) = {
  .path = "show snort interface",
  .function = show_snort_interface_fn,
  .short_help = "show snort interface",
};

VLIB_CLI_COMMAND (snort_feature_status_command, static) = {
  .path = "show snort status",
  .function = snort_feature_status_fn,
  .short_help = "show snort status",
};

/*?
 * @cliexpar
 * @cliexstart{set interface snort}
 * Enable/disable snort feature on the interface.
 * To enable snort feature use:
 *  vpp# set interface snort GigabitEthernetX/X/X
 * @cliexend
?*/
VLIB_CLI_COMMAND (snort_set_interface_command, static) = {
  .path = "set interface snort",
  .function = snort_feature_command_fn,
  .short_help = "set interface snort <iface> [del]",
};

/*?
 * @cliexpar
 * @cliexstart{snort enable|disable}
 * Enable/disable snort plugin.
 * To enable snort feature use:
 *  vpp# snort enable memif0/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (snort_enable_command, static) = {
  .path = "snort",
  .function = snort_command_fn,
  .short_help = "snort enable|disable [snort interface]",
};
