/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <stdint.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>

#include <igmp/igmp.h>

/* *INDENT-ON* */

static clib_error_t *
igmp_proxy_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 enable = 1;
  ip46_address_t addr;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      error =
	clib_error_return (0, "'help igmp proxy' or 'igmp proxy ?' for help");
      return error;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	enable = 1;
      else if (unformat (line_input, "disable"))
	{
	  enable = 0;
	  /* if we want to disable IGMP proxy we don't need to specify any parameters */
	  goto disable;
	}
      else
	if (unformat
	    (line_input, "int %U", unformat_vnet_sw_interface, vnm,
	     &sw_if_index));
      else
	if (unformat (line_input, "addr %U", unformat_ip46_address, &addr));
      else
	{
	  error =
	    clib_error_return (0, "unknown input '%U'", format_unformat_error,
			       line_input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      clib_error_return (0, "Please specify an interface.");
      goto done;
    }

  if ((vnet_sw_interface_get_flags (vnm, sw_if_index)
       && VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
    {
      error = clib_error_return (0, "Interface is down");
      goto done;
    }

disable:
  rv = igmp_proxy (vm, enable, sw_if_index, addr);
  if (rv < 0)
    error =
      clib_error_return (0, "Failed to enable IGMP Proxy on interface %U",
			 format_vnet_sw_if_index_name, vnm, sw_if_index);
done:
  unformat_free (line_input);
  return error;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igmp_proxy_command, static) = {
  .path = "igmp proxy",
  .short_help = "igmp proxy [<enable|disable>] "
                "int <interface> addr <ip4-address>",
  .function = igmp_proxy_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
igmp_clear_interface_command_fn (vlib_main_t * vm, unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index;

  igmp_main_t *im = &igmp_main;
  igmp_config_t *config;

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      error =
	clib_error_return (0, "'help clear igmp' or 'clear igmp ?' for help");
      return error;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "int %U", unformat_vnet_sw_interface, vnm,
	   &sw_if_index));
      else
	{
	  error =
	    clib_error_return (0, "unknown input '%U'", format_unformat_error,
			       line_input);
	  goto done;
	}
    }

  config = igmp_config_lookup (im, sw_if_index);
  if (!config)
    goto done;

  igmp_clear_config (config);

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igmp_clear_interface_command, static) = {
  .path = "clear igmp",
  .short_help = "clear igmp int <interface> Warning: this call will not send notifications. Use carefully.",
  .function = igmp_clear_interface_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
igmp_listen_command_fn (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 enable = 1;
  ip46_address_t saddr, gaddr;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      error =
	clib_error_return (0,
			   "'help igmp listen' or 'igmp listen ?' for help");
      return error;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	enable = 1;
      else if (unformat (line_input, "disable"))
	enable = 0;
      else
	if (unformat
	    (line_input, "int %U", unformat_vnet_sw_interface, vnm,
	     &sw_if_index));
      else
	if (unformat (line_input, "saddr %U", unformat_ip46_address, &saddr));
      else
	if (unformat (line_input, "gaddr %U", unformat_ip46_address, &gaddr));
      else
	{
	  error =
	    clib_error_return (0, "unknown input '%U'", format_unformat_error,
			       line_input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      clib_error_return (0, "Please specify an interface.");
      goto done;
    }

  if ((vnet_sw_interface_get_flags (vnm, sw_if_index)
       && VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
    {
      error = clib_error_return (0, "Interface is down");
      goto done;
    }

  rv =
    igmp_listen (vm, enable, sw_if_index, saddr, gaddr,
		 IGMP_CONFIG_FLAG_CLI_API_CONFIGURED);

  if (rv == -1)
    {
      if (enable)
	error =
	  clib_error_return (0, "This igmp configuration already exists");
      else
	error =
	  clib_error_return (0, "This igmp configuration does not nexist");
    }
  else if (rv == -2)
    error =
      clib_error_return (0,
			 "Failed to add configuration, interface is in router mode");

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igmp_listen_command, static) = {
  .path = "igmp listen",
  .short_help = "igmp listen [<enable|disable>] "
                "int <interface> saddr <ip4-address> gaddr <ip4-address>",
  .function = igmp_listen_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
igmp_show_config_command_fn (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;
  igmp_main_t *im = &igmp_main;
  vnet_main_t *vnm = vnet_get_main ();
  igmp_config_t *config;
  igmp_group_t *group;
  igmp_src_t *src;

  /* *INDENT-OFF* */
  pool_foreach (config, im->configs, (
    {
      vlib_cli_output (vm, "interface: %U\nflags:%U",
	format_vnet_sw_if_index_name,
	  vnm, config->sw_if_index, format_igmp_config_flags, config->flags);

      if (config->flags & IGMP_CONFIG_FLAG_PROXY_ENABLED)
	vlib_cli_output (vm, "proxy address: %U", format_ip46_address,
	  &config->proxy_addr, ip46_address_is_ip4(&config->proxy_addr));

	pool_foreach (group, config->groups, (
	  {
	    vlib_cli_output (vm, "\t%U:%U", format_igmp_report_type,
	      group->type, format_ip46_address, &group->addr,
	      ip46_address_is_ip4 (&group->addr));

	    pool_foreach (src, group->srcs, (
	      {
		vlib_cli_output (vm, "\t\t%U", format_ip46_address, &src->addr,
		  ip46_address_is_ip4 (&src->addr));
	      }));
	  }));
    }));
  /* *INDENT-ON* */

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igmp_show_config_command, static) = {
  .path = "show igmp config",
  .short_help = "show igmp config",
  .function = igmp_show_config_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
igmp_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (igmp_cli_init);
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
