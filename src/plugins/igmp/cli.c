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
  if (config)
    igmp_clear_config (config);

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igmp_clear_interface_command, static) = {
  .path = "clear igmp",
  .short_help = "clear igmp int <interface>",
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
  u32 sw_if_index;
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

  if ((vnet_sw_interface_get_flags (vnm, sw_if_index)
       && VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
    {
      error = clib_error_return (0, "Interface is down");
      goto done;
    }

  rv = igmp_listen (vm, enable, sw_if_index, saddr, gaddr,
		    /* cli_api_listen */ 1);
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
igmp_show_command_fn (vlib_main_t * vm, unformat_input_t * input,
		      vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;
  igmp_main_t *im = &igmp_main;
  vnet_main_t *vnm = vnet_get_main ();
  igmp_config_t *config;
  igmp_sg_t *sg;

  /* *INDENT-OFF* */
  pool_foreach (config, im->configs, (
    {
      vlib_cli_output (vm, "interface: %U", format_vnet_sw_if_index_name,
		       vnm, config->sw_if_index);
	pool_foreach (sg, config->sg, (
	  {
	    vlib_cli_output (vm, "\t(S,G): %U:%U:%U", format_ip46_address,
			     &sg->saddr, ip46_address_is_ip4 (&sg->saddr),
			     format_ip46_address, &sg->gaddr, ip46_address_is_ip4
			     (&sg->gaddr), format_igmp_report_type, sg->group_type);
	  }));
    }));
  /* *INDENT-ON* */

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igmp_show_command, static) = {
  .path = "show igmp config",
  .short_help = "show igmp config",
  .function = igmp_show_command_fn,
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
