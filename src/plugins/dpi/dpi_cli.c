/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Intel and/or its affiliates.
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
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dpi/dpi.h>


dpi_main_t dpi_main;

static clib_error_t *
hs_set_ip_dpi_bypass (u32 is_ip6,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index, is_enable;

  sw_if_index = ~0;
  is_enable = 1;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat_user
	  (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	is_enable = 0;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (~0 == sw_if_index)
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  vnet_int_dpi_bypass (sw_if_index, is_ip6, is_enable);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
hs_set_interface_ip4_dpi_bypass_command_fn (vlib_main_t * vm,
					    unformat_input_t * input,
					    vlib_cli_command_t * cmd)
{
  return hs_set_ip_dpi_bypass (0, input, cmd);
}

/*?
 * This command adds the 'ip4-dpi-bypass' graph node for a given interface.
 * By adding the IPv4 dpi graph node to an interface, the node checks
 *  for and validate input dpi packet and bypass ip4-lookup, ip4-local,
 * ip4-udp-lookup/ip4-tcp-lookup nodes to speedup dpi packet scan.
 *
 * Example of how to enable ip4-dpi-bypass on an interface:
 * @cliexcmd{set interface ip dpi-bypass GigabitEthernet2/0/0}
 *
 * Example of how to disable ip4-dpi-bypass on an interface:
 * @cliexcmd{set interface ip dpi-bypass GigabitEthernet2/0/0 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (hs_set_interface_ip4_dpi_bypass_command, static) = {
  .path = "hs set interface ip4 dpi-bypass",
  .function = hs_set_interface_ip4_dpi_bypass_command_fn,
  .short_help = "hs set interface ip4 dpi-bypass <interface> [del]",
};
/* *INDENT-ON* */

static clib_error_t *
hs_set_interface_ip6_dpi_bypass_command_fn (vlib_main_t * vm,
					    unformat_input_t * input,
					    vlib_cli_command_t * cmd)
{
  return hs_set_ip_dpi_bypass (1, input, cmd);
}

/*?
 * This command adds the 'ip6-dpi-bypass' graph node for a given interface.
 * By adding the IPv6 dpi graph node to an interface, the node checks
 *  for and validate input dpi packet and bypass ip6-lookup, ip6-local,
 * ip6-udp-lookup/ip6-tcp-lookup nodes to speedup dpi packet scan.
 *
 * Example of how to enable ip6-dpi-bypass on an interface:
 * @cliexcmd{hs set interface ip6 dpi-bypass GigabitEthernet2/0/0}
 *
 * Example of how to disable ip6-dpi-bypass on an interface:
 * @cliexcmd{hs set interface ip6 dpi-bypass GigabitEthernet2/0/0 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (hs_set_interface_ip6_dpi_bypass_command, static) = {
  .path = "hs set interface ip6 dpi-bypass",
  .function = hs_set_interface_ip6_dpi_bypass_command_fn,
  .short_help = "hs set interface ip6 dpi-bypass <interface> [del]",
};
/* *INDENT-ON* */

static clib_error_t *
hs_compile_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  dpi_main_t *hsm = &dpi_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  char *flagstr;
  hs_compile_error_t *compile_err;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "mode block"))
	hsm->mode = HS_MODE_BLOCK;
      else if (unformat (line_input, "mode stream"))
	hsm->mode = HS_MODE_STREAM;
      else if (unformat (line_input, "flags %s", &flagstr))
	{
	  hsm->flags = hs_parse_flagstr (flagstr);
	}
      else if (unformat (line_input, "patterns %s", &hsm->pattern))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (hs_compile (hsm->pattern, hsm->flags, hsm->mode,
		  NULL, &hsm->db_block, &compile_err) != HS_SUCCESS)
    {
      error = clib_error_return (0,
				 "ERROR: Unable to compile pattern \"%s\": %s\n",
				 hsm->pattern, compile_err->message);
      hs_free_compile_error (compile_err);
      goto done;
    }

  printf ("Hyperscan compile successfully!\n");

  if (hs_alloc_scratch (hsm->db_block, &hsm->scratch) != HS_SUCCESS)
    {
      error = clib_error_return (0,
				 "ERROR: Unable to allocate scratch space. Exiting.\n");
      hs_free_database (hsm->db_block);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/*
 * Configure regular matching patterns and compile them into database.
 *
 * @cliexpar
 * Example of how to Configure regular matching patterns:
 * @cliexcmd{}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (hs_compile_command, static) = {
  .path = "hs compile",
  .short_help = "hs compile mode [block|stream] flags [imsHV8W\r]"
                " patterns <patterns>",
  .function = hs_compile_command_fn,
};
/* *INDENT-ON* */



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
