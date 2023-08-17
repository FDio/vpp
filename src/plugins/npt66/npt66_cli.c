// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2023 Cisco Systems, Inc.

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip.h>
#include <vppinfra/clib_error.h>
#include "npt66.h"

static clib_error_t *
set_npt66_binding_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  bool internal_set = false, external_set = false;
  bool add = true;
  u32 sw_if_index = ~0;
  ip6_address_t internal, external;
  int internal_plen = 0, external_plen = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "internal %U/%d", unformat_ip6_address,
		    &internal, &internal_plen))
	internal_set = true;
      else if (unformat (line_input, "external %U/%d", unformat_ip6_address,
			 &external, &external_plen))
	external_set = true;
      else if (unformat (line_input, "interface %U",
			 unformat_vnet_sw_interface, vnet_get_main (),
			 &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	{
	  add = false;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }
  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "interface is required `%U'",
				 format_unformat_error, line_input);
      goto done;
    }
  if (!internal_set)
    {
      error = clib_error_return (0, "missing parameter: internal `%U'",
				 format_unformat_error, line_input);
      goto done;
    }
  if (!external_set)
    {
      error = clib_error_return (0, "missing parameter: external `%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  int rv = npt66_binding_add_del (sw_if_index, &internal, internal_plen,
				  &external, external_plen, add);
  if (rv)
    {
      error = clib_error_return (0, "Adding binding failed %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (set_npt66_binding_command, static) = {
  .path = "set npt66 binding",
  .short_help = "set npt66 binding interface <name> internal <pfx> "
		"external <pfx> [del]",
  .function = set_npt66_binding_command_fn,
};
