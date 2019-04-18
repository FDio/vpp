/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vnet/nhrp/nhrp.h>

static clib_error_t *
nhrp_add (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t peer = ip46_address_initializer;
  ip46_address_t nh = ip46_address_initializer;
  u32 sw_if_index, nh_table_id;
  clib_error_t *error = NULL;
  int rv;

  sw_if_index = ~0;
  nh_table_id = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface,
		    vnet_get_main (), &sw_if_index))
	;
      else if (unformat (line_input, "peer %U", unformat_ip46_address, &peer))
	;
      else if (unformat (line_input, "nh %U", unformat_ip46_address, &nh))
	;
      else if (unformat (line_input, "nh-table-id %d", &nh_table_id))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (~0 == sw_if_index)
    {
      error = clib_error_return (0, "interface required'",
				 format_unformat_error, line_input);
      goto done;
    }
  if (ip46_address_is_zero (&peer))
    {
      error = clib_error_return (0, "peer required'",
				 format_unformat_error, line_input);
      goto done;
    }
  if (ip46_address_is_zero (&nh))
    {
      error = clib_error_return (0, "next-hop required'",
				 format_unformat_error, line_input);
      goto done;
    }

  rv = nhrp_entry_add (sw_if_index, &peer, nh_table_id, &nh);

  if (rv)
    {
      error = clib_error_return_code (NULL, rv, 0,
				      "NRHP error",
				      format_unformat_error, line_input);
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (nhrp_create_command, static) = {
  .path = "create nhrp",
  .short_help = "create nhrp <interface> peer <addr> nh <addr> [nh-table-id <ID>]",
  .function = nhrp_add,
};
/* *INDENT-ON* */

static clib_error_t *
nhrp_del (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t peer = ip46_address_initializer;
  clib_error_t *error = NULL;
  u32 sw_if_index;
  int rv;

  sw_if_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface,
		    vnet_get_main (), &sw_if_index))
	;
      else if (unformat (line_input, "peer %U", unformat_ip46_address, &peer))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (~0 == sw_if_index)
    {
      error = clib_error_return (0, "interface required'",
				 format_unformat_error, line_input);
    }
  if (ip46_address_is_zero (&peer))
    {
      error = clib_error_return (0, "peer required'",
				 format_unformat_error, line_input);
      goto done;
    }

  rv = nhrp_entry_del (sw_if_index, &peer);

  if (rv)
    {
      error = clib_error_return_code (NULL, rv, 0,
				      "NRHP error",
				      format_unformat_error, line_input);
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (nhrp_delete_command, static) = {
  .path = "delete nhrp",
  .short_help = "delete nhrp <interface> peer <addr>",
  .function = nhrp_del,
};
/* *INDENT-ON* */

static walk_rc_t
nhrp_show_one (index_t nei, void *ctx)
{
  vlib_cli_output (ctx, "%U", format_nhrp_entry, nei);

  return (WALK_CONTINUE);
}


static clib_error_t *
nhrp_show (vlib_main_t * vm,
	   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  nhrp_walk (nhrp_show_one, vm);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (nhrp_show_command, static) = {
  .path = "show nhrp",
  .short_help = "show nhrp",
  .function = nhrp_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
