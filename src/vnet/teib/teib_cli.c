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

#include <vnet/teib/teib.h>

static clib_error_t *
teib_add (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip_address_t peer = ip_address_initializer;
  ip_address_t nh = ip_address_initializer;
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
      else if (unformat (line_input, "peer %U", unformat_ip_address, &peer))
	;
      else if (unformat (line_input, "nh-table-id %d", &nh_table_id))
	;
      else if (unformat (line_input, "nh %U", unformat_ip_address, &nh))
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
  if (ip_address_is_zero (&peer))
    {
      error = clib_error_return (0, "peer required'",
				 format_unformat_error, line_input);
      goto done;
    }
  if (ip_address_is_zero (&nh))
    {
      error = clib_error_return (0, "next-hop required'",
				 format_unformat_error, line_input);
      goto done;
    }

  rv = teib_entry_add (sw_if_index, &peer, nh_table_id, &nh);

  if (rv)
    {
      error = clib_error_return_code (NULL, rv, 0, "TEIB error",
				      format_unformat_error, line_input);
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (teib_create_command, static) = {
  .path = "create teib",
  .short_help = "create teib <interface> peer <addr> nh <addr> [nh-table-id <ID>]",
  .function = teib_add,
};
/* *INDENT-ON* */

static clib_error_t *
teib_del (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip_address_t peer = ip_address_initializer;
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
      else if (unformat (line_input, "peer %U", unformat_ip_address, &peer))
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
  if (ip_address_is_zero (&peer))
    {
      error = clib_error_return (0, "peer required'",
				 format_unformat_error, line_input);
      goto done;
    }

  rv = teib_entry_del (sw_if_index, &peer);

  if (rv)
    {
      error = clib_error_return_code (NULL, rv, 0, "TEIB error",
				      format_unformat_error, line_input);
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (teib_delete_command, static) = {
  .path = "delete teib",
  .short_help = "delete teib <interface> peer <addr>",
  .function = teib_del,
};
/* *INDENT-ON* */

static walk_rc_t
teib_show_one (index_t nei, void *ctx)
{
  vlib_cli_output (ctx, "%U", format_teib_entry, nei);

  return (WALK_CONTINUE);
}


static clib_error_t *
teib_show (vlib_main_t * vm,
	   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  teib_walk (teib_show_one, vm);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (teib_show_command, static) = {
  .path = "show teib",
  .short_help = "show teib",
  .function = teib_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
