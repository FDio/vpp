/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/hash/hash.h>

static clib_error_t *
set_interface_tx_hash_cmd (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index = (u32) ~0;
  vnet_hash_type_t htype;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_hw_interface, vnm,
		    &hw_if_index))
	;
      else if (unformat (line_input, "hash %U", unformat_vnet_hash_type,
			 &htype))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  unformat_free (line_input);
	  return error;
	}
    }

  unformat_free (line_input);

  if (hw_if_index == (u32) ~0)
    {
      error = clib_error_return (0, "please specify valid interface name");
      goto error;
    }

  set_interface_tx_hash (vm, hw_if_index, htype);

error:
  return (error);
}

VLIB_CLI_COMMAND (cmd_set_if_tx_hash, static) = {
  .path = "set interface tx-hash",
  .short_help = "set interface tx-hash <interface> <hash-name> ",
  .function = set_interface_tx_hash_cmd,
};

static clib_error_t *
show_tx_hash (vlib_main_t *vm, unformat_input_t *input,
	      vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hash_main_t *hm = &vnet_hash_main;
  vnet_hash_function_registration_t *hash;
  u32 hw_if_index;
  u8 is_hw_if_index_set = 0, avail = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_hw_interface, vnm,
		    &hw_if_index))
	is_hw_if_index_set = 1;
      else if (unformat (line_input, "avail"))
	avail = 1;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  unformat_free (line_input);
	  return error;
	}
    }

  unformat_free (line_input);

  if (is_hw_if_index_set)
    {
      vnet_main_t *vnm = vnet_get_main ();
      vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
      vnet_hw_interface_class_t *hc =
	vnet_get_hw_interface_class (vnm, hi->hw_class_index);
      vnet_hash_function_registration_t *hash;

      if (hc->vnet_hash_func)
	{
	  hash = vnet_hash_function_from_func (hc->vnet_hash_func);
	  vlib_cli_output (vm, "%U", format_vnet_hash, hash);
	}
      else
	vlib_cli_output (vm, "no hashing function set");
    }
  else if (avail)
    {
      hash = hm->hash_registrations;
      vlib_cli_output (vm, "            NAME                   TYPE\n");
      vlib_cli_output (vm, "=========================   ===============\n");
      while (hash)
	{
	  vlib_cli_output (vm, " %-25s   %-10U\n", hash->name,
			   format_vnet_hash_type, hash->type);
	  hash = hash->next;
	}
    }

  return (error);
}

VLIB_CLI_COMMAND (cmd_show_tx_hash, static) = {
  .path = "show tx-hash",
  .short_help = "show tx-hash [interface] [avail]",
  .function = show_tx_hash,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
