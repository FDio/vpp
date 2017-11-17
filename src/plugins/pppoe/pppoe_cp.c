/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Intel and/or its affiliates.
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

#include <pppoe/pppoe.h>

static clib_error_t *
pppoe_add_del_cp_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  pppoe_main_t *pem = &pppoe_main;
  u8 is_add = 1;
  u8 cp_if_index_set = 0;
  u32 cp_if_index = 0;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (line_input, "cp-if-index %d", &cp_if_index))
	cp_if_index_set = 1;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (cp_if_index_set == 0)
    {
      error = clib_error_return (0, "cp if index not specified");
      goto done;
    }

  if (is_add)
    {
      pem->cp_if_index = cp_if_index;
    }
  else
    {
      pem->cp_if_index = ~0;
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_pppoe_cp_cmd, static) =
{
    .path = "create pppoe cp",
    .short_help = "create pppoe cp if-name <intfc> [del]",
    .function = pppoe_add_del_cp_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
