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

#include <vnet/vnet.h>
#include <vnet/classify/vnet_classify.h>

static clib_error_t *
trace_interface (vlib_main_t * vm, unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw;
  vlib_trace_main_t *tm;
  u32 hw_if_index = (u32) ~ 0;
  u32 count = 10;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	;
      else if (unformat (line_input, "count %d", &count))
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

  if (hw_if_index == (u32) ~ 0)
    return clib_error_return (0, "please specify a valid interface name");

  if (vnet_trace_dummy == 0)
    vec_validate_aligned (vnet_trace_dummy, 2048, CLIB_CACHE_LINE_BYTES);

  /* *INDENT-OFF* */
  foreach_vlib_main ((
    {
      tm = &this_vlib_main->trace_main;
      tm->trace_enable = 1;
    }));
  /* *INDENT-ON* */

  hw = vnet_get_hw_interface (vnm, hw_if_index);
  hw->n_trace = count;
  /*
   * Note: hw->trace_classify_table_index maintained by
   * the "classify filter" CLI in ../src/vnet/vnet_classify.c.
   */

  return (error);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_trace_if,static) = {
    .path = "trace interface",
    .short_help = "trace interface <interface> [count <n>] "
      "[classify-table-index <n>]",
    .function = trace_interface,
};
/* *INDENT-ON* */

static clib_error_t *
vnet_device_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (vnet_device_cli_init);
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
