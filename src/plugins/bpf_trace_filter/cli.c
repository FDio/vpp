/*
 *------------------------------------------------------------------
 * Copyright (c) 2023 Cisco and/or its affiliates.
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
#include <bpf_trace_filter/bpf_trace_filter.h>

static clib_error_t *
set_bpf_trace_filter_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *bpf_expr = 0;
  u8 is_del = 0;
  u8 optimize = 1;
  clib_error_t *err = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_del = 1;
      else if (unformat (line_input, "no-optimize"))
	optimize = 0;
      else if (unformat (line_input, "%s", &bpf_expr))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, input);
	  break;
	}
    }
  unformat_free (line_input);

  if (err != 0)
    return err;

  err = bpf_trace_filter_set_unset ((char *) bpf_expr, is_del, optimize);

  return err;
}

VLIB_CLI_COMMAND (set_bpf_trace_filter, static) = {
  .path = "set bpf trace filter",
  .short_help = "set bpf trace filter [del] [no-optimize] {<pcap string>}",
  .function = set_bpf_trace_filter_command_fn,
};

static clib_error_t *
show_bpf_trace_filter_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  bpf_trace_filter_main_t *btm = &bpf_trace_filter_main;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      return (clib_error_return (0, "unknown input '%U'",
				 format_unformat_error, input));
    }

  vlib_cli_output (vm, "%U", format_bpf_trace_filter, btm);

  return 0;
}

VLIB_CLI_COMMAND (show_bpf_trace_filter, static) = {
  .path = "show bpf trace filter",
  .short_help = "show bpf trace filter",
  .function = show_bpf_trace_filter_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
