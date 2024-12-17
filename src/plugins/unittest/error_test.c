/*
 * Copyright (c) 2021 Dave Barach
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

#include <vlib/vlib.h>
#include <vlib/error.h>

static clib_error_t *
test_error_context_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{


	vlib_register_errors_per_context(vm, 10);
  vlib_cli_output (vm, "Test succeeded...\n");
  return 0;
}

VLIB_CLI_COMMAND (test_error_context_command, static) = {
  .path = "test error context",
  .short_help = "vlib error context tests",
  .function = test_error_context_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
