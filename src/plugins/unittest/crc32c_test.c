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
#include <vppinfra/crc32.h>
#include "crc32c.h"

static void
test_crc32c (vlib_main_t *vm, void *data, int len)
{
  u32 crc32c_vlib;
  u32 crc32c_base;

  crc32c_vlib = clib_crc32c (data, len);
  crc32c_base = calculate_crc32c (0, data, len);
  char *test_result = "PASS";

  if (crc32c_vlib != crc32c_base)
    {
      test_result = "FAIL";
    }
  vlib_cli_output (vm, "%s: CRC32C for length %d: vlib: 0x%08x base: 0x%08x",
		   test_result, len, crc32c_vlib, crc32c_base);
}

static clib_error_t *
test_crc32c_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  char *test_string =
    "The quick brown fox jumped over the lazy dog and stumbled.";
  int i;

  for (i = 0; i < strlen (test_string); i++)
    {
      test_crc32c (vm, test_string, i);
    }

  vlib_cli_output (vm, "Test finished.\n");
  return 0;
}

VLIB_CLI_COMMAND (test_pool_command, static) = {
  .path = "test crc32c",
  .short_help = "crc32c tests",
  .function = test_crc32c_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
