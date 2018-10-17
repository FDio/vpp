/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <vppinfra/string.h>

static int
test_memcpy (vlib_main_t * vm, unformat_input_t * input)
{
  char src[64], dst[64];
  int i;
  errno_t err;

  for (i = 0; i < ARRAY_LEN (src); i++)
    src[i] = i + 1;

  /* Typical case */
  err = memcpy_s (dst, sizeof (dst), src, sizeof (src));

  if (err != EOK)
    return -1;

  /* This better not fail but check anyhow */
  for (i = 0; i < ARRAY_LEN (dst); i++)
    if (src[i] != dst[i])
      return -1;

  /* Size fail */
  err = memcpy_s (dst + 1, sizeof (dst) - 1, src, sizeof (src));

  if (err == EOK)
    return -1;

  /* overlap fail */
  err = memcpy_s (dst, sizeof (dst), dst + 1, sizeof (dst) - 1);

  if (err == EOK)
    return -1;

  /* Zero length copy */
  err = memcpy_s (0, sizeof (dst), src, 0);

  if (err != EOK)
    return -1;

  /* OK, seems to work */
  return 0;
}

static clib_error_t *
string_test_command_fn (vlib_main_t * vm,
			unformat_input_t * input,
			vlib_cli_command_t * cmd_arg)
{
  int res = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "memcpy_s"))
	res = test_memcpy (vm, input);
      else
	break;
    }

  if (res)
    vlib_cli_output (vm, "String unit test failed...");
  else
    vlib_cli_output (vm, "String unit test OK...");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (string_test_command, static) =
{
  .path = "test string",
  .short_help = "string library tests",
  .function = string_test_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
