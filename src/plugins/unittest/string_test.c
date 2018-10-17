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
test_clib_memset (vlib_main_t * vm, unformat_input_t * input)
{
  u8 dst[64];
  int i;
  errno_t err;

  vlib_cli_output (vm, "Test memset_s...");

  err = memset_s (dst, ARRAY_LEN (dst), 0xfe, ARRAY_LEN (dst));

  if (err != EOK)
    return -1;

  for (i = 0; i < ARRAY_LEN (dst); i++)
    if (dst[i] != 0xFE)
      return -1;

  err = memset_s (dst, ARRAY_LEN (dst), 0xfa, ARRAY_LEN (dst) + 1);

  if (err == EOK)
    return -1;

  return 0;
}

static int
test_memcpy (vlib_main_t * vm, unformat_input_t * input)
{
  char src[64], dst[64];
  int i;
  errno_t err;

  vlib_cli_output (vm, "Test memcpy_s...");

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
  u8 t_memcpy = 0;
  u8 t_clib_memset = 0;
  u8 specific_test;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "memcpy_s"))
	t_memcpy = 1;
      else if (unformat (input, "memset_s"))
	t_clib_memset = 1;
      break;
    }

  specific_test = t_memcpy + t_clib_memset;

  if (specific_test == 0)
    {
      res = test_memcpy (vm, input);
      res += test_clib_memset (vm, input);
      goto done;
    }

  if (t_memcpy)
    res = test_memcpy (vm, input);
  else if (t_clib_memset)
    res = test_clib_memset (vm, input);

done:
  if (res)
    vlib_cli_output (vm, "String unit test(s) failed...");
  else
    vlib_cli_output (vm, "String unit test(s) OK...");
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
