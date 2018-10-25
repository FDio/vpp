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

static int
test_memcmp (vlib_main_t * vm, unformat_input_t * input)
{
  char src[64], dst[64];
  errno_t err;
  int diff = 0;

  vlib_cli_output (vm, "Test memcmp_s...");

  /* Fill array with different values */
  err = clib_memset (src, 0x1, ARRAY_LEN (src));
  if (err != EOK)
    return -1;
  err = clib_memset (dst, 0x3, ARRAY_LEN (dst));
  if (err != EOK)
    return -1;

  /* s1 > s2, > 0 is expected in diff */
  err = memcmp_s (dst, ARRAY_LEN (dst), src, ARRAY_LEN (src), &diff);
  if (err != EOK)
    return -1;
  if (!(diff > 0))
    return -1;

  /* s1 < s2, < 0 is expected in diff */
  err = memcmp_s (src, ARRAY_LEN (src), dst, ARRAY_LEN (dst), &diff);
  if (err != EOK)
    return -1;
  if (!(diff < 0))
    return -1;

  err = clib_memset (dst, 0x1, ARRAY_LEN (dst));
  if (err != EOK)
    return -1;

  /* s1 == s2, 0 is expected in diff */
  err = memcmp_s (src, ARRAY_LEN (src), dst, ARRAY_LEN (dst), &diff);
  if (err != EOK)
    return -1;
  if (diff != 0)
    return -1;

  /* Try negative tests */
  err = memcmp_s (0, 0, 0, 0, 0);
  if (err != EINVAL)
    return -1;

  /* Try s2max > s1max */
  err = memcmp_s (src, ARRAY_LEN (src) - 1, dst, ARRAY_LEN (dst), &diff);
  if (err != EINVAL)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strcmp (vlib_main_t * vm, unformat_input_t * input)
{
  const char s1[] = "this is a string";
  uword s1len = strlen (s1);
  errno_t err;
  int indicator = 0;

  vlib_cli_output (vm, "Test strcmp_s...");

  /* s1 == s2, 0 is expected */
  err = strcmp_s (s1, s1len, "this is a string", &indicator);
  if (err != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* s1 > s2, > 0 is expected */
  err = strcmp_s (s1, s1len, "this is a strin", &indicator);
  if (err != EOK)
    return -1;
  if (!(indicator > 0))
    return -1;

  /* s1 < s2, < 0 is expected */
  err = strcmp_s (s1, s1len, "this is b string", &indicator);
  if (err != EOK)
    return -1;
  if (!(indicator < 0))
    return -1;

  /* Try some negative tests */

  /* OK, seems to work */
  return 0;
}

static int
test_strncmp (vlib_main_t * vm, unformat_input_t * input)
{
  vlib_cli_output (vm, "Test strncmp_s...");

  /* OK, seems to work */
  return 0;
}

static int
test_strcpy (vlib_main_t * vm, unformat_input_t * input)
{
  vlib_cli_output (vm, "Test strcpy_s...");

  /* OK, seems to work */
  return 0;
}

static int
test_strncpy (vlib_main_t * vm, unformat_input_t * input)
{
  vlib_cli_output (vm, "Test strncpy_s...");

  /* OK, seems to work */
  return 0;
}

static int
test_strcat (vlib_main_t * vm, unformat_input_t * input)
{
  vlib_cli_output (vm, "Test strcat_s...");

  /* OK, seems to work */
  return 0;
}

static int
test_strncat (vlib_main_t * vm, unformat_input_t * input)
{
  vlib_cli_output (vm, "Test strncat_s...");

  /* OK, seems to work */
  return 0;
}

static int
test_strtok (vlib_main_t * vm, unformat_input_t * input)
{
  vlib_cli_output (vm, "Test strtok_s...");

  /* OK, seems to work */
  return 0;
}

static int
test_strnlen (vlib_main_t * vm, unformat_input_t * input)
{
  vlib_cli_output (vm, "Test strnlen_s...");

  /* OK, seems to work */
  return 0;
}

static int
test_strstr (vlib_main_t * vm, unformat_input_t * input)
{
  vlib_cli_output (vm, "Test strstr_s...");

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
      res += test_memcmp (vm, input);
      res += test_strcmp (vm, input);
      res += test_strncmp (vm, input);
      res += test_strcpy (vm, input);
      res += test_strncpy (vm, input);
      res += test_strcat (vm, input);
      res += test_strncat (vm, input);
      res += test_strtok (vm, input);
      res += test_strnlen (vm, input);
      res += test_strstr (vm, input);
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
