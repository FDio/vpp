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
  char s1[] = "simplicity is the ultimate sophistication";
  uword s1len = strlen (s1);
  errno_t err;
  int indicator = 0;

  vlib_cli_output (vm, "Test strcmp_s...");

  /* s1 == s2, 0 is expected */
  err = strcmp_s (s1, s1len, "simplicity is the ultimate sophistication",
		  &indicator);
  if (err != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* s1 > s2, > 0 is expected */
  err = strcmp_s (s1, s1len, "simplicity is the ultimate", &indicator);
  if (err != EOK)
    return -1;
  if (!(indicator > 0))
    return -1;

  /* s1 < s2, < 0 is expected */
  err = strcmp_s (s1, s1len, "simplicity is the ultimate sophistication!",
		  &indicator);
  if (err != EOK)
    return -1;
  if (!(indicator < 0))
    return -1;

  /* Try some negative tests */
  err = strcmp_s (0, 0, 0, 0);
  if (err != EINVAL)
    return -1;

  /* non-null terminated s1 */
  s1[strlen (s1)] = 0x1;
  err = strcmp_s (s1, s1len, "simplicity is the ultimate sophistication",
		  &indicator);
  if (err != EINVAL)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strncmp (vlib_main_t * vm, unformat_input_t * input)
{
  char s1[] = "every moment is a fresh beginning";
  uword s1len = strlen (s1);
  errno_t err;
  int indicator = 0;

  vlib_cli_output (vm, "Test strncmp_s...");

  /* s1 == s2, 0 is expected */
  err = strncmp_s (s1, s1len, "every moment is a fresh beginning",
		   strlen ("every moment is a fresh beginning"), &indicator);
  if (err != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* s1 > s2,  0 is expected since comparison is no more than n character */
  err = strncmp_s (s1, s1len, "every moment is a fresh begin",
		   strlen ("every moment is a fresh begin"), &indicator);
  if (err != EOK)
    return -1;
  if (!(indicator == 0))
    return -1;

  /* s1 < s2, < 0 is expected */
  err = strncmp_s (s1, s1len, "every moment is fresh beginning",
		   strlen ("every moment is fresh beginning"), &indicator);
  if (err != EOK)
    return -1;
  if (!(indicator < 0))
    return -1;

  /* s1 > s2, > 0 is expected */
  err = strncmp_s ("every moment is fresh beginning. ",
		   strlen ("every moment is fresh beginning. "), s1, s1len,
		   &indicator);
  if (err != EOK)
    return -1;
  if (!(indicator > 0))
    return -1;

  /* Try some negative tests */
  err = strncmp_s (0, 0, 0, 0, 0);
  if (err != EINVAL)
    return -1;

  /* n > s1max */
  err = strncmp_s (s1, s1len, "every moment is a fresh beginning", s1len + 1,
		   &indicator);
  if (err != EINVAL)
    return -1;

  /* non-null terminated s1 */
  s1[strlen (s1)] = 0x1;
  err = strncmp_s (s1, s1len, "every moment is a fresh beginning",
		   strlen ("every moment is a fresh beginning"), &indicator);
  if (err != EINVAL)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strcpy (vlib_main_t * vm, unformat_input_t * input)
{
  char src[64], dst[64];
  int i;
  errno_t err;

  vlib_cli_output (vm, "Test strcpy_s...");

  /* fill up src */
  for (i = 0; i < ARRAY_LEN (src) - 1; i++)
    src[i] = i + 1;
  src[ARRAY_LEN (src) - 1] = '\0';

  err = strcpy_s (dst, sizeof (dst), src);
  if (err != EOK)
    return -1;

  /* This better not fail but check anyhow */
  for (i = 0; i < ARRAY_LEN (dst); i++)
    if (src[i] != dst[i])
      return -1;

  /* Negative tests */

  err = strcpy_s (0, 0, 0);
  if (err == EOK)
    return -1;

  /* Size fail */
  err = strcpy_s (dst + 1, sizeof (dst) - 1, src);
  if (err == EOK)
    return -1;

  /* overlap fail */
  err = strcpy_s (dst, sizeof (dst), dst + 1);
  if (err == EOK)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strncpy (vlib_main_t * vm, unformat_input_t * input)
{
  char src[64], dst[64];
  int i;
  errno_t err;

  vlib_cli_output (vm, "Test strncpy_s...");

  /* fill up src */
  for (i = 0; i < ARRAY_LEN (src) - 1; i++)
    src[i] = i + 1;
  src[ARRAY_LEN (src) - 1] = '\0';

  /* dmax includes null, n excludes null */
  err = strncpy_s (dst, sizeof (dst), src, sizeof (src) - 1);
  if (err != EOK)
    return -1;

  /* This better not fail but check anyhow */
  for (i = 0; i < ARRAY_LEN (dst); i++)
    if (src[i] != dst[i])
      return -1;

  /* truncation, n >= dmax */
  err = strncpy_s (dst, sizeof (dst) - 1, src, sizeof (src) - 1);
  if (err == EOK)
    return -1;

  /* Check dst content */
  for (i = 0; i < ARRAY_LEN (dst) - 2; i++)
    if (src[i] != dst[i])
      return -1;
  if (dst[ARRAY_LEN (dst) - 2] != '\0')
    return -1;

  /* Negative tests */

  err = strncpy_s (0, 0, 0, 0);
  if (err == EOK)
    return -1;

  /* overlap fail */
  err = strncpy_s (dst, sizeof (dst), dst + 1, sizeof (dst + 1));
  if (err == EOK)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strcat (vlib_main_t * vm, unformat_input_t * input)
{
  char src[64], dst[64];
  errno_t err;

  vlib_cli_output (vm, "Test strcat_s...");

  strcpy (dst, "tough time never last ");
  strcpy (src, "but tough people do");
  err = strcat_s (dst, ARRAY_LEN (dst), src);
  if (err != EOK)
    return -1;
  if (strcmp (dst, "tough time never last but tough people do") != 0)
    return -1;

  /* negative stuff */
  err = strcat_s (0, 0, 0);
  if (err != EINVAL)
    return -1;

  /* overlap fail */
  err = strcat_s (dst, ARRAY_LEN (dst), dst + 1);
  if (err != EINVAL)
    return -1;

  /* not enough space for dst */
  err = strcat_s (dst, 10, src);
  if (err != EINVAL)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strncat (vlib_main_t * vm, unformat_input_t * input)
{
  char src[200], dst[200];
  errno_t err;
  char *s1 = "two things are infinite: ";
  char *s2 = "the universe and human stupidity; ";
  char *s3 = "I am not sure about the universe.";

  vlib_cli_output (vm, "Test strncat_s...");

  strncpy (dst, s1, sizeof (dst));
  strncpy (src, s2, sizeof (src));
  err = strncat_s (dst, ARRAY_LEN (dst), src, strlen (src));
  if (err != EOK)
    return -1;
  if (strcmp (dst,
	      "two things are infinite: the universe and human stupidity; ")
      != 0)
    return -1;

  /* truncation */
  err = strncat_s (dst, strlen (dst) + strlen ("I am not sure"), s3,
		   strlen (s3));
  if (err == EOK)
    return -1;
  /* resulting string is original dst + 4 additional characters + null */
  if (strcmp (dst,
	      "two things are infinite: the universe and human stupidity; "
	      "I am not sur") != 0)
    return -1;

  /* negative stuff */
  err = strncat_s (0, 0, 0, 0);
  if (err != EINVAL)
    return -1;

  /* no room for dst */
  err = strncat_s (dst, strlen (dst), s2, strlen (s3) - 1);
  if (err != EINVAL)
    return -1;

  /* overlap fail */
  err = strncat_s (dst, ARRAY_LEN (dst), dst + 1, ARRAY_LEN (dst) - 1);
  if (err != EINVAL)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strtok (vlib_main_t * vm, unformat_input_t * input)
{
  char *tok, *ptr = 0;
  char *str2 = " ";
  char str1[100];
  uword len;
  char *p2str = 0;
  char *tok1, *tok2, *tok3, *tok4, *tok5, *tok6, *tok7;

  vlib_cli_output (vm, "Test strtok_s...");
  strncpy (str1, "brevity is the soul of wit", sizeof (str1));
  len = strlen (str1);
  tok1 = strtok_s (str1, &len, str2, &p2str);
  tok2 = strtok_s (0, &len, str2, &p2str);
  tok3 = strtok_s (0, &len, str2, &p2str);
  tok4 = strtok_s (0, &len, str2, &p2str);
  tok5 = strtok_s (0, &len, str2, &p2str);
  tok6 = strtok_s (0, &len, str2, &p2str);
  tok7 = strtok_s (0, &len, str2, &p2str);
  if (strcmp (tok1, "brevity") || strcmp (tok2, "is") ||
      strcmp (tok3, "the") || strcmp (tok4, "soul") ||
      strcmp (tok5, "of") || strcmp (tok6, "wit") || (tok7 != 0))
    return -1;

  /* delimiter not present in the string -- the whole string is returned */
  strncpy (str1, "brevity is the soul of wit", sizeof (str1));
  len = strlen (str1);
  p2str = 0;
  tok1 = strtok_s (str1, &len, ",", &p2str);
  if (strcmp (tok1, str1))
    return -1;

  /* negative stuff */
  tok = strtok_s (0, 0, 0, 0);
  if (tok != 0)
    return -1;

  tok = strtok_s (0, 0, 0, &ptr);
  if (tok != 0)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strnlen (vlib_main_t * vm, unformat_input_t * input)
{
  const char *s1 = "truth is incontrovertible";
  size_t len;

  vlib_cli_output (vm, "Test strnlen_s...");

  len = strnlen_s (s1, strlen (s1));
  if (len != strlen (s1))
    return -1;

  len = strnlen_s (s1, 5);
  if (len != 5)
    return -1;

  /* negative stuff */
  len = strnlen_s (0, 0);
  if (len != 0)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strstr (vlib_main_t * vm, unformat_input_t * input)
{
  errno_t err;
  char *sub = 0;
  char *s1 = "success is not final, failure is not fatal.";

  vlib_cli_output (vm, "Test strstr_s...");

  err = strstr_s (s1, strlen (s1), "final", strlen ("final"), &sub);
  if (err != EOK)
    return -1;
  if (strcmp (sub, "final, failure is not fatal.") != 0)
    return -1;

  err = strstr_s (s1, strlen (s1), "failure", strlen ("failure"), &sub);
  if (err != EOK)
    return -1;
  if (strcmp (sub, "failure is not fatal.") != 0)
    return -1;

  /* negative stuff */
  err = strstr_s (0, 0, 0, 0, 0);
  if (err != EINVAL)
    return -1;

  /* OK, seems to work */
  return 0;
}

static clib_error_t *
string_test_command_fn (vlib_main_t * vm,
			unformat_input_t * input,
			vlib_cli_command_t * cmd_arg)
{
  int res = 0, ok;
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
      ok = test_memcpy (vm, input);
      res += ok;
      if (ok != 0)
	vlib_cli_output (vm, "test_memcpy failed");
      ok = test_clib_memset (vm, input);
      res += ok;
      if (ok != 0)
	vlib_cli_output (vm, "test_clib_memset failed");
      ok = test_memcmp (vm, input);
      res += ok;
      if (ok != 0)
	vlib_cli_output (vm, "test_memcmp failed");
      ok = test_strcmp (vm, input);
      res += ok;
      if (ok != 0)
	vlib_cli_output (vm, "test_strcmp failed");
      ok = test_strncmp (vm, input);
      res += ok;
      if (ok != 0)
	vlib_cli_output (vm, "test_strncmp failed");
      ok = test_strcpy (vm, input);
      res += ok;
      if (ok != 0)
	vlib_cli_output (vm, "test_strcpy failed");
      ok = test_strncpy (vm, input);
      res += ok;
      if (ok != 0)
	vlib_cli_output (vm, "test_strncpy failed");
      ok = test_strcat (vm, input);
      res += ok;
      if (ok != 0)
	vlib_cli_output (vm, "test_strcat failed");
      ok = test_strncat (vm, input);
      res += ok;
      if (ok != 0)
	vlib_cli_output (vm, "test_strncat failed");
      ok = test_strtok (vm, input);
      res += ok;
      if (ok != 0)
	vlib_cli_output (vm, "test_strtok failed");
      ok = test_strnlen (vm, input);
      res += ok;
      if (ok != 0)
	vlib_cli_output (vm, "test_strnlen failed");
      ok = test_strstr (vm, input);
      res += ok;
      if (ok != 0)
	vlib_cli_output (vm, "test_strstr failed");
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
