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
  uword s1len = sizeof (s1) - 1;	// excluding null
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
  s1[s1len] = 0x1;
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
  uword s1len = sizeof (s1) - 1;	// excluding null
  errno_t err;
  int indicator = 0;

  vlib_cli_output (vm, "Test strncmp_s...");

  /* s1 == s2, 0 is expected */
  err = strncmp_s (s1, s1len, "every moment is a fresh beginning", s1len,
		   &indicator);
  if (err != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* s1 > s2,  0 is expected since comparison is no more than n character */
  err = strncmp_s (s1, s1len, "every moment is a fresh begin",
		   sizeof ("every moment is a fresh begin") - 1, &indicator);
  if (err != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* s1 < s2, < 0 is expected */
  err = strncmp_s (s1, s1len, "every moment is fresh beginning",
		   sizeof ("every moment is fresh beginning") - 1,
		   &indicator);
  if (err != EOK)
    return -1;
  if (!(indicator < 0))
    return -1;

  /* s1 > s2, > 0 is expected */
  err = strncmp_s ("every moment is fresh beginning. ",
		   sizeof ("every moment is fresh beginning. ") - 1, s1,
		   s1len, &indicator);
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

  /* unterminated s1 */
  s1[s1len] = 0x1;
  err = strncmp_s (s1, s1len, "every moment is a fresh beginning",
		   sizeof ("every moment is a fresh beginning") - 1,
		   &indicator);
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
  size_t s1size = sizeof (dst);	// including null
  errno_t err;

  vlib_cli_output (vm, "Test strcpy_s...");

  /* fill up src */
  for (i = 0; i < ARRAY_LEN (src) - 1; i++)
    src[i] = i + 1;
  src[ARRAY_LEN (src) - 1] = '\0';

  err = strcpy_s (dst, s1size, src);
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
  err = strcpy_s (dst + 1, s1size - 1, src);
  if (err == EOK)
    return -1;

  /* overlap fail */
  err = strcpy_s (dst, s1size, dst);
  if (err == EOK)
    return -1;

  /* overlap fail */
  err = strcpy_s (dst, s1size, dst + 1);
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
  size_t s1size = sizeof (dst);	// including null
  errno_t err;

  vlib_cli_output (vm, "Test strncpy_s...");

  /* fill up src */
  for (i = 0; i < ARRAY_LEN (src) - 1; i++)
    src[i] = i + 1;
  src[ARRAY_LEN (src) - 1] = '\0';

  /* dmax includes null, n excludes null */
  err = strncpy_s (dst, s1size, src, s1size - 1);
  if (err != EOK)
    return -1;

  /* This better not fail but check anyhow */
  for (i = 0; i < ARRAY_LEN (dst); i++)
    if (src[i] != dst[i])
      return -1;

  /* truncation, n >= dmax */
  err = strncpy_s (dst, s1size - 1, src, s1size - 1);
  if (err != EOVERFLOW)
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
  err = strncpy_s (dst, s1size, dst + 1, s1size - 1);
  if (err == EOK)
    return -1;

  /* overlap fail */
  err = strncpy_s (dst, s1size, dst, s1size);
  if (err == EOK)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strcat (vlib_main_t * vm, unformat_input_t * input)
{
  char src[100], dst[100];
  size_t s1size = sizeof (dst);	// including null
  errno_t err;
  int indicator;

  vlib_cli_output (vm, "Test strcat_s...");

  strcpy_s (dst, sizeof (dst), "tough time never last ");
  strcpy_s (src, sizeof (src), "but tough people do");
  err = strcat_s (dst, s1size, src);
  if (err != EOK)
    return -1;
  if (strcmp_s (dst, s1size - 1,
		"tough time never last but tough people do",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* negative stuff */
  err = strcat_s (0, 0, 0);
  if (err != EINVAL)
    return -1;

  /* overlap fail */
  err = strcat_s (dst, s1size, dst + 1);
  if (err != EINVAL)
    return -1;

  /* overlap fail */
  err = strcat_s (dst, s1size, dst);
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
  size_t s1size = sizeof (dst);	// including null
  errno_t err;
  char *s1 = "two things are infinite: ";
  char *s2 = "the universe and human stupidity; ";
  char *s3 = "I am not sure about the universe.";
  int indicator;

  vlib_cli_output (vm, "Test strncat_s...");

  strcpy_s (dst, sizeof (dst), s1);
  strcpy_s (src, sizeof (src), s2);
  err = strncat_s (dst, s1size, src, s1size);
  if (err != EOK)
    return -1;
  if (strcmp_s (dst, s1size - 1,
		"two things are infinite: the universe and human stupidity; ",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* truncation */
  err = strncat_s (dst, strlen (dst) + strlen (s3), s3, strlen (s3));
  if (err != EOVERFLOW)
    return -1;

  /*
   * resulting string is dst + strlen (s3) - 1 characters + null.
   * notice the "." is missing at the end of the resulting string because
   * the space is needed to accommodate the null
   * Notice strcmp_s will check s1 or dst to make sure it is null terminated
   */
  if (strcmp_s (dst, s1size - 1,
		"two things are infinite: the universe and human stupidity; "
		"I am not sure about the universe", &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* negative stuff */
  err = strncat_s (0, 0, 0, 0);
  if (err != EINVAL)
    return -1;

  /* no room for dst -- allowed size == 0 */
  err = strncat_s (dst, strnlen_s (dst, sizeof (dst)), s2, s1size);
  if (err != EINVAL)
    return -1;

  /* overlap fail */
  err = strncat_s (dst, s1size, dst + 1, s1size - 1);
  if (err != EINVAL)
    return -1;

  /* overlap fail */
  err = strncat_s (dst, s1size, dst, s1size);
  if (err != EINVAL)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strtok (vlib_main_t * vm, unformat_input_t * input)
{
  int indicator;
  char *tok, *ptr;
  char str2[20];
  char str1[100];
  uword len;
  char *p2str = 0;
  char *tok1, *tok2, *tok3, *tok4, *tok5, *tok6, *tok7;

  vlib_cli_output (vm, "Test strtok_s...");
  strcpy_s (str1, sizeof (str1), "brevity is the soul of wit");
  len = strnlen_s (str1, sizeof (str1));
  tok1 = strtok_s (str1, &len, " ", &p2str);
  tok2 = strtok_s (0, &len, " ", &p2str);
  tok3 = strtok_s (0, &len, " ", &p2str);
  tok4 = strtok_s (0, &len, " ", &p2str);
  tok5 = strtok_s (0, &len, " ", &p2str);
  tok6 = strtok_s (0, &len, " ", &p2str);
  tok7 = strtok_s (0, &len, " ", &p2str);
  if ((tok1 == 0) ||
      strcmp_s (tok1, strlen (tok1), "brevity", &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;
  if ((tok2 == 0) || strcmp_s (tok2, strlen (tok2), "is", &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;
  if ((tok3 == 0) || strcmp_s (tok3, strlen (tok3), "the", &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;
  if ((tok4 == 0)
      || strcmp_s (tok4, strlen (tok4), "soul", &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;
  if ((tok5 == 0) || strcmp_s (tok5, strlen (tok5), "of", &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;
  if ((tok6 == 0) || strcmp_s (tok6, strlen (tok6), "wit", &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;
  if (tok7 != 0)
    return -1;

  /* delimiter not present in the string -- the whole string is returned */
  strcpy_s (str1, sizeof (str1), "brevity is the soul of wit");
  len = strnlen_s (str1, sizeof (str1) - 1);
  p2str = 0;
  tok1 = strtok_s (str1, &len, ",", &p2str);
  if ((tok1 == 0) || strcmp_s (tok1, strlen (tok1), str1, &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* negative stuff */
  tok = strtok_s (0, 0, 0, 0);
  if (tok != 0)
    return -1;

  /* s1 and ptr contents are null */
  ptr = 0;
  tok = strtok_s (0, 0, 0, &ptr);
  if (tok != 0)
    return -1;

  /* unterminate s1 */
  p2str = 0;
  len = strnlen_s (str1, sizeof (str1) - 1);
  str1[strlen (str1)] = 0x2;
  tok = strtok_s (str1, &len, ",", &p2str);
  if (tok != 0)
    return -1;

  /* unterminated s2 */
  memset_s (str2, sizeof (str2), 0xfa, sizeof (str2));
  tok = strtok_s (str1, &len, str2, &p2str);
  if (tok != 0)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strnlen (vlib_main_t * vm, unformat_input_t * input)
{
  const char s1[] = "truth is incontrovertible";
  size_t len;

  vlib_cli_output (vm, "Test strnlen_s...");

  len = strnlen_s (s1, sizeof (s1));
  if (len != sizeof (s1) - 1)
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
  char s1[100];
  size_t s1len = sizeof (s1) - 1;	// excluding null
  int indicator;

  vlib_cli_output (vm, "Test strstr_s...");

  /* substring not present */
  strcpy_s (s1, s1len, "success is not final, failure is not fatal.");
  err = strstr_s (s1, s1len, "failures", sizeof ("failures"), &sub);;
  if (err != ESRCH)
    return -1;

  /* substring present */
  err = strstr_s (s1, s1len, "failure", sizeof ("failure"), &sub);
  if (err != EOK)
    return -1;

  if ((sub == 0) ||
      strcmp_s (sub, strlen (sub), "failure is not fatal.", &indicator)
      != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* negative stuff */
  err = strstr_s (0, 0, 0, 0, 0);
  if (err != EINVAL)
    return -1;

  /* unterminated s1 and s2 */
  memset_s (s1, ARRAY_LEN (s1), 0xfe, ARRAY_LEN (s1));
  err = strstr_s (s1, s1len, s1, s1len, &sub);
  if (err != EINVAL)
    return -1;

  /* OK, seems to work */
  return 0;
}

#define foreach_string_test  \
  _ (1, MEMCPY_S, "memcpy_s") \
  _ (2, MEMSET_S , "memset_s") \
  _ (3, MEMCMP_S, "memcmp_s")  \
  _ (4, STRCMP_S, "strcmp_s")  \
  _ (5, STRNCMP_S, "strncmp_s")  \
  _ (6, STRCPY_S, "strcpy_s")  \
  _ (7, STRNCPY_S, "strncpy_s")  \
  _ (8, STRCAT_S, "strcat_s")  \
  _ (9, STRNCAT_S, "strncat_s")  \
  _ (10, STRTOK_S, "strtok_s")  \
  _ (11, STRNLEN_S, "strnlen_s")  \
  _ (12, STRSTR_S, "strstr_s")

typedef enum
{
#define _(v, f, s) STRING_TEST_##f = v,
  foreach_string_test
#undef _
} string_test_t;

static uword
unformat_string_test (unformat_input_t * input, va_list * args)
{
  u8 *r = va_arg (*args, u8 *);

  if (0);
#define _(v, f, s) else if (unformat (input, s)) *r = STRING_TEST_##f;
  foreach_string_test
#undef _
    else
    return 0;

  return 1;
}

static clib_error_t *
string_test_command_fn (vlib_main_t * vm,
			unformat_input_t * input,
			vlib_cli_command_t * cmd_arg)
{
  int res = 0, ok;
  u8 specific_test = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_string_test, &specific_test))
	break;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  switch (specific_test)
    {
    default:
    case 0:
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
      break;
    case STRING_TEST_MEMCPY_S:
      res = test_memcpy (vm, input);
      break;
    case STRING_TEST_MEMSET_S:
      res = test_clib_memset (vm, input);
      break;
    case STRING_TEST_MEMCMP_S:
      res = test_memcmp (vm, input);
      break;
    case STRING_TEST_STRCMP_S:
      res = test_strcmp (vm, input);
      break;
    case STRING_TEST_STRNCMP_S:
      res = test_strncmp (vm, input);
      break;
    case STRING_TEST_STRCPY_S:
      res = test_strcpy (vm, input);
      break;
    case STRING_TEST_STRNCPY_S:
      res = test_strncpy (vm, input);
      break;
    case STRING_TEST_STRCAT_S:
      res = test_strcat (vm, input);
      break;
    case STRING_TEST_STRNCAT_S:
      res = test_strncat (vm, input);
      break;
    case STRING_TEST_STRTOK_S:
      res = test_strtok (vm, input);
      break;
    case STRING_TEST_STRNLEN_S:
      res = test_strnlen (vm, input);
      break;
    case STRING_TEST_STRSTR_S:
      res = test_strstr (vm, input);
      break;
    }

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
  .short_help = "test string [memcmp_s | memset_s | memcmp_s | strcmp_s | "
  "strncmp_s | strcpy_s | strncpy_s | strcat_s | strncat_s | strtok_s | "
  "strnlen_s | strstr_s]",
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
