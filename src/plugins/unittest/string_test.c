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
test_memset_s (vlib_main_t * vm, unformat_input_t * input)
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
test_clib_memset (vlib_main_t * vm, unformat_input_t * input)
{
  u8 dst[64];
  int i;
  errno_t err;

  vlib_cli_output (vm, "Test clib_memset...");

  err = clib_memset (dst, 0xfe, ARRAY_LEN (dst));

  if (err != EOK)
    return -1;

  for (i = 0; i < ARRAY_LEN (dst); i++)
    if (dst[i] != 0xFE)
      return -1;

  return 0;
}

static int
test_memcpy_s (vlib_main_t * vm, unformat_input_t * input)
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
test_clib_memcpy (vlib_main_t * vm, unformat_input_t * input)
{
  char src[64], dst[64];
  int i;
  errno_t err;

  vlib_cli_output (vm, "Test clib_memcpy...");

  for (i = 0; i < ARRAY_LEN (src); i++)
    src[i] = i + 1;

  /* Typical case */
  err = clib_memcpy (dst, src, sizeof (src));

  if (err != EOK)
    return -1;

  /* This better not fail but check anyhow */
  for (i = 0; i < ARRAY_LEN (dst); i++)
    if (src[i] != dst[i])
      return -1;
  /* verify it against memcpy */
  memcpy (dst, src, sizeof (src));

  /* This better not fail but check anyhow */
  for (i = 0; i < ARRAY_LEN (dst); i++)
    if (src[i] != dst[i])
      return -1;

  /* Zero length copy */
  err = clib_memcpy (0, src, 0);

  if (err != EOK)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_memcmp_s (vlib_main_t * vm, unformat_input_t * input)
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
test_clib_memcmp (vlib_main_t * vm, unformat_input_t * input)
{
  char src[64], dst[64];
  errno_t err;
  char *s;

  vlib_cli_output (vm, "Test clib_memcmp...");

  /* Fill array with different values */
  err = clib_memset (src, 0x1, ARRAY_LEN (src));
  if (err != EOK)
    return -1;
  err = clib_memset (dst, 0x3, ARRAY_LEN (dst));
  if (err != EOK)
    return -1;

  /* s1 > s2, > 0 is expected in diff */
  if (!(clib_memcmp (dst, src, ARRAY_LEN (src)) > 0))
    return -1;
  /* verify it against memcmp */
  if (!(memcmp (dst, src, ARRAY_LEN (src)) > 0))
    return -1;

  /* s1 < s2, < 0 is expected in diff */
  if (!(clib_memcmp (src, dst, ARRAY_LEN (dst)) < 0))
    return -1;
  /* verify it against memcmp */
  if (!(memcmp (src, dst, ARRAY_LEN (dst)) < 0))
    return -1;

  err = clib_memset (dst, 0x1, ARRAY_LEN (dst));
  if (err != EOK)
    return -1;

  /* s1 == s2, 0 is expected in diff */
  if (clib_memcmp (src, dst, ARRAY_LEN (dst)) != 0)
    return -1;
  /* verify it against memcmp */
  if (memcmp (src, dst, ARRAY_LEN (dst)) != 0)
    return -1;

  /* Try negative tests */
  s = 0;
  if (clib_memcmp (s, s, 0) != 0)
    return -1;
  /* verify it against memcmp */
  if (memcmp (s, s, 0) != 0)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strcmp_s (vlib_main_t * vm, unformat_input_t * input)
{
  char s1[] = "Simplicity is the ultimate sophistication";
  uword s1len = sizeof (s1) - 1;	// excluding null
  errno_t err;
  int indicator = 0;

  vlib_cli_output (vm, "Test strcmp_s...");

  /* s1 == s2, 0 is expected */
  err = strcmp_s (s1, s1len, "Simplicity is the ultimate sophistication",
		  &indicator);
  if (err != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* s1 > s2, > 0 is expected */
  err = strcmp_s (s1, s1len, "Simplicity is the ultimate", &indicator);
  if (err != EOK)
    return -1;
  if (!(indicator > 0))
    return -1;

  /* s1 < s2, < 0 is expected */
  err = strcmp_s (s1, s1len, "Simplicity is the ultimate sophistication!",
		  &indicator);
  if (err != EOK)
    return -1;
  if (!(indicator < 0))
    return -1;

  /* Try some negative tests */

  /* Null pointers test */
  err = strcmp_s (0, 0, 0, 0);
  if (err != EINVAL)
    return -1;

  /* non-null terminated s1 */
  s1[s1len] = 0x1;
  err = strcmp_s (s1, s1len, "Simplicity is the ultimate sophistication",
		  &indicator);
  if (err != EINVAL)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_clib_strcmp (vlib_main_t * vm, unformat_input_t * input)
{
  char s1[] = "Simplicity is the ultimate sophistication";
  int indicator;
  char *s;

  vlib_cli_output (vm, "Test clib_strcmp...");

  /* s1 == s2, 0 is expected */
  indicator = clib_strcmp (s1, "Simplicity is the ultimate sophistication");
  if (indicator != 0)
    return -1;
  /* verify it against strcmp */
  indicator = strcmp (s1, "Simplicity is the ultimate sophistication");
  if (indicator != 0)
    return -1;

  /* s1 > s2, > 0 is expected */
  indicator = clib_strcmp (s1, "Simplicity is the ultimate");
  if (!(indicator > 0))
    return -1;
  /* verify it against strcmp */
  indicator = strcmp (s1, "Simplicity is the ultimate");
  if (!(indicator > 0))
    return -1;

  /* s1 < s2, < 0 is expected */
  indicator = clib_strcmp (s1, "Simplicity is the ultimate sophistication!");
  if (!(indicator < 0))
    return -1;
  /* verify it against strcmp */
  indicator = strcmp (s1, "Simplicity is the ultimate sophistication!");
  if (!(indicator < 0))
    return -1;

  /* Try some negative tests */

  /* Null pointers comparison */
  s = 0;
  indicator = clib_strcmp (s, s);
  if (indicator != 0)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strncmp_s (vlib_main_t * vm, unformat_input_t * input)
{
  char s1[] = "Every moment is a fresh beginning";
  uword s1len = sizeof (s1) - 1;	// excluding null
  errno_t err;
  int indicator = 0;

  vlib_cli_output (vm, "Test strncmp_s...");

  /* s1 == s2, 0 is expected */
  err = strncmp_s (s1, s1len, "Every moment is a fresh beginning", s1len,
		   &indicator);
  if (err != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* s1 > s2, 0 is expected since comparison is no more than n character */
  err = strncmp_s (s1, s1len, "Every moment is a fresh begin",
		   sizeof ("Every moment is a fresh begin") - 1, &indicator);
  if (err != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* s1 < s2, < 0 is expected */
  err = strncmp_s (s1, s1len, "Every moment is fresh beginning",
		   sizeof ("Every moment is fresh beginning") - 1,
		   &indicator);
  if (err != EOK)
    return -1;
  if (!(indicator < 0))
    return -1;

  /* s1 > s2, > 0 is expected */
  err = strncmp_s ("Every moment is fresh beginning. ",
		   sizeof ("Every moment is fresh beginning. ") - 1, s1,
		   s1len, &indicator);
  if (err != EOK)
    return -1;
  if (!(indicator > 0))
    return -1;

  /* Try some negative tests */

  /* Null pointers */
  err = strncmp_s (0, 0, 0, 0, 0);
  if (err != EINVAL)
    return -1;

  /* n > s1max */
  err = strncmp_s (s1, s1len, "Every moment is a fresh beginning", s1len + 1,
		   &indicator);
  if (err != EINVAL)
    return -1;

  /* unterminated s1 */
  s1[s1len] = 0x1;
  err = strncmp_s (s1, s1len, "Every moment is a fresh beginning",
		   sizeof ("Every moment is a fresh beginning") - 1,
		   &indicator);
  if (err != EINVAL)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_clib_strncmp (vlib_main_t * vm, unformat_input_t * input)
{
  char s1[] = "Every moment is a fresh beginning";
  uword s1len = sizeof (s1) - 1;	// excluding null
  int indicator, v_indicator;

  vlib_cli_output (vm, "Test clib_strncmp...");

  /* s1 == s2, 0 is expected */
  indicator = clib_strncmp (s1, "Every moment is a fresh beginning", s1len);
  if (indicator != 0)
    return -1;
  /* verify it against strncmp */
  v_indicator = strncmp (s1, "Every moment is a fresh beginning", s1len);
  if (v_indicator != 0)
    return -1;
  if (v_indicator != indicator)
    return -1;

  /* s1 > s2, 0 is expected since comparison is no more than n character */
  indicator = clib_strncmp (s1, "Every moment is a fresh begin",
			    sizeof ("Every moment is a fresh begin") - 1);
  if (indicator != 0)
    return -1;
  /* verify it against strncmp */
  v_indicator = strncmp (s1, "Every moment is a fresh begin",
			 sizeof ("Every moment is a fresh begin") - 1);
  if (v_indicator != 0)
    return -1;
  if (v_indicator != indicator)
    return -1;

  /* s1 < s2, < 0 is expected */
  indicator = clib_strncmp (s1, "Every moment is fresh beginning",
			    sizeof ("Every moment is fresh beginning") - 1);
  if (!(indicator < 0))
    return -1;
  /* verify it against strncmp */
  v_indicator = strncmp (s1, "Every moment is fresh beginning",
			 sizeof ("Every moment is fresh beginning") - 1);
  if (!(v_indicator < 0))
    return -1;
  if (v_indicator != indicator)
    return -1;

  /* s1 > s2, > 0 is expected */
  indicator = clib_strncmp ("Every moment is fresh beginning. ", s1, s1len);
  if (!(indicator > 0))
    return -1;
  /* verify it against strncmp */
  v_indicator = strncmp ("Every moment is fresh beginning. ", s1, s1len);
  if (!(v_indicator > 0))
    return -1;
  if (v_indicator != indicator)
    return -1;

  /* Try some negative tests */

  /* Null pointers */

  /* make sure we don't crash */
  indicator = clib_strncmp (0, 0, 0);
  if (indicator != EOK)
    return -1;

  /* n > s1 len */
  indicator =
    clib_strncmp (s1, "Every moment is a fresh beginning", s1len + 1);
  if (indicator != 0)
    return -1;
  /* verify it against strncmp */
  v_indicator = strncmp (s1, "Every moment is a fresh beginning", s1len + 1);
  if (v_indicator != 0)
    return -1;
  if (v_indicator != indicator)
    return -1;

  /* unterminated s1 */
  s1[s1len] = 0x1;
  indicator = clib_strncmp (s1, "Every moment is a fresh beginning",
			    sizeof ("every moment is a fresh beginning") - 1);
  if (indicator != 0)
    return -1;
  /* verify it against strncmp */
  v_indicator = strncmp (s1, "Every moment is a fresh beginning",
			 sizeof ("Every moment is a fresh beginning") - 1);
  if (v_indicator != 0)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strcpy_s (vlib_main_t * vm, unformat_input_t * input)
{
  char src[] = "To err is human.";
  char dst[64];
  int indicator;
  size_t s1size = sizeof (dst);	// including null
  errno_t err;

  vlib_cli_output (vm, "Test strcpy_s...");

  err = strcpy_s (dst, s1size, src);
  if (err != EOK)
    return -1;

  /* This better not fail but check anyhow */
  if (strcmp_s (dst, clib_strnlen (dst, sizeof (dst)), src, &indicator) !=
      EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* Negative tests */

  err = strcpy_s (0, 0, 0);
  if (err == EOK)
    return -1;

  /* Size fail */
  err = strcpy_s (dst, 10, src);
  if (err == EOK)
    return -1;

  /* overlap fail */
#if __GNUC__ < 8
  /* GCC 8 flunks this one at compile time... */
  err = strcpy_s (dst, s1size, dst);
  if (err == EOK)
    return -1;
#endif

  /* overlap fail */
  err = strcpy_s (dst, s1size, dst + 1);
  if (err == EOK)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_clib_strcpy (vlib_main_t * vm, unformat_input_t * input)
{
  char src[] = "The journey of a one thousand miles begins with one step.";
  char dst[100];
  int indicator;
  errno_t err;

  vlib_cli_output (vm, "Test clib_strcpy...");

  err = clib_strcpy (dst, src);
  if (err != EOK)
    return -1;

  /* This better not fail but check anyhow */
  if (strcmp_s (dst, clib_strnlen (dst, sizeof (dst)), src, &indicator) !=
      EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* verify it against strcpy */
  strcpy (dst, src);

  /* This better not fail but check anyhow */
  if (strcmp_s (dst, clib_strnlen (dst, sizeof (dst)), src, &indicator) !=
      EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* Negative tests */

  err = clib_strcpy (0, 0);
  if (err == EOK)
    return -1;

  /* overlap fail */
#if __GNUC__ < 8
  /* GCC 8 flunks this one at compile time... */
  err = clib_strcpy (dst, dst);
  if (err == EOK)
    return -1;
#endif

  /* overlap fail */
  err = clib_strcpy (dst, dst + 1);
  if (err == EOK)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strncpy_s (vlib_main_t * vm, unformat_input_t * input)
{
  char src[] = "Those who dare to fail miserably can achieve greatly.";
  char dst[100], old_dst[100];
  int indicator, i;
  size_t s1size = sizeof (dst);	// including null
  errno_t err;

  vlib_cli_output (vm, "Test strncpy_s...");

  /* dmax includes null, n excludes null */

  /* n == string len of src */
  err = strncpy_s (dst, s1size, src, clib_strnlen (src, sizeof (src)));
  if (err != EOK)
    return -1;
  if (strcmp_s (dst, clib_strnlen (dst, sizeof (dst)), src, &indicator) !=
      EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* limited copy -- strlen src > n, copy up to n */
  err = strncpy_s (dst, s1size, "The price of greatness is responsibility.",
		   10);
  if (err != EOK)
    return -1;
  if (strcmp_s (dst, clib_strnlen (dst, sizeof (dst)), "The price ",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* n > string len of src */
  err = clib_memset (dst, 1, sizeof (dst));
  if (err != EOK)
    return -1;

  err = strncpy_s (dst, s1size, src, clib_strnlen (src, sizeof (src)) + 10);
  if (err != EOK)
    return -1;
  if (strcmp_s (dst, clib_strnlen (dst, sizeof (dst)), src, &indicator) !=
      EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* Make sure bytes after strlen(dst) is untouched */
  for (i = 1 + clib_strnlen (dst, sizeof (dst)); i < sizeof (dst); i++)
    if (dst[i] != 1)
      return -1;

  /* truncation, n >= dmax */
  err = strncpy_s (dst, clib_strnlen (src, sizeof (src)), src,
		   clib_strnlen (src, sizeof (src)));
  if (err != EOVERFLOW)
    return -1;

  /* Check dst content */
  if (dst[strlen (dst)] != '\0')
    return -1;
  if (strncmp_s (dst, clib_strnlen (dst, sizeof (dst)), src,
		 clib_strnlen (dst, sizeof (dst)), &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* zero length copy */
  clib_strncpy (old_dst, dst, clib_strnlen (dst, sizeof (dst)));
  err = strncpy_s (dst, sizeof (dst), src, 0);
  if (err != EOK)
    return -1;
  /* verify dst is untouched */
  if (strcmp_s (dst, clib_strnlen (dst, sizeof (dst)), old_dst, &indicator) !=
      EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* Negative tests */

  err = strncpy_s (0, 0, 0, 1);
  if (err == EOK)
    return -1;

  /* overlap fail */
  err = strncpy_s (dst, s1size, dst + 1, s1size - 1);
  if (err == EOK)
    return -1;

  /* overlap fail */
#if __GNUC__ < 8
  /* GCC 8 flunks this one at compile time... */
  err = strncpy_s (dst, s1size, dst, s1size);
  if (err == EOK)
    return -1;
#endif

  /* OK, seems to work */
  return 0;
}

static int
test_clib_strncpy (vlib_main_t * vm, unformat_input_t * input)
{
  char src[] = "Those who dare to fail miserably can achieve greatly.";
  char dst[100], old_dst[100];
  int indicator;
  size_t s1size = sizeof (dst);	// including null
  errno_t err;

  vlib_cli_output (vm, "Test clib_strncpy...");

  /* n == string len of src */
  err = clib_strncpy (dst, src, clib_strnlen (src, sizeof (src)));
  if (err != EOK)
    return -1;

  /* This better not fail but check anyhow */
  if (strcmp_s (dst, clib_strnlen (dst, sizeof (dst)), src, &indicator) !=
      EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* Verify it against strncpy */
  strncpy (dst, src, strlen (src));

  /* This better not fail but check anyhow */
  if (strcmp_s (dst, clib_strnlen (dst, sizeof (dst)), src, &indicator) !=
      EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* limited copy -- strlen src > n, copy up to n */
  err = clib_strncpy (dst, "The price of greatness is responsibility.", 10);
  if (err != EOK)
    return -1;
  if (strcmp_s (dst, clib_strnlen (dst, sizeof (dst)), "The price ",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;
  /* verify it against strncpy */
  memset_s (dst, sizeof (dst), 0, sizeof (dst));

#if __GNUC__ < 8
  /* GCC 8 flunks this one at compile time... */
  strncpy (dst, "The price of greatness is responsibility.", 10);
  if (strcmp_s (dst, clib_strnlen (dst, sizeof (dst)), "The price ",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;
#endif

  /* n > string len of src */
  err = clib_strncpy (dst, src, clib_strnlen (src, sizeof (src)) + 10);
  if (err != EOK)
    return -1;
  if (strcmp_s (dst, clib_strnlen (dst, sizeof (dst)), src, &indicator) !=
      EOK)
    return -1;
  if (indicator != 0)
    return -1;
  /* Verify it against strncpy */
  strncpy (dst, src, strlen (src));
  if (strcmp_s (dst, clib_strnlen (dst, sizeof (dst)), src, &indicator) !=
      EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* zero length copy */
  clib_strncpy (old_dst, dst, clib_strnlen (dst, sizeof (dst)));
  err = clib_strncpy (dst, src, 0);
  if (err != EOK)
    return -1;
  /* verify dst is untouched */
  if (strcmp_s (dst, clib_strnlen (dst, sizeof (dst)), old_dst, &indicator) !=
      EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* Negative tests */

  err = clib_strncpy (0, 0, 1);
  if (err == EOK)
    return -1;

  /* overlap fail */
  err = clib_strncpy (dst, dst + 1, s1size);
  if (err == EOK)
    return -1;

  /* overlap fail */
#if __GNUC__ < 8
  /* GCC 8 flunks this one at compile time... */
  err = clib_strncpy (dst, dst, s1size);
  if (err == EOK)
    return -1;
#endif

  /* OK, seems to work */
  return 0;
}

static int
test_strcat_s (vlib_main_t * vm, unformat_input_t * input)
{
  char src[100], dst[100], old_dst[100];
  size_t s1size = sizeof (dst);	// including null
  errno_t err;
  int indicator;

  vlib_cli_output (vm, "Test strcat_s...");

  strcpy_s (dst, sizeof (dst), "Tough time never last ");
  strcpy_s (src, sizeof (src), "but tough people do");
  err = strcat_s (dst, s1size, src);
  if (err != EOK)
    return -1;
  if (strcmp_s (dst, s1size - 1,
		"Tough time never last but tough people do",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* empty string concatenation */
  clib_strncpy (old_dst, dst, clib_strnlen (dst, sizeof (dst)));
  err = strcat_s (dst, s1size, "");
  if (err != EOK)
    return -1;
  /* verify dst is untouched */
  if (strcmp_s (dst, s1size - 1, old_dst, &indicator) != EOK)
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
#if __GNUC__ < 8
  /* GCC 8 flunks this one at compile time... */
  err = strcat_s (dst, s1size, dst);
  if (err != EINVAL)
    return -1;
#endif

  /* not enough space for dst */
  err = strcat_s (dst, 10, src);
  if (err != EINVAL)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_clib_strcat (vlib_main_t * vm, unformat_input_t * input)
{
  char src[100], dst[100], old_dst[100];
  size_t s1size = sizeof (dst);	// including null
  errno_t err;
  int indicator;

  vlib_cli_output (vm, "Test clib_strcat...");

  strcpy_s (dst, sizeof (dst), "Tough time never last ");
  strcpy_s (src, sizeof (src), "but tough people do");
  err = clib_strcat (dst, src);
  if (err != EOK)
    return -1;
  if (strcmp_s (dst, s1size - 1,
		"Tough time never last but tough people do",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;
  /* verify it against strcat */
  strcpy_s (dst, sizeof (dst), "Tough time never last ");
  strcpy_s (src, sizeof (src), "but tough people do");
  strcat (dst, src);
  if (strcmp_s (dst, s1size - 1,
		"Tough time never last but tough people do",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* empty string concatenation */
  clib_strncpy (old_dst, dst, clib_strnlen (dst, sizeof (dst)));
  err = clib_strcat (dst, "");
  if (err != EOK)
    return -1;
  /* verify dst is untouched */
  if (strcmp_s (dst, s1size - 1, old_dst, &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* negative stuff */
  err = clib_strcat (0, 0);
  if (err != EINVAL)
    return -1;

  /* overlap fail */
  err = clib_strcat (dst, dst + 1);
  if (err != EINVAL)
    return -1;

  /* overlap fail */
#if __GNUC__ < 8
  /* GCC 8 flunks this one at compile time... */
  err = clib_strcat (dst, dst);
  if (err != EINVAL)
    return -1;
#endif

  /* OK, seems to work */
  return 0;
}

static int
test_strncat_s (vlib_main_t * vm, unformat_input_t * input)
{
  char src[100], dst[100], old_dst[100];
  size_t s1size = sizeof (dst);	// including null
  errno_t err;
  char s1[] = "Two things are infinite: ";
  char s2[] = "the universe and human stupidity; ";
  char s3[] = "I am not sure about the universe.";
  int indicator;

  vlib_cli_output (vm, "Test strncat_s...");

  strcpy_s (dst, sizeof (dst), s1);
  strcpy_s (src, sizeof (src), s2);
  err = strncat_s (dst, s1size, src, clib_strnlen (src, sizeof (src)));
  if (err != EOK)
    return -1;
  if (strcmp_s (dst, s1size - 1,
		"Two things are infinite: the universe and human stupidity; ",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* truncation, n >= dmax - strnlen_s (dst, dmax) */
  err = strncat_s (dst, clib_strnlen (dst, sizeof (dst)) +
		   clib_strnlen (s3, sizeof (s3)), s3,
		   clib_strnlen (s3, sizeof (s3)));
  if (err != EOVERFLOW)
    return -1;
  /*
   * resulting string is dst + strlen (s3) - 1 characters + null.
   * notice the "." is missing at the end of the resulting string because
   * the space is needed to accommodate the null
   * Notice strcmp_s will check s1 or dst to make sure it is null terminated
   */
  if (strcmp_s (dst, s1size - 1,
		"Two things are infinite: the universe and human stupidity; "
		"I am not sure about the universe", &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* n > strlen src */
  strcpy_s (dst, sizeof (dst), s1);
  err = strncat_s (dst, s1size, src, clib_strnlen (src, sizeof (src)) + 10);
  if (err != EOK)
    return -1;
  if (strcmp_s (dst, s1size - 1,
		"Two things are infinite: the universe and human stupidity; ",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* zero length strncat */
  clib_strncpy (old_dst, dst, clib_strnlen (dst, sizeof (dst)));
  err = strncat_s (dst, sizeof (dst), src, 0);
  if (err != EOK)
    return -1;
  /* verify dst is untouched */
  if (strcmp_s (dst, s1size - 1, old_dst, &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* empty string, wrong n concatenation */
  err = strncat_s (dst, sizeof (dst), "", 10);
  if (err != EOK)
    return -1;
  /* verify dst is untouched */
  if (strcmp_s (dst, s1size - 1, old_dst, &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* limited concatenation, string > n, copy up to n */
  strcpy_s (dst, sizeof (dst), s1);
  err = strncat_s (dst, s1size, s2, 13);
  if (err != EOK)
    return -1;
  if (strcmp_s (dst, s1size - 1, "Two things are infinite: the universe ",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;
  /* verify it against strncat */
  strcpy_s (dst, sizeof (dst), s1);
  strncat (dst, s2, 13);
  if (strcmp_s (dst, s1size - 1, "Two things are infinite: the universe ",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* negative stuff */
  err = strncat_s (0, 0, 0, 1);
  if (err != EINVAL)
    return -1;

  /* no room for dst -- dmax - strnlen_s (dst, dmax) == 0 */
  err = strncat_s (dst, clib_strnlen (dst, sizeof (dst)), s2,
		   clib_strnlen (s2, sizeof (s2)));
  if (err != EINVAL)
    return -1;

  /* overlap fail */
  err = strncat_s (dst, s1size, dst + 1, clib_strnlen (dst + 1, s1size - 1));
  if (err != EINVAL)
    return -1;

  /* overlap fail */
#if __GNUC__ < 8
  /* GCC 8 flunks this one at compile time... */
  err = strncat_s (dst, s1size, dst, clib_strnlen (dst, sizeof (dst)));
  if (err != EINVAL)
    return -1;
#endif

  /* OK, seems to work */
  return 0;
}

static int
test_clib_strncat (vlib_main_t * vm, unformat_input_t * input)
{
  char src[100], dst[100], old_dst[100];
  size_t s1size = sizeof (dst);	// including null
  errno_t err;
  char s1[] = "Two things are infinite: ";
  char s2[] = "the universe and human stupidity; ";
  int indicator;

  vlib_cli_output (vm, "Test clib_strncat...");

  /* n == strlen src */
  strcpy_s (dst, sizeof (dst), s1);
  strcpy_s (src, sizeof (src), s2);
  err = clib_strncat (dst, src, clib_strnlen (src, sizeof (src)));
  if (err != EOK)
    return -1;
  if (strcmp_s (dst, s1size - 1,
		"Two things are infinite: the universe and human stupidity; ",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;
  /* verify it against strncat */
  strcpy_s (dst, sizeof (dst), s1);
  strncat (dst, src, clib_strnlen (src, sizeof (src)));
  if (strcmp_s (dst, s1size - 1,
		"Two things are infinite: the universe and human stupidity; ",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* n > strlen src */
  strcpy_s (dst, sizeof (dst), s1);
  err = clib_strncat (dst, src, clib_strnlen (src, sizeof (src)) + 10);
  if (err != EOK)
    return -1;
  if (strcmp_s (dst, s1size - 1,
		"Two things are infinite: the universe and human stupidity; ",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;
  /* verify it against strncat */
  strcpy_s (dst, sizeof (dst), s1);
  strncat (dst, src, clib_strnlen (src, sizeof (src)));
  if (strcmp_s (dst, s1size - 1,
		"Two things are infinite: the universe and human stupidity; ",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* zero length strncat */
  clib_strncpy (old_dst, dst, clib_strnlen (dst, sizeof (dst)));
  err = clib_strncat (dst, src, 0);
  if (err != EOK)
    return -1;
  /* verify dst is untouched */
  if (strcmp_s (dst, s1size - 1, old_dst, &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* empty string, wrong n concatenation */
  err = clib_strncat (dst, "", 10);
  if (err != EOK)
    return -1;
  /* verify dst is untouched */
  if (strcmp_s (dst, s1size - 1, old_dst, &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* limited concatenation, string > n, copy up to n */
  strcpy_s (dst, sizeof (dst), s1);
  err = clib_strncat (dst, s2, 13);
  if (err != EOK)
    return -1;
  if (strcmp_s (dst, s1size - 1, "Two things are infinite: the universe ",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;
  /* verify it against strncat */
  strcpy_s (dst, sizeof (dst), s1);
  strncat (dst, s2, 13);
  if (strcmp_s (dst, s1size - 1, "Two things are infinite: the universe ",
		&indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* negative stuff */
  err = clib_strncat (0, 0, 1);
  if (err != EINVAL)
    return -1;

  /* overlap fail */
  err = clib_strncat (dst, dst + 1, s1size - 1);
  if (err != EINVAL)
    return -1;

  /* overlap fail */
#if __GNUC__ < 8
  /* GCC 8 flunks this one at compile time... */
  err = clib_strncat (dst, dst, clib_strnlen (dst, sizeof (dst)));
  if (err != EINVAL)
    return -1;
#endif

  /* OK, seems to work */
  return 0;
}

static int
test_strtok_s (vlib_main_t * vm, unformat_input_t * input)
{
  int indicator;
  char *tok, *ptr;
  char str2[20];
  char str1[40];
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

  /*
   * unterminated s2. This test case in not perfect because there is no
   * argument for s2max. But s2 len is limited to 16 characters. If the API
   * does not find the null character at s2[15], it declares the string s2
   * as unterminated.
   */
  memset_s (str2, sizeof (str2), 0xfa, sizeof (str2));
  tok = strtok_s (str1, &len, str2, &p2str);
  if (tok != 0)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_clib_strtok (vlib_main_t * vm, unformat_input_t * input)
{
  int indicator;
  char *s1 __attribute__ ((unused));
  char *tok __attribute__ ((unused));
  char *ptr __attribute__ ((unused));
  char str1[40];
  char *p2str;
  char *tok1, *tok2, *tok3, *tok4, *tok5, *tok6, *tok7;

  vlib_cli_output (vm, "Test clib_strtok...");
  strcpy_s (str1, sizeof (str1), "brevity is the soul of wit");
  p2str = 0;
  tok1 = clib_strtok (str1, " ", &p2str);
  tok2 = clib_strtok (0, " ", &p2str);
  tok3 = clib_strtok (0, " ", &p2str);
  tok4 = clib_strtok (0, " ", &p2str);
  tok5 = clib_strtok (0, " ", &p2str);
  tok6 = clib_strtok (0, " ", &p2str);
  tok7 = clib_strtok (0, " ", &p2str);
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
  /* verify it againest strtok_r */
  strcpy_s (str1, sizeof (str1), "brevity is the soul of wit");
  p2str = 0;
  tok1 = strtok_r (str1, " ", &p2str);
  tok2 = strtok_r (0, " ", &p2str);
  tok3 = strtok_r (0, " ", &p2str);
  tok4 = strtok_r (0, " ", &p2str);
  tok5 = strtok_r (0, " ", &p2str);
  tok6 = strtok_r (0, " ", &p2str);
  tok7 = strtok_r (0, " ", &p2str);
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
  p2str = 0;
  tok1 = clib_strtok (str1, ",", &p2str);
  if ((tok1 == 0) || strcmp_s (tok1, strlen (tok1), str1, &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;
  /* verify it against strtok_r */
  strcpy_s (str1, sizeof (str1), "brevity is the soul of wit");
  p2str = 0;
  tok1 = strtok_r (str1, ",", &p2str);
  if ((tok1 == 0) || strcmp_s (tok1, strlen (tok1), str1, &indicator) != EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* negative stuff */
  s1 = 0;
  ptr = 0;
#if __GNUC__ < 8
  /* GCC 8 flunks this one at compile time... */
  tok = clib_strtok (s1, s1, (char **) 0);
  if (tok != 0)
    return -1;

  /* s1 and ptr contents are null */
  tok = clib_strtok (s1, s1, &ptr);
  if (tok != 0)
    return -1;
#endif

  /* verify it against strtok_r */
  /* No can do. This causes a crash in strtok_r */
  // tok = strtok_r (s1, " ", &ptr);
  // if (tok != 0)
  //  return -1;

  /*
   * Can't test unterminated string s1 and s2 becuase clib_strtok does not
   * supply s1 and s2 max
   */

  /* OK, seems to work */
  return 0;
}

static int
test_strnlen_s (vlib_main_t * vm, unformat_input_t * input)
{
  const char s1[] = "Truth is incontrovertible";
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
test_clib_strnlen (vlib_main_t * vm, unformat_input_t * input)
{
  const char s1[] = "Truth is incontrovertible";
  size_t len;

  vlib_cli_output (vm, "Test clib_strnlen...");

  len = clib_strnlen (s1, sizeof (s1));
  if (len != sizeof (s1) - 1)
    return -1;

  len = clib_strnlen (s1, 5);
  if (len != 5)
    return -1;

  /* negative stuff */
  len = clib_strnlen (0, 0);
  if (len != 0)
    return -1;

  /* OK, seems to work */
  return 0;
}

static int
test_strstr_s (vlib_main_t * vm, unformat_input_t * input)
{
  errno_t err;
  char *sub = 0;
  char s1[64];
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

  /* Null pointers test */
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

static int
test_clib_strstr (vlib_main_t * vm, unformat_input_t * input)
{
  char *sub, *s;
  char s1[64];
  size_t s1len = sizeof (s1) - 1;	// excluding null
  int indicator;

  vlib_cli_output (vm, "Test clib_strstr...");

  /* substring not present */
  strcpy_s (s1, s1len, "success is not final, failure is not fatal.");
  sub = clib_strstr (s1, "failures");
  if (sub != 0)
    return -1;
  /* verify it against strstr */
  sub = strstr (s1, "failures");
  if (sub != 0)
    return -1;

  /* substring present */
  sub = clib_strstr (s1, "failure");
  if (sub == 0)
    return -1;
  if (strcmp_s (sub, strlen (sub), "failure is not fatal.", &indicator) !=
      EOK)
    return -1;
  if (indicator != 0)
    return -1;
  /* verify it against strstr */
  sub = strstr (s1, "failure");
  if (sub == 0)
    return -1;
  if (strcmp_s (sub, strlen (sub), "failure is not fatal.", &indicator) !=
      EOK)
    return -1;
  if (indicator != 0)
    return -1;

  /* negative stuff */

  /* Null pointers test */
  s = 0;
  sub = clib_strstr (s, s);
  if (sub != 0)
    return -1;
  /*
   * Can't verify it against strstr for this test. Null pointers cause strstr
   * to crash. Go figure!
   */

  /* unterminated s1 and s2 */
  memset_s (s1, ARRAY_LEN (s1), 0xfe, ARRAY_LEN (s1));
  sub = clib_strstr (s1, s1);
  if (sub == 0)
    return -1;
  /*
   * Can't verify it against strstr for this test. Unterminated string causes
   * strstr to crash. Go figure!
   */

  /* OK, seems to work */
  return 0;
}

#define foreach_string_test                               \
  _ (0, MEMCPY_S, "memcpy_s", memcpy_s)                   \
  _ (1, CLIB_MEMCPY, "clib_memcpy", clib_memcpy)          \
  _ (2, MEMSET_S , "memset_s", memset_s)                  \
  _ (3, CLIB_MEMSET , "clib_memset", clib_memset)         \
  _ (4, MEMCMP_S, "memcmp_s", memcmp_s)			  \
  _ (5, CLIB_MEMCMP, "clib_memcmp", clib_memcmp)          \
  _ (6, STRCMP_S, "strcmp_s", strcmp_s)			  \
  _ (7, CLIB_STRCMP, "clib_strcmp", clib_strcmp)	  \
  _ (8, STRNCMP_S, "strncmp_s", strncmp_s)		  \
  _ (9, CLIB_STRNCMP, "clib_strncmp", clib_strncmp)	  \
  _ (10, STRCPY_S, "strcpy_s", strcpy_s)		  \
  _ (11, CLIB_STRCPY, "clib_strcpy", clib_strcpy)	  \
  _ (12, STRNCPY_S, "strncpy_s", strncpy_s)		  \
  _ (13, CLIB_STRNCPY, "clib_strncpy", clib_strncpy)	  \
  _ (14, STRCAT_S, "strcat_s", strcat_s)		  \
  _ (15, CLIB_STRCAT, "clib_strcat", clib_strcat)	  \
  _ (16, STRNCAT_S, "strncat_s", strncat_s)		  \
  _ (17, CLIB_STRNCAT, "clib_strncat", clib_strncat)	  \
  _ (18, STRTOK_S, "strtok_s", strtok_s)		  \
  _ (19, CLIB_STRTOK, "clib_strtok", clib_strtok)	  \
  _ (20, STRNLEN_S, "strnlen_s", strnlen_s)		  \
  _ (21, CLIB_STRNLEN, "clib_strnlen", clib_strnlen)	  \
  _ (22, STRSTR_S, "strstr_s", strstr_s)		  \
  _ (23, CLIB_STRSTR, "clib_strstr", clib_strstr)

typedef enum
{
#define _(v,f,s,p) STRING_TEST_##f = v,
  foreach_string_test
#undef _
} string_test_t;

static uword
unformat_string_test (unformat_input_t * input, va_list * args)
{
  u8 *r = va_arg (*args, u8 *);

  if (0)
    ;
#define _(v,f,s,p) else if (unformat (input, s)) *r = STRING_TEST_##f;
  foreach_string_test
#undef _
    else
    return 0;

  return 1;
}

typedef int (*string_test_func) (vlib_main_t * vm, unformat_input_t * input);

typedef struct
{
  string_test_func test;
} string_test_func_t;

static clib_error_t *
string_test_command_fn (vlib_main_t * vm,
			unformat_input_t * input,
			vlib_cli_command_t * cmd_arg)
{
  string_test_func_t string_func[] = {
#define _(v,f,s,p) { test_##p },
    foreach_string_test
#undef _
  };
  const char *string_table[] = {
#define _(v,f,s,p) s,
    foreach_string_test
#undef _
  };
  int res = 0, ok;
  i8 specific_test = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_string_test, &specific_test))
	break;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (specific_test == ~0)
    {
      for (specific_test = STRING_TEST_MEMCPY_S;
	   specific_test <= STRING_TEST_CLIB_STRSTR; specific_test++)
	{
	  ok = (string_func[specific_test]).test (vm, input);
	  res += ok;
	  if (ok != 0)
	    vlib_cli_output (vm, "test_%s failed",
			     string_table[specific_test]);
	}
    }
  else
    res = (string_func[specific_test]).test (vm, input);
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
  .short_help = "test string [memcpy_s | clib_memcpy | memset_s | "
  "clib_memset | memcmp_s | clib_memcmp | strcmp_s | clib_strcmp | "
  "strncmp_s | clib_strncmp | strcpy_s | clib_strcpy | strncpy_s | "
  "clib_strncpy | strcat_s | clib_strcat | strncat_s | clib_strncat | "
  "strtok_s |  clib_strtok | strnlen_s | clib_strnlen | strstr_s | "
  "clib_strstr]",
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
