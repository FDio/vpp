/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/json.h>

#include <fcntl.h>

static char *test_strings[] = { "null",
				" true",
				" false ",
				" \"some string\"",
				"[]",
				"[ true, false]",
				"{}",
				"{ \"State\": true }",
				"{ \"True\": true, \"Array\": [true, false, "
				"null ], \"String\": \"some string\" }" };

#define TEST_ASSERT(c)                                                        \
  if (!(c))                                                                   \
    return clib_error_return (0, "%s:%d: assertion failed: %s", __func__,     \
			      __LINE__, #c);

static clib_error_t *
test_json_checks (void)
{
  static char *invalid[] = { "",	  "[",	      "]",	   "{",
			     "{\"a\"}",  "{\"a\":}",  "[1,]",	   "[,1]",
			     "{\"a\":1,}", "01",	      "1.",	   "-",
			     "\"abc",	  "\"\\x\"",  "nul",	   "truefalse",
			     "[1] 2",	  "{} {}",    "\"\\ud800\"", "1e",
			     "\"a\nb\"" };
  clib_json_text_t j, to;
  char *str = "[-12.5e1, \"\\u00e9\"]";
  u8 *s;
  int idx;
  f64 num;

  /* every valid text must survive parse -> format -> parse -> format */
  static char *valid[] = {
    "-12.5e3",
    "[1, -2, 3.25, 1e-3, 0, 123456789012]",
    "{\"a\": {\"b\": [true, false, null, {}, []]}, \"c\": \"x\"}",
    "\"q\\\" b\\\\ \\n \\t \\u0001 \\u00e9 \\ud83d\\ude00\"",
    "{\"na%sme\": \"va%ulue\"}",
  };

  for (int n = 0; n < ARRAY_LEN (valid); n++)
    {
      clib_json_text_t k;
      u8 *s1, *s2;

      TEST_ASSERT (clib_json_init_from_string (&j, valid[n],
					       strlen (valid[n])) == 0);
      s1 = format (0, "%U", format_clib_json_text, &j);
      clib_json_free (&j);
      TEST_ASSERT (clib_json_init_from_string (&k, (char *) s1,
					       vec_len (s1)) == 0);
      s2 = format (0, "%U", format_clib_json_text, &k);
      clib_json_free (&k);
      TEST_ASSERT (vec_is_equal (s1, s2));
      vec_free (s1);
      vec_free (s2);
    }

  for (int n = 0; n < ARRAY_LEN (invalid); n++)
    {
      clib_error_t *e = clib_json_init_from_string (&j, invalid[n],
						    strlen (invalid[n]));
      TEST_ASSERT (e != 0);
      clib_error_free (e);
    }

  /* numbers and strings are parsed to the right values */
  TEST_ASSERT (clib_json_init_from_string (&j, str, strlen (str)) == 0);
  idx = clib_json_get_array_value_indices (&j, j.root_value)[0];
  num = pool_elt_at_index (j.values, idx)->number;
  TEST_ASSERT (num == -125.0);
  idx = clib_json_get_array_value_indices (&j, j.root_value)[1];
  s = pool_elt_at_index (j.values, idx)->string;
  TEST_ASSERT (vec_len (s) == 2 && s[0] == 0xc3 && s[1] == 0xa9);
  clib_json_free (&j);

  /* builder: names with format characters, number append, single root */
  clib_json_init (&j);
  TEST_ASSERT (clib_json_add_object (&j, 0) >= 0);
  TEST_ASSERT (clib_json_add_number (&j, "n%d", 42.0, 1) >= 0);
  TEST_ASSERT (clib_json_add_string (&j, "s", "a\"b") >= 0);
  TEST_ASSERT (clib_json_add_true (&j, 0) < 0); /* object member needs name */
  clib_json_parent (&j);
  TEST_ASSERT (clib_json_add_true (&j, 0) < 0); /* second root value */
  s = format (0, "%U", format_clib_json_text, &j);
  TEST_ASSERT (strstr ((char *) format (s, "%c", 0), "\"n1\": 42") != 0);
  TEST_ASSERT (strstr ((char *) s, "\"a\\\"b\"") != 0);
  vec_free (s);

  clib_json_init (&to);
  TEST_ASSERT (clib_json_add_array (&to, 0) >= 0);
  TEST_ASSERT (clib_json_append (&to, &j, 0) >= 0);
  idx = clib_json_find_object_value_by_name (
    &to, clib_json_get_array_value_indices (&to, to.root_value)[0], "n%d", 1);
  TEST_ASSERT (idx >= 0 && pool_elt_at_index (to.values, idx)->number == 42.0);
  clib_json_free (&to);
  clib_json_free (&j);

  return 0;
}

int
main (int argc, char *argv[])
{
  clib_error_t *err = 0;
  unformat_input_t i;
  clib_json_text_t _j = {}, *j = &_j;
  clib_json_text_t _child = {}, *child = &_child;
  int verbose = 0, input_fd = -1;
  u8 *filename = 0;

  clib_mem_init (0, 256 << 20);

  unformat_init_command_line (&i, argv);

  while (unformat_check_input (&i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (&i, "verbose"))
	verbose = 1;
      else if (unformat (&i, "input %s", &filename))
	{
	  if (strlen ((char *) filename) == 1 && filename[0] == '-')
	    input_fd = STDIN_FILENO;
	  else
	    {
	      input_fd = open ((char *) filename, 0);
	      if (input_fd < 0)
		{
		  err = clib_error_return_unix (0, "open '%v'");
		  goto done;
		}
	    }
	}
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, &i);
	  goto done;
	}
    }
  unformat_free (&i);

  if (input_fd > -1)
    {

      err = clib_json_init_from_file (j, input_fd);
      if (err == 0)
	{
	  fformat (stdout, "%U\n", format_clib_json_text, j);
	  clib_json_free (j);
	}
      else
	fformat (stderr, "%U\n", format_clib_error, err);
      goto done;
    }

  /* initialize new JSON context */
  clib_json_init (j);

  clib_json_add_object (j, 0);

  /* add some simple values */
  clib_json_add_true (j, "State");
  clib_json_add_false (j, "Foo");
  clib_json_add_string (j, "Bar", "some text");
  clib_json_add_number (j, "Number", 1.23);

  /* add child object with some simple values */
  clib_json_add_object (j, "Child");
  clib_json_add_true (j, "State");
  clib_json_add_string (j, "Desc", "Some formatted string %.3f", 0.12);
  clib_json_parent (j);

  /* add child Array with some simple types */
  clib_json_add_array (j, "Array");

  for (int i = 0; i < 3; i++)
    clib_json_add_string (j, 0, "elt %u", i);

  clib_json_add_array (j, 0);

  for (int i = 0; i < 3; i++)
    clib_json_add_string (j, 0, "elt %u", i);

  clib_json_init (child);
  clib_json_add_array (child, 0);
  clib_json_add_string (child, 0, "child string");
  clib_json_add_string (child, 0, "child string2");
  clib_json_add_object (child, 0);
  clib_json_add_true (child, "True:");
  clib_json_add_false (child, "False:");
  clib_json_append (j, child, 0);
  clib_json_free (child);

  fformat (stdout, "JSON: %U\n", format_clib_json_text, j);

  clib_json_free (j);

  for (int i = 0; i < ARRAY_LEN (test_strings); i++)
    {
      if (verbose)
	fformat (stdout,
		 "--------------------------------------------------\n"
		 "Input:\n%s\n",
		 test_strings[i]);
      if ((err = clib_json_init_from_string (j, test_strings[i],
					     strlen (test_strings[i]))))
	goto done;

      if (verbose)
	fformat (stdout, "Output:\n%U\n\n", format_clib_json_text, j);

      clib_json_free (j);
    }

  if ((err = test_json_checks ()))
    goto done;

done:
  unformat_free (&i);
  if (err)
    {
      fformat (stdout, "%U\n", format_clib_error, err);
      vec_free (err);
      return 1;
    }
  return 0;
}
