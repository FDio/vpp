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

int
main (int argc, char *argv[])
{
  clib_error_t *err = 0;
  unformat_input_t i;
  unformat_input_t _in, *in = &_in;
  clib_json_text_t _j = {}, *j = &_j;
  clib_json_text_t _child = {}, *child = &_child;
  int input_fd = -1;
  u8 *filename = 0;

  clib_mem_init (0, 256 << 20);

  unformat_init_command_line (&i, argv);

  while (unformat_check_input (&i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (&i, "input %s", &filename))
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
	  fformat (stdout, "%U\n", format_clib_json, j);
	  clib_json_free (j);
	}
      else
	fformat (stderr, "%U\n", format_clib_error, err);
      goto done;
    }

  /* initialize new JSON context */
  clib_json_init (j);

  clib_json_add_object (j);

  /* add some simple values */
  clib_json_set_next_nvpair_name (j, "State");
  clib_json_add_true (j);
  clib_json_set_next_nvpair_name (j, "Foo");
  clib_json_add_false (j);
  clib_json_set_next_nvpair_name (j, "Bar");
  clib_json_add_string (j, "some text");

  /* add child object with some simple values */
  clib_json_set_next_nvpair_name (j, "Child");
  clib_json_add_object (j);
  clib_json_set_next_nvpair_name (j, "State");
  clib_json_add_true (j);
  clib_json_set_next_nvpair_name (j, "Desc");
  clib_json_add_string (j, "Some formatted string %.3f", 0.12);
  clib_json_parent (j);

  /* add child Array with some simple types */
  clib_json_set_next_nvpair_name (j, "Array");
  clib_json_add_array (j);

  for (int i = 0; i < 3; i++)
    clib_json_add_string (j, "elt %u", i);

  clib_json_add_array (j);

  for (int i = 0; i < 3; i++)
    clib_json_add_string (j, "elt %u", i);

  clib_json_init (child);
  clib_json_add_array (child);
  clib_json_add_string (child, "child string");
  clib_json_add_string (child, "child string2");
  clib_json_add_object (child);
  clib_json_set_next_nvpair_name (child, "True:");
  clib_json_add_true (child);
  clib_json_set_next_nvpair_name (child, "False:");
  clib_json_add_false (child);
  clib_json_append (j, child);
  clib_json_free (child);

  fformat (stdout, "JSON: %U\n", format_clib_json, j);

  clib_json_free (j);

  for (int i = 0; i < ARRAY_LEN (test_strings); i++)
    {
      unformat_init_cstring (in, test_strings[i]);
      clib_json_init (j);

      if (!unformat (in, "%U", unformat_clib_json_value, j))
	{
	  fformat (stderr, "ERROR cannot parse:\n%U\n", format_unformat_error,
		   in);
	  exit (1);
	}
      else
	fformat (stdout, "JSON: %U\n", format_clib_json, j);

      unformat_free (in);
      clib_json_free (j);
    }

done:
  unformat_free (&i);
  if (err)
    {
      clib_error_report (err);
      return 1;
    }
  return 0;
}
