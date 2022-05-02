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
  clib_json_text_t _j = {}, *j = &_j;
  clib_json_text_t _child = {}, *child = &_child;
  int verbose, input_fd = -1;
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
	  fformat (stdout, "%U\n", format_clib_json, j);
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

  fformat (stdout, "JSON: %U\n", format_clib_json, j);

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
	fformat (stdout, "Output:\n%U\n\n", format_clib_json, j);

      clib_json_free (j);
    }

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
