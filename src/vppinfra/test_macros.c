/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2014 Cisco and/or its affiliates.
 */

#include <vppinfra/macros.h>

clib_macro_main_t clib_macro_main;

__clib_export int
test_macros_main (unformat_input_t *input)
{
  clib_macro_main_t *mm = &clib_macro_main;

  clib_macro_init (mm);

  fformat (stdout, "hostname: %s\n",
	   clib_macro_eval_dollar (mm, (i8 *) "hostname", 1 /* complain */ ));

  clib_macro_set_value (mm, "foo", "this is foo which contains $(bar)");
  clib_macro_set_value (mm, "bar", "bar");

  fformat (stdout, "evaluate: %s\n",
	   clib_macro_eval (mm, (i8 *) "returns '$(foo)'", 1 /* complain */ ,
			    0 /* recursion_level */ ,
			    8 /* max recursion level */ ));

  clib_macro_free (mm);

  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  clib_mem_init (0, 64ULL << 20);

  unformat_init_command_line (&i, argv);
  ret = test_macros_main (&i);
  unformat_free (&i);

  return ret;
}
#endif /* CLIB_UNIX */
