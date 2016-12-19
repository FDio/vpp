/*
  Copyright (c) 2014 Cisco and/or its affiliates.

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

#include <vppinfra/macros.h>

macro_main_t macro_main;

int
test_macros_main (unformat_input_t * input)
{
  macro_main_t *mm = &macro_main;

  clib_macro_init (mm);

  fformat (stdout, "hostname: %s\n",
	   clib_macro_eval_dollar (mm, "hostname", 1 /* complain */ ));

  clib_macro_set_value (mm, "foo", "this is foo which contains $(bar)");
  clib_macro_set_value (mm, "bar", "bar");

  fformat (stdout, "evaluate: %s\n",
	   clib_macro_eval (mm, "returns '$(foo)'", 1 /* complain */ ));

  clib_macro_free (mm);

  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  unformat_init_command_line (&i, argv);
  ret = test_macros_main (&i);
  unformat_free (&i);

  return ret;
}
#endif /* CLIB_UNIX */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
