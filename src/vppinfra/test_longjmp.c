/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
  Copyright (c) 2005 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <vppinfra/clib.h>
#include <vppinfra/longjmp.h>
#include <vppinfra/format.h>

static void test_calljmp (unformat_input_t * input);

static int i;

static int verbose;
#define if_verbose(format,args...) \
  if (verbose) { clib_warning(format, ## args); }

static never_inline void
f2 (clib_longjmp_t * env)
{
  i++;
  clib_longjmp (env, 1);
}

static never_inline void
f1 (clib_longjmp_t * env)
{
  i++;
  f2 (env);
}

int
test_longjmp_main (unformat_input_t * input)
{
  clib_longjmp_t env;

  i = 0;
  if (clib_setjmp (&env, 0) == 0)
    {
      if_verbose ("calling long jumper %d", i);
      f1 (&env);
    }
  if_verbose ("back from long jump %d", i);

  test_calljmp (input);

  return 0;
}

static uword
f3 (uword arg)
{
  return (uword) __builtin_frame_address (0);
}

static void
test_calljmp (unformat_input_t * input)
{
  u8 stack[4096] __attribute__ ((aligned (16))) = {};
  uword start, end, v;

  start = pointer_to_uword (stack);
  end = start + ARRAY_LEN (stack);

  v = f3 (0);
  if (!(v < start || v > end))
    clib_panic ("something went wrong in the calljmp test");

  v = clib_calljmp (f3, 0, stack + sizeof (stack));
  if_verbose ("calljump %s",
	      v >= start && v < (end - sizeof (uword)) ? "ok" : "fail");
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int res;

  clib_mem_init (0, 64 << 20);

  verbose = (argc > 1);
  unformat_init_command_line (&i, argv);
  res = test_longjmp_main (&i);
  unformat_free (&i);
  return res;
}
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
