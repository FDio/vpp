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
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

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

#include <vppinfra/format.h>

static int verbose;
static u8 *test_vec;

static u8 *
format_test1 (u8 * s, va_list * va)
{
  uword x = va_arg (*va, uword);
  f64 y = va_arg (*va, f64);
  return format (s, "%12d %12f%12.4e", x, y, y);
}

static int
expectation (const char *exp, char *fmt, ...)
{
  int ret = 0;

  va_list va;
  va_start (va, fmt);
  test_vec = va_format (test_vec, fmt, &va);
  va_end (va);

  vec_add1 (test_vec, 0);
  if (strcmp (exp, (char *) test_vec))
    {
      fformat (stdout, "FAIL: %s (expected vs. result)\n\"%s\"\n\"%v\"\n",
	       fmt, exp, test_vec);
      ret = 1;
    }
  else if (verbose)
    fformat (stdout, "PASS: %s\n", fmt);
  vec_delete (test_vec, vec_len (test_vec), 0);
  return ret;
}

int
test_format_main (unformat_input_t * input)
{
  int ret = 0;
  u8 *food = format (0, "food");

  ret |= expectation ("foo", "foo");
  ret |= expectation ("foo", "%s", "foo");
  ret |= expectation ("9876", "%d", 9876);
  ret |= expectation ("-9876", "%wd", (word) - 9876);
  ret |= expectation ("98765432", "%u", 98765432);
  ret |= expectation ("1200ffee", "%x", 0x1200ffee);
  ret |= expectation ("BABEBABE", "%X", 0xbabebabe);
  ret |= expectation ("10%a", "%d%%%c", 10, 'a');
  ret |= expectation ("123456789abcdef0", "%016Lx", 0x123456789abcdef0LL);
  ret |= expectation ("00000123", "%08x", 0x123);
  ret |= expectation ("             23           23    2.3037e1",
		      "%40U", format_test1, 23, 23.0367);
  ret |= expectation ("left      ", "%-10s", "left");
  ret |= expectation ("  center  ", "%=10s", "center");
  ret |= expectation ("     right", "%+10s", "right");
  ret |= expectation ("123456", "%.0f", 123456.);
  ret |= expectation ("1234567.0", "%.1f", 1234567.);
  ret |= expectation ("foo", "%.*s", 3, "food");
  ret |= expectation ("food      ", "%.*s", 10, "food          ");
  ret |= expectation ("(nil)", "%.*s", 3, (void *) 0);
  ret |= expectation ("foo", "%.*v", 3, food);
  ret |= expectation ("foobar", "%.*v%s", 3, food, "bar");
  ret |= expectation ("foo bar", "%S", "foo_bar");
  vec_free (food);
  vec_free (test_vec);
  return ret;
}

typedef struct
{
  int a, b;
} foo_t;

static u8 *
format_foo (u8 * s, va_list * va)
{
  foo_t *foo = va_arg (*va, foo_t *);
  return format (s, "{a %d, b %d}", foo->a, foo->b);
}

static uword
unformat_foo (unformat_input_t * i, va_list * va)
{
  foo_t *foo = va_arg (*va, foo_t *);
  return unformat (i, "{%D,%D}",
		   sizeof (foo->a), &foo->a, sizeof (foo->b), &foo->b);
}

int
test_unformat_main (unformat_input_t * input)
{
  u32 v[8];
  long l;
  long long ll;
  f64 f;
  u8 *s;
  foo_t foo = {.a = ~0,.b = ~0 };

  v[0] = v[1] = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "01 %d %d", &v[0], &v[1]))
	fformat (stdout, "got 01 %d %d\n", v[0], v[1]);
      else if (unformat (input, "d %d", &v[0]))
	fformat (stdout, "got it d %d\n", v[0]);
      else if (unformat (input, "ld %ld", &l))
	fformat (stdout, "got it ld %ld\n", l);
      else if (unformat (input, "lld %lld", &ll))
	fformat (stdout, "got it lld %lld\n", ll);
      else if (unformat (input, "string %s", &s))
	fformat (stdout, "got string `%s'\n", s);
      else if (unformat (input, "float %f", &f))
	fformat (stdout, "got float `%.4f'\n", f);
      else if (unformat (input, "foo %U", unformat_foo, &foo))
	fformat (stdout, "got a foo `%U'\n", format_foo, &foo);
      else if (unformat (input, "ignore-me1"))
	fformat (stdout, "got an `ignore-me1'\n");
      else if (unformat (input, "ignore-me2"))
	fformat (stdout, "got an `ignore-me2'\n");
      else if (unformat (input, "gi%d_%d@-", &v[0], &v[1]))
	fformat (stdout, "got `gi%d_%d@-'\n", v[0], v[1]);
      else if (unformat (input, "%_%d.%d.%d.%d%_->%_%d.%d.%d.%d%_",
			 &v[0], &v[1], &v[2], &v[3],
			 &v[4], &v[5], &v[6], &v[7]))
	fformat (stdout, "got %d.%d.%d.%d -> %d.%d.%d.%d",
		 v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]);
      else
	{
	  clib_warning ("unknown input `%U'\n", format_unformat_error, input);
	  return 1;
	}
    }

  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;

  verbose = (argc > 1);
  unformat_init_command_line (&i, argv);

  if (unformat (&i, "unformat"))
    return test_unformat_main (&i);
  else
    return test_format_main (&i);
}
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
