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

#include <vppinfra/format.h>
#include <vppinfra/time.h>
#include <vppinfra/math.h>	/* for sqrt */

static int verbose;
#define if_verbose(format,args...) \
  if (verbose) { clib_warning(format, ## args); }

static int
test_time_main (unformat_input_t * input)
{
  f64 wait, error;
  f64 t, tu[3], ave, rms;
  clib_time_t c;
  int i, n, j;

  clib_time_init (&c);
  wait = 1e-3;
  n = 1000;
  unformat (input, "%f %d", &wait, &n);
  ave = rms = 0;
  tu[0] = unix_time_now ();
  tu[1] = unix_time_now ();
  for (i = 0; i < n; i++)
    {
      j = 0;
      t = clib_time_now (&c);
      while (clib_time_now (&c) < t + wait)
	j++;
      t = j;
      ave += t;
      rms += t * t;
    }
  tu[2] = unix_time_now ();
  ave /= n;
  rms = sqrt (rms / n - ave * ave);

  error = ((tu[2] - tu[1]) - 2 * (tu[1] - tu[0]) - n * wait) / n;
  if_verbose ("tested %d x %.6e sec waits, error %.6e loops %.6e +- %.6e\n",
	      n, wait, error, ave, rms);

  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  verbose = (argc > 1);
  unformat_init_command_line (&i, argv);
  ret = test_time_main (&i);
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
