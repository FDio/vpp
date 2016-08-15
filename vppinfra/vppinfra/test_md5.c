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
  Copyright (c) 2004 Eliot Dresselhaus

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

#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/md5.h>

#include <fcntl.h>
#include <unistd.h>

static clib_error_t *md5_test_suite (void);

int
main (int argc, char *argv[])
{
  int i;

  if (argc == 1)
    {
      clib_error_t *e;
      e = md5_test_suite ();
      if (e)
	{
	  clib_error_report (e);
	  exit (1);
	}
    }

  for (i = 1; i < argc; i++)
    {
      md5_context_t m;
      u8 digest[16];
      u8 buffer[64 * 1024];
      int fd, n;

      fd = open (argv[i], 0);
      if (fd < 0)
	clib_unix_error ("can't open %s", argv[i]);

      md5_init (&m);
      while ((n = read (fd, buffer, sizeof (buffer))) > 0)
	md5_add (&m, buffer, n);
      close (fd);
      md5_finish (&m, digest);
      fformat (stdout, "%U  %s\n",
	       format_hex_bytes, digest, sizeof (digest), argv[i]);
    }

  return 0;
}

static clib_error_t *
md5_test_suite (void)
{
  typedef struct
  {
    char *input;
    char *output;
  } md5_test_t;

  static md5_test_t tests[] = {
    {.input = "",
     .output = "d41d8cd98f00b204e9800998ecf8427e",},
    {.input = "a",
     .output = "0cc175b9c0f1b6a831c399e269772661",},
    {.input = "abc",
     .output = "900150983cd24fb0d6963f7d28e17f72",},
    {.input = "message digest",
     .output = "f96b697d7cb7938d525a2f31aaf161d0",},
    {.input = "abcdefghijklmnopqrstuvwxyz",
     .output = "c3fcd3d76192e4007dfb496cca67e13b",},
    {.input =
     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
     .output = "d174ab98d277d9f5a5611c2c9f419d9f",},
    {.input =
     "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
     .output = "57edf4a22be3c955ac49da2e2107b67a",},
  };

  int i;
  u8 *s;
  md5_context_t m;
  u8 digest[16];

  for (i = 0; i < ARRAY_LEN (tests); i++)
    {
      md5_init (&m);
      md5_add (&m, tests[i].input, strlen (tests[i].input));
      md5_finish (&m, digest);
      s = format (0, "%U", format_hex_bytes, digest, sizeof (digest));
      if (memcmp (s, tests[i].output, 2 * sizeof (digest)))
	return clib_error_return
	  (0, "%s -> %v expected %s", tests[i].input, s, tests[i].output);
      vec_free (s);
    }

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
