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
#include <vppinfra/socket.h>

static int verbose;
#define if_verbose(format,args...) \
  if (verbose) { clib_warning(format, ## args); }

int
test_socket_main (unformat_input_t * input)
{
  clib_socket_t _s = { 0 }, *s = &_s;
  char *config;
  clib_error_t *error;

  s->config = "localhost:22";
  s->flags = CLIB_SOCKET_F_IS_CLIENT;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "server %s %=", &config,
		    &s->flags, CLIB_SOCKET_F_IS_SERVER))
	;
      else if (unformat (input, "client %s %=", &config,
			 &s->flags, CLIB_SOCKET_F_IS_CLIENT))
	;
      else
	{
	  error = clib_error_create ("unknown input `%U'\n",
				     format_unformat_error, input);
	  goto done;
	}
    }

  error = clib_socket_init (s);
  if (error)
    goto done;

  if (0)
    {
      struct
      {
	int a, b;
      } *msg;
      msg = clib_socket_tx_add (s, sizeof (msg[0]));
      msg->a = 99;
      msg->b = 100;
    }
  else
    clib_socket_tx_add_formatted (s, "hello there mr server %d\n", 99);

  error = clib_socket_tx (s);
  if (error)
    goto done;

  while (1)
    {
      error = clib_socket_rx (s, 100);
      if (error)
	break;

      if (clib_socket_rx_end_of_file (s))
	break;

      if_verbose ("%v", s->rx_buffer);
      _vec_len (s->rx_buffer) = 0;
    }

  error = clib_socket_close (s);

done:
  if (error)
    clib_error_report (error);
  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int r;

  verbose = (argc > 1);
  unformat_init_command_line (&i, argv);
  r = test_socket_main (&i);
  unformat_free (&i);
  return r;
}
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
