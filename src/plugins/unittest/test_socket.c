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

#include <vlib/vlib.h>
#include <vppinfra/format.h>
#include <vppinfra/socket.h>

typedef struct test_clib_socket_example_msg_t_
{
  char b;
  int a;
} test_clib_socket_example_msg_t;

static clib_error_t *
test_clib_socket_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  clib_socket_t _srv = { 0 }, *srv = &_srv;
  clib_socket_t _cli = { 0 }, *cli = &_cli;
  clib_socket_t _srv2 = { 0 }, *srv2 = &_srv2;
  clib_error_t *err = 0;

  srv->flags = CLIB_SOCKET_F_IS_SERVER;
  cli->flags = CLIB_SOCKET_F_IS_CLIENT;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "config %s", &srv->config))
	cli->config = srv->config;
      else
	{
	  err = clib_error_create ("unknown input `%U'\n",
				   format_unformat_error, input);
	  goto done;
	}
    }

  if (!srv->config)
    {
      err = clib_error_create ("Missing socket name");
      goto done;
    }

  if ((err = clib_socket_init (srv)))
    goto done;

  if ((err = clib_socket_init (cli)))
    goto done;

  if ((err = clib_socket_accept (srv, srv2)))
    goto done;

  test_clib_socket_example_msg_t srv_msg;
  test_clib_socket_example_msg_t cli_msg;

  srv_msg.a = 54321;
  srv_msg.b = 'f';

  if ((err = clib_socket_sendmsg (srv2, &srv_msg, sizeof (srv_msg), 0, 0)))
    goto done;

  if ((err = clib_socket_recvmsg (cli, &cli_msg, sizeof (cli_msg), 0, 0)))
    goto done;

  if (cli_msg.a != 54321 || cli_msg.b != 'f')
    {
      err = clib_error_create ("socket message mismatch");
      goto done;
    }

  if ((err = clib_socket_close (srv2)))
    goto done;

  if ((err = clib_socket_close (cli)))
    goto done;

  if ((err = clib_socket_close (srv)))
    goto done;

  fprintf (stderr, "PASS test_socket %s", srv->config);
done:
  return err;
}
#ifdef CLIB_UNIX
#endif

VLIB_CLI_COMMAND (test_clib_socket_command, static) = {
  .path = "test clib socket",
  .short_help = "test clib socket",
  .function = test_clib_socket_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
