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
  Copyright (c) 2001, 2002, 2003, 2005 Eliot Dresselhaus

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

#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>		/* strchr */

#include <vppinfra/mem.h>
#include <vppinfra/vec.h>
#include <vppinfra/socket.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>

void
clib_socket_tx_add_formatted (clib_socket_t * s, char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  clib_socket_tx_add_va_formatted (s, fmt, &va);
  va_end (va);
}

/* Return and bind to an unused port. */
static word
find_free_port (word sock)
{
  word port;

  for (port = IPPORT_USERRESERVED; port < 1 << 16; port++)
    {
      struct sockaddr_in a;

      memset (&a, 0, sizeof (a));	/* Warnings be gone */

      a.sin_family = PF_INET;
      a.sin_addr.s_addr = INADDR_ANY;
      a.sin_port = htons (port);

      if (bind (sock, (struct sockaddr *) &a, sizeof (a)) >= 0)
	break;
    }

  return port < 1 << 16 ? port : -1;
}

/* Convert a config string to a struct sockaddr and length for use
   with bind or connect. */
static clib_error_t *
socket_config (char *config,
	       void *addr, socklen_t * addr_len, u32 ip4_default_address)
{
  clib_error_t *error = 0;

  if (!config)
    config = "";

  /* Anything that begins with a / is a local PF_LOCAL socket. */
  if (config[0] == '/')
    {
      struct sockaddr_un *su = addr;
      su->sun_family = PF_LOCAL;
      clib_memcpy (&su->sun_path, config,
		   clib_min (sizeof (su->sun_path), 1 + strlen (config)));
      *addr_len = sizeof (su[0]);
    }

  /* Hostname or hostname:port or port. */
  else
    {
      char *host_name;
      int port = -1;
      struct sockaddr_in *sa = addr;

      host_name = 0;
      port = -1;
      if (config[0] != 0)
	{
	  unformat_input_t i;

	  unformat_init_string (&i, config, strlen (config));
	  if (unformat (&i, "%s:%d", &host_name, &port)
	      || unformat (&i, "%s:0x%x", &host_name, &port))
	    ;
	  else if (unformat (&i, "%s", &host_name))
	    ;
	  else
	    error = clib_error_return (0, "unknown input `%U'",
				       format_unformat_error, &i);
	  unformat_free (&i);

	  if (error)
	    goto done;
	}

      sa->sin_family = PF_INET;
      *addr_len = sizeof (sa[0]);
      if (port != -1)
	sa->sin_port = htons (port);
      else
	sa->sin_port = 0;

      if (host_name)
	{
	  struct in_addr host_addr;

	  /* Recognize localhost to avoid host lookup in most common cast. */
	  if (!strcmp (host_name, "localhost"))
	    sa->sin_addr.s_addr = htonl (INADDR_LOOPBACK);

	  else if (inet_aton (host_name, &host_addr))
	    sa->sin_addr = host_addr;

	  else if (host_name && strlen (host_name) > 0)
	    {
	      struct hostent *host = gethostbyname (host_name);
	      if (!host)
		error = clib_error_return (0, "unknown host `%s'", config);
	      else
		clib_memcpy (&sa->sin_addr.s_addr, host->h_addr_list[0],
			     host->h_length);
	    }

	  else
	    sa->sin_addr.s_addr = htonl (ip4_default_address);

	  vec_free (host_name);
	  if (error)
	    goto done;
	}
    }

done:
  return error;
}

static clib_error_t *
default_socket_write (clib_socket_t * s)
{
  clib_error_t *err = 0;
  word written = 0;
  word fd = 0;
  word tx_len;

  fd = s->fd;

  /* Map standard input to standard output.
     Typically, fd is a socket for which read/write both work. */
  if (fd == 0)
    fd = 1;

  tx_len = vec_len (s->tx_buffer);
  written = write (fd, s->tx_buffer, tx_len);

  /* Ignore certain errors. */
  if (written < 0 && !unix_error_is_fatal (errno))
    written = 0;

  /* A "real" error occurred. */
  if (written < 0)
    {
      err = clib_error_return_unix (0, "write %wd bytes", tx_len);
      vec_free (s->tx_buffer);
      goto done;
    }

  /* Reclaim the transmitted part of the tx buffer on successful writes. */
  else if (written > 0)
    {
      if (written == tx_len)
	_vec_len (s->tx_buffer) = 0;
      else
	vec_delete (s->tx_buffer, written, 0);
    }

  /* If a non-fatal error occurred AND
     the buffer is full, then we must free it. */
  else if (written == 0 && tx_len > 64 * 1024)
    {
      vec_free (s->tx_buffer);
    }

done:
  return err;
}

static clib_error_t *
default_socket_read (clib_socket_t * sock, int n_bytes)
{
  word fd, n_read;
  u8 *buf;

  /* RX side of socket is down once end of file is reached. */
  if (sock->flags & SOCKET_RX_END_OF_FILE)
    return 0;

  fd = sock->fd;

  n_bytes = clib_max (n_bytes, 4096);
  vec_add2 (sock->rx_buffer, buf, n_bytes);

  if ((n_read = read (fd, buf, n_bytes)) < 0)
    {
      n_read = 0;

      /* Ignore certain errors. */
      if (!unix_error_is_fatal (errno))
	goto non_fatal;

      return clib_error_return_unix (0, "read %d bytes", n_bytes);
    }

  /* Other side closed the socket. */
  if (n_read == 0)
    sock->flags |= SOCKET_RX_END_OF_FILE;

non_fatal:
  _vec_len (sock->rx_buffer) += n_read - n_bytes;

  return 0;
}

static clib_error_t *
default_socket_close (clib_socket_t * s)
{
  if (close (s->fd) < 0)
    return clib_error_return_unix (0, "close");
  return 0;
}

static void
socket_init_funcs (clib_socket_t * s)
{
  if (!s->write_func)
    s->write_func = default_socket_write;
  if (!s->read_func)
    s->read_func = default_socket_read;
  if (!s->close_func)
    s->close_func = default_socket_close;
}

clib_error_t *
clib_socket_init (clib_socket_t * s)
{
  union
  {
    struct sockaddr sa;
    struct sockaddr_un su;
  } addr;
  socklen_t addr_len = 0;
  clib_error_t *error = 0;
  word port;

  error = socket_config (s->config, &addr.sa, &addr_len,
			 (s->flags & SOCKET_IS_SERVER
			  ? INADDR_LOOPBACK : INADDR_ANY));
  if (error)
    goto done;

  socket_init_funcs (s);

  s->fd = socket (addr.sa.sa_family, SOCK_STREAM, 0);
  if (s->fd < 0)
    {
      error = clib_error_return_unix (0, "socket");
      goto done;
    }

  port = 0;
  if (addr.sa.sa_family == PF_INET)
    port = ((struct sockaddr_in *) &addr)->sin_port;

  if (s->flags & SOCKET_IS_SERVER)
    {
      uword need_bind = 1;

      if (addr.sa.sa_family == PF_INET)
	{
	  if (port == 0)
	    {
	      port = find_free_port (s->fd);
	      if (port < 0)
		{
		  error = clib_error_return (0, "no free port");
		  goto done;
		}
	      need_bind = 0;
	    }
	}
      if (addr.sa.sa_family == PF_LOCAL)
	unlink (((struct sockaddr_un *) &addr)->sun_path);

      /* Make address available for multiple users. */
      {
	int v = 1;
	if (setsockopt (s->fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof (v)) < 0)
	  clib_unix_warning ("setsockopt SO_REUSEADDR fails");
      }

      if (need_bind && bind (s->fd, &addr.sa, addr_len) < 0)
	{
	  error = clib_error_return_unix (0, "bind");
	  goto done;
	}

      if (listen (s->fd, 5) < 0)
	{
	  error = clib_error_return_unix (0, "listen");
	  goto done;
	}
    }
  else
    {
      if ((s->flags & SOCKET_NON_BLOCKING_CONNECT)
	  && fcntl (s->fd, F_SETFL, O_NONBLOCK) < 0)
	{
	  error = clib_error_return_unix (0, "fcntl NONBLOCK");
	  goto done;
	}

      if (connect (s->fd, &addr.sa, addr_len) < 0
	  && !((s->flags & SOCKET_NON_BLOCKING_CONNECT) &&
	       errno == EINPROGRESS))
	{
	  error = clib_error_return_unix (0, "connect");
	  goto done;
	}
    }

  return error;

done:
  if (s->fd > 0)
    close (s->fd);
  return error;
}

clib_error_t *
clib_socket_accept (clib_socket_t * server, clib_socket_t * client)
{
  clib_error_t *err = 0;
  socklen_t len = 0;

  memset (client, 0, sizeof (client[0]));

  /* Accept the new socket connection. */
  client->fd = accept (server->fd, 0, 0);
  if (client->fd < 0)
    return clib_error_return_unix (0, "accept");

  /* Set the new socket to be non-blocking. */
  if (fcntl (client->fd, F_SETFL, O_NONBLOCK) < 0)
    {
      err = clib_error_return_unix (0, "fcntl O_NONBLOCK");
      goto close_client;
    }

  /* Get peer info. */
  len = sizeof (client->peer);
  if (getpeername (client->fd, (struct sockaddr *) &client->peer, &len) < 0)
    {
      err = clib_error_return_unix (0, "getpeername");
      goto close_client;
    }

  client->flags = SOCKET_IS_CLIENT;

  socket_init_funcs (client);
  return 0;

close_client:
  close (client->fd);
  return err;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
