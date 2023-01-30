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

#include <stdio.h>
#include <string.h>		/* strchr */
#define __USE_GNU
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#include <vppinfra/mem.h>
#include <vppinfra/vec.h>
#include <vppinfra/socket.h>
#include <vppinfra/linux/netns.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>

#ifndef __GLIBC__
/* IPPORT_USERRESERVED is not part of musl libc. */
#define IPPORT_USERRESERVED 5000
#endif

__clib_export void
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

      clib_memset (&a, 0, sizeof (a));	/* Warnings be gone */

      a.sin_family = PF_INET;
      a.sin_addr.s_addr = INADDR_ANY;
      a.sin_port = htons (port);

      if (bind (sock, (struct sockaddr *) &a, sizeof (a)) >= 0)
	break;
    }

  return port < 1 << 16 ? port : -1;
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
      err = clib_error_return_unix (0, "write %wd bytes (fd %d, '%s')",
				    tx_len, s->fd, s->config);
      vec_free (s->tx_buffer);
      goto done;
    }

  /* Reclaim the transmitted part of the tx buffer on successful writes. */
  else if (written > 0)
    {
      if (written == tx_len)
	vec_set_len (s->tx_buffer, 0);
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
  if (sock->rx_end_of_file)
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

      return clib_error_return_unix (0, "read %d bytes (fd %d, '%s')",
				     n_bytes, sock->fd, sock->config);
    }

  /* Other side closed the socket. */
  if (n_read == 0)
    sock->rx_end_of_file = 1;

non_fatal:
  vec_inc_len (sock->rx_buffer, n_read - n_bytes);

  return 0;
}

static clib_error_t *
default_socket_close (clib_socket_t * s)
{
  if (close (s->fd) < 0)
    return clib_error_return_unix (0, "close (fd %d, %s)", s->fd, s->config);
  return 0;
}

static clib_error_t *
default_socket_sendmsg (clib_socket_t * s, void *msg, int msglen,
			int fds[], int num_fds)
{
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  char ctl[CMSG_SPACE (sizeof (int) * num_fds)];
  int rv;

  iov[0].iov_base = msg;
  iov[0].iov_len = msglen;
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;

  if (num_fds > 0)
    {
      struct cmsghdr *cmsg;
      clib_memset (&ctl, 0, sizeof (ctl));
      mh.msg_control = ctl;
      mh.msg_controllen = sizeof (ctl);
      cmsg = CMSG_FIRSTHDR (&mh);
      cmsg->cmsg_len = CMSG_LEN (sizeof (int) * num_fds);
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;
      memcpy (CMSG_DATA (cmsg), fds, sizeof (int) * num_fds);
    }
  rv = sendmsg (s->fd, &mh, 0);
  if (rv < 0)
    return clib_error_return_unix (0, "sendmsg");
  return 0;
}


static clib_error_t *
default_socket_recvmsg (clib_socket_t * s, void *msg, int msglen,
			int fds[], int num_fds)
{
#ifdef CLIB_LINUX
  char ctl[CMSG_SPACE (sizeof (int) * num_fds) +
	   CMSG_SPACE (sizeof (struct ucred))];
  struct ucred *cr = 0;
#else
  char ctl[CMSG_SPACE (sizeof (int) * num_fds)];
#endif
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  ssize_t size;
  struct cmsghdr *cmsg;

  iov[0].iov_base = msg;
  iov[0].iov_len = msglen;
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;
  mh.msg_control = ctl;
  mh.msg_controllen = sizeof (ctl);

  clib_memset (ctl, 0, sizeof (ctl));

  /* receive the incoming message */
  size = recvmsg (s->fd, &mh, 0);
  if (size != msglen)
    {
      return (size == 0) ? clib_error_return (0, "disconnected") :
	clib_error_return_unix (0, "recvmsg: malformed message (fd %d, '%s')",
				s->fd, s->config);
    }

  cmsg = CMSG_FIRSTHDR (&mh);
  while (cmsg)
    {
      if (cmsg->cmsg_level == SOL_SOCKET)
	{
#ifdef CLIB_LINUX
	  if (cmsg->cmsg_type == SCM_CREDENTIALS)
	    {
	      cr = (struct ucred *) CMSG_DATA (cmsg);
	      s->uid = cr->uid;
	      s->gid = cr->gid;
	      s->pid = cr->pid;
	    }
	  else
#endif
	  if (cmsg->cmsg_type == SCM_RIGHTS)
	    {
	      clib_memcpy_fast (fds, CMSG_DATA (cmsg),
				num_fds * sizeof (int));
	    }
	}
      cmsg = CMSG_NXTHDR (&mh, cmsg);
    }
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
  if (!s->sendmsg_func)
    s->sendmsg_func = default_socket_sendmsg;
  if (!s->recvmsg_func)
    s->recvmsg_func = default_socket_recvmsg;
}

__clib_export clib_error_t *
clib_socket_init (clib_socket_t *s)
{
  struct sockaddr_un su = { .sun_family = PF_UNIX };
  struct sockaddr_in si = { .sin_family = PF_INET };
  struct sockaddr *sa = 0;
  socklen_t addr_len = 0;
  int socket_type, rv;
  clib_error_t *err = 0;
#if CLIB_LINUX
  int old_netns_fd = -1;
#endif

  if (!s->config)
    s->config = "";

#if CLIB_LINUX
  /* Linux abstract sockets */
  if (s->is_local && s->config[0] == '@')
    {
      u32 socket_name_off = 1;
      u32 socket_name_len = 0;
      u32 netns_name_len = 0;

      for (int i = 1; s->config[i] != 0; i++)
	{
	  if (netns_name_len == 0 && s->config[i] == '/')
	    {
	      netns_name_len = socket_name_len;
	      socket_name_len = 0;
	      socket_name_off = i + 1;
	    }
	  else
	    socket_name_len++;
	}

      if (netns_name_len)
	{
	  u8 *path, *name = 0;
	  int fd;

	  for (int i = 1; i <= netns_name_len; i++)
	    vec_add1 (name, s->config[i]);
	  old_netns_fd = open ("/proc/self/ns/net", O_RDONLY);
	  path = format (0, "/var/run/netns/%v%c", name, 0);
	  fd = open ((char *) s, O_RDONLY);
	  if (fd < 0)
	    err = clib_error_return_unix (0, "open('%s')", path);

	  vec_free (path);
	  vec_free (name);
	  if (err)
	    goto done;

	  if (setns (fd, CLONE_NEWNET) < 0)
	    {
	      err = clib_error_return_unix (0, "setns(%d)", fd);
	      goto done;
	    }
	}

      clib_memcpy (&su.sun_path[1], s->config + socket_name_off,
		   clib_min (sizeof (su.sun_path), 1 + socket_name_len));

      addr_len = sizeof (su.sun_family) + strlen (s->config + socket_name_off);
      sa = (struct sockaddr *) &su;
      s->allow_group_write = 0;
    }
#endif
  /* Anything that begins with a / is a local PF_LOCAL socket. */
  else if (s->is_local || s->config[0] == '/')
    {
      struct stat st = { 0 };
      char *path = (char *) &su.sun_path;

      clib_memcpy (path, s->config,
		   clib_min (sizeof (su.sun_path), 1 + strlen (s->config)));
      addr_len = sizeof (su);
      sa = (struct sockaddr *) &su;

      rv = stat (path, &st);
      if (!s->is_server && rv < 0)
	{
	  err = clib_error_return_unix (0, "stat ('%s')", path);
	  goto done;
	}

      if (s->is_server && rv == 0)
	{
	  if (S_ISSOCK (st.st_mode))
	    {
	      int client_fd = socket (AF_UNIX, SOCK_STREAM, 0);
	      int ret = connect (client_fd, (const struct sockaddr *) &su,
				 sizeof (su));
	      typeof (errno) connect_errno = errno;
	      close (client_fd);

	      if (ret == 0 || (ret < 0 && connect_errno != ECONNREFUSED))
		{
		  err = clib_error_return (0, "Active listener on '%s'", path);
		  goto done;
		}

	      if (unlink (path) < 0)
		{
		  err = clib_error_return_unix (0, "unlink ('%s')", path);
		  goto done;
		}
	    }
	  else
	    {
	      err = clib_error_return (0, "File '%s' already exists", path);
	      goto done;
	    }
	}
    }

  /* Hostname or hostname:port or port. */
  else if (s->is_local == 0)
    {
      char *host_name;
      int tmp = -1;

      host_name = 0;
      if (s->config[0] != 0)
	{
	  unformat_input_t i;

	  unformat_init_string (&i, s->config, (int) strlen (s->config));
	  if (unformat (&i, "%s:%d", &host_name, &tmp) ||
	      unformat (&i, "%s:0x%x", &host_name, &tmp))
	    ;
	  else if (unformat (&i, "%s", &host_name))
	    ;
	  else
	    err = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, &i);
	  unformat_free (&i);

	  if (err)
	    goto done;
	}

      addr_len = sizeof (si);
      si.sin_port = tmp != -1 ? htons (tmp) : 0;

      if (host_name)
	{
	  struct in_addr host_addr;

	  /* Recognize localhost to avoid host lookup in most common cast. */
	  if (!strcmp (host_name, "localhost"))
	    si.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

	  else if (inet_aton (host_name, &host_addr))
	    si.sin_addr = host_addr;

	  else if (host_name && strlen (host_name) > 0)
	    {
	      struct hostent *host = gethostbyname (host_name);
	      if (!host)
		err = clib_error_return (0, "unknown host `%s'", s->config);
	      else
		clib_memcpy (&si.sin_addr.s_addr, host->h_addr_list[0],
			     host->h_length);
	    }

	  else
	    si.sin_addr.s_addr =
	      htonl (s->is_server ? INADDR_LOOPBACK : INADDR_ANY);

	  vec_free (host_name);
	  if (err)
	    goto done;
	}
      sa = (struct sockaddr *) &si;
    }
  else
    {
      err = clib_error_return_unix (0, "unsupported socket config");
      goto done;
    }

  socket_init_funcs (s);

  socket_type = s->is_seqpacket ? SOCK_SEQPACKET : SOCK_STREAM;

  if (sa == 0)
    {
      err = clib_error_return_unix (0, "unknown socket family");
      goto done;
    }

  if ((s->fd = socket (sa->sa_family, socket_type, 0)) < 0)
    {
      err =
	clib_error_return_unix (0, "socket (fd %d, '%s')", s->fd, s->config);
      goto done;
    }

  if (s->is_server)
    {
      uword need_bind = 1;

      if (sa->sa_family == PF_INET && si.sin_port == 0)
	{
	  word port = find_free_port (s->fd);
	  if (port < 0)
	    {
	      err = clib_error_return (0, "no free port (fd %d, '%s')", s->fd,
				       s->config);
	      goto done;
	    }
	  si.sin_port = port;
	  need_bind = 0;
	}

      if (setsockopt (s->fd, SOL_SOCKET, SO_REUSEADDR, &((int){ 1 }),
		      sizeof (int)) < 0)
	clib_unix_warning ("setsockopt SO_REUSEADDR fails");

#if CLIB_LINUX
      if (s->is_local && s->passcred)
	{
	  if (setsockopt (s->fd, SOL_SOCKET, SO_PASSCRED, &((int){ 1 }),
			  sizeof (int)) < 0)
	    {
	      err = clib_error_return_unix (0,
					    "setsockopt (SO_PASSCRED, "
					    "fd %d, '%s')",
					    s->fd, s->config);
	      goto done;
	    }
	}
#endif

      if (need_bind && bind (s->fd, sa, addr_len) < 0)
	{
	  err =
	    clib_error_return_unix (0, "bind (fd %d, '%s')", s->fd, s->config);
	  goto done;
	}

      if (listen (s->fd, 5) < 0)
	{
	  err = clib_error_return_unix (0, "listen (fd %d, '%s')", s->fd,
					s->config);
	  goto done;
	}

      if (s->is_local && s->allow_group_write)
	{
	  if (fchmod (s->fd, S_IWGRP) < 0)
	    {
	      err = clib_error_return_unix (
		0, "fchmod (fd %d, '%s', mode S_IWGRP)", s->fd, s->config);
	      goto done;
	    }
	}
    }
  else
    {
      if (s->non_blocking_connect && fcntl (s->fd, F_SETFL, O_NONBLOCK) < 0)
	{
	  err = clib_error_return_unix (0, "fcntl NONBLOCK (fd %d, '%s')",
					s->fd, s->config);
	  goto done;
	}

      while ((rv = connect (s->fd, sa, addr_len)) < 0 && errno == EAGAIN)
	;
      if (rv < 0 && !(s->non_blocking_connect && errno == EINPROGRESS))
	{
	  err = clib_error_return_unix (0, "connect (fd %d, '%s')", s->fd,
					s->config);
	  goto done;
	}
      /* Connect was blocking so set fd to non-blocking now unless
       * blocking mode explicitly requested. */
      if (!s->non_blocking_connect && !s->is_blocking &&
	  fcntl (s->fd, F_SETFL, O_NONBLOCK) < 0)
	{
	  err = clib_error_return_unix (0, "fcntl NONBLOCK2 (fd %d, '%s')",
					s->fd, s->config);
	  goto done;
	}
    }

done:
  if (err && s->fd > 0)
    close (s->fd);
#if CLIB_LINUX
  if (old_netns_fd != -1)
    setns (CLONE_NEWNET, old_netns_fd);
#endif
  return err;
}

__clib_export clib_error_t *
clib_socket_init_netns (clib_socket_t *s, u8 *namespace)
{
  if (namespace == NULL || namespace[0] == 0)
    return clib_socket_init (s);

  clib_error_t *error;
  int old_netns_fd, nfd = -1;

  old_netns_fd = clib_netns_open (NULL /* self */);
  if (old_netns_fd < 0)
    return clib_error_return_unix (0, "get current netns failed");

  if ((nfd = clib_netns_open (namespace)) == -1)
    {
      error = clib_error_return_unix (0, "clib_netns_open '%s'", namespace);
      goto done;
    }

  if (clib_setns (nfd) == -1)
    {
      error = clib_error_return_unix (0, "setns '%s'", namespace);
      goto done;
    }

  error = clib_socket_init (s);

done:
  if (clib_setns (old_netns_fd) == -1)
    clib_warning ("Cannot set old ns");

  close (old_netns_fd);

  if (-1 != nfd)
    close (nfd);

  return error;
}

__clib_export clib_error_t *
clib_socket_accept (clib_socket_t * server, clib_socket_t * client)
{
  clib_error_t *err = 0;
  socklen_t len = 0;

  clib_memset (client, 0, sizeof (client[0]));

  /* Accept the new socket connection. */
  client->fd = accept (server->fd, 0, 0);
  if (client->fd < 0)
    return clib_error_return_unix (0, "accept (fd %d, '%s')",
				   server->fd, server->config);

  /* Set the new socket to be non-blocking. */
  if (fcntl (client->fd, F_SETFL, O_NONBLOCK) < 0)
    {
      err = clib_error_return_unix (0, "fcntl O_NONBLOCK (fd %d)",
				    client->fd);
      goto close_client;
    }

  /* Get peer info. */
  len = sizeof (client->peer);
  if (getpeername (client->fd, (struct sockaddr *) &client->peer, &len) < 0)
    {
      err = clib_error_return_unix (0, "getpeername (fd %d)", client->fd);
      goto close_client;
    }

  client->flags = CLIB_SOCKET_F_IS_CLIENT;

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
