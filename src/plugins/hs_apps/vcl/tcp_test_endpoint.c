/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/*
 * tcp_test_endpoint
 *
 *   ctl --control PATH ---- unix control socket ----> server
 *   ctl --control PATH ---- unix control socket ----> client
 *
 *   client ================= TCP data path =================> server
 *
 * Available APIs / modes:
 *   - server: plain Linux TCP listener and reader
 *   - client: VCL TCP connector and sender
 *   - ctl: CLI that talks to either server or client control socket
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vcl/vppcom.h>

#define TCP_TEST_ENDPOINT_BUFSZ		      4096
#define TCP_TEST_ENDPOINT_CTL_READ_TIMEOUT_MS 5000
typedef struct
{
  int listen_fd;
  int conn_fd;
  int ctl_fd;
  int paused;
  int running;
  int accepted;
  int peer_closed;
  uint64_t bytes_read;
  uint32_t rcvbuf;
  uint32_t window_clamp;
} tcp_test_endpoint_server_t;

typedef struct
{
  int conn_fd;
  int ctl_fd;
  int running;
  int connected;
  int app_created;
  uint64_t bytes_sent;
  const char *connect_ip;
  const char *port;
} tcp_test_endpoint_client_t;

static void
tcp_test_endpoint_usage (void)
{
  fprintf (stderr, "Usage:\n"
		   "  tcp_test_endpoint server --listen IP --port PORT --control PATH "
		   "[--rcvbuf BYTES] [--window-clamp BYTES] [--pause-read]\n"
		   "  tcp_test_endpoint client --control PATH [--connect IP --port PORT]\n"
		   "  tcp_test_endpoint ctl --control PATH COMMAND\n"
		   "Commands:\n"
		   "  server: stats | pause-read | resume-read | shutdown\n"
		   "  client: stats | connect [IP PORT] | send BYTES | close | shutdown\n");
}

static int
tcp_test_endpoint_set_nonblock (int fd)
{
  int flags = fcntl (fd, F_GETFL, 0);
  if (flags < 0)
    return -1;
  if (fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return -1;
  return 0;
}

static int
tcp_test_endpoint_make_listener (const char *listen_ip, const char *port)
{
  struct addrinfo hints, *res = 0, *ai;
  int fd = -1, one = 1;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if (getaddrinfo (listen_ip, port, &hints, &res))
    return -1;

  for (ai = res; ai; ai = ai->ai_next)
    {
      fd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
      if (fd < 0)
	continue;

      if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one)) < 0)
	goto fail;

      if (bind (fd, ai->ai_addr, ai->ai_addrlen) == 0 && listen (fd, 1) == 0)
	break;

    fail:
      close (fd);
      fd = -1;
    }

  freeaddrinfo (res);
  if (fd < 0)
    return -1;
  if (tcp_test_endpoint_set_nonblock (fd))
    {
      close (fd);
      return -1;
    }

  return fd;
}

static int
tcp_test_endpoint_make_ctl_listener (const char *path)
{
  struct sockaddr_un sun = {};
  int fd;

  unlink (path);
  fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  sun.sun_family = AF_UNIX;
  snprintf (sun.sun_path, sizeof (sun.sun_path), "%s", path);

  if (bind (fd, (struct sockaddr *) &sun, sizeof (sun)) < 0 || listen (fd, 4) < 0 ||
      tcp_test_endpoint_set_nonblock (fd))
    {
      close (fd);
      unlink (path);
      return -1;
    }

  return fd;
}

static int
tcp_test_endpoint_write_all (int fd, const void *buf, size_t len)
{
  const char *p = buf;

  while (len > 0)
    {
      ssize_t n = write (fd, p, len);
      if (n < 0)
	{
	  if (errno == EINTR)
	    continue;
	  return -1;
	}
      if (n == 0)
	return -1;
      p += n;
      len -= n;
    }

  return 0;
}

static int
tcp_test_endpoint_ctl_reply (int fd, const char *reply)
{
  return tcp_test_endpoint_write_all (fd, reply, strlen (reply));
}

static int
tcp_test_endpoint_accept_ctl (int ctl_fd, char *buf, size_t bufsz)
{
  struct pollfd pfd = {};
  ssize_t n;
  int fd, rv;

  fd = accept (ctl_fd, 0, 0);
  if (fd < 0)
    return -1;

  pfd.fd = fd;
  pfd.events = POLLIN;
  do
    {
      rv = poll (&pfd, 1, TCP_TEST_ENDPOINT_CTL_READ_TIMEOUT_MS);
    }
  while (rv < 0 && errno == EINTR);

  if (rv <= 0 || !(pfd.revents & POLLIN))
    {
      close (fd);
      return -1;
    }

  do
    {
      n = read (fd, buf, bufsz - 1);
    }
  while (n < 0 && errno == EINTR);
  if (n <= 0)
    {
      close (fd);
      return -1;
    }

  while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
    n--;
  buf[n] = 0;

  return fd;
}

static int
tcp_test_endpoint_handle_command (tcp_test_endpoint_server_t *srv, int fd, const char *cmd)
{
  char reply[256];

  if (!strcmp (cmd, "pause-read"))
    {
      srv->paused = 1;
      return tcp_test_endpoint_ctl_reply (fd, "ok\n");
    }
  if (!strcmp (cmd, "resume-read"))
    {
      srv->paused = 0;
      return tcp_test_endpoint_ctl_reply (fd, "ok\n");
    }
  if (!strcmp (cmd, "shutdown"))
    {
      srv->running = 0;
      return tcp_test_endpoint_ctl_reply (fd, "ok\n");
    }
  if (!strcmp (cmd, "stats"))
    {
      snprintf (reply, sizeof (reply), "accepted=%d paused=%d peer_closed=%d bytes_read=%llu\n",
		srv->accepted, srv->paused, srv->peer_closed, (unsigned long long) srv->bytes_read);
      return tcp_test_endpoint_ctl_reply (fd, reply);
    }

  return tcp_test_endpoint_ctl_reply (fd, "error=unknown-command\n");
}

static void
tcp_test_endpoint_handle_ctl (tcp_test_endpoint_server_t *srv)
{
  char buf[256];
  int fd;

  fd = tcp_test_endpoint_accept_ctl (srv->ctl_fd, buf, sizeof (buf));
  if (fd < 0)
    return;

  (void) tcp_test_endpoint_handle_command (srv, fd, buf);
  close (fd);
}

static int
tcp_test_endpoint_client_connect (tcp_test_endpoint_client_t *cl, const char *connect_ip,
				  const char *port)
{
  struct in_addr addr;
  vppcom_endpt_t endpt = {};
  int one = 1, rv, fd;
  uint32_t optlen = sizeof (one);
  unsigned long port_ul;

  if (cl->connected)
    return 0;

  if (!connect_ip || !port || !inet_aton (connect_ip, &addr))
    return -1;

  port_ul = strtoul (port, 0, 10);
  if (!port_ul || port_ul > 65535)
    return -1;

  fd = vppcom_session_create (VPPCOM_PROTO_TCP, 0 /* is_nonblocking */);
  if (fd < 0)
    return fd;

  (void) vppcom_session_attr (fd, VPPCOM_ATTR_SET_TCP_NODELAY, &one, &optlen);

  endpt.is_ip4 = 1;
  endpt.ip = (uint8_t *) &addr;
  endpt.port = htons ((uint16_t) port_ul);

  rv = vppcom_session_connect (fd, &endpt);
  if (rv < 0)
    {
      vppcom_session_close (fd);
      return rv;
    }

  cl->conn_fd = fd;
  cl->connected = 1;
  return 0;
}

static void
tcp_test_endpoint_client_disconnect (tcp_test_endpoint_client_t *cl)
{
  if (cl->conn_fd < 0)
    return;

  (void) vppcom_session_close (cl->conn_fd);
  cl->conn_fd = -1;
  cl->connected = 0;
}

static int
tcp_test_endpoint_client_send (tcp_test_endpoint_client_t *cl, uint64_t total_bytes)
{
  static uint8_t buf[TCP_TEST_ENDPOINT_BUFSZ];
  uint64_t bytes_left = total_bytes;

  if (cl->conn_fd < 0)
    return -1;

  while (bytes_left > 0)
    {
      size_t chunk = bytes_left > sizeof (buf) ? sizeof (buf) : (size_t) bytes_left;
      int rv = vppcom_session_write (cl->conn_fd, buf, chunk);

      if (rv == -EINTR || rv == VPPCOM_EAGAIN || rv == VPPCOM_EWOULDBLOCK)
	continue;

      if (rv <= 0)
	return rv ? rv : -1;

      cl->bytes_sent += rv;
      bytes_left -= rv;
    }

  return 0;
}

static int
tcp_test_endpoint_client_handle_command (tcp_test_endpoint_client_t *cl, int fd, char *cmd)
{
  char reply[256];
  char *saveptr = 0, *verb, *arg1, *arg2;

  verb = strtok_r (cmd, " ", &saveptr);
  if (!verb)
    return tcp_test_endpoint_ctl_reply (fd, "error=empty-command\n");

  if (!strcmp (verb, "shutdown"))
    {
      cl->running = 0;
      return tcp_test_endpoint_ctl_reply (fd, "ok\n");
    }
  if (!strcmp (verb, "stats"))
    {
      snprintf (reply, sizeof (reply), "connected=%d bytes_sent=%llu\n", cl->connected,
		(unsigned long long) cl->bytes_sent);
      return tcp_test_endpoint_ctl_reply (fd, reply);
    }
  if (!strcmp (verb, "connect"))
    {
      int rv;

      arg1 = strtok_r (0, " ", &saveptr);
      arg2 = strtok_r (0, " ", &saveptr);
      if (arg1 && !arg2)
	return tcp_test_endpoint_ctl_reply (fd, "error=missing-port\n");

      rv =
	tcp_test_endpoint_client_connect (cl, arg1 ? arg1 : cl->connect_ip, arg2 ? arg2 : cl->port);
      if (rv < 0)
	{
	  snprintf (reply, sizeof (reply), "error=connect-failed rv=%d\n", rv);
	  return tcp_test_endpoint_ctl_reply (fd, reply);
	}
      return tcp_test_endpoint_ctl_reply (fd, "ok\n");
    }
  if (!strcmp (verb, "send"))
    {
      unsigned long long bytes;
      int rv;

      arg1 = strtok_r (0, " ", &saveptr);
      if (!arg1)
	return tcp_test_endpoint_ctl_reply (fd, "error=missing-bytes\n");

      bytes = strtoull (arg1, 0, 10);
      rv = tcp_test_endpoint_client_send (cl, bytes);
      if (rv < 0)
	{
	  snprintf (reply, sizeof (reply), "error=send-failed rv=%d\n", rv);
	  return tcp_test_endpoint_ctl_reply (fd, reply);
	}
      return tcp_test_endpoint_ctl_reply (fd, "ok\n");
    }
  if (!strcmp (verb, "close"))
    {
      tcp_test_endpoint_client_disconnect (cl);
      return tcp_test_endpoint_ctl_reply (fd, "ok\n");
    }

  return tcp_test_endpoint_ctl_reply (fd, "error=unknown-command\n");
}

static void
tcp_test_endpoint_client_handle_ctl (tcp_test_endpoint_client_t *cl)
{
  char buf[256];
  int fd;

  fd = tcp_test_endpoint_accept_ctl (cl->ctl_fd, buf, sizeof (buf));
  if (fd < 0)
    return;

  (void) tcp_test_endpoint_client_handle_command (cl, fd, buf);
  close (fd);
}

static void
tcp_test_endpoint_server_set_sockopts (int fd, uint32_t rcvbuf, uint32_t window_clamp)
{
  int one = 1;

  if (rcvbuf)
    (void) setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof (rcvbuf));
  if (window_clamp)
    (void) setsockopt (fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &window_clamp, sizeof (window_clamp));
  (void) setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));
}

static void
tcp_test_endpoint_accept_conn (tcp_test_endpoint_server_t *srv)
{
  int fd;

  if (srv->conn_fd >= 0)
    return;

  fd = accept (srv->listen_fd, 0, 0);
  if (fd < 0)
    return;

  tcp_test_endpoint_server_set_sockopts (fd, srv->rcvbuf, srv->window_clamp);
  if (tcp_test_endpoint_set_nonblock (fd))
    {
      close (fd);
      return;
    }

  srv->conn_fd = fd;
  srv->accepted = 1;
}

static void
tcp_test_endpoint_drain_conn (tcp_test_endpoint_server_t *srv)
{
  char buf[TCP_TEST_ENDPOINT_BUFSZ];
  ssize_t n;

  if (srv->conn_fd < 0 || srv->paused)
    return;

  for (;;)
    {
      n = read (srv->conn_fd, buf, sizeof (buf));
      if (n > 0)
	{
	  srv->bytes_read += n;
	  continue;
	}
      if (n == 0)
	{
	  srv->peer_closed = 1;
	  close (srv->conn_fd);
	  srv->conn_fd = -1;
	  return;
	}
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
	return;
      srv->peer_closed = 1;
      close (srv->conn_fd);
      srv->conn_fd = -1;
      return;
    }
}

static int
tcp_test_endpoint_server_run (const char *listen_ip, const char *port, const char *control_path,
			      uint32_t rcvbuf, uint32_t window_clamp, int paused)
{
  struct pollfd pfds[3];
  tcp_test_endpoint_server_t srv = {
    .listen_fd = -1,
    .conn_fd = -1,
    .ctl_fd = -1,
    .paused = paused,
    .running = 1,
    .rcvbuf = rcvbuf,
    .window_clamp = window_clamp,
  };

  signal (SIGPIPE, SIG_IGN);

  srv.listen_fd = tcp_test_endpoint_make_listener (listen_ip, port);
  srv.ctl_fd = tcp_test_endpoint_make_ctl_listener (control_path);
  if (srv.listen_fd < 0 || srv.ctl_fd < 0)
    goto fail;

  tcp_test_endpoint_server_set_sockopts (srv.listen_fd, srv.rcvbuf, srv.window_clamp);

  fprintf (stderr, "tcp_test_endpoint: listening on %s:%s control=%s paused=%d\n", listen_ip, port,
	   control_path, paused);

  while (srv.running)
    {
      int nfds = 0;
      memset (pfds, 0, sizeof (pfds));

      pfds[nfds].fd = srv.ctl_fd;
      pfds[nfds++].events = POLLIN;

      if (srv.conn_fd < 0)
	{
	  pfds[nfds].fd = srv.listen_fd;
	  pfds[nfds++].events = POLLIN;
	}
      else if (!srv.paused)
	{
	  pfds[nfds].fd = srv.conn_fd;
	  pfds[nfds++].events = POLLIN;
	}

      if (poll (pfds, nfds, -1) < 0)
	{
	  if (errno == EINTR)
	    continue;
	  goto fail;
	}

      if (pfds[0].revents & POLLIN)
	tcp_test_endpoint_handle_ctl (&srv);

      if (srv.conn_fd < 0 && nfds > 1 && (pfds[1].revents & POLLIN))
	tcp_test_endpoint_accept_conn (&srv);
      else if (srv.conn_fd >= 0 && !srv.paused && nfds > 1 && (pfds[1].revents & POLLIN))
	tcp_test_endpoint_drain_conn (&srv);
    }

  if (srv.conn_fd >= 0)
    close (srv.conn_fd);
  close (srv.listen_fd);
  close (srv.ctl_fd);
  unlink (control_path);
  return 0;

fail:
  perror ("tcp_test_endpoint");
  if (srv.conn_fd >= 0)
    close (srv.conn_fd);
  if (srv.listen_fd >= 0)
    close (srv.listen_fd);
  if (srv.ctl_fd >= 0)
    close (srv.ctl_fd);
  unlink (control_path);
  return 1;
}

static int
tcp_test_endpoint_client_run (const char *connect_ip, const char *port, const char *control_path)
{
  struct pollfd pfd = {};
  tcp_test_endpoint_client_t cl = {
    .conn_fd = -1,
    .ctl_fd = -1,
    .running = 1,
    .connect_ip = connect_ip,
    .port = port,
  };
  int rv = 0;

  signal (SIGPIPE, SIG_IGN);

  cl.ctl_fd = tcp_test_endpoint_make_ctl_listener (control_path);
  if (cl.ctl_fd < 0)
    goto fail;

  rv = vppcom_app_create ("tcp_test_endpoint");
  if (rv)
    goto fail;
  cl.app_created = 1;

  if (connect_ip || port)
    {
      rv = tcp_test_endpoint_client_connect (&cl, connect_ip, port);
      if (rv < 0)
	goto fail;
    }

  fprintf (stderr, "tcp_test_endpoint: client control=%s target=%s:%s connected=%d\n", control_path,
	   connect_ip ? connect_ip : "-", port ? port : "-", cl.connected);

  while (cl.running)
    {
      pfd.fd = cl.ctl_fd;
      pfd.events = POLLIN;
      pfd.revents = 0;

      if (poll (&pfd, 1, -1) < 0)
	{
	  if (errno == EINTR)
	    continue;
	  goto fail;
	}

      if (pfd.revents & POLLIN)
	tcp_test_endpoint_client_handle_ctl (&cl);
    }

  tcp_test_endpoint_client_disconnect (&cl);
  if (cl.app_created)
    vppcom_app_destroy ();
  close (cl.ctl_fd);
  unlink (control_path);
  return 0;

fail:
  if (rv)
    fprintf (stderr, "tcp_test_endpoint client error: %d\n", rv);
  tcp_test_endpoint_client_disconnect (&cl);
  if (cl.app_created)
    vppcom_app_destroy ();
  if (cl.ctl_fd >= 0)
    close (cl.ctl_fd);
  if (control_path)
    unlink (control_path);
  return 1;
}

static int
tcp_test_endpoint_ctl_run (const char *control_path, const char *cmd)
{
  struct sockaddr_un sun = {};
  char buf[512], line[256];
  size_t len;
  ssize_t n;
  int fd;

  signal (SIGPIPE, SIG_IGN);

  fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return 1;

  sun.sun_family = AF_UNIX;
  snprintf (sun.sun_path, sizeof (sun.sun_path), "%s", control_path);
  if (connect (fd, (struct sockaddr *) &sun, sizeof (sun)) < 0)
    {
      close (fd);
      return 1;
    }

  len = strlen (cmd);
  if (len >= sizeof (line))
    {
      close (fd);
      return 1;
    }
  memcpy (line, cmd, len);
  line[len++] = '\n';

  if (tcp_test_endpoint_write_all (fd, line, len))
    {
      close (fd);
      return 1;
    }

  while ((n = read (fd, buf, sizeof (buf))) > 0)
    fwrite (buf, 1, n, stdout);

  close (fd);
  return 0;
}

int
main (int argc, char **argv)
{
  const char *listen_ip = "0.0.0.0";
  const char *connect_ip = 0, *port = 0, *control_path = 0;
  char cmd[256] = {};
  uint32_t rcvbuf = 0, window_clamp = 0;
  int paused = 0;
  int i;

  if (argc < 2)
    {
      tcp_test_endpoint_usage ();
      return 1;
    }

  if (!strcmp (argv[1], "server"))
    {
      for (i = 2; i < argc; i++)
	{
	  if (!strcmp (argv[i], "--listen") && i + 1 < argc)
	    listen_ip = argv[++i];
	  else if (!strcmp (argv[i], "--port") && i + 1 < argc)
	    port = argv[++i];
	  else if (!strcmp (argv[i], "--control") && i + 1 < argc)
	    control_path = argv[++i];
	  else if (!strcmp (argv[i], "--rcvbuf") && i + 1 < argc)
	    rcvbuf = (uint32_t) strtoul (argv[++i], 0, 10);
	  else if (!strcmp (argv[i], "--window-clamp") && i + 1 < argc)
	    window_clamp = (uint32_t) strtoul (argv[++i], 0, 10);
	  else if (!strcmp (argv[i], "--pause-read"))
	    paused = 1;
	  else
	    {
	      tcp_test_endpoint_usage ();
	      return 1;
	    }
	}

      if (!port || !control_path)
	{
	  tcp_test_endpoint_usage ();
	  return 1;
	}

      return tcp_test_endpoint_server_run (listen_ip, port, control_path, rcvbuf, window_clamp,
					   paused);
    }

  if (!strcmp (argv[1], "client"))
    {
      for (i = 2; i < argc; i++)
	{
	  if (!strcmp (argv[i], "--control") && i + 1 < argc)
	    control_path = argv[++i];
	  else if (!strcmp (argv[i], "--connect") && i + 1 < argc)
	    connect_ip = argv[++i];
	  else if (!strcmp (argv[i], "--port") && i + 1 < argc)
	    port = argv[++i];
	  else
	    {
	      tcp_test_endpoint_usage ();
	      return 1;
	    }
	}

      if (!control_path || ((connect_ip && !port) || (!connect_ip && port)))
	{
	  tcp_test_endpoint_usage ();
	  return 1;
	}

      return tcp_test_endpoint_client_run (connect_ip, port, control_path);
    }

  if (!strcmp (argv[1], "ctl"))
    {
      size_t off = 0;

      for (i = 2; i < argc; i++)
	{
	  if (!strcmp (argv[i], "--control") && i + 1 < argc)
	    control_path = argv[++i];
	  else
	    {
	      size_t arg_len = strlen (argv[i]);

	      if (off && off + 1 >= sizeof (cmd))
		{
		  fprintf (stderr, "tcp_test_endpoint: control command too long\n");
		  return 1;
		}
	      if (off)
		cmd[off++] = ' ';
	      if (arg_len >= sizeof (cmd) - off)
		{
		  fprintf (stderr, "tcp_test_endpoint: control command too long\n");
		  return 1;
		}
	      memcpy (cmd + off, argv[i], arg_len);
	      off += arg_len;
	      cmd[off] = 0;
	    }
	}

      if (!control_path || !cmd[0])
	{
	  tcp_test_endpoint_usage ();
	  return 1;
	}

      return tcp_test_endpoint_ctl_run (control_path, cmd);
    }

  tcp_test_endpoint_usage ();
  return 1;
}
