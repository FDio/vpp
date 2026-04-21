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
#include <netinet/ip.h>
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

#define TCP_TEST_PEER_BUFSZ		  4096
#define TCP_TEST_ENDPOINT_MAX_SACK_BLOCKS 4

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
  const char *control_path;
  uint32_t rcvbuf;
  uint32_t window_clamp;
} tcp_test_endpoint_server_t;

typedef struct
{
  int conn_fd;
  int ctl_fd;
  int running;
  int connected;
  int peer_closed;
  int app_created;
  uint64_t bytes_read;
  uint64_t bytes_sent;
  const char *control_path;
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
		   "  server: stats | pause-read | resume-read | shutdown |\n"
		   "          inject-ack SEQ ACK WIN [SACK_LEFT SACK_RIGHT ...]\n"
		   "  client: stats | connect [IP PORT] | send BYTES | close | shutdown\n");
}

static uint16_t
tcp_test_endpoint_csum_reduce (uint32_t sum)
{
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  return (uint16_t) ~sum;
}

static uint16_t
tcp_test_endpoint_checksum (const void *data, size_t len)
{
  const uint8_t *p = data;
  uint32_t sum = 0;

  while (len > 1)
    {
      sum += ((uint16_t) p[0] << 8) | p[1];
      p += 2;
      len -= 2;
    }

  if (len)
    sum += (uint16_t) p[0] << 8;

  return tcp_test_endpoint_csum_reduce (sum);
}

static uint16_t
tcp_test_endpoint_tcp_checksum (const struct iphdr *ip, const uint8_t *tcp, size_t tcp_len)
{
  uint32_t sum = 0;
  const uint8_t *p = tcp;
  size_t len = tcp_len;

  sum += (ntohl (ip->saddr) >> 16) & 0xffff;
  sum += ntohl (ip->saddr) & 0xffff;
  sum += (ntohl (ip->daddr) >> 16) & 0xffff;
  sum += ntohl (ip->daddr) & 0xffff;
  sum += IPPROTO_TCP;
  sum += tcp_len;

  while (len > 1)
    {
      sum += ((uint16_t) p[0] << 8) | p[1];
      p += 2;
      len -= 2;
    }

  if (len)
    sum += (uint16_t) p[0] << 8;

  return tcp_test_endpoint_csum_reduce (sum);
}

static int
tcp_test_endpoint_server_inject_ack (tcp_test_endpoint_server_t *srv, uint32_t seq, uint32_t ack,
				     uint16_t window, const uint32_t *sacks, size_t sack_pairs)
{
  struct sockaddr_in local = {}, peer = {};
  socklen_t addrlen;
  struct sockaddr_in dst = {};
  uint8_t packet[sizeof (struct iphdr) + sizeof (struct tcphdr) +
		 TCP_TEST_ENDPOINT_MAX_SACK_BLOCKS * 8 + 8] = {};
  struct iphdr *ip = (struct iphdr *) packet;
  struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof (*ip));
  uint8_t *options = packet + sizeof (*ip) + sizeof (*tcp);
  size_t tcp_opt_len = 0, tcp_len;
  int fd = -1, one = 1, rv = -1;

  if (srv->conn_fd < 0)
    return -1;
  if (sack_pairs > TCP_TEST_ENDPOINT_MAX_SACK_BLOCKS)
    return -1;

  addrlen = sizeof (local);
  if (getsockname (srv->conn_fd, (struct sockaddr *) &local, &addrlen) < 0)
    return -1;
  addrlen = sizeof (peer);
  if (getpeername (srv->conn_fd, (struct sockaddr *) &peer, &addrlen) < 0)
    return -1;

  if (sack_pairs)
    {
      size_t sack_len = 2 + sack_pairs * 8;

      options[tcp_opt_len++] = TCPOPT_NOP;
      options[tcp_opt_len++] = TCPOPT_SACK;
      options[tcp_opt_len++] = (uint8_t) sack_len;

      for (size_t i = 0; i < sack_pairs; i++)
	{
	  uint32_t left = htonl (sacks[i * 2]);
	  uint32_t right = htonl (sacks[i * 2 + 1]);
	  memcpy (options + tcp_opt_len, &left, sizeof (left));
	  tcp_opt_len += sizeof (left);
	  memcpy (options + tcp_opt_len, &right, sizeof (right));
	  tcp_opt_len += sizeof (right);
	}

      while (tcp_opt_len % 4)
	options[tcp_opt_len++] = TCPOPT_NOP;
    }

  tcp_len = sizeof (*tcp) + tcp_opt_len;

  ip->ihl = sizeof (*ip) / 4;
  ip->version = 4;
  ip->tot_len = htons (sizeof (*ip) + tcp_len);
  ip->ttl = 64;
  ip->protocol = IPPROTO_TCP;
  ip->saddr = local.sin_addr.s_addr;
  ip->daddr = peer.sin_addr.s_addr;
  ip->check = tcp_test_endpoint_checksum (ip, sizeof (*ip));

  tcp->source = local.sin_port;
  tcp->dest = peer.sin_port;
  tcp->seq = htonl (seq);
  tcp->ack_seq = htonl (ack);
  tcp->doff = tcp_len / 4;
  tcp->ack = 1;
  tcp->window = htons (window);
  tcp->check = htons (tcp_test_endpoint_tcp_checksum (ip, (const uint8_t *) tcp, tcp_len));

  dst.sin_family = AF_INET;
  dst.sin_addr = peer.sin_addr;
  dst.sin_port = peer.sin_port;

  fd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (fd < 0)
    goto done;
  if (setsockopt (fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0)
    goto done;

  rv = sendto (fd, packet, sizeof (*ip) + tcp_len, 0, (struct sockaddr *) &dst, sizeof (dst));
  if (rv < 0)
    rv = -1;
  else
    rv = 0;

done:
  if (fd >= 0)
    close (fd);
  return rv;
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
tcp_test_endpoint_ctl_reply (int fd, const char *reply)
{
  size_t len = strlen (reply);

  while (len > 0)
    {
      ssize_t n = write (fd, reply, len);
      if (n < 0)
	{
	  if (errno == EINTR)
	    continue;
	  return -1;
	}
      reply += n;
      len -= n;
    }

  return 0;
}

static int
tcp_test_endpoint_handle_command (tcp_test_endpoint_server_t *srv, int fd, const char *cmd)
{
  char reply[256];
  char cmd_copy[256];
  char *saveptr = 0, *verb, *arg;

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

  snprintf (cmd_copy, sizeof (cmd_copy), "%s", cmd);
  verb = strtok_r (cmd_copy, " ", &saveptr);
  if (verb && !strcmp (verb, "inject-ack"))
    {
      uint32_t values[3 + TCP_TEST_ENDPOINT_MAX_SACK_BLOCKS * 2];
      size_t n_values = 0;
      char *end = 0;
      int rv;

      while ((arg = strtok_r (0, " ", &saveptr)))
	{
	  unsigned long v;

	  if (n_values >= sizeof (values) / sizeof (values[0]))
	    return tcp_test_endpoint_ctl_reply (fd, "error=too-many-args\n");

	  errno = 0;
	  v = strtoul (arg, &end, 10);
	  if (errno || !end || *end || v > UINT32_MAX)
	    return tcp_test_endpoint_ctl_reply (fd, "error=bad-arg\n");

	  values[n_values++] = (uint32_t) v;
	}

      if (n_values < 3)
	return tcp_test_endpoint_ctl_reply (fd, "error=missing-args\n");
      if ((n_values - 3) % 2)
	return tcp_test_endpoint_ctl_reply (fd, "error=bad-sack-args\n");

      rv = tcp_test_endpoint_server_inject_ack (srv, values[0], values[1], (uint16_t) values[2],
						values + 3, (n_values - 3) / 2);
      if (rv < 0)
	{
	  snprintf (reply, sizeof (reply), "error=inject-failed rv=%d\n", rv);
	  return tcp_test_endpoint_ctl_reply (fd, reply);
	}
      return tcp_test_endpoint_ctl_reply (fd, "ok\n");
    }

  return tcp_test_endpoint_ctl_reply (fd, "error=unknown-command\n");
}

static void
tcp_test_endpoint_handle_ctl (tcp_test_endpoint_server_t *srv)
{
  char buf[256];
  ssize_t n;
  int fd;

  fd = accept (srv->ctl_fd, 0, 0);
  if (fd < 0)
    return;

  n = read (fd, buf, sizeof (buf) - 1);
  if (n > 0)
    {
      while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
	n--;
      buf[n] = 0;
      (void) tcp_test_endpoint_handle_command (srv, fd, buf);
    }

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
  cl->peer_closed = 0;
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
  static uint8_t buf[TCP_TEST_PEER_BUFSZ];
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
	{
	  if (rv == 0 || rv == VPPCOM_ECONNRESET || rv == VPPCOM_ENOTCONN)
	    cl->peer_closed = 1;
	  return rv ? rv : -1;
	}

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
  ssize_t n;
  int fd;

  fd = accept (cl->ctl_fd, 0, 0);
  if (fd < 0)
    return;

  n = read (fd, buf, sizeof (buf) - 1);
  if (n > 0)
    {
      while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
	n--;
      buf[n] = 0;
      (void) tcp_test_endpoint_client_handle_command (cl, fd, buf);
    }

  close (fd);
}

static void
tcp_test_endpoint_accept_conn (tcp_test_endpoint_server_t *srv)
{
  int fd, one = 1;

  if (srv->conn_fd >= 0)
    return;

  fd = accept (srv->listen_fd, 0, 0);
  if (fd < 0)
    return;

  if (srv->rcvbuf)
    (void) setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &srv->rcvbuf, sizeof (srv->rcvbuf));
  if (srv->window_clamp)
    (void) setsockopt (fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &srv->window_clamp,
		       sizeof (srv->window_clamp));
  (void) setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));
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
  char buf[TCP_TEST_PEER_BUFSZ];
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
    .control_path = control_path,
    .rcvbuf = rcvbuf,
    .window_clamp = window_clamp,
  };
  int one = 1;

  signal (SIGPIPE, SIG_IGN);

  srv.listen_fd = tcp_test_endpoint_make_listener (listen_ip, port);
  srv.ctl_fd = tcp_test_endpoint_make_ctl_listener (control_path);
  if (srv.listen_fd < 0 || srv.ctl_fd < 0)
    goto fail;

  if (srv.rcvbuf)
    (void) setsockopt (srv.listen_fd, SOL_SOCKET, SO_RCVBUF, &srv.rcvbuf, sizeof (srv.rcvbuf));
  if (srv.window_clamp)
    (void) setsockopt (srv.listen_fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &srv.window_clamp,
		       sizeof (srv.window_clamp));
  (void) setsockopt (srv.listen_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));

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

      if (poll (pfds, nfds, 100) < 0)
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
    .control_path = control_path,
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

      if (poll (&pfd, 1, 100) < 0)
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
  char buf[512];
  ssize_t n;
  int fd;

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

  if (write (fd, cmd, strlen (cmd)) < 0 || write (fd, "\n", 1) < 0)
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
	      if (off)
		cmd[off++] = ' ';
	      off += snprintf (cmd + off, sizeof (cmd) - off, "%s", argv[i]);
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
