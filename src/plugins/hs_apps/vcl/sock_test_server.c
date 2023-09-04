/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <hs_apps/vcl/sock_test.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/un.h>

#define SOCK_SERVER_MAX_TEST_CONN  10
#define SOCK_SERVER_MAX_EPOLL_EVENTS 10

typedef struct
{
  uint8_t is_alloc;
  int fd;
  uint8_t *buf;
  uint32_t buf_size;
  hs_test_cfg_t cfg;
  vcl_test_stats_t stats;
} sock_server_conn_t;

typedef struct
{
  uint32_t port;
  uint32_t address_ip6;
  uint32_t transport_udp;
} sock_server_cfg_t;

typedef struct
{
  int listen_fd;
  sock_server_cfg_t cfg;
  int epfd;
  struct epoll_event listen_ev;
  struct epoll_event wait_events[SOCK_SERVER_MAX_EPOLL_EVENTS];
  int af_unix_listen_fd;
  int af_unix_fd;
  struct epoll_event af_unix_listen_ev;
  struct sockaddr_un serveraddr;
  uint32_t af_unix_xacts;
  size_t num_conn;
  size_t conn_pool_size;
  sock_server_conn_t *conn_pool;
  int nfds;
  fd_set rd_fdset;
  fd_set wr_fdset;
  struct timeval timeout;
} sock_server_main_t;

sock_server_main_t sock_server_main;

static inline void
conn_pool_expand (size_t expand_size)
{
  sock_server_main_t *ssm = &sock_server_main;
  sock_server_conn_t *conn_pool;
  size_t new_size = ssm->conn_pool_size + expand_size;
  int i;

  conn_pool = realloc (ssm->conn_pool, new_size * sizeof (*ssm->conn_pool));
  if (!conn_pool)
    stfail ("conn_pool_expand()");

  for (i = ssm->conn_pool_size; i < new_size; i++)
    {
      sock_server_conn_t *conn = &conn_pool[i];
      memset (conn, 0, sizeof (*conn));
      hs_test_cfg_init (&conn->cfg);
      vcl_test_buf_alloc (&conn->cfg, 1 /* is_rxbuf */ , &conn->buf,
			  &conn->buf_size);
      conn->cfg.txbuf_size = conn->cfg.rxbuf_size;
    }

  ssm->conn_pool = conn_pool;
  ssm->conn_pool_size = new_size;
}

static inline sock_server_conn_t *
conn_pool_alloc (void)
{
  sock_server_main_t *ssm = &sock_server_main;
  int i;

  for (i = 0; i < ssm->conn_pool_size; i++)
    {
      if (!ssm->conn_pool[i].is_alloc)
	{
	  ssm->conn_pool[i].is_alloc = 1;
	  return (&ssm->conn_pool[i]);
	}
    }

  return 0;
}

static inline void
conn_pool_free (sock_server_conn_t * conn)
{
  conn->fd = 0;
  conn->is_alloc = 0;
}

static inline void
sync_config_and_reply (sock_server_conn_t * conn, hs_test_cfg_t * rx_cfg)
{
  conn->cfg = *rx_cfg;
  vcl_test_buf_alloc (&conn->cfg, 1 /* is_rxbuf */ ,
		      &conn->buf, &conn->buf_size);
  conn->cfg.txbuf_size = conn->cfg.rxbuf_size;

  if (conn->cfg.verbose)
    {
      stinf ("(fd %d): Replying to cfg message!\n", conn->fd);
      hs_test_cfg_dump (&conn->cfg, 0 /* is_client */ );
    }
  (void) sock_test_write (conn->fd, (uint8_t *) & conn->cfg,
			  sizeof (conn->cfg), NULL, conn->cfg.verbose);
}

static void
stream_test_server_start_stop (sock_server_conn_t * conn,
			       hs_test_cfg_t * rx_cfg)
{
  sock_server_main_t *ssm = &sock_server_main;
  int client_fd = conn->fd;
  hs_test_t test = rx_cfg->test;

  if (rx_cfg->ctrl_handle == conn->fd)
    {
      int i;
      clock_gettime (CLOCK_REALTIME, &conn->stats.stop);

      for (i = 0; i < ssm->conn_pool_size; i++)
	{
	  sock_server_conn_t *tc = &ssm->conn_pool[i];

	  if (tc->cfg.ctrl_handle == conn->fd)
	    {
	      vcl_test_stats_accumulate (&conn->stats, &tc->stats);

	      if (conn->cfg.verbose)
		{
		  static char buf[64];

		  snprintf (buf, sizeof (buf), "SERVER (fd %d) RESULTS",
			    tc->fd);
		  vcl_test_stats_dump (buf, &tc->stats, 1 /* show_rx */ ,
				       test == HS_TEST_TYPE_BI
				       /* show tx */ ,
				       conn->cfg.verbose);
		}
	    }
	}

      vcl_test_stats_dump ("SERVER RESULTS", &conn->stats, 1 /* show_rx */ ,
			   (test == HS_TEST_TYPE_BI) /* show_tx */ ,
			   conn->cfg.verbose);
      hs_test_cfg_dump (&conn->cfg, 0 /* is_client */ );
      if (conn->cfg.verbose)
	{
	  stinf ("  sock server main\n"
		 HS_TEST_SEPARATOR_STRING
		 "       buf:  %p\n"
		 "  buf size:  %u (0x%08x)\n"
		 HS_TEST_SEPARATOR_STRING,
		 conn->buf, conn->buf_size, conn->buf_size);
	}

      sync_config_and_reply (conn, rx_cfg);
      stinf ("SERVER (fd %d): %s-directional Stream Test Complete!\n"
	     SOCK_TEST_BANNER_STRING "\n", conn->fd,
	     test == HS_TEST_TYPE_BI ? "Bi" : "Uni");
    }
  else
    {
      stinf (SOCK_TEST_BANNER_STRING
	     "SERVER (fd %d): %s-directional Stream Test!\n"
	     "  Sending client the test cfg to start streaming data...\n",
	     client_fd, test == HS_TEST_TYPE_BI ? "Bi" : "Uni");

      rx_cfg->ctrl_handle = (rx_cfg->ctrl_handle == ~0) ? conn->fd :
	rx_cfg->ctrl_handle;

      sync_config_and_reply (conn, rx_cfg);

      /* read the 1st chunk, record start time */
      memset (&conn->stats, 0, sizeof (conn->stats));
      clock_gettime (CLOCK_REALTIME, &conn->stats.start);
    }
}


static inline void
stream_test_server (sock_server_conn_t * conn, int rx_bytes)
{
  int client_fd = conn->fd;
  hs_test_t test = conn->cfg.test;

  if (test == HS_TEST_TYPE_BI)
    (void) sock_test_write (client_fd, conn->buf, rx_bytes, &conn->stats,
			    conn->cfg.verbose);

  if (conn->stats.rx_bytes >= conn->cfg.total_bytes)
    {
      clock_gettime (CLOCK_REALTIME, &conn->stats.stop);
    }
}

static inline void
af_unix_echo (void)
{
  sock_server_main_t *ssm = &sock_server_main;
  int af_unix_client_fd, rv;
  uint8_t buffer[256];
  size_t nbytes = strlen (SOCK_TEST_MIXED_EPOLL_DATA) + 1;

  af_unix_client_fd = accept (ssm->af_unix_listen_fd,
			      (struct sockaddr *) NULL, NULL);
  if (af_unix_client_fd < 0)
    stfail ("af_unix_echo accept()");

  stinf ("Got an AF_UNIX connection -- fd = %d (0x%08x)!",
	 af_unix_client_fd, af_unix_client_fd);

  memset (buffer, 0, sizeof (buffer));

  rv = read (af_unix_client_fd, buffer, nbytes);
  if (rv < 0)
    stfail ("af_unix_echo read()");

  /* Make the buffer is NULL-terminated. */
  buffer[sizeof (buffer) - 1] = 0;
  stinf ("(AF_UNIX): RX (%d bytes) - '%s'", rv, buffer);

  if (!strncmp (SOCK_TEST_MIXED_EPOLL_DATA, (const char *) buffer, nbytes))
    {
      rv = write (af_unix_client_fd, buffer, nbytes);
      if (rv < 0)
	stfail ("af_unix_echo write()");
      stinf ("(AF_UNIX): TX (%d bytes) - '%s'\n", rv, buffer);
      ssm->af_unix_xacts++;
    }
  close (af_unix_client_fd);
}

static inline void
new_client (void)
{
  sock_server_main_t *ssm = &sock_server_main;
  int client_fd;
  sock_server_conn_t *conn;

  if (ssm->conn_pool_size < (ssm->num_conn + SOCK_SERVER_MAX_TEST_CONN + 1))
    conn_pool_expand (SOCK_SERVER_MAX_TEST_CONN + 1);

  conn = conn_pool_alloc ();
  if (!conn)
    stfail ("No free connections!");

  client_fd = accept (ssm->listen_fd, (struct sockaddr *) NULL, NULL);
  if (client_fd < 0)
    stfail ("new_client accept()");

  stinf ("Got a connection -- fd = %d (0x%08x)!\n", client_fd, client_fd);
  if (fcntl (client_fd, F_SETFL, O_NONBLOCK) < 0)
    stfail ("fcntl()");

  conn->fd = client_fd;

  struct epoll_event ev;
  int rv;

  ev.events = EPOLLET | EPOLLIN;
  ev.data.u64 = conn - ssm->conn_pool;
  rv = epoll_ctl (ssm->epfd, EPOLL_CTL_ADD, client_fd, &ev);

  if (rv < 0)
    stfail ("new_client epoll_ctl()");

  ssm->nfds++;
}

static int
socket_server_echo_af_unix_init (sock_server_main_t * ssm)
{
  int rv;

  if (ssm->af_unix_listen_fd > 0)
    return 0;

  unlink ((const char *) SOCK_TEST_AF_UNIX_FILENAME);
  ssm->af_unix_listen_fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (ssm->af_unix_listen_fd < 0)
    stfail ("echo_af_unix_init socket()");

  memset (&ssm->serveraddr, 0, sizeof (ssm->serveraddr));
  ssm->serveraddr.sun_family = AF_UNIX;
  strncpy (ssm->serveraddr.sun_path, SOCK_TEST_AF_UNIX_FILENAME,
	   sizeof (ssm->serveraddr.sun_path));

  rv = bind (ssm->af_unix_listen_fd, (struct sockaddr *) &ssm->serveraddr,
	     SUN_LEN (&ssm->serveraddr));
  if (rv < 0)
    stfail ("echo_af_unix_init bind()");

  rv = listen (ssm->af_unix_listen_fd, 10);
  if (rv < 0)
    stfail ("echo_af_unix_init listen()");

  ssm->af_unix_listen_ev.events = EPOLLET | EPOLLIN;
  ssm->af_unix_listen_ev.data.u32 = SOCK_TEST_AF_UNIX_ACCEPT_DATA;
  rv = epoll_ctl (ssm->epfd, EPOLL_CTL_ADD, ssm->af_unix_listen_fd,
		  &ssm->af_unix_listen_ev);
  if (rv < 0)
    stfail ("echo_af_unix_init epoll_ctl()");

  return 0;
}

void
print_usage_and_exit (void)
{
  fprintf (stderr,
	   "sock_test_server [OPTIONS] <port>\n"
	   "  OPTIONS\n"
	   "  -h               Print this message and exit.\n"
	   "  -6               Use IPv6\n"
	   "  -u               Use UDP transport layer\n");
  exit (1);
}


static void
sts_server_echo (sock_server_conn_t * conn, int rx_bytes)
{
  int tx_bytes, nbytes, pos;

  /* If it looks vaguely like a string make sure it's terminated */
  pos = rx_bytes < conn->buf_size ? rx_bytes : conn->buf_size - 1;
  ((char *) conn->buf)[pos] = 0;

  if (conn->cfg.verbose)
    stinf ("(fd %d): Echoing back\n", conn->fd);

  nbytes = strlen ((const char *) conn->buf) + 1;

  tx_bytes = sock_test_write (conn->fd, conn->buf, nbytes, &conn->stats,
			      conn->cfg.verbose);
  if (tx_bytes >= 0)
    stinf ("(fd %d): TX (%d bytes) - '%s'\n", conn->fd, tx_bytes, conn->buf);
}

static int
sts_handle_cfg (hs_test_cfg_t * rx_cfg, sock_server_conn_t * conn,
		int rx_bytes)
{
  sock_server_main_t *ssm = &sock_server_main;

  if (rx_cfg->verbose)
    {
      stinf ("(fd %d): Received a cfg message!\n", conn->fd);
      hs_test_cfg_dump (rx_cfg, 0 /* is_client */ );
    }

  if (rx_bytes != sizeof (*rx_cfg))
    {
      stinf ("(fd %d): Invalid cfg message size (%d) expected %lu!", conn->fd,
	     rx_bytes, sizeof (*rx_cfg));
      conn->cfg.rxbuf_size = 0;
      conn->cfg.num_writes = 0;
      if (conn->cfg.verbose)
	{
	  stinf ("(fd %d): Replying to cfg message!\n", conn->fd);
	  hs_test_cfg_dump (rx_cfg, 0 /* is_client */ );
	}
      sock_test_write (conn->fd, (uint8_t *) & conn->cfg, sizeof (conn->cfg),
		       NULL, conn->cfg.verbose);
      return -1;
    }

  switch (rx_cfg->test)
    {
    case HS_TEST_TYPE_NONE:
      sync_config_and_reply (conn, rx_cfg);
      break;

    case HS_TEST_TYPE_ECHO:
      if (socket_server_echo_af_unix_init (ssm))
	goto done;

      sync_config_and_reply (conn, rx_cfg);
      break;

    case HS_TEST_TYPE_BI:
    case HS_TEST_TYPE_UNI:
      stream_test_server_start_stop (conn, rx_cfg);
      break;

    case HS_TEST_TYPE_EXIT:
      stinf ("Have a great day connection %d!", conn->fd);
      close (conn->fd);
      conn_pool_free (conn);
      stinf ("Closed client fd %d", conn->fd);
      ssm->nfds--;
      break;

    default:
      stinf ("ERROR: Unknown test type!\n");
      hs_test_cfg_dump (rx_cfg, 0 /* is_client */ );
      break;
    }

done:
  return 0;
}

static int
sts_conn_expect_config (sock_server_conn_t * conn)
{
  if (conn->cfg.test == HS_TEST_TYPE_ECHO)
    return 1;

  return (conn->stats.rx_bytes < 128
	  || conn->stats.rx_bytes > conn->cfg.total_bytes);
}

int
main (int argc, char **argv)
{
  int client_fd, rv, main_rv = 0, rx_bytes, c, v, i;
  sock_server_main_t *ssm = &sock_server_main;
  sock_server_conn_t *conn;
  hs_test_cfg_t *rx_cfg;
  struct sockaddr_storage servaddr;
  uint16_t port = VCL_TEST_SERVER_PORT;
  uint32_t servaddr_size;

  opterr = 0;
  while ((c = getopt (argc, argv, "6D")) != -1)
    switch (c)
      {
      case '6':
	ssm->cfg.address_ip6 = 1;
	break;

      case 'D':
	ssm->cfg.transport_udp = 1;
	break;

      case '?':
	switch (optopt)
	  {
	  default:
	    if (isprint (optopt))
	      stinf ("ERROR: Unknown option `-%c'", optopt);
	    else
	      stinf ("ERROR: Unknown option character `\\x%x'.\n", optopt);
	  }
	/* fall thru */
      case 'h':
      default:
	print_usage_and_exit ();
      }

  if (argc < (optind + 1))
    {
      stinf ("ERROR: Insufficient number of arguments!\n");
      print_usage_and_exit ();
    }

  if (sscanf (argv[optind], "%d", &v) == 1)
    port = (uint16_t) v;
  else
    {
      stinf ("ERROR: Invalid port (%s)!\n", argv[optind]);
      print_usage_and_exit ();
    }

  conn_pool_expand (SOCK_SERVER_MAX_TEST_CONN + 1);

  ssm->listen_fd = socket (ssm->cfg.address_ip6 ? AF_INET6 : AF_INET,
			   ssm->cfg.transport_udp ? SOCK_DGRAM : SOCK_STREAM,
			   0);

  if (ssm->listen_fd < 0)
    stfail ("main listen()");

  memset (&servaddr, 0, sizeof (servaddr));

  if (ssm->cfg.address_ip6)
    {
      struct sockaddr_in6 *server_addr = (struct sockaddr_in6 *) &servaddr;
      servaddr_size = sizeof (*server_addr);
      server_addr->sin6_family = AF_INET6;
      server_addr->sin6_addr = in6addr_any;
      server_addr->sin6_port = htons (port);
    }
  else
    {
      struct sockaddr_in *server_addr = (struct sockaddr_in *) &servaddr;
      servaddr_size = sizeof (*server_addr);
      server_addr->sin_family = AF_INET;
      server_addr->sin_addr.s_addr = htonl (INADDR_ANY);
      server_addr->sin_port = htons (port);
    }

  rv = bind (ssm->listen_fd, (struct sockaddr *) &servaddr, servaddr_size);
  if (rv < 0)
    stfail ("main bind()");

  rv = fcntl (ssm->listen_fd, F_SETFL, O_NONBLOCK);
  if (rv < 0)
    stfail ("main fcntl()");

  rv = listen (ssm->listen_fd, 10);
  if (rv < 0)
    stfail ("main listen()");

  ssm->epfd = epoll_create (1);
  if (ssm->epfd < 0)
    stfail ("main epoll_create()");

  ssm->listen_ev.events = EPOLLET | EPOLLIN;
  ssm->listen_ev.data.u32 = ~0;

  rv = epoll_ctl (ssm->epfd, EPOLL_CTL_ADD, ssm->listen_fd, &ssm->listen_ev);
  if (rv < 0)
    stfail ("main epoll_ctl()");

  stinf ("Waiting for a client to connect on port %d...\n", port);

  while (1)
    {
      int num_ev;
      num_ev = epoll_wait (ssm->epfd, ssm->wait_events,
			   SOCK_SERVER_MAX_EPOLL_EVENTS, 60000);
      if (num_ev < 0)
	stfail ("main epoll_wait()");

      if (num_ev == 0)
	{
	  stinf ("epoll_wait() timeout!\n");
	  continue;
	}
      for (i = 0; i < num_ev; i++)
	{
	  conn = &ssm->conn_pool[ssm->wait_events[i].data.u32];
	  if (ssm->wait_events[i].events & (EPOLLHUP | EPOLLRDHUP))
	    {
	      close (conn->fd);
	      continue;
	    }
	  if (ssm->wait_events[i].data.u32 == ~0)
	    {
	      new_client ();
	      continue;
	    }
	  else if (ssm->wait_events[i].data.u32 ==
		   SOCK_TEST_AF_UNIX_ACCEPT_DATA)
	    {
	      af_unix_echo ();
	      continue;
	    }
	  client_fd = conn->fd;

	  if (EPOLLIN & ssm->wait_events[i].events)
	    {
	    read_again:
	      rx_bytes = sock_test_read (client_fd, conn->buf,
					 conn->buf_size, &conn->stats);

	      if (rx_bytes <= 0)
		{
		  if (errno == ECONNRESET)
		    {
		      stinf ("Connection reset by peer\n");
		      main_rv = -1;
		      goto done;
		    }
		  else
		    continue;
		}

	      if (sts_conn_expect_config (conn))
		{
		  rx_cfg = (hs_test_cfg_t *) conn->buf;
		  if (rx_cfg->magic == HS_TEST_CFG_CTRL_MAGIC)
		    {
		      sts_handle_cfg (rx_cfg, conn, rx_bytes);
		      if (!ssm->nfds)
			{
			  stinf ("All client connections closed.\n\nSERVER: "
				 "May the force be with you!\n\n");
			  goto done;
			}
		      continue;
		    }
		}

	      if ((conn->cfg.test == HS_TEST_TYPE_UNI)
		  || (conn->cfg.test == HS_TEST_TYPE_BI))
		{
		  stream_test_server (conn, rx_bytes);
		  if (ioctl (conn->fd, FIONREAD))
		    goto read_again;
		  continue;
		}
	      else if (isascii (conn->buf[0]))
		{
		  sts_server_echo (conn, rx_bytes);
		}
	      else
		{
		  stwrn ("FIFO not drained! extra bytes %d", rx_bytes);
		}
	    }
	}
    }

done:
  close (ssm->listen_fd);
  close (ssm->af_unix_listen_fd);
  unlink ((const char *) SOCK_TEST_AF_UNIX_FILENAME);

  if (ssm->conn_pool)
    free (ssm->conn_pool);

  return main_rv;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
