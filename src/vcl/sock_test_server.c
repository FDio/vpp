/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vcl/sock_test.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SOCK_SERVER_USE_EPOLL 1
#define VPPCOM_SESSION_ATTR_UNIT_TEST 0

#if SOCK_SERVER_USE_EPOLL
#include <sys/epoll.h>
#endif

#ifdef VCL_TEST
#if VPPCOM_SESSION_ATTR_UNIT_TEST
#define BUFLEN  sizeof (uint64_t) * 16
uint64_t buffer[16];
uint32_t buflen = BUFLEN;
uint32_t *flags = (uint32_t *) buffer;
#endif
#endif

typedef struct
{
  uint8_t is_alloc;
  int fd;
  uint8_t *buf;
  uint32_t buf_size;
  sock_test_cfg_t cfg;
  sock_test_stats_t stats;
#ifdef VCL_TEST
  vppcom_endpt_t endpt;
  uint8_t ip[16];
#endif
} sock_server_conn_t;

#define SOCK_SERVER_MAX_TEST_CONN  10
#define SOCK_SERVER_MAX_EPOLL_EVENTS 10
typedef struct
{
  int listen_fd;
#if SOCK_SERVER_USE_EPOLL
  int epfd;
  struct epoll_event listen_ev;
  struct epoll_event wait_events[SOCK_SERVER_MAX_EPOLL_EVENTS];
#endif
  size_t num_conn;
  size_t conn_pool_size;
  sock_server_conn_t *conn_pool;
  int nfds;
  fd_set rd_fdset;
  fd_set wr_fdset;
  struct timeval timeout;
} sock_server_main_t;

sock_server_main_t sock_server_main;

#if ! SOCK_SERVER_USE_EPOLL
static inline int
get_nfds (void)
{
  sock_server_main_t *ssm = &sock_server_main;
  int i, nfds;

  for (nfds = i = 0; i < FD_SETSIZE; i++)
    {
      if (FD_ISSET (i, &ssm->rd_fdset) || FD_ISSET (i, &ssm->wr_fdset))
	nfds = i + 1;
    }
  return nfds;
}

static inline void
conn_fdset_set (sock_server_conn_t * conn, fd_set * fdset)
{
  sock_server_main_t *ssm = &sock_server_main;

  FD_SET (conn->fd, fdset);
  ssm->nfds = get_nfds ();
}

static inline void
conn_fdset_clr (sock_server_conn_t * conn, fd_set * fdset)
{
  sock_server_main_t *ssm = &sock_server_main;

  FD_CLR (conn->fd, fdset);
  ssm->nfds = get_nfds ();
}
#endif

static inline void
conn_pool_expand (size_t expand_size)
{
  sock_server_main_t *ssm = &sock_server_main;
  sock_server_conn_t *conn_pool;
  size_t new_size = ssm->conn_pool_size + expand_size;
  int i;

  conn_pool = realloc (ssm->conn_pool, new_size * sizeof (*ssm->conn_pool));
  if (conn_pool)
    {
      for (i = ssm->conn_pool_size; i < new_size; i++)
	{
	  sock_server_conn_t *conn = &conn_pool[i];
	  memset (conn, 0, sizeof (*conn));
	  sock_test_cfg_init (&conn->cfg);
	  sock_test_buf_alloc (&conn->cfg, 1 /* is_rxbuf */ ,
			       &conn->buf, &conn->buf_size);
	  conn->cfg.txbuf_size = conn->cfg.rxbuf_size;
	}

      ssm->conn_pool = conn_pool;
      ssm->conn_pool_size = new_size;
    }
  else
    {
      int errno_val = errno;
      perror ("ERROR in conn_pool_expand()");
      fprintf (stderr, "ERROR: Memory allocation failed (errno = %d)!\n",
	       errno_val);
    }
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
#ifdef VCL_TEST
	  ssm->conn_pool[i].endpt.ip = ssm->conn_pool[i].ip;
#endif
	  ssm->conn_pool[i].is_alloc = 1;
	  return (&ssm->conn_pool[i]);
	}
    }

  return 0;
}

static inline void
conn_pool_free (sock_server_conn_t * conn)
{
#if ! SOCK_SERVER_USE_EPOLL
  sock_server_main_t *ssm = &sock_server_main;

  conn_fdset_clr (conn, &ssm->rd_fdset);
  conn_fdset_clr (conn, &ssm->wr_fdset);
#endif
  conn->fd = 0;
  conn->is_alloc = 0;
}

static inline void
sync_config_and_reply (sock_server_conn_t * conn, sock_test_cfg_t * rx_cfg)
{
  conn->cfg = *rx_cfg;
  sock_test_buf_alloc (&conn->cfg, 1 /* is_rxbuf */ ,
		       &conn->buf, &conn->buf_size);
  conn->cfg.txbuf_size = conn->cfg.rxbuf_size;

  if (conn->cfg.verbose)
    {
      printf ("\nSERVER (fd %d): Replying to cfg message!\n", conn->fd);
      sock_test_cfg_dump (&conn->cfg, 0 /* is_client */ );
    }
  (void) sock_test_write (conn->fd, (uint8_t *) & conn->cfg,
			  sizeof (conn->cfg), NULL, conn->cfg.verbose);
}

static void
stream_test_server_start_stop (sock_server_conn_t * conn,
			       sock_test_cfg_t * rx_cfg)
{
  sock_server_main_t *ssm = &sock_server_main;
  int client_fd = conn->fd;
  sock_test_t test = rx_cfg->test;

  if (rx_cfg->ctrl_handle == conn->fd)
    {
      int i;
      clock_gettime (CLOCK_REALTIME, &conn->stats.stop);

      for (i = 0; i < ssm->conn_pool_size; i++)
	{
	  sock_server_conn_t *tc = &ssm->conn_pool[i];

	  if (tc->cfg.ctrl_handle == conn->fd)
	    {
	      sock_test_stats_accumulate (&conn->stats, &tc->stats);

	      if (conn->cfg.verbose)
		{
		  static char buf[64];

		  sprintf (buf, "SERVER (fd %d) RESULTS", tc->fd);
		  sock_test_stats_dump (buf, &tc->stats, 1 /* show_rx */ ,
					test == SOCK_TEST_TYPE_BI
					/* show tx */ ,
					conn->cfg.verbose);
		}
	    }
	}

      sock_test_stats_dump ("SERVER RESULTS", &conn->stats, 1 /* show_rx */ ,
			    (test == SOCK_TEST_TYPE_BI) /* show_tx */ ,
			    conn->cfg.verbose);
      sock_test_cfg_dump (&conn->cfg, 0 /* is_client */ );
      if (conn->cfg.verbose)
	{
	  printf ("  sock server main\n"
		  SOCK_TEST_SEPARATOR_STRING
		  "       buf:  %p\n"
		  "  buf size:  %u (0x%08x)\n"
		  SOCK_TEST_SEPARATOR_STRING,
		  conn->buf, conn->buf_size, conn->buf_size);
	}

      sync_config_and_reply (conn, rx_cfg);
      printf ("\nSERVER (fd %d): %s-directional Stream Test Complete!\n"
	      SOCK_TEST_BANNER_STRING "\n", conn->fd,
	      test == SOCK_TEST_TYPE_BI ? "Bi" : "Uni");
    }
  else
    {
      printf ("\n" SOCK_TEST_BANNER_STRING
	      "SERVER (fd %d): %s-directional Stream Test!\n"
	      "  Sending client the test cfg to start streaming data...\n",
	      client_fd, test == SOCK_TEST_TYPE_BI ? "Bi" : "Uni");

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
  sock_test_t test = conn->cfg.test;

  if (test == SOCK_TEST_TYPE_BI)
    (void) sock_test_write (client_fd, conn->buf, rx_bytes, &conn->stats,
			    conn->cfg.verbose);

  if (conn->stats.rx_bytes >= conn->cfg.total_bytes)
    {
      clock_gettime (CLOCK_REALTIME, &conn->stats.stop);
    }
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
    {
      fprintf (stderr, "\nERROR: No free connections!\n");
      return;
    }

#ifdef VCL_TEST
  client_fd = vppcom_session_accept (ssm->listen_fd, &conn->endpt, 0,
				     -1.0 /* wait forever */ );
  if (client_fd < 0)
    errno = -client_fd;
#elif HAVE_ACCEPT4
  client_fd = accept4 (ssm->listen_fd, (struct sockaddr *) NULL, NULL, NULL);
#else
  client_fd = accept (ssm->listen_fd, (struct sockaddr *) NULL, NULL);
#endif
  if (client_fd < 0)
    {
      int errno_val;
      errno_val = errno;
      perror ("ERROR in new_client()");
      fprintf (stderr, "ERROR: accept failed (errno = %d)!\n", errno_val);
    }

  printf ("SERVER: Got a connection -- fd = %d (0x%08x)!\n",
	  client_fd, client_fd);

  conn->fd = client_fd;

#if ! SOCK_SERVER_USE_EPOLL
  conn_fdset_set (conn, &ssm->rd_fdset);
  ssm->nfds++;
#else
  {
    struct epoll_event ev;
    int rv;

    ev.events = EPOLLIN;
    ev.data.u64 = conn - ssm->conn_pool;
#ifdef VCL_TEST
    rv = vppcom_epoll_ctl (ssm->epfd, EPOLL_CTL_ADD, client_fd, &ev);
    if (rv)
      errno = -rv;
#else
    rv = epoll_ctl (ssm->epfd, EPOLL_CTL_ADD, client_fd, &ev);
#endif
    if (rv < 0)
      {
	int errno_val;
	errno_val = errno;
	perror ("ERROR in new_client()");
	fprintf (stderr, "ERROR: epoll_ctl failed (errno = %d)!\n",
		 errno_val);
      }
    else
      ssm->nfds++;
  }
#endif
}

int
main (int argc, char **argv)
{
  sock_server_main_t *ssm = &sock_server_main;
  int client_fd, rv, main_rv = 0;
  int tx_bytes, rx_bytes, nbytes;
  sock_server_conn_t *conn;
  sock_test_cfg_t *rx_cfg;
  uint32_t xtra = 0;
  uint64_t xtra_bytes = 0;
  struct sockaddr_in servaddr;
  int errno_val;
  int v, i;
  uint16_t port = SOCK_TEST_SERVER_PORT;
#if ! SOCK_SERVER_USE_EPOLL
  fd_set _rfdset, *rfdset = &_rfdset;
#endif
#ifdef VCL_TEST
  vppcom_endpt_t endpt;
#else
#if ! SOCK_SERVER_USE_EPOLL
  fd_set _wfdset, *wfdset = &_wfdset;
#endif
#endif

  if ((argc == 2) && (sscanf (argv[1], "%d", &v) == 1))
    port = (uint16_t) v;

  conn_pool_expand (SOCK_SERVER_MAX_TEST_CONN + 1);

#ifdef VCL_TEST
  rv = vppcom_app_create ("vcl_test_server");
  if (rv)
    {
      errno = -rv;
      ssm->listen_fd = -1;
    }
  else
    {
      ssm->listen_fd =
	vppcom_session_create (VPPCOM_VRF_DEFAULT, VPPCOM_PROTO_TCP,
			       0 /* is_nonblocking */ );
    }
#else
  ssm->listen_fd = socket (AF_INET, SOCK_STREAM, 0);
#endif
  if (ssm->listen_fd < 0)
    {
      errno_val = errno;
      perror ("ERROR in main()");
      fprintf (stderr, "ERROR: socket() failed (errno = %d)!\n", errno_val);
      return ssm->listen_fd;
    }

  memset (&servaddr, 0, sizeof (servaddr));

  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl (INADDR_ANY);
  servaddr.sin_port = htons (port);

#ifdef VCL_TEST
  endpt.vrf = VPPCOM_VRF_DEFAULT;
  endpt.is_ip4 = (servaddr.sin_family == AF_INET);
  endpt.ip = (uint8_t *) & servaddr.sin_addr;
  endpt.port = (uint16_t) servaddr.sin_port;

  rv = vppcom_session_bind (ssm->listen_fd, &endpt);
  if (rv)
    {
      errno = -rv;
      rv = -1;
    }

#if VPPCOM_SESSION_ATTR_UNIT_TEST
  buflen = BUFLEN;
  if (vppcom_session_attr (ssm->listen_fd, VPPCOM_ATTR_GET_FLAGS,
			   buffer, &buflen) != VPPCOM_OK)
    printf ("\nGET_FLAGS0: Oh no, Mr. Biiiiiiiiiiiilllllll ! ! ! !\n");
  buflen = BUFLEN;
  *flags = O_RDWR | O_NONBLOCK;
  if (vppcom_session_attr (ssm->listen_fd, VPPCOM_ATTR_SET_FLAGS,
			   buffer, &buflen) != VPPCOM_OK)
    printf ("\nSET_FLAGS1: Oh no, Mr. Biiiiiiiiiiiilllllll ! ! ! !\n");
  buflen = BUFLEN;
  if (vppcom_session_attr (ssm->listen_fd, VPPCOM_ATTR_GET_FLAGS,
			   buffer, &buflen) != VPPCOM_OK)
    printf ("\nGET_FLAGS1:Oh no, Mr. Biiiiiiiiiiiilllllll ! ! ! !\n");
  *flags = O_RDWR;
  buflen = BUFLEN;
  if (vppcom_session_attr (ssm->listen_fd, VPPCOM_ATTR_SET_FLAGS,
			   buffer, &buflen) != VPPCOM_OK)
    printf ("\nSET_FLAGS2: Oh no, Mr. Biiiiiiiiiiiilllllll ! ! ! !\n");
  buflen = BUFLEN;
  if (vppcom_session_attr (ssm->listen_fd, VPPCOM_ATTR_GET_FLAGS,
			   buffer, &buflen) != VPPCOM_OK)
    printf ("\nGET_FLAGS2:Oh no, Mr. Biiiiiiiiiiiilllllll ! ! ! !\n");

  buflen = BUFLEN;
  if (vppcom_session_attr (ssm->listen_fd, VPPCOM_ATTR_GET_PEER_ADDR,
			   buffer, &buflen) != VPPCOM_OK)
    printf ("\nGET_PEER_ADDR: Oh no, Mr. Biiiiiiiiiiiilllllll ! ! ! !\n");
  buflen = BUFLEN;
  if (vppcom_session_attr (ssm->listen_fd, VPPCOM_ATTR_GET_LCL_ADDR,
			   buffer, &buflen) != VPPCOM_OK)
    printf ("\nGET_LCL_ADDR: Oh no, Mr. Biiiiiiiiiiiilllllll ! ! ! !\n");
#endif
#else
  rv =
    bind (ssm->listen_fd, (struct sockaddr *) &servaddr, sizeof (servaddr));
#endif
  if (rv < 0)
    {
      errno_val = errno;
      perror ("ERROR in main()");
      fprintf (stderr, "ERROR: bind failed (errno = %d)!\n", errno_val);
      return rv;
    }

#ifdef VCL_TEST
  rv = vppcom_session_listen (ssm->listen_fd, 10);
  if (rv)
    {
      errno = -rv;
      rv = -1;
    }
#else
  rv = listen (ssm->listen_fd, 10);
#endif
  if (rv < 0)
    {
      errno_val = errno;
      perror ("ERROR in main()");
      fprintf (stderr, "ERROR: listen failed (errno = %d)!\n", errno_val);
      return rv;
    }

  printf ("\nSERVER: Waiting for a client to connect on port %d...\n", port);

#if ! SOCK_SERVER_USE_EPOLL

  FD_ZERO (&ssm->wr_fdset);
  FD_ZERO (&ssm->rd_fdset);

  FD_SET (ssm->listen_fd, &ssm->rd_fdset);
  ssm->nfds = ssm->listen_fd + 1;

#else
#ifdef VCL_TEST
  ssm->epfd = vppcom_epoll_create ();
  if (ssm->epfd < 0)
    errno = -ssm->epfd;
#else
  ssm->epfd = epoll_create (1);
#endif
  if (ssm->epfd < 0)
    {
      errno_val = errno;
      perror ("ERROR in main()");
      fprintf (stderr, "ERROR: epoll_create failed (errno = %d)!\n",
	       errno_val);
      return ssm->epfd;
    }

  ssm->listen_ev.events = EPOLLIN;
  ssm->listen_ev.data.u32 = ~0;
#ifdef VCL_TEST
  rv = vppcom_epoll_ctl (ssm->epfd, EPOLL_CTL_ADD, ssm->listen_fd,
			 &ssm->listen_ev);
  if (rv < 0)
    errno = -rv;
#else
  rv = epoll_ctl (ssm->epfd, EPOLL_CTL_ADD, ssm->listen_fd, &ssm->listen_ev);
#endif
  if (rv < 0)
    {
      errno_val = errno;
      perror ("ERROR in main()");
      fprintf (stderr, "ERROR: epoll_ctl failed (errno = %d)!\n", errno_val);
      return rv;
    }
#endif

  while (1)
    {
#if ! SOCK_SERVER_USE_EPOLL
      _rfdset = ssm->rd_fdset;

#ifdef VCL_TEST
      rv = vppcom_select (ssm->nfds, (uint64_t *) rfdset, NULL, NULL, 0);
#else
      {
	struct timeval timeout;
	timeout = ssm->timeout;
	_wfdset = ssm->wr_fdset;
	rv = select (ssm->nfds, rfdset, wfdset, NULL, &timeout);
      }
#endif
      if (rv < 0)
	{
	  perror ("select()");
	  fprintf (stderr, "\nERROR: select() failed -- aborting!\n");
	  main_rv = -1;
	  goto done;
	}
      else if (rv == 0)
	continue;

      if (FD_ISSET (ssm->listen_fd, rfdset))
	new_client ();

      for (i = 0; i < ssm->conn_pool_size; i++)
	{
	  if (!ssm->conn_pool[i].is_alloc)
	    continue;

	  conn = &ssm->conn_pool[i];
#else
      int num_ev;
#ifdef VCL_TEST
      num_ev = vppcom_epoll_wait (ssm->epfd, ssm->wait_events,
				  SOCK_SERVER_MAX_EPOLL_EVENTS, 60.0);
      if (num_ev < 0)
	errno = -num_ev;
#else
      num_ev = epoll_wait (ssm->epfd, ssm->wait_events,
			   SOCK_SERVER_MAX_EPOLL_EVENTS, 60000);
#endif
      if (num_ev < 0)
	{
	  perror ("epoll_wait()");
	  fprintf (stderr, "\nERROR: epoll_wait() failed -- aborting!\n");
	  main_rv = -1;
	  goto done;
	}
      if (num_ev == 0)
	{
	  fprintf (stderr, "\nepoll_wait() timeout!\n");
	  continue;
	}
      for (i = 0; i < num_ev; i++)
	{
	  if (ssm->wait_events[i].data.u32 == ~0)
	    {
	      new_client ();
	      continue;
	    }
	  conn = &ssm->conn_pool[ssm->wait_events[i].data.u32];
#endif
	  client_fd = conn->fd;

#if ! SOCK_SERVER_USE_EPOLL
	  if (FD_ISSET (client_fd, rfdset))
#else
	  if (EPOLLIN & ssm->wait_events[i].events)
#endif
	    {
#ifdef VCL_TEST
#if VPPCOM_SESSION_ATTR_UNIT_TEST
	      buflen = BUFLEN;
	      if (vppcom_session_attr (client_fd, VPPCOM_ATTR_GET_NREAD,
				       buffer, &buflen) < VPPCOM_OK)
		printf ("\nNREAD: Oh no, Mr. Biiiiiiiiiiiilllllll ! ! ! !\n");
	      if (vppcom_session_attr (client_fd,
				       VPPCOM_ATTR_GET_PEER_ADDR,
				       buffer, &buflen) != VPPCOM_OK)
		printf ("\nGET_PEER_ADDR: Oh no, Mr. "
			"Biiiiiiiiiiiilllllll ! ! ! !\n");
	      buflen = BUFLEN;
	      if (vppcom_session_attr (client_fd, VPPCOM_ATTR_GET_LCL_ADDR,
				       buffer, &buflen) != VPPCOM_OK)
		printf ("\nGET_LCL_ADDR: Oh no, Mr. "
			"Biiiiiiiiiiiilllllll ! ! ! !\n");
#endif
#endif
	      rx_bytes = sock_test_read (client_fd, conn->buf,
					 conn->buf_size, &conn->stats);
	      if (rx_bytes > 0)
		{
		  rx_cfg = (sock_test_cfg_t *) conn->buf;
		  if (rx_cfg->magic == SOCK_TEST_CFG_CTRL_MAGIC)
		    {
		      if (rx_cfg->verbose)
			{
			  printf ("SERVER (fd %d): Received a cfg message!\n",
				  client_fd);
			  sock_test_cfg_dump (rx_cfg, 0 /* is_client */ );
			}

		      if (rx_bytes != sizeof (*rx_cfg))
			{
			  printf ("SERVER (fd %d): Invalid cfg message "
				  "size (%d)!\n  Should be %lu bytes.\n",
				  client_fd, rx_bytes, sizeof (*rx_cfg));
			  conn->cfg.rxbuf_size = 0;
			  conn->cfg.num_writes = 0;
			  if (conn->cfg.verbose)
			    {
			      printf ("SERVER (fd %d): Replying to "
				      "cfg message!\n", client_fd);
			      sock_test_cfg_dump (rx_cfg, 0 /* is_client */ );
			    }
			  sock_test_write (client_fd, (uint8_t *) & conn->cfg,
					   sizeof (conn->cfg), NULL,
					   conn->cfg.verbose);
			  continue;
			}

		      switch (rx_cfg->test)
			{
			case SOCK_TEST_TYPE_NONE:
			case SOCK_TEST_TYPE_ECHO:
			  sync_config_and_reply (conn, rx_cfg);
			  break;

			case SOCK_TEST_TYPE_BI:
			case SOCK_TEST_TYPE_UNI:
			  stream_test_server_start_stop (conn, rx_cfg);
			  break;

			case SOCK_TEST_TYPE_EXIT:
			  printf ("SERVER: Have a great day, "
				  "connection %d!\n", client_fd);
#ifdef VCL_TEST
			  vppcom_session_close (client_fd);
#else
			  close (client_fd);
#endif
			  conn_pool_free (conn);
#if ! SOCK_SERVER_USE_EPOLL
			  if (ssm->nfds == (ssm->listen_fd + 1))
#else
			  ssm->nfds--;
			  if (!ssm->nfds)
#endif
			    {
			      printf ("SERVER: All client connections "
				      "closed.\n\nSERVER: "
				      "May the force be with you!\n\n");
			      goto done;
			    }
			  break;

			default:
			  fprintf (stderr, "ERROR: Unknown test type!\n");
			  sock_test_cfg_dump (rx_cfg, 0 /* is_client */ );
			  break;
			}
		      continue;
		    }

		  else if ((conn->cfg.test == SOCK_TEST_TYPE_UNI) ||
			   (conn->cfg.test == SOCK_TEST_TYPE_BI))
		    {
		      stream_test_server (conn, rx_bytes);
		      continue;
		    }

		  else if (isascii (conn->buf[0]))
		    {
		      // If it looks vaguely like a string, make sure it's terminated
		      ((char *) conn->buf)[rx_bytes <
					   conn->buf_size ? rx_bytes :
					   conn->buf_size - 1] = 0;
		      printf ("SERVER (fd %d): RX (%d bytes) - '%s'\n",
			      conn->fd, rx_bytes, conn->buf);
		    }
		}
	      else		// rx_bytes < 0
		{
		  if (errno == ECONNRESET)
		    {
		      printf ("\nSERVER: Connection reset by remote peer.\n"
			      "  Y'all have a great day now!\n\n");
		      break;
		    }
		  else
		    continue;
		}

	      if (isascii (conn->buf[0]))
		{
		  // If it looks vaguely like a string, make sure it's terminated
		  ((char *) conn->buf)[rx_bytes <
				       conn->buf_size ? rx_bytes :
				       conn->buf_size - 1] = 0;
		  if (xtra)
		    fprintf (stderr,
			     "ERROR: FIFO not drained in previous test!\n"
			     "       extra chunks %u (0x%x)\n"
			     "        extra bytes %lu (0x%lx)\n",
			     xtra, xtra, xtra_bytes, xtra_bytes);

		  xtra = 0;
		  xtra_bytes = 0;

		  if (conn->cfg.verbose)
		    printf ("SERVER (fd %d): Echoing back\n", client_fd);

		  nbytes = strlen ((const char *) conn->buf) + 1;

		  tx_bytes = sock_test_write (client_fd, conn->buf,
					      nbytes, &conn->stats,
					      conn->cfg.verbose);
		  if (tx_bytes >= 0)
		    printf ("SERVER (fd %d): TX (%d bytes) - '%s'\n",
			    conn->fd, tx_bytes, conn->buf);
		}

	      else		// Extraneous read data from non-echo tests???
		{
		  xtra++;
		  xtra_bytes += rx_bytes;
		}
	    }
	}
    }

done:
#ifdef VCL_TEST
  vppcom_session_close (ssm->listen_fd);
  vppcom_app_destroy ();
#else
  close (ssm->listen_fd);
#endif
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
