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
#include <sys/stat.h>
#include <fcntl.h>
#include <hs_apps/vcl/vcl_test.h>
#include <sys/epoll.h>
#include <vppinfra/mem.h>
#include <pthread.h>

typedef struct
{
  uint16_t port;
  uint32_t address_ip6;
  u8 proto;
  u8 workers;
  vppcom_endpt_t endpt;
} vcl_test_server_cfg_t;

typedef struct
{
  uint32_t wrk_index;
  vcl_test_session_t listener;
  int listen_fd;
  int epfd;
  struct epoll_event wait_events[VCL_TEST_CFG_MAX_EPOLL_EVENTS];
  size_t conn_pool_size;
  vcl_test_session_t *conn_pool;
  int nfds;
  pthread_t thread_handle;
} vcl_test_server_worker_t;

typedef struct
{
  vcl_test_server_cfg_t cfg;
  vcl_test_server_worker_t *workers;

  vcl_test_session_t *ctrl;
  int ctrl_listen_fd;
  struct sockaddr_storage servaddr;
  volatile int worker_fails;
  volatile int active_workers;
  u8 use_ds;
} vcl_test_server_main_t;

vcl_test_main_t vcl_test_main;

// static __thread int __wrk_index = 0;

static vcl_test_server_main_t vcl_server_main;

static inline void
conn_pool_expand (vcl_test_server_worker_t * wrk, size_t expand_size)
{
  vcl_test_session_t *conn_pool;
  size_t new_size = wrk->conn_pool_size + expand_size;
  int i;

  conn_pool = realloc (wrk->conn_pool, new_size * sizeof (*wrk->conn_pool));
  if (conn_pool)
    {
      for (i = wrk->conn_pool_size; i < new_size; i++)
	{
	  vcl_test_session_t *conn = &conn_pool[i];
	  memset (conn, 0, sizeof (*conn));
	  vcl_test_cfg_init (&conn->cfg);
	  vcl_test_buf_alloc (&conn->cfg, 1 /* is_rxbuf */,
			      (uint8_t **) &conn->rxbuf, &conn->rxbuf_size);
	  conn->cfg.txbuf_size = conn->cfg.rxbuf_size;
	}

      wrk->conn_pool = conn_pool;
      wrk->conn_pool_size = new_size;
    }
  else
    {
      vterr ("conn_pool_expand()", -errno);
    }
}

static inline vcl_test_session_t *
conn_pool_alloc (vcl_test_server_worker_t *wrk)
{
  int i, expand = 0;

again:
  for (i = 0; i < wrk->conn_pool_size; i++)
    {
      if (!wrk->conn_pool[i].is_alloc)
	{
	  wrk->conn_pool[i].endpt.ip = wrk->conn_pool[i].ip;
	  wrk->conn_pool[i].is_alloc = 1;
	  wrk->conn_pool[i].session_index = i;
	  return (&wrk->conn_pool[i]);
	}
    }

  if (expand == 0)
    {
      conn_pool_expand (wrk, 2 * wrk->conn_pool_size);
      expand = 1;
      goto again;
    }
  vtwrn ("Failed to allocate connection even after expand");
  return 0;
}

static inline void
conn_pool_free (vcl_test_session_t *conn)
{
  conn->fd = 0;
  conn->is_alloc = 0;
}

static inline void
sync_config_and_reply (vcl_test_session_t *conn, vcl_test_cfg_t *rx_cfg)
{
  conn->cfg = *rx_cfg;
  vcl_test_buf_alloc (&conn->cfg, 1 /* is_rxbuf */, (uint8_t **) &conn->rxbuf,
		      &conn->rxbuf_size);
  conn->cfg.txbuf_size = conn->cfg.rxbuf_size;

  if (conn->cfg.verbose)
    {
      vtinf ("(fd %d): Replying to cfg message!\n", conn->fd);
      vcl_test_cfg_dump (&conn->cfg, 0 /* is_client */ );
    }
  (void) vcl_test_write (conn, &conn->cfg, sizeof (conn->cfg));
}

static void
vts_session_close (vcl_test_session_t *conn)
{
  if (!conn->is_open)
    return;
  vppcom_session_close (conn->fd);
  conn->is_open = 0;
}

static void
vts_session_cleanup (vcl_test_session_t *conn)
{
  vts_session_close (conn);
  conn_pool_free (conn);
}

static void
vts_wrk_cleanup_all (vcl_test_server_worker_t *wrk)
{
  vcl_test_session_t *conn;
  int i;

  for (i = 0; i < wrk->conn_pool_size; i++)
    {
      conn = &wrk->conn_pool[i];
      vts_session_cleanup (conn);
    }

  wrk->nfds = 0;
}

static void
vts_test_cmd (vcl_test_server_worker_t *wrk, vcl_test_session_t *conn,
	      vcl_test_cfg_t *rx_cfg)
{
  u8 is_bi = rx_cfg->test == VCL_TEST_TYPE_BI;
  vcl_test_session_t *tc;
  char buf[64];
  int i;

  if (rx_cfg->cmd == VCL_TEST_CMD_STOP)
    {
      struct timespec stop;
      clock_gettime (CLOCK_REALTIME, &stop);

      /* Test session are not closed, e.g., connection-less or errors */
      if (wrk->nfds > 1)
	{
	  vtinf ("%u sessions are still open", wrk->nfds - 1);
	  stop.tv_sec -= VCL_TEST_DELAY_DISCONNECT;
	  conn->stats.stop = stop;
	}

      /* Accumulate stats over all of the worker's sessions */
      for (i = 0; i < wrk->conn_pool_size; i++)
	{
	  tc = &wrk->conn_pool[i];
	  if (tc == conn)
	    continue;

	  vcl_test_stats_accumulate (&conn->stats, &tc->stats);
	  if (tc->is_open)
	    {
	      vts_session_close (tc);
	      continue;
	    }
	  /* Only relevant if all connections previously closed */
	  if (vcl_comp_tspec (&conn->stats.stop, &tc->stats.stop) < 0)
	    conn->stats.stop = tc->stats.stop;
	}

      if (conn->cfg.verbose)
	{
	  snprintf (buf, sizeof (buf), "SERVER (fd %d) RESULTS", conn->fd);
	  vcl_test_stats_dump (buf, &conn->stats, 1 /* show_rx */,
			       is_bi /* show tx */, conn->cfg.verbose);
	}

      vcl_test_stats_dump ("SERVER RESULTS", &conn->stats, 1 /* show_rx */ ,
			   is_bi /* show_tx */ , conn->cfg.verbose);
      vcl_test_cfg_dump (&conn->cfg, 0 /* is_client */ );
      if (conn->cfg.verbose)
	{
	  vtinf ("  vcl server main\n" VCL_TEST_SEPARATOR_STRING
		 "       buf:  %p\n"
		 "  buf size:  %u (0x%08x)\n" VCL_TEST_SEPARATOR_STRING,
		 conn->rxbuf, conn->rxbuf_size, conn->rxbuf_size);
	}

      sync_config_and_reply (conn, rx_cfg);
      memset (&conn->stats, 0, sizeof (conn->stats));
    }
  else if (rx_cfg->cmd == VCL_TEST_CMD_SYNC)
    {
      rx_cfg->ctrl_handle = conn->fd;
      vtinf ("Set control fd %d for test!", conn->fd);
      sync_config_and_reply (conn, rx_cfg);
    }
  else if (rx_cfg->cmd == VCL_TEST_CMD_START)
    {
      vtinf ("Starting %s-directional Stream Test (fd %d)!",
	     is_bi ? "Bi" : "Uni", conn->fd);
      rx_cfg->ctrl_handle = conn->fd;
      sync_config_and_reply (conn, rx_cfg);

      /* read the 1st chunk, record start time */
      memset (&conn->stats, 0, sizeof (conn->stats));
      clock_gettime (CLOCK_REALTIME, &conn->stats.start);
    }
}

static inline void
vts_server_process_rx (vcl_test_session_t *conn, int rx_bytes)
{
  vcl_test_server_main_t *vsm = &vcl_server_main;

  if (conn->cfg.test == VCL_TEST_TYPE_BI)
    {
      if (vsm->use_ds)
	{
	  (void) vcl_test_write (conn, conn->ds[0].data, conn->ds[0].len);
	  if (conn->ds[1].len)
	    (void) vcl_test_write (conn, conn->ds[1].data, conn->ds[1].len);
	}
      else
	(void) vcl_test_write (conn, conn->rxbuf, rx_bytes);
    }

  if (vsm->use_ds)
    vppcom_session_free_segments (conn->fd, rx_bytes);

  if (conn->stats.rx_bytes >= conn->cfg.total_bytes)
    clock_gettime (CLOCK_REALTIME, &conn->stats.stop);
}

static void
vts_server_echo (vcl_test_session_t *conn, int rx_bytes)
{
  int tx_bytes, nbytes, pos;

  /* If it looks vaguely like a string, make sure it's terminated */
  pos = rx_bytes < conn->rxbuf_size ? rx_bytes : conn->rxbuf_size - 1;
  ((char *) conn->rxbuf)[pos] = 0;
  vtinf ("(fd %d): RX (%d bytes) - '%s'", conn->fd, rx_bytes, conn->rxbuf);

  if (conn->cfg.verbose)
    vtinf ("(fd %d): Echoing back", conn->fd);

  nbytes = strlen ((const char *) conn->rxbuf) + 1;
  tx_bytes = vcl_test_write (conn, conn->rxbuf, nbytes);
  if (tx_bytes >= 0)
    vtinf ("(fd %d): TX (%d bytes) - '%s'", conn->fd, tx_bytes, conn->rxbuf);
}

static vcl_test_session_t *
vts_accept_client (vcl_test_server_worker_t *wrk, int listen_fd)
{
  vcl_test_server_main_t *vsm = &vcl_server_main;
  vcl_test_proto_vft_t *tp;
  vcl_test_session_t *conn;
  struct epoll_event ev;
  int rv;

  conn = conn_pool_alloc (wrk);
  if (!conn)
    {
      vtwrn ("No free connections!");
      return 0;
    }

  tp = vcl_test_main.protos[vsm->cfg.proto];
  if (tp->accept (listen_fd, conn))
    return 0;

  vtinf ("Got a connection -- fd = %d (0x%08x) on listener fd = %d (0x%08x)",
	 conn->fd, conn->fd, listen_fd, listen_fd);

  ev.events = EPOLLIN;
  ev.data.u64 = conn - wrk->conn_pool;
  rv = vppcom_epoll_ctl (wrk->epfd, EPOLL_CTL_ADD, conn->fd, &ev);
  if (rv < 0)
    {
      vterr ("vppcom_epoll_ctl()", rv);
      return 0;
    }
  wrk->nfds++;

  return conn;
}

static void
print_usage_and_exit (void)
{
  fprintf (stderr,
	   "vcl_test_server [OPTIONS] <port>\n"
	   "  OPTIONS\n"
	   "  -h               Print this message and exit.\n"
	   "  -6               Use IPv6\n"
	   "  -w <num>         Number of workers\n"
	   "  -p <PROTO>       Use <PROTO> transport layer\n"
	   "  -D               Use UDP transport layer\n"
	   "  -L               Use TLS transport layer\n");
  exit (1);
}

static void
vcl_test_init_endpoint_addr (vcl_test_server_main_t * vsm)
{
  struct sockaddr_storage *servaddr = &vsm->servaddr;
  memset (servaddr, 0, sizeof (*servaddr));

  if (vsm->cfg.address_ip6)
    {
      struct sockaddr_in6 *server_addr = (struct sockaddr_in6 *) servaddr;
      server_addr->sin6_family = AF_INET6;
      server_addr->sin6_addr = in6addr_any;
      server_addr->sin6_port = htons (vsm->cfg.port);
    }
  else
    {
      struct sockaddr_in *server_addr = (struct sockaddr_in *) servaddr;
      server_addr->sin_family = AF_INET;
      server_addr->sin_addr.s_addr = htonl (INADDR_ANY);
      server_addr->sin_port = htons (vsm->cfg.port);
    }

  if (vsm->cfg.address_ip6)
    {
      struct sockaddr_in6 *server_addr = (struct sockaddr_in6 *) servaddr;
      vsm->cfg.endpt.is_ip4 = 0;
      vsm->cfg.endpt.ip = (uint8_t *) & server_addr->sin6_addr;
      vsm->cfg.endpt.port = (uint16_t) server_addr->sin6_port;
    }
  else
    {
      struct sockaddr_in *server_addr = (struct sockaddr_in *) servaddr;
      vsm->cfg.endpt.is_ip4 = 1;
      vsm->cfg.endpt.ip = (uint8_t *) & server_addr->sin_addr;
      vsm->cfg.endpt.port = (uint16_t) server_addr->sin_port;
    }
}

static void
vcl_test_server_process_opts (vcl_test_server_main_t * vsm, int argc,
			      char **argv)
{
  int v, c;

  vsm->cfg.proto = VPPCOM_PROTO_TCP;

  opterr = 0;
  while ((c = getopt (argc, argv, "6DLsw:hp:")) != -1)
    switch (c)
      {
      case '6':
	vsm->cfg.address_ip6 = 1;
	break;

      case 'p':
	if (vppcom_unformat_proto (&vsm->cfg.proto, optarg))
	  vtwrn ("Invalid vppcom protocol %s, defaulting to TCP", optarg);
	break;

      case 'D':
	vsm->cfg.proto = VPPCOM_PROTO_UDP;
	break;

      case 'L':
	vsm->cfg.proto = VPPCOM_PROTO_TLS;
	break;

      case 'w':
	v = atoi (optarg);
	if (v > 1)
	  vsm->cfg.workers = v;
	else
	  vtwrn ("Invalid number of workers %d", v);
	break;
      case 's':
	vsm->use_ds = 1;
	break;
      case '?':
	switch (optopt)
	  {
	  case 'w':
	  case 'p':
	    vtwrn ("Option `-%c' requires an argument.", optopt);
	    break;
	  default:
	    if (isprint (optopt))
	      vtwrn ("Unknown option `-%c'.", optopt);
	    else
	      vtwrn ("Unknown option character `\\x%x'.", optopt);
	  }
	/* fall thru */
      case 'h':
      default:
	print_usage_and_exit ();
      }

  if (argc < (optind + 1))
    {
      fprintf (stderr, "SERVER: ERROR: Insufficient number of arguments!\n");
      print_usage_and_exit ();
    }

  if (sscanf (argv[optind], "%d", &v) == 1)
    vsm->cfg.port = (uint16_t) v;
  else
    {
      fprintf (stderr, "SERVER: ERROR: Invalid port (%s)!\n", argv[optind]);
      print_usage_and_exit ();
    }

  vcl_test_init_endpoint_addr (vsm);
}

static void
vts_clean_connected_listeners (vcl_test_server_worker_t * wrk,
			       int listener_fd)
{
  if ((vppcom_session_n_accepted (listener_fd) == 0) &
      vppcom_session_is_connectable_listener (listener_fd))
    {
      vtinf ("Connected Listener fd %x has no more sessions", listener_fd);
      vppcom_session_close (listener_fd);
      wrk->nfds--;
    }
}

int
vts_handle_ctrl_cfg (vcl_test_server_worker_t *wrk, vcl_test_cfg_t *rx_cfg,
		     vcl_test_session_t *conn, int rx_bytes)
{
  int listener_fd;
  if (rx_cfg->verbose)
    {
      vtinf ("(fd %d): Received a cfg msg!", conn->fd);
      vcl_test_cfg_dump (rx_cfg, 0 /* is_client */ );
    }

  if (rx_bytes != sizeof (*rx_cfg))
    {
      vtinf ("(fd %d): Invalid cfg msg size %d expected %lu!", conn->fd,
	     rx_bytes, sizeof (*rx_cfg));
      conn->cfg.rxbuf_size = 0;
      conn->cfg.num_writes = 0;
      if (conn->cfg.verbose)
	{
	  vtinf ("(fd %d): Replying to cfg msg", conn->fd);
	  vcl_test_cfg_dump (rx_cfg, 0 /* is_client */ );
	}
      vcl_test_write (conn, &conn->cfg, sizeof (conn->cfg));
      return -1;
    }

  switch (rx_cfg->test)
    {
    case VCL_TEST_TYPE_NONE:
    case VCL_TEST_TYPE_ECHO:
      sync_config_and_reply (conn, rx_cfg);
      break;

    case VCL_TEST_TYPE_BI:
    case VCL_TEST_TYPE_UNI:
      vts_test_cmd (wrk, conn, rx_cfg);
      break;

    case VCL_TEST_TYPE_EXIT:
      vtinf ("Ctrl session fd %d closing!", conn->fd);
      listener_fd = vppcom_session_listener (conn->fd);
      vts_clean_connected_listeners (wrk, listener_fd);
      vts_session_cleanup (conn);
      wrk->nfds--;
      if (wrk->nfds)
	vts_wrk_cleanup_all (wrk);
      break;

    default:
      vtwrn ("Unknown test type %d", rx_cfg->test);
      vcl_test_cfg_dump (rx_cfg, 0 /* is_client */ );
      break;
    }

  return 0;
}

static void
vts_worker_init (vcl_test_server_worker_t * wrk)
{
  vcl_test_server_main_t *vsm = &vcl_server_main;
  struct epoll_event listen_ev;
  vcl_test_proto_vft_t *tp;
  int rv;

  __wrk_index = wrk->wrk_index;

  vtinf ("Initializing worker ...");

  conn_pool_expand (wrk, VCL_TEST_CFG_MAX_TEST_SESS + 1);
  if (wrk->wrk_index)
    if (vppcom_worker_register ())
      vtfail ("vppcom_worker_register()", 1);

  //  wrk->listen_fd = vppcom_session_create (vsm->cfg.proto,
  //					  0 /* is_nonblocking */ );
  //  if (wrk->listen_fd < 0)
  //    vtfail ("vppcom_session_create()", wrk->listen_fd);
  //
  //  if (vsm->cfg.proto == VPPCOM_PROTO_UDP)
  //    {
  //      vppcom_session_attr (wrk->listen_fd, VPPCOM_ATTR_SET_CONNECTED, 0,
  //      0);
  //    }
  //
  //  if (vsm->cfg.proto == VPPCOM_PROTO_TLS ||
  //      vsm->cfg.proto == VPPCOM_PROTO_QUIC ||
  //      vsm->cfg.proto == VPPCOM_PROTO_DTLS)
  //    {
  //      vppcom_cert_key_pair_t ckpair;
  //      uint32_t ckp_len;
  //      int ckp_index;
  //
  //      vtinf ("Adding tls certs ...");
  //      ckpair.cert = vcl_test_crt_rsa;
  //      ckpair.key = vcl_test_key_rsa;
  //      ckpair.cert_len = vcl_test_crt_rsa_len;
  //      ckpair.key_len = vcl_test_key_rsa_len;
  //      ckp_index = vppcom_add_cert_key_pair (&ckpair);
  //      if (ckp_index < 0)
  //	vtfail ("vppcom_add_cert_key_pair()", ckp_index);
  //
  //      ckp_len = sizeof (ckp_index);
  //      vppcom_session_attr (wrk->listen_fd, VPPCOM_ATTR_SET_CKPAIR,
  //      &ckp_index,
  //			   &ckp_len);
  //    }
  //
  //  rv = vppcom_session_bind (wrk->listen_fd, &vsm->cfg.endpt);
  //  if (rv < 0)
  //    vtfail ("vppcom_session_bind()", rv);
  //
  //  if (!(vsm->cfg.proto == VPPCOM_PROTO_UDP))
  //    {
  //      rv = vppcom_session_listen (wrk->listen_fd, 10);
  //      if (rv < 0)
  //	vtfail ("vppcom_session_listen()", rv);
  //    }

  tp = vcl_test_main.protos[vsm->cfg.proto];
  if ((rv = tp->listen (&wrk->listener, &vsm->cfg.endpt)))
    vtfail ("proto listen", rv);

  /* First worker already has epoll fd */
  if (wrk->wrk_index)
    {
      wrk->epfd = vppcom_epoll_create ();
      if (wrk->epfd < 0)
	vtfail ("vppcom_epoll_create()", wrk->epfd);
    }

  listen_ev.events = EPOLLIN;
  listen_ev.data.u32 = VCL_TEST_DATA_LISTENER;
  rv =
    vppcom_epoll_ctl (wrk->epfd, EPOLL_CTL_ADD, wrk->listener.fd, &listen_ev);
  if (rv < 0)
    vtfail ("vppcom_epoll_ctl", rv);

  vsm->active_workers += 1;
  vtinf ("Waiting for a client to connect on port %d ...", vsm->cfg.port);
}

static inline int
vts_conn_read (vcl_test_session_t *conn)
{
  vcl_test_server_main_t *vsm = &vcl_server_main;
  if (vsm->use_ds)
    return vcl_test_read_ds (conn);
  else
    return conn->read (conn, conn->rxbuf, conn->rxbuf_size);
}

static void *
vts_worker_loop (void *arg)
{
  vcl_test_server_main_t *vsm = &vcl_server_main;
  vcl_test_server_worker_t *wrk = arg;
  vcl_test_session_t *conn;
  int i, rx_bytes, num_ev, listener_fd;
  vcl_test_cfg_t *rx_cfg;

  if (wrk->wrk_index)
    vts_worker_init (wrk);

  while (1)
    {
      num_ev = vppcom_epoll_wait (wrk->epfd, wrk->wait_events,
				  VCL_TEST_CFG_MAX_EPOLL_EVENTS, 60000.0);
      if (num_ev < 0)
	{
	  vterr ("vppcom_epoll_wait()", num_ev);
	  goto fail;
	}
      else if (num_ev == 0)
	{
	  vtinf ("vppcom_epoll_wait() timeout!");
	  continue;
	}
      for (i = 0; i < num_ev; i++)
	{
	  conn = &wrk->conn_pool[wrk->wait_events[i].data.u32];
	  /*
	   * Check for close events
	   */
	  if (wrk->wait_events[i].events & (EPOLLHUP | EPOLLRDHUP))
	    {
	      listener_fd = vppcom_session_listener (conn->fd);
	      vts_clean_connected_listeners (wrk, listener_fd);
	      vts_session_close (conn);
	      wrk->nfds--;
	      if (!wrk->nfds)
		{
		  vtinf ("All client connections closed\n");
		  goto done;
		}
	      continue;
	    }

	  /*
	   * Check if new session needs to be accepted
	   */

	  if (wrk->wait_events[i].data.u32 == VCL_TEST_CTRL_LISTENER)
	    {
	      if (vsm->ctrl)
		{
		  vtwrn ("ctrl already exists");
		  continue;
		}
	      vsm->ctrl = vts_accept_client (wrk, vsm->ctrl_listen_fd);
	      continue;
	    }
	  if (wrk->wait_events[i].data.u32 == VCL_TEST_DATA_LISTENER)
	    {
	      conn = vts_accept_client (wrk, wrk->listener.fd);
	      conn->cfg = vsm->ctrl->cfg;
	      continue;
	    }
	  else if (vppcom_session_is_connectable_listener (conn->fd))
	    {
	      vts_accept_client (wrk, conn->fd);
	      continue;
	    }

	  /*
	   * Message on control session
	   */

	  if (!wrk->wrk_index && conn->fd == vsm->ctrl->fd)
	    {
	      rx_bytes = conn->read (conn, conn->rxbuf, conn->rxbuf_size);
	      rx_cfg = (vcl_test_cfg_t *) conn->rxbuf;
	      if (rx_cfg->magic == VCL_TEST_CFG_CTRL_MAGIC)
		{
		  vts_handle_ctrl_cfg (wrk, rx_cfg, conn, rx_bytes);
		  if (!wrk->nfds)
		    {
		      vtinf ("All client connections closed\n");
		      goto done;
		    }
		}
	      else if (isascii (conn->rxbuf[0]))
		{
		  vts_server_echo (conn, rx_bytes);
		}
	      else
		{
		  vtwrn ("FIFO not drained! extra bytes %d", rx_bytes);
		}
	      continue;
	    }

	  /*
	   * Read perf test data
	   */

	  if (EPOLLIN & wrk->wait_events[i].events)
	    {
	    read_again:
	      rx_bytes = vts_conn_read (conn);

	      if (rx_bytes <= 0)
		{
		  if (errno == ECONNRESET)
		    {
		      vtinf ("Connection reset by remote peer.\n");
		      goto fail;
		    }
		  else
		    continue;
		}
	      vts_server_process_rx (conn, rx_bytes);
	      if (vppcom_session_attr (conn->fd, VPPCOM_ATTR_GET_NREAD, 0, 0) >
		  0)
		goto read_again;
	      continue;
	    }
	  else
	    {
	      vtwrn ("Unhandled event");
	      goto fail;
	    }
	}
    }

fail:
  vsm->worker_fails -= 1;

done:
  vppcom_session_close (wrk->listener.fd);
  if (wrk->conn_pool)
    free (wrk->conn_pool);
  vsm->active_workers -= 1;
  return 0;
}

static void
vts_ctrl_session_init (vcl_test_server_worker_t *wrk)
{
  vcl_test_server_main_t *vsm = &vcl_server_main;
  struct epoll_event listen_ev;
  int rv;

  vtinf ("Initializing main ctrl session ...");

  vsm->ctrl_listen_fd =
    vppcom_session_create (VPPCOM_PROTO_TCP, 0 /* is_nonblocking */);
  if (vsm->ctrl_listen_fd < 0)
    vtfail ("vppcom_session_create()", vsm->ctrl_listen_fd);

  rv = vppcom_session_bind (vsm->ctrl_listen_fd, &vsm->cfg.endpt);
  if (rv < 0)
    vtfail ("vppcom_session_bind()", rv);

  rv = vppcom_session_listen (vsm->ctrl_listen_fd, 10);
  if (rv < 0)
    vtfail ("vppcom_session_listen()", rv);

  wrk->epfd = vppcom_epoll_create ();
  if (wrk->epfd < 0)
    vtfail ("vppcom_epoll_create()", wrk->epfd);

  listen_ev.events = EPOLLIN;
  listen_ev.data.u32 = VCL_TEST_CTRL_LISTENER;
  rv = vppcom_epoll_ctl (wrk->epfd, EPOLL_CTL_ADD, vsm->ctrl_listen_fd,
			 &listen_ev);
  if (rv < 0)
    vtfail ("vppcom_epoll_ctl", rv);

  vtinf ("Waiting for a client to connect on port %d ...", vsm->cfg.port);
}

int
main (int argc, char **argv)
{
  vcl_test_server_main_t *vsm = &vcl_server_main;
  vcl_test_main_t *vt = &vcl_test_main;
  int rv, i;

  clib_mem_init_thread_safe (0, 64 << 20);
  vsm->cfg.port = VCL_TEST_SERVER_PORT;
  vsm->cfg.workers = 1;
  vsm->active_workers = 0;
  vcl_test_server_process_opts (vsm, argc, argv);

  rv = vppcom_app_create ("vcl_test_server");
  if (rv)
    vtfail ("vppcom_app_create()", rv);

  /* Protos like tls/dtls/quic need init */
  if (vt->protos[vsm->cfg.proto]->init)
    vt->protos[vsm->cfg.proto]->init ();

  vsm->workers = calloc (vsm->cfg.workers, sizeof (*vsm->workers));
  vts_ctrl_session_init (&vsm->workers[0]);

  /* Update ctrl port to data port */
  vsm->cfg.endpt.port += 1;
  vts_worker_init (&vsm->workers[0]);
  for (i = 1; i < vsm->cfg.workers; i++)
    {
      vsm->workers[i].wrk_index = i;
      rv = pthread_create (&vsm->workers[i].thread_handle, NULL,
			   vts_worker_loop, (void *) &vsm->workers[i]);
    }

  vts_worker_loop (&vsm->workers[0]);

  while (vsm->active_workers > 0)
    ;

  vppcom_app_destroy ();
  free (vsm->workers);

  return vsm->worker_fails;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
