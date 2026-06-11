/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2021 Cisco and/or its affiliates.
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
#include <vperf/vcl/vperf.h>
#include <sys/epoll.h>
#include <vppinfra/mem.h>
#include <pthread.h>

/*
 * XXX: Unfortunately libepoll-shim requires some hacks to work, one of these
 * defines 'close' as a macro. This collides with vcl test callback 'close'.
 * Undef the 'close' macro on FreeBSD if it exists.
 */
#ifdef __FreeBSD__
#ifdef close
#undef close
#endif
#endif /* __FreeBSD__ */

typedef struct
{
  uint16_t port;
  uint32_t address_ip6;
  u8 proto;
  u8 workers;
  vppcom_endpt_t endpt;
} vperf_server_cfg_t;

typedef struct
{
  vperf_session_t *conn_pool;
  uint32_t wrk_index;
  int epfd;
  int conn_pool_size;
  int nfds;
  vperf_session_t listener;
  pthread_t thread_handle;
} vperf_server_worker_t;

typedef struct
{
  vperf_server_worker_t *workers;
  vperf_session_t *ctrl;
  vperf_server_cfg_t server_cfg;
  int ctrl_listen_fd;
  struct sockaddr_storage servaddr;
  volatile int worker_fails;
  volatile int active_workers;
  u8 use_ds;
  u8 incremental_stats;
} vperf_server_main_t;

vperf_main_t vperf_main;

static vperf_server_main_t vperf_server_main;

static inline void
conn_pool_expand (vperf_server_worker_t *wrk, size_t expand_size)
{
  vperf_session_t *conn_pool;
  size_t new_size = wrk->conn_pool_size + expand_size;
  int i;

  conn_pool = realloc (wrk->conn_pool, new_size * sizeof (*wrk->conn_pool));
  if (conn_pool)
    {
      for (i = wrk->conn_pool_size; i < new_size; i++)
	{
	  vperf_session_t *conn = &conn_pool[i];
	  memset (conn, 0, sizeof (*conn));
	}

      wrk->conn_pool = conn_pool;
      wrk->conn_pool_size = new_size;
    }
  else
    {
      vperf_err ("conn_pool_expand()", -errno);
    }
}

static inline vperf_session_t *
conn_pool_alloc (vperf_server_worker_t *wrk)
{
  vperf_session_t *conn;
  int i, expand = 0;

again:
  for (i = 0; i < wrk->conn_pool_size; i++)
    {
      if (!wrk->conn_pool[i].is_alloc)
	{
	  conn = &wrk->conn_pool[i];
	  memset (conn, 0, sizeof (*conn));
	  conn->endpt.ip = wrk->conn_pool[i].ip;
	  conn->is_alloc = 1;
	  conn->session_index = i;
	  vperf_cfg_init (&conn->cfg);
	  return (&wrk->conn_pool[i]);
	}
    }

  if (expand == 0)
    {
      conn_pool_expand (wrk, 2 * wrk->conn_pool_size);
      expand = 1;
      goto again;
    }
  vperf_warn ("Failed to allocate connection even after expand");
  return 0;
}

static inline void
conn_pool_free (vperf_session_t *ts)
{
  ts->fd = 0;
  ts->is_alloc = 0;
  vperf_session_buf_free (ts);
}

static inline void
sync_config_and_reply (vperf_session_t *conn, vperf_cfg_t *rx_cfg)
{
  conn->cfg = *rx_cfg;
  vperf_buf_alloc (&conn->cfg, 1 /* is_rxbuf */, (uint8_t **) &conn->rxbuf, &conn->rxbuf_size);
  conn->cfg.txbuf_size = conn->cfg.rxbuf_size;

  if (conn->cfg.verbose)
    {
      vperf_info ("(fd %d): Replying to cfg message!\n", conn->fd);
      vperf_cfg_dump (&conn->cfg, 0 /* is_client */);
    }
  (void) vperf_write (conn, &conn->cfg, sizeof (conn->cfg));
}

static void
vperf_server_session_close (vperf_session_t *conn)
{
  vperf_server_main_t *vsm = &vperf_server_main;
  vperf_main_t *vt = &vperf_main;

  if (!conn->is_open)
    return;

  if (vt->protos[vsm->server_cfg.proto]->cleanup)
    vt->protos[vsm->server_cfg.proto]->cleanup (conn);

  vppcom_session_close (conn->fd);
  conn->is_open = 0;
}

static void
vperf_server_session_cleanup (vperf_session_t *ts)
{
  vperf_server_session_close (ts);
  conn_pool_free (ts);
}

static void
vperf_server_wrk_cleanup_all (vperf_server_worker_t *wrk)
{
  vperf_session_t *conn;
  int i;

  for (i = 0; i < wrk->conn_pool_size; i++)
    {
      conn = &wrk->conn_pool[i];
      vperf_server_session_cleanup (conn);
    }

  wrk->nfds = 0;
}

static void
vperf_server_test_cmd (vperf_server_worker_t *wrk, vperf_session_t *conn, vperf_cfg_t *rx_cfg)
{
  u8 is_bi = rx_cfg->test == VPERF_TEST_TYPE_BI;
  vperf_session_t *tc;
  char buf[64];
  int i;

  if (rx_cfg->cmd == VPERF_CMD_STOP)
    {
      struct timespec stop;
      clock_gettime (CLOCK_REALTIME, &stop);

      /* Test session are not closed, e.g., connection-less or errors */
      if (wrk->nfds > 1)
	{
	  vperf_info ("%u sessions are still open", wrk->nfds - 1);
	  stop.tv_sec -= VPERF_DELAY_DISCONNECT;
	  conn->stats.stop = stop;
	}

      /* Accumulate stats over all of the worker's sessions */
      for (i = 0; i < wrk->conn_pool_size; i++)
	{
	  tc = &wrk->conn_pool[i];
	  if (tc == conn)
	    continue;

	  vperf_stats_accumulate (&conn->stats, &tc->stats);
	  if (tc->is_open)
	    {
	      vperf_server_session_cleanup (tc);
	      wrk->nfds--;
	      continue;
	    }
	  /* Only relevant if all connections previously closed */
	  if (vcl_comp_tspec (&conn->stats.stop, &tc->stats.stop) < 0)
	    conn->stats.stop = tc->stats.stop;
	}

      if (conn->cfg.verbose)
	{
	  snprintf (buf, sizeof (buf), "SERVER (fd %d) RESULTS", conn->fd);
	  vperf_stats_dump (buf, &conn->stats, 1 /* show_rx */, is_bi /* show tx */,
			    conn->cfg.verbose);
	}

      vperf_stats_dump ("SERVER RESULTS", &conn->stats, 1 /* show_rx */, is_bi /* show_tx */,
			conn->cfg.verbose);
      vperf_cfg_dump (&conn->cfg, 0 /* is_client */);
      if (conn->cfg.verbose)
	{
	  vperf_info ("  vcl server main\n" VPERF_SEPARATOR_STRING "       buf:  %p\n"
		      "  buf size:  %u (0x%08x)\n" VPERF_SEPARATOR_STRING,
		      conn->rxbuf, conn->rxbuf_size, conn->rxbuf_size);
	}

      conn->is_done = 1;
      sync_config_and_reply (conn, rx_cfg);
    }
  else if (rx_cfg->cmd == VPERF_CMD_SYNC)
    {
      rx_cfg->ctrl_handle = conn->fd;
      vperf_info ("Set control fd %d for test!", conn->fd);
      sync_config_and_reply (conn, rx_cfg);
    }
  else if (rx_cfg->cmd == VPERF_CMD_START)
    {
      vperf_info ("Starting %s-directional Stream Test (fd %d)!", is_bi ? "Bi" : "Uni", conn->fd);
      rx_cfg->ctrl_handle = conn->fd;
      sync_config_and_reply (conn, rx_cfg);

      /* read the 1st chunk, record start time */
      memset (&conn->stats, 0, sizeof (conn->stats));
      clock_gettime (CLOCK_REALTIME, &conn->stats.start);
    }
}

static inline void
vperf_server_server_process_rx (vperf_session_t *conn, int rx_bytes)
{
  vperf_server_main_t *vsm = &vperf_server_main;

  if (conn->cfg.test == VPERF_TEST_TYPE_BI)
    {
      if (vsm->use_ds)
	(void) vperf_write_ds (conn);
      else
	(void) conn->write (conn, conn->rxbuf, rx_bytes);
    }

  if (vsm->use_ds)
    vppcom_session_free_segments (conn->fd, rx_bytes);

  if (conn->stats.rx_bytes >= conn->cfg.total_bytes)
    clock_gettime (CLOCK_REALTIME, &conn->stats.stop);
}

static void
vperf_server_echo (vperf_session_t *conn, int rx_bytes)
{
  int tx_bytes, nbytes, pos;

  /* If it looks vaguely like a string, make sure it's terminated */
  pos = rx_bytes < conn->rxbuf_size ? rx_bytes : conn->rxbuf_size - 1;
  ((char *) conn->rxbuf)[pos] = 0;
  vperf_info ("(fd %d): RX (%d bytes) - '%s'", conn->fd, rx_bytes, conn->rxbuf);

  if (conn->cfg.verbose)
    vperf_info ("(fd %d): Echoing back", conn->fd);

  nbytes = strlen ((const char *) conn->rxbuf) + 1;
  tx_bytes = conn->write (conn, conn->rxbuf, nbytes);
  if (tx_bytes >= 0)
    vperf_info ("(fd %d): TX (%d bytes) - '%s'", conn->fd, tx_bytes, conn->rxbuf);
}

static vperf_session_t *
vperf_server_accept_ctrl (vperf_server_worker_t *wrk, int listen_fd)
{
  vperf_server_main_t *vsm = &vperf_server_main;
  const vperf_proto_vft_t *tp;
  vperf_session_t *conn;
  struct epoll_event ev;
  int rv;

  conn = conn_pool_alloc (wrk);
  if (!conn)
    {
      vperf_warn ("No free connections!");
      return 0;
    }

  if (vsm->ctrl)
    conn->cfg = vsm->ctrl->cfg;
  vperf_session_buf_alloc (conn);
  clock_gettime (CLOCK_REALTIME, &conn->old_stats.stop);

  tp = vperf_main.protos[VPPCOM_PROTO_TCP];
  if (tp->accept (listen_fd, conn))
    return 0;

  vperf_info ("CTRL accepted fd = %d (0x%08x) on listener fd = %d (0x%08x)", conn->fd, conn->fd,
	      listen_fd, listen_fd);

  ev.events = EPOLLET | EPOLLIN;
  ev.data.u64 = conn - wrk->conn_pool;
  rv = vppcom_epoll_ctl (wrk->epfd, EPOLL_CTL_ADD, conn->fd, &ev);
  if (rv < 0)
    {
      vperf_err ("vppcom_epoll_ctl()", rv);
      return 0;
    }

  wrk->nfds++;

  return conn;
}

static vperf_session_t *
vperf_server_accept_client (vperf_server_worker_t *wrk, int listen_fd)
{
  vperf_server_main_t *vsm = &vperf_server_main;
  const vperf_proto_vft_t *tp;
  vperf_session_t *conn;
  struct epoll_event ev;
  int rv;

  conn = conn_pool_alloc (wrk);
  if (!conn)
    {
      vperf_warn ("No free connections!");
      return 0;
    }

  if (vsm->ctrl)
    conn->cfg = vsm->ctrl->cfg;
  vperf_session_buf_alloc (conn);
  clock_gettime (CLOCK_REALTIME, &conn->old_stats.stop);

  tp = vperf_main.protos[vsm->server_cfg.proto];
  if (tp->accept (listen_fd, conn))
    return 0;

  if (conn->cfg.num_test_sessions < VPERF_CFG_MAX_SELECT_SESS)
    vperf_info ("Got a connection -- fd = %d (0x%08x) on listener fd = %d (0x%08x)", conn->fd,
		conn->fd, listen_fd, listen_fd);

  ev.events = EPOLLET | EPOLLIN | EPOLLRDHUP;
  ev.data.u64 = conn - wrk->conn_pool;
  rv = vppcom_epoll_ctl (wrk->epfd, EPOLL_CTL_ADD, conn->fd, &ev);
  if (rv < 0)
    {
      vperf_err ("vppcom_epoll_ctl()", rv);
      return 0;
    }
  wrk->nfds++;

  return conn;
}

static void
print_usage_and_exit (void)
{
  fprintf (stderr, "vperf_server [OPTIONS] <port>\n"
		   "  OPTIONS\n"
		   "  -h               Print this message and exit.\n"
		   "  -6               Use IPv6\n"
		   "  -w <num>         Number of workers\n"
		   "  -p <PROTO>       Use <PROTO> transport layer\n"
		   "  -D               Use UDP transport layer\n"
		   "  -L               Use TLS transport layer\n"
		   "  -S	       Incremental stats\n");
  exit (1);
}

static void
vperf_init_endpoint_addr (vperf_server_main_t *vsm)
{
  struct sockaddr_storage *servaddr = &vsm->servaddr;

  if (vsm->server_cfg.address_ip6)
    {
      struct sockaddr_in6 *server_addr = (struct sockaddr_in6 *) servaddr;
      vsm->server_cfg.endpt.is_ip4 = 0;
      vsm->server_cfg.endpt.ip = (uint8_t *) &server_addr->sin6_addr;
      vsm->server_cfg.endpt.port = htons (vsm->server_cfg.port);
    }
  else
    {
      struct sockaddr_in *server_addr = (struct sockaddr_in *) servaddr;
      vsm->server_cfg.endpt.is_ip4 = 1;
      vsm->server_cfg.endpt.ip = (uint8_t *) &server_addr->sin_addr;
      vsm->server_cfg.endpt.port = htons (vsm->server_cfg.port);
    }
}

static void
vperf_clear_endpoint_addr (vperf_server_main_t *vsm)
{
  struct sockaddr_storage *servaddr = &vsm->servaddr;

  memset (&vsm->servaddr, 0, sizeof (vsm->servaddr));

  if (vsm->server_cfg.address_ip6)
    {
      struct sockaddr_in6 *server_addr = (struct sockaddr_in6 *) servaddr;
      server_addr->sin6_family = AF_INET6;
      server_addr->sin6_addr = in6addr_any;
    }
  else
    {
      struct sockaddr_in *server_addr = (struct sockaddr_in *) servaddr;
      server_addr->sin_family = AF_INET;
      server_addr->sin_addr.s_addr = htonl (INADDR_ANY);
    }
}

static void
vperf_server_process_opts (vperf_server_main_t *vsm, int argc, char **argv)
{
  int v, c;

  vsm->server_cfg.proto = VPPCOM_PROTO_TCP;
  vperf_clear_endpoint_addr (vsm);

  opterr = 0;
  while ((c = getopt (argc, argv, "6DLsw:hp:SB:")) != -1)
    switch (c)
      {
      case '6':
	vsm->server_cfg.address_ip6 = 1;
	break;

      case 'p':
	if (vppcom_unformat_proto (&vsm->server_cfg.proto, optarg))
	  vperf_warn ("Invalid vppcom protocol %s, defaulting to TCP", optarg);
	break;
      case 'B':
	if (vsm->server_cfg.address_ip6)
	  {
	    if (inet_pton (
		  AF_INET6, optarg,
		  &((struct sockaddr_in6 *) &vsm->servaddr)->sin6_addr) != 1)
	      vperf_warn ("couldn't parse ipv6 addr %s", optarg);
	  }
	else
	  {
	    if (inet_pton (
		  AF_INET, optarg,
		  &((struct sockaddr_in *) &vsm->servaddr)->sin_addr) != 1)
	      vperf_warn ("couldn't parse ipv4 addr %s", optarg);
	  }
	break;
      case 'D':
	vsm->server_cfg.proto = VPPCOM_PROTO_UDP;
	break;

      case 'L':
	vsm->server_cfg.proto = VPPCOM_PROTO_TLS;
	break;

      case 'w':
	v = atoi (optarg);
	if (v > 1)
	  vsm->server_cfg.workers = v;
	else
	  vperf_warn ("Invalid number of workers %d", v);
	break;
      case 's':
	vsm->use_ds = 1;
	break;
      case 'S':
	vsm->incremental_stats = 1;
	break;
      case '?':
	switch (optopt)
	  {
	  case 'w':
	  case 'p':
	    vperf_warn ("Option `-%c' requires an argument.", optopt);
	    break;
	  default:
	    if (isprint (optopt))
	      vperf_warn ("Unknown option `-%c'.", optopt);
	    else
	      vperf_warn ("Unknown option character `\\x%x'.", optopt);
	  }
	/* fall thru */
      case 'h':
      default:
	print_usage_and_exit ();
      }

  if (argc > (optind + 1))
    {
      fprintf (stderr, "Incorrect number of arguments!\n");
      print_usage_and_exit ();
    }
  else if (argc > 1 && argc == (optind + 1))
    {
      if (sscanf (argv[optind], "%d", &v) == 1)
	vsm->server_cfg.port = (uint16_t) v;
      else
	{
	  fprintf (stderr, "Invalid port (%s)!\n", argv[optind]);
	  print_usage_and_exit ();
	}
    }

  vperf_init_endpoint_addr (vsm);
}

int
vperf_server_handle_ctrl_cfg (vperf_server_worker_t *wrk, vperf_cfg_t *rx_cfg,
			      vperf_session_t *conn, int rx_bytes)
{
  if (rx_cfg->verbose)
    {
      vperf_info ("(fd %d): Received a cfg msg!", conn->fd);
      vperf_cfg_dump (rx_cfg, 0 /* is_client */);
    }

  if (rx_bytes != sizeof (*rx_cfg))
    {
      vperf_info ("(fd %d): Invalid cfg msg size %d expected %lu!", conn->fd, rx_bytes,
		  sizeof (*rx_cfg));
      conn->cfg.rxbuf_size = 0;
      conn->cfg.num_writes = 0;
      if (conn->cfg.verbose)
	{
	  vperf_info ("(fd %d): Replying to cfg msg", conn->fd);
	  vperf_cfg_dump (rx_cfg, 0 /* is_client */);
	}
      conn->write (conn, &conn->cfg, sizeof (conn->cfg));
      return -1;
    }

  switch (rx_cfg->test)
    {
    case VPERF_TEST_TYPE_NONE:
    case VPERF_TEST_TYPE_ECHO:
      /* post-test sync, send our rx stats to the client, builtin echo use it to show datagram loss
       * rate */
      if (conn->is_done)
	{
	  rx_cfg->total_bytes = conn->stats.rx_bytes;
	  rx_cfg->num_reads = conn->stats.rx_xacts;
	  memset (&conn->stats, 0, sizeof (conn->stats));
	}
      sync_config_and_reply (conn, rx_cfg);
      break;

    case VPERF_TEST_TYPE_BI:
    case VPERF_TEST_TYPE_UNI:
      vperf_server_test_cmd (wrk, conn, rx_cfg);
      break;

    case VPERF_TEST_TYPE_EXIT:
      vperf_info ("Ctrl session fd %d closing!", conn->fd);
      vperf_server_session_cleanup (conn);
      wrk->nfds--;
      if (wrk->nfds)
	vperf_server_wrk_cleanup_all (wrk);
      vperf_server_main.ctrl = 0;
      break;

    default:
      vperf_warn ("Unknown test type %d", rx_cfg->test);
      vperf_cfg_dump (rx_cfg, 0 /* is_client */);
      break;
    }

  return 0;
}

static void
vperf_server_worker_init (vperf_server_worker_t *wrk)
{
  vperf_server_main_t *vsm = &vperf_server_main;
  vperf_main_t *vt = &vperf_main;
  const vperf_proto_vft_t *tp;
  struct epoll_event listen_ev;
  int rv;

  __wrk_index = wrk->wrk_index;

  vperf_info ("Initializing worker ...");

  conn_pool_expand (wrk, VPERF_CFG_INIT_TEST_SESS + 1);
  if (wrk->wrk_index)
    if (vppcom_worker_register ())
      vperf_fail ("vppcom_worker_register()", 1);

  tp = vt->protos[vsm->server_cfg.proto];
  if ((rv = tp->listen (&wrk->listener, &vsm->server_cfg.endpt)))
    vperf_fail ("proto listen", rv);

  /* First worker already has epoll fd */
  if (wrk->wrk_index)
    {
      wrk->epfd = vppcom_epoll_create ();
      if (wrk->epfd < 0)
	vperf_fail ("vppcom_epoll_create()", wrk->epfd);
    }

  listen_ev.events = EPOLLET | EPOLLIN;
  listen_ev.data.u32 = VPERF_DATA_LISTENER;
  rv =
    vppcom_epoll_ctl (wrk->epfd, EPOLL_CTL_ADD, wrk->listener.fd, &listen_ev);
  if (rv < 0)
    vperf_fail ("vppcom_epoll_ctl", rv);

  vsm->active_workers += 1;
  vperf_info ("Waiting for client data connections on port %d ...",
	      ntohs (vsm->server_cfg.endpt.port));
}

static inline int
vperf_server_conn_read (vperf_session_t *conn)
{
  vperf_server_main_t *vsm = &vperf_server_main;
  if (vsm->use_ds)
    return vperf_read_ds (conn);
  else
    return conn->read (conn, conn->rxbuf, conn->rxbuf_size);
}

static void
vperf_server_inc_stats_check (vperf_session_t *ts)
{
  /* Avoid checking time too often because of syscall cost */
  if (ts->stats.rx_bytes - ts->old_stats.rx_bytes < 1 << 20)
    return;

  clock_gettime (CLOCK_REALTIME, &ts->stats.stop);
  if (vperf_time_diff (&ts->old_stats.stop, &ts->stats.stop) > 1)
    {
      vperf_stats_dump_inc (ts, 1 /* is_rx */);
      ts->old_stats = ts->stats;
    }
}

static inline void
vperf_server_worker_write_test_data (vperf_server_worker_t *wrk)
{
  vperf_server_main_t *vsm = &vperf_server_main;
  vperf_session_t *conn;
  int i;

  if (vsm->ctrl && vsm->ctrl->cfg.test == VPERF_TEST_TYPE_BI &&
      vperf_main.server_data_source == VPERF_TEST_DATA_SOURCE)
    {
      for (i = 0; i < wrk->conn_pool_size; i++)
	{
	  conn = &wrk->conn_pool[i];
	  if (conn == vsm->ctrl)
	    continue;
	  if (conn->is_open)
	    (void) conn->write (conn, 0, 0);
	}
    }
}

static void *
vperf_server_worker_loop (void *arg)
{
  struct epoll_event ep_evts[VPERF_CFG_MAX_EPOLL_EVENTS];
  vperf_server_main_t *vsm = &vperf_server_main;
  vperf_server_worker_t *wrk = arg;
  vperf_session_t *conn;
  int i, rx_bytes, num_ev;
  vperf_cfg_t *rx_cfg;
  const vperf_proto_vft_t *tp;

  if (wrk->wrk_index)
    vperf_server_worker_init (wrk);

  tp = vperf_main.protos[vsm->server_cfg.proto];

  while (1)
    {
      num_ev = vppcom_epoll_wait (wrk->epfd, ep_evts, VPERF_CFG_MAX_EPOLL_EVENTS,
				  0 /* poll session events */);
      if (num_ev < 0)
	{
	  vperf_err ("vppcom_epoll_wait()", num_ev);
	  goto fail;
	}
      else if (num_ev == 0)
	{
	  /* if we want to send test data without reading do it now */
	  vperf_server_worker_write_test_data (wrk);
	  continue;
	}
      for (i = 0; i < num_ev; i++)
	{
	  conn = &wrk->conn_pool[ep_evts[i].data.u32];
	  /*
	   * Check for close events
	   */
	  if (ep_evts[i].events & (EPOLLHUP | EPOLLRDHUP))
	    {
	      if (conn == vsm->ctrl)
		{
		  vperf_info ("ctrl session went away");
		  vsm->ctrl = 0;
		  vperf_server_wrk_cleanup_all (wrk);
		}
	      else
		{
		  /* if close return 1 we can delete session, otherwise keep
		   * session (e.g. quic half-close stream) */
		  if (!tp->close (conn, ep_evts[i].events))
		    continue;
		  vperf_info ("deleting %d (fd %d)", conn->session_index, conn->fd);
		  vperf_server_session_cleanup (conn);
		  wrk->nfds--;
		}
	      continue;
	    }

	  /*
	   * Check if new session needs to be accepted
	   */

	  if (!wrk->wrk_index && ep_evts[i].data.u32 == VPERF_CTRL_LISTENER)
	    {
	      if (vsm->ctrl)
		{
		  vperf_warn ("ctrl already exists");
		  continue;
		}
	      vsm->ctrl = vperf_server_accept_ctrl (wrk, vsm->ctrl_listen_fd);
	      continue;
	    }

	  /* drop event if we don't have ctrl session in place first */
	  if (!vsm->ctrl)
	    continue;

	  if (ep_evts[i].data.u32 == VPERF_DATA_LISTENER)
	    {
	      conn = vperf_server_accept_client (wrk, wrk->listener.fd);
	      conn->cfg = vsm->ctrl->cfg;
	      continue;
	    }
	  else if (vppcom_session_is_connectable_listener (conn->fd))
	    {
	      while (vperf_server_accept_client (wrk, conn->fd))
		;
	      continue;
	    }

	  /*
	   * Message on control session
	   */

	  if (!wrk->wrk_index && conn->fd == vsm->ctrl->fd)
	    {
	      rx_bytes =
		vppcom_session_read (conn->fd, conn->rxbuf, conn->rxbuf_size);
	      rx_cfg = (vperf_cfg_t *) conn->rxbuf;
	      if (rx_cfg->magic == VPERF_CFG_CTRL_MAGIC)
		{
		  vperf_server_handle_ctrl_cfg (wrk, rx_cfg, conn, rx_bytes);
		  if (!wrk->nfds)
		    {
		      vperf_info ("All client connections closed\n");
		      goto done;
		    }
		}
	      else if (isascii (conn->rxbuf[0]))
		{
		  vperf_server_echo (conn, rx_bytes);
		}
	      else
		{
		  vperf_warn ("FIFO not drained! extra bytes %d", rx_bytes);
		}
	      continue;
	    }

	  /*
	   * Read perf test data
	   */

	  if (EPOLLIN & ep_evts[i].events)
	    {
	    read_again:
	      rx_bytes = vperf_server_conn_read (conn);

	      if (rx_bytes <= 0)
		{
		  if (errno == ECONNRESET)
		    {
		      /* if reset return 1 it was not expected (failure) */
		      if (!tp->reset (conn))
			continue;
		      vperf_info ("Connection reset by remote peer.\n");
		      goto fail;
		    }
		  else
		    continue;
		}
	      vperf_server_server_process_rx (conn, rx_bytes);
	      if (vppcom_session_attr (conn->fd, VPPCOM_ATTR_GET_NREAD, 0, 0) >
		  0)
		goto read_again;
	      if (vsm->incremental_stats)
		vperf_server_inc_stats_check (conn);
	      continue;
	    }
	  else
	    {
	      vperf_warn ("Unhandled event");
	      goto fail;
	    }
	}
    }

fail:
  vsm->worker_fails -= 1;

done:
  vppcom_session_close (wrk->listener.fd);
  if (wrk->conn_pool)
    {
      if (!wrk->wrk_index)
	vsm->ctrl = 0;
      free (wrk->conn_pool);
    }
  vsm->active_workers -= 1;
  return 0;
}

static void
vperf_server_ctrl_session_init (vperf_server_worker_t *wrk)
{
  vperf_server_main_t *vsm = &vperf_server_main;
  struct epoll_event listen_ev;
  int rv;

  vperf_info ("Initializing main ctrl session ...");

  vsm->ctrl_listen_fd =
    vppcom_session_create (VPPCOM_PROTO_TCP, 0 /* is_nonblocking */);
  if (vsm->ctrl_listen_fd < 0)
    vperf_fail ("vppcom_session_create()", vsm->ctrl_listen_fd);

  rv = vppcom_session_bind (vsm->ctrl_listen_fd, &vsm->server_cfg.endpt);
  if (rv < 0)
    vperf_fail ("vppcom_session_bind()", rv);

  rv = vppcom_session_listen (vsm->ctrl_listen_fd, 10);
  if (rv < 0)
    vperf_fail ("vppcom_session_listen()", rv);

  wrk->epfd = vppcom_epoll_create ();
  if (wrk->epfd < 0)
    vperf_fail ("vppcom_epoll_create()", wrk->epfd);

  listen_ev.events = EPOLLET | EPOLLIN;
  listen_ev.data.u32 = VPERF_CTRL_LISTENER;
  rv = vppcom_epoll_ctl (wrk->epfd, EPOLL_CTL_ADD, vsm->ctrl_listen_fd,
			 &listen_ev);
  if (rv < 0)
    vperf_fail ("vppcom_epoll_ctl", rv);

  vperf_info ("Waiting for client ctrl connection on port %d ...", vsm->server_cfg.port);
}

int
main (int argc, char **argv)
{
  vperf_server_main_t *vsm = &vperf_server_main;
  vperf_main_t *vt = &vperf_main;
  int rv, i;

  vsm->server_cfg.port = VPERF_SERVER_PORT;
  vsm->server_cfg.workers = 1;
  vsm->active_workers = 0;
  vperf_server_process_opts (vsm, argc, argv);

  rv = vppcom_app_create ("vperf_server");
  if (rv)
    vperf_fail ("vppcom_app_create()", rv);

  /* Protos like tls/dtls/quic need init */
  if (vt->protos[vsm->server_cfg.proto]->init)
    vt->protos[vsm->server_cfg.proto]->init (0);

  vsm->workers = calloc (vsm->server_cfg.workers, sizeof (*vsm->workers));
  vperf_server_ctrl_session_init (&vsm->workers[0]);

  /* Update ctrl port to data port */
  vsm->server_cfg.endpt.port = vperf_make_data_port (vsm->server_cfg.endpt.port);
  vperf_server_worker_init (&vsm->workers[0]);
  for (i = 1; i < vsm->server_cfg.workers; i++)
    {
      vsm->workers[i].wrk_index = i;
      rv = pthread_create (&vsm->workers[i].thread_handle, NULL, vperf_server_worker_loop,
			   (void *) &vsm->workers[i]);
      if (rv)
	vperf_fail ("pthread_create()", rv);
    }

  vperf_server_worker_loop (&vsm->workers[0]);

  while (vsm->active_workers > 0)
    ;

  vppcom_app_destroy ();
  free (vsm->workers);

  return vsm->worker_fails;
}
