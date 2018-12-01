/*
 * Copyright (c) 2017-2018 Cisco and/or its affiliates.
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
#include <vcl/vcl_test.h>
#include <sys/epoll.h>
#include <vppinfra/mem.h>
#include <pthread.h>

typedef struct
{
  uint8_t is_alloc;
  int fd;
  uint8_t *buf;
  uint32_t buf_size;
  vcl_test_cfg_t cfg;
  vcl_test_stats_t stats;
  vppcom_endpt_t endpt;
  uint8_t ip[16];
  vppcom_data_segments_t ds;
} vcl_test_server_conn_t;

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
  int listen_fd;
  int epfd;
  struct epoll_event wait_events[VCL_TEST_CFG_MAX_EPOLL_EVENTS];
  size_t conn_pool_size;
  vcl_test_server_conn_t *conn_pool;
  int nfds;
  pthread_t thread_handle;
} vcl_test_server_worker_t;

typedef struct
{
  vcl_test_server_cfg_t cfg;
  vcl_test_server_worker_t *workers;

  struct sockaddr_storage servaddr;
  volatile int worker_fails;
  volatile int active_workers;
  u8 use_ds;
} vcl_test_server_main_t;

static __thread int __wrk_index = 0;

static vcl_test_server_main_t vcl_server_main;

static inline void
conn_pool_expand (vcl_test_server_worker_t * wrk, size_t expand_size)
{
  vcl_test_server_conn_t *conn_pool;
  size_t new_size = wrk->conn_pool_size + expand_size;
  int i;

  conn_pool = realloc (wrk->conn_pool, new_size * sizeof (*wrk->conn_pool));
  if (conn_pool)
    {
      for (i = wrk->conn_pool_size; i < new_size; i++)
	{
	  vcl_test_server_conn_t *conn = &conn_pool[i];
	  memset (conn, 0, sizeof (*conn));
	  vcl_test_cfg_init (&conn->cfg);
	  vcl_test_buf_alloc (&conn->cfg, 1 /* is_rxbuf */ ,
			      &conn->buf, &conn->buf_size);
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

static inline vcl_test_server_conn_t *
conn_pool_alloc (vcl_test_server_worker_t * wrk)
{
  int i, expand = 0;

again:
  for (i = 0; i < wrk->conn_pool_size; i++)
    {
      if (!wrk->conn_pool[i].is_alloc)
	{
	  wrk->conn_pool[i].endpt.ip = wrk->conn_pool[i].ip;
	  wrk->conn_pool[i].is_alloc = 1;
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
conn_pool_free (vcl_test_server_conn_t * conn)
{
  conn->fd = 0;
  conn->is_alloc = 0;
}

static inline void
sync_config_and_reply (vcl_test_server_conn_t * conn, vcl_test_cfg_t * rx_cfg)
{
  conn->cfg = *rx_cfg;
  vcl_test_buf_alloc (&conn->cfg, 1 /* is_rxbuf */ ,
		      &conn->buf, &conn->buf_size);
  conn->cfg.txbuf_size = conn->cfg.rxbuf_size;

  if (conn->cfg.verbose)
    {
      vtinf ("(fd %d): Replying to cfg message!\n", conn->fd);
      vcl_test_cfg_dump (&conn->cfg, 0 /* is_client */ );
    }
  (void) vcl_test_write (conn->fd, (uint8_t *) & conn->cfg,
			 sizeof (conn->cfg), NULL, conn->cfg.verbose);
}

static void
vts_server_start_stop (vcl_test_server_worker_t * wrk,
		       vcl_test_server_conn_t * conn, vcl_test_cfg_t * rx_cfg)
{
  u8 is_bi = rx_cfg->test == VCL_TEST_TYPE_BI;
  vcl_test_server_conn_t *tc;
  char buf[64];
  int i;

  if (rx_cfg->ctrl_handle == conn->fd)
    {
      for (i = 0; i < wrk->conn_pool_size; i++)
	{
	  tc = &wrk->conn_pool[i];
	  if (tc->cfg.ctrl_handle != conn->fd)
	    continue;

	  vcl_test_stats_accumulate (&conn->stats, &tc->stats);
	  if (vcl_comp_tspec (&conn->stats.stop, &tc->stats.stop) < 0)
	    conn->stats.stop = tc->stats.stop;
	  /* Client delays sending of disconnect */
	  conn->stats.stop.tv_sec -= VCL_TEST_DELAY_DISCONNECT;
	  if (conn->cfg.verbose)
	    {
	      sprintf (buf, "SERVER (fd %d) RESULTS", tc->fd);
	      vcl_test_stats_dump (buf, &tc->stats, 1 /* show_rx */ ,
				   is_bi /* show tx */ , conn->cfg.verbose);
	    }
	}

      vcl_test_stats_dump ("SERVER RESULTS", &conn->stats, 1 /* show_rx */ ,
			   is_bi /* show_tx */ , conn->cfg.verbose);
      vcl_test_cfg_dump (&conn->cfg, 0 /* is_client */ );
      if (conn->cfg.verbose)
	{
	  vtinf ("  vcl server main\n"
		 VCL_TEST_SEPARATOR_STRING
		 "       buf:  %p\n"
		 "  buf size:  %u (0x%08x)\n"
		 VCL_TEST_SEPARATOR_STRING,
		 conn->buf, conn->buf_size, conn->buf_size);
	}

      sync_config_and_reply (conn, rx_cfg);
      memset (&conn->stats, 0, sizeof (conn->stats));
    }
  else
    {
      if (rx_cfg->ctrl_handle == ~0)
	{
	  rx_cfg->ctrl_handle = conn->fd;
	  vtinf ("Set control fd %d for test!", conn->fd);
	}
      else
	{
	  vtinf ("Starting %s-directional Stream Test (fd %d)!",
		 is_bi ? "Bi" : "Uni", conn->fd);
	}

      sync_config_and_reply (conn, rx_cfg);

      /* read the 1st chunk, record start time */
      memset (&conn->stats, 0, sizeof (conn->stats));
      clock_gettime (CLOCK_REALTIME, &conn->stats.start);
    }
}

static inline void
vts_server_rx (vcl_test_server_conn_t * conn, int rx_bytes)
{
  vcl_test_server_main_t *vsm = &vcl_server_main;
  int client_fd = conn->fd;

  if (conn->cfg.test == VCL_TEST_TYPE_BI)
    {
      if (vsm->use_ds)
	{
	  (void) vcl_test_write (client_fd, conn->ds[0].data, conn->ds[0].len,
				 &conn->stats, conn->cfg.verbose);
	  if (conn->ds[1].len)
	    (void) vcl_test_write (client_fd, conn->ds[1].data,
				   conn->ds[1].len, &conn->stats,
				   conn->cfg.verbose);
	}
      else
	(void) vcl_test_write (client_fd, conn->buf, rx_bytes, &conn->stats,
			       conn->cfg.verbose);
    }

  if (vsm->use_ds)
    vppcom_session_free_segments (conn->fd, conn->ds);

  if (conn->stats.rx_bytes >= conn->cfg.total_bytes)
    clock_gettime (CLOCK_REALTIME, &conn->stats.stop);
}

static void
vts_server_echo (vcl_test_server_conn_t * conn, int rx_bytes)
{
  vcl_test_server_main_t *vsm = &vcl_server_main;
  int tx_bytes, nbytes, pos;

  if (vsm->use_ds)
    vppcom_data_segment_copy (conn->buf, conn->ds, rx_bytes);

  /* If it looks vaguely like a string, make sure it's terminated */
  pos = rx_bytes < conn->buf_size ? rx_bytes : conn->buf_size - 1;
  ((char *) conn->buf)[pos] = 0;
  vtinf ("(fd %d): RX (%d bytes) - '%s'", conn->fd, rx_bytes, conn->buf);

  if (conn->cfg.verbose)
    vtinf ("(fd %d): Echoing back", conn->fd);

  nbytes = strlen ((const char *) conn->buf) + 1;
  tx_bytes = vcl_test_write (conn->fd, conn->buf, nbytes, &conn->stats,
			     conn->cfg.verbose);
  if (tx_bytes >= 0)
    vtinf ("(fd %d): TX (%d bytes) - '%s'", conn->fd, tx_bytes, conn->buf);
}

static void
vts_new_client (vcl_test_server_worker_t * wrk)
{
  vcl_test_server_conn_t *conn;
  struct epoll_event ev;
  int rv, client_fd;

  conn = conn_pool_alloc (wrk);
  if (!conn)
    {
      vtwrn ("No free connections!");
      return;
    }

  client_fd = vppcom_session_accept (wrk->listen_fd, &conn->endpt, 0);
  if (client_fd < 0)
    {
      vterr ("vppcom_session_accept()", client_fd);
      return;
    }
  conn->fd = client_fd;

  vtinf ("Got a connection -- fd = %d (0x%08x)!", client_fd, client_fd);

  ev.events = EPOLLIN;
  ev.data.u64 = conn - wrk->conn_pool;
  rv = vppcom_epoll_ctl (wrk->epfd, EPOLL_CTL_ADD, client_fd, &ev);
  if (rv < 0)
    {
      vterr ("vppcom_epoll_ctl()", rv);
      return;
    }
  wrk->nfds++;
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
	   "  -D               Use UDP transport layer\n"
	   "  -S               Use TLS transport layer\n");
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
  while ((c = getopt (argc, argv, "6DSsw:")) != -1)
    switch (c)
      {
      case '6':
	vsm->cfg.address_ip6 = 1;
	break;

      case 'D':
	vsm->cfg.proto = VPPCOM_PROTO_UDP;
	break;

      case 'S':
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

int
vts_handle_cfg (vcl_test_server_worker_t * wrk, vcl_test_cfg_t * rx_cfg,
		vcl_test_server_conn_t * conn, int rx_bytes)
{
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
      vcl_test_write (conn->fd, (uint8_t *) & conn->cfg,
		      sizeof (conn->cfg), NULL, conn->cfg.verbose);
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
      vts_server_start_stop (wrk, conn, rx_cfg);
      break;

    case VCL_TEST_TYPE_EXIT:
      vtinf ("Session fd %d closing!", conn->fd);
      clock_gettime (CLOCK_REALTIME, &conn->stats.stop);
      vppcom_session_close (conn->fd);
      conn_pool_free (conn);
      wrk->nfds--;
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
  int rv;

  __wrk_index = wrk->wrk_index;

  vtinf ("Initializing worker ...");

  conn_pool_expand (wrk, VCL_TEST_CFG_MAX_TEST_SESS + 1);
  if (wrk->wrk_index)
    if (vppcom_worker_register ())
      vtfail ("vppcom_worker_register()", 1);

  wrk->listen_fd = vppcom_session_create (vsm->cfg.proto,
					  0 /* is_nonblocking */ );
  if (wrk->listen_fd < 0)
    vtfail ("vppcom_session_create()", wrk->listen_fd);


  if (vsm->cfg.proto == VPPCOM_PROTO_TLS)
    {
      vppcom_session_tls_add_cert (wrk->listen_fd, vcl_test_crt_rsa,
				   vcl_test_crt_rsa_len);
      vppcom_session_tls_add_key (wrk->listen_fd, vcl_test_key_rsa,
				  vcl_test_key_rsa_len);
    }

  rv = vppcom_session_bind (wrk->listen_fd, &vsm->cfg.endpt);
  if (rv < 0)
    vtfail ("vppcom_session_bind()", rv);

  if (!(vsm->cfg.proto == VPPCOM_PROTO_UDP))
    {
      rv = vppcom_session_listen (wrk->listen_fd, 10);
      if (rv < 0)
	vtfail ("vppcom_session_listen()", rv);
    }

  wrk->epfd = vppcom_epoll_create ();
  if (wrk->epfd < 0)
    vtfail ("vppcom_epoll_create()", wrk->epfd);

  listen_ev.events = EPOLLIN;
  listen_ev.data.u32 = ~0;
  rv = vppcom_epoll_ctl (wrk->epfd, EPOLL_CTL_ADD, wrk->listen_fd,
			 &listen_ev);
  if (rv < 0)
    vtfail ("vppcom_epoll_ctl", rv);

  vsm->active_workers += 1;
  vtinf ("Waiting for a client to connect on port %d ...", vsm->cfg.port);
}

static int
vts_conn_expect_config (vcl_test_server_conn_t * conn)
{
  if (conn->cfg.test == VCL_TEST_TYPE_ECHO)
    return 1;

  return (conn->stats.rx_bytes < 128
	  || conn->stats.rx_bytes > conn->cfg.total_bytes);
}

static vcl_test_cfg_t *
vts_conn_read_config (vcl_test_server_conn_t * conn)
{
  vcl_test_server_main_t *vsm = &vcl_server_main;

  if (vsm->use_ds)
    {
      /* We could avoid the copy if the first segment is big enough but this
       * just simplifies things */
      vppcom_data_segment_copy (conn->buf, conn->ds, sizeof (vcl_test_cfg_t));
    }
  return (vcl_test_cfg_t *) conn->buf;
}

static inline int
vts_conn_read (vcl_test_server_conn_t * conn)
{
  vcl_test_server_main_t *vsm = &vcl_server_main;
  if (vsm->use_ds)
    return vcl_test_read_ds (conn->fd, conn->ds, &conn->stats);
  else
    return vcl_test_read (conn->fd, conn->buf, conn->buf_size, &conn->stats);
}

static inline int
vts_conn_has_ascii (vcl_test_server_conn_t * conn)
{
  vcl_test_server_main_t *vsm = &vcl_server_main;

  if (vsm->use_ds)
    return isascii (conn->ds[0].data[0]);
  else
    return isascii (conn->buf[0]);
}

static void *
vts_worker_loop (void *arg)
{
  vcl_test_server_main_t *vsm = &vcl_server_main;
  vcl_test_server_worker_t *wrk = arg;
  vcl_test_server_conn_t *conn;
  int i, rx_bytes, num_ev;
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
	  if (wrk->wait_events[i].events & (EPOLLHUP | EPOLLRDHUP))
	    {
	      vppcom_session_close (conn->fd);
	      wrk->nfds -= 1;
	      if (!wrk->nfds)
		{
		  vtinf ("All client connections closed\n");
		  goto done;
		}
	      continue;
	    }
	  if (wrk->wait_events[i].data.u32 == ~0)
	    {
	      vts_new_client (wrk);
	      continue;
	    }

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

	      if (vts_conn_expect_config (conn))
		{
		  rx_cfg = vts_conn_read_config (conn);
		  if (rx_cfg->magic == VCL_TEST_CFG_CTRL_MAGIC)
		    {
		      if (vsm->use_ds)
			vppcom_session_free_segments (conn->fd, conn->ds);
		      vts_handle_cfg (wrk, rx_cfg, conn, rx_bytes);
		      if (!wrk->nfds)
			{
			  vtinf ("All client connections closed\n");
			  goto done;
			}
		      continue;
		    }
		}
	      if ((conn->cfg.test == VCL_TEST_TYPE_UNI)
		  || (conn->cfg.test == VCL_TEST_TYPE_BI))
		{
		  vts_server_rx (conn, rx_bytes);
		  if (vppcom_session_attr (conn->fd, VPPCOM_ATTR_GET_NREAD, 0,
					   0) > 0)
		    goto read_again;
		  continue;
		}
	      if (vts_conn_has_ascii (conn))
		{
		  vts_server_echo (conn, rx_bytes);
		}
	      else
		{
		  vtwrn ("FIFO not drained! extra bytes %d", rx_bytes);
		}
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
  vppcom_session_close (wrk->listen_fd);
  if (wrk->conn_pool)
    free (wrk->conn_pool);
  vsm->active_workers -= 1;
  return 0;
}

int
main (int argc, char **argv)
{
  vcl_test_server_main_t *vsm = &vcl_server_main;
  int rv, i;

  clib_mem_init_thread_safe (0, 64 << 20);
  vsm->cfg.port = VCL_TEST_SERVER_PORT;
  vsm->cfg.workers = 1;
  vsm->active_workers = 0;
  vcl_test_server_process_opts (vsm, argc, argv);

  rv = vppcom_app_create ("vcl_test_server");
  if (rv)
    vtfail ("vppcom_app_create()", rv);

  vsm->workers = calloc (vsm->cfg.workers, sizeof (*vsm->workers));
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
