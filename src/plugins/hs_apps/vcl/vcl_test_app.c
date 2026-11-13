/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

/*
 * VCL Test Client/Server with Multi-threading Support
 *
 * Usage:
 *   Server: vcl_test_app -s <server_ip> [-p <proto>] [-w <num_workers>]
 *   Client: vcl_test_app -c <server_ip> [-p <proto>] [-w <num_workers>]
 *
 * Options:
 *   -s <ip>    Start as server bound to specified IP address
 *   -c <ip>    Start as client connecting to specified IP address
 *   -p <proto> Transport protocol, udp (connectionless, default) or tcp
 *   -w <num>   Number of worker threads (default: 1)
 *
 * With tcp, client workers send VTA_TCP_BYTES and wait for an ack. Server
 * workers use level-triggered epoll and read at most VTA_TCP_SRV_READ bytes
 * per event, so data is left in rx fifos across epoll waits.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <vcl/vppcom.h>
#include <vperf/vcl/vperf.h>

#define VTA_TCP_BYTES	     (64 << 10)
#define VTA_TCP_SRV_READ     64
#define VTA_MAX_EPOLL_EVENTS 8

typedef enum vta_type_
{
  VTA_TYPE_NONE = 0,
  VTA_TYPE_SERVER,
  VTA_TYPE_CLIENT,
} vta_type_t;

typedef struct vta_main_
{
  vta_type_t app_type;
  vppcom_endpt_t endpt;
  union
  {
    struct sockaddr_storage srvr_addr;
    struct sockaddr_storage clnt_addr;
  };
  uint16_t port;
  uint8_t dscp;
  uint8_t proto;
  int num_workers;
  pthread_t *worker_threads;
  int thread_id_counter;
  volatile int msgs_received;
} vta_main_t;

static vta_main_t vta_main;
static const uint32_t dscplen = 1;

typedef struct vta_worker_args_
{
  vta_main_t *vtam;
  int worker_id;
} vta_worker_args_t;

typedef struct vta_conn_
{
  int sh;
  uint32_t bytes;
} vta_conn_t;

static void
vta_parse_args (vta_main_t *vtam, int argc, char **argv)
{
  int c;
  int temp;

  memset (vtam, 0, sizeof (*vtam));
  vtam->port = VPERF_SERVER_PORT;
  vtam->num_workers = 1;
  vtam->dscp = 0;
  vtam->proto = VPPCOM_PROTO_UDP;

  opterr = 0;
  while ((c = getopt (argc, argv, "s:c:w:d:p:")) != -1)
    switch (c)
      {
      case 'p':
	if (!strcmp (optarg, "tcp"))
	  vtam->proto = VPPCOM_PROTO_TCP;
	else if (strcmp (optarg, "udp"))
	  vperf_warn ("invalid proto %s, using udp", optarg);
	break;
      case 's':
	vtam->app_type = VTA_TYPE_SERVER;
	if (inet_pton (AF_INET, optarg, &((struct sockaddr_in *) &vtam->srvr_addr)->sin_addr) != 1)
	  vperf_warn ("couldn't parse ipv4 addr %s", optarg);
	break;
      case 'c':
	vtam->app_type = VTA_TYPE_CLIENT;
	if (inet_pton (AF_INET, optarg, &((struct sockaddr_in *) &vtam->clnt_addr)->sin_addr) != 1)
	  vperf_warn ("couldn't parse ipv4 addr %s", optarg);
	break;
      case 'w':
	vtam->num_workers = atoi (optarg);
	if (vtam->num_workers <= 0)
	  {
	    vperf_warn ("invalid number of workers %s", optarg);
	    vtam->num_workers = 1;
	  }
	break;
      case 'd':
	temp = atoi (optarg);
	if (temp <= 0 || temp > 63)
	  {
	    vperf_warn ("invalid dscp value %s", optarg);
	    vtam->dscp = 0;
	  }
	vtam->dscp = temp;
	break;
      }

  if (vtam->app_type == VTA_TYPE_NONE)
    {
      vperf_warn ("client or server must be configured");
      exit (1);
    }

  vtam->endpt.is_ip4 = 1;
  vtam->endpt.ip = (uint8_t *) &((struct sockaddr_in *) &vtam->srvr_addr)->sin_addr;
  vtam->endpt.port = htons (vtam->port);
}

static int
vta_test_done (vta_main_t *vtam)
{
  return vtam->msgs_received >= vtam->num_workers;
}

__thread char ep_ip_str[INET_ADDRSTRLEN + 16];

static char *
vta_ep_to_str (vppcom_endpt_t *ep)
{
  inet_ntop (AF_INET, ep->ip, ep_ip_str, INET_ADDRSTRLEN);
  snprintf (ep_ip_str + strlen (ep_ip_str),
	    INET_ADDRSTRLEN - strlen (ep_ip_str), ":%d", ntohs (ep->port));
  return ep_ip_str;
}

__thread jmp_buf sig_jmp_buf;

static void
vta_sig_handler (int sig)
{
  longjmp (sig_jmp_buf, 1);
}

void
vta_catch_sig (void (*handler) (int))
{
  signal (SIGUSR1, handler);
}

void
vta_handle_sig (vta_main_t *vtam, int worker_id)
{
  vperf_info ("Worker %d interrupted", worker_id);
  vtam->msgs_received = vtam->num_workers;
}

static void *
vta_server_worker (void *arg)
{
  vta_worker_args_t *args = (vta_worker_args_t *) arg;
  vta_main_t *vtam = args->vtam;
  int worker_id = args->worker_id;
  int rv, vcl_sh, epfd;
  const int buflen = 64;
  char buf[buflen];
  struct sockaddr_in _addr;
  vppcom_endpt_t rmt_ep = { .ip = (void *) &_addr };
  struct epoll_event ev, events[1];

  if (worker_id)
    vppcom_worker_register ();

  vperf_info ("Server worker %d starting", worker_id);

  epfd = vppcom_epoll_create ();
  if (epfd < 0)
    {
      vperf_err ("vppcom_epoll_create()", epfd);
      return NULL;
    }

  vcl_sh = vppcom_session_create (VPPCOM_PROTO_UDP, 0 /* is_nonblocking */);
  if (vcl_sh < 0)
    {
      vperf_err ("vppcom_session_create()", vcl_sh);
      return NULL;
    }

  if (vtam->dscp)
    vppcom_session_attr (vcl_sh, VPPCOM_ATTR_SET_DSCP, &vtam->dscp, (uint32_t *) &dscplen);

  /* Bind to the same endpoint as main thread */
  rv = vppcom_session_bind (vcl_sh, &vtam->endpt);
  if (rv < 0)
    {
      vperf_err ("vppcom_session_bind()", rv);
      return NULL;
    }

  ev.events = EPOLLIN;
  ev.data.fd = vcl_sh;

  rv = vppcom_epoll_ctl (epfd, EPOLL_CTL_ADD, vcl_sh, &ev);
  if (rv < 0)
    {
      vperf_err ("vppcom_epoll_ctl()", rv);
      vppcom_session_close (epfd);
      return NULL;
    }

  vta_catch_sig (vta_sig_handler);
  if (setjmp (sig_jmp_buf))
    vta_handle_sig (vtam, worker_id);

  /* Server worker loop */
  while (!vta_test_done (vtam))
    {
      rv = vppcom_epoll_wait (epfd, events, 1, -1);
      if (rv < 0)
	{
	  vperf_warn ("worker %d: epoll_wait returned %d", worker_id, rv);
	  vppcom_session_close (epfd);
	  break;
	}
      else if (rv == 0)
	{
	  continue;
	}

      rv = vppcom_session_recvfrom (vcl_sh, buf, buflen, 0, &rmt_ep);
      if (rv < 0)
	{
	  vperf_warn ("worker %d: recvfrom returned %d", worker_id, rv);
	  break;
	}
      buf[rv] = 0;

      vperf_info ("Worker %d received message from client %s: %s", worker_id,
		  vta_ep_to_str (&rmt_ep), buf);
      vperf_atomic_add (&vtam->msgs_received, 1);

      char response[buflen];
      int msg_len =
	snprintf (response, buflen, "hello from worker %d", worker_id);

      /* send 2 times to be sure */
      for (int i = 0; i < 2; i++)
	{
	  rv = vppcom_session_sendto (vcl_sh, response, msg_len, 0, &rmt_ep);
	  if (rv < 0)
	    {
	      vperf_warn ("worker %d: sendto returned %d", worker_id, rv);
	      break;
	    }
	  usleep (500);
	}
    }

  vppcom_session_close (vcl_sh);
  vppcom_session_close (epfd);
  vperf_info ("Server worker %d exiting", worker_id);
  return NULL;
}

static void *
vta_client_worker (void *arg)
{
  vta_worker_args_t *args = (vta_worker_args_t *) arg;
  vta_main_t *vtam = args->vtam;
  int worker_id = args->worker_id;
  int rv, vcl_sh;
  const int buflen = 64;
  char buf[buflen];
  struct sockaddr_in _addr;
  vppcom_endpt_t rmt_ep = { .ip = (void *) &_addr };

  if (worker_id)
    vppcom_worker_register ();

  vperf_info ("Client worker %d starting", worker_id);

  vcl_sh = vppcom_session_create (VPPCOM_PROTO_UDP, 0 /* is_nonblocking */);
  if (vcl_sh < 0)
    {
      vperf_err ("vppcom_session_create()", vcl_sh);
      return NULL;
    }
  if (vtam->dscp)
    vppcom_session_attr (vcl_sh, VPPCOM_ATTR_SET_DSCP, &vtam->dscp, (uint32_t *) &dscplen);

  char message[buflen];
  int msg_len =
    snprintf (message, buflen, "hello from client worker %d", worker_id);

  vta_catch_sig (vta_sig_handler);
  if (setjmp (sig_jmp_buf))
    vta_handle_sig (vtam, worker_id);

  while (!vta_test_done (vtam))
    {
      /* send 3 times to be sure */
      for (int i = 0; i < 3; i++)
	{
	  rv = vppcom_session_sendto (vcl_sh, message, msg_len, 0, &vtam->endpt);
	  if (rv < 0)
	    {
	      vperf_warn ("worker %d: sendto returned %d", worker_id, rv);
	      goto cleanup;
	    }
	  usleep (500);
	}

      rv = vppcom_session_recvfrom (vcl_sh, buf, buflen, 0, &rmt_ep);
      if (rv < 0)
	{
	  vperf_warn ("worker %d: recvfrom returned %d", worker_id, rv);
	  goto cleanup;
	}
      buf[rv] = 0;

      vperf_info ("Worker %d received message from server %s: %s", worker_id,
		  vta_ep_to_str (&rmt_ep), buf);

      vperf_atomic_add (&vtam->msgs_received, 1);
    }

cleanup:
  vppcom_session_close (vcl_sh);
  vperf_info ("Client worker %d exiting", worker_id);
  return NULL;
}

static void *
vta_tcp_server_worker (void *arg)
{
  vta_worker_args_t *args = (vta_worker_args_t *) arg;
  vta_main_t *vtam = args->vtam;
  int worker_id = args->worker_id;
  struct epoll_event ev, events[VTA_MAX_EPOLL_EVENTS];
  int rv, listen_sh, epfd, n_evts, i;
  char buf[VTA_TCP_SRV_READ];
  vta_conn_t *conn;

  if (worker_id)
    vppcom_worker_register ();

  vperf_info ("Server worker %d starting", worker_id);

  epfd = vppcom_epoll_create ();
  if (epfd < 0)
    {
      vperf_err ("vppcom_epoll_create()", epfd);
      return NULL;
    }

  listen_sh = vppcom_session_create (VPPCOM_PROTO_TCP, 0 /* is_nonblocking */);
  if (listen_sh < 0)
    {
      vperf_err ("vppcom_session_create()", listen_sh);
      return NULL;
    }

  if (vtam->dscp)
    vppcom_session_attr (listen_sh, VPPCOM_ATTR_SET_DSCP, &vtam->dscp, (uint32_t *) &dscplen);

  rv = vppcom_session_bind (listen_sh, &vtam->endpt);
  if (rv < 0)
    {
      vperf_err ("vppcom_session_bind()", rv);
      return NULL;
    }

  rv = vppcom_session_listen (listen_sh, 10);
  if (rv < 0)
    {
      vperf_err ("vppcom_session_listen()", rv);
      return NULL;
    }

  /* No EPOLLET, so level-triggered */
  ev.events = EPOLLIN;
  ev.data.ptr = NULL;
  rv = vppcom_epoll_ctl (epfd, EPOLL_CTL_ADD, listen_sh, &ev);
  if (rv < 0)
    {
      vperf_err ("vppcom_epoll_ctl()", rv);
      return NULL;
    }

  vta_catch_sig (vta_sig_handler);
  if (setjmp (sig_jmp_buf))
    vta_handle_sig (vtam, worker_id);

  while (!vta_test_done (vtam))
    {
      n_evts = vppcom_epoll_wait (epfd, events, VTA_MAX_EPOLL_EVENTS, -1);
      if (n_evts < 0)
	{
	  vperf_warn ("worker %d: epoll_wait returned %d", worker_id, n_evts);
	  break;
	}

      for (i = 0; i < n_evts; i++)
	{
	  conn = events[i].data.ptr;
	  if (!conn)
	    {
	      rv = vppcom_session_accept (listen_sh, 0, O_NONBLOCK);
	      if (rv < 0)
		{
		  vperf_warn ("worker %d: accept returned %d", worker_id, rv);
		  continue;
		}
	      conn = calloc (1, sizeof (*conn));
	      conn->sh = rv;
	      ev.events = EPOLLIN;
	      ev.data.ptr = conn;
	      rv = vppcom_epoll_ctl (epfd, EPOLL_CTL_ADD, conn->sh, &ev);
	      if (rv < 0)
		{
		  vperf_warn ("worker %d: epoll_ctl returned %d", worker_id, rv);
		  vppcom_session_close (conn->sh);
		  free (conn);
		}
	      continue;
	    }

	  /* Read less than available so data is left in the rx fifo */
	  rv = vppcom_session_read (conn->sh, buf, sizeof (buf));
	  if (rv == VPPCOM_EWOULDBLOCK)
	    continue;
	  if (rv <= 0)
	    {
	      vperf_warn ("worker %d: read returned %d after %u bytes", worker_id, rv, conn->bytes);
	      vppcom_session_close (conn->sh);
	      free (conn);
	      continue;
	    }
	  conn->bytes += rv;
	  if (conn->bytes < VTA_TCP_BYTES)
	    continue;

	  vperf_info ("Worker %d received %u bytes", worker_id, conn->bytes);
	  rv = vppcom_session_write (conn->sh, "ack", 3);
	  if (rv < 0)
	    vperf_warn ("worker %d: write returned %d", worker_id, rv);
	  vppcom_session_close (conn->sh);
	  free (conn);
	  vperf_atomic_add (&vtam->msgs_received, 1);
	}
    }

  vppcom_session_close (listen_sh);
  vppcom_session_close (epfd);
  vperf_info ("Server worker %d exiting", worker_id);
  return NULL;
}

static void *
vta_tcp_client_worker (void *arg)
{
  vta_worker_args_t *args = (vta_worker_args_t *) arg;
  vta_main_t *vtam = args->vtam;
  int worker_id = args->worker_id;
  uint32_t sent = 0, len;
  char buf[4096];
  int rv, sh;

  if (worker_id)
    vppcom_worker_register ();

  vperf_info ("Client worker %d starting", worker_id);

  sh = vppcom_session_create (VPPCOM_PROTO_TCP, 0 /* is_nonblocking */);
  if (sh < 0)
    vperf_fail ("vppcom_session_create()", sh);

  if (vtam->dscp)
    vppcom_session_attr (sh, VPPCOM_ATTR_SET_DSCP, &vtam->dscp, (uint32_t *) &dscplen);

  rv = vppcom_session_connect (sh, &vtam->endpt);
  if (rv < 0)
    vperf_fail ("vppcom_session_connect()", rv);

  vta_catch_sig (vta_sig_handler);
  if (setjmp (sig_jmp_buf))
    {
      vta_handle_sig (vtam, worker_id);
      goto cleanup;
    }

  memset (buf, 'a', sizeof (buf));
  while (sent < VTA_TCP_BYTES)
    {
      len = VTA_TCP_BYTES - sent < sizeof (buf) ? VTA_TCP_BYTES - sent : sizeof (buf);
      rv = vppcom_session_write (sh, buf, len);
      if (rv < 0)
	vperf_fail ("vppcom_session_write()", rv);
      sent += rv;
    }

  /* Keep the session open until the ack is received. A disconnect would
   * wake up the server even if its epoll wait is stuck */
  rv = vppcom_session_read (sh, buf, sizeof (buf) - 1);
  if (rv <= 0)
    vperf_fail ("vppcom_session_read()", rv);
  buf[rv] = 0;

  vperf_info ("Worker %d received ack from server: %s", worker_id, buf);
  vperf_atomic_add (&vtam->msgs_received, 1);

cleanup:
  vppcom_session_close (sh);
  vperf_info ("Client worker %d exiting", worker_id);
  return NULL;
}

int
main (int argc, char **argv)
{
  vta_main_t *vtam = &vta_main;
  int rv;

  vta_parse_args (vtam, argc, argv);

  rv = vppcom_app_create ("vcl_test_app");
  if (rv)
    vperf_fail ("vppcom_app_create()", rv);

  vperf_info ("Starting %s with %d worker(s)",
	      vtam->app_type == VTA_TYPE_SERVER ? "server" : "client", vtam->num_workers);

  vtam->worker_threads = calloc (vtam->num_workers, sizeof (pthread_t));
  vta_worker_args_t *worker_args = calloc (vtam->num_workers, sizeof (vta_worker_args_t));

  if (!vtam->worker_threads || !worker_args)
    {
      vperf_err ("Failed to allocate memory for worker threads", -1);
      return -1;
    }

  void *(*worker_func) (void *);
  if (vtam->proto == VPPCOM_PROTO_TCP)
    worker_func =
      (vtam->app_type == VTA_TYPE_SERVER) ? vta_tcp_server_worker : vta_tcp_client_worker;
  else
    worker_func = (vtam->app_type == VTA_TYPE_SERVER) ? vta_server_worker : vta_client_worker;

  /* Create worker threads */
  for (int i = 1; i < vtam->num_workers; i++)
    {
      worker_args[i].vtam = vtam;
      worker_args[i].worker_id = i;

      rv = pthread_create (&vtam->worker_threads[i], NULL, worker_func, &worker_args[i]);
      if (rv != 0)
	{
	  vperf_err ("Failed to create worker thread", rv);
	  /* Clean up any threads that were created */
	  for (int j = 0; j < i; j++)
	    pthread_cancel (vtam->worker_threads[j]);
	  return rv;
	}
    }

  /* First worker */
  worker_args[0].vtam = vtam;
  worker_args[0].worker_id = 0;
  worker_func (worker_args);

  /* Wait for all worker threads to complete */
  while (!vta_test_done (vtam))
    ;

  /* Wait for pthreads to cleanup before signaling */
  usleep (100e3);

  for (int i = 1; i < vtam->num_workers; i++)
    {
      pthread_kill (vtam->worker_threads[i], SIGUSR1);
      pthread_join (vtam->worker_threads[i], NULL);
    }

  free (vtam->worker_threads);
  free (worker_args);
  vperf_info ("All worker threads completed");

  vppcom_app_destroy ();
  return 0;
}