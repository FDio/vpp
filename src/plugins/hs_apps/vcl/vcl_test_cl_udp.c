/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

/*
 * VCL CL UDP Test Client/Server with Multi-threading Support
 *
 * Usage:
 *   Server: vcl_test_cl_udp -s <server_ip> [-w <num_workers>]
 *   Client: vcl_test_cl_udp -c <server_ip> [-w <num_workers>]
 *
 * Options:
 *   -s <ip>    Start as server bound to specified IP address
 *   -c <ip>    Start as client connecting to specified IP address
 *   -w <num>   Number of worker threads (default: 1)
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <vcl/vppcom.h>
#include <hs_apps/vcl/vcl_test.h>

typedef enum vt_clu_type_
{
  VT_CLU_TYPE_NONE = 0,
  VT_CLU_TYPE_SERVER,
  VT_CLU_TYPE_CLIENT,
} vt_clu_type_t;

typedef struct vtclu_main_
{
  vt_clu_type_t app_type;
  vppcom_endpt_t endpt;
  union
  {
    struct sockaddr_storage srvr_addr;
    struct sockaddr_storage clnt_addr;
  };
  uint16_t port;
  uint8_t dscp;
  int num_workers;
  pthread_t *worker_threads;
  int thread_id_counter;
  volatile int msgs_received;
} vt_clu_main_t;

static vt_clu_main_t vt_clu_main;
static const uint32_t dscplen = 1;

typedef struct vtclu_worker_args_
{
  vt_clu_main_t *vclum;
  int worker_id;
} vtclu_worker_args_t;

static void
vt_clu_parse_args (vt_clu_main_t *vclum, int argc, char **argv)
{
  int c;
  int temp;

  memset (vclum, 0, sizeof (*vclum));
  vclum->port = VCL_TEST_SERVER_PORT;
  vclum->num_workers = 1;
  vclum->dscp = 0;

  opterr = 0;
  while ((c = getopt (argc, argv, "s:c:w:d:")) != -1)
    switch (c)
      {
      case 's':
	vclum->app_type = VT_CLU_TYPE_SERVER;
	if (inet_pton (
	      AF_INET, optarg,
	      &((struct sockaddr_in *) &vclum->srvr_addr)->sin_addr) != 1)
	  vtwrn ("couldn't parse ipv4 addr %s", optarg);
	break;
      case 'c':
	vclum->app_type = VT_CLU_TYPE_CLIENT;
	if (inet_pton (
	      AF_INET, optarg,
	      &((struct sockaddr_in *) &vclum->clnt_addr)->sin_addr) != 1)
	  vtwrn ("couldn't parse ipv4 addr %s", optarg);
	break;
      case 'w':
	vclum->num_workers = atoi (optarg);
	if (vclum->num_workers <= 0)
	  {
	    vtwrn ("invalid number of workers %s", optarg);
	    vclum->num_workers = 1;
	  }
	break;
      case 'd':
	temp = atoi (optarg);
	if (temp <= 0 || temp > 63)
	  {
	    vtwrn ("invalid dscp value %s", optarg);
	    vclum->dscp = 0;
	  }
	vclum->dscp = temp;
	break;
      }

  if (vclum->app_type == VT_CLU_TYPE_NONE)
    {
      vtwrn ("client or server must be configured");
      exit (1);
    }

  vclum->endpt.is_ip4 = 1;
  vclum->endpt.ip =
    (uint8_t *) &((struct sockaddr_in *) &vclum->srvr_addr)->sin_addr;
  vclum->endpt.port = htons (vclum->port);
}

static int
vt_clu_test_done (vt_clu_main_t *vclum)
{
  return vclum->msgs_received >= vclum->num_workers;
}

__thread char ep_ip_str[INET_ADDRSTRLEN + 16];

static char *
vt_clu_ep_to_str (vppcom_endpt_t *ep)
{
  inet_ntop (AF_INET, ep->ip, ep_ip_str, INET_ADDRSTRLEN);
  snprintf (ep_ip_str + strlen (ep_ip_str),
	    INET_ADDRSTRLEN - strlen (ep_ip_str), ":%d", ntohs (ep->port));
  return ep_ip_str;
}

__thread jmp_buf sig_jmp_buf;

static void
vt_clu_sig_handler (int sig)
{
  longjmp (sig_jmp_buf, 1);
}

void
vt_clu_catch_sig (void (*handler) (int))
{
  signal (SIGUSR1, handler);
}

void
vt_clu_handle_sig (vt_clu_main_t *vclum, int worker_id)
{
  vtinf ("Worker %d interrupted", worker_id);
  vclum->msgs_received = vclum->num_workers;
}

static void *
vt_clu_server_worker (void *arg)
{
  vtclu_worker_args_t *args = (vtclu_worker_args_t *) arg;
  vt_clu_main_t *vclum = args->vclum;
  int worker_id = args->worker_id;
  int rv, vcl_sh, epfd;
  const int buflen = 64;
  char buf[buflen];
  struct sockaddr_in _addr;
  vppcom_endpt_t rmt_ep = { .ip = (void *) &_addr };
  struct epoll_event ev, events[1];

  if (worker_id)
    vppcom_worker_register ();

  vtinf ("Server worker %d starting", worker_id);

  epfd = vppcom_epoll_create ();
  if (epfd < 0)
    {
      vterr ("vppcom_epoll_create()", epfd);
      return NULL;
    }

  vcl_sh = vppcom_session_create (VPPCOM_PROTO_UDP, 0 /* is_nonblocking */);
  if (vcl_sh < 0)
    {
      vterr ("vppcom_session_create()", vcl_sh);
      return NULL;
    }

  if (vclum->dscp)
    vppcom_session_attr (vcl_sh, VPPCOM_ATTR_SET_DSCP, &vclum->dscp,
			 (uint32_t *) &dscplen);

  /* Bind to the same endpoint as main thread */
  rv = vppcom_session_bind (vcl_sh, &vclum->endpt);
  if (rv < 0)
    {
      vterr ("vppcom_session_bind()", rv);
      return NULL;
    }

  ev.events = EPOLLIN;
  ev.data.fd = vcl_sh;

  rv = vppcom_epoll_ctl (epfd, EPOLL_CTL_ADD, vcl_sh, &ev);
  if (rv < 0)
    {
      vterr ("vppcom_epoll_ctl()", rv);
      vppcom_session_close (epfd);
      return NULL;
    }

  vt_clu_catch_sig (vt_clu_sig_handler);
  if (setjmp (sig_jmp_buf))
    vt_clu_handle_sig (vclum, worker_id);

  /* Server worker loop */
  while (!vt_clu_test_done (vclum))
    {
      rv = vppcom_epoll_wait (epfd, events, 1, -1);
      if (rv < 0)
	{
	  vtwrn ("worker %d: epoll_wait returned %d", worker_id, rv);
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
	  vtwrn ("worker %d: recvfrom returned %d", worker_id, rv);
	  break;
	}
      buf[rv] = 0;

      vtinf ("Worker %d received message from client %s: %s", worker_id,
	     vt_clu_ep_to_str (&rmt_ep), buf);
      vt_atomic_add (&vclum->msgs_received, 1);

      char response[buflen];
      int msg_len =
	snprintf (response, buflen, "hello from worker %d", worker_id);

      /* send 2 times to be sure */
      for (int i = 0; i < 2; i++)
	{
	  rv = vppcom_session_sendto (vcl_sh, response, msg_len, 0, &rmt_ep);
	  if (rv < 0)
	    {
	      vtwrn ("worker %d: sendto returned %d", worker_id, rv);
	      break;
	    }
	  usleep (500);
	}
    }

  vppcom_session_close (vcl_sh);
  vtinf ("Server worker %d exiting", worker_id);
  return NULL;
}

static void *
vt_clu_client_worker (void *arg)
{
  vtclu_worker_args_t *args = (vtclu_worker_args_t *) arg;
  vt_clu_main_t *vclum = args->vclum;
  int worker_id = args->worker_id;
  int rv, vcl_sh;
  const int buflen = 64;
  char buf[buflen];
  struct sockaddr_in _addr;
  vppcom_endpt_t rmt_ep = { .ip = (void *) &_addr };

  if (worker_id)
    vppcom_worker_register ();

  vtinf ("Client worker %d starting", worker_id);

  vcl_sh = vppcom_session_create (VPPCOM_PROTO_UDP, 0 /* is_nonblocking */);
  if (vcl_sh < 0)
    {
      vterr ("vppcom_session_create()", vcl_sh);
      return NULL;
    }
  if (vclum->dscp)
    vppcom_session_attr (vcl_sh, VPPCOM_ATTR_SET_DSCP, &vclum->dscp,
			 (uint32_t *) &dscplen);

  char message[buflen];
  int msg_len =
    snprintf (message, buflen, "hello from client worker %d", worker_id);

  vt_clu_catch_sig (vt_clu_sig_handler);
  if (setjmp (sig_jmp_buf))
    vt_clu_handle_sig (vclum, worker_id);

  while (!vt_clu_test_done (vclum))
    {
      /* send 3 times to be sure */
      for (int i = 0; i < 3; i++)
	{
	  rv =
	    vppcom_session_sendto (vcl_sh, message, msg_len, 0, &vclum->endpt);
	  if (rv < 0)
	    {
	      vtwrn ("worker %d: sendto returned %d", worker_id, rv);
	      goto cleanup;
	    }
	  usleep (500);
	}

      rv = vppcom_session_recvfrom (vcl_sh, buf, buflen, 0, &rmt_ep);
      if (rv < 0)
	{
	  vtwrn ("worker %d: recvfrom returned %d", worker_id, rv);
	  goto cleanup;
	}
      buf[rv] = 0;

      vtinf ("Worker %d received message from server %s: %s", worker_id,
	     vt_clu_ep_to_str (&rmt_ep), buf);

      vt_atomic_add (&vclum->msgs_received, 1);
    }

cleanup:
  vppcom_session_close (vcl_sh);
  vtinf ("Client worker %d exiting", worker_id);
  return NULL;
}

int
main (int argc, char **argv)
{
  vt_clu_main_t *vclum = &vt_clu_main;
  int rv;

  vt_clu_parse_args (vclum, argc, argv);

  rv = vppcom_app_create ("vcl_test_cl_udp");
  if (rv)
    vtfail ("vppcom_app_create()", rv);

  vtinf ("Starting %s with %d worker(s)",
	 vclum->app_type == VT_CLU_TYPE_SERVER ? "server" : "client",
	 vclum->num_workers);

  vclum->worker_threads = calloc (vclum->num_workers, sizeof (pthread_t));
  vtclu_worker_args_t *worker_args =
    calloc (vclum->num_workers, sizeof (vtclu_worker_args_t));

  if (!vclum->worker_threads || !worker_args)
    {
      vterr ("Failed to allocate memory for worker threads", -1);
      return -1;
    }

  void *(*worker_func) (void *) = (vclum->app_type == VT_CLU_TYPE_SERVER) ?
				    vt_clu_server_worker :
				    vt_clu_client_worker;

  /* Create worker threads */
  for (int i = 1; i < vclum->num_workers; i++)
    {
      worker_args[i].vclum = vclum;
      worker_args[i].worker_id = i;

      rv = pthread_create (&vclum->worker_threads[i], NULL, worker_func,
			   &worker_args[i]);
      if (rv != 0)
	{
	  vterr ("Failed to create worker thread", rv);
	  /* Clean up any threads that were created */
	  for (int j = 0; j < i; j++)
	    pthread_cancel (vclum->worker_threads[j]);
	  return rv;
	}
    }

  /* First worker */
  worker_args[0].vclum = vclum;
  worker_args[0].worker_id = 0;
  worker_func (worker_args);

  /* Wait for all worker threads to complete */
  while (!vt_clu_test_done (vclum))
    ;

  /* Wait for pthreads to cleanup before signaling */
  usleep (100e3);

  for (int i = 1; i < vclum->num_workers; i++)
    {
      pthread_kill (vclum->worker_threads[i], SIGUSR1);
      pthread_join (vclum->worker_threads[i], NULL);
    }

  free (vclum->worker_threads);
  free (worker_args);
  vtinf ("All worker threads completed");

  vppcom_app_destroy ();
  return 0;
}