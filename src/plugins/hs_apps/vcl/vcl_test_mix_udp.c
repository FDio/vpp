/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

/*
 * VCL Mix UDP Test Client/Server
 *
 * Usage:
 *   Server: vcl_test_mix_udp -s <server_ip>
 *   Client: vcl_test_mix_udp -c <server_ip>
 *
 * Options:
 *   -s <ip>    Start as server bound to specified IP address
 *   -c <ip>    Start as client connecting to specified IP address
 *   -x         Force close after connect
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <vcl/vppcom.h>
#include <hs_apps/vcl/vcl_test.h>

typedef enum vt_mu_type_
{
  VT_MU_TYPE_NONE = 0,
  VT_MU_TYPE_SERVER,
  VT_MU_TYPE_CLIENT,
} vt_mu_type_t;

typedef struct vtmu_main_
{
  vt_mu_type_t app_type;
  vppcom_endpt_t endpt;
  union
  {
    struct sockaddr_storage srvr_addr;
    struct sockaddr_storage clnt_addr;
  };
  uint16_t port;
  int force_close;
} vt_mu_main_t;

static vt_mu_main_t vt_mu_main;

static void
print_usage_and_exit (void)
{
  fprintf (stderr,
	   "VCL Mix UDP Test Client/Server\n"
	   "\n"
	   "Usage:\n"
	   "  Server: vcl_test_mix_udp -s <server_ip>\n"
	   "  Client: vcl_test_mix_udp -c <server_ip>\n"
	   "\n"
	   "Options:\n"
	   "  -s <ip>    Start as server bound to specified IP address\n"
	   "  -c <ip>    Start as client connecting to specified IP address\n"
	   "  -x         Force close after connect\n"
	   "  -h         Print this help and exit\n");
  exit (1);
}

static void
vt_mu_parse_args (vt_mu_main_t *vclum, int argc, char **argv)
{
  int c;

  /* Initialize defaults */
  vclum->app_type = VT_MU_TYPE_NONE;
  vclum->force_close = 0;
  vclum->port = VCL_TEST_SERVER_PORT;

  opterr = 0;
  while ((c = getopt (argc, argv, "s:c:xh")) != -1)
    {
      switch (c)
	{
	case 's':
	  if (vclum->app_type != VT_MU_TYPE_NONE)
	    {
	      fprintf (stderr, "Error: Cannot specify both server (-s) and "
			       "client (-c) modes\n");
	      print_usage_and_exit ();
	    }
	  vclum->app_type = VT_MU_TYPE_SERVER;
	  if (inet_pton (
		AF_INET, optarg,
		&((struct sockaddr_in *) &vclum->srvr_addr)->sin_addr) != 1)
	    {
	      fprintf (stderr, "Error: Invalid IPv4 address '%s' for server\n",
		       optarg);
	      print_usage_and_exit ();
	    }
	  break;

	case 'c':
	  if (vclum->app_type != VT_MU_TYPE_NONE)
	    {
	      fprintf (stderr, "Error: Cannot specify both server (-s) and "
			       "client (-c) modes\n");
	      print_usage_and_exit ();
	    }
	  vclum->app_type = VT_MU_TYPE_CLIENT;
	  if (inet_pton (
		AF_INET, optarg,
		&((struct sockaddr_in *) &vclum->clnt_addr)->sin_addr) != 1)
	    {
	      fprintf (stderr, "Error: Invalid IPv4 address '%s' for client\n",
		       optarg);
	      print_usage_and_exit ();
	    }
	  break;

	case 'x':
	  vclum->force_close = 1;
	  break;

	case 'h':
	  print_usage_and_exit ();
	  break;

	case '?':
	  fprintf (stderr, "Error: Unknown option '-%c'\n", optopt);
	  print_usage_and_exit ();
	  break;

	default:
	  fprintf (stderr, "Error: Unexpected getopt return value: %d\n", c);
	  print_usage_and_exit ();
	}
    }

  /* Validate required arguments */
  if (vclum->app_type == VT_MU_TYPE_NONE)
    {
      fprintf (stderr,
	       "Error: Must specify either server (-s) or client (-c) mode\n");
      print_usage_and_exit ();
    }

  vclum->endpt.is_ip4 = 1;
  vclum->endpt.ip =
    (uint8_t *) &((struct sockaddr_in *) &vclum->srvr_addr)->sin_addr;
  vclum->endpt.port = htons (vclum->port);

  if (optind < argc)
    {
      fprintf (stderr, "Error: Unexpected extra arguments\n");
      print_usage_and_exit ();
    }
}

static char ep_ip_str[INET_ADDRSTRLEN + 16];

static char *
vt_mu_ep_to_str (vppcom_endpt_t *ep)
{
  inet_ntop (AF_INET, ep->ip, ep_ip_str, INET_ADDRSTRLEN);
  snprintf (ep_ip_str + strlen (ep_ip_str),
	    INET_ADDRSTRLEN - strlen (ep_ip_str), ":%d", ntohs (ep->port));
  return ep_ip_str;
}

static int
vt_mu_server ()
{
  vt_mu_main_t *vmm = &vt_mu_main;
  int rv, vcl_sh, epfd, client_sh;
  const int buflen = 64;
  char buf[buflen];
  struct sockaddr_in _addr;
  vppcom_endpt_t rmt_ep = { .ip = (void *) &_addr };
  struct epoll_event ev, events[1];

  vtinf ("Server starting");

  epfd = vppcom_epoll_create ();
  if (epfd < 0)
    {
      vterr ("vppcom_epoll_create()", epfd);
      return -1;
    }

  vcl_sh = vppcom_session_create (VPPCOM_PROTO_UDP, 0 /* is_nonblocking */);
  if (vcl_sh < 0)
    {
      vterr ("vppcom_session_create()", vcl_sh);
      return -1;
    }

  rv = vppcom_session_bind (vcl_sh, &vmm->endpt);
  if (rv < 0)
    {
      vterr ("vppcom_session_bind()", rv);
      return -1;
    }

  ev.events = EPOLLIN;
  ev.data.fd = vcl_sh;

  rv = vppcom_epoll_ctl (epfd, EPOLL_CTL_ADD, vcl_sh, &ev);
  if (rv < 0)
    {
      vterr ("vppcom_epoll_ctl()", rv);
      vppcom_session_close (epfd);
      return -1;
    }

  /* Wait for client */
  while (1)
    {
      rv = vppcom_epoll_wait (epfd, events, 1, -1);
      if (rv < 0)
	{
	  vppcom_session_close (epfd);
	  vterr ("vppcom_epoll_wait()", rv);
	  return -1;
	}
      else if (rv == 0)
	{
	  continue;
	}
      break;
    }

  rv = vppcom_session_recvfrom (vcl_sh, buf, buflen, 0, &rmt_ep);
  if (rv < 0)
    {
      vtwrn ("recvfrom returned %d", rv);
      return -1;
    }

  vtinf ("Received message from client %s: %s", vt_mu_ep_to_str (&rmt_ep),
	 buf);

  client_sh = vppcom_session_create (VPPCOM_PROTO_UDP, 0 /* is_nonblocking */);
  if (client_sh < 0)
    {
      vterr ("vppcom_session_create()", client_sh);
      return -1;
    }
  rv = vppcom_session_connect (client_sh, &rmt_ep);
  if (rv < 0)
    {
      vtwrn ("connect returned %d", rv);
      return -1;
    }

  if (vmm->force_close)
    {
      vtinf ("Force close after connect");
      /* Leave session open, we're done */
      sleep (1);
      return 0;
    }

  char *response = "hello from server";
  int msg_len = strlen (response);

  /* send 2 times to be sure */
  for (int i = 0; i < 2; i++)
    {
      rv = vppcom_session_sendto (client_sh, response, msg_len, 0, 0);
      if (rv < 0)
	{
	  vtwrn ("sendto returned %d", rv);
	  return -1;
	}
      usleep (500);
    }

  return 0;
}

static int
vt_mu_client ()
{
  vt_mu_main_t *vmm = &vt_mu_main;
  int rv, vcl_sh;
  const int buflen = 64;
  char buf[buflen];
  //   struct in_addr _addr = { INADDR_ANY };
  //   vppcom_endpt_t lcl_ep = { .ip = (void *) &_addr,
  // 			    .is_ip4 = 1,
  // 			    .port = htons (vmm->port) };
  //   struct sockaddr_in _rmt_addr;
  //   vppcom_endpt_t rmt_ep = { .ip = (void *) &_rmt_addr };

  vtinf ("Client starting");

  vcl_sh = vppcom_session_create (VPPCOM_PROTO_UDP, 0 /* is_nonblocking */);
  if (vcl_sh < 0)
    {
      vterr ("vppcom_session_create()", vcl_sh);
      return -1;
    }

  rv = vppcom_session_connect (vcl_sh, &vmm->endpt);
  if (rv < 0)
    {
      vtwrn ("connect returned %d", rv);
      return -1;
    }

  char *msg = "hello from client";
  int msg_len = strlen (msg);

  /* send 2 times to be sure */
  for (int i = 0; i < 2; i++)
    {
      rv = vppcom_session_sendto (vcl_sh, msg, msg_len, 0, 0);
      if (rv < 0)
	{
	  vtwrn ("sendto returned %d", rv);
	  return -1;
	}
      usleep (500);
    }

  if (vmm->force_close)
    {
      vtinf ("Force close after send");
      vppcom_session_close (vcl_sh);
      return 0;
    }

  rv = vppcom_session_recvfrom (vcl_sh, buf, buflen, 0, 0);
  if (rv < 0)
    {
      vtwrn ("recvfrom returned %d", rv);
      return -1;
    }

  vtinf ("Received message: %s", buf);

  return 0;
}

int
main (int argc, char **argv)
{
  vt_mu_main_t *vmm = &vt_mu_main;
  int rv;

  vt_mu_parse_args (vmm, argc, argv);

  rv = vppcom_app_create ("vcl_test_cl_udp");
  if (rv)
    vtfail ("vppcom_app_create()", rv);

  rv =
    (vmm->app_type == VT_MU_TYPE_SERVER) ? vt_mu_server () : vt_mu_client ();

  if (rv)
    vtfail ("test failed", rv);

  vtinf ("Finished");

  vppcom_app_destroy ();
  return 0;
}