/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
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
} vt_clu_main_t;

static vt_clu_main_t vt_clu_main;

static void
vt_clu_parse_args (vt_clu_main_t *vclum, int argc, char **argv)
{
  int c;

  memset (vclum, 0, sizeof (*vclum));
  vclum->port = VCL_TEST_SERVER_PORT;

  opterr = 0;
  while ((c = getopt (argc, argv, "s:c:")) != -1)
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
  vclum->endpt.port = htons (vclum->endpt.port);
}

int
main (int argc, char **argv)
{
  vt_clu_main_t *vclum = &vt_clu_main;
  int rv, vcl_sh;
  const int buflen = 64;
  char buf[buflen];

  struct sockaddr_in _addr;
  vppcom_endpt_t rmt_ep = { .ip = (void *) &_addr };

  vt_clu_parse_args (vclum, argc, argv);

  rv = vppcom_app_create ("vcl_test_cl_udp");
  if (rv)
    vtfail ("vppcom_app_create()", rv);

  vcl_sh = vppcom_session_create (VPPCOM_PROTO_UDP, 0 /* is_nonblocking */);
  if (vcl_sh < 0)
    {
      vterr ("vppcom_session_create()", vcl_sh);
      return vcl_sh;
    }

  if (vclum->app_type == VT_CLU_TYPE_SERVER)
    {
      /* Listen is implicit */
      rv = vppcom_session_bind (vcl_sh, &vclum->endpt);
      if (rv < 0)
	{
	  vterr ("vppcom_session_bind()", rv);
	  return rv;
	}

      rv = vppcom_session_recvfrom (vcl_sh, buf, buflen, 0, &rmt_ep);
      if (rv < 0)
	{
	  vterr ("vppcom_session_recvfrom()", rv);
	  return rv;
	}
      buf[rv] = 0;
      vtinf ("Received message from client: %s", buf);

      char *msg = "hello cl udp client";
      int msg_len = strnlen (msg, buflen);
      memcpy (buf, msg, msg_len);
      /* send 2 times to be sure */
      for (int i = 0; i < 2; i++)
	{
	  rv = vppcom_session_sendto (vcl_sh, buf, msg_len, 0, &rmt_ep);
	  if (rv < 0)
	    {
	      vterr ("vppcom_session_sendto()", rv);
	      return rv;
	    }
	  usleep (500);
	}
    }
  else if (vclum->app_type == VT_CLU_TYPE_CLIENT)
    {
      char *msg = "hello cl udp server";
      int msg_len = strnlen (msg, buflen);
      memcpy (buf, msg, msg_len);

      /* send 3 times to be sure */
      for (int i = 0; i < 3; i++)
	{
	  rv = vppcom_session_sendto (vcl_sh, buf, msg_len, 0, &vclum->endpt);
	  if (rv < 0)
	    {
	      vterr ("vppcom_session_sendto()", rv);
	      return rv;
	    }
	  usleep (500);
	}

      rv = vppcom_session_recvfrom (vcl_sh, buf, buflen, 0, &rmt_ep);
      if (rv < 0)
	{
	  vterr ("vppcom_session_recvfrom()", rv);
	  return rv;
	}
      buf[rv] = 0;
      vtinf ("Received message from server: %s", buf);
    }
}