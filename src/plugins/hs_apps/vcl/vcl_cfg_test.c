/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

/*
 * VCL Configuration Test
 * Modified to use vppcom_app_create_with_config() API instead of environment
 * variables
 *
 * Usage:
 *   Usage: vcl_cfg_test -s <server_ip> [-d <debug_level>] [-n <namespace>] [-k
 * <secret>] [-t <timeout>]
 *
 * Options:
 *   -s <ip>    Start as server bound to specified IP address
 *   -d <level> Debug level (default: 0)
 *   -n <ns>    Namespace ID
 *   -k <secret> Namespace secret (default: 0)
 *   -a <socket> VPP API socket path
 *   -t <sec>   Timeout for session bind in seconds (default: 10)
 */

#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <vcl/vppcom.h>
#include <hs_apps/vcl/vcl_test.h>

typedef enum vt_clu_type_
{
  VT_CLU_TYPE_NONE = 0,
  VT_CLU_TYPE_SERVER,
} vt_clu_type_t;

typedef struct vtclu_main_
{
  vt_clu_type_t app_type;
  vppcom_endpt_t endpt;
  struct sockaddr_storage srvr_addr;
  uint16_t port;
  int timeout_seconds;

  /* VCL configuration structure */
  vppcom_cfg_t vcl_cfg;
} vt_clu_main_t;

static vt_clu_main_t vt_clu_main;

/* Initialize VCL configuration with default values */
static void
vcl_test_config_init (vt_clu_main_t *vclum)
{
  vppcom_cfg_t *cfg = &vclum->vcl_cfg;

  memset (cfg, 0, sizeof (*cfg));

  /* Set VCL defaults matching vppcom_cfg_init */
  cfg->heapsize = (256ULL << 20);
  cfg->max_workers = 16;
  cfg->segment_size = (256 << 20);
  cfg->add_segment_size = (128 << 20);
  cfg->preallocated_fifo_pairs = 8;
  cfg->rx_fifo_size = (1 << 20);
  cfg->tx_fifo_size = (1 << 20);
  cfg->event_queue_size = 2048;
  cfg->app_timeout = 10 * 60.0;
  cfg->session_timeout = 10 * 60.0;
  cfg->event_log_path = "/dev/shm";
  cfg->app_name = "vcl_cfg_test";

  /* Initialize other fields */
  cfg->app_proxy_transport_tcp = 0;
  cfg->app_proxy_transport_udp = 0;
  cfg->app_scope_local = 0;
  cfg->app_scope_global = 0;
  cfg->namespace_id = 0;
  cfg->namespace_secret = 0;
  cfg->use_mq_eventfd = 0;
  cfg->vpp_bapi_socket_name = 0;
  cfg->vpp_app_socket_api = 0;
  cfg->tls_engine = 0;
  cfg->mt_wrk_supported = 0;
  cfg->huge_page = 0;
  cfg->app_original_dst = 0;
}

static void
vt_clu_parse_args (vt_clu_main_t *vclum, int argc, char **argv)
{
  int c;

  memset (vclum, 0, sizeof (*vclum));
  vclum->port = VCL_TEST_SERVER_PORT;
  vclum->timeout_seconds = 10; /* Default timeout: 10 seconds */

  /* Initialize VCL configuration with defaults */
  vcl_test_config_init (vclum);

  opterr = 0;
  while ((c = getopt (argc, argv, "s:d:n:a:t:k:")) != -1)
    switch (c)
      {
      case 's':
	vclum->app_type = VT_CLU_TYPE_SERVER;
	if (inet_pton (
	      AF_INET, optarg,
	      &((struct sockaddr_in *) &vclum->srvr_addr)->sin_addr) != 1)
	  vtwrn ("couldn't parse ipv4 addr %s", optarg);
	break;
      case 'd':
	/* Set debug level programmatically */
	vclum->vcl_cfg.debug_level = atoi (optarg);
	break;
      case 'n':
	/* Set namespace ID programmatically */
	vclum->vcl_cfg.namespace_id = optarg;
	break;
      case 'a':
	/* Set VPP API socket path programmatically */
	vclum->vcl_cfg.vpp_app_socket_api = optarg;
	break;
      case 't':
	/* Set timeout for session bind */
	vclum->timeout_seconds = atoi (optarg);
	if (vclum->timeout_seconds <= 0)
	  {
	    vtwrn ("invalid timeout %s, using default 10 seconds", optarg);
	    vclum->timeout_seconds = 10;
	  }
	break;
      case 'k':
	/* Set namespace secret programmatically */
	vclum->vcl_cfg.namespace_secret = atoi (optarg);
	break;
      }

  if (vclum->app_type == VT_CLU_TYPE_NONE)
    {
      vtwrn ("server must be configured");
      exit (1);
    }

  vclum->endpt.is_ip4 = 1;
  vclum->endpt.ip =
    (uint8_t *) &((struct sockaddr_in *) &vclum->srvr_addr)->sin_addr;
  vclum->endpt.port = htons (vclum->port);
}

static void
vt_clu_server_test (vt_clu_main_t *vclum)
{
  int rv, vcl_sh;

  vtinf ("Server test starting (delay: %d seconds)", vclum->timeout_seconds);

  vcl_sh = vppcom_session_create (VPPCOM_PROTO_UDP, 0 /* is_nonblocking */);
  if (vcl_sh < 0)
    {
      vterr ("vppcom_session_create()", vcl_sh);
      return;
    }

  rv = vppcom_session_bind (vcl_sh, &vclum->endpt);
  if (rv < 0)
    {
      vterr ("vppcom_session_bind()", rv);
      return;
    }

  vtinf ("Server successfully bound to endpoint");
  sleep (vclum->timeout_seconds);
  vppcom_session_close (vcl_sh);
  vtinf ("Server test completed");
}

int
main (int argc, char **argv)
{
  vt_clu_main_t *vclum = &vt_clu_main;
  int rv;

  vt_clu_parse_args (vclum, argc, argv);

  /* Initialize VCL with programmatic configuration using new API */
  rv = vppcom_app_create_with_config (&vclum->vcl_cfg);
  if (rv)
    {
      vterr ("vppcom_app_create_with_config() failed", rv);
      return rv;
    }

  vtinf ("Starting server [using programmatic VCL config]");

  if (vclum->vcl_cfg.namespace_id)
    vtinf ("Using namespace: %s", vclum->vcl_cfg.namespace_id);
  if (vclum->vcl_cfg.vpp_bapi_socket_name)
    vtinf ("Using VPP API socket: %s", vclum->vcl_cfg.vpp_bapi_socket_name);

  /* Run the server test */
  vt_clu_server_test (vclum);

  vtinf ("Server test completed");

  vppcom_app_destroy ();
  return 0;
}
