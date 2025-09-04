/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

/*
 * VCL Configuration Test 
 * Modified to use vppcom_app_create_with_config() API instead of environment variables
 *
 * Usage:
 *   Usage: vcl_cfg_test -s <server_ip> [-w <num_workers>] [-d <debug_level>] [-n <namespace>]
 *
 * Options:
 *   -s <ip>    Start as server bound to specified IP address
 *   -w <num>   Number of worker threads (default: 1)
 *   -d <level> Debug level (default: 0)
 *   -n <ns>    Namespace ID
 *   -a <socket> VPP API socket path
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
// #include <vcl/vcl_private.h>
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
  int num_workers;
  pthread_t *worker_threads;
  int thread_id_counter;
  volatile int msgs_received;
  
  /* VCL configuration structure */
  vppcom_cfg_t vcl_cfg;
//   u32 debug_level;
} vt_clu_main_t;

static vt_clu_main_t vt_clu_main;

typedef struct vtclu_worker_args_
{
  vt_clu_main_t *vclum;
  int worker_id;
} vtclu_worker_args_t;

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
  
  /* Test-specific defaults */
//   vclum->debug_level = 0;
}

/* Helper function to set namespace ID */
// static void
// vcl_test_set_namespace_id (vppcom_cfg_t *cfg, const char *namespace_id)
// {
//   if (namespace_id)
//     {
//       u32 ns_id_len = strlen (namespace_id);
//       vec_reset_length (cfg->namespace_id);
//       vec_validate (cfg->namespace_id, ns_id_len - 1);
//       clib_memcpy (cfg->namespace_id, namespace_id, ns_id_len);
//     }
// }

/* Helper function to set VPP API socket path */
// static void
// vcl_test_set_api_socket (vppcom_cfg_t *cfg, const char *socket_path)
// {
//   if (socket_path)
//     {
//       cfg->vpp_app_socket_api = format (0, "%s%c", socket_path, 0);
//     }
// }

static void
vt_clu_parse_args (vt_clu_main_t *vclum, int argc, char **argv)
{
  int c;

  memset (vclum, 0, sizeof (*vclum));
  vclum->port = VCL_TEST_SERVER_PORT;
  vclum->num_workers = 1;
  
  /* Initialize VCL configuration with defaults */
  vcl_test_config_init (vclum);

  opterr = 0;
  while ((c = getopt (argc, argv, "s:w:d:n:a:")) != -1)
    switch (c)
      {
      case 's':
	vclum->app_type = VT_CLU_TYPE_SERVER;
	if (inet_pton (
	      AF_INET, optarg,
	      &((struct sockaddr_in *) &vclum->srvr_addr)->sin_addr) != 1)
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
	/* Set debug level programmatically */
	vclum->vcl_cfg.debug_level = atoi (optarg);
	break;
      case 'n':
	/* Set namespace ID programmatically */
	// vcl_test_set_namespace_id (&vclum->vcl_cfg, optarg);
        vclum->vcl_cfg.namespace_id = optarg;
	break;
      case 'a':
	/* Set VPP API socket path programmatically */
	// vcl_test_set_api_socket (&vclum->vcl_cfg, optarg);
        vclum->vcl_cfg.vpp_app_socket_api = optarg;
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

static int
vt_clu_test_done (vt_clu_main_t *vclum)
{
  return vclum->msgs_received >= vclum->num_workers;
}


static void *
vt_clu_server_worker (void *arg)
{
  vtclu_worker_args_t *args = (vtclu_worker_args_t *) arg;
  vt_clu_main_t *vclum = args->vclum;
  int worker_id = args->worker_id;
  int rv, vcl_sh;
//  const int buflen = 64;
//  char buf[buflen];
//  struct sockaddr_in _addr;
// vppcom_endpt_t rmt_ep = { .ip = (void *) &_addr };

  if (worker_id)
    vppcom_worker_register ();

  vtinf ("Server worker %d starting", worker_id);

  vcl_sh = vppcom_session_create (VPPCOM_PROTO_UDP, 0 /* is_nonblocking */);
  if (vcl_sh < 0)
    {
      vterr ("vppcom_session_create()", vcl_sh);
      return NULL;
    }

  /* Bind to the same endpoint as main thread */
  rv = vppcom_session_bind (vcl_sh, &vclum->endpt);
  if (rv < 0)
    {
      vterr ("vppcom_session_bind()", rv);
      return NULL;
    }

//   vt_clu_catch_sig (vt_clu_sig_handler);
//   if (setjmp (sig_jmp_buf))
//     vt_clu_handle_sig (vclum, worker_id);

//   while (!vt_clu_test_done (vclum))
//     {
//       rv = vppcom_session_recvfrom (vcl_sh, buf, buflen, 0, &rmt_ep);
//       if (rv < 0)
// 	{
// 	  vtwrn ("worker %d: recvfrom returned %d", worker_id, rv);
// 	  break;
// 	}
//       buf[rv] = 0;

//       vtinf ("Worker %d received message from client %s: %s", worker_id,
// 	     vt_clu_ep_to_str (&rmt_ep), buf);
//       vt_atomic_add (&vclum->msgs_received, 1);

//       char response[buflen];
//       int msg_len =
// 	snprintf (response, buflen, "hello from worker %d", worker_id);

//       /* send 2 times to be sure */
//       for (int i = 0; i < 2; i++)
// 	{
// 	  rv = vppcom_session_sendto (vcl_sh, response, msg_len, 0, &rmt_ep);
// 	  if (rv < 0)
// 	    {
// 	      vtwrn ("worker %d: sendto returned %d", worker_id, rv);
// 	      break;
// 	    }
// 	  usleep (500);
// 	}
//     }

  vppcom_session_close (vcl_sh);
  vtinf ("Server worker %d exiting", worker_id);
  return NULL;
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

//   /* Set debug level separately since it's stored in vcm->debug */
//   if (vclum->debug_level > 0)
//     {
//       extern vppcom_main_t *vcm;
//       vcm->debug = vclum->debug_level;
//       vtinf ("Debug level set to %u", vclum->debug_level);
//     }

  vtinf ("Starting server with %d worker(s) [using programmatic VCL config]",
	 vclum->num_workers);

  if (vec_len (vclum->vcl_cfg.namespace_id))
    vtinf ("Using namespace: %s", vclum->vcl_cfg.namespace_id);
  if (vclum->vcl_cfg.vpp_bapi_socket_name)
    vtinf ("Using VPP API socket: %s", vclum->vcl_cfg.vpp_bapi_socket_name);

  vclum->worker_threads = calloc (vclum->num_workers, sizeof (pthread_t));
  vtclu_worker_args_t *worker_args =
    calloc (vclum->num_workers, sizeof (vtclu_worker_args_t));

  if (!vclum->worker_threads || !worker_args)
    {
      vterr ("Failed to allocate memory for worker threads", -1);
      return -1;
    }

  void *(*worker_func) (void *) = vt_clu_server_worker;

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
