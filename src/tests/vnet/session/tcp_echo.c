/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <stdio.h>
#include <signal.h>

#include <vnet/session/application_interface.h>
#include <svm/svm_fifo_segment.h>
#include <vlibmemory/api.h>

#include <vpp/api/vpe_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun

#define TCP_ECHO_DBG 0
#define DBG(_fmt,_args...)			\
    if (TCP_ECHO_DBG) 				\
      clib_warning (_fmt, _args)

typedef struct
{
  svm_fifo_t *server_rx_fifo;
  svm_fifo_t *server_tx_fifo;

  svm_msg_q_t *vpp_evt_q;

  u64 vpp_session_handle;
  u64 bytes_sent;
  u64 bytes_to_send;
  volatile u64 bytes_received;
  volatile u64 bytes_to_receive;
  f64 start;
} session_t;

typedef enum
{
  STATE_START,
  STATE_ATTACHED,
  STATE_LISTEN,
  STATE_READY,
  STATE_DISCONNECTING,
  STATE_FAILED,
  STATE_DETACHED
} connection_state_t;

typedef struct
{
  /* vpe input queue */
  svm_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  /* The URI we're playing with */
  u8 *uri;

  /* Session pool */
  session_t *sessions;

  /* Hash table for disconnect processing */
  uword *session_index_by_vpp_handles;

  /* intermediate rx buffer */
  u8 *rx_buf;

  /* URI for slave's connect */
  u8 *connect_uri;

  u32 connected_session_index;

  int i_am_master;

  /* drop all packets */
  int no_return;

  /* Our event queue */
  svm_msg_q_t *our_event_queue;

  u8 *socket_name;

  pid_t my_pid;

  /* For deadman timers */
  clib_time_t clib_time;

  /* State of the connection, shared between msg RX thread and main thread */
  volatile connection_state_t state;

  /* Signal variables */
  volatile int time_to_stop;
  volatile int time_to_print_stats;

  u32 configured_segment_size;

  /* VNET_API_ERROR_FOO -> "Foo" hash table */
  uword *error_string_by_error_number;

  u8 *connect_test_data;
  pthread_t *client_thread_handles;
  u32 *thread_args;
  u32 client_bytes_received;
  u8 test_return_packets;
  u64 bytes_to_send;
  u32 fifo_size;

  u32 n_clients;
  u64 tx_total;
  u64 rx_total;

  volatile u32 n_clients_connected;
  volatile u32 n_active_clients;


  /** Flag that decides if socket, instead of svm, api is used to connect to
   * vpp. If sock api is used, shm binary api is subsequently bootstrapped
   * and all other messages are exchanged using shm IPC. */
  u8 use_sock_api;

  svm_fifo_segment_main_t segment_main;
} echo_main_t;

echo_main_t echo_main;

#if CLIB_DEBUG > 0
#define NITER 10000
#else
#define NITER 4000000
#endif

const char test_srv_crt_rsa[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIID5zCCAs+gAwIBAgIJALeMYCEHrTtJMA0GCSqGSIb3DQEBCwUAMIGJMQswCQYD\r\n"
  "VQQGEwJVUzELMAkGA1UECAwCQ0ExETAPBgNVBAcMCFNhbiBKb3NlMQ4wDAYDVQQK\r\n"
  "DAVDaXNjbzEOMAwGA1UECwwFZmQuaW8xFjAUBgNVBAMMDXRlc3R0bHMuZmQuaW8x\r\n"
  "IjAgBgkqhkiG9w0BCQEWE3ZwcC1kZXZAbGlzdHMuZmQuaW8wHhcNMTgwMzA1MjEx\r\n"
  "NTEyWhcNMjgwMzAyMjExNTEyWjCBiTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNB\r\n"
  "MREwDwYDVQQHDAhTYW4gSm9zZTEOMAwGA1UECgwFQ2lzY28xDjAMBgNVBAsMBWZk\r\n"
  "LmlvMRYwFAYDVQQDDA10ZXN0dGxzLmZkLmlvMSIwIAYJKoZIhvcNAQkBFhN2cHAt\r\n"
  "ZGV2QGxpc3RzLmZkLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\r\n"
  "4C1k8a1DuStgggqT4o09fP9sJ2dC54bxhS/Xk2VEfaIZ222WSo4X/syRVfVy9Yah\r\n"
  "cpI1zJ/RDxaZSFhgA+nPZBrFMsrULkrdAOpOVj8eDEp9JuWdO2ODSoFnCvLxcYWB\r\n"
  "Yc5kHryJpEaGJl1sFQSesnzMFty/59ta0stk0Fp8r5NhIjWvSovGzPo6Bhz+VS2c\r\n"
  "ebIZh4x1t2hHaFcgm0qJoJ6DceReWCW8w+yOVovTolGGq+bpb2Hn7MnRSZ2K2NdL\r\n"
  "+aLXpkZbS/AODP1FF2vTO1mYL290LO7/51vJmPXNKSDYMy5EvILr5/VqtjsFCwRL\r\n"
  "Q4jcM/+GeHSAFWx4qIv0BwIDAQABo1AwTjAdBgNVHQ4EFgQUWa1SOB37xmT53tZQ\r\n"
  "aXuLLhRI7U8wHwYDVR0jBBgwFoAUWa1SOB37xmT53tZQaXuLLhRI7U8wDAYDVR0T\r\n"
  "BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAoUht13W4ya27NVzQuCMvqPWL3VM4\r\n"
  "3xbPFk02FaGz/WupPu276zGlzJAZrbuDcQowwwU1Ni1Yygxl96s1c2M5rHDTrOKG\r\n"
  "rK0hbkSFBo+i6I8u4HiiQ4rYmG0Hv6+sXn3of0HsbtDPGgWZoipPWDljPYEURu3e\r\n"
  "3HRe/Dtsj9CakBoSDzs8ndWaBR+f4sM9Tk1cjD46Gq2T/qpSPXqKxEUXlzhdCAn4\r\n"
  "twub17Bq2kykHpppCwPg5M+v30tHG/R2Go15MeFWbEJthFk3TZMjKL7UFs7fH+x2\r\n"
  "wSonXb++jY+KmCb93C+soABBizE57g/KmiR2IxQ/LMjDik01RSUIaM0lLA==\r\n"
  "-----END CERTIFICATE-----\r\n";
const u32 test_srv_crt_rsa_len = sizeof (test_srv_crt_rsa);

const char test_srv_key_rsa[] =
  "-----BEGIN PRIVATE KEY-----\r\n"
  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDgLWTxrUO5K2CC\r\n"
  "CpPijT18/2wnZ0LnhvGFL9eTZUR9ohnbbZZKjhf+zJFV9XL1hqFykjXMn9EPFplI\r\n"
  "WGAD6c9kGsUyytQuSt0A6k5WPx4MSn0m5Z07Y4NKgWcK8vFxhYFhzmQevImkRoYm\r\n"
  "XWwVBJ6yfMwW3L/n21rSy2TQWnyvk2EiNa9Ki8bM+joGHP5VLZx5shmHjHW3aEdo\r\n"
  "VyCbSomgnoNx5F5YJbzD7I5Wi9OiUYar5ulvYefsydFJnYrY10v5otemRltL8A4M\r\n"
  "/UUXa9M7WZgvb3Qs7v/nW8mY9c0pINgzLkS8guvn9Wq2OwULBEtDiNwz/4Z4dIAV\r\n"
  "bHioi/QHAgMBAAECggEBAMzGipP8+oT166U+NlJXRFifFVN1DvdhG9PWnOxGL+c3\r\n"
  "ILmBBC08WQzmHshPemBvR6DZkA1H23cV5JTiLWrFtC00CvhXsLRMrE5+uWotI6yE\r\n"
  "iofybMroHvD6/X5R510UX9hQ6MHu5ShLR5VZ9zXHz5MpTmB/60jG5dLx+jgcwBK8\r\n"
  "LuGv2YB/WCUwT9QJ3YU2eaingnXtz/MrFbkbltrqlnBdlD+kTtw6Yac9y1XuuQXc\r\n"
  "BPeulLNDuPolJVWbUvDBZrpt2dXTgz8ws1sv+wCNE0xwQJsqW4Nx3QkpibUL9RUr\r\n"
  "CVbKlNfa9lopT6nGKlgX69R/uH35yh9AOsfasro6w0ECgYEA82UJ8u/+ORah+0sF\r\n"
  "Q0FfW5MTdi7OAUHOz16pUsGlaEv0ERrjZxmAkHA/VRwpvDBpx4alCv0Hc39PFLIk\r\n"
  "nhSsM2BEuBkTAs6/GaoNAiBtQVE/hN7awNRWVmlieS0go3Y3dzaE9IUMyj8sPOFT\r\n"
  "5JdJ6BM69PHKCkY3dKdnnfpFEuECgYEA68mRpteunF1mdZgXs+WrN+uLlRrQR20F\r\n"
  "ZyMYiUCH2Dtn26EzA2moy7FipIIrQcX/j+KhYNGM3e7MU4LymIO29E18mn8JODnH\r\n"
  "sQOXzBTsf8A4yIVMkcuQD3bfb0JiUGYUPOidTp2N7IJA7+6Yc3vQOyb74lnKnJoO\r\n"
  "gougPT2wS+cCgYAn7muzb6xFsXDhyW0Tm6YJYBfRS9yAWEuVufINobeBZPSl2cN1\r\n"
  "Jrnw+HlrfTNbrJWuJmjtZJXUXQ6cVp2rUbjutNyRV4vG6iRwEXYQ40EJdkr1gZpi\r\n"
  "CHQhuShuuPih2MNAy7EEbM+sXrDjTBR3bFqzuHPzu7dp+BshCFX3lRfAAQKBgGQt\r\n"
  "K5i7IhCFDjb/+3IPLgOAK7mZvsvZ4eXD33TQ2eZgtut1PXtBtNl17/b85uv293Fm\r\n"
  "VDISVcsk3eLNS8zIiT6afUoWlxAwXEs0v5WRfjl4radkGvgGiJpJYvyeM67877RB\r\n"
  "EDSKc/X8ESLfOB44iGvZUEMG6zJFscx9DgN25iQZAoGAbyd+JEWwdVH9/K3IH1t2\r\n"
  "PBkZX17kNWv+iVM1WyFjbe++vfKZCrOJiyiqhDeEqgrP3AuNMlaaduC3VRC3G5oV\r\n"
  "Mj1tlhDWQ/qhvKdCKNdIVQYDE75nw+FRWV8yYkHAnXYW3tNoweDIwixE0hkPR1bc\r\n"
  "oEjPLVNtx8SOj/M4rhaPT3I=\r\n" "-----END PRIVATE KEY-----\r\n";
const u32 test_srv_key_rsa_len = sizeof (test_srv_key_rsa);

static u8 *
format_api_error (u8 * s, va_list * args)
{
  echo_main_t *em = &echo_main;
  i32 error = va_arg (*args, u32);
  uword *p;

  p = hash_get (em->error_string_by_error_number, -error);

  if (p)
    s = format (s, "%s", p[0]);
  else
    s = format (s, "%d", error);
  return s;
}

static void
init_error_string_table (echo_main_t * em)
{
  em->error_string_by_error_number = hash_create (0, sizeof (uword));

#define _(n,v,s) hash_set (em->error_string_by_error_number, -v, s);
  foreach_vnet_api_error;
#undef _

  hash_set (em->error_string_by_error_number, 99, "Misc");
}

static void handle_mq_event (session_event_t * e);

static int
wait_for_state_change (echo_main_t * em, connection_state_t state)
{
  svm_msg_q_msg_t msg;
  session_event_t *e;
  f64 timeout;

#if CLIB_DEBUG > 0
#define TIMEOUT 600.0
#else
#define TIMEOUT 600.0
#endif

  timeout = clib_time_now (&em->clib_time) + TIMEOUT;

  while (clib_time_now (&em->clib_time) < timeout)
    {
      if (em->state == state)
	return 0;
      if (em->state == STATE_FAILED)
	return -1;
      if (em->time_to_stop == 1)
	return 0;
      if (!em->our_event_queue || em->state < STATE_ATTACHED)
	continue;

      if (svm_msg_q_sub (em->our_event_queue, &msg, SVM_Q_NOWAIT, 0))
	continue;
      e = svm_msg_q_msg_data (em->our_event_queue, &msg);
      handle_mq_event (e);
      svm_msg_q_free_msg (em->our_event_queue, &msg);
    }
  clib_warning ("timeout waiting for state %d", state);
  return -1;
}

void
application_send_attach (echo_main_t * em)
{
  vl_api_application_attach_t *bmp;
  vl_api_application_tls_cert_add_t *cert_mp;
  vl_api_application_tls_key_add_t *key_mp;

  bmp = vl_msg_api_alloc (sizeof (*bmp));
  clib_memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_ATTACH);
  bmp->client_index = em->my_client_index;
  bmp->context = ntohl (0xfeedface);
  bmp->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_ACCEPT_REDIRECT;
  bmp->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_ADD_SEGMENT;
  bmp->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_MQ_FOR_CTRL_MSGS;
  bmp->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 16;
  bmp->options[APP_OPTIONS_RX_FIFO_SIZE] = em->fifo_size;
  bmp->options[APP_OPTIONS_TX_FIFO_SIZE] = em->fifo_size;
  bmp->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 128 << 20;
  bmp->options[APP_OPTIONS_SEGMENT_SIZE] = 256 << 20;
  bmp->options[APP_OPTIONS_EVT_QUEUE_SIZE] = 256;
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & bmp);

  cert_mp = vl_msg_api_alloc (sizeof (*cert_mp) + test_srv_crt_rsa_len);
  clib_memset (cert_mp, 0, sizeof (*cert_mp));
  cert_mp->_vl_msg_id = ntohs (VL_API_APPLICATION_TLS_CERT_ADD);
  cert_mp->client_index = em->my_client_index;
  cert_mp->context = ntohl (0xfeedface);
  cert_mp->cert_len = clib_host_to_net_u16 (test_srv_crt_rsa_len);
  clib_memcpy_fast (cert_mp->cert, test_srv_crt_rsa, test_srv_crt_rsa_len);
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & cert_mp);

  key_mp = vl_msg_api_alloc (sizeof (*key_mp) + test_srv_key_rsa_len);
  clib_memset (key_mp, 0, sizeof (*key_mp) + test_srv_key_rsa_len);
  key_mp->_vl_msg_id = ntohs (VL_API_APPLICATION_TLS_KEY_ADD);
  key_mp->client_index = em->my_client_index;
  key_mp->context = ntohl (0xfeedface);
  key_mp->key_len = clib_host_to_net_u16 (test_srv_key_rsa_len);
  clib_memcpy_fast (key_mp->key, test_srv_key_rsa, test_srv_key_rsa_len);
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & key_mp);
}

static int
application_attach (echo_main_t * em)
{
  application_send_attach (em);
  if (wait_for_state_change (em, STATE_ATTACHED))
    {
      clib_warning ("timeout waiting for STATE_ATTACHED");
      return -1;
    }
  return 0;
}

void
application_detach (echo_main_t * em)
{
  vl_api_application_detach_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  clib_memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_DETACH);
  bmp->client_index = em->my_client_index;
  bmp->context = ntohl (0xfeedface);
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & bmp);

  DBG ("%s", "Sent detach");
}

static int
ssvm_segment_attach (char *name, ssvm_segment_type_t type, int fd)
{
  svm_fifo_segment_create_args_t _a, *a = &_a;
  svm_fifo_segment_main_t *sm = &echo_main.segment_main;
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->segment_name = (char *) name;
  a->segment_type = type;

  if (type == SSVM_SEGMENT_MEMFD)
    a->memfd_fd = fd;

  if ((rv = svm_fifo_segment_attach (sm, a)))
    {
      clib_warning ("svm_fifo_segment_attach ('%s') failed", name);
      return rv;
    }

  vec_reset_length (a->new_segment_indices);
  return 0;
}

static void
vl_api_application_attach_reply_t_handler (vl_api_application_attach_reply_t *
					   mp)
{
  echo_main_t *em = &echo_main;
  int *fds = 0;
  u32 n_fds = 0;

  if (mp->retval)
    {
      clib_warning ("attach failed: %U", format_api_error,
		    clib_net_to_host_u32 (mp->retval));
      goto failed;
    }

  if (mp->segment_name_length == 0)
    {
      clib_warning ("segment_name_length zero");
      goto failed;
    }

  ASSERT (mp->app_event_queue_address);
  em->our_event_queue = uword_to_pointer (mp->app_event_queue_address,
					  svm_msg_q_t *);

  if (mp->n_fds)
    {
      vec_validate (fds, mp->n_fds);
      vl_socket_client_recv_fd_msg (fds, mp->n_fds, 5);

      if (mp->fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
	if (ssvm_segment_attach (0, SSVM_SEGMENT_MEMFD, fds[n_fds++]))
	  goto failed;

      if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
	if (ssvm_segment_attach ((char *) mp->segment_name,
				 SSVM_SEGMENT_MEMFD, fds[n_fds++]))
	  goto failed;

      if (mp->fd_flags & SESSION_FD_F_MQ_EVENTFD)
	svm_msg_q_set_consumer_eventfd (em->our_event_queue, fds[n_fds++]);

      vec_free (fds);
    }
  else
    {
      if (ssvm_segment_attach ((char *) mp->segment_name, SSVM_SEGMENT_SHM,
			       -1))
	goto failed;
    }

  em->state = STATE_ATTACHED;
  return;
failed:
  em->state = STATE_FAILED;
  return;
}

static void
vl_api_application_detach_reply_t_handler (vl_api_application_detach_reply_t *
					   mp)
{
  if (mp->retval)
    clib_warning ("detach returned with err: %d", mp->retval);
  echo_main.state = STATE_DETACHED;
}

static void
stop_signal (int signum)
{
  echo_main_t *um = &echo_main;

  um->time_to_stop = 1;
}

static void
stats_signal (int signum)
{
  echo_main_t *um = &echo_main;

  um->time_to_print_stats = 1;
}

static clib_error_t *
setup_signal_handlers (void)
{
  signal (SIGINT, stats_signal);
  signal (SIGQUIT, stop_signal);
  signal (SIGTERM, stop_signal);

  return 0;
}

void
vlib_cli_output (struct vlib_main_t *vm, char *fmt, ...)
{
  clib_warning ("BUG");
}

int
connect_to_vpp (char *name)
{
  echo_main_t *em = &echo_main;
  api_main_t *am = &api_main;

  if (em->use_sock_api)
    {
      if (vl_socket_client_connect ((char *) em->socket_name, name,
				    0 /* default rx, tx buffer */ ))
	{
	  clib_warning ("socket connect failed");
	  return -1;
	}

      if (vl_socket_client_init_shm (0))
	{
	  clib_warning ("init shm api failed");
	  return -1;
	}
    }
  else
    {
      if (vl_client_connect_to_vlib ("/vpe-api", name, 32) < 0)
	{
	  clib_warning ("shmem connect failed");
	  return -1;
	}
    }
  em->vl_input_queue = am->shmem_hdr->vl_input_queue;
  em->my_client_index = am->my_client_index;
  return 0;
}

void
disconnect_from_vpp (echo_main_t * em)
{
  if (em->use_sock_api)
    vl_socket_client_disconnect ();
  else
    vl_client_disconnect_from_vlib ();
}

static void
vl_api_map_another_segment_t_handler (vl_api_map_another_segment_t * mp)
{
  svm_fifo_segment_main_t *sm = &echo_main.segment_main;
  svm_fifo_segment_create_args_t _a, *a = &_a;
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->segment_name = (char *) mp->segment_name;
  a->segment_size = mp->segment_size;
  /* Attach to the segment vpp created */
  rv = svm_fifo_segment_attach (sm, a);
  if (rv)
    {
      clib_warning ("svm_fifo_segment_attach ('%s') failed",
		    mp->segment_name);
      return;
    }
  clib_warning ("Mapped new segment '%s' size %d", mp->segment_name,
		mp->segment_size);
}

static void
session_print_stats (echo_main_t * em, session_t * session)
{
  f64 deltat;
  u64 bytes;

  deltat = clib_time_now (&em->clib_time) - session->start;
  bytes = em->i_am_master ? session->bytes_received : em->bytes_to_send;
  fformat (stdout, "Finished in %.6f\n", deltat);
  fformat (stdout, "%.4f Gbit/second\n", (bytes * 8.0) / deltat / 1e9);
}

static void
test_recv_bytes (session_t * s, u8 * rx_buf, u32 n_read)
{
  int i;
  for (i = 0; i < n_read; i++)
    {
      if (rx_buf[i] != ((s->bytes_received + i) & 0xff))
	{
	  clib_warning ("error at byte %lld, 0x%x not 0x%x",
			s->bytes_received + i, rx_buf[i],
			((s->bytes_received + i) & 0xff));
	}
    }
}

static void
recv_test_chunk (echo_main_t * em, session_t * s, u8 * rx_buf)
{
  svm_fifo_t *rx_fifo = s->server_rx_fifo;
  u32 n_read_now, n_to_read;
  int n_read;

  n_to_read = svm_fifo_max_dequeue (rx_fifo);
  svm_fifo_unset_event (rx_fifo);

  do
    {
      n_read_now = clib_min (vec_len (rx_buf), n_to_read);
      n_read = svm_fifo_dequeue_nowait (rx_fifo, n_read_now, rx_buf);
      if (n_read <= 0)
	break;

      if (n_read_now != n_read)
	clib_warning ("huh?");

      if (em->test_return_packets)
	test_recv_bytes (s, rx_buf, n_read);

      n_to_read -= n_read;
      s->bytes_received += n_read;
      s->bytes_to_receive -= n_read;
    }
  while (n_to_read > 0);
}

void
client_handle_fifo_event_rx (echo_main_t * em, session_event_t * e,
			     u8 * rx_buf)
{
  session_t *s;

  s = pool_elt_at_index (em->sessions, e->fifo->client_session_index);
  recv_test_chunk (em, s, rx_buf);
}

static void
send_test_chunk (echo_main_t * em, session_t * s)
{
  u64 test_buf_len, bytes_this_chunk, test_buf_offset;
  svm_fifo_t *tx_fifo = s->server_tx_fifo;
  u8 *test_data = em->connect_test_data;
  u32 enq_space = 16 << 10;
  int written;

  test_buf_len = vec_len (test_data);
  test_buf_offset = s->bytes_sent % test_buf_len;
  bytes_this_chunk = clib_min (test_buf_len - test_buf_offset,
			       s->bytes_to_send);
  enq_space = svm_fifo_max_enqueue (tx_fifo);

  bytes_this_chunk = clib_min (bytes_this_chunk, enq_space);
  written = svm_fifo_enqueue_nowait (tx_fifo, bytes_this_chunk,
				     test_data + test_buf_offset);

  if (written > 0)
    {
      s->bytes_to_send -= written;
      s->bytes_sent += written;

      if (svm_fifo_set_event (tx_fifo))
	app_send_io_evt_to_vpp (s->vpp_evt_q, tx_fifo, FIFO_EVENT_APP_TX,
				0 /* do wait for mutex */ );
    }
}

/*
 * Rx/Tx polling thread per connection
 */
static void *
client_thread_fn (void *arg)
{
  echo_main_t *em = &echo_main;
  static u8 *rx_buf = 0;
  u32 session_index = *(u32 *) arg;
  session_t *s;

  vec_validate (rx_buf, 1 << 20);

  while (!em->time_to_stop && em->state != STATE_READY)
    ;

  s = pool_elt_at_index (em->sessions, session_index);
  while (!em->time_to_stop)
    {
      send_test_chunk (em, s);
      recv_test_chunk (em, s, rx_buf);
      if (!s->bytes_to_send && !s->bytes_to_receive)
	break;
    }

  DBG ("session %d done", session_index);
  em->tx_total += s->bytes_sent;
  em->rx_total += s->bytes_received;
  em->n_active_clients--;

  pthread_exit (0);
}

/*
 * Rx thread that handles all connections.
 *
 * Not used.
 */
void *
client_rx_thread_fn (void *arg)
{
  session_event_t _e, *e = &_e;
  echo_main_t *em = &echo_main;
  static u8 *rx_buf = 0;
  svm_msg_q_msg_t msg;

  vec_validate (rx_buf, 1 << 20);

  while (!em->time_to_stop && em->state != STATE_READY)
    ;

  while (!em->time_to_stop)
    {
      svm_msg_q_sub (em->our_event_queue, &msg, SVM_Q_WAIT, 0);
      e = svm_msg_q_msg_data (em->our_event_queue, &msg);
      switch (e->event_type)
	{
	case FIFO_EVENT_APP_RX:
	  client_handle_fifo_event_rx (em, e, rx_buf);
	  break;
	default:
	  clib_warning ("unknown event type %d", e->event_type);
	  break;
	}
      svm_msg_q_free_msg (em->our_event_queue, &msg);
    }
  pthread_exit (0);
}

void
client_send_connect (echo_main_t * em)
{
  vl_api_connect_uri_t *cmp;
  cmp = vl_msg_api_alloc (sizeof (*cmp));
  clib_memset (cmp, 0, sizeof (*cmp));

  cmp->_vl_msg_id = ntohs (VL_API_CONNECT_URI);
  cmp->client_index = em->my_client_index;
  cmp->context = ntohl (0xfeedface);
  memcpy (cmp->uri, em->connect_uri, vec_len (em->connect_uri));
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & cmp);
}

void
client_send_disconnect (echo_main_t * em, session_t * s)
{
  vl_api_disconnect_session_t *dmp;
  dmp = vl_msg_api_alloc (sizeof (*dmp));
  clib_memset (dmp, 0, sizeof (*dmp));
  dmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION);
  dmp->client_index = em->my_client_index;
  dmp->handle = s->vpp_session_handle;
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & dmp);
}

int
client_disconnect (echo_main_t * em, session_t * s)
{
  client_send_disconnect (em, s);
  pool_put (em->sessions, s);
  clib_memset (s, 0xfe, sizeof (*s));
  return 0;
}

static void
session_accepted_handler (session_accepted_msg_t * mp)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_accepted_reply_msg_t *rmp;
  svm_fifo_t *rx_fifo, *tx_fifo;
  echo_main_t *em = &echo_main;
  session_t *session;
  static f64 start_time;
  u32 session_index;
  u8 *ip_str;

  if (start_time == 0.0)
    start_time = clib_time_now (&em->clib_time);

  ip_str = format (0, "%U", format_ip46_address, &mp->ip, mp->is_ip4);
  clib_warning ("Accepted session from: %s:%d", ip_str,
		clib_net_to_host_u16 (mp->port));

  /* Allocate local session and set it up */
  pool_get (em->sessions, session);
  session_index = session - em->sessions;

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session_index;
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session_index;

  session->server_rx_fifo = rx_fifo;
  session->server_tx_fifo = tx_fifo;
  session->vpp_evt_q = uword_to_pointer (mp->vpp_event_queue_address,
					 svm_msg_q_t *);

  /* Add it to lookup table */
  hash_set (em->session_index_by_vpp_handles, mp->handle, session_index);

  em->state = STATE_READY;

  /* Stats printing */
  if (pool_elts (em->sessions) && (pool_elts (em->sessions) % 20000) == 0)
    {
      f64 now = clib_time_now (&em->clib_time);
      fformat (stdout, "%d active sessions in %.2f seconds, %.2f/sec...\n",
	       pool_elts (em->sessions), now - start_time,
	       (f64) pool_elts (em->sessions) / (now - start_time));
    }

  /*
   * Send accept reply to vpp
   */
  app_alloc_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_ACCEPTED_REPLY);
  rmp = (session_accepted_reply_msg_t *) app_evt->evt->data;
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  app_send_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt);

  session->bytes_received = 0;
  session->start = clib_time_now (&em->clib_time);
}

static void
session_connected_handler (session_connected_msg_t * mp)
{
  echo_main_t *em = &echo_main;
  session_t *session;
  u32 session_index;
  svm_fifo_t *rx_fifo, *tx_fifo;
  int rv;

  if (mp->retval)
    {
      clib_warning ("connection failed with code: %U", format_api_error,
		    clib_net_to_host_u32 (mp->retval));
      em->state = STATE_FAILED;
      return;
    }

  /*
   * Setup session
   */

  pool_get (em->sessions, session);
  clib_memset (session, 0, sizeof (*session));
  session_index = session - em->sessions;

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session_index;
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session_index;

  session->server_rx_fifo = rx_fifo;
  session->server_tx_fifo = tx_fifo;
  session->vpp_session_handle = mp->handle;
  session->start = clib_time_now (&em->clib_time);
  session->vpp_evt_q = uword_to_pointer (mp->vpp_event_queue_address,
					 svm_msg_q_t *);

  hash_set (em->session_index_by_vpp_handles, mp->handle, session_index);

  /*
   * Start RX thread
   */
  em->thread_args[em->n_clients_connected] = session_index;
  rv = pthread_create (&em->client_thread_handles[em->n_clients_connected],
		       NULL /*attr */ , client_thread_fn,
		       (void *) &em->thread_args[em->n_clients_connected]);
  if (rv)
    {
      clib_warning ("pthread_create returned %d", rv);
      return;
    }

  em->n_clients_connected += 1;
  clib_warning ("session %u (0x%llx) connected with local ip %U port %d",
		session_index, mp->handle, format_ip46_address, mp->lcl_ip,
		mp->is_ip4, clib_net_to_host_u16 (mp->lcl_port));
}

static void
session_disconnected_handler (session_disconnected_msg_t * mp)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_disconnected_reply_msg_t *rmp;
  echo_main_t *em = &echo_main;
  session_t *session = 0;
  uword *p;
  int rv = 0;

  p = hash_get (em->session_index_by_vpp_handles, mp->handle);
  if (!p)
    {
      clib_warning ("couldn't find session key %llx", mp->handle);
      return;
    }

  session = pool_elt_at_index (em->sessions, p[0]);
  hash_unset (em->session_index_by_vpp_handles, mp->handle);
  pool_put (em->sessions, session);

  app_alloc_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_DISCONNECTED_REPLY);
  rmp = (session_disconnected_reply_msg_t *) app_evt->evt->data;
  rmp->retval = rv;
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  app_send_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt);

  session_print_stats (em, session);
}

static void
session_reset_handler (session_reset_msg_t * mp)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  echo_main_t *em = &echo_main;
  session_reset_reply_msg_t *rmp;
  session_t *session = 0;
  uword *p;
  int rv = 0;

  p = hash_get (em->session_index_by_vpp_handles, mp->handle);

  if (p)
    {
      session = pool_elt_at_index (em->sessions, p[0]);
      clib_warning ("got reset");
      /* Cleanup later */
      em->time_to_stop = 1;
    }
  else
    {
      clib_warning ("couldn't find session key %llx", mp->handle);
      return;
    }

  app_alloc_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_RESET_REPLY);
  rmp = (session_reset_reply_msg_t *) app_evt->evt->data;
  rmp->retval = rv;
  rmp->handle = mp->handle;
  app_send_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt);
}

static void
handle_mq_event (session_event_t * e)
{
  switch (e->event_type)
    {
    case SESSION_CTRL_EVT_ACCEPTED:
      session_accepted_handler ((session_accepted_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_CONNECTED:
      session_connected_handler ((session_connected_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_DISCONNECTED:
      session_disconnected_handler ((session_disconnected_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_RESET:
      session_reset_handler ((session_reset_msg_t *) e->data);
      break;
    default:
      clib_warning ("unhandled %u", e->event_type);
    }
}

static void
clients_run (echo_main_t * em)
{
  f64 start_time, deltat, timeout = 100.0;
  svm_msg_q_msg_t msg;
  session_event_t *e;
  session_t *s;
  int i;

  /* Init test data */
  vec_validate (em->connect_test_data, 1024 * 1024 - 1);
  for (i = 0; i < vec_len (em->connect_test_data); i++)
    em->connect_test_data[i] = i & 0xff;

  /*
   * Attach and connect the clients
   */
  if (application_attach (em))
    return;

  for (i = 0; i < em->n_clients; i++)
    client_send_connect (em);

  start_time = clib_time_now (&em->clib_time);
  while (em->n_clients_connected < em->n_clients
	 && (clib_time_now (&em->clib_time) - start_time < timeout)
	 && em->state != STATE_FAILED)

    {
      svm_msg_q_sub (em->our_event_queue, &msg, SVM_Q_WAIT, 0);
      e = svm_msg_q_msg_data (em->our_event_queue, &msg);
      handle_mq_event (e);
      svm_msg_q_free_msg (em->our_event_queue, &msg);
    }

  if (em->n_clients_connected != em->n_clients)
    {
      clib_warning ("failed to initialize all connections");
      return;
    }

  /*
   * Initialize connections
   */
  for (i = 0; i < em->n_clients; i++)
    {
      s = pool_elt_at_index (em->sessions, i);
      s->bytes_to_send = em->bytes_to_send;
      if (!em->no_return)
	s->bytes_to_receive = em->bytes_to_send;
    }
  em->n_active_clients = em->n_clients_connected;

  /*
   * Wait for client threads to send the data
   */
  start_time = clib_time_now (&em->clib_time);
  em->state = STATE_READY;
  while (em->n_active_clients)
    if (!svm_msg_q_is_empty (em->our_event_queue))
      {
	if (svm_msg_q_sub (em->our_event_queue, &msg, SVM_Q_WAIT, 0))
	  {
	    clib_warning ("svm msg q returned");
	    continue;
	  }
	e = svm_msg_q_msg_data (em->our_event_queue, &msg);
	if (e->event_type != FIFO_EVENT_APP_RX)
	  handle_mq_event (e);
	svm_msg_q_free_msg (em->our_event_queue, &msg);
      }

  for (i = 0; i < em->n_clients; i++)
    {
      s = pool_elt_at_index (em->sessions, i);
      client_disconnect (em, s);
    }

  /*
   * Stats and detach
   */
  deltat = clib_time_now (&em->clib_time) - start_time;
  fformat (stdout, "%lld bytes (%lld mbytes, %lld gbytes) in %.2f seconds\n",
	   em->tx_total, em->tx_total / (1ULL << 20),
	   em->tx_total / (1ULL << 30), deltat);
  fformat (stdout, "%.4f Gbit/second\n", (em->tx_total * 8.0) / deltat / 1e9);

  application_detach (em);
}

static void
vl_api_bind_uri_reply_t_handler (vl_api_bind_uri_reply_t * mp)
{
  echo_main_t *em = &echo_main;

  if (mp->retval)
    {
      clib_warning ("bind failed: %U", format_api_error,
		    clib_net_to_host_u32 (mp->retval));
      em->state = STATE_FAILED;
      return;
    }

  em->state = STATE_READY;
}

static void
vl_api_unbind_uri_reply_t_handler (vl_api_unbind_uri_reply_t * mp)
{
  echo_main_t *em = &echo_main;

  if (mp->retval != 0)
    clib_warning ("returned %d", ntohl (mp->retval));

  em->state = STATE_START;
}

u8 *
format_ip4_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

u8 *
format_ip6_address (u8 * s, va_list * args)
{
  ip6_address_t *a = va_arg (*args, ip6_address_t *);
  u32 i, i_max_n_zero, max_n_zeros, i_first_zero, n_zeros, last_double_colon;

  i_max_n_zero = ARRAY_LEN (a->as_u16);
  max_n_zeros = 0;
  i_first_zero = i_max_n_zero;
  n_zeros = 0;
  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      u32 is_zero = a->as_u16[i] == 0;
      if (is_zero && i_first_zero >= ARRAY_LEN (a->as_u16))
	{
	  i_first_zero = i;
	  n_zeros = 0;
	}
      n_zeros += is_zero;
      if ((!is_zero && n_zeros > max_n_zeros)
	  || (i + 1 >= ARRAY_LEN (a->as_u16) && n_zeros > max_n_zeros))
	{
	  i_max_n_zero = i_first_zero;
	  max_n_zeros = n_zeros;
	  i_first_zero = ARRAY_LEN (a->as_u16);
	  n_zeros = 0;
	}
    }

  last_double_colon = 0;
  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      if (i == i_max_n_zero && max_n_zeros > 1)
	{
	  s = format (s, "::");
	  i += max_n_zeros - 1;
	  last_double_colon = 1;
	}
      else
	{
	  s = format (s, "%s%x",
		      (last_double_colon || i == 0) ? "" : ":",
		      clib_net_to_host_u16 (a->as_u16[i]));
	  last_double_colon = 0;
	}
    }

  return s;
}

/* Format an IP46 address. */
u8 *
format_ip46_address (u8 * s, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  ip46_type_t type = va_arg (*args, ip46_type_t);
  int is_ip4 = 1;

  switch (type)
    {
    case IP46_TYPE_ANY:
      is_ip4 = ip46_address_is_ip4 (ip46);
      break;
    case IP46_TYPE_IP4:
      is_ip4 = 1;
      break;
    case IP46_TYPE_IP6:
      is_ip4 = 0;
      break;
    }

  return is_ip4 ?
    format (s, "%U", format_ip4_address, &ip46->ip4) :
    format (s, "%U", format_ip6_address, &ip46->ip6);
}

static void
server_handle_fifo_event_rx (echo_main_t * em, session_event_t * e)
{
  svm_fifo_t *rx_fifo, *tx_fifo;
  int n_read;
  session_t *session;
  int rv;
  u32 max_dequeue, offset, max_transfer, rx_buf_len;

  rx_buf_len = vec_len (em->rx_buf);
  rx_fifo = e->fifo;
  session = pool_elt_at_index (em->sessions, rx_fifo->client_session_index);
  tx_fifo = session->server_tx_fifo;

  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  /* Allow enqueuing of a new event */
  svm_fifo_unset_event (rx_fifo);

  if (PREDICT_FALSE (!max_dequeue))
    return;

  /* Read the max_dequeue */
  do
    {
      max_transfer = clib_min (rx_buf_len, max_dequeue);
      n_read = svm_fifo_dequeue_nowait (rx_fifo, max_transfer, em->rx_buf);
      if (n_read > 0)
	{
	  max_dequeue -= n_read;
	  session->bytes_received += n_read;
	  session->bytes_to_receive -= n_read;
	}

      /* Reflect if a non-drop session */
      if (!em->no_return && n_read > 0)
	{
	  offset = 0;
	  do
	    {
	      rv = svm_fifo_enqueue_nowait (tx_fifo, n_read,
					    &em->rx_buf[offset]);
	      if (rv > 0)
		{
		  n_read -= rv;
		  offset += rv;
		}
	    }
	  while ((rv <= 0 || n_read > 0) && !em->time_to_stop);

	  /* If event wasn't set, add one */
	  if (svm_fifo_set_event (tx_fifo))
	    app_send_io_evt_to_vpp (session->vpp_evt_q, tx_fifo,
				    FIFO_EVENT_APP_TX, SVM_Q_WAIT);
	}
    }
  while ((n_read < 0 || max_dequeue > 0) && !em->time_to_stop);
}

static void
server_handle_event_queue (echo_main_t * em)
{
  svm_msg_q_msg_t msg;
  session_event_t *e;

  while (1)
    {
      svm_msg_q_sub (em->our_event_queue, &msg, SVM_Q_WAIT, 0);
      e = svm_msg_q_msg_data (em->our_event_queue, &msg);
      switch (e->event_type)
	{
	case FIFO_EVENT_APP_RX:
	  server_handle_fifo_event_rx (em, e);
	  break;
	default:
	  handle_mq_event (e);
	  break;
	}
      if (PREDICT_FALSE (em->time_to_stop == 1))
	break;
      if (PREDICT_FALSE (em->time_to_print_stats == 1))
	{
	  em->time_to_print_stats = 0;
	  fformat (stdout, "%d connections\n", pool_elts (em->sessions));
	}
      svm_msg_q_free_msg (em->our_event_queue, &msg);
    }
}

void
server_send_listen (echo_main_t * em)
{
  vl_api_bind_uri_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  clib_memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_BIND_URI);
  bmp->client_index = em->my_client_index;
  bmp->context = ntohl (0xfeedface);
  memcpy (bmp->uri, em->uri, vec_len (em->uri));
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & bmp);
}

int
server_listen (echo_main_t * em)
{
  server_send_listen (em);
  if (wait_for_state_change (em, STATE_READY))
    {
      clib_warning ("timeout waiting for STATE_READY");
      return -1;
    }
  return 0;
}

void
server_send_unbind (echo_main_t * em)
{
  vl_api_unbind_uri_t *ump;

  ump = vl_msg_api_alloc (sizeof (*ump));
  clib_memset (ump, 0, sizeof (*ump));

  ump->_vl_msg_id = ntohs (VL_API_UNBIND_URI);
  ump->client_index = em->my_client_index;
  memcpy (ump->uri, em->uri, vec_len (em->uri));
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & ump);
}

int
server_unbind (echo_main_t * em)
{
  server_send_unbind (em);
  if (wait_for_state_change (em, STATE_START))
    {
      clib_warning ("timeout waiting for STATE_START");
      return -1;
    }
  return 0;
}

void
server_run (echo_main_t * em)
{
  session_t *session;
  int i;

  /* $$$$ hack preallocation */
  for (i = 0; i < 200000; i++)
    {
      pool_get (em->sessions, session);
      clib_memset (session, 0, sizeof (*session));
    }
  for (i = 0; i < 200000; i++)
    pool_put_index (em->sessions, i);

  if (application_attach (em))
    return;

  /* Bind to uri */
  if (server_listen (em))
    return;

  /* Enter handle event loop */
  server_handle_event_queue (em);

  /* Cleanup */
  server_send_unbind (em);

  application_detach (em);

  fformat (stdout, "Test complete...\n");
}

static void
vl_api_disconnect_session_reply_t_handler (vl_api_disconnect_session_reply_t *
					   mp)
{
  echo_main_t *em = &echo_main;
  uword *p;

  if (mp->retval)
    {
      clib_warning ("vpp complained about disconnect: %d",
		    ntohl (mp->retval));
      return;
    }

  em->state = STATE_START;

  p = hash_get (em->session_index_by_vpp_handles, mp->handle);
  if (p)
    {
      hash_unset (em->session_index_by_vpp_handles, mp->handle);
    }
  else
    {
      clib_warning ("couldn't find session key %llx", mp->handle);
    }
}

static void
  vl_api_application_tls_cert_add_reply_t_handler
  (vl_api_application_tls_cert_add_reply_t * mp)
{
  if (mp->retval)
    clib_warning ("failed to add tls cert");
}

static void
  vl_api_application_tls_key_add_reply_t_handler
  (vl_api_application_tls_key_add_reply_t * mp)
{
  if (mp->retval)
    clib_warning ("failed to add tls key");
}

#define foreach_tcp_echo_msg                            		\
_(BIND_URI_REPLY, bind_uri_reply)                       		\
_(UNBIND_URI_REPLY, unbind_uri_reply)                   		\
_(DISCONNECT_SESSION_REPLY, disconnect_session_reply)   		\
_(APPLICATION_ATTACH_REPLY, application_attach_reply)   		\
_(APPLICATION_DETACH_REPLY, application_detach_reply)			\
_(MAP_ANOTHER_SEGMENT, map_another_segment)				\
_(APPLICATION_TLS_CERT_ADD_REPLY, application_tls_cert_add_reply)	\
_(APPLICATION_TLS_KEY_ADD_REPLY, application_tls_key_add_reply)		\

void
tcp_echo_api_hookup (echo_main_t * em)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_tcp_echo_msg;
#undef _
}

int
main (int argc, char **argv)
{
  int i_am_server = 1, test_return_packets = 0;
  echo_main_t *em = &echo_main;
  svm_fifo_segment_main_t *sm = &em->segment_main;
  unformat_input_t _argv, *a = &_argv;
  u8 *chroot_prefix;
  u8 *uri = 0;
  u8 *bind_uri = (u8 *) "tcp://0.0.0.0/1234";
  u8 *connect_uri = (u8 *) "tcp://6.0.1.1/1234";
  u64 bytes_to_send = 64 << 10, mbytes;
  char *app_name;
  u32 tmp;

  clib_mem_init_thread_safe (0, 256 << 20);

  clib_memset (em, 0, sizeof (*em));
  em->session_index_by_vpp_handles = hash_create (0, sizeof (uword));
  em->my_pid = getpid ();
  em->configured_segment_size = 1 << 20;
  em->socket_name = 0;
  em->use_sock_api = 1;
  em->fifo_size = 64 << 10;
  em->n_clients = 1;

  clib_time_init (&em->clib_time);
  init_error_string_table (em);
  svm_fifo_segment_main_init (sm, HIGH_SEGMENT_BASEVA, 20);
  unformat_init_command_line (a, argv);

  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (a, "chroot prefix %s", &chroot_prefix))
	{
	  vl_set_memory_root_path ((char *) chroot_prefix);
	}
      else if (unformat (a, "uri %s", &uri))
	;
      else if (unformat (a, "segment-size %dM", &tmp))
	em->configured_segment_size = tmp << 20;
      else if (unformat (a, "segment-size %dG", &tmp))
	em->configured_segment_size = tmp << 30;
      else if (unformat (a, "server"))
	i_am_server = 1;
      else if (unformat (a, "client"))
	i_am_server = 0;
      else if (unformat (a, "no-return"))
	em->no_return = 1;
      else if (unformat (a, "test"))
	test_return_packets = 1;
      else if (unformat (a, "mbytes %lld", &mbytes))
	{
	  bytes_to_send = mbytes << 20;
	}
      else if (unformat (a, "gbytes %lld", &mbytes))
	{
	  bytes_to_send = mbytes << 30;
	}
      else if (unformat (a, "socket-name %s", &em->socket_name))
	;
      else if (unformat (a, "use-svm-api"))
	em->use_sock_api = 0;
      else if (unformat (a, "fifo-size %d", &tmp))
	em->fifo_size = tmp << 10;
      else if (unformat (a, "nclients %d", &em->n_clients))
	;
      else
	{
	  fformat (stderr, "%s: usage [master|slave]\n", argv[0]);
	  exit (1);
	}
    }

  if (!em->socket_name)
    em->socket_name = format (0, "%s%c", API_SOCKET_FILE, 0);

  if (uri)
    {
      em->uri = format (0, "%s%c", uri, 0);
      em->connect_uri = format (0, "%s%c", uri, 0);
    }
  else
    {
      em->uri = format (0, "%s%c", bind_uri, 0);
      em->connect_uri = format (0, "%s%c", connect_uri, 0);
    }

  em->i_am_master = i_am_server;
  em->test_return_packets = test_return_packets;
  em->bytes_to_send = bytes_to_send;
  em->time_to_stop = 0;
  vec_validate (em->rx_buf, 128 << 10);
  vec_validate (em->client_thread_handles, em->n_clients - 1);
  vec_validate (em->thread_args, em->n_clients - 1);

  setup_signal_handlers ();
  tcp_echo_api_hookup (em);

  app_name = i_am_server ? "tcp_echo_server" : "tcp_echo_client";
  if (connect_to_vpp (app_name) < 0)
    {
      svm_region_exit ();
      fformat (stderr, "Couldn't connect to vpe, exiting...\n");
      exit (1);
    }

  if (i_am_server == 0)
    clients_run (em);
  else
    server_run (em);

  /* Make sure detach finishes */
  wait_for_state_change (em, STATE_DETACHED);

  disconnect_from_vpp (em);
  exit (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
