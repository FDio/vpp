/*
 * Copyright (c) 2018-2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this
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

#include <vcl/vcl_private.h>
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

static u8 *
format_api_error (u8 * s, va_list * args)
{
  i32 error = va_arg (*args, u32);
  uword *p;

  p = hash_get (vcm->error_string_by_error_number, -error);

  if (p)
    s = format (s, "%s (%d)", p[0], error);
  else
    s = format (s, "%d", error);
  return s;
}

static void
  vl_api_session_enable_disable_reply_t_handler
  (vl_api_session_enable_disable_reply_t * mp)
{
  vcl_worker_t *wrk = vcl_worker_get (0);

  if (mp->retval)
    {
      clib_warning ("VCL<%d>: session_enable_disable failed: %U", getpid (),
		    format_api_error, ntohl (mp->retval));
    }
  else
    wrk->bapi_app_state = STATE_APP_ENABLED;
}

static void
vl_api_app_attach_reply_t_handler (vl_api_app_attach_reply_t * mp)
{
  vcl_worker_t *wrk = vcl_worker_get (0);
  u64 segment_handle;
  int *fds = 0, i, rv;
  u32 n_fds = 0;
  char *segment_name = 0;

  if (mp->retval)
    {
      VERR ("attach failed: %U", format_api_error, ntohl (mp->retval));
      goto failed;
    }

  vcl_set_worker_index (0);

  segment_handle = clib_net_to_host_u64 (mp->segment_handle);
  if (segment_handle == VCL_INVALID_SEGMENT_HANDLE)
    {
      VERR ("invalid segment handle");
      goto failed;
    }

  if (mp->n_fds)
    {
      vec_validate (fds, mp->n_fds);
      if (vl_socket_client_recv_fd_msg2 (&wrk->bapi_sock_ctx, fds, mp->n_fds,
					 5))
	goto failed;

      if (mp->fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
	if (vcl_segment_attach (vcl_vpp_worker_segment_handle (0),
				"vpp-mq-seg", SSVM_SEGMENT_MEMFD,
				fds[n_fds++]))
	  goto failed;

      vcl_segment_attach_mq (vcl_vpp_worker_segment_handle (0),
			     mp->vpp_ctrl_mq, mp->vpp_ctrl_mq_thread,
			     &wrk->ctrl_mq);
      vcm->ctrl_mq = wrk->ctrl_mq;

      if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
	{
	  segment_name = vl_api_from_api_to_new_c_string (&mp->segment_name);
	  rv =
	    vcl_segment_attach (segment_handle, segment_name,
				SSVM_SEGMENT_MEMFD, fds[n_fds++]);
	  vec_free (segment_name);
	  if (rv != 0)
	    goto failed;
	}

      vcl_segment_attach_mq (segment_handle, mp->app_mq, 0,
			     &wrk->app_event_queue);

      if (mp->fd_flags & SESSION_FD_F_MQ_EVENTFD)
	{
	  svm_msg_q_set_consumer_eventfd (wrk->app_event_queue, fds[n_fds]);
	  vcl_mq_epoll_add_evfd (wrk, wrk->app_event_queue);
	  n_fds++;
	}

      ASSERT (mp->fd_flags & SESSION_FD_F_VPP_MQ_EVENTFD);
      svm_msg_q_set_producer_eventfd (wrk->ctrl_mq, fds[n_fds++]);

      vec_free (fds);
    }
  else
    {
      segment_name = vl_api_from_api_to_new_c_string (&mp->segment_name);
      rv =
	vcl_segment_attach (segment_handle, segment_name, SSVM_SEGMENT_SHM,
			    -1);
      vec_free (segment_name);
      if (rv != 0)
	goto failed;
    }

  vcm->app_index = clib_net_to_host_u32 (mp->app_index);
  wrk->bapi_app_state = STATE_APP_ATTACHED;
  return;

failed:
  wrk->bapi_app_state = STATE_APP_FAILED;
  for (i = clib_max (n_fds - 1, 0); i < vec_len (fds); i++)
    close (fds[i]);
  vec_free (fds);
}

static void
vl_api_app_worker_add_del_reply_t_handler (vl_api_app_worker_add_del_reply_t *
					   mp)
{
  int n_fds = 0, *fds = 0, i, rv;
  u64 segment_handle;
  vcl_worker_t *wrk;
  u32 wrk_index;
  char *segment_name = 0;

  if (!mp->is_add)
    return;

  wrk_index = mp->context;
  wrk = vcl_worker_get_if_valid (wrk_index);
  if (!wrk)
    return;

  if (mp->retval)
    {
      clib_warning ("VCL<%d>: add/del worker failed: %U", getpid (),
		    format_api_error, ntohl (mp->retval));
      goto failed;
    }

  vcl_set_worker_index (wrk_index);
  wrk->vpp_wrk_index = clib_net_to_host_u32 (mp->wrk_index);
  wrk->ctrl_mq = vcm->ctrl_mq;

  segment_handle = clib_net_to_host_u64 (mp->segment_handle);
  if (segment_handle == VCL_INVALID_SEGMENT_HANDLE)
    {
      clib_warning ("invalid segment handle");
      goto failed;
    }

  if (mp->n_fds)
    {
      vec_validate (fds, mp->n_fds);
      if (vl_socket_client_recv_fd_msg2 (&wrk->bapi_sock_ctx, fds, mp->n_fds,
					 5))
	goto failed;

      if (mp->fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
	if (vcl_segment_attach (vcl_vpp_worker_segment_handle (wrk_index),
				"vpp-worker-seg", SSVM_SEGMENT_MEMFD,
				fds[n_fds++]))
	  goto failed;

      if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
	{
	  segment_name = vl_api_from_api_to_new_c_string (&mp->segment_name);
	  rv =
	    vcl_segment_attach (segment_handle, segment_name,
				SSVM_SEGMENT_MEMFD, fds[n_fds++]);
	  vec_free (segment_name);
	  if (rv != 0)
	    goto failed;
	}

      vcl_segment_attach_mq (segment_handle, mp->app_event_queue_address, 0,
			     &wrk->app_event_queue);

      if (mp->fd_flags & SESSION_FD_F_MQ_EVENTFD)
	{
	  svm_msg_q_set_consumer_eventfd (wrk->app_event_queue, fds[n_fds]);
	  vcl_mq_epoll_add_evfd (wrk, wrk->app_event_queue);
	  n_fds++;
	}

      vec_free (fds);
    }
  else
    {
      segment_name = vl_api_from_api_to_new_c_string (&mp->segment_name);
      rv =
	vcl_segment_attach (segment_handle, segment_name, SSVM_SEGMENT_SHM,
			    -1);
      vec_free (segment_name);
      if (rv != 0)
	goto failed;
    }
  wrk->bapi_app_state = STATE_APP_READY;
  VDBG (0, "worker %u vpp-worker %u added", wrk_index, wrk->vpp_wrk_index);
  return;

failed:
  wrk->bapi_app_state = STATE_APP_FAILED;
  for (i = clib_max (n_fds - 1, 0); i < vec_len (fds); i++)
    close (fds[i]);
  vec_free (fds);
}

static void
vl_api_app_add_cert_key_pair_reply_t_handler (
  vl_api_app_add_cert_key_pair_reply_t *mp)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();

  if (mp->retval)
    {
      VDBG (0, "Adding cert and key failed: %U", format_api_error,
	    ntohl (mp->retval));
      return;
    }
  wrk->bapi_return = clib_net_to_host_u32 (mp->index);
  wrk->bapi_app_state = STATE_APP_READY;
}

static void
vl_api_app_del_cert_key_pair_reply_t_handler (
  vl_api_app_del_cert_key_pair_reply_t *mp)
{
  if (mp->retval)
    {
      VDBG (0, "Deleting cert and key failed: %U", format_api_error,
	    ntohl (mp->retval));
      return;
    }
}

#define foreach_sock_msg                                                      \
  _ (SESSION_ENABLE_DISABLE_REPLY, session_enable_disable_reply)              \
  _ (APP_ATTACH_REPLY, app_attach_reply)                                      \
  _ (APP_ADD_CERT_KEY_PAIR_REPLY, app_add_cert_key_pair_reply)                \
  _ (APP_DEL_CERT_KEY_PAIR_REPLY, app_del_cert_key_pair_reply)                \
  _ (APP_WORKER_ADD_DEL_REPLY, app_worker_add_del_reply)

static void
vcl_bapi_hookup (void)
{
#define _(N, n)                                                	\
    vl_msg_api_set_handlers(VL_API_##N, #n,                    	\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_sock_msg;
#undef _
}

/*
 * VPP-API message functions
 */
static void
vcl_bapi_send_session_enable_disable (u8 is_enable)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vl_api_session_enable_disable_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_SESSION_ENABLE_DISABLE);
  bmp->client_index = wrk->api_client_handle;
  bmp->context = htonl (0xfeedface);
  bmp->is_enable = is_enable;
  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & bmp);
}

void
vcl_bapi_send_attach (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  u8 tls_engine = CRYPTO_ENGINE_OPENSSL;
  vl_api_app_attach_t *bmp;
  u8 nsid_len = vec_len (vcm->cfg.namespace_id);
  u8 app_is_proxy = (vcm->cfg.app_proxy_transport_tcp ||
		     vcm->cfg.app_proxy_transport_udp);

  tls_engine = vcm->cfg.tls_engine ? vcm->cfg.tls_engine : tls_engine;

  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APP_ATTACH);
  bmp->client_index = wrk->api_client_handle;
  bmp->context = htonl (0xfeedface);
  bmp->options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_ACCEPT_REDIRECT | APP_OPTIONS_FLAGS_ADD_SEGMENT |
    (vcm->cfg.app_scope_local ? APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE : 0) |
    (vcm->cfg.app_scope_global ? APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE : 0) |
    (app_is_proxy ? APP_OPTIONS_FLAGS_IS_PROXY : 0) |
    (vcm->cfg.use_mq_eventfd ? APP_OPTIONS_FLAGS_EVT_MQ_USE_EVENTFD : 0);
  bmp->options[APP_OPTIONS_PROXY_TRANSPORT] =
    (u64) ((vcm->cfg.app_proxy_transport_tcp ? 1 << TRANSPORT_PROTO_TCP : 0) |
	   (vcm->cfg.app_proxy_transport_udp ? 1 << TRANSPORT_PROTO_UDP : 0));
  bmp->options[APP_OPTIONS_SEGMENT_SIZE] = vcm->cfg.segment_size;
  bmp->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = vcm->cfg.add_segment_size;
  bmp->options[APP_OPTIONS_RX_FIFO_SIZE] = vcm->cfg.rx_fifo_size;
  bmp->options[APP_OPTIONS_TX_FIFO_SIZE] = vcm->cfg.tx_fifo_size;
  bmp->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] =
    vcm->cfg.preallocated_fifo_pairs;
  bmp->options[APP_OPTIONS_EVT_QUEUE_SIZE] = vcm->cfg.event_queue_size;
  bmp->options[APP_OPTIONS_TLS_ENGINE] = tls_engine;
  if (nsid_len)
    {
      vl_api_vec_to_api_string (vcm->cfg.namespace_id, &bmp->namespace_id);
      bmp->options[APP_OPTIONS_NAMESPACE_SECRET] = vcm->cfg.namespace_secret;
    }
  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & bmp);
}

void
vcl_bapi_send_detach (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vl_api_application_detach_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_DETACH);
  bmp->client_index = wrk->api_client_handle;
  bmp->context = htonl (0xfeedface);
  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & bmp);
}

static void
vcl_bapi_send_app_worker_add_del (u8 is_add)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vl_api_app_worker_add_del_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = ntohs (VL_API_APP_WORKER_ADD_DEL);
  mp->client_index = wrk->api_client_handle;
  mp->app_index = clib_host_to_net_u32 (vcm->app_index);
  mp->context = wrk->wrk_index;
  mp->is_add = is_add;
  if (!is_add)
    mp->wrk_index = clib_host_to_net_u32 (wrk->vpp_wrk_index);

  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & mp);
}

static void
vcl_bapi_send_child_worker_del (vcl_worker_t * child_wrk)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vl_api_app_worker_add_del_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = ntohs (VL_API_APP_WORKER_ADD_DEL);
  mp->client_index = wrk->api_client_handle;
  mp->app_index = clib_host_to_net_u32 (vcm->app_index);
  mp->context = wrk->wrk_index;
  mp->is_add = 0;
  mp->wrk_index = clib_host_to_net_u32 (child_wrk->vpp_wrk_index);

  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & mp);
}

static void
vcl_bapi_send_app_add_cert_key_pair (vppcom_cert_key_pair_t *ckpair)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  u32 cert_len = test_srv_crt_rsa_len;
  u32 key_len = test_srv_key_rsa_len;
  vl_api_app_add_cert_key_pair_t *bmp;

  bmp = vl_msg_api_alloc (sizeof (*bmp) + cert_len + key_len);
  clib_memset (bmp, 0, sizeof (*bmp) + cert_len + key_len);

  bmp->_vl_msg_id = ntohs (VL_API_APP_ADD_CERT_KEY_PAIR);
  bmp->client_index = wrk->api_client_handle;
  bmp->context = wrk->wrk_index;
  bmp->cert_len = clib_host_to_net_u16 (cert_len);
  bmp->certkey_len = clib_host_to_net_u16 (key_len + cert_len);
  clib_memcpy_fast (bmp->certkey, test_srv_crt_rsa, cert_len);
  clib_memcpy_fast (bmp->certkey + cert_len, test_srv_key_rsa, key_len);

  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) &bmp);
}

static void
vcl_bapi_send_app_del_cert_key_pair (u32 ckpair_index)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vl_api_app_del_cert_key_pair_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  clib_memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APP_DEL_CERT_KEY_PAIR);
  bmp->client_index = wrk->api_client_handle;
  bmp->context = wrk->wrk_index;
  bmp->index = clib_host_to_net_u32 (ckpair_index);
  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) &bmp);
}

u32
vcl_bapi_max_nsid_len (void)
{
  vl_api_app_attach_t *mp;
  return (sizeof (mp->namespace_id) - 1);
}

static void
vcl_bapi_init_error_string_table (void)
{
  vcm->error_string_by_error_number = hash_create (0, sizeof (uword));

#define _(n, v, s) hash_set (vcm->error_string_by_error_number, -v, s);
  foreach_vnet_api_error;
#undef _

  hash_set (vcm->error_string_by_error_number, 99, "Misc");
}

static void
vcl_bapi_cleanup (void)
{
  socket_client_main_t *scm = &socket_client_main;
  api_main_t *am = vlibapi_get_main ();

  am->my_client_index = ~0;
  am->my_registration = 0;
  am->vl_input_queue = 0;
  am->msg_index_by_name_and_crc = 0;
  scm->socket_fd = 0;

  vl_client_api_unmap ();
}

static int
vcl_bapi_connect_to_vpp (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vppcom_cfg_t *vcl_cfg = &vcm->cfg;
  int rv = VPPCOM_OK;
  api_main_t *am;
  u8 *wrk_name;

  wrk_name = format (0, "%v-wrk-%u%c", vcm->app_name, wrk->wrk_index, 0);

  /* Make sure api is cleaned up in case this is a connect from a
   * forked worker */
  vcl_bapi_cleanup ();

  vlibapi_set_main (&wrk->bapi_api_ctx);
  vcl_bapi_hookup ();

  if (!vcl_cfg->vpp_bapi_socket_name)
    {
      rv = VPPCOM_EINVAL;
      goto error;
    }

  if (vl_socket_client_connect2 (&wrk->bapi_sock_ctx,
				 (char *) vcl_cfg->vpp_bapi_socket_name,
				 (char *) wrk_name,
				 0 /* default rx/tx buffer */ ))
    {
      VERR ("app (%s) socket connect failed!", wrk_name);
      rv = VPPCOM_ECONNREFUSED;
      goto error;
    }

  if (vl_socket_client_init_shm2 (&wrk->bapi_sock_ctx, 0,
				  1 /* want_pthread */ ))
    {
      VERR ("app (%s) init shm failed!", wrk_name);
      rv = VPPCOM_ECONNREFUSED;
      goto error;
    }

  am = vlibapi_get_main ();
  wrk->vl_input_queue = am->shmem_hdr->vl_input_queue;
  wrk->api_client_handle = (u32) am->my_client_index;

  VDBG (0, "app (%s) is connected to VPP!", wrk_name);
  vcl_evt (VCL_EVT_INIT, vcm);

error:
  vec_free (wrk_name);
  return rv;
}

void
vcl_bapi_disconnect_from_vpp (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vppcom_cfg_t *vcl_cfg = &vcm->cfg;

  if (vcl_cfg->vpp_bapi_socket_name)
    vl_socket_client_disconnect2 (&wrk->bapi_sock_ctx);
  else
    vl_client_disconnect_from_vlib ();
}

static const char *
vcl_bapi_app_state_str (vcl_bapi_app_state_t state)
{
  char *st;

  switch (state)
    {
    case STATE_APP_START:
      st = "STATE_APP_START";
      break;

    case STATE_APP_CONN_VPP:
      st = "STATE_APP_CONN_VPP";
      break;

    case STATE_APP_ENABLED:
      st = "STATE_APP_ENABLED";
      break;

    case STATE_APP_ATTACHED:
      st = "STATE_APP_ATTACHED";
      break;

    default:
      st = "UNKNOWN_APP_STATE";
      break;
    }

  return st;
}

static int
vcl_bapi_wait_for_wrk_state_change (vcl_bapi_app_state_t app_state)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  f64 timeout = clib_time_now (&wrk->clib_time) + vcm->cfg.app_timeout;

  while (clib_time_now (&wrk->clib_time) < timeout)
    {
      if (wrk->bapi_app_state == app_state)
	return VPPCOM_OK;
      if (wrk->bapi_app_state == STATE_APP_FAILED)
	return VPPCOM_ECONNABORTED;
    }
  VDBG (0, "timeout waiting for state %s (%d)",
	vcl_bapi_app_state_str (app_state), app_state);
  vcl_evt (VCL_EVT_SESSION_TIMEOUT, vcm, bapi_app_state);

  return VPPCOM_ETIMEDOUT;
}

static int
vcl_bapi_session_enable (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  int rv;

  if (wrk->bapi_app_state != STATE_APP_ENABLED)
    {
      vcl_bapi_send_session_enable_disable (1 /* is_enabled == TRUE */ );
      rv = vcl_bapi_wait_for_wrk_state_change (STATE_APP_ENABLED);
      if (PREDICT_FALSE (rv))
	{
	  VDBG (0, "application session enable timed out! returning %d (%s)",
		rv, vppcom_retval_str (rv));
	  return rv;
	}
    }
  return VPPCOM_OK;
}

static int
vcl_bapi_init (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  int rv;

  wrk->bapi_app_state = STATE_APP_START;
  vcl_bapi_init_error_string_table ();
  rv = vcl_bapi_connect_to_vpp ();
  if (rv)
    {
      VERR ("couldn't connect to VPP!");
      return rv;
    }
  VDBG (0, "sending session enable");
  rv = vcl_bapi_session_enable ();
  if (rv)
    {
      VERR ("vppcom_app_session_enable() failed!");
      return rv;
    }

  return 0;
}

int
vcl_bapi_attach (void)
{
  int rv;

  /* API hookup and connect to VPP */
  if ((rv = vcl_bapi_init ()))
    return rv;

  vcl_bapi_send_attach ();
  rv = vcl_bapi_wait_for_wrk_state_change (STATE_APP_ATTACHED);
  if (PREDICT_FALSE (rv))
    {
      VDBG (0, "application attach timed out! returning %d (%s)", rv,
	    vppcom_retval_str (rv));
      return rv;
    }

  return 0;
}

int
vcl_bapi_app_worker_add (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();

  if (vcl_bapi_connect_to_vpp ())
    return -1;

  wrk->bapi_app_state = STATE_APP_ADDING_WORKER;
  vcl_bapi_send_app_worker_add_del (1 /* is_add */ );
  if (vcl_bapi_wait_for_wrk_state_change (STATE_APP_READY))
    return -1;
  return 0;
}

void
vcl_bapi_app_worker_del (vcl_worker_t * wrk)
{
  /* Notify vpp that the worker is going away */
  if (wrk->wrk_index == vcl_get_worker_index ())
    vcl_bapi_send_app_worker_add_del (0 /* is_add */ );
  else
    vcl_bapi_send_child_worker_del (wrk);

  /* Disconnect the binary api */
  if (vec_len (vcm->workers) == 1)
    vcl_bapi_disconnect_from_vpp ();
  else
    vl_client_send_disconnect (1 /* vpp should cleanup */ );
}

int
vcl_bapi_recv_fds (vcl_worker_t * wrk, int *fds, int n_fds)
{
  clib_error_t *err;

  if ((err = vl_socket_client_recv_fd_msg2 (&wrk->bapi_sock_ctx, fds, n_fds,
					    5)))
    {
      clib_error_report (err);
      return -1;
    }

  return 0;
}

int
vcl_bapi_add_cert_key_pair (vppcom_cert_key_pair_t *ckpair)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();

  if (ckpair->key_len == 0 || ckpair->key_len == ~0)
    return VPPCOM_EINVAL;

  vcl_bapi_send_app_add_cert_key_pair (ckpair);
  wrk->bapi_app_state = STATE_APP_ADDING_TLS_DATA;
  vcl_bapi_wait_for_wrk_state_change (STATE_APP_READY);
  if (wrk->bapi_app_state == STATE_APP_READY)
    return wrk->bapi_return;
  return VPPCOM_EFAULT;
}

int
vcl_bapi_del_cert_key_pair (u32 ckpair_index)
{
  /* Don't wait for reply */
  vcl_bapi_send_app_del_cert_key_pair (ckpair_index);
  return 0;
}

int
vcl_bapi_worker_set (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  int i;

  /* Find the first worker with the same pid */
  for (i = 0; i < vec_len (vcm->workers); i++)
    {
      if (i == wrk->wrk_index)
	continue;
      if (vcm->workers[i].current_pid == wrk->current_pid)
	{
	  wrk->vl_input_queue = vcm->workers[i].vl_input_queue;
	  wrk->api_client_handle = vcm->workers[i].api_client_handle;
	  return 0;
	}
    }
  return -1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
