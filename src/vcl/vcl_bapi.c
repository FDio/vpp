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

u8 *
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
  if (mp->retval)
    {
      clib_warning ("VCL<%d>: session_enable_disable failed: %U", getpid (),
		    format_api_error, ntohl (mp->retval));
    }
  else
    vcm->app_state = STATE_APP_ENABLED;
}

static u64
vcl_vpp_worker_segment_handle (u32 wrk_index)
{
  return (VCL_INVALID_SEGMENT_HANDLE - wrk_index - 1);
}

static void
vl_api_app_attach_reply_t_handler (vl_api_app_attach_reply_t * mp)
{
  vcl_worker_t *wrk = vcl_worker_get (0);
  svm_msg_q_t *ctrl_mq;
  u64 segment_handle;
  int *fds = 0, i;
  u32 n_fds = 0;

  if (mp->retval)
    {
      VERR ("attach failed: %U", format_api_error, ntohl (mp->retval));
      goto failed;
    }

  wrk->app_event_queue = uword_to_pointer (mp->app_mq, svm_msg_q_t *);
  ctrl_mq = uword_to_pointer (mp->vpp_ctrl_mq, svm_msg_q_t *);
  vec_validate (wrk->vpp_event_queues, mp->vpp_ctrl_mq_thread);
  wrk->vpp_event_queues[mp->vpp_ctrl_mq_thread] = ctrl_mq;
  vcm->ctrl_mq = wrk->ctrl_mq = ctrl_mq;
  segment_handle = clib_net_to_host_u64 (mp->segment_handle);
  if (segment_handle == VCL_INVALID_SEGMENT_HANDLE)
    {
      VERR ("invalid segment handle");
      goto failed;
    }

  if (mp->n_fds)
    {
      vec_validate (fds, mp->n_fds);
      if (vl_socket_client_recv_fd_msg (fds, mp->n_fds, 5))
	goto failed;

      if (mp->fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
	if (vcl_segment_attach (vcl_vpp_worker_segment_handle (0),
				"vpp-mq-seg", SSVM_SEGMENT_MEMFD,
				fds[n_fds++]))
	  goto failed;

      if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
	if (vcl_segment_attach (segment_handle, (char *) mp->segment_name,
				SSVM_SEGMENT_MEMFD, fds[n_fds++]))
	  goto failed;

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
      if (vcl_segment_attach (segment_handle, (char *) mp->segment_name,
			      SSVM_SEGMENT_SHM, -1))
	goto failed;
    }

  vcm->app_index = clib_net_to_host_u32 (mp->app_index);
  vcm->app_state = STATE_APP_ATTACHED;
  return;

failed:
  vcm->app_state = STATE_APP_FAILED;
  for (i = clib_max (n_fds - 1, 0); i < vec_len (fds); i++)
    close (fds[i]);
  vec_free (fds);
}

static void
vl_api_app_worker_add_del_reply_t_handler (vl_api_app_worker_add_del_reply_t *
					   mp)
{
  int n_fds = 0, *fds = 0, i;
  u64 segment_handle;
  vcl_worker_t *wrk;
  u32 wrk_index;

  if (mp->retval)
    {
      clib_warning ("VCL<%d>: add/del worker failed: %U", getpid (),
		    format_api_error, ntohl (mp->retval));
      goto failed;
    }

  if (!mp->is_add)
    return;

  wrk_index = mp->context;
  wrk = vcl_worker_get_if_valid (wrk_index);
  if (!wrk)
    return;

  wrk->vpp_wrk_index = clib_net_to_host_u32 (mp->wrk_index);
  wrk->app_event_queue = uword_to_pointer (mp->app_event_queue_address,
					   svm_msg_q_t *);
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
      if (vl_socket_client_recv_fd_msg (fds, mp->n_fds, 5))
	goto failed;

      if (mp->fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
	if (vcl_segment_attach (vcl_vpp_worker_segment_handle (wrk_index),
				"vpp-worker-seg", SSVM_SEGMENT_MEMFD,
				fds[n_fds++]))
	  goto failed;

      if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
	if (vcl_segment_attach (segment_handle, (char *) mp->segment_name,
				SSVM_SEGMENT_MEMFD, fds[n_fds++]))
	  goto failed;

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
      if (vcl_segment_attach (segment_handle, (char *) mp->segment_name,
			      SSVM_SEGMENT_SHM, -1))
	goto failed;
    }
  vcm->app_state = STATE_APP_READY;
  VDBG (0, "worker %u vpp-worker %u added", wrk_index, wrk->vpp_wrk_index);
  return;

failed:
  vcm->app_state = STATE_APP_FAILED;
  for (i = clib_max (n_fds - 1, 0); i < vec_len (fds); i++)
    close (fds[i]);
  vec_free (fds);
}

static void
  vl_api_application_tls_cert_add_reply_t_handler
  (vl_api_application_tls_cert_add_reply_t * mp)
{
  if (mp->retval)
    VDBG (0, "add cert failed: %U", format_api_error, ntohl (mp->retval));
  vcm->app_state = STATE_APP_READY;
}

static void
  vl_api_application_tls_key_add_reply_t_handler
  (vl_api_application_tls_key_add_reply_t * mp)
{
  if (mp->retval)
    VDBG (0, "add key failed: %U", format_api_error, ntohl (mp->retval));
  vcm->app_state = STATE_APP_READY;
}

#define foreach_sock_msg                                        	\
_(SESSION_ENABLE_DISABLE_REPLY, session_enable_disable_reply)   	\
_(APP_ATTACH_REPLY, app_attach_reply)           			\
_(APPLICATION_TLS_CERT_ADD_REPLY, application_tls_cert_add_reply)  	\
_(APPLICATION_TLS_KEY_ADD_REPLY, application_tls_key_add_reply)  	\
_(APP_WORKER_ADD_DEL_REPLY, app_worker_add_del_reply)			\

void
vppcom_api_hookup (void)
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
void
vppcom_send_session_enable_disable (u8 is_enable)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vl_api_session_enable_disable_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_SESSION_ENABLE_DISABLE);
  bmp->client_index = wrk->my_client_index;
  bmp->context = htonl (0xfeedface);
  bmp->is_enable = is_enable;
  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & bmp);
}

void
vppcom_app_send_attach (void)
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
  bmp->client_index = wrk->my_client_index;
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
      bmp->namespace_id_len = nsid_len;
      clib_memcpy_fast (bmp->namespace_id, vcm->cfg.namespace_id, nsid_len);
      bmp->options[APP_OPTIONS_NAMESPACE_SECRET] = vcm->cfg.namespace_secret;
    }
  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & bmp);
}

void
vppcom_app_send_detach (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vl_api_application_detach_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_DETACH);
  bmp->client_index = wrk->my_client_index;
  bmp->context = htonl (0xfeedface);
  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & bmp);
}

void
vcl_send_app_worker_add_del (u8 is_add)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vl_api_app_worker_add_del_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = ntohs (VL_API_APP_WORKER_ADD_DEL);
  mp->client_index = wrk->my_client_index;
  mp->app_index = clib_host_to_net_u32 (vcm->app_index);
  mp->context = wrk->wrk_index;
  mp->is_add = is_add;
  if (!is_add)
    mp->wrk_index = clib_host_to_net_u32 (wrk->vpp_wrk_index);

  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & mp);
}

void
vcl_send_child_worker_del (vcl_worker_t * child_wrk)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vl_api_app_worker_add_del_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = ntohs (VL_API_APP_WORKER_ADD_DEL);
  mp->client_index = wrk->my_client_index;
  mp->app_index = clib_host_to_net_u32 (vcm->app_index);
  mp->context = wrk->wrk_index;
  mp->is_add = 0;
  mp->wrk_index = clib_host_to_net_u32 (child_wrk->vpp_wrk_index);

  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & mp);
}

void
vppcom_send_application_tls_cert_add (vcl_session_t * session, char *cert,
				      u32 cert_len)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vl_api_application_tls_cert_add_t *cert_mp;

  cert_mp = vl_msg_api_alloc (sizeof (*cert_mp) + cert_len);
  clib_memset (cert_mp, 0, sizeof (*cert_mp));
  cert_mp->_vl_msg_id = ntohs (VL_API_APPLICATION_TLS_CERT_ADD);
  cert_mp->client_index = wrk->my_client_index;
  cert_mp->context = session->session_index;
  cert_mp->cert_len = clib_host_to_net_u16 (cert_len);
  clib_memcpy_fast (cert_mp->cert, cert, cert_len);
  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & cert_mp);
}

void
vppcom_send_application_tls_key_add (vcl_session_t * session, char *key,
				     u32 key_len)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vl_api_application_tls_key_add_t *key_mp;

  key_mp = vl_msg_api_alloc (sizeof (*key_mp) + key_len);
  clib_memset (key_mp, 0, sizeof (*key_mp));
  key_mp->_vl_msg_id = ntohs (VL_API_APPLICATION_TLS_KEY_ADD);
  key_mp->client_index = wrk->my_client_index;
  key_mp->context = session->session_index;
  key_mp->key_len = clib_host_to_net_u16 (key_len);
  clib_memcpy_fast (key_mp->key, key, key_len);
  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & key_mp);
}

u32
vcl_max_nsid_len (void)
{
  vl_api_application_attach_t *mp;
  return (sizeof (mp->namespace_id) - 1);
}

void
vppcom_init_error_string_table (void)
{
  vcm->error_string_by_error_number = hash_create (0, sizeof (uword));

#define _(n, v, s) hash_set (vcm->error_string_by_error_number, -v, s);
  foreach_vnet_api_error;
#undef _

  hash_set (vcm->error_string_by_error_number, 99, "Misc");
}

int
vppcom_connect_to_vpp (char *app_name)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  api_main_t *am = &api_main;
  vppcom_cfg_t *vcl_cfg = &vcm->cfg;

  if (vcl_cfg->vpp_api_socket_name)
    {
      if (vl_socket_client_connect ((char *) vcl_cfg->vpp_api_socket_name,
				    app_name, 0 /* default rx/tx buffer */ ))
	{
	  VERR ("app (%s) socket connect failed!", app_name);
	  return VPPCOM_ECONNREFUSED;
	}

      if (vl_socket_client_init_shm (0, 1 /* want_pthread */ ))
	{
	  VERR ("app (%s) init shm failed!", app_name);
	  return VPPCOM_ECONNREFUSED;
	}
    }
  else
    {
      if (!vcl_cfg->vpp_api_filename)
	vcl_cfg->vpp_api_filename = format (0, "/vpe-api%c", 0);

      VDBG (0, "app (%s) connecting to VPP api (%s)...",
	    app_name, vcl_cfg->vpp_api_filename);

      if (vl_client_connect_to_vlib ((char *) vcl_cfg->vpp_api_filename,
				     app_name, vcm->cfg.vpp_api_q_length) < 0)
	{
	  VERR ("app (%s) connect failed!", app_name);
	  return VPPCOM_ECONNREFUSED;
	}

    }

  wrk->vl_input_queue = am->shmem_hdr->vl_input_queue;
  wrk->my_client_index = (u32) am->my_client_index;
  wrk->wrk_state = STATE_APP_CONN_VPP;

  VDBG (0, "app (%s) is connected to VPP!", app_name);
  vcl_evt (VCL_EVT_INIT, vcm);
  return VPPCOM_OK;
}

void
vppcom_disconnect_from_vpp (void)
{
  vppcom_cfg_t *vcl_cfg = &vcm->cfg;

  if (vcl_cfg->vpp_api_socket_name)
    vl_socket_client_disconnect ();
  else
    vl_client_disconnect_from_vlib ();
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
