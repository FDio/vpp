/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

static int
vcl_api_connect_app_socket (vcl_worker_t * wrk)
{
  clib_socket_t *cs = &wrk->app_api_sock;
  clib_error_t *err;
  int rv = 0;

  cs->config = (char *) vcm->cfg.vpp_app_socket_api;
  cs->flags = CLIB_SOCKET_F_IS_CLIENT | CLIB_SOCKET_F_SEQPACKET;

  wrk->vcl_needs_real_epoll = 1;

  if ((err = clib_socket_init (cs)))
    {
      clib_error_report (err);
      rv = -1;
      goto done;
    }

done:

  wrk->vcl_needs_real_epoll = 0;

  return rv;
}

static int
vcl_api_attach_reply_handler (app_sapi_attach_reply_msg_t * mp, int *fds)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  int i, rv, n_fds_used = 0;
  u64 segment_handle;
  u8 *segment_name;

  if (mp->retval)
    {
      VERR ("attach failed: %U", format_session_error, mp->retval);
      goto failed;
    }

  wrk->api_client_handle = mp->api_client_handle;
  segment_handle = mp->segment_handle;
  if (segment_handle == VCL_INVALID_SEGMENT_HANDLE)
    {
      VERR ("invalid segment handle");
      goto failed;
    }

  if (!mp->n_fds)
    goto failed;

  if (mp->fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
    if (vcl_segment_attach (vcl_vpp_worker_segment_handle (0), "vpp-mq-seg",
			    SSVM_SEGMENT_MEMFD, fds[n_fds_used++]))
      goto failed;

  if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
    {
      segment_name = format (0, "memfd-%ld%c", segment_handle, 0);
      rv = vcl_segment_attach (segment_handle, (char *) segment_name,
			       SSVM_SEGMENT_MEMFD, fds[n_fds_used++]);
      vec_free (segment_name);
      if (rv != 0)
	goto failed;
    }

  vcl_segment_attach_mq (segment_handle, mp->app_mq, 0, &wrk->app_event_queue);

  if (mp->fd_flags & SESSION_FD_F_MQ_EVENTFD)
    {
      svm_msg_q_set_eventfd (wrk->app_event_queue, fds[n_fds_used++]);
      vcl_mq_epoll_add_evfd (wrk, wrk->app_event_queue);
    }

  vcl_segment_discover_mqs (vcl_vpp_worker_segment_handle (0),
			    fds + n_fds_used, mp->n_fds - n_fds_used);
  vcl_segment_attach_mq (vcl_vpp_worker_segment_handle (0), mp->vpp_ctrl_mq,
			 mp->vpp_ctrl_mq_thread, &wrk->ctrl_mq);
  vcm->ctrl_mq = wrk->ctrl_mq;
  vcm->app_index = mp->app_index;

  return 0;

failed:

  for (i = clib_max (n_fds_used - 1, 0); i < mp->n_fds; i++)
    close (fds[i]);

  return -1;
}

static int
vcl_api_send_attach (clib_socket_t * cs)
{
  app_sapi_msg_t msg = { 0 };
  app_sapi_attach_msg_t *mp = &msg.attach;
  u8 app_is_proxy, tls_engine;
  clib_error_t *err;

  app_is_proxy = (vcm->cfg.app_proxy_transport_tcp ||
		  vcm->cfg.app_proxy_transport_udp);
  tls_engine = CRYPTO_ENGINE_OPENSSL;

  clib_memcpy (&mp->name, vcm->app_name, vec_len (vcm->app_name));
  mp->options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_ACCEPT_REDIRECT | APP_OPTIONS_FLAGS_ADD_SEGMENT |
    (vcm->cfg.app_scope_local ? APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE : 0) |
    (vcm->cfg.app_scope_global ? APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE : 0) |
    (app_is_proxy ? APP_OPTIONS_FLAGS_IS_PROXY : 0) |
    (vcm->cfg.use_mq_eventfd ? APP_OPTIONS_FLAGS_EVT_MQ_USE_EVENTFD : 0);
  mp->options[APP_OPTIONS_PROXY_TRANSPORT] =
    (u64) ((vcm->cfg.app_proxy_transport_tcp ? 1 << TRANSPORT_PROTO_TCP : 0) |
	   (vcm->cfg.app_proxy_transport_udp ? 1 << TRANSPORT_PROTO_UDP : 0));
  mp->options[APP_OPTIONS_SEGMENT_SIZE] = vcm->cfg.segment_size;
  mp->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = vcm->cfg.add_segment_size;
  mp->options[APP_OPTIONS_RX_FIFO_SIZE] = vcm->cfg.rx_fifo_size;
  mp->options[APP_OPTIONS_TX_FIFO_SIZE] = vcm->cfg.tx_fifo_size;
  mp->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] =
    vcm->cfg.preallocated_fifo_pairs;
  mp->options[APP_OPTIONS_EVT_QUEUE_SIZE] = vcm->cfg.event_queue_size;
  mp->options[APP_OPTIONS_TLS_ENGINE] = tls_engine;

  msg.type = APP_SAPI_MSG_TYPE_ATTACH;
  err = clib_socket_sendmsg (cs, &msg, sizeof (msg), 0, 0);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }

  return 0;
}

int
vcl_sapi_attach (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  app_sapi_msg_t _rmp, *rmp = &_rmp;
  clib_error_t *err;
  clib_socket_t *cs;
  int fds[32];

  /*
   * Init client socket and send attach
   */
  if (vcl_api_connect_app_socket (wrk))
    return -1;

  cs = &wrk->app_api_sock;
  if (vcl_api_send_attach (cs))
    return -1;

  /*
   * Wait for attach reply
   */
  err = clib_socket_recvmsg (cs, rmp, sizeof (*rmp), fds, ARRAY_LEN (fds));
  if (err)
    {
      clib_error_report (err);
      return -1;
    }

  if (rmp->type != APP_SAPI_MSG_TYPE_ATTACH_REPLY)
    return -1;

  return vcl_api_attach_reply_handler (&rmp->attach_reply, fds);
}

static int
vcl_api_add_del_worker_reply_handler (app_sapi_worker_add_del_reply_msg_t *
				      mp, int *fds)
{
  int n_fds = 0, i, rv;
  u64 segment_handle;
  vcl_worker_t *wrk;

  if (mp->retval)
    {
      VDBG (0, "add/del worker failed: %U", format_session_error, mp->retval);
      goto failed;
    }

  if (!mp->is_add)
    goto failed;

  wrk = vcl_worker_get_current ();
  wrk->api_client_handle = mp->api_client_handle;
  wrk->vpp_wrk_index = mp->wrk_index;
  wrk->ctrl_mq = vcm->ctrl_mq;

  segment_handle = mp->segment_handle;
  if (segment_handle == VCL_INVALID_SEGMENT_HANDLE)
    {
      clib_warning ("invalid segment handle");
      goto failed;
    }

  if (!mp->n_fds)
    goto failed;

  if (mp->fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
    if (vcl_segment_attach (vcl_vpp_worker_segment_handle (wrk->wrk_index),
			    "vpp-worker-seg", SSVM_SEGMENT_MEMFD,
			    fds[n_fds++]))
      goto failed;

  if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
    {
      u8 *segment_name = format (0, "memfd-%ld%c", segment_handle, 0);
      rv = vcl_segment_attach (segment_handle, (char *) segment_name,
			       SSVM_SEGMENT_MEMFD, fds[n_fds++]);
      vec_free (segment_name);
      if (rv != 0)
	goto failed;
    }

  vcl_segment_attach_mq (segment_handle, mp->app_event_queue_address, 0,
			 &wrk->app_event_queue);

  if (mp->fd_flags & SESSION_FD_F_MQ_EVENTFD)
    {
      svm_msg_q_set_eventfd (wrk->app_event_queue, fds[n_fds]);
      vcl_mq_epoll_add_evfd (wrk, wrk->app_event_queue);
      n_fds++;
    }

  VDBG (0, "worker %u vpp-worker %u added", wrk->wrk_index,
	wrk->vpp_wrk_index);

  return 0;

failed:
  for (i = clib_max (n_fds - 1, 0); i < mp->n_fds; i++)
    close (fds[i]);

  return -1;
}

int
vcl_sapi_app_worker_add (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  app_sapi_worker_add_del_msg_t *mp;
  app_sapi_msg_t _rmp, *rmp = &_rmp;
  app_sapi_msg_t msg = { 0 };
  int fds[SESSION_N_FD_TYPE];
  clib_error_t *err;
  clib_socket_t *cs;

  /* Connect to socket api */
  if (vcl_api_connect_app_socket (wrk))
    return -1;

  /*
   * Send add worker
   */
  cs = &wrk->app_api_sock;

  msg.type = APP_SAPI_MSG_TYPE_ADD_DEL_WORKER;
  mp = &msg.worker_add_del;
  mp->app_index = vcm->app_index;
  mp->is_add = 1;

  err = clib_socket_sendmsg (cs, &msg, sizeof (msg), 0, 0);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }

  /*
   * Wait for reply and process it
   */
  err = clib_socket_recvmsg (cs, rmp, sizeof (*rmp), fds, ARRAY_LEN (fds));
  if (err)
    {
      clib_error_report (err);
      return -1;
    }

  if (rmp->type != APP_SAPI_MSG_TYPE_ADD_DEL_WORKER_REPLY)
    {
      clib_warning ("unexpected reply type %u", rmp->type);
      return -1;
    }

  return vcl_api_add_del_worker_reply_handler (&rmp->worker_add_del_reply,
					       fds);
}

void
vcl_sapi_app_worker_del (vcl_worker_t * wrk)
{
  app_sapi_worker_add_del_msg_t *mp;
  app_sapi_msg_t msg = { 0 };
  clib_error_t *err;
  clib_socket_t *cs;

  cs = &wrk->app_api_sock;

  msg.type = APP_SAPI_MSG_TYPE_ADD_DEL_WORKER;
  mp = &msg.worker_add_del;
  mp->app_index = vcm->app_index;
  mp->wrk_index = wrk->vpp_wrk_index;
  mp->is_add = 0;

  err = clib_socket_sendmsg (cs, &msg, sizeof (msg), 0, 0);
  if (err)
    clib_error_report (err);
  clib_socket_close (cs);
}

void
vcl_sapi_detach (vcl_worker_t * wrk)
{
  clib_socket_t *cs = &wrk->app_api_sock;
  clib_socket_close (cs);
}

int
vcl_sapi_recv_fds (vcl_worker_t * wrk, int *fds, int n_fds)
{
  app_sapi_msg_t _msg, *msg = &_msg;
  clib_socket_t *cs;
  clib_error_t *err;

  cs = &wrk->app_api_sock;

  err = clib_socket_recvmsg (cs, msg, sizeof (*msg), fds, n_fds);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }
  if (msg->type != APP_SAPI_MSG_TYPE_SEND_FDS)
    return -1;

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
