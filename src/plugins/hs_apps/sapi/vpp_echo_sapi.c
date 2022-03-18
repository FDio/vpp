/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#include <hs_apps/sapi/vpp_echo_common.h>

int
echo_api_connect_app_socket (echo_main_t *em)
{
  clib_socket_t *cs = &em->app_api_sock;
  clib_error_t *err;
  int rv = 0;

  cs->config = (char *) em->socket_name;
  cs->flags =
    CLIB_SOCKET_F_IS_CLIENT | CLIB_SOCKET_F_SEQPACKET | CLIB_SOCKET_F_BLOCKING;

  if ((err = clib_socket_init (cs)))
    {
      clib_error_report (err);
      rv = -1;
    }

  return rv;
}

static inline u64
echo_vpp_worker_segment_handle (u32 wrk_index)
{
  return (ECHO_INVALID_SEGMENT_HANDLE - wrk_index - 1);
}

static int
echo_segment_discover_mqs (uword segment_handle, int *fds, u32 n_fds)
{
  echo_main_t *em = &echo_main;
  fifo_segment_t *fs;
  u32 fs_index;

  fs_index = echo_segment_lookup (segment_handle);
  if (fs_index == ECHO_INVALID_SEGMENT_INDEX)
    {
      ECHO_LOG (0, "ERROR: mq segment %lx for is not attached!",
		segment_handle);
      return -1;
    }

  clib_spinlock_lock (&em->segment_handles_lock);

  fs = fifo_segment_get_segment (&em->segment_main, fs_index);
  fifo_segment_msg_qs_discover (fs, fds, n_fds);

  clib_spinlock_unlock (&em->segment_handles_lock);

  return 0;
}

static int
echo_api_attach_reply_handler (app_sapi_attach_reply_msg_t *mp, int *fds)
{
  echo_main_t *em = &echo_main;
  int i, rv, n_fds_used = 0;
  u64 segment_handle;
  u8 *segment_name;

  if (mp->retval)
    {
      ECHO_LOG (0, "attach failed: %U", format_session_error, mp->retval);
      goto failed;
    }

  em->my_client_index = mp->api_client_handle;
  segment_handle = mp->segment_handle;
  if (segment_handle == ECHO_INVALID_SEGMENT_HANDLE)
    {
      ECHO_LOG (0, "invalid segment handle");
      goto failed;
    }

  if (!mp->n_fds)
    goto failed;

  if (mp->fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
    if (echo_segment_attach (echo_vpp_worker_segment_handle (0), "vpp-mq-seg",
			     SSVM_SEGMENT_MEMFD, fds[n_fds_used++]))
      goto failed;

  if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
    {
      segment_name = format (0, "memfd-%ld%c", segment_handle, 0);
      rv = echo_segment_attach (segment_handle, (char *) segment_name,
				SSVM_SEGMENT_MEMFD, fds[n_fds_used++]);
      vec_free (segment_name);
      if (rv != 0)
	goto failed;
    }

  echo_segment_attach_mq (segment_handle, mp->app_mq, 0, &em->app_mq);

  if (mp->fd_flags & SESSION_FD_F_MQ_EVENTFD)
    {
      ECHO_LOG (0, "SESSION_FD_F_MQ_EVENTFD unsupported!");
      goto failed;
    }

  echo_segment_discover_mqs (echo_vpp_worker_segment_handle (0),
			     fds + n_fds_used, mp->n_fds - n_fds_used);
  echo_segment_attach_mq (echo_vpp_worker_segment_handle (0), mp->vpp_ctrl_mq,
			  mp->vpp_ctrl_mq_thread, &em->ctrl_mq);

  em->state = STATE_ATTACHED_NO_CERT;
  return 0;

failed:

  for (i = clib_max (n_fds_used - 1, 0); i < mp->n_fds; i++)
    close (fds[i]);

  return -1;
}

static int
echo_api_send_attach (clib_socket_t *cs)
{
  echo_main_t *em = &echo_main;
  app_sapi_msg_t msg = { 0 };
  app_sapi_attach_msg_t *mp = &msg.attach;
  clib_error_t *err;

  clib_memcpy (&mp->name, em->app_name, vec_len (em->app_name));
  mp->options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_ACCEPT_REDIRECT | APP_OPTIONS_FLAGS_ADD_SEGMENT;
  mp->options[APP_OPTIONS_SEGMENT_SIZE] = 256 << 20;
  mp->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 128 << 20;
  mp->options[APP_OPTIONS_RX_FIFO_SIZE] = em->fifo_size;
  mp->options[APP_OPTIONS_TX_FIFO_SIZE] = em->fifo_size;
  mp->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = em->prealloc_fifo_pairs;
  mp->options[APP_OPTIONS_EVT_QUEUE_SIZE] = em->evt_q_size;

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
echo_sapi_attach (echo_main_t *em)
{
  app_sapi_msg_t _rmp, *rmp = &_rmp;
  clib_error_t *err;
  clib_socket_t *cs;
  int fds[32];

  cs = &em->app_api_sock;
  if (echo_api_send_attach (cs))
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

  return echo_api_attach_reply_handler (&rmp->attach_reply, fds);
}

int
echo_sapi_add_cert_key (echo_main_t *em)
{
  u32 cert_len = test_srv_crt_rsa_len;
  u32 key_len = test_srv_key_rsa_len;
  u32 certkey_len = cert_len + key_len;
  app_sapi_msg_t _msg = { 0 }, *msg = &_msg;
  app_sapi_cert_key_add_del_msg_t *mp;
  app_sapi_msg_t _rmp, *rmp = &_rmp;
  clib_error_t *err;
  clib_socket_t *cs;
  u8 *certkey = 0;
  int rv = -1;

  msg->type = APP_SAPI_MSG_TYPE_ADD_DEL_CERT_KEY;
  mp = &msg->cert_key_add_del;
  mp->context = ntohl (0xfeedface);
  mp->cert_len = cert_len;
  mp->certkey_len = certkey_len;
  mp->is_add = 1;

  vec_validate (certkey, certkey_len - 1);
  clib_memcpy_fast (certkey, test_srv_crt_rsa, cert_len);
  clib_memcpy_fast (certkey + cert_len, test_srv_key_rsa, key_len);

  cs = &em->app_api_sock;
  err = clib_socket_sendmsg (cs, msg, sizeof (*msg), 0, 0);
  if (err)
    {
      clib_error_report (err);
      goto done;
    }

  err = clib_socket_sendmsg (cs, certkey, certkey_len, 0, 0);
  if (err)
    {
      clib_error_report (err);
      goto done;
    }

  /*
   * Wait for reply and process it
   */
  err = clib_socket_recvmsg (cs, rmp, sizeof (*rmp), 0, 0);
  if (err)
    {
      clib_error_report (err);
      goto done;
    }

  if (rmp->type != APP_SAPI_MSG_TYPE_ADD_DEL_CERT_KEY_REPLY)
    {
      ECHO_LOG (0, "unexpected reply type %u", rmp->type);
      goto done;
    }

  if (!rmp->cert_key_add_del_reply.retval)
    rv = rmp->cert_key_add_del_reply.index;

  em->state = STATE_ATTACHED;
  em->ckpair_index = rv;

done:

  return rv;
}

int
echo_sapi_recv_fd (echo_main_t *em, int *fds, int n_fds)
{
  app_sapi_msg_t _msg, *msg = &_msg;
  clib_error_t *err =
    clib_socket_recvmsg (&em->app_api_sock, msg, sizeof (*msg), fds, n_fds);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }
  return 0;
}

int
echo_sapi_detach (echo_main_t *em)
{
  clib_socket_t *cs = &em->app_api_sock;
  clib_socket_close (cs);
  em->state = STATE_DETACHED;
  return 0;
}

int
echo_sapi_del_cert_key (echo_main_t *em)
{
  app_sapi_msg_t _msg = { 0 }, *msg = &_msg;
  app_sapi_cert_key_add_del_msg_t *mp;
  app_sapi_msg_t _rmp, *rmp = &_rmp;
  clib_error_t *err;
  clib_socket_t *cs;

  msg->type = APP_SAPI_MSG_TYPE_ADD_DEL_CERT_KEY;
  mp = &msg->cert_key_add_del;
  mp->index = em->ckpair_index;

  cs = &em->app_api_sock;
  err = clib_socket_sendmsg (cs, msg, sizeof (*msg), 0, 0);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }

  /*
   * Wait for reply and process it
   */
  err = clib_socket_recvmsg (cs, rmp, sizeof (*rmp), 0, 0);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }

  if (rmp->type != APP_SAPI_MSG_TYPE_ADD_DEL_CERT_KEY_REPLY)
    {
      ECHO_LOG (0, "unexpected reply type %u", rmp->type);
      return -1;
    }

  if (rmp->cert_key_add_del_reply.retval)
    return -1;

  em->state = STATE_CLEANED_CERT_KEY;
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
