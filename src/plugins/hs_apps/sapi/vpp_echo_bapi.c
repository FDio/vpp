/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <hs_apps/sapi/vpp_echo_common.h>

/*
 *
 *  Binary API Messages
 *
 */

void
echo_send_attach (echo_main_t * em)
{
  vl_api_app_attach_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  clib_memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APP_ATTACH);
  bmp->client_index = em->my_client_index;
  bmp->context = ntohl (0xfeedface);
  bmp->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_ACCEPT_REDIRECT;
  bmp->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_ADD_SEGMENT;
  bmp->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = em->prealloc_fifo_pairs;
  bmp->options[APP_OPTIONS_RX_FIFO_SIZE] = em->fifo_size;
  bmp->options[APP_OPTIONS_TX_FIFO_SIZE] = em->fifo_size;
  bmp->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 128 << 20;
  bmp->options[APP_OPTIONS_SEGMENT_SIZE] = 256 << 20;
  bmp->options[APP_OPTIONS_EVT_QUEUE_SIZE] = em->evt_q_size;
  if (em->appns_id)
    {
      bmp->namespace_id_len = vec_len (em->appns_id);
      clib_memcpy_fast (bmp->namespace_id, em->appns_id,
			bmp->namespace_id_len);
      bmp->options[APP_OPTIONS_FLAGS] |= em->appns_flags;
      bmp->options[APP_OPTIONS_NAMESPACE_SECRET] = em->appns_secret;
    }
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & bmp);
}

void
echo_send_detach (echo_main_t * em)
{
  vl_api_application_detach_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  clib_memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_DETACH);
  bmp->client_index = em->my_client_index;
  bmp->context = ntohl (0xfeedface);

  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & bmp);
}

void
echo_send_add_cert_key (echo_main_t * em)
{
  u32 cert_len = test_srv_crt_rsa_len;
  u32 key_len = test_srv_key_rsa_len;
  vl_api_app_add_cert_key_pair_t *bmp;

  bmp = vl_msg_api_alloc (sizeof (*bmp) + cert_len + key_len);
  clib_memset (bmp, 0, sizeof (*bmp) + cert_len + key_len);

  bmp->_vl_msg_id = ntohs (VL_API_APP_ADD_CERT_KEY_PAIR);
  bmp->client_index = em->my_client_index;
  bmp->context = ntohl (0xfeedface);
  bmp->cert_len = clib_host_to_net_u16 (cert_len);
  bmp->certkey_len = clib_host_to_net_u16 (key_len + cert_len);
  clib_memcpy_fast (bmp->certkey, test_srv_crt_rsa, cert_len);
  clib_memcpy_fast (bmp->certkey + cert_len, test_srv_key_rsa, key_len);

  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & bmp);
}

void
echo_send_del_cert_key (echo_main_t * em)
{
  vl_api_app_del_cert_key_pair_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  clib_memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APP_DEL_CERT_KEY_PAIR);
  bmp->client_index = em->my_client_index;
  bmp->context = ntohl (0xfeedface);
  bmp->index = clib_host_to_net_u32 (em->ckpair_index);
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & bmp);
}

void
echo_send_listen (echo_main_t * em)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_listen_msg_t *mp;
  svm_msg_q_t *mq = em->ctrl_mq;

  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_LISTEN);
  mp = (session_listen_msg_t *) app_evt->evt->data;
  memset (mp, 0, sizeof (*mp));
  mp->client_index = em->my_client_index;
  mp->context = ntohl (0xfeedface);
  mp->wrk_index = 0;
  mp->is_ip4 = em->uri_elts.is_ip4;
  clib_memcpy_fast (&mp->ip, &em->uri_elts.ip, sizeof (mp->ip));
  mp->port = em->uri_elts.port;
  mp->proto = em->uri_elts.transport_proto;
  mp->ckpair_index = em->ckpair_index;
  mp->crypto_engine = em->crypto_engine;
  app_send_ctrl_evt_to_vpp (mq, app_evt);
}

void
echo_send_unbind (echo_main_t * em, echo_session_t * s)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_unlisten_msg_t *mp;
  svm_msg_q_t *mq = em->ctrl_mq;

  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_UNLISTEN);
  mp = (session_unlisten_msg_t *) app_evt->evt->data;
  memset (mp, 0, sizeof (*mp));
  mp->client_index = em->my_client_index;
  mp->wrk_index = 0;
  mp->handle = s->vpp_session_handle;
  mp->context = 0;
  app_send_ctrl_evt_to_vpp (mq, app_evt);
}

void
echo_send_connect (u64 parent_session_handle, u32 opaque)
{
  echo_main_t *em = &echo_main;
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_connect_msg_t *mp;
  svm_msg_q_t *mq = em->ctrl_mq;

  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_CONNECT);
  mp = (session_connect_msg_t *) app_evt->evt->data;
  memset (mp, 0, sizeof (*mp));
  mp->client_index = em->my_client_index;
  mp->context = ntohl (opaque);
  mp->wrk_index = 0;
  mp->is_ip4 = em->uri_elts.is_ip4;
  clib_memcpy_fast (&mp->ip, &em->uri_elts.ip, sizeof (mp->ip));
  mp->port = em->uri_elts.port;
  mp->proto = em->uri_elts.transport_proto;
  mp->parent_handle = parent_session_handle;
  mp->ckpair_index = em->ckpair_index;
  mp->crypto_engine = em->crypto_engine;
  app_send_ctrl_evt_to_vpp (mq, app_evt);
}

void
echo_send_disconnect_session (u64 handle, u32 opaque)
{
  echo_main_t *em = &echo_main;
  echo_session_t *s;
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_disconnect_msg_t *mp;
  svm_msg_q_t *mq = em->ctrl_mq;

  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_DISCONNECT);
  mp = (session_disconnect_msg_t *) app_evt->evt->data;
  memset (mp, 0, sizeof (*mp));
  mp->client_index = em->my_client_index;
  mp->handle = handle;
  app_send_ctrl_evt_to_vpp (mq, app_evt);

  if (!(s = echo_get_session_from_handle (em, mp->handle)))
    return;
  em->proto_cb_vft->sent_disconnect_cb (s);
}

/*
 *
 *  Helpers
 *
 */

static int
ssvm_segment_attach (char *name, ssvm_segment_type_t type, int fd)
{
  fifo_segment_create_args_t _a, *a = &_a;
  fifo_segment_main_t *sm = &echo_main.segment_main;
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->segment_name = (char *) name;
  a->segment_type = type;

  if (type == SSVM_SEGMENT_MEMFD)
    a->memfd_fd = fd;

  if ((rv = fifo_segment_attach (sm, a)))
    return rv;
  vec_reset_length (a->new_segment_indices);
  return 0;
}

static inline void
echo_segment_handle_add_del (echo_main_t * em, u64 segment_handle, u8 add)
{
  clib_spinlock_lock (&em->segment_handles_lock);
  if (add)
    hash_set (em->shared_segment_handles, segment_handle, 1);
  else
    hash_unset (em->shared_segment_handles, segment_handle);
  clib_spinlock_unlock (&em->segment_handles_lock);
}

/*
 *
 *  Binary API callbacks
 *
 */

static void
  vl_api_app_add_cert_key_pair_reply_t_handler
  (vl_api_app_add_cert_key_pair_reply_t * mp)
{
  echo_main_t *em = &echo_main;
  if (mp->retval)
    {
      ECHO_FAIL (ECHO_FAIL_VL_API_CERT_KEY_ADD_REPLY,
		 "Adding cert and key returned %d",
		 clib_net_to_host_u32 (mp->retval));
      return;
    }
  /* No concurrency here, only bapi thread writes */
  if (em->state != STATE_ATTACHED_NO_CERT)
    {
      ECHO_FAIL (ECHO_FAIL_VL_API_CERT_KEY_ADD_REPLY, "Wrong state");
      return;
    }
  em->ckpair_index = clib_net_to_host_u32 (mp->index);
  em->state = STATE_ATTACHED;
}

static void
  vl_api_app_del_cert_key_pair_reply_t_handler
  (vl_api_app_del_cert_key_pair_reply_t * mp)
{
  echo_main_t *em = &echo_main;
  if (mp->retval)
    {
      ECHO_FAIL (ECHO_FAIL_VL_API_CERT_KEY_DEL_REPLY,
		 "Delete cert and key returned %d",
		 clib_net_to_host_u32 (mp->retval));
      return;
    }
  em->state = STATE_CLEANED_CERT_KEY;
}

static void
vl_api_app_attach_reply_t_handler (vl_api_app_attach_reply_t * mp)
{
  echo_main_t *em = &echo_main;
  int *fds = 0, i;
  u32 n_fds = 0;
  u64 segment_handle;
  segment_handle = clib_net_to_host_u64 (mp->segment_handle);
  ECHO_LOG (1, "Attached returned app %u", htons (mp->app_index));

  if (mp->retval)
    {
      ECHO_FAIL (ECHO_FAIL_VL_API_APP_ATTACH, "attach failed: %U",
		 format_api_error, clib_net_to_host_u32 (mp->retval));
      return;
    }

  if (mp->segment_name_length == 0)
    {
      ECHO_FAIL (ECHO_FAIL_VL_API_MISSING_SEGMENT_NAME,
		 "segment_name_length zero");
      return;
    }

  if (!mp->app_mq)
    {
      ECHO_FAIL (ECHO_FAIL_VL_API_NULL_APP_MQ, "NULL app_mq");
      return;
    }
  em->app_mq = uword_to_pointer (mp->app_mq, svm_msg_q_t *);
  em->ctrl_mq = uword_to_pointer (mp->vpp_ctrl_mq, svm_msg_q_t *);

  if (mp->n_fds)
    {
      vec_validate (fds, mp->n_fds);
      if (vl_socket_client_recv_fd_msg (fds, mp->n_fds, 5))
	{
	  ECHO_FAIL (ECHO_FAIL_VL_API_RECV_FD_MSG,
		     "vl_socket_client_recv_fd_msg failed");
	  goto failed;
	}

      if (mp->fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
	if (ssvm_segment_attach (0, SSVM_SEGMENT_MEMFD, fds[n_fds++]))
	  {
	    ECHO_FAIL (ECHO_FAIL_VL_API_SVM_FIFO_SEG_ATTACH,
		       "svm_fifo_segment_attach failed on SSVM_SEGMENT_MEMFD");
	    goto failed;
	  }

      if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
	if (ssvm_segment_attach ((char *) mp->segment_name,
				 SSVM_SEGMENT_MEMFD, fds[n_fds++]))
	  {
	    ECHO_FAIL (ECHO_FAIL_VL_API_SVM_FIFO_SEG_ATTACH,
		       "svm_fifo_segment_attach ('%s') "
		       "failed on SSVM_SEGMENT_MEMFD", mp->segment_name);
	    goto failed;
	  }
      if (mp->fd_flags & SESSION_FD_F_MQ_EVENTFD)
	svm_msg_q_set_consumer_eventfd (em->app_mq, fds[n_fds++]);

      vec_free (fds);
    }
  else
    {
      if (ssvm_segment_attach ((char *) mp->segment_name, SSVM_SEGMENT_SHM,
			       -1))
	{
	  ECHO_FAIL (ECHO_FAIL_VL_API_SVM_FIFO_SEG_ATTACH,
		     "svm_fifo_segment_attach ('%s') "
		     "failed on SSVM_SEGMENT_SHM", mp->segment_name);
	  return;
	}
    }
  echo_segment_handle_add_del (em, segment_handle, 1 /* add */ );
  ECHO_LOG (1, "Mapped segment 0x%lx", segment_handle);

  em->state = STATE_ATTACHED_NO_CERT;
  return;
failed:
  for (i = clib_max (n_fds - 1, 0); i < vec_len (fds); i++)
    close (fds[i]);
  vec_free (fds);
}

static void
vl_api_application_detach_reply_t_handler (vl_api_application_detach_reply_t *
					   mp)
{
  if (mp->retval)
    {
      ECHO_FAIL (ECHO_FAIL_VL_API_DETACH_REPLY,
		 "app detach returned with err: %d", mp->retval);
      return;
    }
  echo_main.state = STATE_DETACHED;
}

static void
vl_api_unmap_segment_t_handler (vl_api_unmap_segment_t * mp)
{
  echo_main_t *em = &echo_main;
  u64 segment_handle = clib_net_to_host_u64 (mp->segment_handle);
  echo_segment_handle_add_del (em, segment_handle, 0 /* add */ );
  ECHO_LOG (1, "Unmaped segment 0x%lx", segment_handle);
}

static void
vl_api_map_another_segment_t_handler (vl_api_map_another_segment_t * mp)
{
  fifo_segment_main_t *sm = &echo_main.segment_main;
  fifo_segment_create_args_t _a, *a = &_a;
  echo_main_t *em = &echo_main;
  int *fds = 0, i;
  char *seg_name = (char *) mp->segment_name;
  u64 segment_handle = clib_net_to_host_u64 (mp->segment_handle);

  if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
    {
      vec_validate (fds, 1);
      if (vl_socket_client_recv_fd_msg (fds, 1, 5))
	{
	  ECHO_FAIL (ECHO_FAIL_VL_API_RECV_FD_MSG,
		     "vl_socket_client_recv_fd_msg failed");
	  goto failed;
	}

      if (ssvm_segment_attach (seg_name, SSVM_SEGMENT_MEMFD, fds[0]))
	{
	  ECHO_FAIL (ECHO_FAIL_VL_API_SVM_FIFO_SEG_ATTACH,
		     "svm_fifo_segment_attach ('%s') "
		     "failed on SSVM_SEGMENT_MEMFD", seg_name);
	  goto failed;
	}
      vec_free (fds);
    }
  else
    {
      clib_memset (a, 0, sizeof (*a));
      a->segment_name = seg_name;
      a->segment_size = mp->segment_size;
      /* Attach to the segment vpp created */
      if (fifo_segment_attach (sm, a))
	{
	  ECHO_FAIL (ECHO_FAIL_VL_API_FIFO_SEG_ATTACH,
		     "fifo_segment_attach ('%s') failed", seg_name);
	  goto failed;
	}
    }
  echo_segment_handle_add_del (em, segment_handle, 1 /* add */ );
  ECHO_LOG (1, "Mapped segment 0x%lx", segment_handle);
  return;

failed:
  for (i = 0; i < vec_len (fds); i++)
    close (fds[i]);
  vec_free (fds);
}

#define foreach_quic_echo_msg                                    \
_(APP_ATTACH_REPLY, app_attach_reply)                            \
_(APPLICATION_DETACH_REPLY, application_detach_reply)            \
_(MAP_ANOTHER_SEGMENT, map_another_segment)                      \
_(APP_ADD_CERT_KEY_PAIR_REPLY, app_add_cert_key_pair_reply)      \
_(APP_DEL_CERT_KEY_PAIR_REPLY, app_del_cert_key_pair_reply)      \
_(UNMAP_SEGMENT, unmap_segment)

void
echo_api_hookup (echo_main_t * em)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_quic_echo_msg;
#undef _
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
