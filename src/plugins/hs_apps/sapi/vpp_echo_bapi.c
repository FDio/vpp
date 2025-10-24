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

#define REPLY_MSG_ID_BASE msg_id_base
static u16 msg_id_base;

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

  bmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_APP_ATTACH);
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
      vl_api_vec_to_api_string (em->appns_id, &bmp->namespace_id);
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

  bmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_APPLICATION_DETACH);
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

  bmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_APP_ADD_CERT_KEY_PAIR);
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

  bmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_APP_DEL_CERT_KEY_PAIR);
  bmp->client_index = em->my_client_index;
  bmp->context = ntohl (0xfeedface);
  bmp->index = clib_host_to_net_u32 (em->ckpair_index);
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & bmp);
}

int
echo_bapi_recv_fd (echo_main_t *em, int *fds, int n_fds)
{
  clib_error_t *err;
  err = vl_socket_client_recv_fd_msg (fds, n_fds, 5);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }
  return 0;
}

static u8
echo_transport_needs_crypto (transport_proto_t proto)
{
  return proto == TRANSPORT_PROTO_TLS || proto == TRANSPORT_PROTO_DTLS ||
	 proto == TRANSPORT_PROTO_QUIC;
}

static void
echo_msg_add_crypto_ext_config (echo_main_t *em, uword *offset)
{
  transport_endpt_ext_cfg_t cfg;
  svm_fifo_chunk_t *c;

  c = echo_segment_alloc_chunk (ECHO_MQ_SEG_HANDLE, 0, sizeof (cfg), offset);
  if (!c)
    return;

  memset (&cfg, 0, sizeof (cfg));
  cfg.type = TRANSPORT_ENDPT_EXT_CFG_CRYPTO;
  cfg.len = sizeof (cfg);
  cfg.crypto.ckpair_index = em->ckpair_index;
  cfg.crypto.crypto_engine = em->crypto_engine;
  clib_memcpy_fast (c->data, &cfg, cfg.len);
}

void
echo_send_listen (echo_main_t * em, ip46_address_t * ip)
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
  clib_memcpy_fast (&mp->ip, ip, sizeof (mp->ip));
  mp->port = em->uri_elts.port;
  mp->proto = em->uri_elts.transport_proto;
  if (echo_transport_needs_crypto (mp->proto))
    echo_msg_add_crypto_ext_config (em, &mp->ext_config);
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
echo_send_connect (echo_main_t * em, void *args)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_connect_msg_t *mp;
  echo_connect_args_t *a = (echo_connect_args_t *) args;
  svm_msg_q_t *mq = em->ctrl_mq;

  clib_atomic_sub_fetch (&em->max_sim_connects, 1);
  while (em->max_sim_connects <= 0)
    ;

  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_CONNECT);
  mp = (session_connect_msg_t *) app_evt->evt->data;
  memset (mp, 0, sizeof (*mp));
  mp->client_index = em->my_client_index;
  mp->context = ntohl (a->context);
  mp->wrk_index = 0;
  mp->is_ip4 = em->uri_elts.is_ip4;
  clib_memcpy_fast (&mp->ip, &a->ip, sizeof (mp->ip));
  clib_memcpy_fast (&mp->lcl_ip, &a->lcl_ip, sizeof (mp->ip));
  mp->port = em->uri_elts.port;
  mp->proto = em->uri_elts.transport_proto;
  mp->parent_handle = a->parent_session_handle;
  if (echo_transport_needs_crypto (mp->proto))
    echo_msg_add_crypto_ext_config (em, &mp->ext_config);
  mp->flags = em->connect_flag;
  app_send_ctrl_evt_to_vpp (mq, app_evt);
}

void
echo_send_connect_stream (echo_main_t *em, void *args)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_connect_msg_t *mp;
  echo_connect_args_t *a = (echo_connect_args_t *) args;
  svm_msg_q_t *mq = em->ctrl_mq;

  clib_atomic_sub_fetch (&em->max_sim_connects, 1);
  while (em->max_sim_connects <= 0)
    ;

  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_CONNECT_STREAM);
  mp = (session_connect_msg_t *) app_evt->evt->data;
  memset (mp, 0, sizeof (*mp));
  mp->client_index = em->my_client_index;
  mp->context = ntohl (a->context);
  mp->wrk_index = 0;
  mp->proto = em->uri_elts.transport_proto;
  mp->parent_handle = a->parent_session_handle;
  mp->flags = em->connect_flag;
  app_send_ctrl_evt_to_vpp (mq, app_evt);
}

void
echo_send_disconnect_session (echo_main_t * em, void *args)
{
  echo_session_t *s;
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_disconnect_msg_t *mp;
  svm_msg_q_t *mq = em->ctrl_mq;
  echo_disconnect_args_t *a = (echo_disconnect_args_t *) args;

  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_DISCONNECT);
  mp = (session_disconnect_msg_t *) app_evt->evt->data;
  memset (mp, 0, sizeof (*mp));
  mp->client_index = em->my_client_index;
  mp->handle = a->session_handle;
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

int
echo_segment_attach (u64 segment_handle, char *name, ssvm_segment_type_t type,
		     int fd)
{
  fifo_segment_create_args_t _a, *a = &_a;
  echo_main_t *em = &echo_main;
  fifo_segment_main_t *sm;
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->segment_name = (char *) name;
  a->segment_type = type;

  if (type == SSVM_SEGMENT_MEMFD)
    a->memfd_fd = fd;

  sm = &em->segment_main;

  if ((rv = fifo_segment_attach (sm, a)))
    return rv;

  clib_spinlock_lock (&em->segment_handles_lock);
  hash_set (em->shared_segment_handles, segment_handle,
	    a->new_segment_indices[0]);
  clib_spinlock_unlock (&em->segment_handles_lock);

  vec_free (a->new_segment_indices);
  return 0;
}

u32
echo_segment_lookup (u64 segment_handle)
{
  echo_main_t *em = &echo_main;
  uword *segment_idxp;

  ECHO_LOG (3, "Check if segment mapped 0x%lx...", segment_handle);

  clib_spinlock_lock (&em->segment_handles_lock);
  segment_idxp = hash_get (em->shared_segment_handles, segment_handle);
  clib_spinlock_unlock (&em->segment_handles_lock);
  if (segment_idxp)
    return ((u32) *segment_idxp);

  ECHO_LOG (2, "Segment not mapped (0x%lx)", segment_handle);
  return ~0;
}

void
echo_segment_detach (u64 segment_handle)
{
  echo_main_t *em = &echo_main;
  fifo_segment_main_t *sm;

  u32 segment_index = echo_segment_lookup (segment_handle);
  if (segment_index == (u32) ~0)
    return;

  sm = &em->segment_main;

  clib_spinlock_lock (&em->segment_handles_lock);
  fifo_segment_delete (sm, fifo_segment_get_segment (sm, segment_index));
  hash_unset (em->shared_segment_handles, segment_handle);
  clib_spinlock_unlock (&em->segment_handles_lock);
}

int
echo_attach_session (uword segment_handle, uword rxf_offset, uword txf_offset,
		     uword mq_offset, echo_session_t *s)
{
  echo_main_t *em = &echo_main;
  u32 fs_index, eqs_index;
  fifo_segment_t *fs;

  fs_index = echo_segment_lookup (segment_handle);
  if (fs_index == (u32) ~0)
    {
      ECHO_LOG (0, "ERROR: segment for session %u is not mounted!",
		s->session_index);
      return -1;
    }

  if (mq_offset != (uword) ~0)
    {
      eqs_index = echo_segment_lookup (ECHO_MQ_SEG_HANDLE);
      ASSERT (eqs_index != (u32) ~0);
    }

  clib_spinlock_lock (&em->segment_handles_lock);

  fs = fifo_segment_get_segment (&em->segment_main, fs_index);
  s->rx_fifo = fifo_segment_alloc_fifo_w_offset (fs, rxf_offset);
  s->tx_fifo = fifo_segment_alloc_fifo_w_offset (fs, txf_offset);
  s->rx_fifo->segment_index = fs_index;
  s->tx_fifo->segment_index = fs_index;
  s->rx_fifo->vpp_session_index = s->rx_fifo->shr->master_session_index;
  s->tx_fifo->vpp_session_index = s->tx_fifo->shr->master_session_index;
  s->rx_fifo->app_session_index = s->session_index;
  s->tx_fifo->app_session_index = s->session_index;
  s->rx_fifo->shr->client_session_index = s->session_index;
  s->tx_fifo->shr->client_session_index = s->session_index;

  if (mq_offset != (uword) ~0)
    {
      fs = fifo_segment_get_segment (&em->segment_main, eqs_index);
      s->vpp_evt_q = fifo_segment_msg_q_attach (fs, mq_offset,
						s->rx_fifo->shr->slice_index);
    }

  clib_spinlock_unlock (&em->segment_handles_lock);

  return 0;
}

int
echo_segment_attach_mq (uword segment_handle, uword mq_offset, u32 mq_index,
			svm_msg_q_t **mq)
{
  echo_main_t *em = &echo_main;
  fifo_segment_t *fs;
  u32 fs_index;

  fs_index = echo_segment_lookup (segment_handle);
  if (fs_index == (u32) ~0)
    {
      ECHO_LOG (0, "ERROR: mq segment %lx for is not attached!",
		segment_handle);
      return -1;
    }

  clib_spinlock_lock (&em->segment_handles_lock);

  fs = fifo_segment_get_segment (&em->segment_main, fs_index);
  *mq = fifo_segment_msg_q_attach (fs, mq_offset, mq_index);

  clib_spinlock_unlock (&em->segment_handles_lock);

  return 0;
}

svm_fifo_chunk_t *
echo_segment_alloc_chunk (uword segment_handle, u32 slice_index, u32 size,
			  uword *offset)
{
  echo_main_t *em = &echo_main;
  svm_fifo_chunk_t *c;
  fifo_segment_t *fs;
  u32 fs_index;

  fs_index = echo_segment_lookup (segment_handle);
  if (fs_index == (u32) ~0)
    {
      ECHO_LOG (0, "ERROR: mq segment %lx for is not attached!",
		segment_handle);
      return 0;
    }

  clib_spinlock_lock (&em->segment_handles_lock);

  fs = fifo_segment_get_segment (&em->segment_main, fs_index);
  c = fifo_segment_alloc_chunk_w_slice (fs, slice_index, size);
  *offset = fifo_segment_chunk_offset (fs, c);

  clib_spinlock_unlock (&em->segment_handles_lock);

  return c;
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
  int *fds = 0, i, rv;
  u32 n_fds = 0;
  u64 segment_handle;
  char *segment_name = 0;

  segment_handle = clib_net_to_host_u64 (mp->segment_handle);
  ECHO_LOG (2, "Attached returned app %u", htons (mp->app_index));

  if (mp->retval)
    {
      ECHO_FAIL (ECHO_FAIL_VL_API_APP_ATTACH, "attach failed: %U",
		 format_api_error, clib_net_to_host_u32 (mp->retval));
      return;
    }

  if (!mp->app_mq)
    {
      ECHO_FAIL (ECHO_FAIL_VL_API_NULL_APP_MQ, "NULL app_mq");
      return;
    }

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
	if (echo_segment_attach (ECHO_MQ_SEG_HANDLE, 0, SSVM_SEGMENT_MEMFD,
				 fds[n_fds++]))
	  {
	    ECHO_FAIL (ECHO_FAIL_VL_API_SVM_FIFO_SEG_ATTACH,
		       "svm_fifo_segment_attach failed on SSVM_SEGMENT_MEMFD");
	    goto failed;
	  }
      echo_segment_attach_mq (ECHO_MQ_SEG_HANDLE, mp->vpp_ctrl_mq,
			      mp->vpp_ctrl_mq_thread, &em->ctrl_mq);

      if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
	{
	  segment_name = vl_api_from_api_to_new_c_string (&mp->segment_name);
	  rv = echo_segment_attach (segment_handle, segment_name,
				    SSVM_SEGMENT_MEMFD, fds[n_fds++]);
	  if (rv != 0)
	    {
	      ECHO_FAIL (ECHO_FAIL_VL_API_SVM_FIFO_SEG_ATTACH,
			 "svm_fifo_segment_attach ('%s') "
			 "failed on SSVM_SEGMENT_MEMFD", segment_name);
	      vec_free (segment_name);
	      goto failed;
	    }
	  vec_free (segment_name);
	}
      echo_segment_attach_mq (segment_handle, mp->app_mq, 0, &em->app_mq);

      if (mp->fd_flags & SESSION_FD_F_MQ_EVENTFD)
	svm_msg_q_set_eventfd (em->app_mq, fds[n_fds++]);

      vec_free (fds);
    }
  else
    {
      segment_name = vl_api_from_api_to_new_c_string (&mp->segment_name);
      rv = echo_segment_attach (segment_handle, segment_name, SSVM_SEGMENT_SHM,
				-1);
      if (rv != 0)
	{
	  ECHO_FAIL (ECHO_FAIL_VL_API_SVM_FIFO_SEG_ATTACH,
		     "svm_fifo_segment_attach ('%s') "
		     "failed on SSVM_SEGMENT_SHM", segment_name);
	  vec_free (segment_name);
	  goto failed;
	}
      vec_free (segment_name);
    }
  ECHO_LOG (2, "Mapped segment 0x%lx", segment_handle);

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

#define foreach_quic_echo_msg                                    \
_(APP_ATTACH_REPLY, app_attach_reply)                            \
_(APPLICATION_DETACH_REPLY, application_detach_reply)            \
_(APP_ADD_CERT_KEY_PAIR_REPLY, app_add_cert_key_pair_reply)      \
_(APP_DEL_CERT_KEY_PAIR_REPLY, app_del_cert_key_pair_reply)

#define vl_endianfun
#include <vnet/session/session.api.h>
#undef vl_endianfun

#define vl_calcsizefun
#include <vnet/session/session.api.h>
#undef vl_calcsizefun

#define vl_printfun
#include <vnet/session/session.api.h>
#undef vl_printfun

#define vl_api_version(n, v) static u32 api_version = v;
#include <vnet/session/session.api.h>
#undef vl_api_version

void
echo_api_hookup (echo_main_t * em)
{
  u8 *name = format (0, "session_%08x%c", api_version, 0);

  REPLY_MSG_ID_BASE = vl_client_get_first_plugin_msg_id ((char *) name);

  vec_free (name);

  if (REPLY_MSG_ID_BASE == (u16) ~0)
    return;

#define _(N, n)                                                               \
  vl_msg_api_config (&(vl_msg_api_msg_config_t){                              \
    .id = REPLY_MSG_ID_BASE + VL_API_##N,                                     \
    .name = #n,                                                               \
    .handler = vl_api_##n##_t_handler,                                        \
    .endian = vl_api_##n##_t_endian,                                          \
    .format_fn = vl_api_##n##_t_format,                                       \
    .size = sizeof (vl_api_##n##_t),                                          \
    .traced = 1,                                                              \
    .tojson = vl_api_##n##_t_tojson,                                          \
    .fromjson = vl_api_##n##_t_fromjson,                                      \
    .calc_size = vl_api_##n##_t_calc_size,                                    \
  });
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
