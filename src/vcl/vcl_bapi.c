/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

static int
vcl_segment_attach (u64 segment_handle, char *name, ssvm_segment_type_t type,
		    int fd)
{
  svm_fifo_segment_create_args_t _a, *a = &_a;
  int rv;

  memset (a, 0, sizeof (*a));
  a->segment_name = (char *) name;
  a->segment_type = type;

  if (type == SSVM_SEGMENT_MEMFD)
    a->memfd_fd = fd;

  if ((rv = svm_fifo_segment_attach (&vcm->segment_main, a)))
    {
      clib_warning ("svm_fifo_segment_attach ('%s') failed", name);
      return rv;
    }
  vcl_segment_table_add (segment_handle, a->new_segment_indices[0]);
  vec_reset_length (a->new_segment_indices);
  return 0;
}

static void
vcl_segment_detach (u64 segment_handle)
{
  svm_fifo_segment_main_t *sm = &vcm->segment_main;
  svm_fifo_segment_private_t *segment;
  u32 segment_index;

  segment_index = vcl_segment_table_lookup (segment_handle);
  if (segment_index == (u32) ~ 0)
    return;
  segment = svm_fifo_segment_get_segment (sm, segment_index);
  svm_fifo_segment_delete (sm, segment);
  vcl_segment_table_del (segment_handle);
  VDBG (0, "detached segment %u handle %u", segment_index, segment_handle);
}

static u64
vcl_vpp_worker_segment_handle (u32 wrk_index)
{
  return (VCL_INVALID_SEGMENT_HANDLE - wrk_index - 1);
}

static void
vl_api_application_attach_reply_t_handler (vl_api_application_attach_reply_t *
					   mp)
{
  vcl_worker_t *wrk = vcl_worker_get (0);
  u64 segment_handle;
  u32 n_fds = 0;
  int *fds = 0;

  if (mp->retval)
    {
      clib_warning ("VCL<%d>: attach failed: %U", getpid (),
		    format_api_error, ntohl (mp->retval));
      return;
    }

  wrk->app_event_queue = uword_to_pointer (mp->app_event_queue_address,
					   svm_msg_q_t *);
  segment_handle = clib_net_to_host_u64 (mp->segment_handle);
  if (segment_handle == VCL_INVALID_SEGMENT_HANDLE)
    {
      clib_warning ("invalid segment handle");
      return;
    }

  if (mp->n_fds)
    {
      vec_validate (fds, mp->n_fds);
      vl_socket_client_recv_fd_msg (fds, mp->n_fds, 5);

      if (mp->fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
	if (vcl_segment_attach (vcl_vpp_worker_segment_handle (0),
				"vpp-mq-seg", SSVM_SEGMENT_MEMFD,
				fds[n_fds++]))
	  return;

      if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
	if (vcl_segment_attach (segment_handle, (char *) mp->segment_name,
				SSVM_SEGMENT_MEMFD, fds[n_fds++]))
	  return;

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
	return;
    }

  vcm->app_index = clib_net_to_host_u32 (mp->app_index);
  vcm->app_state = STATE_APP_ATTACHED;
}

static void
vl_api_app_worker_add_del_reply_t_handler (vl_api_app_worker_add_del_reply_t *
					   mp)
{
  int n_fds = 0, *fds = 0;
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

  segment_handle = clib_net_to_host_u64 (mp->segment_handle);
  if (segment_handle == VCL_INVALID_SEGMENT_HANDLE)
    {
      clib_warning ("invalid segment handle");
      goto failed;
    }

  if (mp->n_fds)
    {
      vec_validate (fds, mp->n_fds);
      vl_socket_client_recv_fd_msg (fds, mp->n_fds, 5);

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
}

static void
vl_api_application_detach_reply_t_handler (vl_api_application_detach_reply_t *
					   mp)
{
  if (mp->retval)
    clib_warning ("VCL<%d>: detach failed: %U", getpid (), format_api_error,
		  ntohl (mp->retval));

  vcm->app_state = STATE_APP_ENABLED;
}

static void
vl_api_map_another_segment_t_handler (vl_api_map_another_segment_t * mp)
{
  ssvm_segment_type_t seg_type = SSVM_SEGMENT_SHM;
  u64 segment_handle;
  int fd = -1;

  if (mp->fd_flags)
    {
      vl_socket_client_recv_fd_msg (&fd, 1, 5);
      seg_type = SSVM_SEGMENT_MEMFD;
    }

  segment_handle = clib_net_to_host_u64 (mp->segment_handle);
  if (segment_handle == VCL_INVALID_SEGMENT_HANDLE)
    {
      clib_warning ("invalid segment handle");
      return;
    }

  if (vcl_segment_attach (segment_handle, (char *) mp->segment_name,
			  seg_type, fd))
    {
      clib_warning ("VCL<%d>: svm_fifo_segment_attach ('%s') failed",
		    getpid (), mp->segment_name);
      return;
    }

  VDBG (1, "VCL<%d>: mapped new segment '%s' size %d", getpid (),
	mp->segment_name, mp->segment_size);
}

static void
vl_api_unmap_segment_t_handler (vl_api_unmap_segment_t * mp)
{
  u64 segment_handle = clib_net_to_host_u64 (mp->segment_handle);
  vcl_segment_detach (segment_handle);
  VDBG (1, "Unmapped segment: %d", segment_handle);
}

static void
  vl_api_app_cut_through_registration_add_t_handler
  (vl_api_app_cut_through_registration_add_t * mp)
{
  vcl_cut_through_registration_t *ctr;
  u32 mqc_index = ~0;
  vcl_worker_t *wrk;
  int *fds = 0;

  if (mp->n_fds)
    {
      ASSERT (mp->n_fds == 2);
      vec_validate (fds, mp->n_fds);
      vl_socket_client_recv_fd_msg (fds, mp->n_fds, 5);
    }

  wrk = vcl_worker_get (mp->wrk_index);
  ctr = vcl_ct_registration_lock_and_alloc (wrk);
  ctr->mq = uword_to_pointer (mp->evt_q_address, svm_msg_q_t *);
  ctr->peer_mq = uword_to_pointer (mp->peer_evt_q_address, svm_msg_q_t *);
  VDBG (0, "Adding ct registration %u", vcl_ct_registration_index (wrk, ctr));

  if (mp->n_fds && (mp->fd_flags & SESSION_FD_F_MQ_EVENTFD))
    {
      svm_msg_q_set_consumer_eventfd (ctr->mq, fds[0]);
      svm_msg_q_set_producer_eventfd (ctr->peer_mq, fds[1]);
      mqc_index = vcl_mq_epoll_add_evfd (wrk, ctr->mq);
      ctr->epoll_evt_conn_index = mqc_index;
      vec_free (fds);
    }
  vcl_ct_registration_lookup_add (wrk, mp->evt_q_address,
				  vcl_ct_registration_index (wrk, ctr));
  vcl_ct_registration_unlock (wrk);
}

static void
vl_api_bind_sock_reply_t_handler (vl_api_bind_sock_reply_t * mp)
{
  /* Expecting a similar message on mq. So ignore this */
  VDBG (0, "bapi msg vpp handle 0x%llx, sid %u: bind retval: %u!",
	getpid (), mp->handle, mp->context, mp->retval);
}

static void
vl_api_unbind_sock_reply_t_handler (vl_api_unbind_sock_reply_t * mp)
{
  if (mp->retval)
    clib_warning ("VCL<%d>: ERROR: sid %u: unbind failed: %U",
		  getpid (), mp->context, format_api_error,
		  ntohl (mp->retval));

  else
    VDBG (1, "VCL<%d>: sid %u: unbind succeeded!", getpid (), mp->context);
}

static void
vl_api_disconnect_session_reply_t_handler (vl_api_disconnect_session_reply_t *
					   mp)
{
  if (mp->retval)
    clib_warning ("VCL<%d>: ERROR: sid %u: disconnect failed: %U",
		  getpid (), mp->context, format_api_error,
		  ntohl (mp->retval));
}

static void
vl_api_connect_session_reply_t_handler (vl_api_connect_sock_reply_t * mp)
{
  if (mp->retval)
    clib_warning ("VCL<%d>: ERROR: sid %u: connect failed: %U",
		  getpid (), mp->context, format_api_error,
		  ntohl (mp->retval));
}

static void
  vl_api_application_tls_cert_add_reply_t_handler
  (vl_api_application_tls_cert_add_reply_t * mp)
{
  if (mp->retval)
    {
      clib_warning ("VCL<%d>: add cert failed: %U", getpid (),
		    format_api_error, ntohl (mp->retval));
      return;
    }
}

static void
  vl_api_application_tls_key_add_reply_t_handler
  (vl_api_application_tls_key_add_reply_t * mp)
{
  if (mp->retval)
    {
      clib_warning ("VCL<%d>: add key failed: %U", getpid (),
		    format_api_error, ntohl (mp->retval));
      return;
    }

}

#define foreach_sock_msg                                        	\
_(SESSION_ENABLE_DISABLE_REPLY, session_enable_disable_reply)   	\
_(BIND_SOCK_REPLY, bind_sock_reply)                             	\
_(UNBIND_SOCK_REPLY, unbind_sock_reply)                         	\
_(CONNECT_SESSION_REPLY, connect_session_reply)                        	\
_(DISCONNECT_SESSION_REPLY, disconnect_session_reply)			\
_(APPLICATION_ATTACH_REPLY, application_attach_reply)           	\
_(APPLICATION_DETACH_REPLY, application_detach_reply)           	\
_(APPLICATION_TLS_CERT_ADD_REPLY, application_tls_cert_add_reply)  	\
_(APPLICATION_TLS_KEY_ADD_REPLY, application_tls_key_add_reply)  	\
_(MAP_ANOTHER_SEGMENT, map_another_segment)                     	\
_(UNMAP_SEGMENT, unmap_segment)						\
_(APP_CUT_THROUGH_REGISTRATION_ADD, app_cut_through_registration_add)	\
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
  vl_api_application_attach_t *bmp;
  u8 nsid_len = vec_len (vcm->cfg.namespace_id);
  u8 app_is_proxy = (vcm->cfg.app_proxy_transport_tcp ||
		     vcm->cfg.app_proxy_transport_udp);

  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_ATTACH);
  bmp->client_index = wrk->my_client_index;
  bmp->context = htonl (0xfeedface);
  bmp->options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_ACCEPT_REDIRECT | APP_OPTIONS_FLAGS_ADD_SEGMENT |
    (vcm->cfg.app_scope_local ? APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE : 0) |
    (vcm->cfg.app_scope_global ? APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE : 0) |
    (app_is_proxy ? APP_OPTIONS_FLAGS_IS_PROXY : 0) |
    APP_OPTIONS_FLAGS_USE_MQ_FOR_CTRL_MSGS |
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
  bmp->options[APP_OPTIONS_TLS_ENGINE] = TLS_ENGINE_OPENSSL;
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
vppcom_send_connect_sock (vcl_session_t * session)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vl_api_connect_sock_t *cmp;

  cmp = vl_msg_api_alloc (sizeof (*cmp));
  memset (cmp, 0, sizeof (*cmp));
  cmp->_vl_msg_id = ntohs (VL_API_CONNECT_SOCK);
  cmp->client_index = wrk->my_client_index;
  cmp->context = session->session_index;
  cmp->wrk_index = wrk->vpp_wrk_index;
  cmp->is_ip4 = session->transport.is_ip4;
  clib_memcpy_fast (cmp->ip, &session->transport.rmt_ip, sizeof (cmp->ip));
  cmp->port = session->transport.rmt_port;
  cmp->proto = session->session_type;
  clib_memcpy_fast (cmp->options, session->options, sizeof (cmp->options));
  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & cmp);
}

void
vppcom_send_disconnect_session (u64 vpp_handle)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vl_api_disconnect_session_t *dmp;

  dmp = vl_msg_api_alloc (sizeof (*dmp));
  memset (dmp, 0, sizeof (*dmp));
  dmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION);
  dmp->client_index = wrk->my_client_index;
  dmp->handle = vpp_handle;
  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & dmp);
}

/* VPP combines bind and listen as one operation. VCL manages the separation
 * of bind and listen locally via vppcom_session_bind() and
 * vppcom_session_listen() */
void
vppcom_send_bind_sock (vcl_session_t * session)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vl_api_bind_sock_t *bmp;

  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_BIND_SOCK);
  bmp->client_index = wrk->my_client_index;
  bmp->context = session->session_index;
  bmp->wrk_index = wrk->vpp_wrk_index;
  bmp->is_ip4 = session->transport.is_ip4;
  clib_memcpy_fast (bmp->ip, &session->transport.lcl_ip, sizeof (bmp->ip));
  bmp->port = session->transport.lcl_port;
  bmp->proto = session->session_type;
  clib_memcpy_fast (bmp->options, session->options, sizeof (bmp->options));
  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & bmp);
}

void
vppcom_send_unbind_sock (u64 vpp_handle)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vl_api_unbind_sock_t *ump;

  ump = vl_msg_api_alloc (sizeof (*ump));
  memset (ump, 0, sizeof (*ump));

  ump->_vl_msg_id = ntohs (VL_API_UNBIND_SOCK);
  ump->client_index = wrk->my_client_index;
  ump->wrk_index = wrk->vpp_wrk_index;
  ump->handle = vpp_handle;
  vl_msg_api_send_shmem (wrk->vl_input_queue, (u8 *) & ump);
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

      if (vl_socket_client_init_shm (0))
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
