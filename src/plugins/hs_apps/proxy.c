/*
* Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <hs_apps/proxy.h>
#include <vnet/tcp/tcp.h>
#include <http/http.h>
#include <http/http_header_names.h>

proxy_main_t proxy_main;

#define TCP_MSS 1460

static proxy_session_side_ctx_t *
proxy_session_side_ctx_alloc (proxy_worker_t *wrk)
{
  proxy_session_side_ctx_t *ctx;

  pool_get_zero (wrk->ctx_pool, ctx);
  ctx->sc_index = ctx - wrk->ctx_pool;
  ctx->ps_index = ~0;

  return ctx;
}

static void
proxy_session_side_ctx_free (proxy_worker_t *wrk,
			     proxy_session_side_ctx_t *ctx)
{
  pool_put (wrk->ctx_pool, ctx);
}

static proxy_session_side_ctx_t *
proxy_session_side_ctx_get (proxy_worker_t *wrk, u32 ctx_index)
{
  return pool_elt_at_index (wrk->ctx_pool, ctx_index);
}

static void
proxy_send_http_resp (session_t *s, http_status_code_t sc,
		      http_header_t *resp_headers)
{
  http_msg_t msg;
  int rv;
  u8 *headers_buf = 0;

  if (vec_len (resp_headers))
    {
      headers_buf = http_serialize_headers (resp_headers);
      msg.data.len = msg.data.headers_len = vec_len (headers_buf);
    }
  else
    msg.data.len = msg.data.headers_len = 0;

  msg.type = HTTP_MSG_REPLY;
  msg.code = sc;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.headers_offset = 0;
  msg.data.body_len = 0;
  msg.data.body_offset = 0;
  rv = svm_fifo_enqueue (s->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));
  if (msg.data.headers_len)
    {
      rv = svm_fifo_enqueue (s->tx_fifo, vec_len (headers_buf), headers_buf);
      ASSERT (rv == vec_len (headers_buf));
      vec_free (headers_buf);
    }

  if (svm_fifo_set_event (s->tx_fifo))
    session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);
}

static void
proxy_do_connect (vnet_connect_args_t *a)
{
  ASSERT (session_vlib_thread_is_cl_thread ());
  vnet_connect (a);
  session_endpoint_free_ext_cfgs (&a->sep_ext);
}

static void
proxy_handle_connects_rpc (void *args)
{
  u32 thread_index = pointer_to_uword (args), n_connects = 0, n_pending;
  proxy_worker_t *wrk;
  u32 max_connects;

  wrk = proxy_worker_get (thread_index);

  clib_spinlock_lock (&wrk->pending_connects_lock);

  n_pending = clib_fifo_elts (wrk->pending_connects);
  max_connects = clib_min (32, n_pending);
  vec_validate (wrk->burst_connects, max_connects);

  while (n_connects < max_connects)
    clib_fifo_sub1 (wrk->pending_connects, wrk->burst_connects[n_connects++]);

  clib_spinlock_unlock (&wrk->pending_connects_lock);

  /* Do connects without locking pending_connects */
  n_connects = 0;
  while (n_connects < max_connects)
    {
      proxy_do_connect (&wrk->burst_connects[n_connects]);
      n_connects += 1;
    }

  /* More work to do, program rpc */
  if (max_connects < n_pending)
    session_send_rpc_evt_to_thread_force (
      transport_cl_thread (), proxy_handle_connects_rpc,
      uword_to_pointer ((uword) thread_index, void *));
}

static void
proxy_program_connect (vnet_connect_args_t *a)
{
  u32 connects_thread = transport_cl_thread (), thread_index, n_pending;
  proxy_worker_t *wrk;

  thread_index = vlib_get_thread_index ();

  /* If already on first worker, handle request */
  if (thread_index == connects_thread)
    {
      proxy_do_connect (a);
      return;
    }

  /* If not on first worker, queue request */
  wrk = proxy_worker_get (thread_index);

  clib_spinlock_lock (&wrk->pending_connects_lock);

  clib_fifo_add1 (wrk->pending_connects, *a);
  n_pending = clib_fifo_elts (wrk->pending_connects);

  clib_spinlock_unlock (&wrk->pending_connects_lock);

  if (n_pending == 1)
    session_send_rpc_evt_to_thread_force (
      connects_thread, proxy_handle_connects_rpc,
      uword_to_pointer ((uword) thread_index, void *));
}

static proxy_session_t *
proxy_session_alloc (void)
{
  proxy_main_t *pm = &proxy_main;
  proxy_session_t *ps;

  pool_get_zero (pm->sessions, ps);
  ps->ps_index = ps - pm->sessions;

  return ps;
}

static inline proxy_session_t *
proxy_session_get (u32 ps_index)
{
  proxy_main_t *pm = &proxy_main;

  return pool_elt_at_index (pm->sessions, ps_index);
}

static void
proxy_session_free (proxy_session_t *ps)
{
  proxy_main_t *pm = &proxy_main;

  if (CLIB_DEBUG > 0)
    clib_memset (ps, 0xFE, sizeof (*ps));
  pool_put (pm->sessions, ps);
}

static int
proxy_session_postponed_free_rpc (void *arg)
{
  uword ps_index = pointer_to_uword (arg);
  proxy_main_t *pm = &proxy_main;
  proxy_session_t *ps = 0;

  clib_spinlock_lock_if_init (&pm->sessions_lock);

  ps = proxy_session_get (ps_index);
  segment_manager_dealloc_fifos (ps->po.rx_fifo, ps->po.tx_fifo);
  proxy_session_free (ps);

  clib_spinlock_unlock_if_init (&pm->sessions_lock);

  return 0;
}

static void
proxy_session_postponed_free (proxy_session_t *ps)
{
  /* Passive open session handle has been invalidated so we don't have thread
   * index at this point */
  session_send_rpc_evt_to_thread (ps->po.rx_fifo->master_thread_index,
				  proxy_session_postponed_free_rpc,
				  uword_to_pointer (ps->ps_index, void *));
}

static void
proxy_session_close_po (proxy_session_t *ps)
{
  vnet_disconnect_args_t _a = {}, *a = &_a;
  proxy_main_t *pm = &proxy_main;

  ASSERT (!vlib_num_workers () ||
	  CLIB_SPINLOCK_IS_LOCKED (&pm->sessions_lock));

  a->handle = ps->po.session_handle;
  a->app_index = pm->server_app_index;
  vnet_disconnect_session (a);

  ps->po_disconnected = 1;
}

static void
proxy_session_close_ao (proxy_session_t *ps)
{
  vnet_disconnect_args_t _a = {}, *a = &_a;
  proxy_main_t *pm = &proxy_main;

  ASSERT (!vlib_num_workers () ||
	  CLIB_SPINLOCK_IS_LOCKED (&pm->sessions_lock));

  a->handle = ps->ao.session_handle;
  a->app_index = pm->active_open_app_index;
  vnet_disconnect_session (a);

  ps->ao_disconnected = 1;
}

static void
proxy_try_close_session (session_t * s, int is_active_open)
{
  proxy_main_t *pm = &proxy_main;
  proxy_session_side_ctx_t *sc;
  proxy_session_t *ps;
  proxy_worker_t *wrk;

  wrk = proxy_worker_get (s->thread_index);
  sc = proxy_session_side_ctx_get (wrk, s->opaque);

  clib_spinlock_lock_if_init (&pm->sessions_lock);

  ps = proxy_session_get (sc->ps_index);

  if (is_active_open)
    {
      proxy_session_close_ao (ps);

      if (!ps->po_disconnected)
	{
	  ASSERT (ps->po.session_handle != SESSION_INVALID_HANDLE);
	  proxy_session_close_po (ps);
	}
    }
  else
    {
      proxy_session_close_po (ps);

      if (!ps->ao_disconnected && !ps->active_open_establishing)
	{
	  /* Proxy session closed before active open */
	  if (ps->ao.session_handle != SESSION_INVALID_HANDLE)
	    proxy_session_close_ao (ps);
	  ps->ao_disconnected = 1;
	}
    }
  clib_spinlock_unlock_if_init (&pm->sessions_lock);
}

static void
proxy_try_side_ctx_cleanup (session_t *s)
{
  proxy_main_t *pm = &proxy_main;
  proxy_session_t *ps;
  proxy_session_side_ctx_t *sc;
  proxy_worker_t *wrk;

  wrk = proxy_worker_get (s->thread_index);
  sc = proxy_session_side_ctx_get (wrk, s->opaque);
  if (sc->state == PROXY_SC_S_CREATED)
    return;

  clib_spinlock_lock_if_init (&pm->sessions_lock);

  ps = proxy_session_get (sc->ps_index);

  if (!ps->po_disconnected)
    proxy_session_close_po (ps);

  if (!ps->ao_disconnected)
    proxy_session_close_ao (ps);

  clib_spinlock_unlock_if_init (&pm->sessions_lock);
}

static void
proxy_try_delete_session (session_t * s, u8 is_active_open)
{
  proxy_main_t *pm = &proxy_main;
  proxy_session_t *ps = 0;
  proxy_session_side_ctx_t *sc;
  proxy_worker_t *wrk;
  u32 ps_index;

  wrk = proxy_worker_get (s->thread_index);
  sc = proxy_session_side_ctx_get (wrk, s->opaque);
  ps_index = sc->ps_index;

  proxy_session_side_ctx_free (wrk, sc);

  clib_spinlock_lock_if_init (&pm->sessions_lock);

  ps = proxy_session_get (ps_index);

  if (is_active_open)
    {
      ps->ao.session_handle = SESSION_INVALID_HANDLE;

      /* Revert master thread index change on connect notification */
      ps->po.rx_fifo->master_thread_index =
	ps->po.tx_fifo->master_thread_index;

      /* Passive open already cleaned up */
      if (ps->po.session_handle == SESSION_INVALID_HANDLE)
	{
	  /* The two sides of the proxy on different threads */
	  if (ps->po.tx_fifo->master_thread_index != s->thread_index)
	    {
	      /* This is not the right thread to delete the fifos */
	      s->rx_fifo = 0;
	      s->tx_fifo = 0;
	      proxy_session_postponed_free (ps);
	    }
	  else
	    {
	      ASSERT (s->rx_fifo->refcnt == 1);
	      proxy_session_free (ps);
	    }
	}
    }
  else
    {
      ps->po.session_handle = SESSION_INVALID_HANDLE;

      if (ps->ao.session_handle == SESSION_INVALID_HANDLE)
	{
	  if (!ps->active_open_establishing)
	    proxy_session_free (ps);
	}
    }
  clib_spinlock_unlock_if_init (&pm->sessions_lock);
}

static int
common_fifo_tuning_callback (session_t * s, svm_fifo_t * f,
			     session_ft_action_t act, u32 bytes)
{
  proxy_main_t *pm = &proxy_main;

  segment_manager_t *sm = segment_manager_get (f->segment_manager);
  fifo_segment_t *fs = segment_manager_get_segment (sm, f->segment_index);

  u8 seg_usage = fifo_segment_get_mem_usage (fs);
  u32 fifo_in_use = svm_fifo_max_dequeue_prod (f);
  u32 fifo_size = svm_fifo_size (f);
  u8 fifo_usage = fifo_in_use * 100 / fifo_size;
  u8 update_size = 0;

  ASSERT (act < SESSION_FT_ACTION_N_ACTIONS);

  if (act == SESSION_FT_ACTION_ENQUEUED)
    {
      if (seg_usage < pm->low_watermark && fifo_usage > 50)
	update_size = fifo_in_use;
      else if (seg_usage < pm->high_watermark && fifo_usage > 80)
	update_size = fifo_in_use;

      update_size = clib_min (update_size, sm->max_fifo_size - fifo_size);
      if (update_size)
	svm_fifo_set_size (f, fifo_size + update_size);
    }
  else				/* dequeued */
    {
      if (seg_usage > pm->high_watermark || fifo_usage < 20)
	update_size = bytes;
      else if (seg_usage > pm->low_watermark && fifo_usage < 50)
	update_size = (bytes / 2);

      ASSERT (fifo_size >= 4096);
      update_size = clib_min (update_size, fifo_size - 4096);
      if (update_size)
	svm_fifo_set_size (f, fifo_size - update_size);
    }

  return 0;
}

static int
proxy_accept_callback (session_t * s)
{
  proxy_main_t *pm = &proxy_main;
  proxy_session_side_ctx_t *sc;
  proxy_session_t *ps;
  proxy_worker_t *wrk;
  transport_proto_t tp = session_get_transport_proto (s);

  wrk = proxy_worker_get (s->thread_index);
  sc = proxy_session_side_ctx_alloc (wrk);
  s->opaque = sc->sc_index;

  clib_spinlock_lock_if_init (&pm->sessions_lock);

  ps = proxy_session_alloc ();

  ps->po.session_handle = session_handle (s);
  ps->po.rx_fifo = s->rx_fifo;
  ps->po.tx_fifo = s->tx_fifo;

  ps->ao.session_handle = SESSION_INVALID_HANDLE;
  sc->ps_index = ps->ps_index;
  sc->is_http = tp == TRANSPORT_PROTO_HTTP ? 1 : 0;

  clib_spinlock_unlock_if_init (&pm->sessions_lock);

  s->session_state = SESSION_STATE_READY;

  return 0;
}

static void
proxy_disconnect_callback (session_t * s)
{
  proxy_try_close_session (s, 0 /* is_active_open */ );
}

static void
proxy_reset_callback (session_t * s)
{
  proxy_try_close_session (s, 0 /* is_active_open */ );
}

static int
proxy_connected_callback (u32 app_index, u32 api_context,
			  session_t * s, session_error_t err)
{
  clib_warning ("called...");
  return -1;
}

static int
proxy_add_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static int
proxy_transport_needs_crypto (transport_proto_t proto)
{
  return proto == TRANSPORT_PROTO_TLS;
}

static void
proxy_session_start_connect (proxy_session_side_ctx_t *sc, session_t *s)
{
  int actual_transfer __attribute__ ((unused));
  vnet_connect_args_t _a = {}, *a = &_a;
  proxy_main_t *pm = &proxy_main;
  u32 max_dequeue, ps_index;
  proxy_session_t *ps;
  transport_proto_t tp = session_get_transport_proto (s);

  clib_spinlock_lock_if_init (&pm->sessions_lock);

  ps = proxy_session_get (sc->ps_index);

  /* maybe we were already here */
  if (ps->active_open_establishing)
    {
      clib_spinlock_unlock_if_init (&pm->sessions_lock);
      return;
    }

  ps->active_open_establishing = 1;
  ps_index = ps->ps_index;

  clib_spinlock_unlock_if_init (&pm->sessions_lock);

  if (tp == TRANSPORT_PROTO_HTTP)
    {
      http_msg_t msg;
      u8 *target_buf = 0;
      http_uri_t target_uri;
      http_header_t *resp_headers = 0;
      session_endpoint_cfg_t target_sep = SESSION_ENDPOINT_CFG_NULL;
      int rv;

      rv = svm_fifo_dequeue (s->rx_fifo, sizeof (msg), (u8 *) &msg);
      ASSERT (rv == sizeof (msg));

      if (msg.type != HTTP_MSG_REQUEST)
	{
	  proxy_send_http_resp (s, HTTP_STATUS_INTERNAL_ERROR, 0);
	  return;
	}
      if (msg.method_type != HTTP_REQ_CONNECT)
	{
	  http_add_header (&resp_headers,
			   http_header_name_token (HTTP_HEADER_ALLOW),
			   http_token_lit ("CONNECT"));
	  proxy_send_http_resp (s, HTTP_STATUS_METHOD_NOT_ALLOWED,
				resp_headers);
	  vec_free (resp_headers);
	  return;
	}

      if (msg.data.target_form != HTTP_TARGET_AUTHORITY_FORM ||
	  msg.data.target_path_len == 0)
	{
	  proxy_send_http_resp (s, HTTP_STATUS_BAD_REQUEST, 0);
	  return;
	}

      /* read target uri */
      target_buf = vec_new (u8, msg.data.target_path_len);
      rv = svm_fifo_peek (s->rx_fifo, msg.data.target_path_offset,
			  msg.data.target_path_len, target_buf);
      ASSERT (rv == msg.data.target_path_len);
      svm_fifo_dequeue_drop (s->rx_fifo, msg.data.len);
      rv = http_parse_authority_form_target (target_buf, &target_uri);
      vec_free (target_buf);
      if (rv)
	{
	  proxy_send_http_resp (s, HTTP_STATUS_BAD_REQUEST, 0);
	  return;
	}
      target_sep.is_ip4 = target_uri.is_ip4;
      target_sep.ip = target_uri.ip;
      target_sep.port = target_uri.port;
      target_sep.transport_proto = TRANSPORT_PROTO_TCP;
      clib_memcpy (&a->sep_ext, &target_sep, sizeof (target_sep));
    }
  else
    {
      max_dequeue = svm_fifo_max_dequeue_cons (s->rx_fifo);
      if (PREDICT_FALSE (max_dequeue == 0))
	return;

      max_dequeue = clib_min (pm->rcv_buffer_size, max_dequeue);
      actual_transfer =
	svm_fifo_peek (s->rx_fifo, 0 /* relative_offset */, max_dequeue,
		       pm->rx_buf[s->thread_index]);

      /* Expectation is that here actual data just received is parsed and based
       * on its contents, the destination and parameters of the connect to the
       * upstream are decided
       */
      clib_memcpy (&a->sep_ext, &pm->client_sep[tp], sizeof (*pm->client_sep));
    }

  a->api_context = ps_index;
  a->app_index = pm->active_open_app_index;

  if (proxy_transport_needs_crypto (a->sep.transport_proto))
    {
      transport_endpt_ext_cfg_t *ext_cfg = session_endpoint_add_ext_cfg (
	&a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
	sizeof (transport_endpt_crypto_cfg_t));
      ext_cfg->crypto.ckpair_index = pm->ckpair_index;
    }

  proxy_program_connect (a);
}

static int
proxy_rx_callback (session_t *s)
{
  proxy_session_side_ctx_t *sc;
  svm_fifo_t *ao_tx_fifo;
  proxy_session_t *ps;
  proxy_worker_t *wrk;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  wrk = proxy_worker_get (s->thread_index);
  sc = proxy_session_side_ctx_get (wrk, s->opaque);

  if (PREDICT_FALSE (sc->state < PROXY_SC_S_ESTABLISHED))
    {
      proxy_main_t *pm = &proxy_main;

      if (sc->state == PROXY_SC_S_CREATED)
	{
	  proxy_session_start_connect (sc, s);
	  sc->state = PROXY_SC_S_CONNECTING;
	  return 0;
	}

      clib_spinlock_lock_if_init (&pm->sessions_lock);

      ps = proxy_session_get (sc->ps_index);
      sc->pair = ps->ao;

      clib_spinlock_unlock_if_init (&pm->sessions_lock);

      if (sc->pair.session_handle == SESSION_INVALID_HANDLE)
	return 0;

      sc->state = PROXY_SC_S_ESTABLISHED;
    }

  ao_tx_fifo = s->rx_fifo;

  /*
   * Send event for active open tx fifo
   */
  if (svm_fifo_set_event (ao_tx_fifo))
    session_program_tx_io_evt (sc->pair.session_handle, SESSION_IO_EVT_TX);

  if (svm_fifo_max_enqueue (ao_tx_fifo) <= TCP_MSS)
    svm_fifo_add_want_deq_ntf (ao_tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);

  return 0;
}

static void
proxy_force_ack (void *handlep)
{
  transport_connection_t *tc;
  session_t *s;

  s = session_get_from_handle (pointer_to_uword (handlep));
  if (session_get_transport_proto (s) != TRANSPORT_PROTO_TCP)
    return;
  tc = session_get_transport (s);
  tcp_send_ack ((tcp_connection_t *) tc);
}

static int
proxy_tx_callback (session_t * proxy_s)
{
  proxy_session_side_ctx_t *sc;
  proxy_worker_t *wrk;
  u32 min_free;

  min_free = clib_min (svm_fifo_size (proxy_s->tx_fifo) >> 3, 128 << 10);
  if (svm_fifo_max_enqueue (proxy_s->tx_fifo) < min_free)
    {
      svm_fifo_add_want_deq_ntf (proxy_s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  wrk = proxy_worker_get (proxy_s->thread_index);
  sc = proxy_session_side_ctx_get (wrk, proxy_s->opaque);
  if (sc->state < PROXY_SC_S_ESTABLISHED)
    return 0;

  /* Force ack on active open side to update rcv wnd. Make sure it's done on
   * the right thread */
  void *arg = uword_to_pointer (sc->pair.session_handle, void *);
  session_send_rpc_evt_to_thread (
    session_thread_from_handle (sc->pair.session_handle), proxy_force_ack,
    arg);

  return 0;
}

static void
proxy_cleanup_callback (session_t * s, session_cleanup_ntf_t ntf)
{
  if (ntf == SESSION_CLEANUP_TRANSPORT)
    {
      proxy_try_side_ctx_cleanup (s);
      return;
    }

  proxy_try_delete_session (s, 0 /* is_active_open */ );
}

static session_cb_vft_t proxy_session_cb_vft = {
  .session_accept_callback = proxy_accept_callback,
  .session_disconnect_callback = proxy_disconnect_callback,
  .session_connected_callback = proxy_connected_callback,
  .add_segment_callback = proxy_add_segment_callback,
  .builtin_app_rx_callback = proxy_rx_callback,
  .builtin_app_tx_callback = proxy_tx_callback,
  .session_reset_callback = proxy_reset_callback,
  .session_cleanup_callback = proxy_cleanup_callback,
  .fifo_tuning_callback = common_fifo_tuning_callback,
};

static int
active_open_alloc_session_fifos (session_t *s)
{
  proxy_main_t *pm = &proxy_main;
  svm_fifo_t *rxf, *txf;
  proxy_session_t *ps;

  clib_spinlock_lock_if_init (&pm->sessions_lock);

  /* Active open opaque is pointing at proxy session */
  ps = proxy_session_get (s->opaque);

  if (ps->po_disconnected)
    {
      clib_spinlock_unlock_if_init (&pm->sessions_lock);
      return SESSION_E_ALLOC;
    }

  txf = ps->po.rx_fifo;
  rxf = ps->po.tx_fifo;

  /*
   * Reset the active-open tx-fifo master indices so the active-open session
   * will receive data, etc.
   */
  txf->shr->master_session_index = s->session_index;
  txf->master_thread_index = s->thread_index;

  /*
   * Account for the active-open session's use of the fifos
   * so they won't disappear until the last session which uses
   * them disappears
   */
  rxf->refcnt++;
  txf->refcnt++;

  clib_spinlock_unlock_if_init (&pm->sessions_lock);

  s->rx_fifo = rxf;
  s->tx_fifo = txf;

  return 0;
}

static int
active_open_connected_callback (u32 app_index, u32 opaque,
				session_t * s, session_error_t err)
{
  proxy_main_t *pm = &proxy_main;
  proxy_session_t *ps;
  proxy_worker_t *wrk;
  proxy_session_side_ctx_t *sc;
  session_t *po_s;
  transport_proto_t tp;

  /* Connection failed */
  if (err)
    {
      clib_spinlock_lock_if_init (&pm->sessions_lock);

      ps = proxy_session_get (opaque);
      po_s = session_get_from_handle (ps->po.session_handle);
      tp = session_get_transport_proto (po_s);
      if (tp == TRANSPORT_PROTO_HTTP)
	{
	  proxy_send_http_resp (po_s, HTTP_STATUS_BAD_GATEWAY, 0);
	}
      ps->ao_disconnected = 1;
      proxy_session_close_po (ps);

      clib_spinlock_unlock_if_init (&pm->sessions_lock);

      return 0;
    }

  wrk = proxy_worker_get (s->thread_index);

  clib_spinlock_lock_if_init (&pm->sessions_lock);

  ps = proxy_session_get (opaque);

  ps->ao.rx_fifo = s->rx_fifo;
  ps->ao.tx_fifo = s->tx_fifo;
  ps->ao.session_handle = session_handle (s);

  ps->active_open_establishing = 0;

  /* Passive open session was already closed! */
  if (ps->po_disconnected)
    {
      /* Setup everything for the cleanup notification */
      ps->ao_disconnected = 1;
      clib_spinlock_unlock_if_init (&pm->sessions_lock);
      return -1;
    }

  po_s = session_get_from_handle (ps->po.session_handle);
  tp = session_get_transport_proto (po_s);

  sc = proxy_session_side_ctx_alloc (wrk);
  sc->pair = ps->po;
  sc->ps_index = ps->ps_index;

  clib_spinlock_unlock_if_init (&pm->sessions_lock);

  sc->state = PROXY_SC_S_ESTABLISHED;
  s->opaque = sc->sc_index;
  sc->is_http = tp == TRANSPORT_PROTO_HTTP ? 1 : 0;

  if (tp == TRANSPORT_PROTO_HTTP)
    {
      proxy_send_http_resp (po_s, HTTP_STATUS_OK, 0);
    }
  else
    {
      /*
       * Send event for active open tx fifo
       */
      ASSERT (s->thread_index == vlib_get_thread_index ());
      if (svm_fifo_set_event (s->tx_fifo))
	session_program_tx_io_evt (session_handle (s), SESSION_IO_EVT_TX);
    }

  return 0;
}

static void
active_open_migrate_po_fixup_rpc (void *arg)
{
  u32 ps_index = pointer_to_uword (arg);
  proxy_session_side_ctx_t *po_sc;
  proxy_main_t *pm = &proxy_main;
  session_handle_t po_sh;
  proxy_worker_t *wrk;
  proxy_session_t *ps;
  session_t *po_s;

  wrk = proxy_worker_get (vlib_get_thread_index ());

  clib_spinlock_lock_if_init (&pm->sessions_lock);

  ps = proxy_session_get (ps_index);

  po_s = session_get_from_handle (ps->po.session_handle);
  po_s->rx_fifo = ps->po.rx_fifo;
  po_s->tx_fifo = ps->po.tx_fifo;

  po_sc = proxy_session_side_ctx_get (wrk, po_s->opaque);
  po_sc->pair = ps->ao;
  po_sh = ps->po.session_handle;

  clib_spinlock_unlock_if_init (&pm->sessions_lock);

  session_program_tx_io_evt (po_sh, SESSION_IO_EVT_TX);
}

static void
active_open_migrate_rpc (void *arg)
{
  u32 ps_index = pointer_to_uword (arg);
  proxy_main_t *pm = &proxy_main;
  proxy_session_side_ctx_t *sc;
  proxy_worker_t *wrk;
  proxy_session_t *ps;
  session_t *s;

  wrk = proxy_worker_get (vlib_get_thread_index ());
  sc = proxy_session_side_ctx_alloc (wrk);

  clib_spinlock_lock_if_init (&pm->sessions_lock);

  ps = proxy_session_get (ps_index);
  sc->ps_index = ps->ps_index;

  s = session_get_from_handle (ps->ao.session_handle);
  s->opaque = sc->sc_index;
  s->flags &= ~SESSION_F_IS_MIGRATING;

  /* Fixup passive open session because of migration and zc */
  ps->ao.rx_fifo = ps->po.tx_fifo = s->rx_fifo;
  ps->ao.tx_fifo = ps->po.rx_fifo = s->tx_fifo;

  ps->po.tx_fifo->shr->master_session_index =
    session_index_from_handle (ps->po.session_handle);
  ps->po.tx_fifo->master_thread_index =
    session_thread_from_handle (ps->po.session_handle);

  sc->pair = ps->po;

  clib_spinlock_unlock_if_init (&pm->sessions_lock);

  session_send_rpc_evt_to_thread (
    session_thread_from_handle (sc->pair.session_handle),
    active_open_migrate_po_fixup_rpc, uword_to_pointer (sc->ps_index, void *));
}

static void
active_open_migrate_callback (session_t *s, session_handle_t new_sh)
{
  proxy_main_t *pm = &proxy_main;
  proxy_session_side_ctx_t *sc;
  proxy_session_t *ps;
  proxy_worker_t *wrk;

  wrk = proxy_worker_get (s->thread_index);
  sc = proxy_session_side_ctx_get (wrk, s->opaque);

  /* NOTE: this is just an example. ZC makes this migration rather
   * tedious. Probably better approaches could be found */
  clib_spinlock_lock_if_init (&pm->sessions_lock);

  ps = proxy_session_get (sc->ps_index);
  ps->ao.session_handle = new_sh;
  ps->ao.rx_fifo = 0;
  ps->ao.tx_fifo = 0;

  clib_spinlock_unlock_if_init (&pm->sessions_lock);

  session_send_rpc_evt_to_thread (session_thread_from_handle (new_sh),
				  active_open_migrate_rpc,
				  uword_to_pointer (sc->ps_index, void *));

  proxy_session_side_ctx_free (wrk, sc);
}

static void
active_open_reset_callback (session_t * s)
{
  proxy_try_close_session (s, 1 /* is_active_open */ );
}

static int
active_open_create_callback (session_t * s)
{
  return 0;
}

static void
active_open_disconnect_callback (session_t * s)
{
  proxy_try_close_session (s, 1 /* is_active_open */ );
}

static int
active_open_rx_callback (session_t * s)
{
  svm_fifo_t *proxy_tx_fifo;

  proxy_tx_fifo = s->rx_fifo;

  /*
   * Send event for server tx fifo
   */
  if (svm_fifo_set_event (proxy_tx_fifo))
    {
      u8 thread_index = proxy_tx_fifo->master_thread_index;
      u32 session_index = proxy_tx_fifo->shr->master_session_index;
      return session_send_io_evt_to_thread_custom (&session_index,
						   thread_index,
						   SESSION_IO_EVT_TX);
    }

  if (svm_fifo_max_enqueue (proxy_tx_fifo) <= TCP_MSS)
    svm_fifo_add_want_deq_ntf (proxy_tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);

  return 0;
}

static int
active_open_tx_callback (session_t * ao_s)
{
  proxy_session_side_ctx_t *sc;
  proxy_worker_t *wrk;
  u32 min_free;

  min_free = clib_min (svm_fifo_size (ao_s->tx_fifo) >> 3, 128 << 10);
  if (svm_fifo_max_enqueue (ao_s->tx_fifo) < min_free)
    {
      svm_fifo_add_want_deq_ntf (ao_s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  wrk = proxy_worker_get (ao_s->thread_index);
  sc = proxy_session_side_ctx_get (wrk, ao_s->opaque);

  if (sc->state < PROXY_SC_S_ESTABLISHED)
    return 0;

  if (sc->is_http)
    {
      /* notify HTTP transport */
      session_t *po = session_get_from_handle (sc->pair.session_handle);
      session_send_io_evt_to_thread_custom (
	&po->session_index, po->thread_index, SESSION_IO_EVT_RX);
    }
  else
    {
      /* Force ack on proxy side to update rcv wnd */
      void *arg = uword_to_pointer (sc->pair.session_handle, void *);
      session_send_rpc_evt_to_thread (
	session_thread_from_handle (sc->pair.session_handle), proxy_force_ack,
	arg);
    }

  return 0;
}

static void
active_open_cleanup_callback (session_t * s, session_cleanup_ntf_t ntf)
{
  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  proxy_try_delete_session (s, 1 /* is_active_open */ );
}

static session_cb_vft_t active_open_clients = {
  .session_reset_callback = active_open_reset_callback,
  .session_connected_callback = active_open_connected_callback,
  .session_migrate_callback = active_open_migrate_callback,
  .session_accept_callback = active_open_create_callback,
  .session_disconnect_callback = active_open_disconnect_callback,
  .session_cleanup_callback = active_open_cleanup_callback,
  .builtin_app_rx_callback = active_open_rx_callback,
  .builtin_app_tx_callback = active_open_tx_callback,
  .fifo_tuning_callback = common_fifo_tuning_callback,
  .proxy_alloc_session_fifos = active_open_alloc_session_fifos,
};

static int
proxy_server_attach ()
{
  proxy_main_t *pm = &proxy_main;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->name = format (0, "proxy-server");
  a->api_client_index = pm->server_client_index;
  a->session_cb_vft = &proxy_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = pm->segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = pm->segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = pm->fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = pm->fifo_size;
  a->options[APP_OPTIONS_MAX_FIFO_SIZE] = pm->max_fifo_size;
  a->options[APP_OPTIONS_HIGH_WATERMARK] = (u64) pm->high_watermark;
  a->options[APP_OPTIONS_LOW_WATERMARK] = (u64) pm->low_watermark;
  a->options[APP_OPTIONS_PRIVATE_SEGMENT_COUNT] = pm->private_segment_count;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] =
    pm->prealloc_fifos ? pm->prealloc_fifos : 0;

  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  pm->server_app_index = a->app_index;

  vec_free (a->name);
  return 0;
}

static int
active_open_attach (void)
{
  proxy_main_t *pm = &proxy_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = pm->active_open_client_index;
  a->session_cb_vft = &active_open_clients;
  a->name = format (0, "proxy-active-open");

  options[APP_OPTIONS_ACCEPT_COOKIE] = 0x12345678;
  options[APP_OPTIONS_SEGMENT_SIZE] = 512 << 20;
  options[APP_OPTIONS_RX_FIFO_SIZE] = pm->fifo_size;
  options[APP_OPTIONS_TX_FIFO_SIZE] = pm->fifo_size;
  options[APP_OPTIONS_MAX_FIFO_SIZE] = pm->max_fifo_size;
  options[APP_OPTIONS_HIGH_WATERMARK] = (u64) pm->high_watermark;
  options[APP_OPTIONS_LOW_WATERMARK] = (u64) pm->low_watermark;
  options[APP_OPTIONS_PRIVATE_SEGMENT_COUNT] = pm->private_segment_count;
  options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] =
    pm->prealloc_fifos ? pm->prealloc_fifos : 0;

  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN
    | APP_OPTIONS_FLAGS_IS_PROXY;

  a->options = options;

  if (vnet_application_attach (a))
    return -1;

  pm->active_open_app_index = a->app_index;

  vec_free (a->name);

  return 0;
}

static int
proxy_server_listen ()
{
  proxy_main_t *pm = &proxy_main;
  vnet_listen_args_t _a, *a = &_a;
  int rv, need_crypto;

  clib_memset (a, 0, sizeof (*a));

  a->app_index = pm->server_app_index;
  clib_memcpy (&a->sep_ext, &pm->server_sep, sizeof (pm->server_sep));
  /* Make sure listener is marked connected for transports like udp */
  a->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;
  need_crypto = proxy_transport_needs_crypto (a->sep.transport_proto);
  if (need_crypto)
    {
      transport_endpt_ext_cfg_t *ext_cfg = session_endpoint_add_ext_cfg (
	&a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
	sizeof (transport_endpt_crypto_cfg_t));
      ext_cfg->crypto.ckpair_index = pm->ckpair_index;
    }
  /* set http timeout for connect-proxy */
  if (pm->server_sep.transport_proto == TRANSPORT_PROTO_HTTP)
    {
      transport_endpt_ext_cfg_t *ext_cfg = session_endpoint_add_ext_cfg (
	&a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_HTTP, sizeof (ext_cfg->opaque));
      ext_cfg->opaque = pm->idle_timeout;
    }

  rv = vnet_listen (a);
  if (need_crypto)
    session_endpoint_free_ext_cfgs (&a->sep_ext);

  return rv;
}

static void
proxy_server_add_ckpair (void)
{
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  proxy_main_t *pm = &proxy_main;

  clib_memset (ck_pair, 0, sizeof (*ck_pair));
  ck_pair->cert = (u8 *) test_srv_crt_rsa;
  ck_pair->key = (u8 *) test_srv_key_rsa;
  ck_pair->cert_len = test_srv_crt_rsa_len;
  ck_pair->key_len = test_srv_key_rsa_len;
  vnet_app_add_cert_key_pair (ck_pair);

  pm->ckpair_index = ck_pair->index;
}

static int
proxy_server_create (vlib_main_t * vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  proxy_main_t *pm = &proxy_main;
  proxy_worker_t *wrk;
  u32 num_threads;
  int i;

  if (vlib_num_workers ())
    clib_spinlock_init (&pm->sessions_lock);

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (pm->rx_buf, num_threads - 1);

  for (i = 0; i < num_threads; i++)
    vec_validate (pm->rx_buf[i], pm->rcv_buffer_size);

  vec_validate (pm->workers, vlib_num_workers ());
  vec_foreach (wrk, pm->workers)
    {
      clib_spinlock_init (&wrk->pending_connects_lock);
    }

  proxy_server_add_ckpair ();

  if (proxy_server_attach ())
    {
      clib_warning ("failed to attach server app");
      return -1;
    }
  if (active_open_attach ())
    {
      clib_warning ("failed to attach active open app");
      return -1;
    }

  return 0;
}

static clib_error_t *
proxy_server_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  char *default_server_uri = "tcp://0.0.0.0/23";
  char *default_client_uri = "tcp://6.0.2.2/23";
  u8 *server_uri = 0, *client_uri = 0;
  proxy_main_t *pm = &proxy_main;
  clib_error_t *error = 0;
  int rv, tmp32;
  u64 tmp64;

  pm->fifo_size = 64 << 10;
  pm->max_fifo_size = 128 << 20;
  pm->high_watermark = 80;
  pm->low_watermark = 50;
  pm->rcv_buffer_size = 1024;
  pm->prealloc_fifos = 0;
  pm->private_segment_count = 0;
  pm->segment_size = 512 << 20;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "fifo-size %U", unformat_memory_size,
		    &pm->fifo_size))
	;
      else if (unformat (line_input, "max-fifo-size %U", unformat_memory_size,
			 &pm->max_fifo_size))
	;
      else if (unformat (line_input, "high-watermark %d", &tmp32))
	pm->high_watermark = (u8) tmp32;
      else if (unformat (line_input, "low-watermark %d", &tmp32))
	pm->low_watermark = (u8) tmp32;
      else if (unformat (line_input, "rcv-buf-size %d", &pm->rcv_buffer_size))
	;
      else if (unformat (line_input, "prealloc-fifos %d", &pm->prealloc_fifos))
	;
      else if (unformat (line_input, "private-segment-count %d",
			 &pm->private_segment_count))
	;
      else if (unformat (line_input, "private-segment-size %U",
			 unformat_memory_size, &tmp64))
	{
	  pm->segment_size = tmp64;
	}
      else if (unformat (line_input, "server-uri %s", &server_uri))
	vec_add1 (server_uri, 0);
      else if (unformat (line_input, "client-uri %s", &client_uri))
	vec_add1 (client_uri, 0);
      else if (unformat (line_input, "idle-timeout %d", &pm->idle_timeout))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!server_uri)
    {
      clib_warning ("No server-uri provided, Using default: %s",
		    default_server_uri);
      server_uri = format (0, "%s%c", default_server_uri, 0);
    }
  if (parse_uri ((char *) server_uri, &pm->server_sep))
    {
      error = clib_error_return (0, "Invalid server uri %v", server_uri);
      goto done;
    }

  /* http proxy get target within request */
  if (pm->server_sep.transport_proto != TRANSPORT_PROTO_HTTP)
    {
      if (!client_uri)
	{
	  clib_warning ("No client-uri provided, Using default: %s",
			default_client_uri);
	  client_uri = format (0, "%s%c", default_client_uri, 0);
	}
      if (parse_uri ((char *) client_uri,
		     &pm->client_sep[pm->server_sep.transport_proto]))
	{
	  error = clib_error_return (0, "Invalid client uri %v", client_uri);
	  goto done;
	}
    }

  if (pm->server_app_index == APP_INVALID_INDEX)
    {
      session_enable_disable_args_t args = { .is_en = 1,
					     .rt_engine_type =
					       RT_BACKEND_ENGINE_RULE_TABLE };
      vnet_session_enable_disable (vm, &args);
      rv = proxy_server_create (vm);
      if (rv)
	{
	  error = clib_error_return (0, "server_create returned %d", rv);
	  goto done;
	}
    }

  if (proxy_server_listen ())
    error = clib_error_return (0, "failed to start listening");

done:
  unformat_free (line_input);
  vec_free (client_uri);
  vec_free (server_uri);
  return error;
}

VLIB_CLI_COMMAND (proxy_create_command, static) = {
  .path = "test proxy server",
  .short_help = "test proxy server [server-uri <proto://ip/port>]"
		"[client-uri <tcp://ip/port>][fifo-size <nn>[k|m]]"
		"[max-fifo-size <nn>[k|m]][high-watermark <nn>]"
		"[low-watermark <nn>][rcv-buf-size <nn>][prealloc-fifos <nn>]"
		"[private-segment-size <mem>][private-segment-count <nn>]"
		"[idle-timeout <nn>]",
  .function = proxy_server_create_command_fn,
};

clib_error_t *
proxy_main_init (vlib_main_t * vm)
{
  proxy_main_t *pm = &proxy_main;
  pm->server_client_index = ~0;
  pm->active_open_client_index = ~0;
  pm->server_app_index = APP_INVALID_INDEX;
  pm->idle_timeout = 600; /* connect-proxy default idle timeout 10 minutes */
  vec_validate (pm->client_sep, TRANSPORT_N_PROTOS - 1);

  return 0;
}

VLIB_INIT_FUNCTION (proxy_main_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
