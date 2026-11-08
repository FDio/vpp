/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <vlib/unix/plugin.h>
#include <vppinfra/unix.h>
#include <hsi/hsi.h>

#define PROXY_LITE_MSS 1460

typedef __typeof__ (hsi_track_pair) *proxy_lite_hsi_track_pair_fn;

typedef enum proxy_lite_session_state_
{
  PROXY_LITE_S_CONNECTING,
  PROXY_LITE_S_PROXYING,
  PROXY_LITE_S_HSI_DONE,
  PROXY_LITE_S_CLOSING,
} proxy_lite_session_state_t;

typedef struct proxy_lite_side_ctx_
{
  session_handle_t peer_handle;
  u32 ps_index;
  u32 ctx_index;
  u8 is_active_open;
} proxy_lite_side_ctx_t;

typedef struct proxy_lite_session_
{
  session_handle_t po_handle;
  session_handle_t ao_handle;
  svm_fifo_t *po_rx_fifo;
  svm_fifo_t *po_tx_fifo;
  u32 po_ctx_index;
  u32 ao_ctx_index;
  clib_thread_index_t po_thread_index;
  clib_thread_index_t ao_thread_index;
  proxy_lite_session_state_t state;
  u8 hsi_offload;
  u8 hsi_tracked;
  u8 po_deleted;
  u8 ao_deleted;
  /** Connect pending, session layer still uses the ps index as opaque */
  u8 ao_connecting;
  /** Active open handed its fifo references to the fifo owner thread */
  u8 ao_fifos_release_pending;
} proxy_lite_session_t;

typedef struct proxy_lite_worker_
{
  proxy_lite_side_ctx_t *ctx_pool;
} proxy_lite_worker_t;

typedef struct proxy_lite_main_
{
  proxy_lite_worker_t *workers;
  proxy_lite_session_t *sessions;
  clib_spinlock_t sessions_lock;

  u32 server_app_index;
  u32 active_open_app_index;
  u32 server_client_index;
  u32 active_open_client_index;
  session_handle_t listener_handle;

  session_endpoint_cfg_t server_sep;
  session_endpoint_cfg_t client_sep;
  u64 fifo_size;
  u64 segment_size;
  u8 hsi_offload;
  u8 hsi_offload_stall;
  u8 started;

  proxy_lite_hsi_track_pair_fn hsi_track_pair;

  u64 accepted;
  u64 connected;
  u64 proxied;
  u64 hsi_tracked;
  u64 hsi_failed;
  u64 hsi_cleanups;
  u64 closed;
  u64 reset;
} proxy_lite_main_t;

static proxy_lite_main_t proxy_lite_main = {
  .server_app_index = APP_INVALID_INDEX,
  .active_open_app_index = APP_INVALID_INDEX,
  .server_client_index = ~0,
  .active_open_client_index = ~0,
  .listener_handle = SESSION_INVALID_HANDLE,
  .fifo_size = 64 << 10,
  .segment_size = 512 << 20,
};

static_always_inline proxy_lite_worker_t *
proxy_lite_worker_get (clib_thread_index_t thread_index)
{
  return vec_elt_at_index (proxy_lite_main.workers, thread_index);
}

/*
 * Session opaque packs the thread that owns the side ctx with the ctx index, so
 * ctx can be found for sessions hsi migrated to other threads. Ctx pools are
 * only reallocated with workers stopped, so ctx can be read from any thread.
 */
#define PROXY_LITE_CTX_INDEX_BITS  24
#define PROXY_LITE_CTX_MAX_THREADS (1 << (32 - PROXY_LITE_CTX_INDEX_BITS))

static proxy_lite_side_ctx_t *
proxy_lite_side_ctx_alloc (clib_thread_index_t thread_index)
{
  proxy_lite_worker_t *wrk = proxy_lite_worker_get (thread_index);
  proxy_lite_side_ctx_t *ctx;

  pool_get_aligned_safe (wrk->ctx_pool, ctx, 0);
  clib_memset (ctx, 0, sizeof (*ctx));
  ctx->ctx_index = ctx - wrk->ctx_pool;
  ASSERT (ctx->ctx_index < (1 << PROXY_LITE_CTX_INDEX_BITS));
  return ctx;
}

static_always_inline u32
proxy_lite_side_ctx_opaque (clib_thread_index_t thread_index, proxy_lite_side_ctx_t *ctx)
{
  return ((u32) thread_index << PROXY_LITE_CTX_INDEX_BITS) | ctx->ctx_index;
}

static_always_inline clib_thread_index_t
proxy_lite_side_ctx_opaque_thread (u32 opaque)
{
  return opaque >> PROXY_LITE_CTX_INDEX_BITS;
}

static_always_inline u32
proxy_lite_side_ctx_opaque_index (u32 opaque)
{
  return opaque & ((1 << PROXY_LITE_CTX_INDEX_BITS) - 1);
}

static void
proxy_lite_side_ctx_free (clib_thread_index_t thread_index, u32 ctx_index)
{
  proxy_lite_worker_t *wrk = proxy_lite_worker_get (thread_index);

  if (ctx_index != ~0)
    pool_put_index (wrk->ctx_pool, ctx_index);
}

static void
proxy_lite_side_ctx_free_rpc (void *arg)
{
  proxy_lite_side_ctx_free (vlib_get_thread_index (), pointer_to_uword (arg));
}

static void
proxy_lite_side_ctx_free_on_thread (clib_thread_index_t thread_index, u32 ctx_index)
{
  if (ctx_index == ~0)
    return;

  if (thread_index == vlib_get_thread_index ())
    proxy_lite_side_ctx_free (thread_index, ctx_index);
  else
    session_send_rpc_evt_to_thread (thread_index, proxy_lite_side_ctx_free_rpc,
				    uword_to_pointer (ctx_index, void *));
}

static_always_inline proxy_lite_side_ctx_t *
proxy_lite_side_ctx_get (u32 opaque)
{
  proxy_lite_worker_t *wrk = proxy_lite_worker_get (proxy_lite_side_ctx_opaque_thread (opaque));

  /* No pool_elt_at_index, free bitmap might be updated by owner thread */
  return wrk->ctx_pool + proxy_lite_side_ctx_opaque_index (opaque);
}

static proxy_lite_session_t *
proxy_lite_session_alloc (void)
{
  proxy_lite_main_t *pm = &proxy_lite_main;
  proxy_lite_session_t *ps;

  ASSERT (!pm->sessions_lock || CLIB_SPINLOCK_IS_LOCKED (&pm->sessions_lock));

  pool_get_zero (pm->sessions, ps);
  ps->po_handle = SESSION_INVALID_HANDLE;
  ps->ao_handle = SESSION_INVALID_HANDLE;
  ps->po_ctx_index = ~0;
  ps->ao_ctx_index = ~0;
  ps->po_thread_index = ~0;
  ps->ao_thread_index = ~0;
  ps->state = PROXY_LITE_S_CONNECTING;
  return ps;
}

static_always_inline proxy_lite_session_t *
proxy_lite_session_get (u32 ps_index)
{
  return pool_elt_at_index (proxy_lite_main.sessions, ps_index);
}

static void
proxy_lite_session_free (proxy_lite_session_t *ps)
{
  ASSERT (!proxy_lite_main.sessions_lock ||
	  CLIB_SPINLOCK_IS_LOCKED (&proxy_lite_main.sessions_lock));
  pool_put (proxy_lite_main.sessions, ps);
}

static u8
proxy_lite_hsi_symbols_init (void)
{
  proxy_lite_main_t *pm = &proxy_lite_main;

  if (pm->hsi_track_pair)
    return 1;

  pm->hsi_track_pair = vlib_get_plugin_symbol ("hsi_plugin.so", "hsi_track_pair");

  return pm->hsi_track_pair != 0;
}

static void
proxy_lite_session_disconnect_rpc (void *arg)
{
  session_handle_tu_t sh = { .handle = pointer_to_uword (arg) };
  vnet_disconnect_args_t a = { .handle = sh.handle };
  app_worker_t *app_wrk;
  session_t *s;

  /* Session might be gone or handed off to hsi */
  s = session_get_from_handle_if_valid (sh);
  if (!s || !(app_wrk = app_worker_get_if_valid (s->app_wrk_index)))
    return;

  a.app_index = app_wrk->app_index;
  vnet_disconnect_session (&a);
}

/* Disconnect from the thread that owns the session */
static void
proxy_lite_session_disconnect (session_handle_t handle)
{
  session_handle_tu_t sh = { .handle = handle };
  void *arg = uword_to_pointer (handle, void *);

  if (sh.thread_index == vlib_get_thread_index ())
    proxy_lite_session_disconnect_rpc (arg);
  else
    session_send_rpc_evt_to_thread (sh.thread_index, proxy_lite_session_disconnect_rpc, arg);
}

static void
proxy_lite_session_close_pair (proxy_lite_session_t *ps)
{
  if (ps->po_handle != SESSION_INVALID_HANDLE && !ps->po_deleted)
    {
      proxy_lite_session_disconnect (ps->po_handle);
      ps->po_deleted = 1;
    }

  if (ps->ao_handle != SESSION_INVALID_HANDLE && !ps->ao_deleted)
    {
      proxy_lite_session_disconnect (ps->ao_handle);
      ps->ao_deleted = 1;
    }
}

static void
proxy_lite_maybe_free_closed_session (proxy_lite_session_t *ps)
{
  if (ps->po_handle != SESSION_INVALID_HANDLE || ps->ao_handle != SESSION_INVALID_HANDLE ||
      ps->ao_connecting || ps->ao_fifos_release_pending)
    return;

  proxy_lite_session_free (ps);
}

static int
proxy_lite_forward_rx (session_t *s)
{
  proxy_lite_main_t *pm = &proxy_lite_main;
  proxy_lite_side_ctx_t *ctx;
  session_handle_t peer_handle;
  proxy_lite_session_t *ps;
  proxy_lite_session_state_t state;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  ctx = proxy_lite_side_ctx_get (s->opaque);

  clib_spinlock_lock_if_init (&pm->sessions_lock);
  ps = proxy_lite_session_get (ctx->ps_index);
  state = ps->state;
  peer_handle = ctx->peer_handle;
  if (peer_handle == SESSION_INVALID_HANDLE && state == PROXY_LITE_S_PROXYING)
    {
      peer_handle = ctx->is_active_open ? ps->po_handle : ps->ao_handle;
      ctx->peer_handle = peer_handle;
    }
  clib_spinlock_unlock_if_init (&pm->sessions_lock);

  if (state == PROXY_LITE_S_HSI_DONE || state == PROXY_LITE_S_CLOSING)
    return 0;

  if (peer_handle == SESSION_INVALID_HANDLE)
    return 0;

  if (svm_fifo_max_dequeue (s->rx_fifo))
    {
      if (svm_fifo_set_event (s->rx_fifo))
	session_program_tx_io_evt (peer_handle, SESSION_IO_EVT_TX);
    }

  if (svm_fifo_max_enqueue (s->rx_fifo) <= PROXY_LITE_MSS)
    svm_fifo_add_want_deq_ntf (s->rx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);

  return 0;
}

static int
proxy_lite_tx_callback (session_t *s)
{
  proxy_lite_main_t *pm = &proxy_lite_main;
  proxy_lite_side_ctx_t *ctx;
  u8 offloaded;

  ctx = proxy_lite_side_ctx_get (s->opaque);
  clib_spinlock_lock_if_init (&pm->sessions_lock);
  offloaded = proxy_lite_session_get (ctx->ps_index)->state == PROXY_LITE_S_HSI_DONE;
  clib_spinlock_unlock_if_init (&pm->sessions_lock);
  if (offloaded)
    return 0;

  if (svm_fifo_max_enqueue (s->tx_fifo) < clib_min (svm_fifo_size (s->tx_fifo) >> 3, 128 << 10))
    svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);

  return 0;
}

static int
proxy_lite_start_hsi_offload (session_t *s, session_handle_t peer_handle, u32 ps_index)
{
  proxy_lite_main_t *pm = &proxy_lite_main;
  hsi_track_args_t args = {
    .s = s,
    .peer_session_handle = peer_handle,
    /* Session state is freed once hsi reports the sessions cleaned up */
    .flags = HSI_TRACK_F_NOTIFY_CLEANUP,
  };
  proxy_lite_session_t *ps;
  session_handle_tu_t sh = { .handle = peer_handle };
  session_t *peer_s;
  u8 closing;

  peer_s = session_get_from_handle_safe (sh);
  if (!peer_s)
    goto fail;

  if (pm->hsi_offload_stall)
    {
      /* Leave the event bits set without queueing TX events. This is fault
       * injection for the drain timeout and overflow tests. */
      (void) svm_fifo_set_event (s->tx_fifo);
      (void) svm_fifo_set_event (peer_s->tx_fifo);
    }
  if (pm->hsi_track_pair (&args))
    goto fail;

  /* Sessions are hsi's now and it frees their fifos, so stop touching them,
   * including on events queued before hsi took them, and wait for cleanups */
  clib_spinlock_lock_if_init (&pm->sessions_lock);
  ps = proxy_lite_session_get (ps_index);
  ps->hsi_tracked = 1;
  ps->state = PROXY_LITE_S_HSI_DONE;
  pm->hsi_tracked++;
  clib_spinlock_unlock_if_init (&pm->sessions_lock);

  return 0;

fail:
  clib_spinlock_lock_if_init (&pm->sessions_lock);
  ps = proxy_lite_session_get (ps_index);
  closing = ps->state == PROXY_LITE_S_CLOSING;
  if (!closing)
    ps->state = PROXY_LITE_S_PROXYING;
  pm->hsi_failed++;
  pm->proxied++;
  clib_spinlock_unlock_if_init (&pm->sessions_lock);

  /* Not tracked, so proxy data already in fifos */
  if (!closing)
    {
      (void) svm_fifo_set_event (s->tx_fifo);
      session_program_tx_io_evt (session_handle (s), SESSION_IO_EVT_TX);
      session_program_tx_io_evt (peer_handle, SESSION_IO_EVT_TX);
    }
  return -1;
}

static int
proxy_lite_start_connect (u32 ps_index)
{
  proxy_lite_main_t *pm = &proxy_lite_main;
  vnet_connect_args_t _a = {}, *a = &_a;

  clib_memcpy (&a->sep_ext, &pm->client_sep, sizeof (pm->client_sep));
  a->api_context = ps_index;
  a->app_index = pm->active_open_app_index;

  return vnet_connect2 (a);
}

static int
proxy_lite_accept_callback (session_t *s)
{
  proxy_lite_main_t *pm = &proxy_lite_main;
  proxy_lite_side_ctx_t *ctx;
  proxy_lite_session_t *ps;
  transport_proto_t proto;
  u32 ps_index;

  proto = session_get_transport_proto (s);
  if (proto != TRANSPORT_PROTO_TCP && proto != TRANSPORT_PROTO_UDP)
    return -1;

  ctx = proxy_lite_side_ctx_alloc (s->thread_index);

  clib_spinlock_lock_if_init (&pm->sessions_lock);
  ps = proxy_lite_session_alloc ();
  ps_index = ps - pm->sessions;
  ps->po_handle = session_handle (s);
  ps->po_rx_fifo = s->rx_fifo;
  ps->po_tx_fifo = s->tx_fifo;
  ps->po_ctx_index = ctx->ctx_index;
  ps->po_thread_index = s->thread_index;
  ps->hsi_offload = pm->hsi_offload;
  ps->ao_connecting = 1;
  ctx->ps_index = ps_index;
  ctx->peer_handle = SESSION_INVALID_HANDLE;
  pm->accepted++;
  clib_spinlock_unlock_if_init (&pm->sessions_lock);

  s->opaque = proxy_lite_side_ctx_opaque (s->thread_index, ctx);
  s->session_state = SESSION_STATE_READY;

  if (proxy_lite_start_connect (ps_index))
    {
      clib_spinlock_lock_if_init (&pm->sessions_lock);
      ps = proxy_lite_session_get (ps_index);
      ps->ao_connecting = 0;
      ps->state = PROXY_LITE_S_CLOSING;
      proxy_lite_session_close_pair (ps);
      clib_spinlock_unlock_if_init (&pm->sessions_lock);
    }

  return 0;
}

static void
proxy_lite_disconnect_callback (session_t *s)
{
  proxy_lite_main_t *pm = &proxy_lite_main;
  proxy_lite_side_ctx_t *ctx;
  proxy_lite_session_t *ps;

  ctx = proxy_lite_side_ctx_get (s->opaque);

  clib_spinlock_lock_if_init (&pm->sessions_lock);
  ps = proxy_lite_session_get (ctx->ps_index);
  /* Hsi closes offloaded sessions */
  if (ps->state == PROXY_LITE_S_HSI_DONE)
    {
      clib_spinlock_unlock_if_init (&pm->sessions_lock);
      return;
    }
  ps->state = PROXY_LITE_S_CLOSING;
  proxy_lite_session_close_pair (ps);
  pm->closed++;
  clib_spinlock_unlock_if_init (&pm->sessions_lock);
}

static void
proxy_lite_reset_callback (session_t *s)
{
  proxy_lite_main_t *pm = &proxy_lite_main;
  proxy_lite_side_ctx_t *ctx;
  proxy_lite_session_t *ps;

  ctx = proxy_lite_side_ctx_get (s->opaque);

  clib_spinlock_lock_if_init (&pm->sessions_lock);
  ps = proxy_lite_session_get (ctx->ps_index);
  /* Hsi closes offloaded sessions */
  if (ps->state == PROXY_LITE_S_HSI_DONE)
    {
      clib_spinlock_unlock_if_init (&pm->sessions_lock);
      return;
    }
  ps->state = PROXY_LITE_S_CLOSING;
  proxy_lite_session_close_pair (ps);
  pm->reset++;
  clib_spinlock_unlock_if_init (&pm->sessions_lock);
}

static void
proxy_lite_ao_fifos_release_rpc (void *arg)
{
  proxy_lite_main_t *pm = &proxy_lite_main;
  proxy_lite_session_t *ps;

  clib_spinlock_lock_if_init (&pm->sessions_lock);
  ps = proxy_lite_session_get (pointer_to_uword (arg));
  segment_manager_dealloc_fifos (ps->po_rx_fifo, ps->po_tx_fifo);
  ps->ao_fifos_release_pending = 0;
  proxy_lite_maybe_free_closed_session (ps);
  clib_spinlock_unlock_if_init (&pm->sessions_lock);
}

static void
proxy_lite_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  proxy_lite_main_t *pm = &proxy_lite_main;
  clib_thread_index_t fifos_thread = ~0;
  proxy_lite_side_ctx_t *ctx;
  proxy_lite_session_t *ps;
  u32 ps_index;

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  /* Ctx might belong to another thread if hsi migrated the session */
  ctx = proxy_lite_side_ctx_get (s->opaque);
  ps_index = ctx->ps_index;
  u8 is_active_open = ctx->is_active_open;
  proxy_lite_side_ctx_free_on_thread (proxy_lite_side_ctx_opaque_thread (s->opaque),
				      ctx->ctx_index);

  clib_spinlock_lock_if_init (&pm->sessions_lock);
  ps = proxy_lite_session_get (ps_index);
  if (ps->hsi_tracked)
    pm->hsi_cleanups++;
  if (is_active_open)
    {
      ps->ao_handle = SESSION_INVALID_HANDLE;
      ps->ao_ctx_index = ~0;
      /* Fifos are shared with the passive open and only the thread that
       * allocated them can free them. Instead of letting session layer
       * release our references here, hand them over to that thread */
      if (s->rx_fifo && segment_manager_fifo_alloc_thread (s->rx_fifo) != s->thread_index)
	{
	  fifos_thread = segment_manager_fifo_alloc_thread (s->rx_fifo);
	  s->rx_fifo = 0;
	  s->tx_fifo = 0;
	  ps->ao_fifos_release_pending = 1;
	}
    }
  else
    {
      ps->po_handle = SESSION_INVALID_HANDLE;
      ps->po_ctx_index = ~0;
    }
  proxy_lite_maybe_free_closed_session (ps);
  clib_spinlock_unlock_if_init (&pm->sessions_lock);

  if (fifos_thread != (clib_thread_index_t) ~0)
    session_send_rpc_evt_to_thread (fifos_thread, proxy_lite_ao_fifos_release_rpc,
				    uword_to_pointer (ps_index, void *));
}

static int
proxy_lite_add_segment_callback (u32 app_wrk_index, u64 segment_handle)
{
  return 0;
}

static int
proxy_lite_del_segment_callback (u32 app_wrk_index, u64 segment_handle)
{
  return 0;
}

static session_cb_vft_t proxy_lite_server_cb_vft = {
  .session_accept_callback = proxy_lite_accept_callback,
  .session_disconnect_callback = proxy_lite_disconnect_callback,
  .session_reset_callback = proxy_lite_reset_callback,
  .session_cleanup_callback = proxy_lite_cleanup_callback,
  .add_segment_callback = proxy_lite_add_segment_callback,
  .del_segment_callback = proxy_lite_del_segment_callback,
  .builtin_app_rx_callback = proxy_lite_forward_rx,
  .builtin_app_tx_callback = proxy_lite_tx_callback,
};

static int
proxy_lite_active_open_alloc_session_fifos (session_t *s)
{
  proxy_lite_main_t *pm = &proxy_lite_main;
  proxy_lite_session_t *ps;
  svm_fifo_t *rxf, *txf;

  clib_spinlock_lock_if_init (&pm->sessions_lock);
  ps = proxy_lite_session_get (s->opaque);
  if (ps->state == PROXY_LITE_S_CLOSING)
    {
      clib_spinlock_unlock_if_init (&pm->sessions_lock);
      return SESSION_E_ALLOC;
    }

  txf = ps->po_rx_fifo;
  rxf = ps->po_tx_fifo;
  txf->vpp_sh = s->handle;
  rxf->refcnt++;
  txf->refcnt++;
  clib_spinlock_unlock_if_init (&pm->sessions_lock);

  s->rx_fifo = rxf;
  s->tx_fifo = txf;

  return 0;
}

static int
proxy_lite_active_open_connected_callback (u32 app_index, u32 opaque, session_t *s,
					   session_error_t err)
{
  proxy_lite_main_t *pm = &proxy_lite_main;
  proxy_lite_side_ctx_t *ao_ctx = 0;
  proxy_lite_session_t *ps;
  session_handle_t po_handle;
  u32 ps_index;
  u8 hsi_offload;

  /* Alloc before taking the lock, growing the pool might sync workers */
  if (!err)
    ao_ctx = proxy_lite_side_ctx_alloc (s->thread_index);

  clib_spinlock_lock_if_init (&pm->sessions_lock);
  ps = proxy_lite_session_get (opaque);
  ps_index = opaque;
  ps->ao_connecting = 0;

  if (err || ps->state == PROXY_LITE_S_CLOSING)
    {
      ps->state = PROXY_LITE_S_CLOSING;
      proxy_lite_session_close_pair (ps);
      /* Passive open might've been cleaned up while connecting */
      proxy_lite_maybe_free_closed_session (ps);
      clib_spinlock_unlock_if_init (&pm->sessions_lock);
      if (ao_ctx)
	proxy_lite_side_ctx_free (s->thread_index, ao_ctx->ctx_index);
      /* Session layer detaches and closes the session */
      return -1;
    }

  ao_ctx->ps_index = opaque;
  ao_ctx->is_active_open = 1;
  ao_ctx->peer_handle = ps->po_handle;

  ps->ao_handle = session_handle (s);
  ps->ao_ctx_index = ao_ctx->ctx_index;
  ps->ao_thread_index = s->thread_index;
  po_handle = ps->po_handle;
  hsi_offload = ps->hsi_offload;

  s->opaque = proxy_lite_side_ctx_opaque (s->thread_index, ao_ctx);

  pm->connected++;
  if (!hsi_offload)
    {
      ps->state = PROXY_LITE_S_PROXYING;
      pm->proxied++;
    }

  clib_spinlock_unlock_if_init (&pm->sessions_lock);

  if (hsi_offload)
    {
      proxy_lite_start_hsi_offload (s, po_handle, ps_index);
      return 0;
    }

  if (svm_fifo_set_event (s->tx_fifo))
    session_program_tx_io_evt (session_handle (s), SESSION_IO_EVT_TX);

  if (po_handle != SESSION_INVALID_HANDLE)
    session_program_tx_io_evt (po_handle, SESSION_IO_EVT_TX);

  return 0;
}

static int
proxy_lite_active_open_create_callback (session_t *s)
{
  return 0;
}

static session_cb_vft_t proxy_lite_active_open_cb_vft = {
  .session_connected_callback = proxy_lite_active_open_connected_callback,
  .session_accept_callback = proxy_lite_active_open_create_callback,
  .session_disconnect_callback = proxy_lite_disconnect_callback,
  .session_reset_callback = proxy_lite_reset_callback,
  .session_cleanup_callback = proxy_lite_cleanup_callback,
  .add_segment_callback = proxy_lite_add_segment_callback,
  .del_segment_callback = proxy_lite_del_segment_callback,
  .builtin_app_rx_callback = proxy_lite_forward_rx,
  .builtin_app_tx_callback = proxy_lite_tx_callback,
  .proxy_alloc_session_fifos = proxy_lite_active_open_alloc_session_fifos,
};

static int
proxy_lite_attach (void)
{
  proxy_lite_main_t *pm = &proxy_lite_main;
  vnet_app_attach_args_t _a = {}, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];

  clib_memset (options, 0, sizeof (options));
  a->name = format (0, "proxy-lite-server");
  a->api_client_index = pm->server_client_index;
  a->session_cb_vft = &proxy_lite_server_cb_vft;
  a->options = options;
  options[APP_OPTIONS_SEGMENT_SIZE] = pm->segment_size;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = pm->segment_size;
  options[APP_OPTIONS_RX_FIFO_SIZE] = pm->fifo_size;
  options[APP_OPTIONS_TX_FIFO_SIZE] = pm->fifo_size;
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  if (vnet_application_attach (a))
    {
      vec_free (a->name);
      return -1;
    }
  pm->server_app_index = a->app_index;
  vec_free (a->name);

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));
  a->name = format (0, "proxy-lite-active-open");
  a->api_client_index = pm->active_open_client_index;
  a->session_cb_vft = &proxy_lite_active_open_cb_vft;
  a->options = options;
  options[APP_OPTIONS_SEGMENT_SIZE] = pm->segment_size;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = pm->segment_size;
  options[APP_OPTIONS_RX_FIFO_SIZE] = pm->fifo_size;
  options[APP_OPTIONS_TX_FIFO_SIZE] = pm->fifo_size;
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN | APP_OPTIONS_FLAGS_IS_PROXY;
  if (vnet_application_attach (a))
    {
      vec_free (a->name);
      return -1;
    }
  pm->active_open_app_index = a->app_index;
  vec_free (a->name);

  return 0;
}

static int
proxy_lite_start (vlib_main_t *vm)
{
  proxy_lite_main_t *pm = &proxy_lite_main;
  session_enable_disable_args_t args = {
    .is_en = 1,
    .rt_engine_type = RT_BACKEND_ENGINE_RULE_TABLE,
  };
  vnet_listen_args_t _a = {}, *a = &_a;
  vlib_thread_main_t *vtm;
  u32 n_threads;

  if (pm->hsi_offload && !proxy_lite_hsi_symbols_init ())
    return -1;

  if (!pm->started)
    {
      vnet_session_enable_disable (vm, &args);

      if (vlib_num_workers ())
	clib_spinlock_init (&pm->sessions_lock);

      vtm = vlib_get_thread_main ();
      n_threads = 1 + vtm->n_threads;
      if (n_threads > PROXY_LITE_CTX_MAX_THREADS)
	return -1;
      vec_validate (pm->workers, n_threads - 1);

      if (proxy_lite_attach ())
	return -1;

      pm->started = 1;
    }

  if (pm->listener_handle != SESSION_INVALID_HANDLE)
    return 0;

  a->app_index = pm->server_app_index;
  clib_memcpy (&a->sep_ext, &pm->server_sep, sizeof (pm->server_sep));
  a->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;
  if (vnet_listen (a))
    return -1;

  pm->listener_handle = a->handle;
  return 0;
}

static clib_error_t *
proxy_lite_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  proxy_lite_main_t *pm = &proxy_lite_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *server_uri = 0, *client_uri = 0;
  clib_error_t *error = 0;

  if (pm->started)
    return clib_error_return (0, "proxy-lite already started");

  pm->fifo_size = 64 << 10;
  pm->segment_size = 512 << 20;
  pm->hsi_offload = 0;
  pm->hsi_offload_stall = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected server-uri and client-uri");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "server-uri %s", &server_uri))
	vec_add1 (server_uri, 0);
      else if (unformat (line_input, "client-uri %s", &client_uri))
	vec_add1 (client_uri, 0);
      else if (unformat (line_input, "fifo-size %U", unformat_memory_size, &pm->fifo_size))
	;
      else if (unformat (line_input, "segment-size %U", unformat_memory_size, &pm->segment_size))
	;
      else if (unformat (line_input, "hsi-offload-stall"))
	{
	  pm->hsi_offload = 1;
	  pm->hsi_offload_stall = 1;
	}
      else if (unformat (line_input, "hsi-offload"))
	pm->hsi_offload = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'", format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!server_uri || !client_uri)
    {
      error = clib_error_return (0, "server-uri and client-uri are required");
      goto done;
    }

  if (parse_uri ((char *) server_uri, &pm->server_sep))
    {
      error = clib_error_return (0, "invalid server-uri %v", server_uri);
      goto done;
    }

  if (parse_uri ((char *) client_uri, &pm->client_sep))
    {
      error = clib_error_return (0, "invalid client-uri %v", client_uri);
      goto done;
    }

  if (pm->server_sep.transport_proto != pm->client_sep.transport_proto)
    {
      error = clib_error_return (0, "server-uri and client-uri protocol mismatch");
      goto done;
    }

  if (pm->server_sep.transport_proto != TRANSPORT_PROTO_TCP &&
      pm->server_sep.transport_proto != TRANSPORT_PROTO_UDP)
    {
      error = clib_error_return (0, "proxy-lite currently supports tcp and udp only");
      goto done;
    }

  if (proxy_lite_start (vm))
    error = pm->hsi_offload ?
	      clib_error_return (0, "failed to start proxy-lite; is hsi_plugin loaded?") :
	      clib_error_return (0, "failed to start proxy-lite");

done:
  unformat_free (line_input);
  vec_free (server_uri);
  vec_free (client_uri);
  return error;
}

VLIB_CLI_COMMAND (proxy_lite_command, static) = {
  .path = "proxy-lite",
  .short_help = "proxy-lite server-uri <tcp://ip:port|udp://ip:port> "
		"client-uri <tcp://ip:port|udp://ip:port> "
		"[fifo-size <n>[k|m]] [segment-size <n>[k|m]] "
		"[hsi-offload] [hsi-offload-stall]",
  .function = proxy_lite_command_fn,
};

static clib_error_t *
proxy_lite_show_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  proxy_lite_main_t *pm = &proxy_lite_main;

  vlib_cli_output (vm, "proxy-lite %s%s%s", pm->started ? "started" : "stopped",
		   pm->hsi_offload ? " hsi-offload" : "",
		   pm->hsi_offload_stall ? " hsi-offload-stall" : "");
  vlib_cli_output (vm, "accepted %lu connected %lu proxied %lu", pm->accepted, pm->connected,
		   pm->proxied);
  vlib_cli_output (vm, "hsi tracked %lu failed %lu", pm->hsi_tracked, pm->hsi_failed);
  vlib_cli_output (vm, "hsi cleanups %lu", pm->hsi_cleanups);
  vlib_cli_output (vm, "closed %lu reset %lu active-sessions %u", pm->closed, pm->reset,
		   pool_elts (pm->sessions));
  return 0;
}

VLIB_CLI_COMMAND (proxy_lite_show_command, static) = {
  .path = "show proxy-lite",
  .short_help = "show proxy-lite",
  .function = proxy_lite_show_command_fn,
};
