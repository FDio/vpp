/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <sys/socket.h>

#include <vnet/session/application.h>
#include <vnet/session/transport.h>
#include <vnet/session/session.h>
#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>

#include <vppinfra/lock.h>

#include <quic/quic.h>

#include <quicly/streambuf.h>
#include <picotls/openssl.h>

static quic_main_t quic_main;

static void quic_update_timer (quic_ctx_t *ctx);

u32
quic_ctx_half_open_alloc (void)
{
  quic_main_t *qm = &quic_main;
  u8 will_expand = 0;
  quic_ctx_t *ctx;
  u32 ctx_index;

  pool_get_aligned_will_expand (qm->half_open_ctx_pool, will_expand, 0);
  if (PREDICT_FALSE (will_expand && vlib_num_workers ()))
    {
      clib_rwlock_writer_lock (&qm->half_open_rwlock);
      pool_get (qm->half_open_ctx_pool, ctx);
      ctx_index = ctx - qm->half_open_ctx_pool;
      clib_rwlock_writer_unlock (&qm->half_open_rwlock);
    }
  else
    {
      /* reader lock assumption: only main thread will call pool_get */
      clib_rwlock_reader_lock (&qm->half_open_rwlock);
      pool_get (qm->half_open_ctx_pool, ctx);
      ctx_index = ctx - qm->half_open_ctx_pool;
      clib_rwlock_reader_unlock (&qm->half_open_rwlock);
    }
  memset (ctx, 0, sizeof (*ctx));
  return ctx_index;
}

void
quic_ctx_half_open_free (u32 ho_index)
{
  quic_main_t *qm = &quic_main;
  clib_rwlock_writer_lock (&qm->half_open_rwlock);
  pool_put_index (qm->half_open_ctx_pool, ho_index);
  clib_rwlock_writer_unlock (&qm->half_open_rwlock);
}

quic_ctx_t *
quic_ctx_half_open_get (u32 ctx_index)
{
  quic_main_t *qm = &quic_main;
  clib_rwlock_reader_lock (&qm->half_open_rwlock);
  return pool_elt_at_index (qm->half_open_ctx_pool, ctx_index);
}

void
quic_ctx_half_open_reader_unlock ()
{
  clib_rwlock_reader_unlock (&quic_main.half_open_rwlock);
}

u32
quic_ctx_half_open_index (quic_ctx_t * ctx)
{
  return (ctx - quic_main.half_open_ctx_pool);
}

u32
quic_listener_ctx_alloc (void)
{
  quic_main_t *qm = &quic_main;
  quic_ctx_t *ctx;

  pool_get (qm->listener_ctx_pool, ctx);
  memset (ctx, 0, sizeof (*ctx));
  return ctx - qm->listener_ctx_pool;
}

void
quic_listener_ctx_free (quic_ctx_t * ctx)
{
  if (CLIB_DEBUG)
    memset (ctx, 0xfb, sizeof (*ctx));
  pool_put (quic_main.listener_ctx_pool, ctx);
}

quic_ctx_t *
quic_listener_ctx_get (u32 ctx_index)
{
  return pool_elt_at_index (quic_main.listener_ctx_pool, ctx_index);
}

u32
quic_listener_ctx_index (quic_ctx_t * ctx)
{
  return (ctx - quic_main.listener_ctx_pool);
}

u32
quic_ctx_alloc ()
{
  u8 thread_index = vlib_get_thread_index ();
  quic_main_t *qm = &quic_main;
  quic_ctx_t *ctx;

  pool_get (qm->ctx_pool[thread_index], ctx);

  memset (ctx, 0, sizeof (quic_ctx_t));
  ctx->c_thread_index = thread_index;
  return ctx - qm->ctx_pool[thread_index];
}

static void
quic_ctx_free (quic_ctx_t * ctx)
{
  if (CLIB_DEBUG)
    memset (ctx, 0xfb, sizeof (*ctx));
  pool_put (quic_main.ctx_pool[ctx->c_thread_index], ctx);
}

static quic_ctx_t *
quic_ctx_get (u32 ctx_handle)
{
  return pool_elt_at_index (quic_main.ctx_pool[vlib_get_thread_index ()],
                            ctx_handle);
}

static quic_ctx_t *
quic_ctx_get_w_thread (u32 ctx_handle, u8 thread_index)
{
  return pool_elt_at_index (quic_main.ctx_pool[thread_index], ctx_handle);
}

static void
quic_disconnect_transport (quic_ctx_t * ctx)
{
  QUIC_DBG (2, "Called quic_disconnect_transport");
  vnet_disconnect_args_t a = {
    .handle = ctx->c_quic_ctx_id.quic_session,
    .app_index = quic_main.app_index,
  };

  if (vnet_disconnect_session (&a))
    clib_warning ("disconnect errored");
}

static int
quic_send_datagram (session_t *session, quicly_datagram_t *packet)
{
  QUIC_DBG (2, "Called quic_send_one");
  u32 max_enqueue;
  session_dgram_hdr_t hdr;
  int rv;
  u32 len;
  svm_fifo_t *f;
  transport_connection_t *tc;

  len = packet->data.len;
  f = session->tx_fifo;
  tc = session_get_transport (session);

  max_enqueue = svm_fifo_max_enqueue (f);
  if (max_enqueue <= sizeof (session_dgram_hdr_t))
    return 1;

  max_enqueue -= sizeof (session_dgram_hdr_t);

  if (max_enqueue < len)
    return 1;

  // Build packet header for fifo
  hdr.data_length = len;
  hdr.data_offset = 0;
  hdr.is_ip4 = tc->is_ip4;
  clib_memcpy (&hdr.lcl_ip, &tc->lcl_ip, sizeof (ip46_address_t));
  hdr.lcl_port = tc->lcl_port;
  
  // Read dest address from quicly-provided sockaddr
  if (hdr.is_ip4)
    {
      ASSERT (packet->sa.sa_family == AF_INET);
      struct sockaddr_in * sa4 = (struct sockaddr_in *) &packet->sa;
      hdr.rmt_port = sa4->sin_port;
      hdr.rmt_ip.ip4.as_u32 = sa4->sin_addr.s_addr;
    }
  else
    {
      ASSERT (packet->sa.sa_family == AF_INET6);
      struct sockaddr_in6 * sa6 = (struct sockaddr_in6 *) &packet->sa;
      hdr.rmt_port = sa6->sin6_port;
      clib_memcpy (&hdr.rmt_ip.ip6, &sa6->sin6_addr, 16);
    }

  rv = svm_fifo_enqueue_nowait (f, sizeof (hdr), (u8 *) & hdr);
  ASSERT (rv == sizeof (hdr));
  if (svm_fifo_enqueue_nowait (f, len, packet->data.base) != len)
    return 1;
  return 0;
}

static void
quic_send_packets (quic_ctx_t *ctx)
{
  QUIC_DBG (2, "Called quic_send_packets");
  quicly_datagram_t *packets[16];
  session_t *quic_session;
  quicly_conn_t *conn;
  size_t num_packets, i;
  int ret;

  quic_session = session_get_from_handle (ctx->c_quic_ctx_id.quic_session);
  conn = ctx->c_quic_ctx_id.conn;

  do
    {
      num_packets = sizeof(packets) / sizeof(packets[0]);
      if ((ret = quicly_send(conn, packets, &num_packets)) == 0)
        {
          for (i = 0; i != num_packets; ++i)
            {
              if (quic_send_datagram(quic_session, packets[i]))
                {
                  perror("quic_send_one failed");
                  break;
                }
              ret = 0;
              quicly_default_free_packet_cb.cb(&quicly_default_free_packet_cb,
                                               packets[i]);
            }
        }
      else
        {
          fprintf(stderr, "quicly_send returned %d\n", ret);
        }
    }
  while (ret == 0 && num_packets == sizeof(packets) / sizeof(packets[0]));

  if (svm_fifo_set_event (quic_session->tx_fifo))
    session_send_io_evt_to_thread (quic_session->tx_fifo,
                                    FIFO_EVENT_APP_TX);

  quic_update_timer (ctx);
}

/*****************************************************************************
 * BEGIN TIMERS HANDLING
 *****************************************************************************/


static int64_t quic_get_time (quicly_now_cb * self)
{
  vlib_main_t * vlib_main = vlib_get_main();
  f64 time = vlib_time_now(vlib_main);
  return (int64_t) time * 1000;
}
quicly_now_cb quicly_vpp_now_cb = {quic_get_time};

static u32
quic_set_time_now (u32 thread_index)
{
  quic_main.wrk_ctx[thread_index].time_now = quic_get_time(NULL);
  return quic_main.wrk_ctx[thread_index].time_now;
}

static void
quic_timer_expired (u32 conn_index)
{
  quic_ctx_t *ctx;
  ctx = quic_ctx_get (conn_index);
  ctx->c_quic_ctx_id.timer_handle = QUIC_TIMER_HANDLE_INVALID;
  quic_send_packets (ctx);
}

static void
quic_update_timer (quic_ctx_t *ctx)
{
  clib_warning("quic_update_timer");
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;
  int64_t next_timeout;

  // This timeout is in ms which is the unit of our timer
  next_timeout = quicly_get_first_timeout (ctx->c_quic_ctx_id.conn);
  tw = &quic_main.wrk_ctx[vlib_get_thread_index ()].timer_wheel;
  f64 next_timeout_f = (f64) next_timeout / 1000;

  if (ctx->c_quic_ctx_id.timer_handle == QUIC_TIMER_HANDLE_INVALID)
    {
      if (next_timeout == INT64_MAX)
        return;
      ctx->c_quic_ctx_id.timer_handle =
          tw_timer_start_1t_3w_1024sl_ov (tw, ctx->c_c_index, 0, next_timeout_f);
    }
  else
    {
      if (next_timeout == INT64_MAX)
        {
          tw_timer_stop_1t_3w_1024sl_ov (tw, ctx->c_quic_ctx_id.timer_handle);
          ctx->c_quic_ctx_id.timer_handle = QUIC_TIMER_HANDLE_INVALID;
        }
      else
        tw_timer_update_1t_3w_1024sl_ov (tw, ctx->c_quic_ctx_id.timer_handle,
                                         next_timeout_f);
    }
}

static void
quic_expired_timers_dispatch (u32 * expired_timers)
{
  int i;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      quic_timer_expired (expired_timers[i]);
    }
}


/*****************************************************************************
 * END TIMERS HANDLING
 *
 * BEGIN TRANSPORT PROTO FUNCTIONS
 *****************************************************************************/




int
quic_connect (transport_endpoint_cfg_t * tep)
{
  QUIC_DBG (2, "Called quic_connect");
  vnet_connect_args_t _cargs = { {}, }, *cargs = &_cargs;
  session_endpoint_cfg_t *sep;
  quic_main_t *qm = &quic_main;
  quic_ctx_t *ctx;
  u32 ctx_index;
  int error;

  sep = (session_endpoint_cfg_t *) tep;
  ctx_index = quic_ctx_half_open_alloc ();
  ctx = quic_ctx_half_open_get (ctx_index);
  ctx->c_quic_ctx_id.parent_app_id = sep->app_wrk_index;
  ctx->c_s_index = sep->opaque;
  ctx->c_quic_ctx_id.udp_is_ip4 = sep->is_ip4;
  ctx->c_quic_ctx_id.timer_handle = QUIC_TIMER_HANDLE_INVALID;
  if (sep->hostname)
    {
      ctx->srv_hostname = format (0, "%v", sep->hostname);
      vec_terminate_c_string (ctx->srv_hostname);
    }
  else
    {
      // needed by quic for crypto + determining client / server
      ctx->srv_hostname = format (0, "%U", format_ip46_address, &sep->ip, sep->is_ip4);
    }

  quic_ctx_half_open_reader_unlock ();

  clib_memcpy (&cargs->sep, sep, sizeof (session_endpoint_cfg_t));
  cargs->sep.transport_proto = TRANSPORT_PROTO_UDP;
  cargs->app_index = qm->app_index;
  cargs->api_context = ctx_index;

  if ((error = vnet_connect (cargs)))
    return error;

  QUIC_DBG (1, "New connect request %u", ctx_index);
  return 0;
}

void
quic_disconnect (u32 ctx_handle, u32 thread_index)
{
  QUIC_DBG (2, "Called quic_disconnect");
  quic_ctx_t *ctx;

  QUIC_DBG (1, "Disconnecting %x", ctx_handle);

  ctx = quic_ctx_get (ctx_handle);
  quic_disconnect_transport (ctx);
  session_transport_delete_notify (&ctx->connection);
  quic_ctx_free (ctx);
}

u32
quic_start_listen (u32 app_listener_index, transport_endpoint_t * tep)
{
  QUIC_DBG (2, "Called quic_start_listen");
  vnet_listen_args_t _bargs, *args = &_bargs;
  quic_main_t *qm = &quic_main;
  session_handle_t udp_handle;
  session_endpoint_cfg_t *sep;
  session_t *quic_listener;
  session_t *app_listener;
  app_worker_t *app_wrk;
  application_t *app;
  quic_ctx_t *lctx;
  u32 lctx_index;
  app_listener_t *al;

  sep = (session_endpoint_cfg_t *) tep;
  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);

  sep->transport_proto = TRANSPORT_PROTO_UDP;
  memset (args, 0, sizeof (*args));
  args->app_index = qm->app_index;
  args->sep_ext = *sep;
  args->sep_ext.ns_index = app->ns_index;
  if (vnet_listen (args))
    return -1;

  lctx_index = quic_listener_ctx_alloc ();
  udp_handle = args->handle;
  al = app_listener_get_w_handle (udp_handle);
  quic_listener = app_listener_get_session (al);
  quic_listener->opaque = lctx_index;

  app_listener = listen_session_get (app_listener_index);

  lctx = quic_listener_ctx_get (lctx_index);
  lctx->c_quic_ctx_id.parent_app_id = sep->app_wrk_index;
  lctx->c_quic_ctx_id.quic_session = udp_handle;
  lctx->c_quic_ctx_id.app_session = listen_session_get_handle (app_listener);
  lctx->c_quic_ctx_id.udp_is_ip4 = sep->is_ip4;

  // TODO: certs setup, separate ptls context may be required
  // load_certificate_chain(ctx.tls, optarg);
  // load_private_key(ctx.tls, optarg);

  QUIC_DBG (1, "Started listening %d", lctx_index);
  return lctx_index;
}

u32
quic_stop_listen (u32 lctx_index)
{
  QUIC_DBG (2, "Called quic_stop_listen");
  quic_ctx_t *lctx;

  lctx = quic_listener_ctx_get (lctx_index);
  vnet_unlisten_args_t a = {
    .handle = lctx->c_quic_ctx_id.quic_session,
    .app_index = quic_main.app_index,
    .wrk_map_index = 0          /* default wrk */
  };
  if (vnet_unlisten (&a))
    clib_warning ("unlisten errored");

  // TODO: crypto state cleanup

  quic_listener_ctx_free (lctx);
  return 0;
}

transport_connection_t *
quic_connection_get (u32 ctx_index, u32 thread_index)
{
  QUIC_DBG (2, "Called quic_connection_get");
  quic_ctx_t *ctx;
  ctx = quic_ctx_get_w_thread (ctx_index, thread_index);
  return &ctx->connection;
}

transport_connection_t *
quic_listener_get (u32 listener_index)
{
  QUIC_DBG (2, "Called quic_listener_get");
  quic_ctx_t *ctx;
  ctx = quic_listener_ctx_get (listener_index);
  return &ctx->connection;
}

static void
quic_update_time (f64 now, u8 thread_index)
{
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;

  tw = &quic_main.wrk_ctx[thread_index].timer_wheel;
  quic_set_time_now (thread_index);
  tw_timer_expire_timers_1t_3w_1024sl_ov (tw, now);
}

static u8 *
format_quic_connection (u8 * s, va_list * args)
{
  s = format (s, "[QUIC] connection");
  return s;
}

static u8 *
format_quic_half_open (u8 * s, va_list * args)
{
  u32 qc_index = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_half_open_get (qc_index);
  s = format (s, "[QUIC] half-open app %u", ctx->c_quic_ctx_id.parent_app_id);
  quic_ctx_half_open_reader_unlock ();
  return s;
}

// TODO improve
static u8 *
format_quic_listener (u8 * s, va_list * args)
{
  s = format (s, "[QUIC] listener");
  return s;
}

/*****************************************************************************
 * END TRANSPORT PROTO FUNCTIONS
 *
 * START SESSION CALLBACKS
 * Called from UDP layer
 *****************************************************************************/

static inline void
quic_build_sockaddr (struct sockaddr * sa, socklen_t * salen,
                     ip46_address_t *addr, u16 port, u8 is_ip4)
{
  if (is_ip4)
    {
      struct sockaddr_in * sa4 = (struct sockaddr_in *) sa;
      sa4->sin_family = AF_INET;
      sa4->sin_port = port;
      sa4->sin_addr.s_addr = addr->ip4.as_u32;
      *salen = sizeof(struct sockaddr_in);
    }
  else
    {
      struct sockaddr_in6 * sa6 = (struct sockaddr_in6 *) sa;
      sa6->sin6_family = AF_INET6;
      sa6->sin6_port = port;
      clib_memcpy(&sa6->sin6_addr, &addr->ip6, 16);
      *salen = sizeof(struct sockaddr_in6);
    }
}

int
quic_session_connected_callback (u32 quic_app_index, u32 ho_ctx_idx,
                                 session_t * s, u8 is_fail)
{
  QUIC_DBG (2, "Called quic_session_connected_callback");
  // This should always be called before quic_connect returns since UDP always
  // connects instantly.
  struct sockaddr_in6 sa6;
  struct sockaddr * sa = (struct sockaddr *) &sa6;
  socklen_t salen;
  transport_connection_t *tc;
  quic_ctx_t *ho_ctx, *ctx;
  u32 ctx_handle;
  int ret;

  ho_ctx = quic_ctx_half_open_get (ho_ctx_idx);
  if (is_fail)
    {
      int (*cb_fn) (u32, u32, session_t *, u8), rv = 0;
      u32 wrk_index, api_context;
      app_worker_t *app_wrk;
      application_t *app;

      wrk_index = ho_ctx->c_quic_ctx_id.parent_app_id;
      app_wrk = app_worker_get_if_valid (ho_ctx->c_quic_ctx_id.parent_app_id);
      if (app_wrk)
        {
          api_context = ho_ctx->c_s_index;
          app = application_get (app_wrk->app_index);
          cb_fn = app->cb_fns.session_connected_callback;
          rv = cb_fn (wrk_index, api_context, 0, 1 /* failed */ );
        }
      quic_ctx_half_open_reader_unlock ();
      quic_ctx_half_open_free (ho_ctx_idx);
      return rv;
    }

  ctx_handle = quic_ctx_alloc ();
  ctx = quic_ctx_get (ctx_handle);
  clib_memcpy (ctx, ho_ctx, sizeof (*ctx));
  quic_ctx_half_open_reader_unlock (); // TODO: this is a race
  quic_ctx_half_open_free (ho_ctx_idx);

  ctx->c_thread_index = vlib_get_thread_index ();
  ctx->c_c_index = ctx_handle;

  QUIC_DBG (1, "Quic connect for returned %u. New connection [%u]%x",
           is_fail, vlib_get_thread_index (),
           (ctx) ? ctx_handle : ~0);

  ctx->c_quic_ctx_id.quic_session = session_handle (s);
  s->opaque = ctx_handle;
  s->session_state = SESSION_STATE_READY;

  // Init QUIC lib connection
  // Generate required sockaddr & salen
  tc = session_get_transport (s);
  quic_build_sockaddr (sa, &salen, &tc->rmt_ip, tc->rmt_port, tc->is_ip4);

  ret = quicly_connect (&ctx->c_quic_ctx_id.conn, &quic_main.quicly_ctx,
                        (char *) ctx->srv_hostname, sa, salen,
                        &quic_main.next_cid, &quic_main.hs_properties, NULL);
  ++quic_main.next_cid.master_id;
  assert (ret == 0);
  quic_send_packets(ctx);

  return ret;
}

void
quic_session_disconnect_callback (session_t * s)
{
  clib_warning("UDP session disconnected???");
}

void
quic_session_reset_callback (session_t * s)
{
  clib_warning("UDP session reset???");
}

static int
quic_add_segment_callback (u32 client_index, u64 seg_handle)
{
  QUIC_DBG (2, "Called quic_add_segment_callback");
  QUIC_DBG (2, "NOT IMPLEMENTED");
  /* No-op for builtin */
  return 0;
}

static int
quic_del_segment_callback (u32 client_index, u64 seg_handle)
{
  QUIC_DBG (2, "Called quic_del_segment_callback");
  QUIC_DBG (2, "NOT IMPLEMENTED");
  /* No-op for builtin */
  return 0;
}

int
quic_add_vpp_q_builtin_tx_evt (session_t * s)
{
  if (svm_fifo_set_event (s->tx_fifo))
    session_send_io_evt_to_thread_custom (s, s->thread_index,
                                          FIFO_EVENT_BUILTIN_TX);
  return 0;
}

void
quic_open_stream_if_ready (quic_ctx_t *ctx)
{
  quicly_conn_t *conn = ctx->c_quic_ctx_id.conn;
  if (ctx->stream)
      return;
  if (quicly_connection_is_ready(conn))
      assert(!quicly_open_stream(conn, &ctx->stream, 1));
}

int
quic_app_tx_callback (session_t * app_session)
{
  QUIC_DBG (2, "Called quic_app_tx_callback");
  quic_ctx_t *ctx;
  svm_fifo_t *f;
  u32 deq_max;
  u8 *data;

  if (PREDICT_FALSE (app_session->session_state == SESSION_STATE_CLOSED))
    return 0;
  ctx = quic_ctx_get (app_session->connection_index);
  quic_open_stream_if_ready (ctx);
  if (!ctx->stream) {
    quic_add_vpp_q_builtin_tx_evt (app_session);
    return 0;
  }

  f = app_session->tx_fifo;
  deq_max = svm_fifo_max_dequeue (f);
  if (!deq_max)
    return 0;

  data = svm_fifo_head (f);
  if (quicly_streambuf_egress_write(ctx->stream, data, deq_max))
    {
      assert (0);
      return 0;
    }
  svm_fifo_dequeue_drop (f, deq_max);
  quic_send_packets (ctx);
  return 0;
}

int
quic_app_rx_callback (session_t * quic_session)
{
  QUIC_DBG (2, "Called quic_app_rx_callback");
  // Read data from UDP rx_fifo and pass it to the quicly conn.

  quicly_decoded_packet_t packet;
  quicly_datagram_t *dgram;
  session_dgram_hdr_t ph;
  quicly_conn_t *conn = NULL;
  quic_ctx_t *lctx, *ctx;
  session_t *quic_listener, *app_session, *app_listener;
  svm_fifo_t *f;
  size_t plen;
  struct sockaddr_in6 sa6;
  struct sockaddr * sa = (struct sockaddr *) &sa6;
  socklen_t salen;
  u32 max_deq, len;
  app_worker_t *app_wrk;
  u8 *data;
  int rv;

  f = quic_session->rx_fifo;

  do {
    max_deq = svm_fifo_max_dequeue (f);
    if (max_deq < sizeof (session_dgram_hdr_t))
      {
        svm_fifo_unset_event (f);
        return 0;
      }

    svm_fifo_unset_event (f);

    svm_fifo_peek (f, 0, sizeof (ph), (u8 *) & ph);
    ASSERT (ph.data_length >= ph.data_offset);
    len = ph.data_length - ph.data_offset;

    quic_build_sockaddr (sa, &salen, &ph.rmt_ip, ph.rmt_port, ph.is_ip4);

    // Quicly can read len bytes from the fifo at offset:
    // ph.data_offset + SESSION_CONN_HDR_LEN
    data = svm_fifo_head (f) + ph.data_offset + SESSION_CONN_HDR_LEN;
    plen = quicly_decode_packet(&quic_main.quicly_ctx, &packet, data, len);
    if (plen != SIZE_MAX)
      {

        pool_foreach (ctx, quic_main.ctx_pool[vlib_get_thread_index()], ({
          quicly_conn_t * conn_ = ctx->c_quic_ctx_id.conn;
          if (quicly_is_destination(conn_, sa, salen, &packet))
          {
            conn = conn_;
            goto connection_found;
          }
        }));

connection_found:
      if (conn != NULL)
        {
          quicly_receive(conn, &packet);
        }
      else if (QUICLY_PACKET_IS_LONG_HEADER(packet.octets.base[0]))
        {
          /* new connection, accept and create context if packet is valid */
          // TODO: check if socket is actually listening?
          QUIC_DBG (2, "New connection created");
          int ret = quicly_accept (&conn, &quic_main.quicly_ctx, sa, salen,
                                   &packet, ptls_iovec_init(NULL, 0),
                                   &quic_main.next_cid, NULL);
          if (ret == 0)
            {
              assert(conn != NULL);
              ++quic_main.next_cid.master_id;
              // Create context
              quic_listener = listen_session_get (quic_session->listener_index);
              lctx = quic_listener_ctx_get (quic_listener->opaque);

              u32 ctx_index = quic_ctx_alloc ();
              ctx = quic_ctx_get (ctx_index);

              ctx->c_thread_index = vlib_get_thread_index ();
              ctx->c_c_index = ctx_index;
              ctx->c_quic_ctx_id.quic_session = session_handle (quic_session);
              ctx->c_quic_ctx_id.parent_app_id = lctx->c_quic_ctx_id.parent_app_id;
              ctx->c_quic_ctx_id.listener_ctx_id = quic_listener->opaque;
              ctx->c_quic_ctx_id.timer_handle = QUIC_TIMER_HANDLE_INVALID;
              ctx->c_quic_ctx_id.conn = conn;
              ctx->c_quic_ctx_id.udp_is_ip4 = lctx->c_quic_ctx_id.udp_is_ip4;

              app_session = session_alloc (ctx->c_thread_index);
              app_session->session_state = SESSION_STATE_CLOSED;
              ctx->c_s_index = app_session->session_index;

              app_listener = listen_session_get_from_handle (lctx->c_quic_ctx_id.app_session);
              app_session->app_wrk_index = ctx->c_quic_ctx_id.parent_app_wrk_idx;
              app_session->connection_index = ctx_index;
              app_session->session_type = app_listener->session_type;
              app_session->listener_index = app_listener->session_index;
              app_session->app_index = quic_main.app_index;

              if ((rv = app_worker_init_accepted (app_session)))
                {
                  QUIC_DBG (1, "failed to allocate fifos");
                  session_free (app_session);
                  return rv;
                }
              ctx->c_quic_ctx_id.app_session = session_handle (app_session);
              session_lookup_add_connection (&ctx->connection,
                                            session_handle (app_session));
              ctx->c_quic_ctx_id.parent_app_wrk_idx = app_session->app_wrk_index;
              app_wrk = app_worker_get (app_session->app_wrk_index);
              rv = app_worker_accept_notify (app_wrk, app_session);
              if (rv) {
                QUIC_DBG (1, "failed to notify accept worker app");
                return rv;
              }
            }
          else
            {
              // Invalid packet, pass
              QUIC_DBG (2, "Accept failed");
              assert(conn == NULL);
            }
        }
      else
        {
          /* short header packet; potentially a dead connection. No need to check the length of the incoming packet,
          * because loop is prevented by authenticating the CID (by checking node_id and thread_id). If the peer is also
          * sending a reset, then the next CID is highly likely to contain a non-authenticating CID, ... */
          if (packet.cid.dest.plaintext.node_id == 0 &&
              packet.cid.dest.plaintext.thread_id == 0)
            {
              dgram = quicly_send_stateless_reset(&quic_main.quicly_ctx, sa, salen,
                                                  &packet.cid.dest.plaintext);
              if (quic_send_datagram(quic_session, dgram) == -1)
                QUIC_DBG (2, "Send reset failed");
            }
        }
    }
    svm_fifo_dequeue_drop (f, ph.data_length + ph.data_offset + SESSION_CONN_HDR_LEN);
 } while (1);


  return 0;
}

/*****************************************************************************
 * END TRANSPORT PROTO FUNCTIONS
 *
 * START QUICLY CALLBACKS
 * Called from QUIC lib
 *****************************************************************************/

static int
quic_on_stop_sending (quicly_stream_t *stream, int error_code)
{
  fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", error_code);
  return 0;
}

static int
quic_on_receive_reset (quicly_stream_t *stream, int error_code)
{
  fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", error_code);
  return 0;
}

static int
quic_on_receive (quicly_stream_t *stream, size_t off, const void *src,
                 size_t len)
{
  // TODO Put data in client rx_fifo and send FIFO_EVENT_APP_RX
  fprintf(stderr, "received data");
  return 0;
}

static const quicly_stream_callbacks_t quic_stream_callbacks = {
  .on_destroy = quicly_streambuf_destroy,
  .on_send_shift = quicly_streambuf_egress_shift,
  .on_send_emit = quicly_streambuf_egress_emit,
  .on_send_stop = quic_on_stop_sending,
  .on_receive = quic_on_receive,
  .on_receive_reset = quic_on_receive_reset
};

static int
quic_on_stream_open (quicly_stream_open_cb *self, quicly_stream_t *stream)
{
  int ret;
  if ((ret = quicly_streambuf_create (stream, sizeof(quicly_streambuf_t))) != 0)
    {
      return ret;
    }
  stream->callbacks = &quic_stream_callbacks;
  return 0;
}

static quicly_stream_open_cb on_stream_open = {&quic_on_stream_open};

static void
quic_on_conn_close (quicly_closed_by_peer_cb *self, quicly_conn_t *conn,
                    int code, uint64_t frame_type,
                    const char *reason, size_t reason_len)
{
  // Close the underlying conn & notify app??
}

static quicly_closed_by_peer_cb on_closed_by_peer = {&quic_on_conn_close};


/*****************************************************************************
 * END QUICLY CALLBACKS
 *****************************************************************************/

/*
static int
quic_notify_app_connected (quic_ctx_t * ctx, u8 is_failed)
{
  session_t *app_session;
  app_worker_t *app_wrk;

  app_wrk = app_worker_get_if_valid (ctx->c_quic_ctx_id.parent_app_wrk_idx);
  if (!app_wrk)
    {
      quic_disconnect_transport (ctx);
      return -1;
    }

  if (is_failed)
    goto failed;

  app_session = session_get (ctx->c_s_index, ctx->c_thread_index);
  app_session->app_wrk_index = ctx->c_quic_ctx_id.parent_app_wrk_idx;
  app_session->connection_index = ctx->c_c_index;
  app_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC,
                                    ctx->c_quic_ctx_id.udp_is_ip4);
  app_session->t_app_index = quic_main.app_index;

  if (app_worker_init_connected (app_wrk, app_session))
    goto failed;

  app_session->session_state = SESSION_STATE_CONNECTING;
  if (app_worker_connect_notify (app_wrk, app_session,
                                 ctx->parent_app_api_context))
    {
      QUIC_DBG (1, "failed to notify app");
      quic_disconnect (ctx->c_c_index, vlib_get_thread_index ());
      return -1;
    }

  ctx->c_quic_ctx_id.app_session = session_handle (app_session);
  app_session->session_state = SESSION_STATE_READY;
  session_lookup_add_connection (&ctx->connection,
                                 session_handle (app_session));

  return 0;

failed:
  quic_disconnect (ctx->c_c_index, vlib_get_thread_index ());
  return app_worker_connect_notify (app_wrk, 0, ctx->parent_app_api_context);
}
*/

/* single-entry session cache */
struct st_util_session_cache_t {
    ptls_encrypt_ticket_t super;
    uint8_t id[32];
    ptls_iovec_t data;
};

static int encrypt_ticket_cb(ptls_encrypt_ticket_t *_self, ptls_t *tls, int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src)
{
    struct st_util_session_cache_t *self = (void *)_self;
    int ret;

    if (is_encrypt) {

        /* replace the cached entry along with a newly generated session id */
        free(self->data.base);
        if ((self->data.base = malloc(src.len)) == NULL)
            return PTLS_ERROR_NO_MEMORY;

        ptls_get_context(tls)->random_bytes(self->id, sizeof(self->id));
        memcpy(self->data.base, src.base, src.len);
        self->data.len = src.len;

        /* store the session id in buffer */
        if ((ret = ptls_buffer_reserve(dst, sizeof(self->id))) != 0)
            return ret;
        memcpy(dst->base + dst->off, self->id, sizeof(self->id));
        dst->off += sizeof(self->id);

    } else {

        /* check if session id is the one stored in cache */
        if (src.len != sizeof(self->id))
            return PTLS_ERROR_SESSION_NOT_FOUND;
        if (memcmp(self->id, src.base, sizeof(self->id)) != 0)
            return PTLS_ERROR_SESSION_NOT_FOUND;

        /* return the cached value */
        if ((ret = ptls_buffer_reserve(dst, self->data.len)) != 0)
            return ret;
        memcpy(dst->base + dst->off, self->data.base, self->data.len);
        dst->off += self->data.len;
    }

    return 0;
}

static struct st_util_session_cache_t sc = {
  .super = {
    .cb = encrypt_ticket_cb,
  },
};


/* *INDENT-OFF* */
const static transport_proto_vft_t quic_proto = {
  .connect = quic_connect,
  .close = quic_disconnect,
  .start_listen = quic_start_listen,
  .stop_listen = quic_stop_listen,
  .get_connection = quic_connection_get,
  .get_listener = quic_listener_get,
  .update_time = quic_update_time,
  .tx_type = TRANSPORT_TX_INTERNAL,
  .service_type = TRANSPORT_SERVICE_APP,
  .format_connection = format_quic_connection,
  .format_half_open = format_quic_half_open,
  .format_listener = format_quic_listener,
};

static session_cb_vft_t quic_app_cb_vft = {
  .session_accept_callback = NULL,
  .session_disconnect_callback = quic_session_disconnect_callback,
  .session_connected_callback = quic_session_connected_callback,
  .session_reset_callback = quic_session_reset_callback,
  .add_segment_callback = quic_add_segment_callback,
  .del_segment_callback = quic_del_segment_callback,
  .builtin_app_rx_callback = quic_app_rx_callback,
  .builtin_app_tx_callback = quic_app_tx_callback,
};

static ptls_context_t quic_tlsctx = {
  .random_bytes = ptls_openssl_random_bytes,
  .get_time = &ptls_get_time,
  .key_exchanges = ptls_openssl_key_exchanges,
  .cipher_suites = ptls_openssl_cipher_suites,
  .certificates = {
    .list = NULL,
    .count = 0
  },
  .esni = NULL,
  .on_client_hello = NULL,
  .emit_certificate = NULL,
  .sign_certificate = NULL,
  .verify_certificate = NULL,
  .ticket_lifetime = 86400,
  .max_early_data_size = 8192,
  .hkdf_label_prefix__obsolete = NULL,
  .require_dhe_on_psk = 1,
  .encrypt_ticket = &sc.super,
};

/* *INDENT-ON* */

static clib_error_t *
quic_init (vlib_main_t * vm)
{
  QUIC_DBG (2, "Called quic_init");
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  u32 segment_size = 512 << 20;
  quic_main_t *qm = &quic_main;
  u32 fifo_size = 64 << 10;
  u32 num_threads;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  memset (a, 0, sizeof (*a));
  memset (options, 0, sizeof (options));

  a->session_cb_vft = &quic_app_cb_vft;
  a->api_client_index = APP_INVALID_INDEX;
  a->options = options;
  a->name = format (0, "quic");
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_IS_TRANSPORT_APP;

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach quic app");
      return clib_error_return (0, "failed to attach quic app");
    }

  vec_validate (qm->ctx_pool, num_threads - 1);
  vec_validate (qm->wrk_ctx, num_threads - 1);
  // Timers, one per thread.
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;
  /* *INDENT-OFF* */
  foreach_vlib_main (({
    tw = &qm->wrk_ctx[ii].timer_wheel;
    tw_timer_wheel_init_1t_3w_1024sl_ov (tw, quic_expired_timers_dispatch,
                                         10e-3 /* timer period 10ms */ , ~0);
    tw->last_run_time = vlib_time_now (this_vlib_main);
  }));
  /* *INDENT-ON* */

  if (!qm->ca_cert_path)
    qm->ca_cert_path = QUIC_DEFAULT_CA_CERT_PATH;

  qm->app_index = a->app_index;
  clib_rwlock_init (&qm->half_open_rwlock);
  qm->quicly_ctx = quicly_default_context;
  qm->quicly_ctx.tls = &quic_tlsctx;
  qm->quicly_ctx.stream_open = &on_stream_open;
  qm->quicly_ctx.closed_by_peer = &on_closed_by_peer;
  qm->tstamp_ticks_per_clock = vm->clib_time.seconds_per_clock
    / QUIC_TSTAMP_RESOLUTION;
  qm->quicly_ctx.now = &quicly_vpp_now_cb;

  quicly_amend_ptls_context(qm->quicly_ctx.tls);

  transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
                               FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
                               FIB_PROTOCOL_IP6, ~0);

  vec_free (a->name);
  return 0;
}

quic_main_t *
vnet_quic_get_main (void)
{
  return &quic_main;
}

VLIB_INIT_FUNCTION (quic_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Quic transport protocol",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
