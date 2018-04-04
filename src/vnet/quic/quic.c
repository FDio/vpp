/*
 * Copyright (c) 2018 SUSE LLC.
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
#include <vnet/quic/quic.h>

quic_main_t quic_main;
static quic_engine_vft_t *quic_vfts;

static inline void
quic_ctx_free (quic_ctx_t * ctx)
{
  vec_free (ctx->srv_hostname);
}

#define QUIC_INVALID_HANDLE 	~0
#define QUIC_IDX_MASK 		0x00FFFFFF
#define QUIC_ENGINE_TYPE_SHIFT 	29

static inline void
quic_ctx_parse_handle (u32 ctx_handle, u32 * ctx_index, u32 * engine_type)
{
  *ctx_index = ctx_handle & QUIC_IDX_MASK;
  *engine_type = ctx_handle >> QUIC_ENGINE_TYPE_SHIFT;
}

static inline quic_ctx_t *
quic_ctx_get (u32 ctx_handle)
{
  u32 ctx_index, engine_type;
  quic_ctx_parse_handle (ctx_handle, &ctx_index, &engine_type);
  return quic_vfts[engine_type].ctx_get (ctx_index);
}


u8 *
format_quic_half_open (u8 * s, va_list * args)
{
  return NULL;
}

u8 *
format_quic_listener (u8 * s, va_list * args)
{
  return NULL;
}

u8 *
format_quic_connection (u8 * s, va_list * args)
{
  return NULL;
}

u32
quic_stop_listen (u32 lctx_index)
{
  return 0;
}

transport_connection_t *
quic_listener_get (u32 listener_index)
{
  return NULL;
}

transport_connection_t *
quic_connection_get (u32 ctx_index, u32 thread_index)
{
  return NULL;
}

u32
quic_start_listen (u32 app_listener_index, transport_endpoint_t * tep)
{
  return 0;
}

void
quic_disconnect (u32 ctx_handle, u32 thread_index)
{
  stream_session_t *quic_session, *app_session;
  quic_ctx_t *ctx;

  QUIC_DBG (1, "Disconnecting %x", ctx_handle);

  ctx = quic_ctx_get (ctx_handle);
  quic_session = session_get_from_handle (ctx->quic_session_handle);
  stream_session_disconnect (quic_session);

  app_session =
    session_get_from_handle_if_valid (ctx->quic_app_session_handle);
  if (app_session)
    {
      segment_manager_dealloc_fifos (app_session->svm_segment_index,
				     app_session->server_rx_fifo,
				     app_session->server_tx_fifo);
      session_free (app_session);
    }
  quic_ctx_free (ctx);
}

u32
quic_ctx_half_open_alloc (void)
{
  quic_main_t *tm = &quic_main;
  u8 will_expand = 0;
  quic_ctx_t *ctx;
  u32 ctx_index;

  pool_get_aligned_will_expand (tm->half_open_ctx_pool, will_expand, 0);
  if (PREDICT_FALSE (will_expand && vlib_num_workers ()))
    {
      clib_rwlock_writer_lock (&tm->half_open_rwlock);
      pool_get (tm->half_open_ctx_pool, ctx);
      memset (ctx, 0, sizeof (*ctx));
      ctx_index = ctx - tm->half_open_ctx_pool;
      clib_rwlock_writer_unlock (&tm->half_open_rwlock);
    }
  else
    {
      pool_get (tm->half_open_ctx_pool, ctx);
      memset (ctx, 0, sizeof (*ctx));
      ctx_index = ctx - tm->half_open_ctx_pool;
    }
  return ctx_index;
}

quic_ctx_t *
quic_ctx_half_open_get (u32 ctx_index)
{
  quic_main_t *tm = &quic_main;
  clib_rwlock_reader_lock (&tm->half_open_rwlock);
  return pool_elt_at_index (tm->half_open_ctx_pool, ctx_index);
}

void
quic_ctx_half_open_reader_unlock ()
{
  clib_rwlock_reader_unlock (&quic_main.half_open_rwlock);
}

int
quic_connect (transport_endpoint_t * tep)
{
  session_endpoint_extended_t *sep;
  session_endpoint_t quic_sep;
  quic_main_t *tm = &quic_main;
  application_t *app;
  quic_ctx_t *ctx;
  u32 ctx_index;
  int rv;

  sep = (session_endpoint_extended_t *) tep;
  app = application_get (sep->app_index);

  ctx_index = quic_ctx_half_open_alloc ();
  ctx = quic_ctx_half_open_get (ctx_index);
  ctx->quic_parent_app_index = sep->app_index;
  ctx->quic_parent_app_api_context = sep->opaque;
  ctx->quic_udp_is_ip4 = sep->is_ip4;
  if (sep->hostname)
    {
      ctx->srv_hostname = format (0, "%v", sep->hostname);
      vec_terminate_c_string (ctx->srv_hostname);
    }
  quic_ctx_half_open_reader_unlock ();

  application_alloc_connects_segment_manager (app);

  clib_memcpy (&quic_sep, sep, sizeof (quic_sep));
  quic_sep.transport_proto = TRANSPORT_PROTO_UDP;
  if ((rv = application_connect (tm->app_index, ctx_index, &quic_sep)))
    return rv;

  QUIC_DBG (1, "New connect request %u engine %d", ctx_index, engine_type);
  return 0;
}

/* *INDENT-OFF* */
const static transport_proto_vft_t quic_proto = {
  .open = quic_connect,
  .close = quic_disconnect,
  .bind = quic_start_listen,
  .get_connection = quic_connection_get,
  .get_listener = quic_listener_get,
  .unbind = quic_stop_listen,
  .tx_type = TRANSPORT_TX_INTERNAL,
  .service_type = TRANSPORT_SERVICE_APP,
  .format_connection = format_quic_connection,
  .format_half_open = format_quic_half_open,
  .format_listener = format_quic_listener,
};
/* *INDENT-ON* */

static void
quic_proto_init ()
{
  /* TODO: INITIALIZE CRYPTO LAYER */

  return;
}

u8
quic_configure ()
{
  return 0;
}

static int
quic_session_accept_callback (stream_session_t * new_session)
{
  return 0;
}

static int
quic_session_connected_callback (u32 app_index, u32 opaque,
				 stream_session_t * s, u8 code)
{
  return 0;
}

static void
quic_session_disconnect_callback (stream_session_t * session)
{
  return;
}

static void
quic_session_reset_callback (stream_session_t * session)
{
  return;
}

static int
quic_app_rx_callback (stream_session_t * session)
{
  return 0;
}

static int
quic_app_tx_callback (stream_session_t * session)
{
  return 0;
}

static int
quic_add_segment_callback (u32 api_client_index,
			   const ssvm_private_t * ssvm_seg)
{
  return 0;
}

static int
quic_del_segment_callback (u32 api_client_index,
			   const ssvm_private_t * ssvm_seg)
{
  return 0;
}

/* *INDENT-OFF* */
static session_cb_vft_t quic_app_cb_vft = {
  .session_accept_callback = quic_session_accept_callback,
  .session_disconnect_callback = quic_session_disconnect_callback,
  .session_connected_callback = quic_session_connected_callback,
  .session_reset_callback = quic_session_reset_callback,
  .add_segment_callback = quic_add_segment_callback,
  .del_segment_callback = quic_del_segment_callback,
  .builtin_app_rx_callback = quic_app_rx_callback,
  .builtin_app_tx_callback = quic_app_tx_callback,
};
/* *INDENT-ON* */

static clib_error_t *
quic_init (vlib_main_t * vm)
{
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

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach quic app");
      return clib_error_return (0, "failed to attach quic app");
    }

  quic_proto_init ();

  qm->app_index = a->app_index;
  clib_rwlock_init (&qm->half_open_rwlock);

  vec_validate (qm->rx_bufs, num_threads - 1);
  vec_validate (qm->tx_bufs, num_threads - 1);

  transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
			       FIB_PROTOCOL_IP6, ~0);
  vec_free (a->name);

  quic_api_reference ();

  return 0;
}

VLIB_INIT_FUNCTION (quic_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
