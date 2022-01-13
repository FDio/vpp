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

#include <http/http.h>
#include <vnet/session/session.h>

static http_main_t http_main;

static inline u32
http_ctx_alloc_w_thread (u32 thread_index)
{
  http_tc_t *ctx;
  pool_get_zero (http_main.ctx_pool[thread_index], ctx);
  ctx->c_thread_index = thread_index;
  ctx->h_ctx_handle = ctx - http_main.ctx_pool[thread_index];
  ctx->h_pa_session_handle = SESSION_INVALID_HANDLE;
  return ctx->h_ctx_handle;
}

static inline http_tc_t *
http_ctx_get_w_thread (u32 ctx_index, u32 thread_index)
{
  return pool_elt_at_index (http_main.ctx_pool[thread_index], ctx_index);
}

void
http_ctx_free (http_tc_t *ctx)
{
  pool_put (http_main.ctx_pool[ctx->c_thread_index], ctx);
}

static u32
http_listener_ctx_alloc (void)
{
  http_main_t *sm = &http_main;
  http_tc_t *ctx;

  pool_get_zero (sm->listener_ctx_pool, ctx);
  ctx->c_c_index = ctx - sm->listener_ctx_pool;
  return ctx->c_c_index;
}

http_tc_t *
http_listener_ctx_get (u32 ctx_index)
{
  return pool_elt_at_index (http_main.listener_ctx_pool, ctx_index);
}

int
http_session_accept_callback (session_t *ts)
{
  session_t *ts_listener, *app_session;
  http_tc_t *lctx, *ctx;
  u32 ctx_handle;

  ts_listener = listen_session_get_from_handle (ts->listener_handle);
  lctx = http_listener_ctx_get (ts_listener->opaque);

  ctx_handle = http_ctx_alloc_w_thread (ts->thread_index);
  ctx = http_ctx_get_w_thread (ctx_handle, ts->thread_index);
  clib_memcpy_fast (ctx, lctx, sizeof (*lctx));
  ctx->c_thread_index = vlib_get_thread_index ();
  ctx->h_ctx_handle = ctx_handle;
  ts->session_state = SESSION_STATE_READY;
  ts->opaque = ctx_handle;
  ctx->h_tc_session_handle = session_handle (ts);
  ctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;

  app_session = session_alloc (ctx->c_thread_index);
  app_session->session_state = SESSION_STATE_CREATED;
  ctx->c_s_index = app_session->session_index;

  HTTP_DBG (1, "Accept on listener %u new connection [%u]%x",
	    ts_listener->opaque, vlib_get_thread_index (), ctx_handle);

  return 0;
}

int
http_add_segment_callback (u32 client_index, u64 segment_handle)
{
  /* No-op for builtin */
  return 0;
}

int
http_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

int
http_app_rx_callback (session_t *ts)
{
  http_tc_t *ctx;

  ctx = http_ctx_get_w_thread (ts->opaque, ts->thread_index);
  // TODO
  return 0;
}

int
http_app_tx_callback (session_t *ts)
{
  http_tc_t *ctx;

  ctx = http_ctx_get_w_thread (ts->opaque, ts->thread_index);
  transport_connection_reschedule (&ctx->connection);

  // TODO
  return 0;
}

static session_cb_vft_t http_app_cb_vft = {
  .session_accept_callback = http_session_accept_callback,
//  .session_disconnect_callback = http_session_disconnect_callback,
//  .session_connected_callback = http_session_connected_callback,
//  .session_reset_callback = http_session_reset_callback,
  .add_segment_callback = http_add_segment_callback,
  .del_segment_callback = http_del_segment_callback,
  .builtin_app_rx_callback = http_app_rx_callback,
  .builtin_app_tx_callback = http_app_tx_callback,
};

static clib_error_t *
http_enable (vlib_main_t *vm, u8 is_en)
{
  u32 add_segment_size = 256 << 20, first_seg_size = 32 << 20;
  vnet_app_detach_args_t _da, *da = &_da;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  http_main_t *sm = &http_main;
  u32 fifo_size = 128 << 12;

  if (!is_en)
    {
      da->app_index = sm->app_index;
      da->api_client_index = APP_INVALID_INDEX;
      vnet_application_detach (da);
      return 0;
    }

  vec_validate (sm->ctx_pool, vlib_num_workers ());

  first_seg_size = sm->first_seg_size ? sm->first_seg_size : first_seg_size;
  fifo_size = sm->fifo_size ? sm->fifo_size : fifo_size;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->session_cb_vft = &http_app_cb_vft;
  a->api_client_index = APP_INVALID_INDEX;
  a->options = options;
  a->name = format (0, "http");
  a->options[APP_OPTIONS_SEGMENT_SIZE] = first_seg_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = add_segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_IS_TRANSPORT_APP;

  if (vnet_application_attach (a))
    return clib_error_return (0, "failed to attach http app");

  sm->app_index = a->app_index;
  vec_free (a->name);

  return 0;
}

static int
http_connect (transport_endpoint_cfg_t *tep)
{
  return 0;
}

static u32
http_start_listen (u32 app_listener_index, transport_endpoint_t *tep)
{
  vnet_listen_args_t _args = {}, *args = &_args;
  session_endpoint_cfg_t *sep;
  session_t *tc_listener, *app_listener;
  app_listener_t *al;
  http_tc_t *lctx;
  u32 lctx_index;

  sep = (session_endpoint_cfg_t *) tep;
  /* TODO maybe use it to configure flavor of http */
  if (sep->ext_cfg)
    {
      clib_warning ("not supported");
      return SESSION_E_NOSUPPORT;
    }

  if (vnet_listen (args))
    return SESSION_INVALID_INDEX;

  lctx_index = http_listener_ctx_alloc ();
  lctx = http_listener_ctx_get (lctx_index);

  /* Grab transport connection listener and link to http listener */
  lctx->h_tc_session_handle = args->handle;
  al = app_listener_get_w_handle (lctx->h_tc_session_handle);
  tc_listener = app_listener_get_session (al);
  tc_listener->opaque = lctx_index;

  /* Grab application listener and link to http listener */
  app_listener = listen_session_get (app_listener_index);
  lctx->h_pa_wrk_index = sep->app_wrk_index;
  lctx->h_pa_session_handle = listen_session_get_handle (app_listener);

  return lctx_index;
}

static const transport_proto_vft_t http_proto = {
  .enable = http_enable,
  .connect = http_connect,
  .start_listen = http_start_listen,
  .transport_options = {
    .name = "http",
    .short_name = "H",
    .tx_type = TRANSPORT_TX_INTERNAL,
    .service_type = TRANSPORT_SERVICE_APP,
  },
};

static clib_error_t *
http_transport_init (vlib_main_t *vm)
{
  transport_register_protocol (TRANSPORT_PROTO_HTTP, &http_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_HTTP, &http_proto,
			       FIB_PROTOCOL_IP6, ~0);
  return 0;
}

VLIB_INIT_FUNCTION (http_transport_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Hypertext Transfer Protocol (HTTP)",
  .default_disabled = 0,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
