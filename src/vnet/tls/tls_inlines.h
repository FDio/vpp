/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TLS_TLS_INLINES_H_
#define SRC_VNET_TLS_TLS_INLINES_H_

#include <vnet/tls/tls.h>

static inline void
tls_ctx_parse_handle (u32 ctx_handle, u32 *ctx_index, u32 *engine_type)
{
  *ctx_index = ctx_handle & TLS_IDX_MASK;
  *engine_type = ctx_handle >> TLS_ENGINE_TYPE_SHIFT;
}

static inline u32
tls_ctx_alloc (crypto_engine_type_t engine_type)
{
  u32 ctx_index;
  ctx_index = tls_vfts[engine_type].ctx_alloc ();
  return (((u32) engine_type << TLS_ENGINE_TYPE_SHIFT) | ctx_index);
}

static inline u32
tls_ctx_alloc_w_thread (crypto_engine_type_t engine_type,
			clib_thread_index_t thread_index)
{
  u32 ctx_index;
  ctx_index = tls_vfts[engine_type].ctx_alloc_w_thread (thread_index);
  return (((u32) engine_type << TLS_ENGINE_TYPE_SHIFT) | ctx_index);
}

static inline tls_ctx_t *
tls_ctx_get (u32 ctx_handle)
{
  u32 ctx_index, engine_type;
  tls_ctx_parse_handle (ctx_handle, &ctx_index, &engine_type);
  return tls_vfts[engine_type].ctx_get (ctx_index);
}

static inline tls_ctx_t *
tls_ctx_get_w_thread (u32 ctx_handle, u8 thread_index)
{
  u32 ctx_index, engine_type;
  tls_ctx_parse_handle (ctx_handle, &ctx_index, &engine_type);
  return tls_vfts[engine_type].ctx_get_w_thread (ctx_index, thread_index);
}

static inline void
tls_ctx_free (tls_ctx_t *ctx)
{
  tls_vfts[ctx->tls_ctx_engine].ctx_free (ctx);
}

static inline int
tls_ctx_init_server (tls_ctx_t *ctx)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_init_server (ctx);
}

static inline int
tls_ctx_init_client (tls_ctx_t *ctx)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_init_client (ctx);
}

static inline u32
tls_ctx_attach (crypto_engine_type_t engine_type,
		clib_thread_index_t thread_index, void *ctx)
{
  u32 ctx_index;
  ctx_index = tls_vfts[engine_type].ctx_attach (thread_index, ctx);
  return (((u32) engine_type << TLS_ENGINE_TYPE_SHIFT) | ctx_index);
}

static inline void *
tls_ctx_detach (tls_ctx_t *ctx)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_detach (ctx);
}

static inline int
tls_ctx_write (tls_ctx_t *ctx, session_t *app_session,
	       transport_send_params_t *sp)
{
  u32 n_wrote;

  sp->max_burst_size = sp->max_burst_size * TRANSPORT_PACER_MIN_MSS;
  n_wrote = tls_vfts[ctx->tls_ctx_engine].ctx_write (ctx, app_session, sp);
  sp->bytes_dequeued = n_wrote;
  return n_wrote > 0 ? clib_max (n_wrote / TRANSPORT_PACER_MIN_MSS, 1) : 0;
}

static inline int
tls_ctx_read (tls_ctx_t *ctx, session_t *tls_session)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_read (ctx, tls_session);
}

static inline int
tls_ctx_transport_close (tls_ctx_t *ctx)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_transport_close (ctx);
}

static inline int
tls_ctx_transport_reset (tls_ctx_t *ctx)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_transport_reset (ctx);
}

static inline int
tls_ctx_app_close (tls_ctx_t *ctx)
{
  return tls_vfts[ctx->tls_ctx_engine].ctx_app_close (ctx);
}

static inline int
tls_reinit_ca_chain (crypto_engine_type_t tls_engine_id)
{
  return tls_vfts[tls_engine_id].ctx_reinit_cachain ();
}

#endif /* SRC_VNET_TLS_TLS_INLINES_H_ */