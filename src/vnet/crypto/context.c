/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025-2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/log.h>
#define VNET_CRYPTO_LOG_MACROS
#include <vnet/api_errno.h>
#include <vnet/crypto/crypto.h>
#include <vnet/crypto/engine.h>
#include <vppinfra/unix.h>

VLIB_REGISTER_LOG_CLASS (crypto_log, static) = {
  .class_name = "crypto",
  .subclass_name = "ctx",
};

static_always_inline void
vnet_crypto_key_call (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_fn_t *fn,
		      vnet_crypto_handler_type_t t, u8 is_add, u8 key_data_per_thread)
{
  vnet_crypto_key_change_args_t args = {
    .handler_type = t,
  };
  u32 i;

  if (fn == 0)
    return;

  if (key_data_per_thread == 0)
    {
      args.action = is_add ? VNET_CRYPTO_KEY_DATA_ADD : VNET_CRYPTO_KEY_DATA_REMOVE;
      args.key_data = vnet_crypto_get_key_data (ctx, t, 0);
      fn (ctx, &args);
      return;
    }

  for (i = 0; i < vlib_get_n_threads (); i++)
    {
      args.action = is_add ? VNET_CRYPTO_THREAD_KEY_DATA_ADD : VNET_CRYPTO_THREAD_KEY_DATA_REMOVE;
      args.thread_index = i;
      args.thread_key_data = vnet_crypto_get_key_data_for_thread (ctx, t, i);
      fn (ctx, &args);
    }
}

static_always_inline void
vnet_crypto_ctx_update_handlers (vnet_crypto_ctx_t *ctx, vnet_crypto_handler_type_t t,
				 vnet_crypto_engine_t *e)
{
  vnet_crypto_op_type_t type;

  for (type = 0; type < VNET_CRYPTO_OP_N_TYPES; type++)
    ctx->handlers[type][t] = e->ops[ctx->alg][type].handlers[t];
}

void
vnet_crypto_ctx_set_engine (vnet_crypto_ctx_t *ctx, vnet_crypto_handler_type_t t,
			    vnet_crypto_engine_id_t engine)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_ctx_layout_t *kl = cm->ctx_layout + ctx->alg;
  vnet_crypto_engine_id_t old_engine = ctx->engine_index[t];
  vnet_crypto_engine_t *e;
  vnet_crypto_key_change_fn_t *fn;
  u8 key_data_per_thread;
  uword key_data_size;

  if (old_engine != VNET_CRYPTO_ENGINE_ID_NONE)
    {
      e = vec_elt_at_index (cm->engines, old_engine);
      fn = e->key_change_fn[t][ctx->alg];
      key_data_per_thread = e->key_data_per_thread[t][ctx->alg];
      vnet_crypto_key_call (ctx, fn, t, 0, key_data_per_thread);
    }

  ctx->engine_index[t] = engine;
  ctx->key_data_stride[t] = 0;
  if (engine != VNET_CRYPTO_ENGINE_ID_NONE)
    {
      e = vec_elt_at_index (cm->engines, engine);
      if (e->key_data_per_thread[t][ctx->alg])
	ctx->key_data_stride[t] = e->key_data_sz[t][ctx->alg];
      vnet_crypto_ctx_update_handlers (ctx, t, e);
    }
  else
    {
      for (vnet_crypto_op_type_t type = 0; type < VNET_CRYPTO_OP_N_TYPES; type++)
	ctx->handlers[type][t] = 0;
    }

  key_data_size = kl->key_data_size[t];
  ASSERT (key_data_size <= CLIB_U16_MAX);
  clib_memset_u8 (vnet_crypto_get_key_data (ctx, t, 0), 0, key_data_size);

  if (engine == VNET_CRYPTO_ENGINE_ID_NONE)
    return;

  e = vec_elt_at_index (cm->engines, engine);
  fn = e->key_change_fn[t][ctx->alg];
  key_data_per_thread = e->key_data_per_thread[t][ctx->alg];
  vnet_crypto_key_call (ctx, fn, t, 1, key_data_per_thread);
}

void
vnet_crypto_ctx_set_default_engine (vnet_crypto_ctx_t *ctx, vnet_crypto_handler_type_t t)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_ctx_layout_t *kl = cm->ctx_layout + ctx->alg;
  vnet_crypto_engine_id_t engine;
  vnet_crypto_engine_t *e;
  vnet_crypto_key_change_fn_t *fn;
  u8 key_data_per_thread;
  uword key_data_size;
  vnet_crypto_op_type_t type;

  ctx->engine_index[t] = VNET_CRYPTO_ENGINE_ID_NONE;
  ctx->key_data_stride[t] = 0;

  for (type = 0; type < VNET_CRYPTO_OP_N_TYPES; type++)
    {
      engine = cm->active_op_engine_index[ctx->alg][type][t];
      if (engine != VNET_CRYPTO_ENGINE_ID_NONE)
	{
	  e = vec_elt_at_index (cm->engines, engine);
	  ctx->handlers[type][t] = e->ops[ctx->alg][type].handlers[t];
	}
      else
	ctx->handlers[type][t] = 0;
    }

  key_data_size = kl->key_data_size[t];
  ASSERT (key_data_size <= CLIB_U16_MAX);
  clib_memset_u8 (vnet_crypto_get_key_data (ctx, t, 0), 0, key_data_size);

  if (ctx->cipher_key_sz == 0 && ctx->auth_key_sz == 0)
    return;

  engine = cm->algs[ctx->alg].key_fn_engine[t];
  if (engine == VNET_CRYPTO_ENGINE_ID_NONE)
    return;

  e = vec_elt_at_index (cm->engines, engine);
  if (e->key_data_per_thread[t][ctx->alg])
    ctx->key_data_stride[t] = e->key_data_sz[t][ctx->alg];
  fn = e->key_change_fn[t][ctx->alg];
  key_data_per_thread = e->key_data_per_thread[t][ctx->alg];
  vnet_crypto_key_call (ctx, fn, t, 1, key_data_per_thread);
}

void
vnet_crypto_register_key_handler_for_alg (vnet_crypto_engine_id_t engine, vnet_crypto_alg_t alg,
					  vnet_crypto_handler_type_t t,
					  vnet_crypto_key_change_fn_t *key_change_fn,
					  u16 key_data_sz, u8 key_data_per_thread)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + alg;
  vnet_crypto_engine_t *new_engine;

  if (key_change_fn == 0 || alg >= VNET_CRYPTO_N_ALGS)
    return;

  new_engine = vec_elt_at_index (cm->engines, engine);

  new_engine->key_change_fn[t][alg] = key_change_fn;
  new_engine->key_data_sz[t][alg] =
    key_data_per_thread ? round_pow2 (key_data_sz, 16) : key_data_sz;
  new_engine->key_data_per_thread[t][alg] = key_data_per_thread;

  if (ad->key_change_fn[t] == 0)
    {
      ad->key_change_fn[t] = key_change_fn;
      ad->key_data_sz[t] = new_engine->key_data_sz[t][alg];
      ad->key_fn_engine[t] = engine;
      return;
    }

  if (cm->active_engine_index[alg][t] == engine)
    {
      ad->key_change_fn[t] = key_change_fn;
      ad->key_data_sz[t] = new_engine->key_data_sz[t][alg];
      ad->key_fn_engine[t] = engine;
    }
}

void
vnet_crypto_register_key_handlers_internal (vnet_crypto_engine_id_t engine,
					    vnet_crypto_handler_type_t t,
					    vnet_crypto_key_change_fn_t *key_change_fn)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e;
  vnet_crypto_key_change_fn_t *fn;
  vnet_crypto_alg_t alg;

  e = vec_elt_at_index (cm->engines, engine);

  FOREACH_ARRAY_ELT (fnp, e->key_change_fn[t])
    {
      alg = fnp - e->key_change_fn[t];
      fn = key_change_fn ? key_change_fn : fnp[0];
      vnet_crypto_register_key_handler_for_alg (engine, alg, t, fn, e->key_data_sz[t][alg],
						e->key_data_per_thread[t][alg]);
    }
}

int
vnet_crypto_register_key_change_handler (vlib_main_t *vm __clib_unused,
					 vnet_crypto_engine_id_t engine,
					 vnet_crypto_key_change_fn_t *key_change_fn,
					 u16 key_data_sz)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);
  vnet_crypto_ctx_layout_t *kl;
  u8 *support_vec;
  vnet_crypto_alg_t alg;

  if (key_change_fn == 0)
    return 0;

  for (alg = 0; alg < VNET_CRYPTO_N_ALGS; alg++)
    {
      support_vec = cm->engine_supports_alg[alg][VNET_CRYPTO_HANDLER_TYPE_ASYNC];
      if (support_vec == 0 || engine >= vec_len (support_vec) || support_vec[engine] == 0)
	continue;
      if (cm->layout_initialized)
	{
	  kl = cm->ctx_layout + alg;
	  if (key_data_sz > kl->key_data_size[VNET_CRYPTO_HANDLER_TYPE_ASYNC])
	    {
	      log_err ("async key data registration failed for alg %s: requested %u, reserved %u",
		       cm->algs[alg].name ? cm->algs[alg].name : "unknown", key_data_sz,
		       kl->key_data_size[VNET_CRYPTO_HANDLER_TYPE_ASYNC]);
	      return -1;
	    }
	}
      e->key_change_fn[VNET_CRYPTO_HANDLER_TYPE_ASYNC][alg] = key_change_fn;
      e->key_data_sz[VNET_CRYPTO_HANDLER_TYPE_ASYNC][alg] = key_data_sz;
      e->key_data_per_thread[VNET_CRYPTO_HANDLER_TYPE_ASYNC][alg] = 0;
      vnet_crypto_register_key_handler_for_alg (engine, alg, VNET_CRYPTO_HANDLER_TYPE_ASYNC,
						key_change_fn, key_data_sz, 0);
    }

  return 0;
}

static vnet_crypto_ctx_t *
vnet_crypto_ctx_alloc (const vnet_crypto_ctx_layout_t *kl)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_ctx_t *ctx, **ctxp;
  uword o = 0;
  uword key_data_base;
  uword key_sz;
  vnet_crypto_handler_type_t t;
  vnet_crypto_ctx_t tmpl = {};

  tmpl.auth_key_offset = kl->cipher_key_len;

  o = kl->cipher_key_len + kl->auth_key_len;
  key_data_base = round_pow2 (o, CLIB_CACHE_LINE_BYTES);
  for (t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
    tmpl.key_data_offset[t] = key_data_base + kl->key_data_offset[t];
  tmpl.total_data_sz = key_data_base + kl->total_key_data_size;
  key_sz = sizeof (*ctx) + tmpl.total_data_sz;

  CLIB_SPINLOCK_LOCK (cm->ctx_pool_lock);
  pool_get (cm->ctxs, ctxp);
  CLIB_SPINLOCK_UNLOCK (cm->ctx_pool_lock);

  ctx = clib_mem_alloc_aligned (key_sz, alignof (vnet_crypto_ctx_t));
  ctxp[0] = ctx;
  clib_memset_u8 (ctx, 0, key_sz);
  tmpl.index = ctxp - cm->ctxs;
  *ctx = tmpl;

  return ctx;
}

static_always_inline int
vnet_crypto_ctx_set_key_internal (vnet_crypto_ctx_t *ctx, const u8 *key, u16 key_len, u8 is_auth)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + ctx->alg;
  u16 max_key_len = is_auth ? ad->auth_key_len : ad->cipher_key_len;
  u8 *dst = ctx->_data + (is_auth ? ctx->auth_key_offset : 0);
  u8 *old_auth_key = 0;
  u8 *new_auth_key = 0;
  const char *key_name = is_auth ? "auth" : "cipher";

  if (is_auth && ad->variable_auth_key_len)
    max_key_len = CLIB_U16_MAX;

  if ((key_len && key == 0) || key_len > max_key_len)
    {
      log_err ("ctx %u alg %s invalid %s key: len %u max %u", ctx->index, ad->name, key_name,
	       key_len, max_key_len);
      return 0;
    }

  if (is_auth == 0 && key_len && ad->cipher_key_len != key_len)
    {
      log_err ("ctx %u alg %s invalid cipher key length %u expected %u", ctx->index, ad->name,
	       key_len, ad->cipher_key_len);
      return 0;
    }
  if (is_auth && ad->variable_auth_key_len == 0 && key_len && max_key_len != key_len)
    {
      log_err ("ctx %u alg %s invalid auth key length %u expected %u", ctx->index, ad->name,
	       key_len, max_key_len);
      return 0;
    }

  if (is_auth && key_len > ad->auth_key_len)
    {
      if (key_len)
	new_auth_key = clib_mem_alloc (key_len);
      if (ctx->indirect_auth_key)
	old_auth_key = *(u8 **) dst;
      else
	clib_memset_u8 (dst, 0, ad->auth_key_len);
      if (new_auth_key)
	clib_memcpy (new_auth_key, key, key_len);
      *(u8 **) dst = new_auth_key;
      ctx->indirect_auth_key = 1;
    }
  else
    {
      if (is_auth && ctx->indirect_auth_key)
	{
	  old_auth_key = *(u8 **) dst;
	  ctx->indirect_auth_key = 0;
	}
      clib_memset_u8 (dst, 0, is_auth ? ad->auth_key_len : max_key_len);
      if (key_len)
	clib_memcpy (dst, key, key_len);
    }

  if (old_auth_key)
    {
      clib_memset_u8 (old_auth_key, 0, ctx->auth_key_sz);
      clib_mem_free (old_auth_key);
    }

  if (is_auth)
    ctx->auth_key_sz = key_len;
  else
    ctx->cipher_key_sz = key_len;

  for (vnet_crypto_handler_type_t t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
    {
      if (vnet_crypto_ctx_get_engine (ctx, t) == VNET_CRYPTO_ENGINE_ID_NONE)
	vnet_crypto_ctx_set_default_engine (ctx, t);
      else
	vnet_crypto_ctx_set_engine (ctx, t, vnet_crypto_ctx_get_engine (ctx, t));
    }
  return 1;
}

vnet_crypto_ctx_t *
vnet_crypto_ctx_create (vnet_crypto_alg_t alg)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_ctx_t *ctx;
  vnet_crypto_handler_type_t t;

  ASSERT (alg != 0);
  ASSERT (cm->layout_initialized);

  ctx = vnet_crypto_ctx_alloc (cm->ctx_layout + alg);
  ctx->alg = alg;

  for (t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
    vnet_crypto_ctx_set_default_engine (ctx, t);

  return ctx;
}

int
vnet_crypto_ctx_set_cipher_key (vnet_crypto_ctx_t *ctx, const u8 *cipher_key, u16 cipher_key_len)
{
  return vnet_crypto_ctx_set_key_internal (ctx, cipher_key, cipher_key_len, 0);
}

int
vnet_crypto_ctx_set_auth_key (vnet_crypto_ctx_t *ctx, const u8 *auth_key, u16 auth_key_len)
{
  return vnet_crypto_ctx_set_key_internal (ctx, auth_key, auth_key_len, 1);
}

void
vnet_crypto_ctx_destroy (vlib_main_t *vm __clib_unused, vnet_crypto_ctx_t *ctx)
{
  vnet_crypto_main_t *cm = &crypto_main;
  u8 **indirect_auth_key = 0;
  vnet_crypto_handler_type_t t;
  uword key_sz = sizeof (vnet_crypto_ctx_t) + ctx->total_data_sz;
  u32 index = ctx->index;

  for (t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
    vnet_crypto_ctx_set_engine (ctx, t, VNET_CRYPTO_ENGINE_ID_NONE);

  if (ctx->indirect_auth_key)
    {
      indirect_auth_key = (u8 **) (ctx->_data + ctx->auth_key_offset);
      if (indirect_auth_key[0])
	{
	  clib_memset_u8 (indirect_auth_key[0], 0, ctx->auth_key_sz);
	  clib_mem_free (indirect_auth_key[0]);
	  indirect_auth_key[0] = 0;
	}
    }

  clib_memset_u8 (ctx->_data, 0, ctx->total_data_sz);

  clib_memset (ctx, 0xfe, key_sz);
  clib_mem_free (ctx);
  pool_put_index (cm->ctxs, index);
}
