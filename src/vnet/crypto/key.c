/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025-2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/log.h>
#define VNET_CRYPTO_LOG_MACROS
#include <vnet/crypto/crypto.h>
#include <vnet/crypto/engine.h>
#include <vppinfra/unix.h>

VLIB_REGISTER_LOG_CLASS (crypto_log, static) = {
  .class_name = "crypto",
  .subclass_name = "key",
};

static_always_inline void
vnet_crypto_key_call (vnet_crypto_key_t *key, vnet_crypto_key_change_fn_t *fn,
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
      args.key_data = vnet_crypto_get_key_data (key, t, 0);
      fn (key, &args);
      return;
    }

  for (i = 0; i < vlib_get_n_threads (); i++)
    {
      args.action = is_add ? VNET_CRYPTO_THREAD_KEY_DATA_ADD : VNET_CRYPTO_THREAD_KEY_DATA_REMOVE;
      args.thread_index = i;
      args.thread_key_data = vnet_crypto_get_key_data_for_thread (key, t, i);
      fn (key, &args);
    }
}

void
vnet_crypto_key_layout_init (vnet_crypto_main_t *cm)
{
  vnet_crypto_engine_t *e;
  uword max_size;
  uword min_async_size;
  uword size;
  uword o;
  vnet_crypto_alg_t alg;
  vnet_crypto_handler_type_t t;
  u32 n_threads = vlib_get_n_threads ();

  FOREACH_ARRAY_ELT (kl, cm->key_layout)
    {
      alg = kl - cm->key_layout;

      o = 0;
      for (t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
	{
	  max_size = 0;
	  vec_foreach (e, cm->engines)
	    {
	      size = e->key_data_per_thread[t][alg] ?
		       (uword) e->key_data_sz[t][alg] * vlib_get_n_threads () :
		       e->key_data_sz[t][alg];
	      if (size > max_size)
		max_size = size;
	    }
	  if (t == VNET_CRYPTO_HANDLER_TYPE_ASYNC)
	    {
	      min_async_size = n_threads * 16;
	      if (max_size < min_async_size)
		max_size = min_async_size;
	    }
	  kl->key_data_size[t] = round_pow2 (max_size, CLIB_CACHE_LINE_BYTES);
	  kl->key_data_offset[t] = o;
	  o += kl->key_data_size[t];
	}
      ASSERT (o <= 0xffff);
      kl->total_key_data_size = o;
    }

  cm->layout_initialized = 1;
}

void
vnet_crypto_key_set_engine (vnet_crypto_key_t *key, vnet_crypto_handler_type_t t,
			    vnet_crypto_engine_id_t engine)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_key_layout_t *kl = cm->key_layout + key->alg;
  vnet_crypto_engine_id_t old_engine = key->engine_index[t];
  vnet_crypto_engine_t *e;
  vnet_crypto_key_change_fn_t *fn;
  u8 key_data_per_thread;
  uword key_data_size;

  if (old_engine != VNET_CRYPTO_ENGINE_ID_NONE)
    {
      e = vec_elt_at_index (cm->engines, old_engine);
      fn = e->key_change_fn[t][key->alg];
      key_data_per_thread = e->key_data_per_thread[t][key->alg];
      vnet_crypto_key_call (key, fn, t, 0, key_data_per_thread);
    }

  key->engine_index[t] = engine;
  key->key_data_stride[t] = 0;
  if (engine != VNET_CRYPTO_ENGINE_ID_NONE)
    {
      e = vec_elt_at_index (cm->engines, engine);
      if (e->key_data_per_thread[t][key->alg])
	key->key_data_stride[t] = e->key_data_sz[t][key->alg];
    }

  key_data_size = kl->key_data_size[t];
  ASSERT (key_data_size <= 0xffff);
  clib_memset_u8 (vnet_crypto_get_key_data (key, t, 0), 0, key_data_size);

  if (engine == VNET_CRYPTO_ENGINE_ID_NONE)
    return;

  e = vec_elt_at_index (cm->engines, engine);
  fn = e->key_change_fn[t][key->alg];
  key_data_per_thread = e->key_data_per_thread[t][key->alg];
  vnet_crypto_key_call (key, fn, t, 1, key_data_per_thread);
}

void
vnet_crypto_key_set_default_engine (vnet_crypto_key_t *key, vnet_crypto_handler_type_t t)
{
  vnet_crypto_main_t *cm = &crypto_main;

  vnet_crypto_key_set_engine (key, t, cm->active_engine_index[key->alg][t]);
}

void
crypto_update_key_handler_for_alg (vnet_crypto_main_t *cm, vnet_crypto_alg_t alg,
				   vnet_crypto_handler_type_t t)
{
  vnet_crypto_alg_data_t *ad = cm->algs + alg;
  u32 n_rekeyed = 0;
  vnet_crypto_engine_id_t old_ei = ad->key_fn_engine[t];
  vnet_crypto_engine_id_t ei = cm->active_engine_index[alg][t];
  vnet_crypto_engine_t *e = 0;
  const char *old_engine_name = "none";
  const char *new_engine_name = "none";
  uword i;

  if (ei == VNET_CRYPTO_ENGINE_ID_NONE)
    return;

  e = vec_elt_at_index (cm->engines, ei);
  if (e->key_change_fn[t][alg] == 0)
    return;

  if (old_ei != ei)
    {
      if (old_ei)
	old_engine_name = vec_elt_at_index (cm->engines, old_ei)->name;
      if (ei)
	new_engine_name = vec_elt_at_index (cm->engines, ei)->name;
      log_debug ("key-handler switch alg %s type %u: old-engine=%s -> new-engine=%s",
		 cm->algs[alg].name, t, old_engine_name, new_engine_name);
    }

  ad->key_change_fn[t] = e->key_change_fn[t][alg];
  ad->key_data_sz[t] = e->key_data_sz[t][alg];
  ad->key_fn_engine[t] = ei;

  for (i = 0; i < vec_len (cm->keys); i++)
    {
      vnet_crypto_key_t *key;

      if (pool_is_free_index (cm->keys, i))
	continue;
      if (cm->keys[i]->alg != alg)
	continue;
      if (old_ei != VNET_CRYPTO_ENGINE_ID_NONE)
	{
	  if (vnet_crypto_key_get_engine (cm->keys[i], t) != old_ei)
	    continue;
	}
      else if (vnet_crypto_key_get_engine (cm->keys[i], t) != ei)
	continue;

      key = cm->keys[i];
      vnet_crypto_key_set_engine (key, t, ei);
      n_rekeyed++;
    }

  if (old_ei != ei)
    log_debug ("key-handler switch alg %s type %u done: rekeyed %u key(s)", cm->algs[alg].name, t,
	       n_rekeyed);
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

void
vnet_crypto_register_key_change_handler (vlib_main_t *vm __clib_unused,
					 vnet_crypto_engine_id_t engine,
					 vnet_crypto_handler_type_t t,
					 vnet_crypto_key_change_fn_t *key_change_fn)
{
  vnet_crypto_register_key_handlers_internal (engine, t, key_change_fn);
}

int
vnet_crypto_register_async_key_change_handler (vlib_main_t *vm __clib_unused,
					       vnet_crypto_engine_id_t engine,
					       vnet_crypto_key_change_fn_t *key_change_fn,
					       u16 key_data_sz)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);
  vnet_crypto_key_layout_t *kl;
  u8 *support_vec;
  vnet_crypto_alg_t alg;

  if (key_change_fn == 0)
    return 0;

  FOREACH_ARRAY_ELT (fnp, e->key_change_fn[VNET_CRYPTO_HANDLER_TYPE_ASYNC])
    {
      alg = fnp - e->key_change_fn[VNET_CRYPTO_HANDLER_TYPE_ASYNC];
      support_vec = cm->engine_supports_alg[alg][VNET_CRYPTO_HANDLER_TYPE_ASYNC];
      if (support_vec == 0 || engine >= vec_len (support_vec) || support_vec[engine] == 0)
	continue;
      if (cm->layout_initialized)
	{
	  kl = cm->key_layout + alg;
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

static vnet_crypto_key_t *
vnet_crypto_key_alloc (u16 cipher_key_len, u16 auth_key_len, const vnet_crypto_key_layout_t *kl)
{
  vnet_crypto_main_t *cm = &crypto_main;
  u8 expected = 0;
  vnet_crypto_key_t *k, **kp;
  u16 cipher_offset, auth_offset, data_size;
  u16 key_data_offset[VNET_CRYPTO_HANDLER_N_TYPES];
  uword o;
  uword key_data_base;
  vnet_crypto_handler_type_t t;
  uword max_data_size = cipher_key_len + auth_key_len + kl->total_key_data_size + 15 + 15 +
			(CLIB_CACHE_LINE_BYTES - 1) + (CLIB_CACHE_LINE_BYTES - 1) +
			(CLIB_CACHE_LINE_BYTES - 1);
  uword key_sz = sizeof (*k) + max_data_size;

  while (!__atomic_compare_exchange_n (&cm->keys_lock, &expected, 1, 0, __ATOMIC_ACQUIRE,
				       __ATOMIC_RELAXED))
    {
      while (__atomic_load_n (&cm->keys_lock, __ATOMIC_RELAXED))
	CLIB_PAUSE ();
      expected = 0;
    }

  pool_get (cm->keys, kp);

  __atomic_store_n (&cm->keys_lock, 0, __ATOMIC_RELEASE);

  k = clib_mem_alloc_aligned (key_sz, alignof (vnet_crypto_key_t));
  kp[0] = k;
  clib_memset_u8 (k, 0, key_sz);
  o = round_pow2 ((uword) k->_key, 16) - (uword) k->_key;
  cipher_offset = o;
  o += cipher_key_len;
  o = round_pow2 ((uword) k->_key + o, 16) - (uword) k->_key;
  auth_offset = o;
  o += auth_key_len;
  key_data_base = round_pow2 ((uword) k->_key + o, CLIB_CACHE_LINE_BYTES) - (uword) k->_key;
  for (t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
    key_data_offset[t] = key_data_base + kl->key_data_offset[t];
  data_size = key_data_base + kl->total_key_data_size;
  ASSERT (data_size <= max_data_size);
  *k = (vnet_crypto_key_t){
    .index = kp - cm->keys,
    .cipher_key_sz = cipher_key_len,
    .auth_key_sz = auth_key_len,
    .cipher_key_offset = cipher_offset,
    .auth_key_offset = auth_offset,
    .key_data_offset = {
      [VNET_CRYPTO_HANDLER_TYPE_SIMPLE] = key_data_offset[VNET_CRYPTO_HANDLER_TYPE_SIMPLE],
      [VNET_CRYPTO_HANDLER_TYPE_CHAINED] = key_data_offset[VNET_CRYPTO_HANDLER_TYPE_CHAINED],
      [VNET_CRYPTO_HANDLER_TYPE_ASYNC] = key_data_offset[VNET_CRYPTO_HANDLER_TYPE_ASYNC],
    },
    .total_data_sz = data_size,
  };

  return k;
}

static_always_inline vnet_crypto_key_t *
vnet_crypto_key_add_inline (vlib_main_t *vm __clib_unused, vnet_crypto_alg_t alg,
			    const u8 *cipher_key, u16 cipher_key_len, const u8 *auth_key,
			    u16 auth_key_len)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_key_t *key;
  vnet_crypto_alg_data_t *ad = cm->algs + alg;
  vnet_crypto_handler_type_t t;

  ASSERT (alg != 0);
  ASSERT (cm->layout_initialized);

  if ((cipher_key_len == 0 && auth_key_len == 0) || (cipher_key_len && cipher_key == 0) ||
      (auth_key_len && auth_key == 0))
    return 0;

  if (ad->variable_cipher_key_length == 0 && ad->key_len != cipher_key_len)
    return 0;

  key = vnet_crypto_key_alloc (cipher_key_len, auth_key_len, cm->key_layout + alg);
  key->alg = alg;

  if (cipher_key_len)
    clib_memcpy ((u8 *) vnet_crypto_get_cipher_key (key), cipher_key, cipher_key_len);
  if (auth_key_len)
    clib_memcpy ((u8 *) vnet_crypto_get_auth_key (key), auth_key, auth_key_len);

  for (t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
    vnet_crypto_key_set_default_engine (key, t);
  return key;
}

vnet_crypto_key_t *
vnet_crypto_key_add (vlib_main_t *vm, vnet_crypto_alg_t alg, const u8 *cipher_key,
		     u16 cipher_key_len, const u8 *auth_key, u16 auth_key_len)
{
  return vnet_crypto_key_add_inline (vm, alg, cipher_key, cipher_key_len, auth_key, auth_key_len);
}

void
vnet_crypto_key_del (vlib_main_t *vm __clib_unused, vnet_crypto_key_t *key)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_handler_type_t t;
  uword key_sz = sizeof (vnet_crypto_key_t) + key->total_data_sz;
  u32 index = key->index;

  for (t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
    vnet_crypto_key_set_engine (key, t, VNET_CRYPTO_ENGINE_ID_NONE);

  clib_memset_u8 (key->_key, 0, key->total_data_sz);

  clib_memset (key, 0xfe, key_sz);
  clib_mem_free (key);
  pool_put_index (cm->keys, index);
}

void
vnet_crypto_key_update (vlib_main_t *vm __clib_unused, vnet_crypto_key_t *key)
{
  for (vnet_crypto_handler_type_t t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
    vnet_crypto_key_set_engine (key, t, vnet_crypto_key_get_engine (key, t));
}
