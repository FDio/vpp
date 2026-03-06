/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <stdbool.h>
#include <string.h>
#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>
#include <vnet/crypto/engine.h>
#include <vppinfra/unix.h>
#include <vlib/log.h>
#include <dlfcn.h>
#include <dirent.h>

VLIB_REGISTER_LOG_CLASS (crypto_main_log, static) = {
  .class_name = "crypto",
  .subclass_name = "main",
};

#define log_debug(f, ...)                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, crypto_main_log.class, f, ##__VA_ARGS__)
#define log_notice(f, ...)                                                    \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, crypto_main_log.class, f, ##__VA_ARGS__)
#define log_err(f, ...)                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, crypto_main_log.class, f, ##__VA_ARGS__)

static_always_inline void
crypto_set_op_status (vnet_crypto_op_t * ops[], u32 n_ops, int status)
{
  while (n_ops--)
    {
      ops[0]->status = status;
      ops++;
    }
}

static_always_inline void
vnet_crypto_key_call (vnet_crypto_key_t *key, vnet_crypto_key_data_t *key_data,
		      vnet_crypto_key_data_fn_t *fn, u8 key_data_per_thread, u16 key_data_sz)
{
  u32 i;

  if (fn == 0)
    return;

  if (key_data_per_thread == 0)
    {
      fn (key, key_data);
      return;
    }

  for (i = 0; i < vlib_get_thread_main ()->n_vlib_mains; i++)
    {
      uword offset = i * key_data_sz;
      fn (key, (vnet_crypto_key_data_t *) ((u8 *) key_data + offset));
    }
}

static_always_inline vnet_crypto_key_data_t *
vnet_crypto_get_key_data_ptr (vnet_crypto_main_t *cm, vnet_crypto_key_t *key,
			      vnet_crypto_handler_type_t t, uword per_thread_offset)
{
  return (vnet_crypto_key_data_t *) ((u8 *) &key->key_data + cm->key_data_offset[t] +
				     per_thread_offset);
}

static_always_inline u32
vnet_crypto_process_ops_call_handler (vlib_main_t * vm,
				      vnet_crypto_main_t * cm,
				      vnet_crypto_op_id_t opt,
				      vnet_crypto_op_t * ops[],
				      vnet_crypto_op_chunk_t * chunks,
				      u32 n_ops)
{
  vnet_crypto_op_data_t *od = cm->opt_data + opt;
  vnet_crypto_key_data_t *key_data[VLIB_FRAME_SIZE];
  vnet_crypto_alg_data_t *ad = cm->algs + od->alg;
  vnet_crypto_handler_type_t t =
    chunks ? VNET_CRYPTO_HANDLER_TYPE_CHAINED : VNET_CRYPTO_HANDLER_TYPE_SIMPLE;
  uword key_data_offset = 0;
  u32 rv = 0;
  u32 i;
  if (n_ops == 0)
    return 0;

  if (ad->key_data_per_thread[t])
    key_data_offset = vm->thread_index * ad->key_data_sz[t];

  for (i = 0; i < n_ops; i++)
    {
      if (od->type == VNET_CRYPTO_OP_TYPE_HASH)
	{
	  key_data[i] = 0;
	  continue;
	}

      key_data[i] =
	vnet_crypto_get_key_data_ptr (cm, cm->keys[ops[i]->key_index], t, key_data_offset);
    }

  if (chunks)
    {
      vnet_crypto_chained_op_fn_t *fn =
	od->handlers[VNET_CRYPTO_HANDLER_TYPE_CHAINED];

      if (fn == 0)
	crypto_set_op_status (ops, n_ops,
			      VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER);
      else
	rv = fn (ops, chunks, key_data, n_ops);
    }
  else
    {
      vnet_crypto_simple_op_fn_t *fn =
	od->handlers[VNET_CRYPTO_HANDLER_TYPE_SIMPLE];
      if (fn == 0)
	crypto_set_op_status (ops, n_ops,
			      VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER);
      else
	rv = fn (ops, key_data, n_ops);
    }
  return rv;
}

static_always_inline u32
vnet_crypto_process_ops_inline (vlib_main_t * vm, vnet_crypto_op_t ops[],
				vnet_crypto_op_chunk_t * chunks, u32 n_ops)
{
  vnet_crypto_main_t *cm = &crypto_main;
  const int op_q_size = VLIB_FRAME_SIZE;
  vnet_crypto_op_t *op_queue[op_q_size];
  vnet_crypto_op_id_t opt, current_op_type = ~0;
  u32 n_op_queue = 0;
  u32 rv = 0, i;

  ASSERT (n_ops >= 1);

  for (i = 0; i < n_ops; i++)
    {
      opt = ops[i].op;

      if (current_op_type != opt || n_op_queue >= op_q_size)
	{
	  rv += vnet_crypto_process_ops_call_handler (vm, cm, current_op_type,
						      op_queue, chunks,
						      n_op_queue);
	  n_op_queue = 0;
	  current_op_type = opt;
	}

      op_queue[n_op_queue++] = &ops[i];
    }

  rv += vnet_crypto_process_ops_call_handler (vm, cm, current_op_type,
					      op_queue, chunks, n_op_queue);
  return rv;
}

u32
vnet_crypto_process_ops (vlib_main_t * vm, vnet_crypto_op_t ops[], u32 n_ops)
{
  return vnet_crypto_process_ops_inline (vm, ops, 0, n_ops);
}

u32
vnet_crypto_process_chained_ops (vlib_main_t * vm, vnet_crypto_op_t ops[],
				 vnet_crypto_op_chunk_t * chunks, u32 n_ops)
{
  return vnet_crypto_process_ops_inline (vm, ops, chunks, n_ops);
}

u32
vnet_crypto_register_engine (vlib_main_t * vm, char *name, int prio,
			     char *desc)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *p;

  vec_add2 (cm->engines, p, 1);
  p->name = name;
  p->desc = desc;
  p->priority = prio;

  hash_set_mem (cm->engine_index_by_name, p->name, p - cm->engines);

  return p - cm->engines;
}

static_always_inline void
crypto_set_active_engine (vnet_crypto_op_data_t *od, vnet_crypto_op_id_t id,
			  u32 ei, vnet_crypto_handler_type_t t)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *ce = vec_elt_at_index (cm->engines, ei);

  if (ce->ops[id].handlers[t])
    {
      od->active_engine_index[t] = ei;
      cm->opt_data[id].handlers[t] = ce->ops[id].handlers[t];
    }
}

static_always_inline int
crypto_engine_is_active_for_alg (vnet_crypto_main_t *cm, vnet_crypto_alg_t alg, u32 engine_index,
				 vnet_crypto_handler_type_t t)
{
  int i;

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    {
      vnet_crypto_op_id_t id = cm->algs[alg].op_by_type[i];
      vnet_crypto_op_data_t *od;

      if (id == 0)
	continue;

      od = cm->opt_data + id;
      if (od->active_engine_index[t] == engine_index)
	return 1;
    }

  return 0;
}

static_always_inline u32
crypto_get_bound_engine_for_alg_type (vnet_crypto_main_t *cm, vnet_crypto_alg_t alg,
				      vnet_crypto_handler_type_t t)
{
  int i;

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    {
      vnet_crypto_op_id_t id = cm->algs[alg].op_by_type[i];
      vnet_crypto_op_data_t *od;

      if (id == 0)
	continue;

      od = cm->opt_data + id;
      if (od->active_engine_index[t])
	return od->active_engine_index[t];
    }

  return 0;
}

static_always_inline u32
crypto_get_active_engine_for_alg (vnet_crypto_main_t *cm, vnet_crypto_alg_t alg,
				  vnet_crypto_handler_type_t t)
{
  int i;

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    {
      vnet_crypto_op_id_t id = cm->algs[alg].op_by_type[i];
      vnet_crypto_op_data_t *od;

      if (id == 0)
	continue;

      od = cm->opt_data + id;
      if (od->active_engine_index[t])
	return od->active_engine_index[t];
    }

  return 0;
}

static void
crypto_update_key_handler_for_alg (vnet_crypto_main_t *cm, vnet_crypto_alg_t alg,
				   vnet_crypto_handler_type_t t)
{
  vnet_crypto_alg_data_t *ad = cm->algs + alg;
  vnet_crypto_key_data_fn_t *old_key_del_fn;
  u16 old_key_data_sz;
  u8 old_key_data_per_thread;
  u32 n_rekeyed = 0;
  u32 old_ei = ad->key_fn_engine[t];
  u32 ei = crypto_get_active_engine_for_alg (cm, alg, t);
  vnet_crypto_engine_t *e = 0;
  const char *old_engine_name = "none";
  const char *new_engine_name = "none";
  uword i;

  if (ei == 0)
    return;

  e = vec_elt_at_index (cm->engines, ei);
  if (e->key_add_fn[t][alg] == 0 && e->key_del_fn[t][alg] == 0)
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

  old_key_del_fn = ad->key_del_fn[t];
  old_key_data_sz = ad->key_data_sz[t];
  old_key_data_per_thread = ad->key_data_per_thread[t];

  ad->key_add_fn[t] = e->key_add_fn[t][alg];
  ad->key_del_fn[t] = e->key_del_fn[t][alg];
  ad->key_data_sz[t] = e->key_data_sz[t][alg];
  ad->key_data_per_thread[t] = e->key_data_per_thread[t][alg];
  ad->key_fn_engine[t] = ei;

  for (i = 0; i < vec_len (cm->keys); i++)
    {
      vnet_crypto_key_data_t *key_data;

      if (pool_is_free_index (cm->keys, i))
	continue;
      if (cm->keys[i]->alg != alg)
	continue;

      key_data = vnet_crypto_get_key_data_ptr (cm, cm->keys[i], t, 0);
      vnet_crypto_key_call (cm->keys[i], key_data, old_key_del_fn, old_key_data_per_thread,
			    old_key_data_sz);
      clib_memset_u8 (key_data, 0, cm->key_data_size[t]);
      vnet_crypto_key_call (cm->keys[i], key_data, ad->key_add_fn[t], ad->key_data_per_thread[t],
			    ad->key_data_sz[t]);
      n_rekeyed++;
    }

  if (old_ei != ei)
    log_debug ("key-handler switch alg %s type %u done: rekeyed %u key(s)", cm->algs[alg].name, t,
	       n_rekeyed);
}

int
vnet_crypto_set_handlers (vnet_crypto_set_handlers_args_t *a)
{
  uword *p;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad;
  int i;

  p = hash_get_mem (cm->alg_index_by_name, a->handler_name);
  if (!p)
    return -1;

  ad = cm->algs + p[0];

  p = hash_get_mem (cm->engine_index_by_name, a->engine);
  if (!p)
    return -1;

  if (a->set_simple || a->set_chained)
    {
      for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
	{
	  vnet_crypto_op_id_t id = ad->op_by_type[i];

	  if (id == 0)
	    continue;

	  if (a->set_simple && vec_elt_at_index (cm->engines, p[0])
				   ->ops[id]
				   .handlers[VNET_CRYPTO_HANDLER_TYPE_SIMPLE] == 0)
	    return -1;

	  if (a->set_chained && vec_elt_at_index (cm->engines, p[0])
				    ->ops[id]
				    .handlers[VNET_CRYPTO_HANDLER_TYPE_CHAINED] == 0)
	    return -1;
	}
    }

  log_debug ("set-handler alg %s -> engine %s [simple=%u chained=%u async=%u]", ad->name, a->engine,
	     a->set_simple, a->set_chained, a->set_async);

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    {
      vnet_crypto_op_data_t *od;
      vnet_crypto_op_id_t id = ad->op_by_type[i];
      if (id == 0)
	continue;

      od = cm->opt_data + id;
      if (a->set_async)
	crypto_set_active_engine (od, id, p[0],
				  VNET_CRYPTO_HANDLER_TYPE_ASYNC);
      if (a->set_simple)
	crypto_set_active_engine (od, id, p[0],
				  VNET_CRYPTO_HANDLER_TYPE_SIMPLE);
      if (a->set_chained)
	crypto_set_active_engine (od, id, p[0],
				  VNET_CRYPTO_HANDLER_TYPE_CHAINED);
    }

  if (a->set_simple)
    crypto_update_key_handler_for_alg (cm, ad - cm->algs, VNET_CRYPTO_HANDLER_TYPE_SIMPLE);
  if (a->set_chained)
    crypto_update_key_handler_for_alg (cm, ad - cm->algs, VNET_CRYPTO_HANDLER_TYPE_CHAINED);

  return 0;
}

int
vnet_crypto_is_set_handler (vnet_crypto_alg_t alg)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_op_id_t opt = 0;
  int i;

  if (alg >= ARRAY_LEN (cm->algs))
    return 0;

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    if ((opt = cm->algs[alg].op_by_type[i]) != 0)
      break;

  return NULL != cm->opt_data[opt].handlers[VNET_CRYPTO_HANDLER_TYPE_SIMPLE];
}

void
vnet_crypto_register_ops_handler_inline (vlib_main_t *vm, u32 engine_index,
					 vnet_crypto_op_id_t opt,
					 vnet_crypto_simple_op_fn_t *fn,
					 vnet_crypto_chained_op_fn_t *cfn)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *ae, *e = vec_elt_at_index (cm->engines, engine_index);
  vnet_crypto_op_data_t *otd = cm->opt_data + opt;
  const char *engine_name = e->name;
  u32 bound_ei;

  if (fn)
    {
      vnet_crypto_handler_type_t t = VNET_CRYPTO_HANDLER_TYPE_SIMPLE;

      bound_ei = crypto_get_bound_engine_for_alg_type (cm, otd->alg, t);
      if (bound_ei && bound_ei != engine_index)
	{
	  log_debug ("reject handler reg opt=%u alg=%s type=simple engine=%s bound-engine=%s", opt,
		     cm->algs[otd->alg].name, engine_name,
		     vec_elt_at_index (cm->engines, bound_ei)->name);
	  fn = 0;
	  goto chained_path;
	}

      e->ops[opt].handlers[t] = fn;
      if (!otd->active_engine_index[t])
	{
	  otd->active_engine_index[t] = engine_index;
	  cm->opt_data[opt].handlers[t] = fn;
	}

      ae = vec_elt_at_index (cm->engines, otd->active_engine_index[t]);
      if (ae->priority < e->priority)
	crypto_set_active_engine (otd, opt, engine_index, t);
    }

chained_path:
  if (cfn)
    {
      vnet_crypto_handler_type_t t = VNET_CRYPTO_HANDLER_TYPE_CHAINED;

      bound_ei = crypto_get_bound_engine_for_alg_type (cm, otd->alg, t);
      if (bound_ei && bound_ei != engine_index)
	{
	  log_debug ("reject handler reg opt=%u alg=%s type=chained engine=%s bound-engine=%s", opt,
		     cm->algs[otd->alg].name, engine_name,
		     vec_elt_at_index (cm->engines, bound_ei)->name);
	  cfn = 0;
	  goto done;
	}

      e->ops[opt].handlers[t] = cfn;
      if (!otd->active_engine_index[t])
	{
	  otd->active_engine_index[t] = engine_index;
	  cm->opt_data[opt].handlers[t] = cfn;
	}

      ae = vec_elt_at_index (cm->engines, otd->active_engine_index[t]);
      if (ae->priority < e->priority)
	crypto_set_active_engine (otd, opt, engine_index, t);
    }

done:
  if (fn)
    crypto_update_key_handler_for_alg (cm, otd->alg, VNET_CRYPTO_HANDLER_TYPE_SIMPLE);
  if (cfn)
    crypto_update_key_handler_for_alg (cm, otd->alg, VNET_CRYPTO_HANDLER_TYPE_CHAINED);

  return;
}

void
vnet_crypto_register_ops_handler (vlib_main_t *vm, u32 engine_index,
				  vnet_crypto_op_id_t opt,
				  vnet_crypto_simple_op_fn_t *fn)
{
  vnet_crypto_register_ops_handler_inline (vm, engine_index, opt, fn, 0);
}

void
vnet_crypto_register_chained_ops_handler (vlib_main_t *vm, u32 engine_index,
					  vnet_crypto_op_id_t opt,
					  vnet_crypto_chained_op_fn_t *fn)
{
  vnet_crypto_register_ops_handler_inline (vm, engine_index, opt, 0, fn);
}

void
vnet_crypto_register_ops_handlers (vlib_main_t *vm, u32 engine_index,
				   vnet_crypto_op_id_t opt,
				   vnet_crypto_simple_op_fn_t *fn,
				   vnet_crypto_chained_op_fn_t *cfn)
{
  vnet_crypto_register_ops_handler_inline (vm, engine_index, opt, fn, cfn);
}

void
vnet_crypto_register_enqueue_handler (vlib_main_t *vm, u32 engine_index,
				      vnet_crypto_op_id_t opt,
				      vnet_crypto_frame_enq_fn_t *enqueue_hdl)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *ae, *e = vec_elt_at_index (cm->engines, engine_index);
  vnet_crypto_op_data_t *otd = cm->opt_data + opt;
  vnet_crypto_handler_type_t t = VNET_CRYPTO_HANDLER_TYPE_ASYNC;

  if (!enqueue_hdl)
    return;

  e->ops[opt].handlers[t] = enqueue_hdl;
  if (!otd->active_engine_index[t])
    {
      otd->active_engine_index[t] = engine_index;
      otd->handlers[t] = enqueue_hdl;
    }

  ae = vec_elt_at_index (cm->engines, otd->active_engine_index[t]);
  if (ae->priority <= e->priority)
    {
      otd->active_engine_index[t] = engine_index;
      otd->handlers[t] = enqueue_hdl;
    }

  return;
}

static int
engine_index_cmp (void *v1, void *v2)
{
  u32 *a1 = v1;
  u32 *a2 = v2;

  if (*a1 > *a2)
    return 1;
  if (*a1 < *a2)
    return -1;
  return 0;
}

static void
vnet_crypto_update_cm_dequeue_handlers (void)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_op_data_t *otd;
  vnet_crypto_engine_t *e;
  u32 *active_engines = 0, *ei, last_ei = ~0, i;

  vec_reset_length (cm->dequeue_handlers);

  for (i = 0; i < VNET_CRYPTO_N_OP_IDS; i++)
    {
      otd = cm->opt_data + i;
      if (!otd->active_engine_index[VNET_CRYPTO_HANDLER_TYPE_ASYNC])
	continue;
      e =
	cm->engines + otd->active_engine_index[VNET_CRYPTO_HANDLER_TYPE_ASYNC];
      if (!e->dequeue_handler)
	continue;
      vec_add1 (active_engines,
		otd->active_engine_index[VNET_CRYPTO_HANDLER_TYPE_ASYNC]);
    }

  vec_sort_with_function (active_engines, engine_index_cmp);

  vec_foreach (ei, active_engines)
    {
      if (ei[0] == last_ei)
	continue;
      if (ei[0] == ~0)
	continue;

      e = cm->engines + ei[0];
      vec_add1 (cm->dequeue_handlers, e->dequeue_handler);
      last_ei = ei[0];
    }

  vec_free (active_engines);
}

void
vnet_crypto_register_dequeue_handler (vlib_main_t *vm, u32 engine_index,
				      vnet_crypto_frame_dequeue_t *deq_fn)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine_index);

  if (!deq_fn)
    return;

  e->dequeue_handler = deq_fn;

  vnet_crypto_update_cm_dequeue_handlers ();

  return;
}

static void
vnet_crypto_register_key_handler_for_alg (u32 engine_index, vnet_crypto_alg_t alg,
					  vnet_crypto_handler_type_t t,
					  vnet_crypto_key_data_fn_t *key_add_fn,
					  vnet_crypto_key_data_fn_t *key_del_fn, u16 key_data_sz,
					  u8 key_data_per_thread)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + alg;
  vnet_crypto_engine_t *new_engine;

  if ((key_add_fn == 0 && key_del_fn == 0) || alg >= VNET_CRYPTO_N_ALGS)
    return;

  new_engine = vec_elt_at_index (cm->engines, engine_index);

  new_engine->key_add_fn[t][alg] = key_add_fn;
  new_engine->key_del_fn[t][alg] = key_del_fn;
  new_engine->key_data_sz[t][alg] = round_pow2 (key_data_sz, CLIB_CACHE_LINE_BYTES);
  new_engine->key_data_per_thread[t][alg] = key_data_per_thread;

  if (ad->key_add_fn[t] == 0 && ad->key_del_fn[t] == 0)
    {
      ad->key_add_fn[t] = key_add_fn;
      ad->key_del_fn[t] = key_del_fn;
      ad->key_data_sz[t] = new_engine->key_data_sz[t][alg];
      ad->key_data_per_thread[t] = key_data_per_thread;
      ad->key_fn_engine[t] = engine_index;
      return;
    }

  if (crypto_engine_is_active_for_alg (cm, alg, engine_index, t))
    {
      ad->key_add_fn[t] = key_add_fn;
      ad->key_del_fn[t] = key_del_fn;
      ad->key_data_sz[t] = new_engine->key_data_sz[t][alg];
      ad->key_data_per_thread[t] = key_data_per_thread;
      ad->key_fn_engine[t] = engine_index;
    }
}

void
vnet_crypto_register_key_handlers_internal (u32 engine_index, u8 update_add,
					    vnet_crypto_key_data_fn_t *key_add_fn, u8 update_del,
					    vnet_crypto_key_data_fn_t *key_del_fn)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_t alg;
  vnet_crypto_handler_type_t t;
  vnet_crypto_engine_t *e;
  vnet_crypto_key_data_fn_t *add_fn;
  vnet_crypto_key_data_fn_t *del_fn;

  e = vec_elt_at_index (cm->engines, engine_index);

  for (alg = 0; alg < VNET_CRYPTO_N_ALGS; alg++)
    {
      for (t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
	{
	  add_fn = update_add ? key_add_fn : e->key_add_fn[t][alg];
	  del_fn = update_del ? key_del_fn : e->key_del_fn[t][alg];
	  vnet_crypto_register_key_handler_for_alg (engine_index, alg, t, add_fn, del_fn, 0, 0);
	}
    }
}

void
vnet_crypto_register_key_handlers (vlib_main_t *vm __clib_unused, u32 engine_index,
				   vnet_crypto_key_data_fn_t *key_add_fn,
				   vnet_crypto_key_data_fn_t *key_del_fn)
{
  vnet_crypto_register_key_handlers_internal (engine_index, 1, key_add_fn, 1, key_del_fn);
}

void
vnet_crypto_register_key_add_handler (vlib_main_t *vm __clib_unused, u32 engine_index,
				      vnet_crypto_key_data_fn_t *key_add_fn)
{
  vnet_crypto_register_key_handlers_internal (engine_index, 1, key_add_fn, 0, 0);
}

void
vnet_crypto_register_key_del_handler (vlib_main_t *vm __clib_unused, u32 engine_index,
				      vnet_crypto_key_data_fn_t *key_del_fn)
{
  vnet_crypto_register_key_handlers_internal (engine_index, 0, 0, 1, key_del_fn);
}

void
vnet_crypto_register_async_key_add_handler (vlib_main_t *vm, u32 engine_index,
					    vnet_crypto_async_key_data_fn_t *key_add_fn)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine_index);

  e->async_key_add_fn = key_add_fn;
}

void
vnet_crypto_register_async_key_del_handler (vlib_main_t *vm, u32 engine_index,
					    vnet_crypto_async_key_data_fn_t *key_del_fn)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine_index);

  e->async_key_del_fn = key_del_fn;
}

static vnet_crypto_key_t *
vnet_crypoto_key_alloc (u32 length)
{
  vnet_crypto_main_t *cm = &crypto_main;
  u8 expected = 0;
  vnet_crypto_key_t *k, **kp;
  u8 *data = 0;
  uword key_sz = sizeof (*k);
  uword key_data_size_total = cm->key_data_size[VNET_CRYPTO_HANDLER_TYPE_SIMPLE] +
			      cm->key_data_size[VNET_CRYPTO_HANDLER_TYPE_CHAINED];

  if (key_data_size_total > sizeof (vnet_crypto_key_data_t))
    key_sz += key_data_size_total - sizeof (vnet_crypto_key_data_t);

  while (!__atomic_compare_exchange_n (&cm->keys_lock, &expected, 1, 0,
				       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
    {
      while (__atomic_load_n (&cm->keys_lock, __ATOMIC_RELAXED))
	CLIB_PAUSE ();
      expected = 0;
    }

  pool_get (cm->keys, kp);

  __atomic_store_n (&cm->keys_lock, 0, __ATOMIC_RELEASE);

  k = clib_mem_alloc_aligned (key_sz, alignof (vnet_crypto_key_t));
  if (length)
    data = clib_mem_alloc_aligned (round_pow2 (length, 16), 16);
  kp[0] = k;
  clib_memset_u8 (k, 0, key_sz);
  *k = (vnet_crypto_key_t){
    .index = kp - cm->keys,
    .length = length,
    .data = data,
  };

  return k;
}

static_always_inline void
vnet_crypto_key_add_call (vnet_crypto_main_t *cm, vnet_crypto_key_t *key,
			  vnet_crypto_handler_type_t t)
{
  vnet_crypto_key_data_t *key_data = vnet_crypto_get_key_data_ptr (cm, key, t, 0);
  vnet_crypto_alg_data_t *ad = cm->algs + key->alg;
  vnet_crypto_key_data_fn_t *fn = ad->key_add_fn[t];

  log_debug ("key-add type %u alg %s key-index %u fn %p per-thread %u key-data-sz %u", t,
	     cm->algs[key->alg].name, key->index, fn, ad->key_data_per_thread[t],
	     ad->key_data_sz[t]);
  vnet_crypto_key_call (key, key_data, fn, ad->key_data_per_thread[t], ad->key_data_sz[t]);
}

static_always_inline void
vnet_crypto_key_del_call (vnet_crypto_main_t *cm, vnet_crypto_key_t *key,
			  vnet_crypto_handler_type_t t)
{
  vnet_crypto_key_data_t *key_data = vnet_crypto_get_key_data_ptr (cm, key, t, 0);
  vnet_crypto_alg_data_t *ad = cm->algs + key->alg;
  vnet_crypto_key_data_fn_t *fn = ad->key_del_fn[t];

  log_debug ("key-del type %u alg %s key-index %u fn %p per-thread %u key-data-sz %u", t,
	     cm->algs[key->alg].name, key->index, fn, ad->key_data_per_thread[t],
	     ad->key_data_sz[t]);
  vnet_crypto_key_call (key, key_data, fn, ad->key_data_per_thread[t], ad->key_data_sz[t]);
}

static_always_inline void
vnet_crypto_key_add_call_async (vnet_crypto_main_t *cm, vnet_crypto_key_t *key)
{
  u32 ei = crypto_get_active_engine_for_alg (cm, key->alg, VNET_CRYPTO_HANDLER_TYPE_ASYNC);
  vnet_crypto_engine_t *e;

  if (ei == 0)
    return;

  e = vec_elt_at_index (cm->engines, ei);
  if (e->async_key_add_fn)
    e->async_key_add_fn (key);
}

static_always_inline void
vnet_crypto_key_del_call_async (vnet_crypto_main_t *cm, vnet_crypto_key_t *key)
{
  u32 ei = crypto_get_active_engine_for_alg (cm, key->alg, VNET_CRYPTO_HANDLER_TYPE_ASYNC);
  vnet_crypto_engine_t *e;

  if (ei == 0)
    return;

  e = vec_elt_at_index (cm->engines, ei);
  if (e->async_key_del_fn)
    e->async_key_del_fn (key);
}

u32
vnet_crypto_key_add (vlib_main_t * vm, vnet_crypto_alg_t alg, u8 * data,
		     u16 length)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_key_t *key;
  vnet_crypto_alg_data_t *ad = cm->algs + alg;

  ASSERT (alg != 0);

  if (length == 0)
    return ~0;

  if (ad->variable_key_length == 0)
    {
      if (ad->key_length == 0)
	return ~0;

      if (ad->key_length != length)
	return ~0;
    }

  key = vnet_crypoto_key_alloc (length);
  key->alg = alg;

  clib_memcpy (key->data, data, length);
  vnet_crypto_key_add_call (cm, key, VNET_CRYPTO_HANDLER_TYPE_SIMPLE);
  vnet_crypto_key_add_call (cm, key, VNET_CRYPTO_HANDLER_TYPE_CHAINED);
  vnet_crypto_key_add_call_async (cm, key);
  return key->index;
}

void
vnet_crypto_key_del (vlib_main_t * vm, vnet_crypto_key_index_t index)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_key_t *key = cm->keys[index];
  uword key_sz = sizeof (vnet_crypto_key_t);
  uword key_data_size_total = cm->key_data_size[VNET_CRYPTO_HANDLER_TYPE_SIMPLE] +
			      cm->key_data_size[VNET_CRYPTO_HANDLER_TYPE_CHAINED];
  u8 *data = key->data;

  if (key_data_size_total > sizeof (vnet_crypto_key_data_t))
    key_sz += key_data_size_total - sizeof (vnet_crypto_key_data_t);

  vnet_crypto_key_del_call_async (cm, key);
  vnet_crypto_key_del_call (cm, key, VNET_CRYPTO_HANDLER_TYPE_SIMPLE);
  vnet_crypto_key_del_call (cm, key, VNET_CRYPTO_HANDLER_TYPE_CHAINED);

  clib_memset_u8 (&key->key_data, 0, key_data_size_total);

  clib_memset (key, 0xfe, key_sz);
  if (data)
    clib_mem_free_s (data);
  clib_mem_free (key);
  pool_put_index (cm->keys, index);
}

void
vnet_crypto_key_update (vlib_main_t *vm, vnet_crypto_key_index_t index)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_key_t *key = cm->keys[index];
  vnet_crypto_key_add_call (cm, key, VNET_CRYPTO_HANDLER_TYPE_SIMPLE);
  vnet_crypto_key_add_call (cm, key, VNET_CRYPTO_HANDLER_TYPE_CHAINED);
  vnet_crypto_key_add_call_async (cm, key);
}

vnet_crypto_alg_t
vnet_crypto_link_algs (vnet_crypto_alg_t crypto_alg,
		       vnet_crypto_alg_t integ_alg)
{
#define _(c, h, s, k ,d) \
  if (crypto_alg == VNET_CRYPTO_ALG_##c && \
      integ_alg == VNET_CRYPTO_ALG_HMAC_##h) \
    return VNET_CRYPTO_ALG_##c##_##h##_TAG##d;
  foreach_crypto_link_async_alg
#undef _
    return ~0;
}

vnet_crypto_op_id_t *
vnet_crypto_ops_from_alg (vnet_crypto_alg_t alg)
{
  vnet_crypto_main_t *cm = &crypto_main;
  return cm->algs[alg].op_by_type;
}

u32
vnet_crypto_register_post_node (vlib_main_t * vm, char *post_node_name)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_async_next_node_t *nn = 0;
  vlib_node_t *cc, *pn;
  uword index = vec_len (cm->next_nodes);

  pn = vlib_get_node_by_name (vm, (u8 *) post_node_name);
  if (!pn)
    return ~0;

  vec_foreach (nn, cm->next_nodes)
    {
      if (nn->node_idx == pn->index)
	return nn->next_idx;
    }

  vec_validate (cm->next_nodes, index);
  nn = vec_elt_at_index (cm->next_nodes, index);

  cc = vlib_get_node_by_name (vm, (u8 *) "crypto-dispatch");
  nn->next_idx = vlib_node_add_named_next (vm, cc->index, post_node_name);
  nn->node_idx = pn->index;

  return nn->next_idx;
}

void
vnet_crypto_set_async_dispatch (u8 mode, u8 adaptive)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 i, node_index = crypto_main.crypto_node_index;
  vlib_node_state_t state =
    mode ? VLIB_NODE_STATE_INTERRUPT : VLIB_NODE_STATE_POLLING;

  for (i = vlib_num_workers () > 0; i < tm->n_vlib_mains; i++)
    {
      vlib_main_t *ovm = vlib_get_main_by_index (i);
      vlib_node_set_state (ovm, node_index, state);
      vlib_node_set_flag (ovm, node_index, VLIB_NODE_FLAG_ADAPTIVE_MODE,
			  adaptive);
    }
}

static void
vnet_crypto_load_engines (vlib_main_t *vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_config_t *pc;
  u8 *path;
  char *p;
  u32 path_len;
  struct dirent *entry;
  DIR *dp;
  uword *config_index;

  path = os_get_exec_path ();
  log_debug ("exec path is %s", path);

  vec_add1 (path, 0);
  if ((p = strrchr ((char *) path, '/')) == 0)
    goto done;
  *p = 0;
  if ((p = strrchr ((char *) path, '/')) == 0)
    goto done;

  vec_set_len (path, (u8 *) p - path);

  path = format (path, "/" CLIB_LIB_DIR "/vpp_crypto_engines");
  path_len = vec_len (path);
  vec_add1 (path, 0);

  log_debug ("libpath is %s", path);

  dp = opendir ((char *) path);

  if (dp)
    {
      while ((entry = readdir (dp)))
	{
	  void *handle;

	  if (entry->d_type != DT_REG)
	    continue;

	  char *ext = strrchr (entry->d_name, '.');
	  if (!ext || strncmp (ext, ".so", 3) != 0)
	    {
	      log_debug ("skipping %s, not .so", entry->d_name);
	    }
	  vec_set_len (path, path_len);
	  path = format (path, "/%s%c", entry->d_name, 0);

	  handle = dlopen ((char *) path, RTLD_LAZY);
	  if (!handle)
	    {
	      log_err ("failed to dlopen %s", path);
	      continue;
	    }

	  vnet_crypto_engine_registration_t *r =
	    dlsym (handle, "__vnet_crypto_engine");
	  if (!r)
	    {
	      log_err ("%s is not a crypto engine", entry->d_name);
	      dlclose (handle);
	      continue;
	    }

	  /* follow crypto-engines config section directive */
	  config_index = hash_get_mem (cm->config_index_by_name, r->name);
	  if (config_index)
	    {
	      pc = vec_elt_at_index (cm->configs, config_index[0]);
	      if (pc->is_disabled)
		{
		  log_notice ("crypto disabled: %s", r->name);
		  dlclose (handle);
		  continue;
		}
	      if (cm->default_disabled && pc->is_enabled == 0)
		{
		  log_notice ("crypto disabled (default): %s", r->name);
		  dlclose (handle);
		  continue;
		}
	    }
	  else if (cm->default_disabled)
	    {
	      log_notice ("crypto disabled (default): %s", r->name);
	      dlclose (handle);
	      continue;
	    }

	  r->num_threads = tm->n_vlib_mains;

	  if (r->init_fn)
	    {
	      char *rv = r->init_fn (r);
	      if (rv)
		{
		  log_err ("%s crypto engine init failed: %s", r->name, rv);
		  dlclose (handle);
		  continue;
		}
	      log_debug ("%s crypto engine initialized", r->name);
	    }
	  u32 eidx =
	    vnet_crypto_register_engine (vm, r->name, r->prio, r->desc);
	  log_debug ("%s crypto engine registered with id %u", r->name, eidx);
	  if (r->reg_op_groups)
	    {
	      vnet_crypto_reg_op_group_t *rog = r->reg_op_groups;
	      vnet_crypto_reg_op_group_t **best_groups = 0;

	      while (rog)
		{
		  int p = rog->probe_fn ? rog->probe_fn () : 1;
		  vnet_crypto_reg_op_group_t **bg;
		  int found = 0;

		  log_debug ("engine %s group %s probe=%d", r->name, rog->name, p);

		  if (p <= 0)
		    {
		      rog = rog->next;
		      continue;
		    }

		  rog->priority = p;
		  vec_foreach (bg, best_groups)
		    if (strcmp (bg[0]->name, rog->name) == 0)
		      {
			if (bg[0]->priority < rog->priority)
			  bg[0] = rog;
			found = 1;
			break;
		      }

		  if (found == 0)
		    vec_add1 (best_groups, rog);

		  rog = rog->next;
		}

	      vnet_crypto_reg_op_group_t **bg;
	      vec_foreach (bg, best_groups)
		{
		  vnet_crypto_reg_op_t *ro = bg[0]->ops;

		  log_debug ("engine %s selected group %s priority=%d key-data-sz=%u per-thread=%u",
			     r->name, bg[0]->name, bg[0]->priority, bg[0]->max_key_data_sz,
			     bg[0]->key_data_per_thread);

		  while (ro)
		    {
		      log_debug ("register op engine=%s group=%s op-id=%u fn=%p cfn=%p", r->name,
				 bg[0]->name, ro->op_id, ro->fn, ro->cfn);
		      vnet_crypto_register_ops_handlers (vm, eidx, ro->op_id, ro->fn, ro->cfn);
		      if (bg[0]->key_add_fn || bg[0]->key_del_fn)
			{
			  vnet_crypto_alg_t alg = cm->opt_data[ro->op_id].alg;
			  if (ro->fn)
			    {
			      log_debug ("register key-handler engine=%s group=%s type=simple "
					 "alg=%s add=%p del=%p sz=%u per-thread=%u",
					 r->name, bg[0]->name, cm->algs[alg].name,
					 bg[0]->key_add_fn, bg[0]->key_del_fn,
					 bg[0]->max_key_data_sz, bg[0]->key_data_per_thread);
			      vnet_crypto_register_key_handler_for_alg (
				eidx, alg, VNET_CRYPTO_HANDLER_TYPE_SIMPLE, bg[0]->key_add_fn,
				bg[0]->key_del_fn, bg[0]->max_key_data_sz,
				bg[0]->key_data_per_thread);
			    }
			  if (ro->cfn)
			    {
			      log_debug ("register key-handler engine=%s group=%s type=chained "
					 "alg=%s add=%p del=%p sz=%u per-thread=%u",
					 r->name, bg[0]->name, cm->algs[alg].name,
					 bg[0]->key_add_fn, bg[0]->key_del_fn,
					 bg[0]->max_key_data_sz, bg[0]->key_data_per_thread);
			      vnet_crypto_register_key_handler_for_alg (
				eidx, alg, VNET_CRYPTO_HANDLER_TYPE_CHAINED, bg[0]->key_add_fn,
				bg[0]->key_del_fn, bg[0]->max_key_data_sz,
				bg[0]->key_data_per_thread);
			    }
			}
		      ro = ro->next;
		    }
		}
	      vec_free (best_groups);
	    }
	}
      closedir (dp);
    }

  {
    uword key_data_size_simple =
      round_pow2 (sizeof (vnet_crypto_key_data_t), CLIB_CACHE_LINE_BYTES);
    uword key_data_size_chained =
      round_pow2 (sizeof (vnet_crypto_key_data_t), CLIB_CACHE_LINE_BYTES);
    vnet_crypto_alg_t alg;

    for (alg = 0; alg < VNET_CRYPTO_N_ALGS; alg++)
      {
	uword sz = cm->algs[alg].key_data_sz[VNET_CRYPTO_HANDLER_TYPE_SIMPLE];

	if (sz == 0)
	  continue;

	if (cm->algs[alg].key_data_per_thread[VNET_CRYPTO_HANDLER_TYPE_SIMPLE])
	  sz *= tm->n_vlib_mains;

	if (sz > key_data_size_simple)
	  key_data_size_simple = sz;
      }

    for (alg = 0; alg < VNET_CRYPTO_N_ALGS; alg++)
      {
	uword sz = cm->algs[alg].key_data_sz[VNET_CRYPTO_HANDLER_TYPE_CHAINED];

	if (sz == 0)
	  continue;

	if (cm->algs[alg].key_data_per_thread[VNET_CRYPTO_HANDLER_TYPE_CHAINED])
	  sz *= tm->n_vlib_mains;

	if (sz > key_data_size_chained)
	  key_data_size_chained = sz;
      }

    cm->key_data_size[VNET_CRYPTO_HANDLER_TYPE_SIMPLE] =
      round_pow2 (key_data_size_simple, CLIB_CACHE_LINE_BYTES);
    cm->key_data_size[VNET_CRYPTO_HANDLER_TYPE_CHAINED] =
      round_pow2 (key_data_size_chained, CLIB_CACHE_LINE_BYTES);
    cm->key_data_offset[VNET_CRYPTO_HANDLER_TYPE_SIMPLE] = 0;
    cm->key_data_offset[VNET_CRYPTO_HANDLER_TYPE_CHAINED] =
      cm->key_data_size[VNET_CRYPTO_HANDLER_TYPE_SIMPLE];

    log_debug ("crypto key_data_size: simple %u chained %u total %u",
	       cm->key_data_size[VNET_CRYPTO_HANDLER_TYPE_SIMPLE],
	       cm->key_data_size[VNET_CRYPTO_HANDLER_TYPE_CHAINED],
	       cm->key_data_size[VNET_CRYPTO_HANDLER_TYPE_SIMPLE] +
		 cm->key_data_size[VNET_CRYPTO_HANDLER_TYPE_CHAINED]);
  }

done:
  vec_free (path);
}

clib_error_t *
vnet_crypto_init (vlib_main_t * vm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_crypto_thread_t *ct = 0;
  vnet_crypto_engine_t *p;

  vec_add2 (cm->engines, p, 1);
  cm->engine_index_by_name = hash_create_string ( /* size */ 0,
						 sizeof (uword));
  cm->alg_index_by_name = hash_create_string (0, sizeof (uword));
  vec_validate_aligned (cm->threads, tm->n_vlib_mains, CLIB_CACHE_LINE_BYTES);
  vec_foreach (ct, cm->threads)
    pool_init_fixed (ct->frame_pool, VNET_CRYPTO_FRAME_POOL_SIZE);

  FOREACH_ARRAY_ELT (e, cm->algs)
    if (e->name)
      hash_set_mem (cm->alg_index_by_name, e->name, e - cm->algs);

  cm->crypto_node_index =
    vlib_get_node_by_name (vm, (u8 *) "crypto-dispatch")->index;

  vnet_crypto_load_engines (vm);

  return 0;
}

VLIB_INIT_FUNCTION (vnet_crypto_init);
