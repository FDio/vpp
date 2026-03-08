/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025-2026 Cisco Systems, Inc.
 */

#include <stdbool.h>
#include <string.h>
#include <vlib/vlib.h>
#define VNET_CRYPTO_LOG_MACROS
#include <vnet/crypto/crypto.h>
#include <vnet/crypto/engine.h>
#include <vnet/api_errno.h>
#include <vppinfra/unix.h>
#include <vlib/log.h>
#include <dlfcn.h>
#include <dirent.h>

VLIB_REGISTER_LOG_CLASS (crypto_log, static) = {
  .class_name = "crypto",
  .subclass_name = "main",
};

static_always_inline void
crypto_set_active_engine (vnet_crypto_alg_t alg, vnet_crypto_op_type_t type,
			  vnet_crypto_engine_id_t engine, vnet_crypto_handler_type_t t)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *ce = vec_elt_at_index (cm->engines, engine);

  if (ce->ops[alg][type].handlers[t])
    {
      cm->active_op_engine_index[alg][type][t] = engine;
      cm->active_engine_index[alg][t] = engine;
      cm->op_type_handlers[alg][type][t] = ce->ops[alg][type].handlers[t];
    }
}

static_always_inline int
crypto_engine_has_handler (vnet_crypto_engine_t *e, vnet_crypto_alg_t alg,
			   vnet_crypto_op_type_t type, vnet_crypto_handler_type_t t)
{
  return e->ops[alg][type].handlers[t] != 0;
}

static_always_inline void
crypto_register_handler (vnet_crypto_main_t *cm, vnet_crypto_engine_t *e, vnet_crypto_alg_t alg,
			 vnet_crypto_op_type_t type, vnet_crypto_handler_type_t t, void *fn)
{
  vnet_crypto_engine_t *ae;
  vnet_crypto_engine_id_t engine;

  if (fn == 0)
    return;

  engine = e - cm->engines;
  e->ops[alg][type].handlers[t] = fn;
  vec_validate_init_empty (cm->engine_supports_alg[alg][t], engine, 0);
  cm->engine_supports_alg[alg][t][engine] = 1;
  if (!cm->active_op_engine_index[alg][type][t])
    {
      cm->active_op_engine_index[alg][type][t] = engine;
      cm->active_engine_index[alg][t] = engine;
      cm->op_type_handlers[alg][type][t] = fn;
      return;
    }

  ae = vec_elt_at_index (cm->engines, cm->active_op_engine_index[alg][type][t]);
  if (ae->priority <= e->priority)
    crypto_set_active_engine (alg, type, engine, t);
}

static void
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

  for (i = 0; i < vec_len (cm->ctxs); i++)
    {
      vnet_crypto_ctx_t *ctx;

      if (pool_is_free_index (cm->ctxs, i))
	continue;
      if (cm->ctxs[i]->alg != alg)
	continue;
      if (old_ei != VNET_CRYPTO_ENGINE_ID_NONE)
	{
	  if (vnet_crypto_key_get_engine (cm->ctxs[i], t) != old_ei)
	    continue;
	}
      else if (vnet_crypto_key_get_engine (cm->ctxs[i], t) != ei)
	continue;

      ctx = cm->ctxs[i];
      vnet_crypto_ctx_set_engine (ctx, t, ei);
      n_rekeyed++;
    }

  if (old_ei != ei)
    log_debug ("key-handler switch alg %s type %u done: rekeyed %u key(s)", cm->algs[alg].name, t,
	       n_rekeyed);
}

static void
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

static_always_inline u32
vnet_crypto_process_ops_one_batch (vlib_main_t *vm, vnet_crypto_op_t ops[],
				   vnet_crypto_op_t *op_queue[], u32 op_q_sz,
				   vnet_crypto_op_chunk_t *chunks, u32 n_ops, u32 first_slot,
				   u32 *n_left, u8 first_run)
{
  vnet_crypto_sync_op_fn_t *batch_fn;
  vnet_crypto_op_status_t bs;
  u32 slot, n_op_queue = 0;
  vnet_crypto_op_t op = ops[first_slot];
  vnet_crypto_handler_type_t handler_type = (op.flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS) ?
					      VNET_CRYPTO_HANDLER_TYPE_CHAINED :
					      VNET_CRYPTO_HANDLER_TYPE_SIMPLE;

  ASSERT (op.ctx != 0);
  batch_fn = op.ctx->handlers[op.type][handler_type];
  bs = batch_fn ? VNET_CRYPTO_OP_STATUS_WORK_IN_PROGRESS : VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER;
  ops[first_slot].status = bs;
  op_queue[n_op_queue++] = ops + first_slot;

  for (slot = first_slot + 1; slot < n_ops && n_op_queue < op_q_sz; slot++)
    {
      vnet_crypto_handler_type_t handler_type;

      op = ops[slot];

      if (!first_run && op.status != VNET_CRYPTO_OP_STATUS_UNPROCESSED)
	continue;

      handler_type = (op.flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS) ?
		       VNET_CRYPTO_HANDLER_TYPE_CHAINED :
		       VNET_CRYPTO_HANDLER_TYPE_SIMPLE;

      ASSERT (op.ctx != 0);
      if (op.ctx->handlers[op.type][handler_type] != batch_fn)
	{
	  if (first_run)
	    ops[slot].status = VNET_CRYPTO_OP_STATUS_UNPROCESSED;
	  continue;
	}

      ops[slot].status = bs;
      op_queue[n_op_queue++] = ops + slot;
    }

  *n_left -= n_op_queue;

  if (first_run && PREDICT_FALSE (slot < n_ops))
    for (; slot < n_ops; slot++)
      ops[slot].status = VNET_CRYPTO_OP_STATUS_UNPROCESSED;

  return batch_fn ? batch_fn (op_queue, chunks, n_op_queue, vm->thread_index) : 0;
}

u32
vnet_crypto_process_ops (vlib_main_t *vm, vnet_crypto_op_t ops[], vnet_crypto_op_chunk_t *chunks,
			 u32 n_ops)
{
  const int op_q_sz = VLIB_FRAME_SIZE;
  vnet_crypto_op_t *queue[op_q_sz];
  u32 first_slot = 1;
  u32 n_left = n_ops;
  u32 rv = 0;

  ASSERT (n_ops >= 1);

  rv += vnet_crypto_process_ops_one_batch (vm, ops, queue, op_q_sz, chunks, n_ops, 0, &n_left, 1);

  while (n_left)
    {
      while (ops[first_slot].status != VNET_CRYPTO_OP_STATUS_UNPROCESSED)
	if (++first_slot == n_ops)
	  return rv;
      rv += vnet_crypto_process_ops_one_batch (vm, ops, queue, op_q_sz, chunks, n_ops, first_slot,
					       &n_left, 0);
    }

  return rv;
}

vnet_crypto_engine_id_t
vnet_crypto_register_engine (vlib_main_t *vm, char *name, int prio, char *desc)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *p;
  vnet_crypto_engine_id_t engine;

  vec_add2 (cm->engines, p, 1);
  engine = p - cm->engines;
  ASSERT (engine < VNET_CRYPTO_ENGINE_ID_INVALID);
  p->name = name;
  p->desc = desc;
  p->priority = prio;

  hash_set_mem (cm->engine_index_by_name, p->name, engine);

  return engine;
}

void
vnet_crypto_register_engine_registration (vnet_crypto_engine_registration_t *r)
{
  vnet_crypto_main_t *cm = &crypto_main;

  r->next = cm->engine_registrations;
  cm->engine_registrations = r;
}

vnet_crypto_engine_id_t
vnet_crypto_get_engine_index_by_name (const char *fmt, ...)
{
  vnet_crypto_main_t *cm = &crypto_main;
  uword *p;
  va_list va;
  u8 *name;
  vnet_crypto_engine_id_t engine = VNET_CRYPTO_ENGINE_ID_INVALID;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);

  vec_add1 (name, 0);
  p = hash_get_mem (cm->engine_index_by_name, name);
  if (p)
    engine = p[0];
  vec_free (name);

  return engine;
}

int
vnet_crypto_set_handlers (vnet_crypto_set_handlers_args_t *a)
{
  uword *p;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad;
  vnet_crypto_engine_t *e;
  vnet_crypto_alg_t alg;
  vnet_crypto_engine_id_t engine;
  int i;

  p = hash_get_mem (cm->alg_index_by_name, a->handler_name);
  if (!p)
    return -1;

  ad = cm->algs + p[0];

  p = hash_get_mem (cm->engine_index_by_name, a->engine);
  if (!p)
    return -1;
  engine = p[0];
  e = vec_elt_at_index (cm->engines, engine);
  alg = ad - cm->algs;

  if (a->set_simple || a->set_chained)
    {
      for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
	{
	  if (!vnet_crypto_alg_has_op_type (alg, i))
	    continue;

	  if (a->set_simple &&
	      !crypto_engine_has_handler (e, alg, i, VNET_CRYPTO_HANDLER_TYPE_SIMPLE))
	    return -1;

	  if (a->set_chained &&
	      !crypto_engine_has_handler (e, alg, i, VNET_CRYPTO_HANDLER_TYPE_CHAINED))
	    return -1;
	}
    }

  log_debug ("set-handler alg %s -> engine %s [simple=%u chained=%u async=%u]", ad->name, a->engine,
	     a->set_simple, a->set_chained, a->set_async);

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    {
      if (!vnet_crypto_alg_has_op_type (alg, i))
	continue;

      if (a->set_async)
	crypto_set_active_engine (alg, i, engine, VNET_CRYPTO_HANDLER_TYPE_ASYNC);
      if (a->set_simple)
	crypto_set_active_engine (alg, i, engine, VNET_CRYPTO_HANDLER_TYPE_SIMPLE);
      if (a->set_chained)
	crypto_set_active_engine (alg, i, engine, VNET_CRYPTO_HANDLER_TYPE_CHAINED);
    }

  if (a->set_simple)
    crypto_update_key_handler_for_alg (cm, alg, VNET_CRYPTO_HANDLER_TYPE_SIMPLE);
  if (a->set_chained)
    crypto_update_key_handler_for_alg (cm, alg, VNET_CRYPTO_HANDLER_TYPE_CHAINED);

  return 0;
}

void
vnet_crypto_register_ops_handler_inline (vlib_main_t *vm __clib_unused,
					 vnet_crypto_engine_id_t engine, vnet_crypto_alg_t alg,
					 vnet_crypto_op_type_t type, vnet_crypto_sync_op_fn_t *fn,
					 vnet_crypto_sync_op_fn_t *cfn)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);

  crypto_register_handler (cm, e, alg, type, VNET_CRYPTO_HANDLER_TYPE_SIMPLE, fn);
  crypto_register_handler (cm, e, alg, type, VNET_CRYPTO_HANDLER_TYPE_CHAINED, cfn);

  if (fn)
    crypto_update_key_handler_for_alg (cm, alg, VNET_CRYPTO_HANDLER_TYPE_SIMPLE);
  if (cfn)
    crypto_update_key_handler_for_alg (cm, alg, VNET_CRYPTO_HANDLER_TYPE_CHAINED);
}

void
vnet_crypto_register_enqueue_handler_by_alg (vlib_main_t *vm __clib_unused,
					     vnet_crypto_engine_id_t engine, vnet_crypto_alg_t alg,
					     vnet_crypto_op_type_t type,
					     vnet_crypto_frame_enq_fn_t *enqueue_hdl)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);

  crypto_register_handler (cm, e, alg, type, VNET_CRYPTO_HANDLER_TYPE_ASYNC, enqueue_hdl);
}

static int
engine_index_cmp (void *v1, void *v2)
{
  vnet_crypto_engine_id_t *a1 = v1;
  vnet_crypto_engine_id_t *a2 = v2;

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
  vnet_crypto_engine_t *e;
  vnet_crypto_engine_id_t *active_engines = 0, *ei;
  vnet_crypto_engine_id_t last_ei = VNET_CRYPTO_ENGINE_ID_INVALID;
  u32 i;

  vec_reset_length (cm->dequeue_handlers);

  for (i = 1; i < VNET_CRYPTO_N_ALGS; i++)
    {
      vnet_crypto_alg_t alg = i;
      vnet_crypto_op_type_t type;

      for (type = 0; type < VNET_CRYPTO_OP_N_TYPES; type++)
	{
	  if (!cm->active_op_engine_index[alg][type][VNET_CRYPTO_HANDLER_TYPE_ASYNC])
	    continue;
	  e = cm->engines + cm->active_op_engine_index[alg][type][VNET_CRYPTO_HANDLER_TYPE_ASYNC];
	  if (!e->dequeue_handler)
	    continue;
	  vec_add1 (active_engines,
		    cm->active_op_engine_index[alg][type][VNET_CRYPTO_HANDLER_TYPE_ASYNC]);
	}
    }

  vec_sort_with_function (active_engines, engine_index_cmp);

  vec_foreach (ei, active_engines)
    {
      if (ei[0] == last_ei)
	continue;
      if (ei[0] == VNET_CRYPTO_ENGINE_ID_INVALID)
	continue;

      e = cm->engines + ei[0];
      vec_add1 (cm->dequeue_handlers, e->dequeue_handler);
      last_ei = ei[0];
    }

  vec_free (active_engines);
}

void
vnet_crypto_register_dequeue_handler (vlib_main_t *vm __clib_unused, vnet_crypto_engine_id_t engine,
				      vnet_crypto_frame_dequeue_t *deq_fn)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);

  if (!deq_fn)
    return;

  e->dequeue_handler = deq_fn;

  vnet_crypto_update_cm_dequeue_handlers ();
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

static void
vnet_crypto_load_engines (vlib_main_t *vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_registration_t *r;
  vnet_crypto_config_t *pc;
  u8 *path;
  char *p;
  u32 path_len;
  struct dirent *entry;
  DIR *dp;
  uword *config_index;

  path = os_get_exec_path ();
  vec_add1 (path, 0);
  log_debug ("exec path is %s", path);
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
	  if (entry->d_type != DT_REG)
	    continue;

	  char *ext = strrchr (entry->d_name, '.');
	  if (!ext || strncmp (ext, ".so", 3) != 0)
	    {
	      log_debug ("skipping %s, not .so", entry->d_name);
	    }
	  vec_set_len (path, path_len);
	  path = format (path, "/%s%c", entry->d_name, 0);

	  if (!dlopen ((char *) path, RTLD_LAZY))
	    {
	      log_err ("failed to dlopen %s", path);
	      continue;
	    }
	}
      closedir (dp);
    }

  for (r = cm->engine_registrations; r; r = r->next)
    {
      if (r->is_registered)
	continue;

      config_index = hash_get_mem (cm->config_index_by_name, r->name);
      if (config_index)
	{
	  pc = vec_elt_at_index (cm->configs, config_index[0]);
	  if (pc->is_disabled)
	    {
	      log_notice ("crypto disabled: %s", r->name);
	      continue;
	    }
	  if (cm->default_disabled && pc->is_enabled == 0)
	    {
	      log_notice ("crypto disabled (default): %s", r->name);
	      continue;
	    }
	}
      else if (cm->default_disabled)
	{
	  log_notice ("crypto disabled (default): %s", r->name);
	  continue;
	}

      r->num_threads = tm->n_vlib_mains;

      if (r->init_fn)
	{
	  char *rv = r->init_fn (r);
	  if (rv)
	    {
	      log_err ("%s crypto engine init failed: %s", r->name, rv);
	      continue;
	    }
	  log_debug ("%s crypto engine initialized", r->name);
	}
      vnet_crypto_engine_id_t engine = vnet_crypto_register_engine (vm, r->name, r->prio, r->desc);
      log_debug ("%s crypto engine registered with id %u", r->name, engine);
      if (r->reg_op_groups)
	{
	  vnet_crypto_reg_alg_group_t *rog = r->reg_op_groups;
	  vnet_crypto_reg_alg_group_t **best_groups = 0;

	  while (rog)
	    {
	      int p = rog->probe_fn ? rog->probe_fn () : 1;
	      vnet_crypto_reg_alg_group_t **bg;
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

	  vnet_crypto_reg_alg_group_t **bg;
	  vec_foreach (bg, best_groups)
	    {
	      vnet_crypto_reg_alg_t *ra = bg[0]->algs;

	      log_debug ("engine %s selected group %s priority=%d key-data-sz=%u per-thread=%u",
			 r->name, bg[0]->name, bg[0]->priority, bg[0]->max_key_data_sz,
			 bg[0]->key_data_per_thread);

	      while (ra)
		{
		  vnet_crypto_op_type_t type;
		  vnet_crypto_alg_t alg = ra->alg_id;

		  for (type = 0; type < VNET_CRYPTO_OP_N_TYPES; type++)
		    {
		      vnet_crypto_sync_op_fn_t *cfn;
		      vnet_crypto_sync_op_fn_t *fn;

		      fn = ra->simple.fn[type];
		      cfn = ra->chained.fn[type];
		      if (fn == 0 && cfn == 0)
			continue;

		      if (!vnet_crypto_alg_has_op_type (alg, type))
			continue;

		      log_debug ("register alg engine=%s group=%s alg=%s type=%u fn=%p cfn=%p",
				 r->name, bg[0]->name, cm->algs[alg].name, type, fn, cfn);
		      vnet_crypto_register_ops_handler_inline (vm, engine, alg, type, fn, cfn);
		      if (bg[0]->key_change_fn && fn)
			{
			  log_debug ("register key-handler engine=%s group=%s type=simple "
				     "alg=%s fn=%p sz=%u per-thread=%u",
				     r->name, bg[0]->name, cm->algs[alg].name, bg[0]->key_change_fn,
				     bg[0]->max_key_data_sz, bg[0]->key_data_per_thread);
			  vnet_crypto_register_key_handler_for_alg (
			    engine, alg, VNET_CRYPTO_HANDLER_TYPE_SIMPLE, bg[0]->key_change_fn,
			    bg[0]->max_key_data_sz, bg[0]->key_data_per_thread);
			}

		      if (bg[0]->key_change_fn && cfn)
			{
			  log_debug ("register key-handler engine=%s group=%s type=chained "
				     "alg=%s fn=%p sz=%u per-thread=%u",
				     r->name, bg[0]->name, cm->algs[alg].name, bg[0]->key_change_fn,
				     bg[0]->max_key_data_sz, bg[0]->key_data_per_thread);
			  vnet_crypto_register_key_handler_for_alg (
			    engine, alg, VNET_CRYPTO_HANDLER_TYPE_CHAINED, bg[0]->key_change_fn,
			    bg[0]->max_key_data_sz, bg[0]->key_data_per_thread);
			}
		    }

		  ra = ra->next;
		}
	    }
	  vec_free (best_groups);
	}
      r->is_registered = 1;
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
    {
      clib_spinlock_init (&ct->free_frames_lock);
      pool_init_fixed (ct->frame_pool, VNET_CRYPTO_FRAME_POOL_SIZE);
    }

  FOREACH_ARRAY_ELT (e, cm->algs)
    if (e->name)
      hash_set_mem (cm->alg_index_by_name, e->name, e - cm->algs);

  cm->crypto_node_index = vlib_get_node_by_name (vm, (u8 *) "crypto-dispatch")->index;

  return 0;
}

VLIB_INIT_FUNCTION (vnet_crypto_init);

static clib_error_t *
vnet_crypto_main_loop_enter (vlib_main_t *vm)
{
  vnet_crypto_main_t *cm = &crypto_main;

  vnet_crypto_load_engines (vm);
  vnet_crypto_key_layout_init (cm);

  return 0;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (vnet_crypto_main_loop_enter);
