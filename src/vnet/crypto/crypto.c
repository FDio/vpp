/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <stdbool.h>
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

static_always_inline u32
vnet_crypto_process_ops_call_handler (vlib_main_t * vm,
				      vnet_crypto_main_t * cm,
				      vnet_crypto_op_id_t opt,
				      vnet_crypto_op_t * ops[],
				      vnet_crypto_op_chunk_t * chunks,
				      u32 n_ops)
{
  vnet_crypto_op_data_t *od = cm->opt_data + opt;
  u32 rv = 0;
  if (n_ops == 0)
    return 0;

  if (chunks)
    {
      vnet_crypto_chained_op_fn_t *fn =
	od->handlers[VNET_CRYPTO_HANDLER_TYPE_CHAINED];

      if (fn == 0)
	crypto_set_op_status (ops, n_ops,
			      VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER);
      else
	rv = fn (vm, ops, chunks, n_ops);
    }
  else
    {
      vnet_crypto_simple_op_fn_t *fn =
	od->handlers[VNET_CRYPTO_HANDLER_TYPE_SIMPLE];
      if (fn == 0)
	crypto_set_op_status (ops, n_ops,
			      VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER);
      else
	rv = fn (vm, ops, n_ops);
    }
  return rv;
}

static_always_inline u32
vnet_crypto_process_ops_call_handlers (vlib_main_t * vm,
				      vnet_crypto_main_t * cm,
				      vnet_crypto_op_id_t opts[],
              u32 n_opts,
				      vnet_crypto_op_t * ops[],
				      vnet_crypto_op_chunk_t * chunks,
				      u32 n_ops)
{
  if (n_ops == 0)
  {
    return 0;
  }

      u32 i, rv;
    for (i = 0; i < n_opts; i++)
  {
    rv = 0;
    vnet_crypto_op_data_t *od = cm->opt_data + opts[i];
        
    if (chunks)
      {
        vnet_crypto_chained_op_fn_t *fn =
    od->handlers[VNET_CRYPTO_HANDLER_TYPE_CHAINED];

        if (fn == 0)
        {
    crypto_set_op_status (ops, n_ops,
              VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER);
              break;
        }
        else
        {
          rv = fn (vm, ops, chunks, n_ops);
          if (rv != n_ops)
            break;
        }
      }
    else
      {
        vnet_crypto_simple_op_fn_t *fn =
    od->handlers[VNET_CRYPTO_HANDLER_TYPE_SIMPLE];
        if (fn == 0)
        {
    crypto_set_op_status (ops, n_ops,
              VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER);
              break;
        }
        else
        {
        rv = fn (vm, ops, n_ops);
          if (rv != n_ops)
            break;
        }
      }
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


  vnet_crypto_op_data_t *od = cm->opt_data + current_op_type;
  vnet_crypto_alg_data_t *cad = cm->algs + od->alg;
  if (PREDICT_FALSE (cad->is_link))
    {
      /* Pre-compute both op IDs to avoid conditional branching inside array assignment.
         Compiler can optimize away unused computation on predictable branch. */
      vnet_crypto_op_type_t op_type = od->type;
      vnet_crypto_op_id_t crypto_op = cm->algs[cad->link_crypto_alg].op_by_type[op_type];
      vnet_crypto_op_id_t integ_op = cm->algs[cad->link_integ_alg].op_by_type[VNET_CRYPTO_OP_TYPE_HMAC];
      
      /* Use conditional move pattern: encrypt = crypto first, decrypt = integ first */
      vnet_crypto_op_id_t linked_crypto_op[2] = {
        (op_type == VNET_CRYPTO_OP_TYPE_ENCRYPT) ? crypto_op : integ_op,
        (op_type == VNET_CRYPTO_OP_TYPE_ENCRYPT) ? integ_op : crypto_op
      };
      
      rv += vnet_crypto_process_ops_call_handlers (vm, cm,
                      linked_crypto_op, 2,
                      op_queue, chunks, n_op_queue);
    }
    else 
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

  if (fn)
    {
      vnet_crypto_handler_type_t t = VNET_CRYPTO_HANDLER_TYPE_SIMPLE;
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

  if (cfn)
    {
      vnet_crypto_handler_type_t t = VNET_CRYPTO_HANDLER_TYPE_CHAINED;
      e->ops[opt].handlers[t] = cfn;
      if (otd->active_engine_index[t])
	{
	  otd->active_engine_index[t] = engine_index;
	  cm->opt_data[opt].handlers[t] = cfn;
	}

      ae = vec_elt_at_index (cm->engines, otd->active_engine_index[t]);
      if (ae->priority < e->priority)
	crypto_set_active_engine (otd, opt, engine_index, t);
    }

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

void
vnet_crypto_register_key_handler (vlib_main_t *vm, u32 engine_index,
				  vnet_crypto_key_fn_t *key_handler)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine_index);
  e->key_op_handler = key_handler;
  return;
}

static vnet_crypto_key_t *
vnet_crypoto_key_alloc (u32 length)
{
  vnet_crypto_main_t *cm = &crypto_main;
  u8 expected = 0;
  vnet_crypto_key_t *k, **kp;
  u32 alloc_sz = sizeof (vnet_crypto_key_t) + round_pow2 (length, 16);

  while (!__atomic_compare_exchange_n (&cm->keys_lock, &expected, 1, 0,
				       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
    {
      while (__atomic_load_n (&cm->keys_lock, __ATOMIC_RELAXED))
	CLIB_PAUSE ();
      expected = 0;
    }

  pool_get (cm->keys, kp);

  __atomic_store_n (&cm->keys_lock, 0, __ATOMIC_RELEASE);

  k = clib_mem_alloc_aligned (alloc_sz, alignof (vnet_crypto_key_t));
  kp[0] = k;
  *k = (vnet_crypto_key_t){
    .index = kp - cm->keys,
    .length = length,
  };

  return k;
}

u32
vnet_crypto_key_add (vlib_main_t * vm, vnet_crypto_alg_t alg, u8 * data,
		     u16 length)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *engine;
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
  vec_foreach (engine, cm->engines)
    if (engine->key_op_handler)
      engine->key_op_handler (VNET_CRYPTO_KEY_OP_ADD, key->index);
  return key->index;
}

void
vnet_crypto_key_del (vlib_main_t * vm, vnet_crypto_key_index_t index)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *engine;
  vnet_crypto_key_t *key = cm->keys[index];
  u32 sz = sizeof (vnet_crypto_key_t) + round_pow2 (key->length, 16);

  vec_foreach (engine, cm->engines)
    if (engine->key_op_handler)
      engine->key_op_handler (VNET_CRYPTO_KEY_OP_DEL, index);

  clib_memset (key, 0xfe, sz);
  clib_mem_free (key);
  pool_put_index (cm->keys, index);
}

void
vnet_crypto_key_update (vlib_main_t *vm, vnet_crypto_key_index_t index)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *engine;

  vec_foreach (engine, cm->engines)
    if (engine->key_op_handler)
      engine->key_op_handler (VNET_CRYPTO_KEY_OP_MODIFY, index);
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
vnet_crypto_key_add_linked (vlib_main_t * vm,
			    vnet_crypto_key_index_t index_crypto,
			    vnet_crypto_key_index_t index_integ)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *engine;
  vnet_crypto_key_t *key_crypto, *key_integ, *key;
  vnet_crypto_alg_t linked_alg;

  key_crypto = cm->keys[index_crypto];
  key_integ = cm->keys[index_integ];

  linked_alg = vnet_crypto_link_algs (key_crypto->alg, key_integ->alg);
  if (linked_alg == ~0)
    return ~0;

  key = vnet_crypoto_key_alloc (0);
  key->is_link = 1;
  key->index_crypto = index_crypto;
  key->index_integ = index_integ;
  key->alg = linked_alg;

  vec_foreach (engine, cm->engines)
    if (engine->key_op_handler)
      engine->key_op_handler (VNET_CRYPTO_KEY_OP_ADD, key->index);

  return key->index;
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

	  if (r->per_thread_data_sz)
	    {
	      u64 sz =
		round_pow2 (r->per_thread_data_sz, CLIB_CACHE_LINE_BYTES);
	      u64 alloc = sz * tm->n_vlib_mains;
	      r->per_thread_data =
		clib_mem_alloc_aligned (alloc, CLIB_CACHE_LINE_BYTES);
	      clib_memset (r->per_thread_data, 0, alloc);
	      log_debug ("%s: allocated %u bytes per thread", r->name, sz);
	    }

	  r->num_threads = tm->n_vlib_mains;

	  if (r->init_fn)
	    {
	      char *rv = r->init_fn (r);
	      if (rv)
		{
		  log_err ("%s crypto engine init failed: %s", r->name, rv);
		  if (r->per_thread_data)
		    clib_mem_free (r->per_thread_data);
		  dlclose (handle);
		  continue;
		}
	      log_debug ("%s crypto engine initialized", r->name);
	    }
	  u32 eidx =
	    vnet_crypto_register_engine (vm, r->name, r->prio, r->desc);
	  log_debug ("%s crypto engine registered with id %u", r->name, eidx);
	  typeof (r->op_handlers) oh = r->op_handlers;

	  while (oh->opt != VNET_CRYPTO_OP_NONE)
	    {
	      vnet_crypto_register_ops_handlers (vm, eidx, oh->opt, oh->fn,
						 oh->cfn);
	      oh++;
	    }

	  if (r->key_handler)
	    vnet_crypto_register_key_handler (vm, eidx, r->key_handler);
	}
      closedir (dp);
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
