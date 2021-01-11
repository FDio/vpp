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

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>

vnet_crypto_main_t crypto_main;

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
  u32 rv = 0;
  if (n_ops == 0)
    return 0;

  if (chunks)
    {

      if (cm->chained_ops_handlers[opt] == 0)
	crypto_set_op_status (ops, n_ops,
			      VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER);
      else
	rv = (cm->chained_ops_handlers[opt]) (vm, ops, chunks, n_ops);
    }
  else
    {
      if (cm->ops_handlers[opt] == 0)
	crypto_set_op_status (ops, n_ops,
			      VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER);
      else
	rv = (cm->ops_handlers[opt]) (vm, ops, n_ops);
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
crypto_set_active_engine (vnet_crypto_op_data_t * od,
			  vnet_crypto_op_id_t id, u32 ei,
			  crypto_op_class_type_t oct)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *ce = vec_elt_at_index (cm->engines, ei);

  if (oct == CRYPTO_OP_BOTH || oct == CRYPTO_OP_CHAINED)
    {
      if (ce->chained_ops_handlers[id])
	{
	  od->active_engine_index_chained = ei;
	  cm->chained_ops_handlers[id] = ce->chained_ops_handlers[id];
	}
    }

  if (oct == CRYPTO_OP_BOTH || oct == CRYPTO_OP_SIMPLE)
    {
      if (ce->ops_handlers[id])
	{
	  od->active_engine_index_simple = ei;
	  cm->ops_handlers[id] = ce->ops_handlers[id];
	}
    }
}

int
vnet_crypto_set_handler2 (char *alg_name, char *engine,
			  crypto_op_class_type_t oct)
{
  uword *p;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad;
  int i;

  p = hash_get_mem (cm->alg_index_by_name, alg_name);
  if (!p)
    return -1;

  ad = vec_elt_at_index (cm->algs, p[0]);

  p = hash_get_mem (cm->engine_index_by_name, engine);
  if (!p)
    return -1;

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    {
      vnet_crypto_op_data_t *od;
      vnet_crypto_op_id_t id = ad->op_by_type[i];
      if (id == 0)
	continue;

      od = cm->opt_data + id;
      crypto_set_active_engine (od, id, p[0], oct);
    }

  return 0;
}

int
vnet_crypto_is_set_handler (vnet_crypto_alg_t alg)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_op_id_t opt = 0;
  int i;

  if (alg > vec_len (cm->algs))
    return 0;

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    if ((opt = cm->algs[alg].op_by_type[i]) != 0)
      break;

  return NULL != cm->ops_handlers[opt];
}

void
vnet_crypto_register_ops_handler_inline (vlib_main_t * vm, u32 engine_index,
					 vnet_crypto_op_id_t opt,
					 vnet_crypto_ops_handler_t * fn,
					 vnet_crypto_chained_ops_handler_t *
					 cfn)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *ae, *e = vec_elt_at_index (cm->engines, engine_index);
  vnet_crypto_op_data_t *otd = cm->opt_data + opt;
  vec_validate_aligned (cm->ops_handlers, VNET_CRYPTO_N_OP_IDS - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (cm->chained_ops_handlers, VNET_CRYPTO_N_OP_IDS - 1,
			CLIB_CACHE_LINE_BYTES);

  if (fn)
    {
      e->ops_handlers[opt] = fn;
      if (otd->active_engine_index_simple == ~0)
	{
	  otd->active_engine_index_simple = engine_index;
	  cm->ops_handlers[opt] = fn;
	}

      ae = vec_elt_at_index (cm->engines, otd->active_engine_index_simple);
      if (ae->priority < e->priority)
	crypto_set_active_engine (otd, opt, engine_index, CRYPTO_OP_SIMPLE);
    }

  if (cfn)
    {
      e->chained_ops_handlers[opt] = cfn;
      if (otd->active_engine_index_chained == ~0)
	{
	  otd->active_engine_index_chained = engine_index;
	  cm->chained_ops_handlers[opt] = cfn;
	}

      ae = vec_elt_at_index (cm->engines, otd->active_engine_index_chained);
      if (ae->priority < e->priority)
	crypto_set_active_engine (otd, opt, engine_index, CRYPTO_OP_CHAINED);
    }

  return;
}

void
vnet_crypto_register_ops_handler (vlib_main_t * vm, u32 engine_index,
				  vnet_crypto_op_id_t opt,
				  vnet_crypto_ops_handler_t * fn)
{
  vnet_crypto_register_ops_handler_inline (vm, engine_index, opt, fn, 0);
}

void
vnet_crypto_register_chained_ops_handler (vlib_main_t * vm, u32 engine_index,
					  vnet_crypto_op_id_t opt,
					  vnet_crypto_chained_ops_handler_t *
					  fn)
{
  vnet_crypto_register_ops_handler_inline (vm, engine_index, opt, 0, fn);
}

void
vnet_crypto_register_ops_handlers (vlib_main_t * vm, u32 engine_index,
				   vnet_crypto_op_id_t opt,
				   vnet_crypto_ops_handler_t * fn,
				   vnet_crypto_chained_ops_handler_t * cfn)
{
  vnet_crypto_register_ops_handler_inline (vm, engine_index, opt, fn, cfn);
}

void
vnet_crypto_register_async_handler (vlib_main_t * vm, u32 engine_index,
				    vnet_crypto_async_op_id_t opt,
				    vnet_crypto_frame_enqueue_t * enqueue_hdl,
				    vnet_crypto_frame_dequeue_t * dequeue_hdl)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *ae, *e = vec_elt_at_index (cm->engines, engine_index);
  vnet_crypto_async_op_data_t *otd = cm->async_opt_data + opt;
  vec_validate_aligned (cm->enqueue_handlers, VNET_CRYPTO_ASYNC_OP_N_IDS - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (cm->dequeue_handlers, VNET_CRYPTO_ASYNC_OP_N_IDS - 1,
			CLIB_CACHE_LINE_BYTES);

  /* both enqueue hdl and dequeue hdl should present */
  if (!enqueue_hdl && !dequeue_hdl)
    return;

  e->enqueue_handlers[opt] = enqueue_hdl;
  e->dequeue_handlers[opt] = dequeue_hdl;
  if (otd->active_engine_index_async == ~0)
    {
      otd->active_engine_index_async = engine_index;
      cm->enqueue_handlers[opt] = enqueue_hdl;
      cm->dequeue_handlers[opt] = dequeue_hdl;
    }

  ae = vec_elt_at_index (cm->engines, otd->active_engine_index_async);
  if (ae->priority < e->priority)
    {
      otd->active_engine_index_async = engine_index;
      cm->enqueue_handlers[opt] = enqueue_hdl;
      cm->dequeue_handlers[opt] = dequeue_hdl;
    }

  return;
}

void
vnet_crypto_register_key_handler (vlib_main_t * vm, u32 engine_index,
				  vnet_crypto_key_handler_t * key_handler)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine_index);
  e->key_op_handler = key_handler;
  return;
}

static int
vnet_crypto_key_len_check (vnet_crypto_alg_t alg, u16 length)
{
  switch (alg)
    {
    case VNET_CRYPTO_N_ALGS:
      return 0;
    case VNET_CRYPTO_ALG_NONE:
      return 1;

#define _(n, s, l) \
      case VNET_CRYPTO_ALG_##n: \
        if ((l) == length) \
          return 1;        \
        break;
      foreach_crypto_cipher_alg foreach_crypto_aead_alg
#undef _
	/* HMAC allows any key length */
#define _(n, s) \
      case VNET_CRYPTO_ALG_HMAC_##n: \
        return 1;
        foreach_crypto_hmac_alg
#undef _
    }

  return 0;
}

u32
vnet_crypto_key_add (vlib_main_t * vm, vnet_crypto_alg_t alg, u8 * data,
		     u16 length)
{
  u32 index;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *engine;
  vnet_crypto_key_t *key;

  if (!vnet_crypto_key_len_check (alg, length))
    return ~0;

  pool_get_zero (cm->keys, key);
  index = key - cm->keys;
  key->type = VNET_CRYPTO_KEY_TYPE_DATA;
  key->alg = alg;
  vec_validate_aligned (key->data, length - 1, CLIB_CACHE_LINE_BYTES);
  clib_memcpy (key->data, data, length);
  /* *INDENT-OFF* */
  vec_foreach (engine, cm->engines)
    if (engine->key_op_handler)
      engine->key_op_handler (vm, VNET_CRYPTO_KEY_OP_ADD, index);
  /* *INDENT-ON* */
  return index;
}

void
vnet_crypto_key_del (vlib_main_t * vm, vnet_crypto_key_index_t index)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *engine;
  vnet_crypto_key_t *key = pool_elt_at_index (cm->keys, index);

  /* *INDENT-OFF* */
  vec_foreach (engine, cm->engines)
    if (engine->key_op_handler)
      engine->key_op_handler (vm, VNET_CRYPTO_KEY_OP_DEL, index);
  /* *INDENT-ON* */

  if (key->type == VNET_CRYPTO_KEY_TYPE_DATA)
    {
      clib_memset (key->data, 0, vec_len (key->data));
      vec_free (key->data);
    }
  else if (key->type == VNET_CRYPTO_KEY_TYPE_LINK)
    {
      key->index_crypto = key->index_integ = 0;
    }

  pool_put (cm->keys, key);
}

vnet_crypto_async_alg_t
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

u32
vnet_crypto_key_add_linked (vlib_main_t * vm,
			    vnet_crypto_key_index_t index_crypto,
			    vnet_crypto_key_index_t index_integ)
{
  u32 index;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *engine;
  vnet_crypto_key_t *key_crypto, *key_integ, *key;
  vnet_crypto_async_alg_t linked_alg;

  key_crypto = pool_elt_at_index (cm->keys, index_crypto);
  key_integ = pool_elt_at_index (cm->keys, index_integ);

  if (!key_crypto || !key_integ)
    return ~0;

  linked_alg = vnet_crypto_link_algs (key_crypto->alg, key_integ->alg);
  if (linked_alg == ~0)
    return ~0;

  pool_get_zero (cm->keys, key);
  index = key - cm->keys;
  key->type = VNET_CRYPTO_KEY_TYPE_LINK;
  key->index_crypto = index_crypto;
  key->index_integ = index_integ;
  key->async_alg = linked_alg;

  /* *INDENT-OFF* */
  vec_foreach (engine, cm->engines)
    if (engine->key_op_handler)
      engine->key_op_handler (vm, VNET_CRYPTO_KEY_OP_ADD, index);
  /* *INDENT-ON* */

  return index;
}

clib_error_t *
crypto_dispatch_enable_disable (int is_enable)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 skip_master = vlib_num_workers () > 0, i;
  vlib_node_state_t state = VLIB_NODE_STATE_DISABLED;
  u8 state_change = 0;

  CLIB_MEMORY_STORE_BARRIER ();
  if (is_enable && cm->async_refcnt > 0)
    {
      state_change = 1;
      state =
	cm->dispatch_mode ==
	VNET_CRYPTO_ASYNC_DISPATCH_POLLING ? VLIB_NODE_STATE_POLLING :
	VLIB_NODE_STATE_INTERRUPT;
    }

  if (!is_enable && cm->async_refcnt == 0)
    {
      state_change = 1;
      state = VLIB_NODE_STATE_DISABLED;
    }

  if (state_change)
    for (i = skip_master; i < tm->n_vlib_mains; i++)
      {
	if (state !=
	    vlib_node_get_state (vlib_mains[i], cm->crypto_node_index))
	  vlib_node_set_state (vlib_mains[i], cm->crypto_node_index, state);
      }
  return 0;
}

static_always_inline void
crypto_set_active_async_engine (vnet_crypto_async_op_data_t * od,
				vnet_crypto_async_op_id_t id, u32 ei)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *ce = vec_elt_at_index (cm->engines, ei);

  if (ce->enqueue_handlers[id] && ce->dequeue_handlers[id])
    {
      od->active_engine_index_async = ei;
      cm->enqueue_handlers[id] = ce->enqueue_handlers[id];
      cm->dequeue_handlers[id] = ce->dequeue_handlers[id];
    }
}

int
vnet_crypto_set_async_handler2 (char *alg_name, char *engine)
{
  uword *p;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_async_alg_data_t *ad;
  int i;

  p = hash_get_mem (cm->async_alg_index_by_name, alg_name);
  if (!p)
    return -1;

  ad = vec_elt_at_index (cm->async_algs, p[0]);

  p = hash_get_mem (cm->engine_index_by_name, engine);
  if (!p)
    return -1;

  for (i = 0; i < VNET_CRYPTO_ASYNC_OP_N_TYPES; i++)
    {
      vnet_crypto_async_op_data_t *od;
      vnet_crypto_async_op_id_t id = ad->op_by_type[i];
      if (id == 0)
	continue;

      od = cm->async_opt_data + id;
      crypto_set_active_async_engine (od, id, p[0]);
    }

  return 0;
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

  /* *INDENT-OFF* */
  vec_foreach (cm->next_nodes, nn)
  {
    if (nn->node_idx == pn->index)
      return nn->next_idx;
  }
  /* *INDENT-ON* */

  vec_validate (cm->next_nodes, index);
  nn = vec_elt_at_index (cm->next_nodes, index);

  cc = vlib_get_node_by_name (vm, (u8 *) "crypto-dispatch");
  nn->next_idx = vlib_node_add_named_next (vm, cc->index, post_node_name);
  nn->node_idx = pn->index;

  return nn->next_idx;
}

void
vnet_crypto_request_async_mode (int is_enable)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 skip_master = vlib_num_workers () > 0, i;
  vlib_node_state_t state = VLIB_NODE_STATE_DISABLED;
  u8 state_change = 0;

  CLIB_MEMORY_STORE_BARRIER ();
  if (is_enable && cm->async_refcnt == 0)
    {
      state_change = 1;
      state =
	cm->dispatch_mode == VNET_CRYPTO_ASYNC_DISPATCH_POLLING ?
	VLIB_NODE_STATE_POLLING : VLIB_NODE_STATE_INTERRUPT;
    }
  if (!is_enable && cm->async_refcnt == 1)
    {
      state_change = 1;
      state = VLIB_NODE_STATE_DISABLED;
    }

  if (state_change)
    for (i = skip_master; i < tm->n_vlib_mains; i++)
      {
	if (state !=
	    vlib_node_get_state (vlib_mains[i], cm->crypto_node_index))
	  vlib_node_set_state (vlib_mains[i], cm->crypto_node_index, state);
      }

  if (is_enable)
    cm->async_refcnt += 1;
  else if (cm->async_refcnt > 0)
    cm->async_refcnt -= 1;
}

void
vnet_crypto_set_async_dispatch_mode (u8 mode)
{
  vnet_crypto_main_t *cm = &crypto_main;
  u32 skip_master = vlib_num_workers () > 0, i;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_node_state_t state = VLIB_NODE_STATE_DISABLED;

  CLIB_MEMORY_STORE_BARRIER ();
  cm->dispatch_mode = mode;
  if (mode == VNET_CRYPTO_ASYNC_DISPATCH_INTERRUPT)
    {
      state =
	cm->async_refcnt == 0 ?
	VLIB_NODE_STATE_DISABLED : VLIB_NODE_STATE_INTERRUPT;
    }
  else if (mode == VNET_CRYPTO_ASYNC_DISPATCH_POLLING)
    {
      state =
	cm->async_refcnt == 0 ?
	VLIB_NODE_STATE_DISABLED : VLIB_NODE_STATE_POLLING;
    }

  for (i = skip_master; i < tm->n_vlib_mains; i++)
    {
      if (state != vlib_node_get_state (vlib_mains[i], cm->crypto_node_index))
	vlib_node_set_state (vlib_mains[i], cm->crypto_node_index, state);
    }
}

int
vnet_crypto_is_set_async_handler (vnet_crypto_async_op_id_t op)
{
  vnet_crypto_main_t *cm = &crypto_main;

  return (op < vec_len (cm->enqueue_handlers) &&
	  NULL != cm->enqueue_handlers[op]);
}

static void
vnet_crypto_init_cipher_data (vnet_crypto_alg_t alg, vnet_crypto_op_id_t eid,
			      vnet_crypto_op_id_t did, char *name, u8 is_aead)
{
  vnet_crypto_op_type_t eopt, dopt;
  vnet_crypto_main_t *cm = &crypto_main;

  cm->algs[alg].name = name;
  cm->opt_data[eid].alg = cm->opt_data[did].alg = alg;
  cm->opt_data[eid].active_engine_index_simple = ~0;
  cm->opt_data[did].active_engine_index_simple = ~0;
  cm->opt_data[eid].active_engine_index_chained = ~0;
  cm->opt_data[did].active_engine_index_chained = ~0;
  if (is_aead)
    {
      eopt = VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT;
      dopt = VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT;
    }
  else
    {
      eopt = VNET_CRYPTO_OP_TYPE_ENCRYPT;
      dopt = VNET_CRYPTO_OP_TYPE_DECRYPT;
    }
  cm->opt_data[eid].type = eopt;
  cm->opt_data[did].type = dopt;
  cm->algs[alg].op_by_type[eopt] = eid;
  cm->algs[alg].op_by_type[dopt] = did;
  hash_set_mem (cm->alg_index_by_name, name, alg);
}

static void
vnet_crypto_init_hmac_data (vnet_crypto_alg_t alg,
			    vnet_crypto_op_id_t id, char *name)
{
  vnet_crypto_main_t *cm = &crypto_main;
  cm->algs[alg].name = name;
  cm->algs[alg].op_by_type[VNET_CRYPTO_OP_TYPE_HMAC] = id;
  cm->opt_data[id].alg = alg;
  cm->opt_data[id].active_engine_index_simple = ~0;
  cm->opt_data[id].active_engine_index_chained = ~0;
  cm->opt_data[id].type = VNET_CRYPTO_OP_TYPE_HMAC;
  hash_set_mem (cm->alg_index_by_name, name, alg);
}

static void
vnet_crypto_init_async_data (vnet_crypto_async_alg_t alg,
			     vnet_crypto_async_op_id_t eid,
			     vnet_crypto_async_op_id_t did, char *name)
{
  vnet_crypto_main_t *cm = &crypto_main;

  cm->async_algs[alg].name = name;
  cm->async_algs[alg].op_by_type[VNET_CRYPTO_ASYNC_OP_TYPE_ENCRYPT] = eid;
  cm->async_algs[alg].op_by_type[VNET_CRYPTO_ASYNC_OP_TYPE_DECRYPT] = did;
  cm->async_opt_data[eid].type = VNET_CRYPTO_ASYNC_OP_TYPE_ENCRYPT;
  cm->async_opt_data[eid].alg = alg;
  cm->async_opt_data[eid].active_engine_index_async = ~0;
  cm->async_opt_data[eid].active_engine_index_async = ~0;
  cm->async_opt_data[did].type = VNET_CRYPTO_ASYNC_OP_TYPE_DECRYPT;
  cm->async_opt_data[did].alg = alg;
  cm->async_opt_data[did].active_engine_index_async = ~0;
  cm->async_opt_data[did].active_engine_index_async = ~0;
  hash_set_mem (cm->async_alg_index_by_name, name, alg);
}

clib_error_t *
vnet_crypto_init (vlib_main_t * vm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_crypto_thread_t *ct = 0;

  cm->dispatch_mode = VNET_CRYPTO_ASYNC_DISPATCH_POLLING;
  cm->engine_index_by_name = hash_create_string ( /* size */ 0,
						 sizeof (uword));
  cm->alg_index_by_name = hash_create_string (0, sizeof (uword));
  cm->async_alg_index_by_name = hash_create_string (0, sizeof (uword));
  vec_validate_aligned (cm->threads, tm->n_vlib_mains, CLIB_CACHE_LINE_BYTES);
  vec_foreach (ct, cm->threads)
    pool_alloc_aligned (ct->frame_pool, 1024, CLIB_CACHE_LINE_BYTES);
  vec_validate (cm->algs, VNET_CRYPTO_N_ALGS);
  vec_validate (cm->async_algs, VNET_CRYPTO_N_ASYNC_ALGS);
  clib_bitmap_validate (cm->async_active_ids, VNET_CRYPTO_ASYNC_OP_N_IDS - 1);

#define _(n, s, l) \
  vnet_crypto_init_cipher_data (VNET_CRYPTO_ALG_##n, \
				VNET_CRYPTO_OP_##n##_ENC, \
				VNET_CRYPTO_OP_##n##_DEC, s, 0);
  foreach_crypto_cipher_alg;
#undef _
#define _(n, s, l) \
  vnet_crypto_init_cipher_data (VNET_CRYPTO_ALG_##n, \
				VNET_CRYPTO_OP_##n##_ENC, \
				VNET_CRYPTO_OP_##n##_DEC, s, 1);
  foreach_crypto_aead_alg;
#undef _
#define _(n, s) \
  vnet_crypto_init_hmac_data (VNET_CRYPTO_ALG_HMAC_##n, \
			      VNET_CRYPTO_OP_##n##_HMAC, "hmac-" s);
  foreach_crypto_hmac_alg;
#undef _
#define _(n, s, k, t, a) \
  vnet_crypto_init_async_data (VNET_CRYPTO_ALG_##n##_TAG##t##_AAD##a, \
			       VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC, \
			       VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC, \
			       s);
  foreach_crypto_aead_async_alg
#undef _
#define _(c, h, s, k ,d) \
  vnet_crypto_init_async_data (VNET_CRYPTO_ALG_##c##_##h##_TAG##d, \
			       VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC, \
			       VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC, \
			       s);
    foreach_crypto_link_async_alg
#undef _
    cm->crypto_node_index =
    vlib_get_node_by_name (vm, (u8 *) "crypto-dispatch")->index;

  return 0;
}

VLIB_INIT_FUNCTION (vnet_crypto_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
