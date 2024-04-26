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

vnet_crypto_main_t crypto_main = {
    .algs = {
#define _(n, s, l)                                                            \
  [VNET_CRYPTO_ALG_##n] = {                                                   \
    .index = VNET_CRYPTO_ALG_##n,                                             \
    .name = (s),                                                              \
    .key_length = (l),                                                        \
    .op_by_type = { [VNET_CRYPTO_OP_TYPE_ENCRYPT] = VNET_CRYPTO_OP_##n##_ENC, \
		    [VNET_CRYPTO_OP_TYPE_DECRYPT] =                           \
		      VNET_CRYPTO_OP_##n##_DEC },                             \
  },
    foreach_crypto_block_alg
    foreach_crypto_stream_alg
#undef _
#define _(n, s, l)                                                            \
  [VNET_CRYPTO_ALG_##n] = {                                                   \
    .index = VNET_CRYPTO_ALG_##n,                                             \
    .name = (s),                                                              \
    .key_length = (l),                                                        \
    .is_aead = 1,                                                             \
    .op_by_type = { [VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT] =                      \
		      VNET_CRYPTO_OP_##n##_ENC,                               \
		    [VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT] =                      \
		      VNET_CRYPTO_OP_##n##_DEC },                             \
  },
    foreach_crypto_aead_alg
#undef _
#define _(n, s)                                                               \
  [VNET_CRYPTO_ALG_##n] = {                                                   \
    .index = VNET_CRYPTO_ALG_##n,                                             \
    .name = (s),                                                              \
    .variable_key_length = 1,                                                 \
    .op_by_type = { [VNET_CRYPTO_OP_TYPE_HASH] = VNET_CRYPTO_OP_##n##_HASH,   \
		    [VNET_CRYPTO_OP_TYPE_HMAC] = VNET_CRYPTO_OP_##n##_HMAC }, \
  },
    foreach_crypto_hash_alg
#undef _
    },
} ;

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

      if (cm->opt_data[opt].chained_ops_fn == 0)
	crypto_set_op_status (ops, n_ops,
			      VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER);
      else
	rv = (cm->opt_data[opt].chained_ops_fn) (vm, ops, chunks, n_ops);
    }
  else
    {
      if (cm->opt_data[opt].ops_fn == 0)
	crypto_set_op_status (ops, n_ops,
			      VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER);
      else
	rv = (cm->opt_data[opt].ops_fn) (vm, ops, n_ops);
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
	  cm->opt_data[id].chained_ops_fn = ce->chained_ops_handlers[id];
	}
    }

  if (oct == CRYPTO_OP_BOTH || oct == CRYPTO_OP_SIMPLE)
    {
      if (ce->ops_handlers[id])
	{
	  od->active_engine_index_simple = ei;
	  cm->opt_data[id].ops_fn = ce->ops_handlers[id];
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

  ad = cm->algs + p[0];

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

  if (alg >= ARRAY_LEN (cm->algs))
    return 0;

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    if ((opt = cm->algs[alg].op_by_type[i]) != 0)
      break;

  if (opt >= ARRAY_LEN (cm->opt_data))
    return 0;

  return NULL != cm->opt_data[opt].ops_fn;
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

  if (fn)
    {
      e->ops_handlers[opt] = fn;
      if (otd->active_engine_index_simple == ~0)
	{
	  otd->active_engine_index_simple = engine_index;
	  cm->opt_data[opt].ops_fn = fn;
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
	  cm->opt_data[opt].chained_ops_fn = cfn;
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
vnet_crypto_register_enqueue_handler (
  vlib_main_t *vm, vnet_crypto_register_enqueue_handler_args_t *a)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *ae,
    *e = vec_elt_at_index (cm->engines, a->engine_index);
  vnet_crypto_async_op_id_t opt = a->op_id;
  vnet_crypto_async_op_data_t *otd = cm->async_opt_data + opt;

  if (!a->enq_fn)
    return;

  e->enqueue_handlers[opt] = a->enq_fn;
  if (otd->active_engine_index_async == ~0)
    {
      otd->active_engine_index_async = a->engine_index;
      cm->async_opt_data[opt].enq_fn = a->enq_fn;
    }

  ae = vec_elt_at_index (cm->engines, otd->active_engine_index_async);
  if (ae->priority <= e->priority)
    {
      otd->active_engine_index_async = a->engine_index;
      cm->async_opt_data[opt].enq_fn = a->enq_fn;
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
  vnet_crypto_async_op_data_t *otd;
  vnet_crypto_engine_t *e;
  u32 *active_engines = 0, *ei, last_ei = ~0, i;

  for (i = 0; i < VNET_CRYPTO_ASYNC_OP_N_IDS; i++)
    {
      otd = cm->async_opt_data + i;
      if (otd->active_engine_index_async == ~0)
	continue;
      e = cm->engines + otd->active_engine_index_async;
      if (!e->dequeue_handler)
	continue;
      vec_add1 (active_engines, otd->active_engine_index_async);
    }

  vec_sort_with_function (active_engines, engine_index_cmp);

  vec_reset_length (cm->active_deq_fn);

  vec_foreach (ei, active_engines)
    {
      if (ei[0] == last_ei)
	continue;
      if (ei[0] == ~0)
	continue;

      e = cm->engines + ei[0];
      vec_add1 (cm->active_deq_fn, e->dequeue_handler);
      last_ei = ei[0];
    }

  vec_free (active_engines);
}

void
vnet_crypto_register_dequeue_handler (
  vlib_main_t *vm, vnet_crypto_register_dequeue_handler_args_t *a)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, a->engine_index);

  if (!a->deq_fn)
    return;

  e->dequeue_handler = a->deq_fn;

  vnet_crypto_update_cm_dequeue_handlers ();

  return;
}

void
vnet_crypto_register_key_handler (vlib_main_t *vm,
				  vnet_crypto_register_key_handler_args_t *a)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, a->engine_index);
  e->key_handle_fn = a->key_handle_fn;
  e->key_handle_user_data = a->user_data;
}

u32
vnet_crypto_key_add (vlib_main_t * vm, vnet_crypto_alg_t alg, u8 * data,
		     u16 length)
{
  u32 index;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *engine;
  vnet_crypto_key_t *key;

  u8 need_barrier_sync = 0;

  if (length != cm->algs[alg].key_length &&
      cm->algs[alg].variable_key_length == 0)
    return ~0;

  need_barrier_sync = pool_get_will_expand (cm->keys);
  /* If the cm->keys will expand, stop the parade. */
  if (need_barrier_sync)
    vlib_worker_thread_barrier_sync (vm);

  pool_get_zero (cm->keys, key);

  if (need_barrier_sync)
    vlib_worker_thread_barrier_release (vm);

  index = key - cm->keys;
  key->type = VNET_CRYPTO_KEY_TYPE_DATA;
  key->alg = alg;
  vec_validate_aligned (key->data, length - 1, CLIB_CACHE_LINE_BYTES);
  clib_memcpy (key->data, data, length);
  vec_foreach (engine, cm->engines)
    if (engine->key_handle_fn)
      engine->key_handle_fn (vm,
			     &(vnet_crypto_key_handle_fn_args_t){
			       .key_op = VNET_CRYPTO_KEY_OP_ADD,
			       .key_index = index,
			       .user_data = engine->key_handle_user_data });
  return index;
}

void
vnet_crypto_key_del (vlib_main_t * vm, vnet_crypto_key_index_t index)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *engine;
  vnet_crypto_key_t *key = pool_elt_at_index (cm->keys, index);

  vec_foreach (engine, cm->engines)
    if (engine->key_handle_fn)
      engine->key_handle_fn (vm,
			     &(vnet_crypto_key_handle_fn_args_t){
			       .key_op = VNET_CRYPTO_KEY_OP_DEL,
			       .key_index = index,
			       .user_data = engine->key_handle_user_data });

  if (key->type == VNET_CRYPTO_KEY_TYPE_DATA)
    {
      clib_memset (key->data, 0xfe, vec_len (key->data));
      vec_free (key->data);
    }
  else if (key->type == VNET_CRYPTO_KEY_TYPE_LINK)
    {
      key->index_crypto = key->index_integ = ~0;
    }

  pool_put (cm->keys, key);
}

void
vnet_crypto_key_update (vlib_main_t *vm, vnet_crypto_key_index_t index)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *engine;

  vec_foreach (engine, cm->engines)
    if (engine->key_handle_fn)
      engine->key_handle_fn (vm,
			     &(vnet_crypto_key_handle_fn_args_t){
			       .key_op = VNET_CRYPTO_KEY_OP_MODIFY,
			       .key_index = index,
			       .user_data = engine->key_handle_user_data });
}

vnet_crypto_async_alg_t
vnet_crypto_link_algs (vnet_crypto_alg_t crypto_alg,
		       vnet_crypto_alg_t integ_alg)
{
#define _(c, h, s, k, d)                                                      \
  if (crypto_alg == VNET_CRYPTO_ALG_##c && integ_alg == VNET_CRYPTO_ALG_##h)  \
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

  linked_alg = vnet_crypto_link_algs (key_crypto->alg, key_integ->alg);
  if (linked_alg == ~0)
    return ~0;

  pool_get_zero (cm->keys, key);
  index = key - cm->keys;
  key->type = VNET_CRYPTO_KEY_TYPE_LINK;
  key->index_crypto = index_crypto;
  key->index_integ = index_integ;
  key->async_alg = linked_alg;

  vec_foreach (engine, cm->engines)
    if (engine->key_handle_fn)
      engine->key_handle_fn (vm,
			     &(vnet_crypto_key_handle_fn_args_t){
			       .key_op = VNET_CRYPTO_KEY_OP_ADD,
			       .key_index = index,
			       .user_data = engine->key_handle_user_data });

  return index;
}

static_always_inline void
crypto_set_active_async_engine (vnet_crypto_async_op_data_t * od,
				vnet_crypto_async_op_id_t id, u32 ei)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *ce = vec_elt_at_index (cm->engines, ei);

  if (ce->enqueue_handlers[id] && ce->dequeue_handler)
    {
      od->active_engine_index_async = ei;
      cm->async_opt_data[id].enq_fn = ce->enqueue_handlers[id];
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

  vnet_crypto_update_cm_dequeue_handlers ();

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

int
vnet_crypto_is_set_async_handler (vnet_crypto_async_op_id_t op)
{
  vnet_crypto_main_t *cm = &crypto_main;

  return (op < ARRAY_LEN (cm->async_opt_data) &&
	  NULL != cm->async_opt_data[op].enq_fn);
}

static void
vnet_crypto_init_cipher_data (vnet_crypto_alg_t alg, vnet_crypto_op_id_t eid,
			      vnet_crypto_op_id_t did, char *name, u8 is_aead)
{
  vnet_crypto_op_type_t eopt, dopt;
  vnet_crypto_main_t *cm = &crypto_main;

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
}

static void
vnet_crypto_init_hash_data (vnet_crypto_alg_t alg, vnet_crypto_op_id_t id,
			    char *name)
{
  vnet_crypto_main_t *cm = &crypto_main;
  cm->opt_data[id].alg = alg;
  cm->opt_data[id].active_engine_index_simple = ~0;
  cm->opt_data[id].active_engine_index_chained = ~0;
  cm->opt_data[id].type = VNET_CRYPTO_OP_TYPE_HASH;
}

static void
vnet_crypto_init_hmac_data (vnet_crypto_alg_t alg,
			    vnet_crypto_op_id_t id, char *name)
{
  vnet_crypto_main_t *cm = &crypto_main;
  cm->opt_data[id].alg = alg;
  cm->opt_data[id].active_engine_index_simple = ~0;
  cm->opt_data[id].active_engine_index_chained = ~0;
  cm->opt_data[id].type = VNET_CRYPTO_OP_TYPE_HMAC;
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
}

clib_error_t *
vnet_crypto_init (vlib_main_t * vm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_crypto_thread_t *ct = 0;

  cm->engine_index_by_name = hash_create_string ( /* size */ 0,
						 sizeof (uword));
  cm->alg_index_by_name = hash_create_string (0, sizeof (uword));
  cm->async_alg_index_by_name = hash_create_string (0, sizeof (uword));

  FOREACH_ARRAY_ELT (a, cm->algs)
    if (a->name)
      hash_set_mem (cm->alg_index_by_name, a->name, a - cm->algs);

  vec_validate_aligned (cm->threads, tm->n_vlib_mains, CLIB_CACHE_LINE_BYTES);
  vec_foreach (ct, cm->threads)
    pool_init_fixed (ct->frame_pool, VNET_CRYPTO_FRAME_POOL_SIZE);
  vec_validate (cm->async_algs, VNET_CRYPTO_N_ASYNC_ALGS);

#define _(n, s, l) \
  vnet_crypto_init_cipher_data (VNET_CRYPTO_ALG_##n, \
				VNET_CRYPTO_OP_##n##_ENC, \
				VNET_CRYPTO_OP_##n##_DEC, s, 0);
  foreach_crypto_block_alg;
  foreach_crypto_stream_alg;
#undef _
#define _(n, s, l) \
  vnet_crypto_init_cipher_data (VNET_CRYPTO_ALG_##n, \
				VNET_CRYPTO_OP_##n##_ENC, \
				VNET_CRYPTO_OP_##n##_DEC, s, 1);
  foreach_crypto_aead_alg;
#undef _
#define _(n, s)                                                               \
  vnet_crypto_init_hash_data (VNET_CRYPTO_ALG_##n, VNET_CRYPTO_OP_##n##_HASH, \
			      s);                                             \
  vnet_crypto_init_hmac_data (VNET_CRYPTO_ALG_##n, VNET_CRYPTO_OP_##n##_HMAC, \
			      "hmac-" s);
  foreach_crypto_hash_alg;
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
