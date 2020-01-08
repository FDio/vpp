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

static_always_inline u32
vnet_crypto_process_ops_call_handler (vlib_main_t * vm,
				      vnet_crypto_main_t * cm,
				      vnet_crypto_op_id_t opt,
				      vnet_crypto_op_t * ops[], u32 n_ops)
{
  if (n_ops == 0)
    return 0;

  if (cm->ops_handlers[opt] == 0)
    {
      while (n_ops--)
	{
	  ops[0]->status = VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER;
	  ops++;
	}
      return 0;
    }

  return (cm->ops_handlers[opt]) (vm, ops, n_ops);
}

static_always_inline u32
vnet_crypto_enqueue_ops_call_handler (vlib_main_t * vm,
				      vnet_crypto_main_t * cm,
				      vnet_crypto_op_id_t opt,
				      vnet_crypto_op_t * ops[], u32 n_ops)
{
  vnet_crypto_thread_t *ct = cm->threads + vm->thread_index;
  u32 n_enq;
  if (n_ops == 0)
    return 0;

  if (cm->async_ops[opt].enqueue_handler == 0)
    {
      while (n_ops--)
	{
	  ops[0]->status = VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER;
	  ops++;
	}
      return 0;
    }

  n_enq = (cm->async_ops[opt].enqueue_handler) (vm, ops, n_ops);
  ct->inflight[opt] += n_enq;
  return n_enq;
}

u32
vnet_crypto_process_ops (vlib_main_t * vm, vnet_crypto_op_t ops[], u32 n_ops)
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
						      op_queue, n_op_queue);
	  n_op_queue = 0;
	  current_op_type = opt;
	}

      op_queue[n_op_queue++] = &ops[i];
    }

  rv += vnet_crypto_process_ops_call_handler (vm, cm, current_op_type,
					      op_queue, n_op_queue);
  return rv;
}

u32
vnet_crypto_submit_ops (vlib_main_t * vm, vnet_crypto_op_t ** jobs,
			u32 n_jobs)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_op_id_t opt, current_op_type = ~0;
  vnet_crypto_op_t **first_job = jobs;
  vnet_crypto_op_t *failed_jobs[n_jobs], **failed_job = failed_jobs;
  u32 n_enq, n_fail = 0;
  u32 rv = 0, n = 0;

  ASSERT (n_jobs >= 1);

  while (n_jobs--)
    {
      opt = jobs[0]->op;

      if (current_op_type != opt)
	{
	  n_enq = vnet_crypto_enqueue_ops_call_handler (vm, cm, current_op_type,
							first_job, n);
	  rv += n_enq;
	  /* the failed n enqueue jobs are alreadys in the tail, write them
	   * to the failed job array
	   */
	  if (n_enq < n)
	    {
	      while (n_enq < n)
		failed_job[n_fail++] = first_job[n_enq++];
	    }

	  current_op_type = opt;
	  n = 0;
	  first_job = jobs;
	}

      n++;
    }

  n_enq = vnet_crypto_enqueue_ops_call_handler (vm, cm, current_op_type,
						first_job, n);
  rv += n_enq;
  if (n_enq < n)
    {
      while (n_enq < n)
	failed_job[n_fail++] = first_job[n_enq++];
    }

  /**
   * Write the failed jobs to the end of the jobs array for applications to
   * free.
   **/
  if (n_fail)
    {
      jobs -= n_fail;
      while (n_fail--)
	{
	  jobs[0] = failed_job[0];
	  jobs++;
	  failed_job++;
	}
    }

  return rv;
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

int
vnet_crypto_set_handler (char *alg_name, char *engine)
{
  uword *p;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad;
  vnet_crypto_engine_t *ce;
  int i;

  p = hash_get_mem (cm->alg_index_by_name, alg_name);
  if (!p)
    return -1;

  ad = vec_elt_at_index (cm->algs, p[0]);

  p = hash_get_mem (cm->engine_index_by_name, engine);
  if (!p)
    return -1;

  ce = vec_elt_at_index (cm->engines, p[0]);

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    {
      vnet_crypto_op_data_t *od;
      vnet_crypto_op_id_t id = ad->op_by_type[i];
      if (id == 0)
	continue;
      od = cm->opt_data + id;
      if (ce->ops_handlers[id])
	{
	  od->active_engine_index = p[0];
	  cm->ops_handlers[id] = ce->ops_handlers[id];
	}
    }

  return 0;
}

int
vnet_crypto_is_set_handler (vnet_crypto_alg_t alg)
{
  vnet_crypto_main_t *cm = &crypto_main;

  return (alg < vec_len (cm->ops_handlers) && NULL != cm->ops_handlers[alg]);
}

int
vnet_crypto_set_async_handler (char *alg_name, char *engine)
{
  uword *p;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad;
  vnet_crypto_engine_t *ce;
  int i;

  p = hash_get_mem (cm->alg_index_by_name, alg_name);
  if (!p)
    return -1;

  ad = vec_elt_at_index (cm->algs, p[0]);

  p = hash_get_mem (cm->engine_index_by_name, engine);
  if (!p)
    return -1;

  ce = vec_elt_at_index (cm->engines, p[0]);

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    {
      vnet_crypto_async_op_data_t *od;
      vnet_crypto_op_data_t *otd;
      vnet_crypto_op_id_t id = ad->op_by_type[i];
      if (id == 0)
	continue;
      otd = cm->opt_data + id;
      od = cm->async_ops + id;
      otd->active_async_engine_index = p[0];
      od->enqueue_handler = ce->enqueue_handler[id];
      od->dequeue_handler = ce->dequeue_handler[id];
      od->op_alloc = ce->op_alloc[id];
      od->op_free = ce->op_free[id];
    }

  return 0;
}

void
vnet_crypto_register_ops_handler (vlib_main_t * vm, u32 engine_index,
				  vnet_crypto_op_id_t opt,
				  vnet_crypto_ops_handler_t * fn)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *ae, *e = vec_elt_at_index (cm->engines, engine_index);
  vnet_crypto_op_data_t *otd = cm->opt_data + opt;
  vec_validate_aligned (cm->ops_handlers, VNET_CRYPTO_N_OP_IDS - 1,
			CLIB_CACHE_LINE_BYTES);
  e->ops_handlers[opt] = fn;

  if (otd->active_engine_index == ~0)
    {
      otd->active_engine_index = engine_index;
      cm->ops_handlers[opt] = fn;
      return;
    }
  ae = vec_elt_at_index (cm->engines, otd->active_engine_index);
  if (ae->priority < e->priority)
    {
      otd->active_engine_index = engine_index;
      cm->ops_handlers[opt] = fn;
    }

  return;
}

void
vnet_crypto_register_async_handlers (vlib_main_t *vm, u32 engine_index,
				     vnet_crypto_op_id_t opt,
				     vnet_crypto_ops_handler_t * enqueue_oph,
				     vnet_crypto_ops_handler_t * dequeue_oph,
				     vnet_crypto_op_alloc_t * alloc_oph,
				     vnet_crypto_op_free_t * free_oph)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *ae, *e = vec_elt_at_index (cm->engines, engine_index);
  vnet_crypto_op_data_t *otd = cm->opt_data + opt;
  vnet_crypto_async_op_data_t *odt;

  vec_validate_aligned (cm->async_ops, VNET_CRYPTO_N_OP_IDS - 1,
			CLIB_CACHE_LINE_BYTES);

  e->enqueue_handler[opt] = enqueue_oph;
  e->dequeue_handler[opt] = dequeue_oph;
  e->op_alloc[opt] = alloc_oph;
  e->op_free[opt] = free_oph;

  odt = cm->async_ops + opt;
  if (otd->active_async_engine_index == ~0)
    {
      otd->active_async_engine_index = engine_index;
      odt->enqueue_handler = enqueue_oph;
      odt->dequeue_handler = dequeue_oph;
      odt->op_alloc = alloc_oph;
      odt->op_free = free_oph;
      return;
    }
  ae = vec_elt_at_index (cm->engines, otd->active_async_engine_index);
  if (ae->priority < e->priority)
    {
      otd->active_async_engine_index = engine_index;
      odt->enqueue_handler = enqueue_oph;
      odt->dequeue_handler = dequeue_oph;
      odt->op_alloc = alloc_oph;
      odt->op_free = free_oph;
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

  clib_memset (key->data, 0, vec_len (key->data));
  vec_free (key->data);
  pool_put (cm->keys, key);
}

int
vnet_crypto_set_async_mode (char *alg_name, u32 is_async)
{
  uword *p;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad;
  int i;

  p = hash_get_mem (cm->alg_index_by_name, alg_name);
  if (!p)
    return -1;

  ad = vec_elt_at_index (cm->algs, p[0]);

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    {
      vnet_crypto_op_id_t id = ad->op_by_type[i];
      if (id == 0)
	continue;
      cm->is_async[id] = is_async ? 1 : 0;
    }

  return 0;
}

u32
vnet_crypto_is_async_mode (vnet_crypto_op_id_t opt)
{
  vnet_crypto_main_t *cm = &crypto_main;
  ASSERT (opt < VNET_CRYPTO_N_OP_IDS);

  return cm->is_async[opt] ? 1 : 0;
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

static u32
vnet_crypto_no_queue_handler (vlib_main_t * vm, vnet_crypto_op_t * ops[],
			      u32 n_ops)
{
  u32 i;

  for (i = 0; i < n_ops; i++)
    ops[i]->status = VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER;

  return 0;
}

static vnet_crypto_op_t *
vnet_crypto_no_op_alloc_handler (vlib_main_t *vm, vnet_crypto_op_id_t opt)
{
  return 0;
}

static void
vnet_crypto_no_op_free_handler (vlib_main_t *vm, vnet_crypto_op_t *op)
{
  return;
}

static void
vnet_crypto_init_cipher_data (vnet_crypto_alg_t alg, vnet_crypto_op_id_t eid,
			      vnet_crypto_op_id_t did, char *name, u8 is_aead)
{
  vnet_crypto_op_type_t eopt, dopt;
  vnet_crypto_main_t *cm = &crypto_main;
  cm->algs[alg].name = name;
  cm->opt_data[eid].alg = cm->opt_data[did].alg = alg;
  cm->opt_data[eid].active_engine_index = ~0;
  cm->opt_data[did].active_engine_index = ~0;
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
  cm->opt_data[eid].active_async_engine_index = ~0;
  cm->opt_data[did].active_async_engine_index = ~0;

  /* set default handlers to no handler to avoid seg fault */
  cm->async_ops[eid].enqueue_handler = vnet_crypto_no_queue_handler;
  cm->async_ops[eid].dequeue_handler = vnet_crypto_no_queue_handler;
  cm->async_ops[eid].op_alloc = vnet_crypto_no_op_alloc_handler;
  cm->async_ops[eid].op_free = vnet_crypto_no_op_free_handler;
  cm->async_ops[did].enqueue_handler = vnet_crypto_no_queue_handler;
  cm->async_ops[did].dequeue_handler = vnet_crypto_no_queue_handler;
  cm->async_ops[did].op_alloc = vnet_crypto_no_op_alloc_handler;
  cm->async_ops[did].op_free = vnet_crypto_no_op_free_handler;

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
  cm->opt_data[id].active_engine_index = ~0;
  cm->opt_data[id].active_async_engine_index = ~0;
  /* set default handlers to no handler to avoid seg fault */
  cm->async_ops[id].enqueue_handler = vnet_crypto_no_queue_handler;
  cm->async_ops[id].dequeue_handler = vnet_crypto_no_queue_handler;
  cm->async_ops[id].op_alloc = vnet_crypto_no_op_alloc_handler;
  cm->async_ops[id].op_free = vnet_crypto_no_op_free_handler;
  cm->opt_data[id].type = VNET_CRYPTO_OP_TYPE_HMAC;
  hash_set_mem (cm->alg_index_by_name, name, alg);
}

clib_error_t *
vnet_crypto_init (vlib_main_t * vm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  cm->engine_index_by_name = hash_create_string ( /* size */ 0,
						 sizeof (uword));
  cm->alg_index_by_name = hash_create_string (0, sizeof (uword));
  vec_validate_aligned (cm->threads, tm->n_vlib_mains, CLIB_CACHE_LINE_BYTES);
  vec_validate (cm->async_ops, VNET_CRYPTO_N_OP_IDS - 1);
  vec_validate (cm->algs, VNET_CRYPTO_N_ALGS);
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
