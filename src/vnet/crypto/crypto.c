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
vnet_crypto_submit_ops (vlib_main_t * vm, vnet_async_crypto_op_t ** jobs,
			u32 n_jobs)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = vec_elt_at_index (cm->threads, vm->thread_index);
  u32 n_enq = 0;
  u32 head = 0, mask = 0;
  vnet_crypto_queue_t *q = 0;
  vnet_crypto_op_id_t last_opt = ~0;

  while (n_enq < n_jobs)
    {
      vnet_async_crypto_op_t *j = jobs[n_enq];
      vnet_crypto_op_id_t opt = j->data.op;

      if (opt != last_opt)
	{
	  if (q)
	    {
	      CLIB_MEMORY_STORE_BARRIER ();
	      q->head = head;
	      clib_bitmap_set_no_check (ct->act_queues, opt, 1);
	    }

	  q = ct->queues[opt];

	  /* Never used before? alloc ... */
	  if (PREDICT_FALSE (q == 0))
	    {
	      u32 sz = VNET_CRYPTO_RING_SIZE * sizeof (void *) + sizeof (*q);
	      q = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
	      ct->queues[opt] = q;
	      clib_memset_u8 (q, 0, sz);
	      q->size = VNET_CRYPTO_RING_SIZE;
	      q->op = j->data.op;
	      clib_bitmap_vec_validate (ct->act_queues, VNET_CRYPTO_N_OP_IDS);
	    }

	  head = q->head;
	  mask = q->size - 1;
	  last_opt = opt;
	}

      /* job is not taken from the queue if pointer is still set */
      if (q->jobs[head & mask])
	goto done;

      q->jobs[head & mask] = j;
      head += 1;
      n_enq += 1;
    }

done:
  if (n_enq)
    {
      CLIB_MEMORY_STORE_BARRIER ();
      q->head = head;
      clib_bitmap_set_no_check (ct->act_queues, last_opt, 1);
    }
  return n_enq;
}

vnet_async_crypto_op_t *
vnet_crypto_no_handler_handler (vlib_main_t * vm, vnet_crypto_queue_t * q)
{
  vnet_async_crypto_op_t *j;
  if ((j = vnet_crypto_dequeue_one_job (q)))
    {
      clib_warning ("got one %U %U on thread %u",
		    format_vnet_crypto_alg, q->alg,
		    format_vnet_crypto_op, q->op, vm->thread_index);
      return j;
    }

  return 0;
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
      od = vec_elt_at_index (cm->opt_data, id);
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

  return (NULL != cm->ops_handlers[alg]);
}

vlib_error_t *
vnet_crypto_register_async_queue_handler (vlib_main_t * vm,
					  u32 engine_index,
					  vnet_crypto_op_id_t opt,
					  vnet_crypto_queue_handler_t * fn)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vec_validate_init_empty_aligned (cm->queue_handlers,
				   VNET_CRYPTO_N_OP_IDS - 1,
				   vnet_crypto_no_handler_handler,
				   CLIB_CACHE_LINE_BYTES);
  cm->queue_handlers[opt] = fn;
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
