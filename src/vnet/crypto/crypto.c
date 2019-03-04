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

u32
vnet_crypto_run (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops)
{
  vnet_crypto_main_t *cm = &crypto_main;
  u32 rv = 0, i;

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_type_t opt = ops[i]->op;
      if (cm->ops_handlers[opt])
	rv += (cm->ops_handlers[opt]) (vm, ops + i, 1);
      else
	ops[i]->status = VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER;
    }

  return rv;
}

u32
vnet_crypto_submit_ops (vlib_main_t * vm, vnet_crypto_op_t ** jobs,
			u32 n_jobs)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = vec_elt_at_index (cm->threads, vm->thread_index);
  u32 n_enq = 0;
  u32 head = 0, mask = 0;
  vnet_crypto_queue_t *q = 0;
  vnet_crypto_op_type_t last_opt = ~0;

  while (n_enq < n_jobs)
    {
      vnet_crypto_op_t *j = jobs[n_enq];
      vnet_crypto_op_type_t opt = j->op;

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
	      q->op = j->op;
	      clib_bitmap_vec_validate (ct->act_queues,
					VNET_CRYPTO_N_OP_TYPES);
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

u32
vnet_crypto_no_handler_handler (vlib_main_t * vm, vnet_crypto_queue_t * q)
{
  if ((vnet_crypto_dequeue_one_job (q)))
    {
      clib_warning ("got one %U %U on thread %u",
		    format_vnet_crypto_alg, q->alg,
		    format_vnet_crypto_op, q->op, vm->thread_index);
      return 1;
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

  return p - cm->engines;
}

vlib_error_t *
vnet_crypto_register_async_queue_handler (vlib_main_t * vm,
					  u32 engine_index,
					  vnet_crypto_op_type_t opt,
					  vnet_crypto_queue_handler_t * fn)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vec_validate_init_empty_aligned (cm->queue_handlers,
				   VNET_CRYPTO_N_OP_TYPES - 1,
				   vnet_crypto_no_handler_handler,
				   CLIB_CACHE_LINE_BYTES);
  cm->queue_handlers[opt] = fn;
  return 0;
}

vlib_error_t *
vnet_crypto_register_ops_handler (vlib_main_t * vm, u32 engine_index,
				  vnet_crypto_op_type_t opt,
				  vnet_crypto_ops_handler_t * fn)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *ae, *e = vec_elt_at_index (cm->engines, engine_index);
  vnet_crypto_op_type_data_t *otd = cm->opt_data + opt;
  vec_validate_aligned (cm->ops_handlers, VNET_CRYPTO_N_OP_TYPES - 1,
			CLIB_CACHE_LINE_BYTES);
  e->ops_handlers[opt] = fn;

  if (otd->active_engine_index == ~0)
    {
      otd->active_engine_index = engine_index;
      cm->ops_handlers[opt] = fn;
      return 0;
    }
  ae = vec_elt_at_index (cm->engines, otd->active_engine_index);
  if (ae->priority < e->priority)
    {
      otd->active_engine_index = engine_index;
      cm->ops_handlers[opt] = fn;
    }

  return 0;
}

clib_error_t *
vnet_crypto_init (vlib_main_t * vm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  const char *enc = "encrypt";
  const char *dec = "decrypt";
  const char *hmac = "hmac";

  vec_validate_aligned (cm->threads, tm->n_vlib_mains, CLIB_CACHE_LINE_BYTES);
  vec_validate (cm->algs, VNET_CRYPTO_N_ALGS);

#define _(n, s) \
  cm->algs[VNET_CRYPTO_ALG_##n].name = s; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_ENC].alg = VNET_CRYPTO_ALG_##n; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_DEC].alg = VNET_CRYPTO_ALG_##n; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_ENC].desc = enc; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_DEC].desc = dec; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_ENC].active_engine_index = ~0; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_DEC].active_engine_index = ~0;
  foreach_crypto_alg;
#undef _

#define _(n, s) \
  cm->algs[VNET_CRYPTO_ALG_##n].name = s; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_HMAC].alg = VNET_CRYPTO_ALG_##n; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_HMAC].desc = hmac; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_HMAC].active_engine_index = ~0;
  foreach_hmac_alg;
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
