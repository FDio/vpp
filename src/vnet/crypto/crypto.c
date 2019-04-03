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
				      vnet_crypto_op_type_t opt,
				      vnet_crypto_op_t * ops[], u32 n_ops)
{
  if (n_ops == 0)
    return 0;

  if (cm->ops_handlers[opt] == 0)
    {
      while (n_ops)
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
  vnet_crypto_op_type_t opt, current_op_type = ~0;
  u32 n_op_queue = 0;
  u32 rv = 0, i;

  ASSERT (n_ops >= 1);

  for (i = 0; i < n_ops; i++)
    {
      opt = ops[i].op;

      if (current_op_type != opt || n_op_queue > op_q_size)
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
vnet_crypto_set_handler (char *ops_handler_name, char *engine)
{
  uword *p;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_op_type_t ot;
  vnet_crypto_op_type_data_t *otd;
  vnet_crypto_engine_t *ce;

  p = hash_get_mem (cm->ops_handler_index_by_name, ops_handler_name);
  if (!p)
    return -1;

  ot = p[0];
  otd = cm->opt_data + ot;

  p = hash_get_mem (cm->engine_index_by_name, engine);
  if (!p)
    return -1;

  ce = cm->engines + p[0];
  otd->active_engine_index = p[0];
  cm->ops_handlers[ot] = ce->ops_handlers[ot];

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
#define CRYPTO_ENC_STR "encrypt"
#define CRYPTO_DEC_STR "decrypt"
#define CRYPTO_HMAC_STR "hmac"

  cm->engine_index_by_name = hash_create_string ( /* size */ 0,
						 sizeof (uword));
  cm->ops_handler_index_by_name = hash_create_string (0, sizeof (uword));

  vec_validate_aligned (cm->threads, tm->n_vlib_mains, CLIB_CACHE_LINE_BYTES);
  vec_validate (cm->algs, VNET_CRYPTO_N_ALGS);

#define _(n, s) \
  cm->algs[VNET_CRYPTO_ALG_##n].name = s; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_ENC].alg = VNET_CRYPTO_ALG_##n; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_DEC].alg = VNET_CRYPTO_ALG_##n; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_ENC].desc = CRYPTO_ENC_STR; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_DEC].desc = CRYPTO_DEC_STR; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_ENC].active_engine_index = ~0; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_DEC].active_engine_index = ~0; \
  hash_set_mem (cm->ops_handler_index_by_name, CRYPTO_ENC_STR "-" s, \
      VNET_CRYPTO_OP_##n##_ENC); \
  hash_set_mem (cm->ops_handler_index_by_name, CRYPTO_DEC_STR "-" s, \
      VNET_CRYPTO_OP_##n##_DEC);
  foreach_crypto_alg;
#undef _

#define _(n, s) \
  cm->algs[VNET_CRYPTO_ALG_##n].name = s; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_HMAC].alg = VNET_CRYPTO_ALG_##n; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_HMAC].desc = CRYPTO_HMAC_STR; \
  cm->opt_data[VNET_CRYPTO_OP_##n##_HMAC].active_engine_index = ~0; \
  hash_set_mem (cm->ops_handler_index_by_name, CRYPTO_HMAC_STR "-" s, \
      VNET_CRYPTO_OP_##n##_HMAC);
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
