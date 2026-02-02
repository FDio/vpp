/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vnet/crypto/crypto.h>
#include <native/crypto_native.h>
#include <vnet/crypto/engine.h>

crypto_native_main_t crypto_native_main;
vnet_crypto_engine_op_handlers_t op_handlers[64], *ophp = op_handlers;

static void
crypto_native_key_handler (vnet_crypto_key_op_t kop, vnet_crypto_key_handler_args_t a)
{
  crypto_native_main_t *cm = &crypto_native_main;

  if (cm->key_fn[a.alg] == 0)
    return;

  cm->key_fn[a.alg](kop, a);
}

static char *
crypto_native_init (vnet_crypto_engine_registration_t *r)
{
  crypto_native_main_t *cm = &crypto_native_main;

  if (cm->op_handlers == 0)
    return 0;

  crypto_native_op_handler_t *oh = cm->op_handlers;
  crypto_native_key_handler_t *kh = cm->key_handlers;
  crypto_native_op_handler_t **best_by_op_id = 0;
  crypto_native_key_handler_t **best_by_alg_id = 0;

  while (oh)
    {
      vec_validate (best_by_op_id, oh->op_id);

      if (best_by_op_id[oh->op_id] == 0 ||
	  best_by_op_id[oh->op_id]->priority < oh->priority)
	best_by_op_id[oh->op_id] = oh;

      oh = oh->next;
    }

  while (kh)
    {
      vec_validate (best_by_alg_id, kh->alg_id);

      if (best_by_alg_id[kh->alg_id] == 0 ||
	  best_by_alg_id[kh->alg_id]->priority < kh->priority)
	best_by_alg_id[kh->alg_id] = kh;

      r->key_data_sz[kh->alg_id] = kh->key_data_sz;
      kh = kh->next;
    }

  vec_foreach_pointer (oh, best_by_op_id)
    if (oh)
      {
	*ophp = (vnet_crypto_engine_op_handlers_t){ .opt = oh->op_id,
						    .fn = oh->fn,
						    .cfn = oh->cfn };
	ophp++;
	ASSERT ((ophp - op_handlers) < ARRAY_LEN (op_handlers));
      }

  vec_foreach_pointer (kh, best_by_alg_id)
    if (kh)
      cm->key_fn[kh->alg_id] = kh->key_fn;

  vec_free (best_by_op_id);
  vec_free (best_by_alg_id);

  return 0;
}

VNET_CRYPTO_ENGINE_REGISTRATION () = {
  .name = "native",
  .desc = "Native ISA Optimized Crypto",
  .prio = 100,
  .init_fn = crypto_native_init,
  .key_handler = crypto_native_key_handler,
  .op_handlers = op_handlers,
};
