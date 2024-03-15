/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <crypto_native/crypto_native.h>

crypto_native_main_t crypto_native_main;

static void
crypto_native_key_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
			   vnet_crypto_key_index_t idx)
{
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  crypto_native_main_t *cm = &crypto_native_main;

  /** TODO: add linked alg support **/
  if (key->type == VNET_CRYPTO_KEY_TYPE_LINK)
    return;

  if (cm->key_fn[key->alg] == 0)
    return;

  if (kop == VNET_CRYPTO_KEY_OP_DEL)
    {
      if (idx >= vec_len (cm->key_data))
	return;

      if (cm->key_data[idx] == 0)
	return;

      clib_mem_free_s (cm->key_data[idx]);
      cm->key_data[idx] = 0;
      return;
    }

  vec_validate_aligned (cm->key_data, idx, CLIB_CACHE_LINE_BYTES);

  if (kop == VNET_CRYPTO_KEY_OP_MODIFY && cm->key_data[idx])
    {
      clib_mem_free_s (cm->key_data[idx]);
    }

  cm->key_data[idx] = cm->key_fn[key->alg] (key);
}

clib_error_t *
crypto_native_init (vlib_main_t * vm)
{
  crypto_native_main_t *cm = &crypto_native_main;

  if (cm->op_handlers == 0)
    return 0;

  cm->crypto_engine_index =
    vnet_crypto_register_engine (vm, "native", 100,
				 "Native ISA Optimized Crypto");

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

      kh = kh->next;
    }

  vec_foreach_pointer (oh, best_by_op_id)
    if (oh)
      vnet_crypto_register_ops_handlers (vm, cm->crypto_engine_index,
					 oh->op_id, oh->fn, oh->cfn);

  vec_foreach_pointer (kh, best_by_alg_id)
    if (kh)
      cm->key_fn[kh->alg_id] = kh->key_fn;

  vec_free (best_by_op_id);
  vec_free (best_by_alg_id);

  vnet_crypto_register_key_handler (vm, cm->crypto_engine_index,
				    crypto_native_key_handler);
  return 0;
}

VLIB_INIT_FUNCTION (crypto_native_init) =
{
  .runs_after = VLIB_INITS ("vnet_crypto_init"),
};

#include <vpp/app/version.h>

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Native Crypto Engine",
};
