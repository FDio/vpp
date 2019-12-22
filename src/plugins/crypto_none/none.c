/*
 * none- VNET_CRYPTO_ALG_NONE crypto engine
 *
 * Copyright (c) 2019 Intel and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/crypto/crypto.h>

static void
crypto_none_key_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
			    vnet_crypto_key_index_t idx)
{
  return;
}

static_always_inline u32
crypto_none_sync_inline (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops)
{
  u32 i;

  for (i = 0; i < n_ops; i++)
    ops[i]->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

  return n_ops;
}

static_always_inline u32
crypto_none_async_queue_handler (vlib_main_t * vm, u32 thread_idx,
                                 vnet_crypto_queue_t * q)
{
  vnet_crypto_op_t *op;
  u32 atomic = (thread_idx != vm->thread_index);
  u32 n = 0;

  if (atomic)
    return 0;

  while ((op = vnet_crypto_async_get_pending_op (q, atomic)) &&
      n < VLIB_FRAME_SIZE)
    {
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
      n++;
    }

  return n;
}

static clib_error_t *
crypto_none_init (vlib_main_t * vm)
{
  u32 eidx;
  u8 *name;

  /*
   * A priority that is better than OpenSSL but worse than VPP natvie
   */
  name = format (0, "None Crypto", 0);
  eidx = vnet_crypto_register_engine (vm, "none", 1, (char *) name);

  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_AES_128_GCM_ENC,
                                    crypto_none_sync_inline);
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_AES_128_GCM_DEC,
                                    crypto_none_sync_inline);
  vnet_crypto_register_queue_handler (vm, eidx, VNET_CRYPTO_OP_AES_128_GCM_ENC,
                                      crypto_none_async_queue_handler);
  vnet_crypto_register_queue_handler (vm, eidx, VNET_CRYPTO_OP_AES_128_GCM_DEC,
                                      crypto_none_async_queue_handler);
  vnet_crypto_register_key_handler (vm, eidx, crypto_none_key_handler);

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (crypto_none_init) =
{
  .runs_after = VLIB_INITS ("vnet_crypto_init"),
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "None Crypto Engine",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
