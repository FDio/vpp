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

#ifndef __crypto_native_h__
#define __crypto_native_h__

typedef void *(crypto_native_key_fn_t) (vnet_crypto_key_t * key);
typedef int (crypto_native_variant_probe_t) ();

typedef struct crypto_native_op_handler
{
  struct crypto_native_op_handler *next;
  vnet_crypto_op_id_t op_id;
  vnet_crypto_ops_handler_t *fn;
  vnet_crypto_chained_ops_handler_t *cfn;
  crypto_native_variant_probe_t *probe;
  int priority;
} crypto_native_op_handler_t;

typedef struct crypto_native_key_handler
{
  struct crypto_native_key_handler *next;
  vnet_crypto_alg_t alg_id;
  crypto_native_key_fn_t *key_fn;
  crypto_native_variant_probe_t *probe;
  int priority;
} crypto_native_key_handler_t;

typedef struct
{
  u32 crypto_engine_index;
  crypto_native_key_fn_t *key_fn[VNET_CRYPTO_N_ALGS];
  void **key_data;
  crypto_native_op_handler_t *op_handlers;
  crypto_native_key_handler_t *key_handlers;
} crypto_native_main_t;

extern crypto_native_main_t crypto_native_main;

#define CRYPTO_NATIVE_OP_HANDLER(x)                                           \
  static crypto_native_op_handler_t __crypto_native_op_handler_##x;           \
  static void __clib_constructor __crypto_native_op_handler_cb_##x (void)     \
  {                                                                           \
    crypto_native_main_t *cm = &crypto_native_main;                           \
    int priority = __crypto_native_op_handler_##x.probe ();                   \
    if (priority >= 0)                                                        \
      {                                                                       \
	__crypto_native_op_handler_##x.priority = priority;                   \
	__crypto_native_op_handler_##x.next = cm->op_handlers;                \
	cm->op_handlers = &__crypto_native_op_handler_##x;                    \
      }                                                                       \
  }                                                                           \
  static crypto_native_op_handler_t __crypto_native_op_handler_##x

#define CRYPTO_NATIVE_KEY_HANDLER(x)                                          \
  static crypto_native_key_handler_t __crypto_native_key_handler_##x;         \
  static void __clib_constructor __crypto_native_key_handler_cb_##x (void)    \
  {                                                                           \
    crypto_native_main_t *cm = &crypto_native_main;                           \
    int priority = __crypto_native_key_handler_##x.probe ();                  \
    if (priority >= 0)                                                        \
      {                                                                       \
	__crypto_native_key_handler_##x.priority = priority;                  \
	__crypto_native_key_handler_##x.next = cm->key_handlers;              \
	cm->key_handlers = &__crypto_native_key_handler_##x;                  \
      }                                                                       \
  }                                                                           \
  static crypto_native_key_handler_t __crypto_native_key_handler_##x
#endif /* __crypto_native_h__ */

