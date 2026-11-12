/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#ifndef included_unittest_crypto_test_h
#define included_unittest_crypto_test_h

#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>
#include <unittest/crypto/crypto.h>

static_always_inline vnet_crypto_op_type_t
crypto_test_first_op_type (vnet_crypto_alg_t alg)
{
  int i;

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    if (vnet_crypto_alg_has_op_type (alg, i))
      return i;

  return VNET_CRYPTO_OP_N_TYPES;
}

vnet_crypto_ctx_t *crypto_test_ctx_add_data (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
					     vnet_crypto_alg_t alg, const u8 *key_data, u16 key_len,
					     u8 is_async);
int crypto_test_alg_has_fixed_auth_len (vnet_crypto_alg_t alg);
int crypto_test_alg_has_fixed_aad_len (vnet_crypto_alg_t alg);
void crypto_test_async_deq_node_disable (vlib_node_state_t **node_states);
void crypto_test_async_deq_node_restore (vlib_node_state_t *node_states);
clib_error_t *test_crypto_perf (vlib_main_t *vm, crypto_test_main_t *tm);
clib_error_t *test_crypto_async_perf (vlib_main_t *vm, crypto_test_main_t *tm);

#endif /* included_unittest_crypto_test_h */
