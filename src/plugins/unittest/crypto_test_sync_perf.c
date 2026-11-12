/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019-2026 Cisco and/or its affiliates.
 */

#include <unittest/crypto_test.h>

clib_error_t *
test_crypto_perf (vlib_main_t *vm, crypto_test_main_t *tm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  clib_error_t *err = 0;
  vnet_crypto_engine_id_t engine = VNET_CRYPTO_ENGINE_ID_INVALID;
  u32 n_buffers, n_alloc = 0, warmup_rounds, rounds;
  u32 *buffer_indices = 0;
  vnet_crypto_op_t *ops1 = 0, *ops2 = 0, *op1, *op2;
  vnet_crypto_alg_data_t *ad = cm->algs + tm->alg;
  vnet_crypto_ctx_t *ctx = 0;
  u16 combined_crypto_key_len = 0;
  u32 key_sz = 0;
  u8 combined_digest_len = 0;
  int is_combined_alg = 0;
  u8 key_data[128];
  int buffer_size = vlib_buffer_get_default_data_size (vm);
  u64 seed = clib_cpu_time_now ();
  u64 t0[5], t1[5], t2[5];
  u64 payload_bytes = 0; /* total payload bytes per round (not doubled for multi-pass) */
  int i, j;

  if (tm->buffer_size > buffer_size)
    return clib_error_return (0, "buffer size must be <= %u", buffer_size);

  if (tm->engine)
    {
      engine = vnet_crypto_get_engine_index_by_name ("%s", tm->engine);
      if (engine == VNET_CRYPTO_ENGINE_ID_INVALID)
	return clib_error_return (0, "unknown engine '%s'", tm->engine);
    }

  rounds = tm->rounds ? tm->rounds : 100;
  n_buffers = tm->n_buffers ? tm->n_buffers : 256;
  buffer_size = tm->buffer_size ? tm->buffer_size : 2048;
  warmup_rounds = tm->warmup_rounds ? tm->warmup_rounds : 100;

  if (buffer_size > vlib_buffer_get_default_data_size (vm))
    return clib_error_return (0, "buffer size too big");

  vec_validate_aligned (buffer_indices, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ops1, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ops2, n_buffers - 1, CLIB_CACHE_LINE_BYTES);

  n_alloc = vlib_buffer_alloc (vm, buffer_indices, n_buffers);
  if (n_alloc != n_buffers)
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffer_indices, n_alloc);
      err = clib_error_return (0, "buffer alloc failure");
      goto done;
    }

  vlib_cli_output (vm,
		   "%U: n_buffers %u buffer-size %u rounds %u "
		   "warmup-rounds %u",
		   format_vnet_crypto_alg, tm->alg, n_buffers, buffer_size, rounds, warmup_rounds);
  vlib_cli_output (vm, "   cpu-freq %.2f GHz", (f64) vm->clib_time.clocks_per_second * 1e-9);

  vnet_crypto_op_type_t ot;

  if (ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED)
    {
      if (vnet_crypto_alg_has_op_type (tm->alg, VNET_CRYPTO_OP_TYPE_ENCRYPT) &&
	  vnet_crypto_alg_has_op_type (tm->alg, VNET_CRYPTO_OP_TYPE_DECRYPT) && ad->cipher_key_len)
	{
	  combined_digest_len = ad->auth_len;
	  if (combined_digest_len)
	    {
	      is_combined_alg = 1;
	      combined_crypto_key_len = ad->cipher_key_len;
	    }
	}
    }

  /* Handle combined algorithms (crypto+integrity) */
  if (is_combined_alg)
    {
      key_sz = combined_crypto_key_len + 32;
    }
  else
    {
      key_sz = cm->algs[tm->alg].cipher_key_len;
      if (key_sz == 0)
	key_sz = 32; /* Use 32 bytes for HMAC algorithms (0 key_len) */
    }

  for (i = 0; i < key_sz; i++)
    key_data[i] = i;

  if (tm->engine)
    ctx = crypto_test_ctx_add_data (vm, engine, tm->alg, key_data, key_sz, 0);
  else if (is_combined_alg)
    {
      ctx = vnet_crypto_ctx_create (tm->alg);
      if (ctx && (!vnet_crypto_ctx_set_cipher_key (ctx, key_data, combined_crypto_key_len) ||
		  !vnet_crypto_ctx_set_auth_key (ctx, key_data + combined_crypto_key_len,
						 key_sz - combined_crypto_key_len)))
	{
	  vnet_crypto_ctx_destroy (vm, ctx);
	  ctx = 0;
	}
    }
  else
    {
      ctx = vnet_crypto_ctx_create (tm->alg);
      if (ctx && ((ad->alg_type == VNET_CRYPTO_ALG_T_AUTH &&
		   !vnet_crypto_ctx_set_auth_key (ctx, key_data, key_sz)) ||
		  (ad->alg_type != VNET_CRYPTO_ALG_T_AUTH &&
		   !vnet_crypto_ctx_set_cipher_key (ctx, key_data, key_sz))))
	{
	  vnet_crypto_ctx_destroy (vm, ctx);
	  ctx = 0;
	}
    }

  if (ctx == 0)
    {
      err = clib_error_return (0, "ctx create failed");
      goto done;
    }

  ot = crypto_test_first_op_type (tm->alg);
  if (ot == VNET_CRYPTO_OP_N_TYPES)
    goto done;

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
      op1 = ops1 + i;
      op2 = ops2 + i;

      switch (ot)
	{
	case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	case VNET_CRYPTO_OP_TYPE_DECRYPT:
	  vnet_crypto_op_init (ctx, op1);
	  vnet_crypto_op_init (ctx, op2);
	  op1->type = VNET_CRYPTO_OP_TYPE_ENCRYPT;
	  op2->type = VNET_CRYPTO_OP_TYPE_DECRYPT;
	  op1->src = op2->src = op1->dst = op2->dst = b->data;
	  op1->iv = op2->iv = b->data - 64;

	  if (is_combined_alg)
	    {
	      /* For combined algorithms, both encrypt and decrypt operations
	       * include integrity (HMAC) processing */
	      op1->auth_src = op2->auth_src = b->data;
	      op1->auth_src_len = op2->auth_src_len = buffer_size;
	      op1->auth = op2->auth = b->data - VLIB_BUFFER_PRE_DATA_SIZE;
	      op1->auth_len = op2->auth_len = combined_digest_len;
	      op2->flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
	    }
	  else if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
	    {
	      op1->auth = op2->auth = b->data - 32;
	      op1->aad = op2->aad = b->data - VLIB_BUFFER_PRE_DATA_SIZE;
	      op1->aad_len = op2->aad_len = 64;
	      op1->auth_len = op2->auth_len = 16;
	    }

	  op1->len = op2->len = buffer_size;
	  break;
	case VNET_CRYPTO_OP_TYPE_HMAC:
	  vnet_crypto_op_init (ctx, op1);
	  op1->type = VNET_CRYPTO_OP_TYPE_HMAC;
	  op1->auth_src = b->data;
	  op1->auth = b->data - VLIB_BUFFER_PRE_DATA_SIZE;
	  op1->auth_len = 12;
	  op1->auth_src_len = buffer_size;
	  break;
	default:
	  return 0;
	}

      for (j = -VLIB_BUFFER_PRE_DATA_SIZE; j < buffer_size; j += 8)
	*(u64 *) (b->data + j) = 1 + random_u64 (&seed);
    }

  for (i = 0; i < 5; i++)
    {
      for (j = 0; j < warmup_rounds; j++)
	{
	  if (tm->engine)
	    vnet_crypto_process_ops (vm, ops1, 0, n_buffers);
	  else
	    vnet_crypto_process_ops (vm, ops1, 0, n_buffers);
	  if (ot != VNET_CRYPTO_OP_TYPE_HMAC)
	    {
	      if (tm->engine)
		vnet_crypto_process_ops (vm, ops2, 0, n_buffers);
	      else
		vnet_crypto_process_ops (vm, ops2, 0, n_buffers);
	    }
	}

      t0[i] = clib_cpu_time_now ();
      for (j = 0; j < rounds; j++)
	{
	  if (tm->engine)
	    vnet_crypto_process_ops (vm, ops1, 0, n_buffers);
	  else
	    vnet_crypto_process_ops (vm, ops1, 0, n_buffers);
	}
      t1[i] = clib_cpu_time_now ();

      if (ot != VNET_CRYPTO_OP_TYPE_HMAC)
	{
	  for (j = 0; j < rounds; j++)
	    {
	      if (tm->engine)
		vnet_crypto_process_ops (vm, ops2, 0, n_buffers);
	      else
		vnet_crypto_process_ops (vm, ops2, 0, n_buffers);
	    }
	  t2[i] = clib_cpu_time_now ();
	}
    }

  /* establish payload bytes once (cipher len or integ_len per buffer) */
  payload_bytes = (u64) n_buffers * buffer_size;

  for (i = 0; i < 5; i++)
    {
      f64 tpb1 = (f64) (t1[i] - t0[i]) / (payload_bytes * rounds);
      f64 gbps1 = vm->clib_time.clocks_per_second * 1e-9 * 8 / tpb1;
      f64 tpb2, gbps2;

      if (ot != VNET_CRYPTO_OP_TYPE_HMAC)
	{
	  tpb2 = (f64) (t2[i] - t1[i]) / (payload_bytes * rounds);
	  gbps2 = vm->clib_time.clocks_per_second * 1e-9 * 8 / tpb2;
	  if (is_combined_alg)
	    {
	      /* For combined alg we measured encrypt(+hmac) and
	       * decrypt(+hmac-check) separately */
	      vlib_cli_output (vm,
			       "%-2u: encrypt+hmac %.03f ticks/byte, %.02f Gbps; "
			       "decrypt+hmac %.03f ticks/byte, %.02f Gbps",
			       i + 1, tpb1, gbps1, tpb2, gbps2);
	    }
	  else
	    {
	      vlib_cli_output (vm,
			       "%-2u: encrypt %.03f ticks/byte, %.02f Gbps; "
			       "decrypt %.03f ticks/byte, %.02f Gbps",
			       i + 1, tpb1, gbps1, tpb2, gbps2);
	    }
	}
      else
	{
	  vlib_cli_output (vm, "%-2u: hash %.03f ticks/byte, %.02f Gbps\n", i + 1, tpb1, gbps1);
	}
    }

done:
  if (n_alloc)
    vlib_buffer_free (vm, buffer_indices, n_alloc);

  if (ctx)
    vnet_crypto_ctx_destroy (vm, ctx);

  vec_free (buffer_indices);
  vec_free (ops1);
  vec_free (ops2);
  return err;
}
