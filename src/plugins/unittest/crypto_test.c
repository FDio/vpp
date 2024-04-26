/*
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
 */
#include <vlib/vlib.h>
#include <vppinfra/time.h>
#include <vppinfra/cache.h>
#include <vppinfra/error.h>
#include <vnet/crypto/crypto.h>
#include <unittest/crypto/crypto.h>

crypto_test_main_t crypto_test_main;

static u32
test_crypto_get_key_sz (vnet_crypto_alg_t alg)
{
  return crypto_main.algs[alg].key_length;
}

static clib_error_t *
test_crypto_one (vlib_main_t *vm, crypto_test_main_t *tm,
		 unittest_crypto_test_registration_t *r,
		 vnet_crypto_op_id_t op, vnet_crypto_engine_t *e, int chained)
{
  vnet_crypto_main_t *cm = &crypto_main;
  clib_error_t *err = 0;
  vnet_crypto_op_data_t *od = cm->opt_data + op;
  u8 *text_alloc = 0;
  u8 *hash_alloc = 0;
  u8 *expected_text, *calculated_text, *calculated_hash;
  u32 text_len = 0;
  u32 hash_len = 0;
  u32 key_index = CLIB_U32_MAX;
  vnet_crypto_op_t *opp;

  if (r->plaintext_incremental)
    return clib_error_return (0, "incremental");

  if (r->key.length)
    key_index = vnet_crypto_key_add (vm, r->alg, r->key.data, r->key.length);

  switch (od->type)
    {
    case VNET_CRYPTO_OP_TYPE_ENCRYPT:
    case VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT:
      text_len = r->ciphertext.length;
      expected_text = r->ciphertext.data;
      break;
    case VNET_CRYPTO_OP_TYPE_DECRYPT:
    case VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT:
      text_len = r->plaintext.length;
      expected_text = r->plaintext.data;
      break;
    default:
      text_len = 0;
    }

  if (text_len)
    {
      text_alloc = clib_mem_alloc (text_len + 6);
      calculated_text = text_alloc + 3;
      for (u32 i = 0; i < text_len; i++)
	text_alloc[i] = i;
    }

  if (od->type == VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT)
    {
      hash_len = r->tag.length;
      hash_alloc = clib_mem_alloc (hash_len + 6);
      calculated_hash = hash_alloc + 3;
      for (u32 i = 0; i < hash_len; i++)
	hash_alloc[i] = i;
    }

  switch (od->type)
    {
    case VNET_CRYPTO_OP_TYPE_ENCRYPT:
      opp = &(vnet_crypto_op_t){
	.iv = r->iv.data,
	.src = r->plaintext.data,
	.len = r->plaintext.length,
	.dst = calculated_text,
	.key_index = key_index,
      };
      break;
    case VNET_CRYPTO_OP_TYPE_DECRYPT:
      opp = &(vnet_crypto_op_t){
	.iv = r->iv.data,
	.src = r->ciphertext.data,
	.len = r->ciphertext.length,
	.dst = calculated_text,
	.key_index = key_index,
      };
      break;
    case VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT:
      opp = &(vnet_crypto_op_t){
	.iv = r->iv.data,
	.aad = r->aad.data,
	.aad_len = r->aad.length,
	.src = r->plaintext.data,
	.len = r->plaintext.length,
	.tag_len = r->tag.length,
	.dst = calculated_text,
	.tag = calculated_hash,
	.key_index = key_index,
      };
      break;
    case VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT:
      opp = &(vnet_crypto_op_t){
	.iv = r->iv.data,
	.aad = r->aad.data,
	.aad_len = r->aad.length,
	.src = r->ciphertext.data,
	.len = r->ciphertext.length,
	.tag_len = r->tag.length,
	.dst = calculated_text,
	.tag = r->tag.data,
	.key_index = key_index,
      };
      break;
    default:
      err = clib_error_return (0, "unsupported type");
      goto done;
    }

  if (chained)
    {
      vnet_crypto_op_chunk_t *chunks = 0;
      u8 *src = opp->src;
      u8 *dst = opp->dst;
      u32 len = opp->len, chlen = 1;

      opp->n_chunks = 0;
      while (len)
	{
	  chlen = clib_min (len, chlen);
	  vnet_crypto_op_chunk_t ch = {
	    .src = src,
	    .dst = dst,
	    .len = chlen,
	  };
	  vec_add1 (chunks, ch);
	  opp->n_chunks++;
	  src += chlen;
	  dst += chlen;
	  len -= chlen;
	  chlen *= 2;
	}

      opp->chunk_index = 0;
      opp->flags = VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
      e->chained_ops_handlers[op](vm, &opp, chunks, 1);
      vec_free (chunks);
    }
  else
    e->ops_handlers[op](vm, &opp, 1);

  if (opp->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
    {
      err = clib_error_return (0, "bad status (%U)",
			       format_vnet_crypto_op_status, opp->status);
      goto done;
    }

  if (text_len && memcmp (expected_text, calculated_text, text_len) != 0)
    {
      err = clib_error_return (0, "bad data");
      goto done;
    }

  if (hash_len && memcmp (r->tag.data, calculated_hash, hash_len) != 0)
    {
      err = clib_error_return (0, "bad hash");
      goto done;
    }

done:
  if (key_index != CLIB_U32_MAX)
    vnet_crypto_key_del (vm, key_index);
  foreach_pointer (p, text_alloc, hash_alloc)
    if (p)
      clib_mem_free (p);
  return err;
}

static clib_error_t *
test_crypto (vlib_main_t * vm, crypto_test_main_t * tm)
{
  clib_error_t *err = 0;
  vnet_crypto_main_t *cm = &crypto_main;
  unittest_crypto_test_registration_t *r = tm->test_registrations;

  FOREACH_ARRAY_ELT (alg, cm->algs)
    {
      if (!alg->name)
	continue;
      vlib_cli_output (vm, "%s", alg->name);
      for (r = tm->test_registrations; r; r = r->next)
	{
	  if (r->alg != alg->index)
	    continue;
	  vlib_cli_output (vm, "  %s", r->name);
	  FOREACH_ARRAY_ELT (opp, alg->op_by_type)
	    {
	      vnet_crypto_op_id_t op = *opp;
	      vnet_crypto_op_data_t *od = cm->opt_data + op;
	      vnet_crypto_engine_t *e;

	      if (op == VNET_CRYPTO_OP_NONE)
		continue;

	      vlib_cli_output (vm, "    op %U", format_vnet_crypto_op_type,
			       od->type);
	      vec_foreach (e, cm->engines)
		{
		  u8 *s = 0;
		  if (e->ops_handlers[op] == 0)
		    continue;
		  s = format (s, "engine %s ", e->name);

		  s = format (s, "simple ");
		  if (e->ops_handlers[op])
		    {
		      err = test_crypto_one (vm, tm, r, op, e, 0);
		      if (err)
			{
			  s = format (s, "FAIL (%U)", format_clib_error, err);
			  clib_error_free (err);
			}
		      else
			s = format (s, "OK");
		    }
		  else
		    s = format (s, "n/a");

		  s = format (s, " chained ");
		  if (e->chained_ops_handlers[op])
		    {
		      err = test_crypto_one (vm, tm, r, op, e, 1);
		      if (err)
			{
			  s = format (s, "FAIL (%U)", format_clib_error, err);
			  clib_error_free (err);
			}
		      else
			s = format (s, "OK");
		    }
		  else
		    s = format (s, "n/a");

		  vlib_cli_output (vm, "      %v", s);
		  vec_free (s);
		}
	    }
	}
    }
  return 0;
}

static clib_error_t *
test_crypto_perf (vlib_main_t * vm, crypto_test_main_t * tm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  clib_error_t *err = 0;
  u32 n_buffers, n_alloc = 0, warmup_rounds, rounds;
  u32 *buffer_indices = 0;
  vnet_crypto_op_t *ops1 = 0, *ops2 = 0, *op1, *op2;
  vnet_crypto_alg_data_t *ad = cm->algs + tm->alg;
  vnet_crypto_key_index_t key_index = ~0;
  u8 key[64];
  int buffer_size = vlib_buffer_get_default_data_size (vm);
  u64 seed = clib_cpu_time_now ();
  u64 t0[5], t1[5], t2[5], n_bytes = 0;
  int i, j;

  if (tm->buffer_size > buffer_size)
    return clib_error_return (0, "buffer size must be <= %u", buffer_size);

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

  vlib_cli_output (vm, "%U: n_buffers %u buffer-size %u rounds %u "
		   "warmup-rounds %u",
		   format_vnet_crypto_alg, tm->alg, n_buffers, buffer_size,
		   rounds, warmup_rounds);
  vlib_cli_output (vm, "   cpu-freq %.2f GHz",
		   (f64) vm->clib_time.clocks_per_second * 1e-9);

  vnet_crypto_op_type_t ot = 0;

  for (i = 0; i < sizeof (key); i++)
    key[i] = i;

  key_index = vnet_crypto_key_add (vm, tm->alg, key,
				   test_crypto_get_key_sz (tm->alg));

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    {
      vnet_crypto_op_id_t id = ad->op_by_type[i];
      if (id == 0)
	continue;
      ot = i;
      break;
    }

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
      op1 = ops1 + i;
      op2 = ops2 + i;

      switch (ot)
	{
	case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	case VNET_CRYPTO_OP_TYPE_DECRYPT:
	  vnet_crypto_op_init (op1,
			       ad->op_by_type[VNET_CRYPTO_OP_TYPE_ENCRYPT]);
	  vnet_crypto_op_init (op2,
			       ad->op_by_type[VNET_CRYPTO_OP_TYPE_DECRYPT]);
	  op1->src = op2->src = op1->dst = op2->dst = b->data;
	  op1->key_index = op2->key_index = key_index;
	  op1->iv = op2->iv = b->data - 64;
	  n_bytes += op1->len = op2->len = buffer_size;
	  break;
	case VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT:
	case VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT:
	  vnet_crypto_op_init (op1,
			       ad->op_by_type
			       [VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT]);
	  vnet_crypto_op_init (op2,
			       ad->op_by_type
			       [VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT]);
	  op1->src = op2->src = op1->dst = op2->dst = b->data;
	  op1->key_index = op2->key_index = key_index;
	  op1->tag = op2->tag = b->data - 32;
	  op1->iv = op2->iv = b->data - 64;
	  op1->aad = op2->aad = b->data - VLIB_BUFFER_PRE_DATA_SIZE;
	  op1->aad_len = op2->aad_len = 64;
	  op1->tag_len = op2->tag_len = 16;
	  n_bytes += op1->len = op2->len = buffer_size;
	  break;
	case VNET_CRYPTO_OP_TYPE_HMAC:
	  vnet_crypto_op_init (op1, ad->op_by_type[VNET_CRYPTO_OP_TYPE_HMAC]);
	  op1->src = b->data;
	  op1->key_index = key_index;
	  op1->iv = 0;
	  op1->digest = b->data - VLIB_BUFFER_PRE_DATA_SIZE;
	  op1->digest_len = 0;
	  n_bytes += op1->len = buffer_size;
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
	  vnet_crypto_process_ops (vm, ops1, n_buffers);
	  if (ot != VNET_CRYPTO_OP_TYPE_HMAC)
	    vnet_crypto_process_ops (vm, ops2, n_buffers);
	}

      t0[i] = clib_cpu_time_now ();
      for (j = 0; j < rounds; j++)
	vnet_crypto_process_ops (vm, ops1, n_buffers);
      t1[i] = clib_cpu_time_now ();

      if (ot != VNET_CRYPTO_OP_TYPE_HMAC)
	{
	  for (j = 0; j < rounds; j++)
	    vnet_crypto_process_ops (vm, ops2, n_buffers);
	  t2[i] = clib_cpu_time_now ();
	}
    }

  for (i = 0; i < 5; i++)
    {
      f64 tpb1 = (f64) (t1[i] - t0[i]) / (n_bytes * rounds);
      f64 gbps1 = vm->clib_time.clocks_per_second * 1e-9 * 8 / tpb1;
      f64 tpb2, gbps2;

      if (ot != VNET_CRYPTO_OP_TYPE_HMAC)
	{
	  tpb2 = (f64) (t2[i] - t1[i]) / (n_bytes * rounds);
	  gbps2 = vm->clib_time.clocks_per_second * 1e-9 * 8 / tpb2;
	  vlib_cli_output (vm, "%-2u: encrypt %.03f ticks/byte, %.02f Gbps; "
			   "decrypt %.03f ticks/byte, %.02f Gbps",
			   i + 1, tpb1, gbps1, tpb2, gbps2);
	}
      else
	{
	  vlib_cli_output (vm, "%-2u: hash %.03f ticks/byte, %.02f Gbps\n",
			   i + 1, tpb1, gbps1);
	}
    }

done:
  if (n_alloc)
    vlib_buffer_free (vm, buffer_indices, n_alloc);

  if (key_index != ~0)
    vnet_crypto_key_del (vm, key_index);

  vec_free (buffer_indices);
  vec_free (ops1);
  vec_free (ops2);
  return err;
}

static clib_error_t *
test_crypto_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  crypto_test_main_t *tm = &crypto_test_main;
  unittest_crypto_test_registration_t *tr;
  int is_perf = 0;

  tr = tm->test_registrations;
  memset (tm, 0, sizeof (crypto_test_main_t));
  tm->test_registrations = tr;
  tm->alg = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	tm->verbose = 1;
      else if (unformat (input, "detail"))
	tm->verbose = 2;
      else
	if (unformat (input, "perf %U", unformat_vnet_crypto_alg, &tm->alg))
	is_perf = 1;
      else if (unformat (input, "buffers %u", &tm->n_buffers))
	;
      else if (unformat (input, "rounds %u", &tm->rounds))
	;
      else if (unformat (input, "warmup-rounds %u", &tm->warmup_rounds))
	;
      else if (unformat (input, "buffer-size %u", &tm->buffer_size))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (is_perf)
    return test_crypto_perf (vm, tm);
  else
    return test_crypto (vm, tm);
}

VLIB_CLI_COMMAND (test_crypto_command, static) =
{
  .path = "test crypto",
  .short_help = "test crypto",
  .function = test_crypto_command_fn,
};

static clib_error_t *
crypto_test_init (vlib_main_t * vm)
{
  return (0);
}

VLIB_INIT_FUNCTION (crypto_test_init);
