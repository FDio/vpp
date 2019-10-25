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

static int
sort_registrations (void *a0, void *a1)
{
  unittest_crypto_test_registration_t **r0 = a0;
  unittest_crypto_test_registration_t **r1 = a1;

  return (strncmp (r0[0]->name, r1[0]->name, 256));
}

static clib_error_t *
test_crypto_async (vlib_main_t * vm, crypto_test_main_t * tm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  unittest_crypto_test_registration_t *r = tm->test_registrations_async;
  unittest_crypto_test_registration_t **rv = 0;
  vnet_crypto_alg_data_t *ad;
  vnet_crypto_op_t **ops = 0, **ops_deqd = 0, *op;
  vnet_crypto_key_index_t *key_indices = 0;
  u8 *s = 0, *err = 0;
  u32 n_ops = 0;
  u32 i, n = 0, n_deq = 0;
  int fail = 0;

  vnet_crypto_async_mode_enable_disable (1);

  /* construct registration vector */
  while (r)
    {
      vec_add1 (rv, r);
      ad = vec_elt_at_index (cm->algs, r->alg);

      for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
	{
	  vnet_crypto_op_id_t id = ad->op_by_type[i];

	  if (id == 0)
	    continue;

	  switch (i)
	    {
	    case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	    case VNET_CRYPTO_OP_TYPE_DECRYPT:
	    case VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT:
	    case VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT:
	    case VNET_CRYPTO_OP_TYPE_HMAC:
	      n_ops += 1;
	      break;
	    default:
	      break;
	    };
	}

      /* next */
      r = r->next;
    }

  /* no tests registered */
  if (n_ops == 0)
    {
      vec_free (rv);
      return 0;
    }

  vec_sort_with_function (rv, sort_registrations);

  vec_validate_aligned (ops, n_ops - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ops_deqd, n_ops - 1, CLIB_CACHE_LINE_BYTES);

  /* *INDENT-OFF* */
  vec_foreach_index (i, rv)
    {
      r = rv[i];
      int t;
      ad = vec_elt_at_index (cm->algs, r->alg);
      for (t = 0; t < VNET_CRYPTO_OP_N_TYPES; t++)
        {
          vnet_crypto_op_id_t id = ad->op_by_type[t];

          if (id == 0)
            continue;

          op = clib_mem_alloc_aligned (sizeof (op[0]), CLIB_CACHE_LINE_BYTES);

          vnet_crypto_op_init (op, id);

          op->src = 0;
          op->dst = 0;
          op->aad = 0;
          op->digest = 0;
          op->tag = 0;

          switch (t)
            {
            case VNET_CRYPTO_OP_TYPE_ENCRYPT:
            case VNET_CRYPTO_OP_TYPE_DECRYPT:
              op->iv = r->iv.data;
              op->key_index = vnet_crypto_key_add (vm, r->alg,
                                                   r->key.data,
                                                   r->key.length);
              vec_add1 (key_indices, op->key_index);
              op->len = r->plaintext.length;
              op->src = vlib_physmem_alloc (vm, op->len);
              if (!op->src)
                {
                  vlib_cli_output (vm, "Failed to allocate %u bytes data\n",
                                   op->len);
                  fail = 1;
                  break;
                }
              memcpy (op->src, t == VNET_CRYPTO_OP_TYPE_ENCRYPT ?
                r->plaintext.data : r->ciphertext.data, op->len);
              op->dst = vlib_physmem_alloc (vm, op->len);
              if (!op->dst)
                {
                  vlib_cli_output (vm, "Failed to allocate %u bytes data\n",
                                   op->len);
                  fail = 1;
                  break;
                }
              break;
            case VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT:
            case VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT:
              op->iv = r->iv.data;
              op->key_index = vnet_crypto_key_add (vm, r->alg,
                                                   r->key.data,
                                                   r->key.length);
              vec_add1 (key_indices, op->key_index);
              op->aad_len = r->aad.length;
              op->len = r->plaintext.length;
              op->aad = vlib_physmem_alloc (vm, op->aad_len);
              if (!op->aad)
                {
                  vlib_cli_output (vm, "Failed to allocate %u bytes data\n",
                                   op->aad_len);
                  fail = 1;
                  break;
                }
              op->src = vlib_physmem_alloc (vm, op->len);
              if (!op->src)
                {
                  vlib_cli_output (vm, "Failed to allocate %u bytes data\n",
                                   op->len);
                  fail = 1;
                  break;
                }
              op->dst = vlib_physmem_alloc (vm, op->len);
              if (!op->dst)
                {
                  vlib_cli_output (vm, "Failed to allocate %u bytes data\n",
                                   op->len);
                  fail = 1;
                  break;
                }

              op->tag = vlib_physmem_alloc (vm, r->tag.length);
              if (!op->tag)
                {
                  vlib_cli_output (vm, "Failed to allocate %u bytes data\n",
                                   r->tag.length);
                  fail = 1;
                  break;
                }

              if (t == VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT)
                  memcpy (op->src, r->plaintext.data, op->len);
              else
                {
                  memcpy (op->src, r->ciphertext.data, op->len);
                  memcpy (op->tag, r->tag.data, op->tag_len);
                }
              op->tag_len = r->tag.length;
              break;
            case VNET_CRYPTO_OP_TYPE_HMAC:
              op->key_index = vnet_crypto_key_add (vm, r->alg,
                                                   r->key.data,
                                                   r->key.length);
              vec_add1 (key_indices, op->key_index);
              op->len = r->plaintext.length;
              op->src = vlib_physmem_alloc (vm, op->len);
              if (!op->src)
                {
                  vlib_cli_output (vm, "Failed to allocate %u bytes data\n",
                                   op->len);
                  fail = 1;
                  break;
                }
              op->digest_len = r->digest.length;
              op->digest = vlib_physmem_alloc (vm, op->digest_len);
              if (!op->digest)
                {
                  vlib_cli_output (vm, "Failed to allocate %u bytes data\n",
                                   op->len);
                  fail = 1;
                  break;
                }
              memcpy (op->src, r->plaintext.data, op->len);
              break;
            default:
              break;
            };

          op->user_data = i;
          ops[n++] = op;
        }
    }
  /* *INDENT-ON* */
  n = vnet_crypto_async_enqueue_ops (vm, ops, vec_len (ops));
  if (n != vec_len (ops))
    {
      vlib_cli_output (vm, "Cannot submit %u jobs", n);
      for (i = n; i < vec_len (ops); i++)
	clib_mem_free (ops[i]);
      fail = 1;
    }

  if (!fail)
    {
      u32 q_idx;
      u32 thread_id = vm->thread_index;
      u32 retry = 0;

      while (n_deq < n && retry++ < 10000)
	{
	  for (q_idx = 0; q_idx < VNET_CRYPTO_N_OP_IDS && n_deq < n; q_idx++)
	    {
	      vnet_crypto_async_dispatch_one_queue (vm, thread_id, q_idx);
	      n_deq += vnet_crypto_async_crypto_dequeue_ops (vm, q_idx,
							     ops_deqd + n_deq,
							     vec_len (ops));
	    }
	}
      if (n_deq < n)
	{
	  vlib_cli_output (vm, "Timeout dequeue ops");
	  fail = 1;
	}
    }
  else
    {
      for (i = 0; i < n; i++)
	clib_mem_free (ops[i]);

      return 0;
    }

  for (i = 0; i < n_deq; i++)
    {
      op = ops_deqd[i];
      r = rv[op->user_data];
      unittest_crypto_test_data_t *exp_pt = 0, *exp_ct = 0;
      unittest_crypto_test_data_t *exp_digest = 0, *exp_tag = 0;

      switch (vnet_crypto_get_op_type (op->op))
	{
	case VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT:
	  exp_tag = &r->tag;
	  /* fall through */
	case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	  exp_ct = &r->ciphertext;
	  break;
	case VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT:
	case VNET_CRYPTO_OP_TYPE_DECRYPT:
	  exp_pt = &r->plaintext;
	  break;
	case VNET_CRYPTO_OP_TYPE_HMAC:
	  exp_digest = &r->digest;
	  break;
	default:
	  break;
	}

      vec_reset_length (err);

      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	err = format (err, "%sengine error: %U", vec_len (err) ? ", " : "",
		      format_vnet_crypto_op_status, op->status);

      if (exp_ct && memcmp (op->dst, exp_ct->data, exp_ct->length) != 0)
	err = format (err, "%sciphertext mismatch",
		      vec_len (err) ? ", " : "");

      if (exp_pt && memcmp (op->dst, exp_pt->data, exp_pt->length) != 0)
	err = format (err, "%splaintext mismatch", vec_len (err) ? ", " : "");

      if (exp_tag && memcmp (op->tag, exp_tag->data, exp_tag->length) != 0)
	err = format (err, "%stag mismatch", vec_len (err) ? ", " : "");

      if (exp_digest &&
	  memcmp (op->digest, exp_digest->data, exp_digest->length) != 0)
	err = format (err, "%sdigest mismatch", vec_len (err) ? ", " : "");

      vec_reset_length (s);
      s = format (s, "%s (%U)", r->name, format_vnet_crypto_op, op->op);

      if (vec_len (err))
	fail = 1;

      vlib_cli_output (vm, "%-60v%s%v", s, vec_len (err) ? "FAIL: " : "OK",
		       err);
      if (tm->verbose)
	{
	  if (tm->verbose == 2)
	    fail = 1;

	  if (exp_ct && fail)
	    vlib_cli_output (vm, "Expected ciphertext:\n%U"
			     "\nCalculated ciphertext:\n%U",
			     format_hexdump, exp_ct->data, exp_ct->length,
			     format_hexdump, op->dst, exp_ct->length);
	  if (exp_pt && fail)
	    vlib_cli_output (vm, "Expected plaintext:\n%U"
			     "\nCalculated plaintext:\n%U",
			     format_hexdump, exp_pt->data, exp_pt->length,
			     format_hexdump, op->dst, exp_pt->length);
	  if (r->tag.length && fail)
	    vlib_cli_output (vm, "Expected tag:\n%U"
			     "\nCalculated tag:\n%U",
			     format_hexdump, r->tag.data, r->tag.length,
			     format_hexdump, op->tag, op->tag_len);
	  if (exp_digest && fail)
	    vlib_cli_output (vm, "Expected digest:\n%U"
			     "\nCalculated Digest:\n%U",
			     format_hexdump, exp_digest->data,
			     exp_digest->length, format_hexdump, op->digest,
			     op->digest_len);
	}
    }

  for (i = 0; i < n_deq; i++)
    {
      if (ops_deqd[i]->src)
	vlib_physmem_free (vm, ops_deqd[i]->src);
      if (ops_deqd[i]->dst)
	vlib_physmem_free (vm, ops_deqd[i]->dst);
      if (ops_deqd[i]->aad)
	vlib_physmem_free (vm, ops_deqd[i]->aad);
      if (ops_deqd[i]->tag)
	vlib_physmem_free (vm, ops_deqd[i]->tag);
      clib_mem_free (ops_deqd[i]);
    }

  vec_foreach_index (i, key_indices) vnet_crypto_key_del (vm, key_indices[i]);
  /* *INDENT-ON* */

  vec_free (ops);
  vec_free (ops_deqd);
  vec_free (err);
  vec_free (rv);
  vec_free (s);
  return 0;
}

static clib_error_t *
test_crypto (vlib_main_t * vm, crypto_test_main_t * tm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  unittest_crypto_test_registration_t *r = tm->test_registrations;
  unittest_crypto_test_registration_t **rv = 0;
  vnet_crypto_alg_data_t *ad;
  vnet_crypto_op_t *ops = 0, *op;
  vnet_crypto_key_index_t *key_indices = 0;
  u8 *computed_data = 0, *s = 0, *err = 0;
  u32 computed_data_total_len = 0, n_ops = 0;
  u32 i;

  /* construct registration vector */
  while (r)
    {
      vec_add1 (rv, r);
      ad = vec_elt_at_index (cm->algs, r->alg);

      for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
	{
	  vnet_crypto_op_id_t id = ad->op_by_type[i];

	  if (id == 0)
	    continue;

	  switch (i)
	    {
	    case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	    case VNET_CRYPTO_OP_TYPE_DECRYPT:
	    case VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT:
	      computed_data_total_len += r->ciphertext.length;
	      n_ops += 1;
	      break;
	    case VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT:
	      computed_data_total_len += r->ciphertext.length;
	      computed_data_total_len += r->tag.length;
	      n_ops += 1;
	      break;
	    case VNET_CRYPTO_OP_TYPE_HMAC:
	      computed_data_total_len += r->digest.length;
	      n_ops += 1;
	      break;
	    default:
	      break;
	    };
	}

      /* next */
      r = r->next;
    }

  /* no tests registered */
  if (n_ops == 0)
    {
      vec_free (rv);
      return 0;
    }

  vec_sort_with_function (rv, sort_registrations);

  vec_validate_aligned (computed_data, computed_data_total_len - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ops, n_ops - 1, CLIB_CACHE_LINE_BYTES);
  computed_data_total_len = 0;

  op = ops;
  /* *INDENT-OFF* */
  vec_foreach_index (i, rv)
    {
      r = rv[i];
      int t;
      ad = vec_elt_at_index (cm->algs, r->alg);
      for (t = 0; t < VNET_CRYPTO_OP_N_TYPES; t++)
	{
	  vnet_crypto_op_id_t id = ad->op_by_type[t];

	  if (id == 0)
	    continue;

	  vnet_crypto_op_init (op, id);

	  switch (t)
	    {
	    case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	    case VNET_CRYPTO_OP_TYPE_DECRYPT:
	      op->iv = r->iv.data;
	      op->key_index = vnet_crypto_key_add (vm, r->alg,
						   r->key.data,
						   r->key.length);
	      vec_add1 (key_indices, op->key_index);
	      op->len = r->plaintext.length;
	      op->src = t == VNET_CRYPTO_OP_TYPE_ENCRYPT ?
		r->plaintext.data : r->ciphertext.data;
	      op->dst = computed_data + computed_data_total_len;
	      computed_data_total_len += r->ciphertext.length;
	      break;
	    case VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT:
	    case VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT:
	      op->iv = r->iv.data;
	      op->key_index = vnet_crypto_key_add (vm, r->alg,
						   r->key.data,
						   r->key.length);
	      vec_add1 (key_indices, op->key_index);
	      op->aad = r->aad.data;
	      op->aad_len = r->aad.length;
	      op->len = r->plaintext.length;
	      op->dst = computed_data + computed_data_total_len;
	      computed_data_total_len += r->ciphertext.length;
	      if (t == VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT)
		{
		  op->src = r->plaintext.data;
	          op->tag = computed_data + computed_data_total_len;
	          computed_data_total_len += r->tag.length;
		}
	      else
		{
		  op->src = r->ciphertext.data;
	          op->tag = r->tag.data;
		}
	      op->tag_len = r->tag.length;
	      break;
	    case VNET_CRYPTO_OP_TYPE_HMAC:
	      op->key_index = vnet_crypto_key_add (vm, r->alg,
						   r->key.data,
						   r->key.length);
	      vec_add1 (key_indices, op->key_index);
	      op->src = r->plaintext.data;
	      op->len = r->plaintext.length;
	      op->digest_len = r->digest.length;
	      op->digest = computed_data + computed_data_total_len;
	      computed_data_total_len += r->digest.length;
	      break;
	    default:
	      break;
	    };

	  op->user_data = i;
	  op++;
	}
    }
  /* *INDENT-ON* */

  vnet_crypto_process_ops (vm, ops, vec_len (ops));

  /* *INDENT-OFF* */
  vec_foreach (op, ops)
    {
      int fail = 0;
      r = rv[op->user_data];
      unittest_crypto_test_data_t *exp_pt = 0, *exp_ct = 0;
      unittest_crypto_test_data_t *exp_digest = 0, *exp_tag = 0;

      switch (vnet_crypto_get_op_type (op->op))
	{
	case VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT:
	  exp_tag = &r->tag;
          /* fall through */
	case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	  exp_ct = &r->ciphertext;
	  break;
	case VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT:
	case VNET_CRYPTO_OP_TYPE_DECRYPT:
	  exp_pt = &r->plaintext;
	  break;
	case VNET_CRYPTO_OP_TYPE_HMAC:
	  exp_digest = &r->digest;
	  break;
	default:
	  break;
	}

      vec_reset_length (err);

      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	err = format (err, "%sengine error: %U", vec_len (err) ? ", " : "",
		      format_vnet_crypto_op_status, op->status);

      if (exp_ct && memcmp (op->dst, exp_ct->data, exp_ct->length) != 0)
	err = format (err, "%sciphertext mismatch",
		      vec_len (err) ? ", " : "");

      if (exp_pt && memcmp (op->dst, exp_pt->data, exp_pt->length) != 0)
	err = format (err, "%splaintext mismatch", vec_len (err) ? ", " : "");

      if (exp_tag && memcmp (op->tag, exp_tag->data, exp_tag->length) != 0)
	err = format (err, "%stag mismatch", vec_len (err) ? ", " : "");

      if (exp_digest &&
	  memcmp (op->digest, exp_digest->data, exp_digest->length) != 0)
	err = format (err, "%sdigest mismatch", vec_len (err) ? ", " : "");

      vec_reset_length (s);
      s = format (s, "%s (%U)", r->name, format_vnet_crypto_op, op->op);

      if (vec_len (err))
	fail = 1;

      vlib_cli_output (vm, "%-60v%s%v", s, vec_len (err) ? "FAIL: " : "OK",
		       err);
      if (tm->verbose)
	{
	  if (tm->verbose == 2)
	    fail = 1;

	  if (exp_ct && fail)
	    vlib_cli_output (vm, "Expected ciphertext:\n%U"
			     "\nCalculated ciphertext:\n%U",
			     format_hexdump, exp_ct->data, exp_ct->length,
			     format_hexdump, op->dst, exp_ct->length);
	  if (exp_pt && fail)
	    vlib_cli_output (vm, "Expected plaintext:\n%U"
			     "\nCalculated plaintext:\n%U",
			     format_hexdump, exp_pt->data, exp_pt->length,
			     format_hexdump, op->dst, exp_pt->length);
	  if (r->tag.length && fail)
	    vlib_cli_output (vm, "Expected tag:\n%U"
			     "\nCalculated tag:\n%U",
			     format_hexdump, r->tag.data, r->tag.length,
			     format_hexdump, op->tag, op->tag_len);
	  if (exp_digest && fail)
	    vlib_cli_output (vm, "Expected digest:\n%U"
			     "\nCalculated Digest:\n%U",
			     format_hexdump, exp_digest->data,
			     exp_digest->length, format_hexdump, op->digest,
			     op->digest_len);
	}
    }

  vec_foreach_index (i, key_indices)
    vnet_crypto_key_del (vm, key_indices[i]);
  /* *INDENT-ON* */

  vec_free (computed_data);
  vec_free (ops);
  vec_free (err);
  vec_free (rv);
  vec_free (s);
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
  vnet_crypto_alg_data_t *ad = vec_elt_at_index (cm->algs, tm->alg);
  vnet_crypto_key_index_t key_index = ~0;
  u8 key[32];
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

  key_index = vnet_crypto_key_add (vm, tm->alg, key, sizeof (key));

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
	  op1->flags = VNET_CRYPTO_OP_FLAG_INIT_IV;
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
test_crypto_perf_async (vlib_main_t * vm, crypto_test_main_t * tm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  clib_error_t *err = 0;
  u32 n_buffers, n_alloc = 0, warmup_rounds, rounds, burst_sz;
  u32 *buffer_indices = 0;
  vnet_crypto_op_t **ops1 = 0, **ops2 = 0, **ops_deq = 0, *op1, *op2;
  vnet_crypto_alg_data_t *ad = vec_elt_at_index (cm->algs, tm->alg);
  vnet_crypto_key_index_t key_index = ~0;
  u8 key[32];
  int buffer_size = vlib_buffer_get_default_data_size (vm);
  u64 seed = clib_cpu_time_now ();
  u64 t0, t1, tt0[5] = { 0 }, tt1[5] =
  {
  0}, err0[5] =
  {
  0}, err1[5] =
  {
  0}, n_bytes = 0;
  u32 n_enq, n_deq;
  u32 thread_id = vm->thread_index;
  vnet_crypto_op_id_t opt1 = 0, opt2 = 0;
  int i, j, k;

  if (tm->buffer_size > buffer_size)
    return clib_error_return (0, "buffer size must be <= %u", buffer_size);

  rounds = tm->rounds ? tm->rounds : 1000;
  n_buffers = tm->n_buffers ? tm->n_buffers : 1024;
  buffer_size = tm->buffer_size ? tm->buffer_size : 2048;
  warmup_rounds = tm->warmup_rounds ? tm->warmup_rounds : 100;
  burst_sz = tm->burst_sz ? tm->burst_sz : 32;

  if (buffer_size > vlib_buffer_get_default_data_size (vm))
    return clib_error_return (0, "buffer size too big");

  vec_validate_aligned (ops1, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ops2, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ops_deq, burst_sz - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (buffer_indices, n_buffers - 1, CLIB_CACHE_LINE_BYTES);


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

  key_index = vnet_crypto_key_add (vm, tm->alg, key, 16);

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
      op1 = clib_mem_alloc_aligned (sizeof (op1[0]), CLIB_CACHE_LINE_BYTES);
      op2 = clib_mem_alloc_aligned (sizeof (op1[0]), CLIB_CACHE_LINE_BYTES);
      ops1[i] = op1;
      ops2[i] = op2;

      switch (ot)
	{
	case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	case VNET_CRYPTO_OP_TYPE_DECRYPT:
	  opt1 = ad->op_by_type[VNET_CRYPTO_OP_TYPE_ENCRYPT];
	  opt2 = ad->op_by_type[VNET_CRYPTO_OP_TYPE_DECRYPT];
	  vnet_crypto_op_init (op1, opt1);
	  vnet_crypto_op_init (op2, opt2);

	  op1->flags = VNET_CRYPTO_OP_FLAG_INIT_IV;
	  op1->src = op2->src = op1->dst = op2->dst = b->data;
	  op1->key_index = op2->key_index = key_index;
	  op1->iv = op2->iv = b->data - 64;
	  n_bytes += op1->len = op2->len = buffer_size;
	  break;
	case VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT:
	case VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT:
	  opt1 = ad->op_by_type[VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT];
	  opt2 = ad->op_by_type[VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT];
	  vnet_crypto_op_init (op1, opt1);
	  vnet_crypto_op_init (op2, opt2);
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
	  opt1 = ad->op_by_type[VNET_CRYPTO_OP_TYPE_HMAC];
	  vnet_crypto_op_init (op1, opt1);
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
	  n_enq = 0;
	  n_deq = 0;

	  while (n_deq != n_buffers)
	    {
	      u32 n = n_buffers - n_enq >= burst_sz ? burst_sz :
		n_buffers - n_enq;
	      if (n)
		n_enq += vnet_crypto_async_enqueue_ops (vm, ops1 + n_enq, n);
	      vnet_crypto_async_dispatch_one_queue (vm, thread_id, opt1);
	      n_deq += vnet_crypto_async_crypto_dequeue_ops (vm, opt1,
							     ops_deq,
							     burst_sz);
	    }

	  if (ot == VNET_CRYPTO_OP_TYPE_HMAC)
	    continue;

	  n_enq = 0;
	  n_deq = 0;

	  while (n_deq != n_buffers)
	    {
	      u32 n = n_buffers - n_enq >= burst_sz ? burst_sz :
		n_buffers - n_enq;
	      if (n)
		n_enq += vnet_crypto_async_enqueue_ops (vm, ops2 + n_enq, n);
	      vnet_crypto_async_dispatch_one_queue (vm, thread_id, opt2);
	      n_deq += vnet_crypto_async_crypto_dequeue_ops (vm, opt2,
							     ops_deq,
							     burst_sz);
	    }
	}

      for (j = 0; j < rounds; j++)
	{
	  n_enq = 0;
	  n_deq = 0;

	  for (k = 0; k < n_buffers; k++)
	    ops1[k]->status = VNET_CRYPTO_OP_STATUS_PENDING;

	  t0 = clib_cpu_time_now ();

	  while (n_deq != n_buffers)
	    {
	      u32 n = n_buffers - n_enq >= burst_sz ? burst_sz :
		n_buffers - n_enq;
	      if (n)
		n_enq += vnet_crypto_async_enqueue_ops (vm, ops1 + n_enq, n);
	      vnet_crypto_async_dispatch_one_queue (vm, thread_id, opt1);
	      n_deq += vnet_crypto_async_crypto_dequeue_ops (vm, opt1,
							     ops_deq,
							     burst_sz);
	    }

	  t1 = clib_cpu_time_now ();
	  for (k = 0; k < n_buffers; k++)
	    {
	      if (ops2[k]->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
		err1[i]++;
	    }

	  tt0[i] += (t1 - t0);
	}

      if (ot != VNET_CRYPTO_OP_TYPE_HMAC)
	{
	  for (j = 0; j < rounds; j++)
	    {
	      n_enq = 0;
	      n_deq = 0;

	      for (k = 0; k < n_buffers; k++)
		ops2[k]->status = VNET_CRYPTO_OP_STATUS_PENDING;

	      t0 = clib_cpu_time_now ();

	      while (n_deq != n_buffers)
		{
		  u32 n = n_buffers - n_enq >= burst_sz ? burst_sz :
		    n_buffers - n_enq;
		  if (n)
		    n_enq += vnet_crypto_async_enqueue_ops (vm, ops2 + n_enq,
							    n);
		  vnet_crypto_async_dispatch_one_queue (vm, thread_id, opt2);
		  n_deq += vnet_crypto_async_crypto_dequeue_ops (vm,
								 opt2,
								 ops_deq,
								 burst_sz);
		}

	      t1 = clib_cpu_time_now ();

	      for (k = 0; k < n_buffers; k++)
		{
		  if (ops2[k]->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
		    err1[i]++;
		}

	      tt1[i] += (t1 - t0);
	    }
	}
    }

  for (i = 0; i < 5; i++)
    {
      f64 tpb1 = (f64) (tt0[i]) / (n_bytes * rounds);
      f64 gbps1 = vm->clib_time.clocks_per_second * 1e-9 * 8 / tpb1;
      f64 tpb2, gbps2;

      if (ot != VNET_CRYPTO_OP_TYPE_HMAC)
	{
	  tpb2 = (f64) (tt1[i]) / (n_bytes * rounds);
	  gbps2 = vm->clib_time.clocks_per_second * 1e-9 * 8 / tpb2;
	  vlib_cli_output (vm, "%-2u: encrypt %.03f ticks/byte, %.02f Gbps; "
			   "decrypt %.03f ticks/byte, %.02f Gbps, err %%%.02f",
			   i + 1, tpb1, gbps1, tpb2, gbps2,
			   (f64) err0[i] / (n_buffers * rounds) * 100);
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

  vec_foreach_index (i, ops1)
  {
    clib_mem_free (ops1[i]);
    clib_mem_free (ops2[i]);
  }

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
  unittest_crypto_test_registration_t *tr, *tra;
  int is_perf = 0;
  int is_async = 0;

  tr = tm->test_registrations;
  tra = tm->test_registrations_async;
  memset (tm, 0, sizeof (crypto_test_main_t));
  tm->test_registrations = tr;
  tm->test_registrations_async = tra;
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
      else if (unformat (input, "async"))
	is_async = 1;
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

  if (is_async)
    {
      if (is_perf)
	return test_crypto_perf_async (vm, tm);
      else
	return test_crypto_async (vm, tm);
    }
  else
    {
      if (is_perf)
	return test_crypto_perf (vm, tm);
      else
	return test_crypto (vm, tm);
    }
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_crypto_command, static) =
{
  .path = "test crypto",
  .short_help = "test crypto",
  .function = test_crypto_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
crypto_test_init (vlib_main_t * vm)
{
  return (0);
}

VLIB_INIT_FUNCTION (crypto_test_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
