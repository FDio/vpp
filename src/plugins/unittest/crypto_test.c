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

static void
print_results (vlib_main_t * vm, unittest_crypto_test_registration_t ** rv,
	       vnet_crypto_op_t * ops, vnet_crypto_op_chunk_t * chunks,
	       u32 n_ops, crypto_test_main_t * tm)
{
  int i;
  unittest_crypto_test_registration_t *r;
  vnet_crypto_op_chunk_t *chp;
  u8 *s = 0, *err = 0;
  vnet_crypto_op_t *op;

  vec_foreach (op, ops)
  {
    int fail = 0;
    r = rv[op->user_data];
    unittest_crypto_test_data_t *exp_pt = 0, *exp_ct = 0, exp_pt_data;
    unittest_crypto_test_data_t *exp_digest = 0, *exp_tag = 0;
    unittest_crypto_test_data_t *exp_pt_chunks = 0, *exp_ct_chunks = 0;

    switch (vnet_crypto_get_op_type (op->op))
      {
      case VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT:
	exp_tag = &r->tag;
	/* fall through */
      case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	exp_ct = &r->ciphertext;
	exp_ct_chunks = r->ct_chunks;
	break;
      case VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT:
      case VNET_CRYPTO_OP_TYPE_DECRYPT:
	if (r->plaintext_incremental)
	  {
	    exp_pt_data.length = r->plaintext_incremental;
	    exp_pt_data.data = tm->inc_data;
	    exp_pt = &exp_pt_data;
	  }
	else
	  {
	    exp_pt = &r->plaintext;
	    exp_pt_chunks = r->pt_chunks;
	  }
	break;
      case VNET_CRYPTO_OP_TYPE_HMAC:
	exp_digest = &r->digest;
	break;
      case VNET_CRYPTO_OP_TYPE_HASH:
	exp_digest = &r->digest;
	break;
      default:
	ASSERT (0);
      }

    vec_reset_length (err);

    if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
      err = format (err, "%sengine error: %U", vec_len (err) ? ", " : "",
		    format_vnet_crypto_op_status, op->status);

    if (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
      {
	if (exp_ct_chunks)
	  {
	    chp = vec_elt_at_index (chunks, op->chunk_index);
	    for (i = 0; i < op->n_chunks; i++)
	      {
		if (memcmp (chp->dst, exp_ct_chunks[i].data, chp->len))
		  err = format (err, "%sciphertext mismatch [chunk %d]",
				vec_len (err) ? ", " : "", i);
		chp += 1;
	      }
	  }

	if (exp_pt_chunks)
	  {
	    chp = vec_elt_at_index (chunks, op->chunk_index);
	    for (i = 0; i < op->n_chunks; i++)
	      {
		if (memcmp (chp->dst, exp_pt_chunks[i].data, chp->len))
		  err = format (err, "%splaintext mismatch [chunk %d]",
				vec_len (err) ? ", " : "", i);
		chp += 1;
	      }
	  }
      }
    else
      {
	if (exp_ct && memcmp (op->dst, exp_ct->data, exp_ct->length) != 0)
	  err = format (err, "%sciphertext mismatch",
			vec_len (err) ? ", " : "");

	if (exp_pt && memcmp (op->dst, exp_pt->data, exp_pt->length) != 0)
	  err = format (err, "%splaintext mismatch",
			vec_len (err) ? ", " : "");
      }

    if (exp_tag && memcmp (op->tag, exp_tag->data, exp_tag->length) != 0)
      err = format (err, "%stag mismatch", vec_len (err) ? ", " : "");

    if (exp_digest &&
	memcmp (op->digest, exp_digest->data, exp_digest->length) != 0)
      err = format (err, "%sdigest mismatch", vec_len (err) ? ", " : "");

    vec_reset_length (s);
    s = format (s, "%s (%U)", r->name, format_vnet_crypto_op, op->op,
		r->is_chained);

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
  vec_free (err);
  vec_free (s);
}

static void
validate_data (u8 ** data, u32 len)
{
  u32 i, diff, old_len;
  if (vec_len (data[0]) >= len)
    return;

  old_len = vec_len (data[0]);
  diff = len - vec_len (data[0]);
  vec_validate (data[0], old_len + diff - 1);
  for (i = old_len; i < len; i++)
    data[0][i] = (u8) i;
}

static void
generate_digest (vlib_main_t * vm,
		 unittest_crypto_test_registration_t * r,
		 vnet_crypto_op_id_t id)
{
  crypto_test_main_t *cm = &crypto_test_main;
  vnet_crypto_op_t op[1];
  vnet_crypto_op_init (op, id);
  vec_validate (r->digest.data, r->digest.length - 1);
  op->src = cm->inc_data;
  op->len = r->plaintext_incremental;
  op->digest = r->digest.data;
  op->digest_len = r->digest.length;
  op->key_index = vnet_crypto_key_add (vm, r->alg,
				       cm->inc_data, r->key.length);

  /* at this point openssl is set for each algo */
  vnet_crypto_process_ops (vm, op, 1);
}

static int
restore_engines (u32 * engs)
{
  vnet_crypto_main_t *cm = &crypto_main;
  u32 i;
  vnet_crypto_engine_t *ce;

  for (i = 1; i < VNET_CRYPTO_N_OP_IDS; i++)
    {
      vnet_crypto_op_data_t *od = &cm->opt_data[i];

      if (engs[i] != ~0)
	{
	  ce = vec_elt_at_index (cm->engines, engs[i]);
	  od->active_engine_index_simple = engs[i];
	  cm->ops_handlers[i] = ce->ops_handlers[i];
	}
    }

  return 0;
}

static int
save_current_engines (u32 * engs)
{
  vnet_crypto_main_t *cm = &crypto_main;
  uword *p;
  u32 i;
  vnet_crypto_engine_t *ce;

  p = hash_get_mem (cm->engine_index_by_name, "openssl");
  if (!p)
    return -1;

  ce = vec_elt_at_index (cm->engines, p[0]);

  /* set openssl for all crypto algs to generate expected data */
  for (i = 1; i < VNET_CRYPTO_N_OP_IDS; i++)
    {
      vnet_crypto_op_data_t *od = &cm->opt_data[i];
      if (od->active_engine_index_simple != ~0)
	{
	  /* save engine index */
	  engs[i] = od->active_engine_index_simple;
	  od->active_engine_index_simple = ce - cm->engines;
	  cm->ops_handlers[i] = ce->ops_handlers[i];
	}
    }

  return 0;
}

static clib_error_t *
test_crypto_incremental (vlib_main_t * vm, crypto_test_main_t * tm,
			 unittest_crypto_test_registration_t ** rv, u32 n_ops,
			 u32 computed_data_total_len)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad;
  vnet_crypto_key_index_t *key_indices = 0;
  u32 i;
  unittest_crypto_test_registration_t *r;
  vnet_crypto_op_t *ops = 0, *op;
  u8 *encrypted_data = 0, *decrypted_data = 0, *s = 0, *err = 0;

  if (n_ops == 0)
    return 0;

  vec_validate_aligned (encrypted_data, computed_data_total_len - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (decrypted_data, computed_data_total_len - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ops, n_ops - 1, CLIB_CACHE_LINE_BYTES);
  computed_data_total_len = 0;

  op = ops;
  /* first stage: encrypt only */

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

	switch (t)
	  {
	  case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	    vnet_crypto_op_init (op, id);
	    op->iv = tm->inc_data;
	    op->key_index = vnet_crypto_key_add (vm, r->alg,
						 tm->inc_data, r->key.length);
	    vec_add1 (key_indices, op->key_index);
	    op->len = r->plaintext_incremental;
	    op->src = tm->inc_data;
	    op->dst = encrypted_data + computed_data_total_len;
	    computed_data_total_len += r->plaintext_incremental;
	    op->user_data = i;
	    op++;
	    break;
	  case VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT:
	    vnet_crypto_op_init (op, id);
	    op->iv = tm->inc_data;
	    op->key_index = vnet_crypto_key_add (vm, r->alg,
						 tm->inc_data, r->key.length);
	    vec_add1 (key_indices, op->key_index);
	    op->aad = tm->inc_data;
	    op->aad_len = r->aad.length;
	    op->len = r->plaintext_incremental;
	    op->dst = encrypted_data + computed_data_total_len;
	    computed_data_total_len += r->plaintext_incremental;
	    op->src = tm->inc_data;
	    op->tag = encrypted_data + computed_data_total_len;
	    computed_data_total_len += r->tag.length;
	    op->tag_len = r->tag.length;
	    op->user_data = i;
	    op++;
	    break;
	  case VNET_CRYPTO_OP_TYPE_HMAC:
	    /* compute hmac in the next stage */
	    op->op = VNET_CRYPTO_OP_NONE;
	    computed_data_total_len += r->digest.length;
	    op->user_data = i;
	    op++;
	    break;
	  default:
	    break;
	  };
      }
  }

  vnet_crypto_process_ops (vm, ops, n_ops);
  computed_data_total_len = 0;

  /* second stage: hash/decrypt previously encrypted data */
  op = ops;

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

	switch (t)
	  {
	  case VNET_CRYPTO_OP_TYPE_DECRYPT:
	    vnet_crypto_op_init (op, id);
	    op->iv = tm->inc_data;
	    op->key_index = vnet_crypto_key_add (vm, r->alg,
						 tm->inc_data, r->key.length);
	    vec_add1 (key_indices, op->key_index);
	    op->len = r->plaintext_incremental;
	    op->src = encrypted_data + computed_data_total_len;
	    op->dst = decrypted_data + computed_data_total_len;
	    computed_data_total_len += r->plaintext_incremental;
	    op->user_data = i;
	    op++;
	    break;
	  case VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT:
	    vnet_crypto_op_init (op, id);
	    op->iv = tm->inc_data;
	    op->key_index = vnet_crypto_key_add (vm, r->alg,
						 tm->inc_data, r->key.length);
	    vec_add1 (key_indices, op->key_index);
	    op->aad = tm->inc_data;
	    op->aad_len = r->aad.length;
	    op->len = r->plaintext_incremental;
	    op->dst = decrypted_data + computed_data_total_len;
	    op->src = encrypted_data + computed_data_total_len;
	    computed_data_total_len += r->plaintext_incremental;

	    op->tag = encrypted_data + computed_data_total_len;
	    computed_data_total_len += r->tag.length;
	    op->tag_len = r->tag.length;
	    op->user_data = i;
	    op++;
	    break;
	  case VNET_CRYPTO_OP_TYPE_HMAC:
	    vnet_crypto_op_init (op, id);
	    op->key_index = vnet_crypto_key_add (vm, r->alg,
						 tm->inc_data, r->key.length);
	    vec_add1 (key_indices, op->key_index);
	    op->src = tm->inc_data;
	    op->len = r->plaintext_incremental;
	    op->digest_len = r->digest.length;
	    op->digest = encrypted_data + computed_data_total_len;
	    computed_data_total_len += r->digest.length;
	    op->user_data = i;
	    op++;
	    break;
	  default:
	    break;
	  };

      }
  }

  vnet_crypto_process_ops (vm, ops, n_ops);
  print_results (vm, rv, ops, 0, n_ops, tm);

  vec_foreach_index (i, key_indices) vnet_crypto_key_del (vm, key_indices[i]);
  vec_free (tm->inc_data);
  vec_free (ops);
  vec_free (encrypted_data);
  vec_free (decrypted_data);
  vec_free (err);
  vec_free (s);
  return 0;
}

static clib_error_t *
test_crypto_static (vlib_main_t * vm, crypto_test_main_t * tm,
		    unittest_crypto_test_registration_t ** rv, u32 n_ops,
		    u32 n_chained_ops, u32 computed_data_total_len)
{
  unittest_crypto_test_data_t *pt, *ct;
  vnet_crypto_op_chunk_t *chunks = 0, ch;
  unittest_crypto_test_registration_t *r;
  vnet_crypto_op_t *ops = 0, *op, *chained_ops = 0;
  vnet_crypto_op_t *current_chained_op = 0, *current_op = 0;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad;
  vnet_crypto_key_index_t *key_indices = 0;
  u8 *computed_data = 0;
  u32 i;

  vec_sort_with_function (rv, sort_registrations);

  vec_validate_aligned (computed_data, computed_data_total_len - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ops, n_ops - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (chained_ops, n_chained_ops - 1,
			CLIB_CACHE_LINE_BYTES);
  computed_data_total_len = 0;

  current_op = ops;
  current_chained_op = chained_ops;
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

          if (r->is_chained)
          {
            op = current_chained_op;
            current_chained_op += 1;
          }
          else
          {
            op = current_op;
            current_op += 1;
          }

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

              if (r->is_chained)
              {
              pt = r->pt_chunks;
              ct = r->ct_chunks;
              op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
              op->chunk_index = vec_len (chunks);
              while (pt->data)
                {
                  ch.src = t == VNET_CRYPTO_OP_TYPE_ENCRYPT ?
                    pt->data : ct->data;
                  ch.len = pt->length;
                  ch.dst = computed_data + computed_data_total_len;
                  computed_data_total_len += pt->length;
                  vec_add1 (chunks, ch);
                  op->n_chunks++;
                  pt++;
                  ct++;
                }
              }
              else
              {
              op->len = r->plaintext.length;
              op->src = t == VNET_CRYPTO_OP_TYPE_ENCRYPT ?
                r->plaintext.data : r->ciphertext.data;
              op->dst = computed_data + computed_data_total_len;
              computed_data_total_len += r->ciphertext.length;
              }
	      break;
	    case VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT:
	    case VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT:
              if (r->is_chained)
              {
	      op->iv = r->iv.data;
	      op->key_index = vnet_crypto_key_add (vm, r->alg,
						   r->key.data,
						   r->key.length);
	      vec_add1 (key_indices, op->key_index);
	      op->aad = r->aad.data;
	      op->aad_len = r->aad.length;
	      if (t == VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT)
		{
                  pt = r->pt_chunks;
                  op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
                  op->chunk_index = vec_len (chunks);
                  while (pt->data)
                    {
                      clib_memset (&ch, 0, sizeof (ch));
                      ch.src = pt->data;
                      ch.len = pt->length;
                      ch.dst = computed_data + computed_data_total_len;
                      computed_data_total_len += pt->length;
                      vec_add1 (chunks, ch);
                      op->n_chunks++;
                      pt++;
                    }
                  op->tag = computed_data + computed_data_total_len;
                  computed_data_total_len += r->tag.length;
                }
              else
                {
                  ct = r->ct_chunks;
                  op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
                  op->chunk_index = vec_len (chunks);
                  while (ct->data)
                    {
                      clib_memset (&ch, 0, sizeof (ch));
                      ch.src = ct->data;
                      ch.len = ct->length;
                      ch.dst = computed_data + computed_data_total_len;
                      computed_data_total_len += ct->length;
                      vec_add1 (chunks, ch);
                      op->n_chunks++;
                      ct++;
                    }
                  op->tag = r->tag.data;
                }
	      op->tag_len = r->tag.length;
              }
              else
              {
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
                  op->tag = r->tag.data;
                  op->src = r->ciphertext.data;
		}
	      op->tag_len = r->tag.length;
              }
	      break;
	    case VNET_CRYPTO_OP_TYPE_HMAC:
              if (r->is_chained)
              {
	      op->key_index = vnet_crypto_key_add (vm, r->alg,
						   r->key.data,
						   r->key.length);
	      vec_add1 (key_indices, op->key_index);
              op->digest_len = r->digest.length;
              op->digest = computed_data + computed_data_total_len;
              computed_data_total_len += r->digest.length;
              pt = r->pt_chunks;
              op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
              op->chunk_index = vec_len (chunks);
              while (pt->data)
                {
                  clib_memset (&ch, 0, sizeof (ch));
                  ch.src = pt->data;
                  ch.len = pt->length;
                  vec_add1 (chunks, ch);
                  op->n_chunks++;
                  pt++;
                }
              }
              else
              {
	      op->key_index = vnet_crypto_key_add (vm, r->alg,
						   r->key.data,
						   r->key.length);
	      vec_add1 (key_indices, op->key_index);
              op->digest_len = r->digest.length;
              op->digest = computed_data + computed_data_total_len;
              computed_data_total_len += r->digest.length;
              op->src = r->plaintext.data;
              op->len = r->plaintext.length;
              }
	      break;
	    case VNET_CRYPTO_OP_TYPE_HASH:
	      op->digest = computed_data + computed_data_total_len;
	      computed_data_total_len += r->digest.length;
	      op->src = r->plaintext.data;
	      op->len = r->plaintext.length;
	      break;
	    default:
	      break;
	    };

	  op->user_data = i;
	}
    }
  /* *INDENT-ON* */

  vnet_crypto_process_ops (vm, ops, vec_len (ops));
  vnet_crypto_process_chained_ops (vm, chained_ops, chunks,
				   vec_len (chained_ops));

  print_results (vm, rv, ops, chunks, vec_len (ops), tm);
  print_results (vm, rv, chained_ops, chunks, vec_len (chained_ops), tm);

  vec_foreach_index (i, key_indices) vnet_crypto_key_del (vm, key_indices[i]);

  vec_free (computed_data);
  vec_free (ops);
  vec_free (chained_ops);
  vec_free (chunks);
  return 0;
}

static u32
test_crypto_get_key_sz (vnet_crypto_alg_t alg)
{
  switch (alg)
    {
#define _(n, s, l) \
  case VNET_CRYPTO_ALG_##n: \
    return l;
  /* *INDENT-OFF* */
  foreach_crypto_cipher_alg
  foreach_crypto_aead_alg
  /* *INDENT-ON* */
#undef _
    case VNET_CRYPTO_ALG_HMAC_MD5:
    case VNET_CRYPTO_ALG_HMAC_SHA1:
      return 20;
    case VNET_CRYPTO_ALG_HMAC_SHA224:
      return 28;
    case VNET_CRYPTO_ALG_HMAC_SHA256:
      return 32;
    case VNET_CRYPTO_ALG_HMAC_SHA384:
      return 48;
    case VNET_CRYPTO_ALG_HMAC_SHA512:
      return 64;
    default:
      return 0;
    }
  return 0;
}

static clib_error_t *
test_crypto (vlib_main_t * vm, crypto_test_main_t * tm)
{
  clib_error_t *err = 0;
  vnet_crypto_main_t *cm = &crypto_main;
  unittest_crypto_test_registration_t *r = tm->test_registrations;
  unittest_crypto_test_registration_t **static_tests = 0, **inc_tests = 0;
  u32 i, j, n_ops_static = 0, n_ops_incr = 0, n_chained_ops = 0;
  vnet_crypto_alg_data_t *ad;
  u32 computed_data_total_len = 0;
  u32 computed_data_total_incr_len = 0;
  u32 saved_engs[VNET_CRYPTO_N_OP_IDS] = { ~0, };
  unittest_crypto_test_data_t *ct;

  /* pre-allocate plaintext data with reasonable length */
  validate_data (&tm->inc_data, 2048);

  int rc = save_current_engines (saved_engs);
  if (rc)
    return clib_error_return (0, "failed to set default crypto engine!");

  /* construct registration vector */
  while (r)
    {
      if (r->plaintext_incremental)
	vec_add1 (inc_tests, r);
      else
	vec_add1 (static_tests, r);

      ad = vec_elt_at_index (cm->algs, r->alg);

      for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
	{
	  vnet_crypto_op_id_t id = ad->op_by_type[i];

	  if (id == 0)
	    continue;

	  switch (i)
	    {
	    case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	      if (r->plaintext_incremental)
		{
		  computed_data_total_incr_len += r->plaintext_incremental;
		  n_ops_incr += 1;
		}
	      /* fall though */
	    case VNET_CRYPTO_OP_TYPE_DECRYPT:
	    case VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT:
	      if (r->is_chained)
		{
		  ct = r->ct_chunks;
		  j = 0;
		  while (ct->data)
		    {
		      if (j > CRYPTO_TEST_MAX_OP_CHUNKS)
			return clib_error_return (0,
						  "test case '%s' exceeds extra data!",
						  r->name);
		      computed_data_total_len += ct->length;
		      ct++;
		      j++;
		    }
		  n_chained_ops += 1;
		}
	      else if (!r->plaintext_incremental)
		{
		  computed_data_total_len += r->ciphertext.length;
		  n_ops_static += 1;
		}
	      break;
	    case VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT:
	      if (r->plaintext_incremental)
		{
		  computed_data_total_incr_len += r->plaintext_incremental;
		  computed_data_total_incr_len += r->tag.length;
		  n_ops_incr += 1;
		}
	      else
		{
		  computed_data_total_len += r->ciphertext.length;
		  computed_data_total_len += r->tag.length;
		  if (r->is_chained)
		    {
		      ct = r->ct_chunks;
		      j = 0;
		      while (ct->data)
			{
			  if (j > CRYPTO_TEST_MAX_OP_CHUNKS)
			    return clib_error_return (0,
						      "test case '%s' exceeds extra data!",
						      r->name);
			  computed_data_total_len += ct->length;
			  ct++;
			  j++;
			}
		      n_chained_ops += 1;
		    }
		  else
		    n_ops_static += 1;
		}
	      break;
	    case VNET_CRYPTO_OP_TYPE_HMAC:
	      if (r->plaintext_incremental)
		{
		  computed_data_total_incr_len += r->digest.length;
		  n_ops_incr += 1;
		  generate_digest (vm, r, id);
		}
	      else
		{
		  computed_data_total_len += r->digest.length;
		  if (r->is_chained)
		    n_chained_ops += 1;
		  else
		    n_ops_static += 1;
		}
	      break;
	    case VNET_CRYPTO_OP_TYPE_HASH:
	      computed_data_total_len += r->digest.length;
	      n_ops_static += 1;
	      break;
	    default:
	      break;
	    };
	}

      /* next: */
      r = r->next;
    }
  restore_engines (saved_engs);

  err = test_crypto_static (vm, tm, static_tests, n_ops_static, n_chained_ops,
			    computed_data_total_len);
  if (err)
    goto done;

  err = test_crypto_incremental (vm, tm, inc_tests, n_ops_incr,
				 computed_data_total_incr_len);

  r = tm->test_registrations;
  while (r)
    {
      if (r->plaintext_incremental)
	vec_free (r->digest.data);
      r = r->next;
    }

done:
  vec_free (inc_tests);
  vec_free (static_tests);
  return err;
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
