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
test_crypto (vlib_main_t * vm, crypto_test_main_t * tm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  unittest_crypto_test_registration_t *r = tm->test_registrations;
  unittest_crypto_test_registration_t **rv = 0;
  vnet_crypto_alg_data_t *ad;
  vnet_crypto_op_t *ops = 0, *op;
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
	      op->iv_len = r->iv.length;
	      op->key = r->key.data;
	      op->key_len = r->key.length;
	      op->len = r->plaintext.length;
	      op->src = t == VNET_CRYPTO_OP_TYPE_ENCRYPT ?
		r->plaintext.data : r->ciphertext.data;
	      op->dst = computed_data + computed_data_total_len;
	      computed_data_total_len += r->ciphertext.length;
	      break;
	    case VNET_CRYPTO_OP_TYPE_AEAD_ENCRYPT:
	    case VNET_CRYPTO_OP_TYPE_AEAD_DECRYPT:
	      op->iv = r->iv.data;
	      op->iv_len = r->iv.length;
	      op->key = r->key.data;
	      op->key_len = r->key.length;
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
	      op->key = r->key.data;
	      op->key_len = r->key.length;
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
      /* next */
      r = r->next;
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
  /* *INDENT-ON* */

  vec_free (computed_data);
  vec_free (ops);
  vec_free (err);
  vec_free (rv);
  vec_free (s);
  return 0;
}

static clib_error_t *
test_crypto_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  crypto_test_main_t *tm = &crypto_test_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	tm->verbose = 1;
      else if (unformat (input, "detail"))
	tm->verbose = 2;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

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
