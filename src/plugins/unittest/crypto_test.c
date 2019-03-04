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

  return (r0[0]->op > r1[0]->op);
}

static clib_error_t *
test_crypto (vlib_main_t * vm, crypto_test_main_t * tm)
{
  unittest_crypto_test_registration_t *r = tm->test_registrations;
  unittest_crypto_test_registration_t **rv = 0;
  vnet_crypto_op_t *jobs = 0, *j, **batch = 0;
  u8 *computed_data = 0, *s = 0;
  u32 computed_data_total_len = 0, n_tests = 0;
  u32 i;

  /* construct registration vector */
  while (r)
    {
      vec_add1 (rv, r);
      computed_data_total_len += r->length;
      n_tests += 1;
      /* next */
      r = r->next;
    }

  vec_sort_with_function (rv, sort_registrations);

  vec_validate_aligned (computed_data, computed_data_total_len - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (jobs, n_tests - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (batch, n_tests - 1, CLIB_CACHE_LINE_BYTES);
  computed_data_total_len = 0;

  /* *INDENT-OFF* */
  vec_foreach_index (i, rv)
    {
      r = rv[i];
      j = jobs + i;
      batch[i] = j;
      j->op = r->op;
      j->iv = r->iv;
      j->key = r->key;
      j->src = r->data;
      j->dst = computed_data + computed_data_total_len;
      j->len = r->length;
      computed_data_total_len += r->length;
      /* next */
      r = r->next;
    }
  /* *INDENT-ON* */

  vnet_crypto_run (vm, batch, vec_len (batch));

  /* *INDENT-OFF* */
  vec_foreach_index (i, rv)
    {
      r = rv[i];
      j = jobs + i;
      char *result;

      if (memcmp (j->dst, r->expected, j->len) == 0)
	result = "OK";
      else
	result = "FAIL";

      vec_reset_length (s);
      s = format (s, "%s (%U)", r->name,
		       format_vnet_crypto_op, r->op);

      vlib_cli_output (vm, "%-60v%s", s, result);
    }
  /* *INDENT-ON* */

  vec_free (computed_data);
  vec_free (batch);
  vec_free (jobs);
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
      if (unformat (input, "verbose %d", &tm->verbose))
	;
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
