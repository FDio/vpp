/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <stdbool.h>
#include <vlib/vlib.h>
#include <vppinfra/bitmap.h>

static clib_error_t *
check_bitmap (const char *test_name, const uword *bm, u32 expected_len, ...)
{
  clib_error_t *error = 0;
  u32 i;
  uword expected_value;

  va_list va;
  va_start (va, expected_len);

  if (vec_len (bm) != expected_len)
    {
      error = clib_error_create ("%s failed, wrong "
				 "bitmap's size (%u != %u expected)",
				 test_name, vec_len (bm), expected_len);
      goto done;
    }

  for (i = 0; i < expected_len; ++i)
    {
      expected_value = va_arg (va, uword);
      if (bm[i] != expected_value)
	{
	  error = clib_error_create (
	    "%s failed, wrong "
	    "bitmap's value at index %u (%u != %u expected)",
	    test_name, i, bm[i], expected_value);
	  break;
	}
    }

done:
  va_end (va);
  return error;
}

static clib_error_t *
check_bitmap_will_expand (const char *test_name, uword **bm, uword index,
			  bool expected_will_expand)
{
  uword max_bytes = vec_max_bytes (*bm);
  bool result;

  result = clib_bitmap_will_expand (*bm, index);
  if (result != expected_will_expand)
    {
      return clib_error_create (
	"%s failed, wrong "
	"bitmap's expansion before set (%u != %u expected)",
	test_name, result, expected_will_expand);
    }

  *bm = clib_bitmap_set (*bm, index, 1);
  result = vec_max_bytes (*bm) > max_bytes;
  if (result != expected_will_expand)
    {
      return clib_error_create (
	"%s failed, wrong "
	"bitmap's expansion after set (%u != %u expected)",
	test_name, result, expected_will_expand);
    }

  return 0;
}

static clib_error_t *
test_bitmap_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  uword *bm = 0;
  uword *bm2 = 0;
  uword *bm3 = 0;
  uword *dup = 0;

  /*  bm should look like:
   *          bm[0]     bm[1]
   *  LSB |0011...11|1100...00| MSB
   */
  bm = clib_bitmap_set_multiple (0, 2, ~0ULL, BITS (uword));
  error = check_bitmap ("clib_bitmap_set_multiple 1", bm, 2, ~0ULL << 2, 3);
  if (error != 0)
    goto done;

  /*  bm2 should look like:
   *	    bm2[0]
   *  LSB |11...11| MSB
   */
  bm2 = clib_bitmap_set_multiple (0, 0, ~0ULL, BITS (uword));
  error = check_bitmap ("clib_bitmap_set_multiple 2", bm2, 1, ~0ULL);
  if (error != 0)
    goto done;

  /*  bm should look like:
   *	      bm[0]      bm[1]
   *  LSB |0011...1100|000...000| MSB
   */
  bm = clib_bitmap_set_multiple (bm, 2, pow2_mask (BITS (uword) - 3),
				 BITS (uword));
  error = check_bitmap ("clib_bitmap_set_multiple 3", bm, 2,
			pow2_mask (BITS (uword) - 3) << 2, 0);
  if (error != 0)
    goto done;

  /*  bm2 should look like:
   *	     bm2[0]
   *  LSB |101...111| MSB
   */
  bm2 = clib_bitmap_xori (bm2, 1);
  error = check_bitmap ("clib_bitmap_xori 1", bm2, 1, ~0ULL ^ 2);
  if (error != 0)
    goto done;

  /*  bm should look like:
   *	       bm[0]      bm[1]
   *  LSB |0011...1100|000...001| MSB
   */
  bm = clib_bitmap_xori (bm, 2 * BITS (uword) - 1);
  error = check_bitmap ("clib_bitmap_xori 2", bm, 2,
			pow2_mask (BITS (uword) - 3) << 2,
			1ULL << (BITS (uword) - 1));
  if (error != 0)
    goto done;

  /*  bm should look like:
   *         bm[0]      bm[1]
   *  LSB |00100...00|000...001| MSB
   */
  bm = clib_bitmap_andi (bm, 2);
  error =
    check_bitmap ("clib_bitmap_andi", bm, 2, 4, 1ULL << (BITS (uword) - 1));
  if (error != 0)
    goto done;

  /*  bm should look like:
   *	     bm[0]
   *  LSB |00100...00| MSB
   */
  bm = clib_bitmap_xori (bm, 2 * BITS (uword) - 1);
  error = check_bitmap ("clib_bitmap_xori 3", bm, 1, 4);
  if (error != 0)
    goto done;

  /*  bm and bm2 should look like:
   *	     bm[0]     bm[1]
   *  LSB |0011...11|1100...00| MSB
   *         bm2[0]    bm2[1]
   *  LSB |101...111|0011...11| MSB
   */
  bm = clib_bitmap_set_multiple (bm, 2, ~0ULL, BITS (uword));
  bm2 =
    clib_bitmap_set_multiple (bm2, BITS (uword) + 2, ~0ULL, BITS (uword) - 3);
  dup = clib_bitmap_dup_and (bm, bm2);
  error = check_bitmap ("clib_bitmap_dup_and", dup, 1, bm[0] & bm2[0]);
  if (error != 0)
    goto done;

  /*  bm should look like:
   *	     bm[0]    bm[1]   ...   bm[3]
   *  LSB |0011...11|11...11| ... |11...11| MSB
   */
  bm = clib_bitmap_set_region (bm, 5, 1, 4 * BITS (uword) - 5);
  error = check_bitmap ("clib_bitmap_set_region 1", bm, 4, ~0ULL << 2, ~0ULL,
			~0ULL, ~0ULL);
  if (error != 0)
    goto done;

  /*  bm should look like:
   *	     bm[0]    bm[1]   ...      bm[3]
   *  LSB |0011...11|11...11| ... |11...1100000| MSB
   */
  bm = clib_bitmap_set_region (bm, 4 * BITS (uword) - 5, 0, 5);
  error = check_bitmap ("clib_bitmap_set_region 2", bm, 4, ~0ULL << 2, ~0ULL,
			~0ULL, pow2_mask (BITS (uword) - 5));
  if (error != 0)
    goto done;

  error = check_bitmap_will_expand ("clib_bitmap_will_expand 1", &bm, 0, 0);
  if (error != 0)
    goto done;

  error = check_bitmap_will_expand ("clib_bitmap_will_expand 2", &bm,
				    vec_max_len (bm) * BITS (uword) - 1, 0);
  if (error != 0)
    goto done;

  error = check_bitmap_will_expand ("clib_bitmap_will_expand 3", &bm,
				    vec_max_len (bm) * BITS (uword), 1);
  if (error != 0)
    goto done;

  error = check_bitmap_will_expand ("clib_bitmap_will_expand 4", &bm3, 0, 1);
  if (error != 0)
    goto done;

done:
  vec_free (bm);
  vec_free (bm2);
  vec_free (bm3);
  vec_free (dup);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_bitmap_command, static) = {
  .path = "test bitmap",
  .short_help = "Coverage test for bitmap.h",
  .function = test_bitmap_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
