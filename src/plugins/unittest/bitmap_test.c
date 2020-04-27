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
#include <vlib/vlib.h>
#include <vppinfra/bitmap.h>

static clib_error_t *
test_bitmap_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u64 *bm = 0;
  u64 *bm2 = 0;
  u64 *dup;
  uword junk;

  bm = clib_bitmap_set_multiple (bm, 2, ~0ULL, BITS (uword));

  junk = clib_bitmap_next_clear (bm, 3);
  junk = clib_bitmap_next_clear (bm, 65);

  bm2 = clib_bitmap_set_multiple (bm2, 0, ~0ULL, BITS (uword));
  _vec_len (bm2) = 1;
  junk = clib_bitmap_next_clear (bm2, 0);


  bm = clib_bitmap_set_multiple (bm, 2, ~0ULL, BITS (uword) - 3);
  junk = clib_bitmap_get_multiple (bm, 2, BITS (uword));
  junk = clib_bitmap_first_set (bm);
  junk = 1 << 3;
  bm = clib_bitmap_xori (bm, junk);
  bm = clib_bitmap_andi (bm, junk);
  bm = clib_bitmap_xori_notrim (bm, junk);
  bm = clib_bitmap_andi_notrim (bm, junk);

  bm = clib_bitmap_set_multiple (bm, 2, ~0ULL, BITS (uword) - 3);
  bm2 = clib_bitmap_set_multiple (bm2, 2, ~0ULL, BITS (uword) - 3);

  dup = clib_bitmap_dup_and (bm, bm2);
  vec_free (dup);
  dup = clib_bitmap_dup_andnot (bm, bm2);
  vec_free (dup);
  vec_free (bm);
  vec_free (bm2);

  return 0;
}



/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_bihash_command, static) =
{
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
