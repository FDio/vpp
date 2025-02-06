/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/vector/array_mask.h>

__test_funct_fn void
clib_array_mask_u32_wrapper (u32 *src, u32 mask, u32 n_elts)
{
  clib_array_mask_u32 (src, mask, n_elts);
}

typedef struct
{
  u32 flag;
  u64 bitmap[4];
  u64 expected_mask[4];
} array_masked_flag_test_t;

typedef struct
{
  u32 flag;
  u64 expected_mask[4];
} array_flag_test_t;

typedef struct
{
  u32 mask;
  u32 expected[256];
} array_mask_test_t;

static array_masked_flag_test_t masked_flag_tests[] = {
  { .flag = 0x0,
    .bitmap = { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF },
    .expected_mask = { 0, 0, 0, 0 } },
  { .flag = 0x4,
    .bitmap = { 0xFFFFFFFFFFFFFFFF, 0, 0, 0 },
    .expected_mask = { 0xA0A0A0A0A0A0A0A0, 0, 0, 0 } },
  { .flag = 0x8,
    .bitmap = { 0xAAAAAAAAAAAAAAAA, 0, 0, 0 },
    .expected_mask = { 0xAA00AA00AA00AA00, 0, 0, 0 } },
  { .flag = 0xF,
    .bitmap = { 0x5555555555555555, 0xFFFFFFFFFFFFFFFF, 0, 0 },
    .expected_mask = { 0, 0xAAAAAAAAAAAAAAAA, 0, 0 } },
  { .flag = 0x1,
    .bitmap = { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF },
    .expected_mask = { 0xAAAAAAAAAAAAAAAA, 0xAAAAAAAAAAAAAAAA,
		       0xAAAAAAAAAAAAAAAA, 0xAAAAAAAAAAAAAAAA } }
};

static array_flag_test_t flag_tests[] = {
  // Test case 1: All zeros (no flags set, bitmap should be all zero)
  { .flag = 0x1, // Arbitrary flag, but no elements should match
    .expected_mask = { 0x0, 0x0, 0x0, 0x0 } },
  // Test case 2: All flags set (every element matches the flag)
  { .flag = 0xF, // Assume all elements contain this flag
    .expected_mask = { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		       0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF } },
  // Test case 3: Alternating pattern (every other element set)
  { .flag = 0x4, // Flag set in alternating elements
    .expected_mask = { 0xAAAAAAAAAAAAAAAA, 0xAAAAAAAAAAAAAAAA,
		       0xAAAAAAAAAAAAAAAA, 0xAAAAAAAAAAAAAAAA } },
  // Test case 4: Edge cases (only first and last element set)
  { .flag = 0x8, // Flag set only at the first and last positions
    .expected_mask = { 0x0000000000000001, 0x0, 0x0, 0x8000000000000000 } }
};

static array_mask_test_t tests[] = {
  /* mask values 0x1, output array of alternating 0 1 0 1 .. */
  { .mask = 1,
    .expected = { 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1 } },
  /* mask values 0xFFFFFFFF, output array of 0, 1, 2, .., 255 */
  { .mask = ~0U,
    .expected = { 0,   1,   2,	 3,   4,   5,	6,   7,	  8,   9,   10,	 11,
		  12,  13,  14,	 15,  16,  17,	18,  19,  20,  21,  22,	 23,
		  24,  25,  26,	 27,  28,  29,	30,  31,  32,  33,  34,	 35,
		  36,  37,  38,	 39,  40,  41,	42,  43,  44,  45,  46,	 47,
		  48,  49,  50,	 51,  52,  53,	54,  55,  56,  57,  58,	 59,
		  60,  61,  62,	 63,  64,  65,	66,  67,  68,  69,  70,	 71,
		  72,  73,  74,	 75,  76,  77,	78,  79,  80,  81,  82,	 83,
		  84,  85,  86,	 87,  88,  89,	90,  91,  92,  93,  94,	 95,
		  96,  97,  98,	 99,  100, 101, 102, 103, 104, 105, 106, 107,
		  108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
		  120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131,
		  132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
		  144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
		  156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167,
		  168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
		  180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
		  192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203,
		  204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215,
		  216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227,
		  228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
		  240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251,
		  252, 253, 254, 255 } },
  /* mask values 0xF, output array of 0, .., 15, 0, .., 15, 0, .., 15 */
  { .mask = 15,
    .expected = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } },
  /* mask values 0x1, output array of 1, 0, 1, 0,.. */
  { .mask = 1, .expected = { 1, 0, 1, 0, 1, 0, 1, 0, 1, 0 } },
};

static clib_error_t *
test_clib_array_masked_test_flag_u32 (clib_error_t *err)
{
  u32 vec[256] = { 0 };
  u64 result_mask[4];
  array_masked_flag_test_t *t;

  for (int i = 0; i < ARRAY_LEN (masked_flag_tests); i++)
    {
      t = masked_flag_tests + i;
      // Fill test vector with the flag at alternating positions
      for (int j = 0; j < 256; j++)
	{
	  if (j & 1)
	    vec[j] = t->flag & j;
	}
      clib_array_mask_flag_test_u32 (t->bitmap, vec, t->flag, result_mask,
				     ARRAY_LEN (vec));
      for (int j = 0; j < ARRAY_LEN (result_mask); j++)
	if (result_mask[j] != t->expected_mask[j])
	  return clib_error_return (
	    err,
	    "testcase %u failed at "
	    "(bitmap[%u] = 0x%llx, expected[%u] = 0x%llx)",
	    i, j, result_mask[j], j, t->expected_mask[j]);
    }
  return err;
}

REGISTER_TEST (clib_array_masked_test_flag_u32) = {
  .name = "clib_array_masked_test_flag_u32",
  .fn = test_clib_array_masked_test_flag_u32,
};

static clib_error_t *
test_clib_array_test_flag_u32 (clib_error_t *err)
{
  u32 i, j;
  array_flag_test_t *t;
  u32 test_array[256];
  u64 bitmap[4] = { 0 };

  for (i = 0; i < ARRAY_LEN (flag_tests); i++)
    {
      t = flag_tests + i;
      switch (i)
	{
	case 0: /* Case 0: All elements are zero (no bits should be set in
		   bitmap) */
	  memset (test_array, 0, sizeof (test_array));
	  break;
	case 1: /* Case 1: All elements have the flag set (all bits should be
		   set) */
	  for (j = 0; j < ARRAY_LEN (test_array); j++)
	    test_array[j] = t->flag;
	  break;
	case 2: /* Case 3: Alternating pattern (010101...) */
	  for (j = 0; j < ARRAY_LEN (test_array); j++)
	    test_array[j] = (j & 1) ? t->flag : 0;
	  break;
	case 3: /* Case 4: Edge cases - first and last element */
	  test_array[0] = t->flag;
	  test_array[255] = t->flag;
	  break;
	default:
	  return clib_error_return (err, "wrong testcase");
	}

      clib_array_test_flag_u32 (test_array, t->flag, bitmap,
				ARRAY_LEN (test_array));
      for (j = 0; j < ARRAY_LEN (bitmap); j++)
	if (bitmap[j] != t->expected_mask[j])
	  return clib_error_return (
	    err,
	    "testcase %u failed at "
	    "(bitmap[%u] = 0x%llx, expected[%u] = 0x%llx)",
	    i, j, bitmap[j], j, t->expected_mask[j]);
    }
  return err;
}

REGISTER_TEST (clib_array_test_flag_u32) = {
  .name = "clib_array_test_flag_u32",
  .fn = test_clib_array_test_flag_u32,
};

static clib_error_t *
test_clib_array_mask_u32 (clib_error_t *err)
{
  u32 i, j, len;
  for (i = 0; i < ARRAY_LEN (tests) - 1; i++)
    {
      u32 src[256];
      for (j = 0; j < ARRAY_LEN (src); j++)
	src[j] = j;

      array_mask_test_t *t = tests + i;
      clib_array_mask_u32_wrapper (src, t->mask, ARRAY_LEN (src));
      for (j = 0; j < ARRAY_LEN (src); j++)
	{
	  if (src[j] != t->expected[j])
	    return clib_error_return (err,
				      "testcase %u failed at "
				      "(src[%u] = 0x%x, expected 0x%x)",
				      i, j, src[j], t->expected[j]);
	}
    }

  for (i = 0; i < ARRAY_LEN (tests) - 1; i++)
    {
      for (len = 1; len <= 256; len++)
	{
	  u32 src[len];
	  for (j = 0; j < ARRAY_LEN (src); j++)
	    src[j] = j;

	  array_mask_test_t *t = tests + i;
	  clib_array_mask_u32_wrapper (src, t->mask, ARRAY_LEN (src));
	  for (j = 0; j < ARRAY_LEN (src); j++)
	    {
	      if (src[j] != t->expected[j])
		return clib_error_return (err,
					  "testcase %u failed at "
					  "(src[%u] = 0x%x, expected 0x%x)",
					  i, j, src[j], t->expected[j]);
	    }
	}
    }

  u32 src[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
  array_mask_test_t *t = tests + i;

  clib_array_mask_u32_wrapper (src, t->mask, ARRAY_LEN (src));
  for (j = 0; j < ARRAY_LEN (src); j++)
    {
      if (src[j] != t->expected[j])
	return clib_error_return (err,
				  "testcase %u failed at "
				  "(src[%u] = 0x%x, expected 0x%x)",
				  i, j, src[j], t->expected[j]);
    }

  return err;
}

REGISTER_TEST (clib_array_mask_u32) = {
  .name = "clib_array_mask_u32",
  .fn = test_clib_array_mask_u32,
};
